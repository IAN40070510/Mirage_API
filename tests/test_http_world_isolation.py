"""以雙獨立 TLS 業務服務驗證 scope 拒絕一致性與跨 Session 交錯操作。"""

import base64
from http.client import HTTPSConnection
import json
import multiprocessing
import shutil
import socket
import ssl
import subprocess
import time
from uuid import uuid4

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deception.domains.ecommerce.carts import SyntheticCarts
from deception.world.session import SessionBinding
from test_postgres_conformance import isolated_test_dsn
from test_trusted_session import encode


def serve_world_service(listener, cert, key, public, dsn, output, next_public=None):
    """啟動完整可信 HTTP／交易／Renderer 程序，模型停用且只使用合成資料。"""
    import uvicorn
    from deception.domains.ecommerce.http_demo import DemoConfig
    from deception.domains.ecommerce.trusted_http import create_app
    from deception.security.trusted_deployment import TrustedDeploymentSettings

    public_keys = {"test": public.hex()}
    if next_public is not None:
        public_keys["next"] = next_public.hex()
    settings = TrustedDeploymentSettings(issuer="gateway", audience="mirage", environment_id="isolated-demo",
        deployment_id="isolated-demo", source_id="local-demo-detector", service_id="synthetic-store",
        site_id="demo-store", public_keys=public_keys)
    app = create_app(settings=settings, postgres_dsn=dsn, output_root=output,
        config=DemoConfig(origin="https://shop.test"), enable_business=True,
        enable_medusa_store=True, medusa_publishable_key="pk_synthetic_isolation")
    uvicorn.Server(uvicorn.Config(app, ssl_certfile=str(cert), ssl_keyfile=str(key),
        http="h11", log_level="error", access_log=False, date_header=False,
        server_header=False)).run(sockets=[listener])


class HTTPWorldLab:
    """只在測試內持有 Gateway 簽章 key，透過兩個實際 TLS socket 送同一受信任 authority。"""

    def __init__(self, ports, trust, signing, fingerprint, dsn):
        """保存已啟動的服務端口及測試簽章器，資源查詢使用同一隔離 schema。"""
        self.ports, self.trust, self.signing, self.fingerprint = ports, trust, signing, fingerprint
        self.carts, self.dsn = SyntheticCarts(dsn), dsn

    def exchange(self, instance, request):
        """只改變連線目的 socket，原樣送出簽章涵蓋的 Host、path、query、headers 與 body。"""
        connection = HTTPSConnection("127.0.0.1", self.ports[instance], context=self.trust, timeout=30)
        try:
            connection.putrequest(request.method, request.url.raw_path.decode("ascii"),
                                  skip_host=True, skip_accept_encoding=True)
            for name, value in request.headers.raw:
                connection.putheader(name.decode("ascii"), value.decode("latin1"))
            connection.endheaders(request.content)
            response = connection.getresponse()
            return httpx.Response(response.status, headers=response.getheaders(), content=response.read(), request=request)
        finally:
            connection.close()

    def send(self, instance, binding, method, path, payload=None, *, changes=None, request_id=None, kid="test"):
        """簽發新 JTI，僅負例可替換 claims；不從 Client header 推定 Session 身份。"""
        now, request_id = int(time.time()), request_id or uuid4().hex
        request = httpx.Request(method, "https://shop.test" + path, json=payload,
            headers={"x-request-id": request_id, "x-publishable-api-key": "pk_synthetic_isolation"})
        claims = dict(iss="gateway", aud="mirage", iat=now, nbf=now, exp=now+60, jti=uuid4().hex,
            environment_id=binding.environment_id, deployment_id=binding.deployment_id,
            session_id=binding.session_id, session_epoch=binding.session_epoch, access_mode=binding.access_mode,
            resource_id=binding.resource_id, request_fingerprint=self.fingerprint(request, request_id),
            assessment_id=uuid4().hex, assessment_digest="a" * 64)
        claims.update(changes or {})
        content = encode(dict(alg="Ed25519", typ="mirage-trusted-session+jwt", protocol_version="1.1", kid=kid)) + "." + encode(claims)
        request.headers["x-trusted-session"] = content + "." + base64.urlsafe_b64encode(
            self.signing.sign(content.encode())).decode().rstrip("=")
        response = self.exchange(instance, request)
        assert "set-cookie" not in response.headers
        return response

    def create(self, instance, name):
        """以不同合成建立者取得新的 cart 能力，不要求 Cookie 或真實顧客。"""
        creator = SessionBinding(environment_id="isolated-demo", deployment_id="isolated-demo",
                                 session_id=name, session_epoch=1)
        response = self.send(instance, creator, "POST", "/store/carts", {})
        assert response.status_code == 200, response.text
        return self.binding(response.json()["cart"]["id"])

    def binding(self, resource_id):
        """從伺服器資源登記取得可信 binding；無效測試值只由負例的 claims 變異注入。"""
        return self.carts.resource_binding(resource_id, environment_id="isolated-demo",
            deployment_id="isolated-demo", now=int(time.time()))

    def snapshot(self, binding):
        """以新資料庫連線觀察資源世界，避免把服務物件快取當作隔離證據。"""
        return self.carts.inspect_binding(binding, now=int(time.time()))

    def counts(self):
        """擷取世界、業務及准入筆數；Replay 消費獨立於 scope 拒絕，不列入此比較。"""
        import psycopg
        from psycopg import sql

        tables = ("world_snapshots", "session_heads", "session_world_bindings", "world_initializations",
                  "world_events", "world_operations", "read_admissions", "response_admissions")
        with psycopg.connect(self.dsn) as connection:
            return {table: connection.execute(sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(table))).fetchone()[0]
                    for table in tables}


@pytest.fixture
def http_worlds(isolated_test_dsn, tmp_path, request):
    """啟動兩個不同 PID 的完整 TLS 服務，結束只清理本 fixture 的 worker 與 socket。"""
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("requires openssl")
    from deception.api.fingerprint import fingerprint_httpx_request as wire_fingerprint

    cert, key, config = tmp_path / "cert.pem", tmp_path / "key.pem", tmp_path / "openssl.cnf"
    config.write_text("[req]\ndistinguished_name=dn\n[dn]\n", encoding="ascii")
    subprocess.run([openssl, "req", "-config", str(config), "-x509", "-newkey", "rsa:2048", "-nodes",
        "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
        "-out", str(cert), "-keyout", str(key)], check=True, capture_output=True, timeout=20)
    context, signing = multiprocessing.get_context("spawn"), Ed25519PrivateKey.generate()
    listeners, workers, ports = [], [], []
    lab = HTTPWorldLab(ports, ssl.create_default_context(cafile=str(cert)), signing, wire_fingerprint, isolated_test_dsn)
    lab.next_signing = Ed25519PrivateKey.generate() if getattr(request, "param", None) == "rotation" else None
    try:
        for number in range(2):
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listeners.append(listener)
            ports.append(listener.getsockname()[1])
            worker = context.Process(target=serve_world_service, args=(listener, cert, key,
                signing.public_key().public_bytes_raw(), isolated_test_dsn, tmp_path / f"instance-{number}",
                None if lab.next_signing is None else lab.next_signing.public_key().public_bytes_raw()))
            workers.append(worker)
            worker.start()
        assert len({worker.pid for worker in workers}) == 2
        for number, worker in enumerate(workers):
            deadline = time.monotonic() + 60
            while True:
                try:
                    if lab.exchange(number, httpx.Request("GET", "https://shop.test/healthz")).status_code == 200:
                        break
                except (OSError, TimeoutError):
                    pass
                assert worker.is_alive() and time.monotonic() < deadline, "world service did not become ready"
                time.sleep(0.05)
        yield lab
    finally:
        for worker in workers:
            if worker.pid is not None:
                if worker.is_alive():
                    worker.terminate()
                worker.join(5)
                worker.close()
        for listener in listeners:
            listener.close()


def add_and_complete(lab, binding, *, instance, quantity=1):
    """從該世界 catalog 選擇有足夠合成庫存的品項，經原生 HTTP 加入並完成訂單。"""
    snapshot = lab.snapshot(binding)
    variant = next(identifier for identifier, item in snapshot.state["catalog"].items()
                   if snapshot.state["inventory"][item["sku"]] >= quantity)
    path = "/store/carts/" + binding.resource_id
    added = lab.send(instance, binding, "POST", path + "/line-items", {"variant_id": variant, "quantity": quantity})
    assert added.status_code == 200, added.text
    completed = lab.send(1-instance, binding, "POST", path + "/complete")
    assert completed.status_code == 200, completed.text
    return lab.binding(completed.json()["order"]["id"])


def test_scope_mismatches_have_identical_http_refusal_without_new_worlds(http_worlds):
    """SEC-05：兩個服務對已存在／不存在資源的各維度錯配回相同 503，不初始化或讀取世界。"""
    lab = http_worlds
    carts = [lab.create(number, "scope-creator-" + str(number)) for number in range(2)]
    orders = [add_and_complete(lab, binding, instance=number) for number, binding in enumerate(carts)]
    before = [lab.snapshot(binding) for binding in carts]
    before_counts = lab.counts()
    refused = set()
    for kind, resources in (("carts", carts), ("orders", orders)):
        own, other = resources
        for prefix in ("/synthetic", "/store"):
            for exists in (True, False):
                target = own.resource_id if exists else ("cart_" if kind == "carts" else "order_") + uuid4().hex
                base = own.model_copy(update={"resource_id": target})
                cases = {
                    "environment": {"environment_id": "other-environment"},
                    "deployment": {"deployment_id": "other-deployment"},
                    "other-session": {"session_id": other.session_id},
                    "unknown-session": {"session_id": "unknown-session"},
                    "old-epoch": {"session_epoch": 0},
                    "new-epoch": {"session_epoch": 2},
                    "read-only": {"access_mode": "read_only", "resource_id": None},
                    "client-generation": {"world_generation_id": before[0].scope.world_generation_id if exists else uuid4().hex},
                }
                for number, (name, changes) in enumerate(cases.items()):
                    response = lab.send(number % 2, base, "GET", f"{prefix}/{kind}/{target}",
                                        changes=changes, request_id="scope-matrix")
                    assert response.status_code == 503, (kind, prefix, exists, name, response.text)
                    assert response.json() == {"code": "pipeline_unavailable", "request_id": "scope-matrix"}
                    refused.add((response.status_code, response.content, tuple(response.headers.raw)))
                mismatched_path = other.resource_id if exists else target
                response = lab.send(0, own, "GET", f"{prefix}/{kind}/{mismatched_path}", request_id="scope-matrix")
                assert response.status_code == 503, (kind, prefix, exists, "path-resource", response.text)
                refused.add((response.status_code, response.content, tuple(response.headers.raw)))
    assert len(refused) == 1
    assert lab.counts() == before_counts
    assert [lab.snapshot(binding) for binding in carts] == before


def test_two_services_interleave_session_writes_without_crossing_inventory(http_worlds):
    """WORLD-02：兩個完整服務交錯寫入兩個 Session，取消 A 不改 B 的訂單、庫存或版本。"""
    lab = http_worlds
    first, second = lab.create(0, "creator-A"), lab.create(1, "creator-B")
    initial = [lab.snapshot(binding) for binding in (first, second)]
    assert first.session_id != second.session_id
    assert initial[0].scope.world_generation_id != initial[1].scope.world_generation_id
    variant = next(identifier for identifier, item in initial[0].state["catalog"].items()
                   if initial[0].state["inventory"][item["sku"]] >= 3)
    sku = initial[0].state["catalog"][variant]["sku"]
    for number, binding, quantity in ((0, first, 1), (1, second, 2)):
        response = lab.send(number, binding, "POST", "/store/carts/" + binding.resource_id + "/line-items",
                            {"variant_id": variant, "quantity": quantity})
        assert response.status_code == 200, response.text
        assert lab.snapshot(binding).state["inventory"] == initial[number].state["inventory"]
        if number == 0:
            assert lab.snapshot(second) == initial[1]
    orders = []
    for number, binding in ((1, first), (0, second)):
        response = lab.send(number, binding, "POST", "/store/carts/" + binding.resource_id + "/complete")
        assert response.status_code == 200, response.text
        orders.append(lab.binding(response.json()["order"]["id"]))
    order_a, order_b = orders
    committed_b = lab.snapshot(second)
    assert lab.snapshot(first).version == committed_b.version == 3
    assert lab.snapshot(first).state["inventory"][sku] == initial[0].state["inventory"][sku] - 1
    assert committed_b.state["inventory"][sku] == initial[1].state["inventory"][sku] - 2
    cancelled = lab.send(1, order_a, "POST", "/synthetic/orders/" + order_a.resource_id + "/cancel",
        {"expected_version": 3, "idempotency_key": "cancel-A", "commit_attempt_id": str(uuid4())})
    assert cancelled.status_code == 200, cancelled.text
    assert lab.snapshot(second) == committed_b
    assert lab.snapshot(first).state["inventory"] == initial[0].state["inventory"]
    assert lab.snapshot(first).version == 4
    for number, binding, expected in ((0, order_a, "canceled"), (1, order_b, "pending")):
        response = lab.send(number, binding, "GET", "/store/orders/" + binding.resource_id)
        assert response.status_code == 200, response.text
        assert response.json()["order"]["status"] == expected
