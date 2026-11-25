"""G4 隔離候選：Client→Gateway→Verifier／Sender 雙 mTLS 原生回應與拒絕鏈。"""

import asyncio
import hashlib
import multiprocessing
from pathlib import Path
import ssl
import time
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
import httpx
import pytest

from deception.api.fingerprint import fingerprint_request
from deception.api.ingress import NormalizedRequest, normalize_request, resolve_request_id
from deception.security.protected_gateway import (
    FixedGatewaySenderMTLSClient, FixedGatewayVerifierMTLSClient,
    GatewayAuthorizedReceipt, GatewayNativeHTTP, GatewayNativeProxyUnverifiable,
    create_gateway_native_proxy_candidate_app,
    serve_gateway_native_proxy_loopback_tls,
)
from deception.security.protected_rpc import (
    create_receipt_proxy_sender_candidate_app, serve_direct_verifier_mtls,
    serve_fixed_sender_mtls,
)
from deception.world import (PostgresCandidatePromoter, PostgresProtectedAuthorizer,
                             PostgresKnownRestoreRecorder, PostgresProtectedSender)
from test_protected_rpc_mtls import _issue_mtls_certificates, _unused_local_port
from test_protected_grant import _login, _promote, _seed
from test_postgres_conformance import isolated_test_dsn
from test_receipt_proxy_sender import _candidate_sender


def _gateway_clients(tmp_path: Path, *, verifier_port: int, sender_port: int):
    """使用分開兩組短期真 X.509 根 CA，建立 Gateway 的兩個出站 mTLS 身分。"""
    verifier_root, sender_root = tmp_path / "verifier", tmp_path / "sender"
    verifier_root.mkdir()
    sender_root.mkdir()
    verifier_ca, _, _, verifier_cert, verifier_key = _issue_mtls_certificates(verifier_root)
    sender_ca, _, _, sender_cert, sender_key = _issue_mtls_certificates(sender_root)
    verifier = FixedGatewayVerifierMTLSClient(
        origin=f"https://127.0.0.1:{verifier_port}",
        client_cert=verifier_cert, client_key=verifier_key, server_ca=verifier_ca,
    )
    sender = FixedGatewaySenderMTLSClient(
        origin=f"https://127.0.0.1:{sender_port}",
        client_cert=sender_cert, client_key=sender_key, server_ca=sender_ca,
    )
    return (verifier, sender), (verifier_ca, sender_ca, verifier_root, sender_root)


def test_gateway_candidate_denies_untrusted_request_before_any_rpc(tmp_path, monkeypatch):
    """非 TLS、無 JWS 或無明確 Request ID 不得對 Verifier／Sender 出站。"""
    (verifier, sender), _ = _gateway_clients(
        tmp_path, verifier_port=52401, sender_port=52402)
    requests = {"verifier": 0, "sender": 0}

    async def verify(*_args):
        """記錄是否繞過原始 HTTP 的前置 TLS/JWS/ID 邊界。"""
        requests["verifier"] += 1
        raise AssertionError("untrusted request reached verifier")

    async def emit(*_args):
        """不允許未完成驗證的 Receipt 到達 Sender。"""
        requests["sender"] += 1
        raise AssertionError("untrusted request reached sender")

    monkeypatch.setattr(verifier, "verify_original", verify)
    monkeypatch.setattr(sender, "emit_receipt_once", emit)
    app = create_gateway_native_proxy_candidate_app(
        verifier_client=verifier, sender_client=sender)
    with TestClient(app, base_url="http://client.example") as client:
        assert client.get("/store/carts", headers={
            "x-request-id": "req-1", "x-trusted-session": "signed",
        }).status_code == 503
    with TestClient(app, base_url="https://client.example") as client:
        assert client.get("/store/carts").status_code == 403
        assert client.get("/store/carts", headers={"x-request-id": "req-2"}).status_code == 403
        assert client.get("/internal/v1/send", headers={
            "x-request-id": "req-3", "x-trusted-session": "signed",
        }).status_code == 404
    assert requests == {"verifier": 0, "sender": 0}


def test_gateway_verifier_forwards_every_original_header_without_httpx_defaults(tmp_path, monkeypatch):
    """Gateway 不得替原始 Client 加 Accept／Accept-Encoding／User-Agent 或改變標頭順序。"""
    (verifier, _), _ = _gateway_clients(tmp_path, verifier_port=52403, sender_port=52404)
    receipt = uuid4()
    source = NormalizedRequest(
        request_id="req-exact", method="GET", raw_url="https://client.example/store/carts",
        path="/store/carts", raw_path=b"/store/carts", query_string=b"", query=(),
        headers=(("host", "client.example"), ("x-request-id", "req-exact"),
                 ("x-trusted-session", "signed")), body=b"",
    )
    seen = []

    class CaptureClient:
        """攔截 HTTPX 出站但保持它原始的 `Request` 實體不受測試改寫。"""

        def __init__(self, **kwargs):
            """驗證 Client 不可使用系統代理或允許自動重新導向。"""
            assert kwargs["trust_env"] is False
            assert kwargs["follow_redirects"] is False

        async def __aenter__(self):
            """建立單次受控非網路 HTTPX context。"""
            return self

        async def __aexit__(self, *_):
            """結束單次受控 HTTPX context。"""
            return False

        async def send(self, outbound):
            """驗證所有原 Header bytes 精確一致，返回可信的固定測試授權。"""
            seen.extend(outbound.headers.raw)
            return httpx.Response(200, json={
                "receipt_id": str(receipt),
                "candidate_promotion": {"receipt_id": str(receipt),
                                        "candidate_hash": "a" * 64},
                "receipt_authorization": {"receipt_id": str(receipt),
                                          "candidate_hash": "a" * 64,
                                          "request_fingerprint": fingerprint_request(source),
                                          "send_owner": "protected-sender-" + receipt.hex,
                                          "trusted_send": "disabled"},
            })

    monkeypatch.setattr("deception.security.protected_gateway.httpx.AsyncClient", CaptureClient)
    pin = asyncio.run(verifier.verify_original(source))
    assert pin.receipt_id == receipt and pin.candidate_hash == "a" * 64
    assert seen == [(b"host", b"client.example"),
                    (b"x-request-id", b"req-exact"),
                    (b"x-trusted-session", b"signed")]


def test_gateway_candidate_two_real_mtls_hops_forward_native_bytes(tmp_path, monkeypatch):
    """真 Client→Gateway→Verifier/Authorizer 證據→Sender mTLS→Client 409、唯一 Lease。"""
    verifier_port, sender_port, gateway_port = (
        _unused_local_port(), _unused_local_port(), _unused_local_port())
    (verifier, sender), (verifier_ca, sender_ca, verifier_root, sender_root) = _gateway_clients(
        tmp_path, verifier_port=verifier_port, sender_port=sender_port)
    receipt = uuid4()
    pg_sender, pin, _ = _candidate_sender(monkeypatch, receipt)
    sender_app = create_receipt_proxy_sender_candidate_app(sender=pg_sender)
    verifier_app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    gateway_root = tmp_path / "gateway"
    gateway_root.mkdir()
    gateway_ca, gateway_cert, gateway_key, _, _ = _issue_mtls_certificates(gateway_root)

    @verifier_app.get("/internal/ready")
    async def ready():
        """只供隔離實驗確認獨立 mTLS Listener 已啟動。"""
        return {"trusted_send": "disabled"}

    @verifier_app.api_route("/{path:path}", methods=["GET", "POST", "DELETE"])
    async def verify(request: Request, path: str):
        """保留原始 HTTP fingerprint 的隔離 Verifier 回應；不假裝真正 JWS 驗章。"""
        original = await normalize_request(request, resolve_request_id(request))
        assert path == "store/carts"
        assert original.raw_url == "https://client.example/store/carts"
        assert original.body == b'{"cart":"test"}'
        fingerprint = fingerprint_request(original)
        return {
            "receipt_id": str(receipt),
            "candidate_promotion": {"receipt_id": str(receipt),
                                    "candidate_hash": hashlib.sha256(
                                        pin.envelope_bytes).hexdigest()},
            "receipt_authorization": {"receipt_id": str(receipt),
                                      "request_fingerprint": fingerprint,
                                      "candidate_hash": hashlib.sha256(
                                          pin.envelope_bytes).hexdigest(),
                                      "send_owner": pin.send_owner,
                                      "trusted_send": "disabled"},
        }

    verifier_worker = multiprocessing.Process(target=serve_direct_verifier_mtls, kwargs={
        "app": verifier_app, "host": "127.0.0.1", "port": verifier_port,
        "server_cert": verifier_root / "server.pem",
        "server_key": verifier_root / "server.key", "client_ca": verifier_ca,
    })
    sender_worker = multiprocessing.Process(target=serve_fixed_sender_mtls, kwargs={
        "app": sender_app, "host": "127.0.0.1", "port": sender_port,
        "server_cert": sender_root / "server.pem",
        "server_key": sender_root / "server.key", "sender_client_ca": sender_ca,
    })
    gateway_app = create_gateway_native_proxy_candidate_app(
        verifier_client=verifier, sender_client=sender)
    gateway_worker = multiprocessing.Process(
        target=serve_gateway_native_proxy_loopback_tls, kwargs={
            "app": gateway_app, "host": "127.0.0.1", "port": gateway_port,
            "server_cert": gateway_cert, "server_key": gateway_key,
        })
    verifier_worker.start()
    sender_worker.start()
    try:
        # 使用真正 HTTPS 驗證兩個獨立 Listener 都已就緒，不能用 sleep 當驗收。
        for worker, port, cert, key, ca in (
            (verifier_worker, verifier_port, verifier_root / "client.pem",
             verifier_root / "client.key", verifier_ca),
            (sender_worker, sender_port, sender_root / "client.pem",
             sender_root / "client.key", sender_ca),
        ):
            context = ssl.create_default_context(cafile=str(ca))
            context.load_cert_chain(str(cert), str(key))
            with httpx.Client(verify=context, trust_env=False, timeout=1) as ready:
                for _ in range(50):
                    try:
                        ready.get(f"https://127.0.0.1:{port}/internal/ready")
                        break
                    except (httpx.ConnectError, httpx.ReadError):
                        assert worker.is_alive(), "mTLS worker stopped before readiness"
                        time.sleep(0.1)
                else:
                    pytest.fail("mTLS worker readiness timed out")
        gateway_worker.start()
        headers = {"host": "client.example", "x-request-id": "req-gateway-1",
                   "x-trusted-session": "isolated-signed-placeholder",
                   "content-type": "application/json"}
        gateway_context = ssl.create_default_context(cafile=str(gateway_ca))
        with httpx.Client(verify=gateway_context, trust_env=False, timeout=4) as client:
            for _ in range(50):
                try:
                    ready = client.get(f"https://127.0.0.1:{gateway_port}/internal/ready")
                    break
                except httpx.ConnectError:
                    assert gateway_worker.is_alive(), "gateway HTTPS worker terminated"
                    time.sleep(0.1)
            else:
                pytest.fail("gateway HTTPS loopback readiness timed out")
            assert ready.json()["trusted_send"] == "disabled"
            first = client.post(f"https://127.0.0.1:{gateway_port}/store/carts",
                                content=b'{"cart":"test"}', headers=headers)
            assert first.status_code == 409
            assert first.content == b'{"native":"preserved"}'
            assert first.headers["x-native-pin"] == "yes"
            # 同一 Receipt 不能再次發業務 409；Gateway 對 Sender 503 只能回固定 503。
            second = client.post(f"https://127.0.0.1:{gateway_port}/store/carts",
                                 content=b'{"cart":"test"}', headers=headers)
            assert second.status_code == 503
            assert second.json() == {"detail": "gateway_delivery_unverifiable"}
            assert "x-native-pin" not in second.headers
        # 兩個 mTLS 根 CA 完全不同：錯誤用途的 Client Cert 必須 TLS 握手失敗。
        wrong_context = ssl.create_default_context(cafile=str(sender_ca))
        wrong_context.load_cert_chain(str(verifier_root / "client.pem"),
                                      str(verifier_root / "client.key"))
        with httpx.Client(verify=wrong_context, trust_env=False, timeout=2) as wrong:
            with pytest.raises(httpx.TransportError):
                wrong.post(f"https://127.0.0.1:{sender_port}/internal/v1/emit-receipt",
                           json={"receipt_id": str(receipt)})
    finally:
        for worker in (gateway_worker, verifier_worker, sender_worker):
            worker.terminate()
            worker.join(timeout=5)
            if worker.is_alive():
                worker.kill()


def test_gateway_candidate_fails_closed_on_invalid_receipt_chain(tmp_path, monkeypatch):
    """Verifier 來源未知或候選 Hash 失配時，Gateway 不可直呼 Sender 補發。"""
    (verifier, sender), _ = _gateway_clients(tmp_path, verifier_port=52405, sender_port=52406)
    attempts = []

    async def bad_verifier(*_args):
        """模擬未知 Verifier 終態；任何回退 Sender 嘗試都不合格。"""
        raise GatewayNativeProxyUnverifiable("verifier_unknown")

    async def forbidden_sender(*_args):
        """若授權失敗還調 Sender，留下測試可觀測的違規。"""
        attempts.append("sent")
        raise AssertionError("Sender called after failed verifier")

    monkeypatch.setattr(verifier, "verify_original", bad_verifier)
    monkeypatch.setattr(sender, "emit_receipt_once", forbidden_sender)
    app = create_gateway_native_proxy_candidate_app(
        verifier_client=verifier, sender_client=sender)
    with TestClient(app, base_url="https://client.example") as client:
        response = client.get("/store/carts", headers={
            "x-request-id": "req-denied", "x-trusted-session": "signed",
        })
    assert response.status_code == 503
    assert response.json() == {"detail": "gateway_delivery_unverifiable"}
    assert attempts == []


def test_gateway_client_disconnect_after_start_never_reinvokes_sender(tmp_path, monkeypatch):
    """原生 Start 已交付後 Client 下游寫入失敗，Gateway 不補發第二次 Sender RPC。"""
    (verifier, sender), _ = _gateway_clients(tmp_path, verifier_port=52407, sender_port=52408)
    receipt = uuid4()
    calls = []

    async def verified(*_args):
        """提供同一個已驗證不可變 Receipt，不讓 Caller 自填授權。"""
        calls.append("verified")
        return GatewayAuthorizedReceipt(receipt, "a" * 64)

    async def emitted(pin):
        """模擬 Sender 的一次性原生 bytes，不含任何可重起送介面。"""
        assert pin.receipt_id == receipt
        calls.append("sender-started-once")
        return GatewayNativeHTTP(200, ((b"content-type", b"application/json"),), b'{"ok":true}')

    monkeypatch.setattr(verifier, "verify_original", verified)
    monkeypatch.setattr(sender, "emit_receipt_once", emitted)
    app = create_gateway_native_proxy_candidate_app(
        verifier_client=verifier, sender_client=sender)
    messages = []

    async def receive():
        """一次性完整 GET HTTP Request，不含 Client 偽造的回應欄位。"""
        return {"type": "http.request", "body": b"", "more_body": False}

    async def disconnect_on_body(message):
        """確認原生 Status 曾嘗試起送，然後在 Body 寫入時斷線。"""
        messages.append(message)
        if message["type"] == "http.response.body":
            raise OSError("client disconnected")

    scope = {
        "type": "http", "http_version": "1.1", "method": "GET", "scheme": "https",
        "path": "/store/carts", "raw_path": b"/store/carts", "query_string": b"",
        "root_path": "", "server": ("client.example", 443), "client": ("127.0.0.1", 0),
        "headers": [(b"host", b"client.example"), (b"x-request-id", b"req-disconnect"),
                    (b"x-trusted-session", b"signed")],
    }
    with pytest.raises(OSError, match="client disconnected"):
        asyncio.run(app(scope, receive, disconnect_on_body))
    assert [message["type"] for message in messages] == [
        "http.response.start", "http.response.body"]
    assert calls == ["verified", "sender-started-once"]


def test_gateway_real_mtls_native_business_503_is_not_internal_sender_503(tmp_path, monkeypatch):
    """真 Sender 合法業務 503 能以 Hash 通過；後續內部 503 缺 Pin 必拒絕。"""
    sender_port = _unused_local_port()
    (_, sender), (_, sender_ca, _, sender_root) = _gateway_clients(
        tmp_path, verifier_port=52409, sender_port=sender_port)
    receipt = uuid4()
    pg_sender, pin, _ = _candidate_sender(monkeypatch, receipt, status=503)
    sender_app = create_receipt_proxy_sender_candidate_app(sender=pg_sender)
    worker = multiprocessing.Process(target=serve_fixed_sender_mtls, kwargs={
        "app": sender_app, "host": "127.0.0.1", "port": sender_port,
        "server_cert": sender_root / "server.pem",
        "server_key": sender_root / "server.key", "sender_client_ca": sender_ca,
    })
    worker.start()
    try:
        context = ssl.create_default_context(cafile=str(sender_ca))
        context.load_cert_chain(str(sender_root / "client.pem"),
                                str(sender_root / "client.key"))
        with httpx.Client(verify=context, trust_env=False, timeout=1) as probe:
            for _ in range(50):
                try:
                    probe.get(f"https://127.0.0.1:{sender_port}/internal/ready")
                    break
                except httpx.ConnectError:
                    assert worker.is_alive()
                    time.sleep(0.1)
            else:
                pytest.fail("native 503 Sender TLS listener did not start")
        pinned = GatewayAuthorizedReceipt(receipt, hashlib.sha256(pin.envelope_bytes).hexdigest())
        native = asyncio.run(sender.emit_receipt_once(pinned))
        assert native.status_code == 503
        assert native.raw_headers == ((b"content-type", b"application/json"),
                                      (b"x-native-pin", b"yes"))
        assert native.body == b'{"native":"preserved"}'
        # 測試故意重播同 Receipt：第二份「內部 503」絕不可能碰巧符合原生 Hash。
        with pytest.raises(GatewayNativeProxyUnverifiable, match="gateway_sender_hash_mismatch"):
            asyncio.run(sender.emit_receipt_once(pinned))
    finally:
        worker.terminate()
        worker.join(timeout=5)
        if worker.is_alive():
            worker.kill()


def test_gateway_three_real_tls_hops_use_one_real_postgres_send_lease(
        tmp_path, isolated_test_dsn):
    """真 Client TLS 與雙 mTLS 連線後，唯一 PG 授權 Pin 發原生 200，重播 503。"""
    import psycopg

    verifier_port, sender_port, gateway_port = (
        _unused_local_port(), _unused_local_port(), _unused_local_port())
    (verifier, sender), (verifier_ca, sender_ca, verifier_root, sender_root) = _gateway_clients(
        tmp_path, verifier_port=verifier_port, sender_port=sender_port)
    gateway_root = tmp_path / "gateway"
    gateway_root.mkdir()
    gateway_ca, gateway_cert, gateway_key, _, _ = _issue_mtls_certificates(gateway_root)
    body = b'{"probe":"pg"}'
    headers = {"host": "client.example", "x-request-id": "req-pg-1",
               "x-trusted-session": "isolated-verifier-placeholder",
               "content-type": "application/json"}
    context = ssl.create_default_context(cafile=str(gateway_ca))
    with httpx.Client(verify=context, trust_env=False, timeout=4) as client:
        outgoing = client.build_request(
            "POST", f"https://127.0.0.1:{gateway_port}/store/carts",
            headers=headers, content=body)
        original = NormalizedRequest(
            request_id="req-pg-1", method="POST",
            raw_url="https://client.example/store/carts", path="/store/carts",
            raw_path=b"/store/carts", query_string=b"", query=(),
            headers=tuple((name.decode("latin-1"), value.decode("latin-1"))
                          for name, value in outgoing.headers.raw), body=body,
        )
        expected_fingerprint = fingerprint_request(original)
        seeded = _seed(isolated_test_dsn, fingerprint=expected_fingerprint)
        selected, source, evidence, receipt_id, ref, hashes, _ = seeded
        promoter = PostgresCandidatePromoter(
            isolated_test_dsn, expected_login=_login(isolated_test_dsn))
        assert promoter.promote(
            receipt_id=receipt_id, scope=selected, candidate_ref=ref,
            request_fingerprint=expected_fingerprint,
            envelope_hash=hashes[0], immutable_body_hash=hashes[1],
            semantic_headers_hash=hashes[2], evidence=evidence, source=source,
        ) == 1
        authorizer = PostgresProtectedAuthorizer(
            isolated_test_dsn, expected_login=_login(isolated_test_dsn))
        admission, owner = authorizer.authorize_promoted_receipt_once(receipt_id)
        pg_sender = PostgresProtectedSender(
            isolated_test_dsn, expected_login=_login(isolated_test_dsn))
        sender_app = create_receipt_proxy_sender_candidate_app(sender=pg_sender)
        verifier_app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

        @verifier_app.get("/internal/ready")
        async def ready():
            """測試 Verifier 使用獨立 TLS Listener 的存活路由。"""
            return {"trusted_send": "disabled"}

        @verifier_app.api_route("/{path:path}", methods=["POST"])
        async def verify(request: Request, path: str):
            """代表已驗 Grant 的固定回執；另由真 PG 建立不可變綁定。"""
            normalized = await normalize_request(request, resolve_request_id(request))
            assert path == "store/carts"
            assert fingerprint_request(normalized) == expected_fingerprint
            return {
                "receipt_id": str(receipt_id),
                "candidate_promotion": {
                    "receipt_id": str(receipt_id), "candidate_hash": admission.candidate_hash},
                "receipt_authorization": {
                    "receipt_id": str(receipt_id), "send_owner": owner,
                    "request_fingerprint": expected_fingerprint,
                    "candidate_hash": admission.candidate_hash, "trusted_send": "disabled"},
            }

        gateway_app = create_gateway_native_proxy_candidate_app(
            verifier_client=verifier, sender_client=sender)
        workers = [
            multiprocessing.Process(target=serve_direct_verifier_mtls, kwargs={
                "app": verifier_app, "host": "127.0.0.1", "port": verifier_port,
                "server_cert": verifier_root / "server.pem",
                "server_key": verifier_root / "server.key", "client_ca": verifier_ca,
            }),
            multiprocessing.Process(target=serve_fixed_sender_mtls, kwargs={
                "app": sender_app, "host": "127.0.0.1", "port": sender_port,
                "server_cert": sender_root / "server.pem",
                "server_key": sender_root / "server.key", "sender_client_ca": sender_ca,
            }),
            multiprocessing.Process(target=serve_gateway_native_proxy_loopback_tls, kwargs={
                "app": gateway_app, "host": "127.0.0.1", "port": gateway_port,
                "server_cert": gateway_cert, "server_key": gateway_key,
            }),
        ]
        for worker in workers:
            worker.start()
        try:
            for _ in range(60):
                try:
                    check = client.get(f"https://127.0.0.1:{gateway_port}/internal/ready")
                    break
                except httpx.ConnectError:
                    assert all(worker.is_alive() for worker in workers)
                    time.sleep(0.1)
            else:
                pytest.fail("Gateway TLS listener did not start")
            assert check.status_code == 200
            # 其餘兩個 Listener 若仍在啟動，最多等 2 秒；不重播有副作用的 Receipt。
            for port, ca, cert, key in (
                (verifier_port, verifier_ca, verifier_root / "client.pem", verifier_root / "client.key"),
                (sender_port, sender_ca, sender_root / "client.pem", sender_root / "client.key"),
            ):
                tls = ssl.create_default_context(cafile=str(ca))
                tls.load_cert_chain(str(cert), str(key))
                with httpx.Client(verify=tls, trust_env=False, timeout=1) as probe:
                    for _ in range(30):
                        try:
                            probe.get(f"https://127.0.0.1:{port}/internal/ready")
                            break
                        except httpx.ConnectError:
                            time.sleep(0.1)
                    else:
                        pytest.fail("Internal mTLS listener did not start")
            first = client.send(outgoing)
            assert first.status_code == 200
            assert first.content == b'{"synthetic":true}'
            second = client.post(f"https://127.0.0.1:{gateway_port}/store/carts",
                                 headers=headers, content=body)
            assert second.status_code == 503
            assert second.json() == {"detail": "gateway_delivery_unverifiable"}
            with psycopg.connect(isolated_test_dsn) as connection:
                assert connection.execute(
                    "SELECT count(*) FROM protected_send_leases WHERE admission_id=%s",
                    (admission.admission_id,),
                ).fetchone() == (1,)
                assert connection.execute(
                    "SELECT state FROM response_admissions WHERE admission_id=%s",
                    (admission.admission_id,),
                ).fetchone() == ("SEND_COMPLETED",)
        finally:
            for worker in workers:
                worker.terminate()
                worker.join(timeout=5)
                if worker.is_alive():
                    worker.kill()


def _g6_authorized_receipt(dsn):
    """建立不同 UUID/JTI 的真 PG Receipt→Promotion→Authorizer，不仰賴假 Lease。"""
    # 同個隔離 schema 的多個 Receipt 不得重用 registry_revision=1 的 Contract。
    seeded = _seed(dsn, contract_hash=hashlib.sha256(uuid4().bytes).hexdigest())
    assert _promote(dsn, seeded) == 1
    authorizer = PostgresProtectedAuthorizer(dsn, expected_login=_login(dsn))
    admission, owner = authorizer.authorize_promoted_receipt_once(seeded[3])
    assert owner == "protected-sender-" + seeded[3].hex
    return GatewayAuthorizedReceipt(seeded[3], admission.candidate_hash), admission


def _g6_start_sender_listener(app, *, port, sender_ca, sender_root):
    """僅啟動一次 loopback Sender mTLS 子程序，確認真的握手就緒。"""
    worker = multiprocessing.Process(target=serve_fixed_sender_mtls, kwargs={
        "app": app, "host": "127.0.0.1", "port": port,
        "server_cert": sender_root / "server.pem",
        "server_key": sender_root / "server.key", "sender_client_ca": sender_ca,
    })
    worker.start()
    context = ssl.create_default_context(cafile=str(sender_ca))
    context.load_cert_chain(str(sender_root / "client.pem"),
                            str(sender_root / "client.key"))
    with httpx.Client(verify=context, trust_env=False, timeout=1) as probe:
        for _ in range(50):
            try:
                response = probe.get(f"https://127.0.0.1:{port}/internal/ready")
                assert response.status_code == 200
                return worker
            except (httpx.ConnectError, httpx.ReadError):
                assert worker.is_alive(), "G6 isolated Sender stopped during startup"
                time.sleep(0.1)
    worker.terminate()
    worker.join(timeout=5)
    pytest.fail("G6 isolated Sender mTLS readiness timed out")


def _g6_stop_worker(worker):
    """只回收本測試建立的專用 loopback 子程序，不觸碰共享服務。"""
    if worker is not None:
        worker.terminate()
        worker.join(timeout=5)
        if worker.is_alive():
            worker.kill()
            worker.join(timeout=5)


def test_gateway_g6_sender_outage_recovers_only_with_fresh_receipt(
        tmp_path, monkeypatch, isolated_test_dsn):
    """Sender 真 TCP 停機回固定 503 無 Lease；重啟後只用新 Receipt 正常發出。"""
    import psycopg

    sender_port = _unused_local_port()
    (verifier, sender), (_, sender_ca, _, sender_root) = _gateway_clients(
        tmp_path, verifier_port=_unused_local_port(), sender_port=sender_port)
    offline_pin, offline_admission = _g6_authorized_receipt(isolated_test_dsn)
    recovered_pin, recovered_admission = _g6_authorized_receipt(isolated_test_dsn)
    current = {"pin": offline_pin, "verifier_calls": 0}

    async def isolated_verified(_original):
        """僅模擬 Verifier 回傳已存在的真 PG 授權；本例不宣稱 JWS 驗章。"""
        current["verifier_calls"] += 1
        return current["pin"]

    monkeypatch.setattr(verifier, "verify_original", isolated_verified)
    app = create_gateway_native_proxy_candidate_app(
        verifier_client=verifier, sender_client=sender)
    pg_sender = PostgresProtectedSender(isolated_test_dsn,
                                        expected_login=_login(isolated_test_dsn))
    sender_app = create_receipt_proxy_sender_candidate_app(sender=pg_sender)
    headers = {"x-request-id": "g6-outage", "x-trusted-session": "isolated-stub"}
    worker = None
    try:
        with TestClient(app, base_url="https://client.example") as client:
            # 真 HTTPS mTLS Sender 連線拒絕；沒有 Sender 被呼叫，自然沒有 Lease。
            offline = client.get("/store/carts", headers=headers)
            assert offline.status_code == 503
            assert offline.json() == {"detail": "gateway_delivery_unverifiable"}
            assert b"synthetic" not in offline.content
            with psycopg.connect(isolated_test_dsn) as connection:
                assert connection.execute(
                    "SELECT count(*) FROM protected_send_leases WHERE admission_id=%s",
                    (offline_admission.admission_id,),
                ).fetchone() == (0,)
            # 不重送未知結果的舊 Receipt；改用獨立 JTI 的全新授權。
            worker = _g6_start_sender_listener(
                sender_app, port=sender_port, sender_ca=sender_ca, sender_root=sender_root)
            current["pin"] = recovered_pin
            headers["x-request-id"] = "g6-recovered-fresh"
            recovered = client.get("/store/carts", headers=headers)
            assert recovered.status_code == 200
            assert recovered.content == b'{"synthetic":true}'
            assert current["verifier_calls"] == 2
            with psycopg.connect(isolated_test_dsn) as connection:
                assert connection.execute(
                    "SELECT admission_id FROM protected_send_leases ORDER BY admission_id"
                ).fetchall() == [(recovered_admission.admission_id,)]
            # Client 的 HTTP body 已到達，但 Sender 的持久 Finish 可稍後完成。
            for _ in range(40):
                with psycopg.connect(isolated_test_dsn) as connection:
                    state = connection.execute(
                        "SELECT state FROM response_admissions WHERE admission_id=%s",
                        (recovered_admission.admission_id,),
                    ).fetchone()
                if state == ("SEND_COMPLETED",):
                    break
                time.sleep(0.05)
            assert state == ("SEND_COMPLETED",)
    finally:
        _g6_stop_worker(worker)


def test_gateway_g6_post_commit_ack_loss_never_emits_native_or_second_lease(
        tmp_path, monkeypatch, isolated_test_dsn):
    """真 PG Lease COMMIT 後遺失應答，Gateway 固定 503；重試不能建立第二個 Lease。"""
    import psycopg

    sender_port = _unused_local_port()
    (verifier, sender), (_, sender_ca, _, sender_root) = _gateway_clients(
        tmp_path, verifier_port=_unused_local_port(), sender_port=sender_port)
    pin, admission = _g6_authorized_receipt(isolated_test_dsn)
    pg_sender = PostgresProtectedSender(isolated_test_dsn,
                                        expected_login=_login(isolated_test_dsn))
    committed_start = pg_sender.start_send

    def commit_then_lose_ack(**kwargs):
        """先取得已實際提交的 Lease，再故意讓 Sender 無法確認 COMMIT 回覆。"""
        lease = committed_start(**kwargs)
        if lease is not None:
            raise OSError("simulated_lost_post_commit_reply")
        return None

    monkeypatch.setattr(pg_sender, "start_send", commit_then_lose_ack)

    async def isolated_verified(_original):
        """固定回傳真 PG Authorizer 所簽發的 Receipt/hash，不假冒 JWS。"""
        return pin

    monkeypatch.setattr(verifier, "verify_original", isolated_verified)
    sender_app = create_receipt_proxy_sender_candidate_app(sender=pg_sender)
    app = create_gateway_native_proxy_candidate_app(
        verifier_client=verifier, sender_client=sender)
    worker = None
    try:
        worker = _g6_start_sender_listener(
            sender_app, port=sender_port, sender_ca=sender_ca, sender_root=sender_root)
        with TestClient(app, base_url="https://client.example") as client:
            for request_id in ("g6-commit-unknown", "g6-explicit-replay-denied"):
                result = client.get("/store/carts", headers={
                    "x-request-id": request_id, "x-trusted-session": "isolated-stub"})
                assert result.status_code == 503
                assert result.json() == {"detail": "gateway_delivery_unverifiable"}
                assert b"synthetic" not in result.content
            with psycopg.connect(isolated_test_dsn) as connection:
                assert connection.execute(
                    "SELECT count(*) FROM protected_send_leases WHERE admission_id=%s",
                    (admission.admission_id,),
                ).fetchone() == (1,)
                assert connection.execute(
                    "SELECT state FROM response_admissions WHERE admission_id=%s",
                    (admission.admission_id,),
                ).fetchone() == ("SEND_STARTED",)
    finally:
        _g6_stop_worker(worker)


def test_gateway_g6_known_restore_quarantines_native_sender_across_mtls(
        tmp_path, monkeypatch, isolated_test_dsn):
    """Known Restore 真 PG 隔離旗標阻止 Sender Lease；Gateway 不洩漏原生內容。"""
    import psycopg

    sender_port = _unused_local_port()
    (verifier, sender), (_, sender_ca, _, sender_root) = _gateway_clients(
        tmp_path, verifier_port=_unused_local_port(), sender_port=sender_port)
    pin, admission = _g6_authorized_receipt(isolated_test_dsn)
    recorder = PostgresKnownRestoreRecorder(
        isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    assert recorder.mark_known_restore(uuid4())

    async def isolated_verified(_original):
        """故意回傳 Restore 前建立的真 Receipt，驗證 Sender 必須重新檢查。"""
        return pin

    monkeypatch.setattr(verifier, "verify_original", isolated_verified)
    sender_app = create_receipt_proxy_sender_candidate_app(sender=PostgresProtectedSender(
        isolated_test_dsn, expected_login=_login(isolated_test_dsn)))
    app = create_gateway_native_proxy_candidate_app(
        verifier_client=verifier, sender_client=sender)
    worker = None
    try:
        worker = _g6_start_sender_listener(
            sender_app, port=sender_port, sender_ca=sender_ca, sender_root=sender_root)
        with TestClient(app, base_url="https://client.example") as client:
            blocked = client.get("/store/carts", headers={
                "x-request-id": "g6-restore", "x-trusted-session": "isolated-stub"})
            assert blocked.status_code == 503
            assert blocked.json() == {"detail": "gateway_delivery_unverifiable"}
            assert b"synthetic" not in blocked.content
        with psycopg.connect(isolated_test_dsn) as connection:
            assert connection.execute(
                "SELECT count(*) FROM protected_send_leases WHERE admission_id=%s",
                (admission.admission_id,),
            ).fetchone() == (0,)
            assert connection.execute(
                "SELECT count(*) FROM protected_local_restore_events"
            ).fetchone() == (1,)
    finally:
        _g6_stop_worker(worker)
