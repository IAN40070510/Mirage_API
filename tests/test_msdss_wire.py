"""用實際 MSDSS proxy 與獨立 HTTPS 程序驗證 SessionBinding 的傳遞。"""

import asyncio
import multiprocessing
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import time
from uuid import uuid4

import httpx
import pytest
from test_postgres_conformance import isolated_test_dsn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def serve_receiver(listener, cert, key, public):
    """在子程序啟動 Mirage 原生請求標準化與驗章入口，只回傳已驗證身份。"""
    import uvicorn
    from fastapi import FastAPI, Request
    from deception.api.ingress import normalize_request, resolve_request_id
    from deception.api.fingerprint import fingerprint_request
    from deception.security import TrustedKeyRegistry, TrustedSessionVerifier
    from deception.world import ReplayStore

    app = FastAPI()
    verifier = TrustedSessionVerifier(keys=TrustedKeyRegistry({("gw", "key"): public}),
                                      replay_store=ReplayStore())

    @app.get("/check")
    async def check(request: Request):
        """依線上收到的 bytes 核對簽章與部署，回傳 session 供父程序比對。"""
        received = await normalize_request(request, resolve_request_id(request))
        claims = verifier.verify(request.headers["x-trusted-session"], expected_issuer="gw",
                                 expected_audience="mirage", environment_id="lab",
                                 deployment_id="test", request_fingerprint=fingerprint_request(received))
        return [claims.session_id, claims.session_epoch, os.getpid()]

    server = uvicorn.Server(uvicorn.Config(app, ssl_certfile=str(cert), ssl_keyfile=str(key),
                                          http="h11", log_level="error"))
    server.run(sockets=[listener])


def serve_pipeline(listener, cert, key, public, native=False):
    """在獨立 HTTPS 程序執行完整電商回應流程，從共用 PostgreSQL 消費 JTI。"""
    import uvicorn
    from deception.domains.ecommerce.http_demo import DemoConfig
    from deception.domains.ecommerce.trusted_http import create_app
    from deception.security.trusted_deployment import TrustedDeploymentSettings

    settings = TrustedDeploymentSettings(
        issuer="gw", audience="mirage", environment_id="isolated-demo", deployment_id="isolated-demo",
        source_id="local-demo-detector", service_id="synthetic-store", site_id="demo-store",
        public_keys={"key": public.hex()},
    )
    origin = f"https://127.0.0.1:{listener.getsockname()[1]}"
    app = create_app(config=DemoConfig(origin=origin), output_root=cert.parent, settings=settings,
                     postgres_dsn=os.environ["MIRAGE_POSTGRES_TEST_DSN"], enable_business=native,
                     enable_medusa_store=native, medusa_publishable_key="pk_synthetic_native" if native else None)
    uvicorn.Server(uvicorn.Config(app, ssl_certfile=str(cert), ssl_keyfile=str(key),
                                  http="h11", log_level="error")).run(sockets=[listener])


@pytest.mark.parametrize("full_pipeline", [False, True, "medusa", "anonymous", "native"], ids=["claims", "postgres-pipeline", "medusa-pipeline", "anonymous-pipeline", "native-store"])
def test_gateway_dispatch_to_independent_mirage(tmp_path, monkeypatch, full_pipeline, request):
    """走 MSDSS 的 proxy 決策與實際 TLS 傳輸，確認訪客標頭無法取代伺服器綁定。"""
    if full_pipeline:
        # 每個流程使用獨立 schema；子程序沿用該 DSN，避免跨輪過期世界及共用 DDL 干擾。
        dsn = request.getfixturevalue("isolated_test_dsn")
        monkeypatch.setenv("MIRAGE_POSTGRES_TEST_DSN", dsn)
    if full_pipeline == "medusa" and not all(os.environ.get(key) for key in (
        "MIRAGE_MEDUSA_TEST_ORIGIN", "MIRAGE_MEDUSA_TEST_ADMIN_EMAIL", "MIRAGE_MEDUSA_TEST_ADMIN_PASSWORD"
    )):
        pytest.skip("requires isolated Medusa identity environment")
    root = Path(os.environ.get("MSDSS_ROOT", Path(__file__).resolve().parents[2] / "MSDSS"))
    if not (root / "sentinel/gateway/app.py").is_file() or not shutil.which("openssl"):
        pytest.skip("requires MSDSS checkout and openssl")
    monkeypatch.syspath_prepend(str(root))
    monkeypatch.syspath_prepend(str(root / "src"))
    # Gateway 可能已由較早的 lifespan 測試載入；每次測試自行宣告模型副本依賴路徑，
    # 不依賴首次 import 對 sys.path 的副作用仍存在。
    monkeypatch.syspath_prepend(str(root / "sentinel" / "model"))
    from sentinel.gateway.app import app
    from msdss.adapters.attack_assessment import AssessmentScope
    from msdss.decision.policy import DecisionPolicy
    from integrations.msdss.trusted_session_dispatch import SessionBinding, TrustedSessionDispatcher

    cert, key = tmp_path / "cert.pem", tmp_path / "tls.pem"
    config = tmp_path / "openssl.cnf"
    config.write_text("[req]\ndistinguished_name=dn\n[dn]\n", encoding="ascii")
    subprocess.run(["openssl", "req", "-config", str(config), "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
                    "-out", str(cert), "-keyout", str(key)], check=True, capture_output=True)
    signing = Ed25519PrivateKey.generate()
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    def start_receiver():
        """以同一監聽位址啟動新的接收程序，確保重送時的 HTTP 綁定完全相同。"""
        target = serve_pipeline if full_pipeline else serve_receiver
        arguments = (listener, cert, key, signing.public_key().public_bytes_raw())
        if full_pipeline == "native":
            arguments += (True,)
        worker = multiprocessing.get_context("spawn").Process(target=target, args=arguments)
        worker.start()
        return worker

    process = start_receiver()
    # 每輪使用新身份，同一案例的兩個接收程序仍共用它；不可續期舊測試留下的過期世界。
    server_session_id = "server-session-" + uuid4().hex

    class Predictor:
        def predict(self, request):
            """提供合成分類結果以走過 Gateway 實際決策與 dispatcher 分支。"""
            return dict(label="sqli", probabilities=dict(normal=0., sqli=1., xss=0.),
                        mode="live", exploratory=False)

    async def run():
        """注入短期 TLS 信任與測試綁定，分別驗證缺少身份及有效身份。"""
        nonlocal process, listener
        scope = AssessmentScope(source_id="detector", environment_id="lab", deployment_id="test",
                                service_id="shop", site_id="site")
        if full_pipeline:
            scope = AssessmentScope(source_id="local-demo-detector", environment_id="isolated-demo",
                                    deployment_id="isolated-demo", service_id="synthetic-store", site_id="demo-store")
        async with httpx.AsyncClient(verify=ssl.create_default_context(cafile=str(cert)),
                                     trust_env=False, timeout=30) as client:
            identity = None
            visitor_headers = {}
            if full_pipeline == "medusa":
                from deception.security.medusa_identity import IdentitySessions, MedusaIdentityProvider
                from test_medusa_live import create_test_customer

                async with httpx.AsyncClient(trust_env=False, timeout=15) as identity_client:
                    publishable, bearer = await create_test_customer(
                        identity_client, os.environ["MIRAGE_MEDUSA_TEST_ORIGIN"],
                        os.environ["MIRAGE_MEDUSA_TEST_ADMIN_EMAIL"], os.environ["MIRAGE_MEDUSA_TEST_ADMIN_PASSWORD"])
                identity = MedusaIdentityProvider(client=client, origin=os.environ["MIRAGE_MEDUSA_TEST_ORIGIN"],
                    publishable_key=publishable, identity_key=os.urandom(32),
                    sessions=IdentitySessions(os.environ["MIRAGE_POSTGRES_TEST_DSN"]),
                    environment_id=scope.environment_id, deployment_id=scope.deployment_id, allow_loopback_http=True)
                visitor_headers = {"authorization": bearer}
            if full_pipeline == "anonymous":
                from deception.security.anonymous_identity import AnonymousGroups, AnonymousIdentityProvider

                identity = AnonymousIdentityProvider(key=os.urandom(32),
                    groups=AnonymousGroups(os.environ["MIRAGE_POSTGRES_TEST_DSN"]),
                    environment_id=scope.environment_id, deployment_id=scope.deployment_id)
            dispatcher = TrustedSessionDispatcher(private_key=signing, kid="key", issuer="gw",
                audience="mirage", scope=scope, mirage_origin=f"https://127.0.0.1:{port}", identity_provider=identity)
            for name, value in dict(client=client, analysis_lock=asyncio.Lock(), analysis_task=None,
                analysis_timeout=3, predictor=Predictor(), deception_dispatcher=dispatcher,
                decision_policy=DecisionPolicy(enforcement_enabled=True, deception_approved=True)).items():
                monkeypatch.setattr(app.state, name, value, raising=False)
            if full_pipeline == "native":
                from integrations.msdss.gateway_bootstrap import GatewayIntegrationSettings, configure_gateway_state
                from deception.security.trusted_deployment import TrustedDeploymentSettings
                monkeypatch.delattr(app.state, "deception_dispatcher")
                configuration = GatewayIntegrationSettings(deployment=TrustedDeploymentSettings(
                    issuer="gw", audience="mirage", environment_id=scope.environment_id,
                    deployment_id=scope.deployment_id, source_id=scope.source_id, service_id=scope.service_id,
                    site_id=scope.site_id, public_keys={"key": signing.public_key().public_bytes_raw().hex()}),
                    kid="key", mirage_origin=f"https://127.0.0.1:{port}", medusa_origin="https://identity.invalid",
                    enable_medusa_store=True, enforcement_enabled=True, deception_approved=True)
                from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
                configure_gateway_state(app.state, settings=configuration,
                    postgres_dsn=os.environ["MIRAGE_POSTGRES_TEST_DSN"], identity_key=os.urandom(32),
                    signing_key=signing.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
                    publishable_key="pk_synthetic_native")
                dispatcher = app.state.deception_dispatcher
            binding = SessionBinding(scope.environment_id, scope.deployment_id, server_session_id, 3)
            async def gateway(scope, receive, send):
                """由測試主機在請求私有 state 提供可信綁定，以實際 Gateway app 處理。"""
                scope["state"] = {"trusted_session_binding": binding} if binding else {}
                await app(scope, receive, send)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway),
                                         base_url="http://gateway.test") as visitor:
                if full_pipeline == "native":
                    info = (await client.get(f"{dispatcher.origin}/demo/info")).json()
                    headers = {"x-publishable-api-key": "pk_synthetic_native", "idempotency-key": "native-wire-create"}
                    created = await visitor.post("/store/carts", json={}, headers=headers)
                    assert created.status_code == 200, created.text
                    cart_id = created.json()["cart"]["id"]
                    assert (await visitor.post("/store/carts", json={}, headers=headers)).json() == created.json()
                    headers["idempotency-key"] = "native-wire-add"
                    added = await visitor.post(f"/store/carts/{cart_id}/line-items", headers=headers,
                        json={"variant_id": info["variants"][0]["id"], "quantity": 1})
                    assert added.status_code == 200, added.text
                    assert added.json()["cart"]["total"] == info["variants"][0]["unit_price"] / 100
                    completed = await visitor.post(f"/store/carts/{cart_id}/complete", headers=headers)
                    assert completed.status_code == 200, completed.text
                    assert completed.json()["type"] == "order"
                    order_id = completed.json()["order"]["id"]
                    retrieved = await visitor.get(f"/store/orders/{order_id}", headers=headers)
                    assert retrieved.status_code == 200 and retrieved.json()["order"] == completed.json()["order"]
                    assert "set-cookie" not in retrieved.headers
                    return
                if full_pipeline:
                    info = (await client.get(f"{dispatcher.origin}/demo/info")).json()
                    assert info["assessment_mode"] == "session_world"
                    product_id = info["product_ids"][0]
                    path = f"/api/products/{product_id}"
                    captured = []

                    async def capture(request):
                        """在記憶體保留本次合成簽章請求，以便原樣送給第二個程序。"""
                        if request.url.port == port:
                            captured.append(request)

                    client.event_hooks["request"].append(capture)
                    response = await visitor.get(path, headers=visitor_headers)
                    assert response.status_code == 200, response.text
                    assert response.json()["product"]["id"] == product_id
                    client.event_hooks["request"].remove(capture)
                    signed, = captured
                    process.terminate()
                    process.join(5)
                    assert not process.is_alive()
                    listener.close()
                    listener = socket.socket()
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    listener.bind(("127.0.0.1", port))
                    listener.listen()
                    process = start_receiver()
                    wait_ready()
                    replay = await client.send(signed)
                    assert replay.status_code == 503
                    assert replay.json()["code"] == "pipeline_unavailable"
                    assert (await visitor.get(path, headers=visitor_headers)).status_code == 200
                else:
                    response = await visitor.get("/check?item=1&item=2", headers={"x-session-id": "visitor"})
                    assert response.status_code == 200, response.text
                    assert response.json() == [server_session_id, 3, process.pid]
                binding = None
                if full_pipeline == "anonymous":
                    continued = await visitor.get(path, headers={"x-session-id": "visitor", "x-forwarded-for": "203.0.113.2"})
                    assert continued.status_code == 200
                    assert "set-cookie" not in continued.headers
                else:
                    assert (await visitor.get("/check", headers={"x-session-id": "visitor"})).status_code == 503

    def wait_ready():
        """等待新程序完成 TLS 與應用啟動，直到收到可識別的診斷回應。"""
        deadline = time.monotonic() + 90
        while True:
            try:
                with httpx.Client(verify=ssl.create_default_context(cafile=str(cert)), trust_env=False,
                                  timeout=1) as probe:
                    endpoint = "/healthz" if full_pipeline else "/ready-probe"
                    if probe.get(f"https://127.0.0.1:{port}{endpoint}").status_code == (200 if full_pipeline else 404):
                        break
            except httpx.TransportError:
                pass
            if not process.is_alive() or time.monotonic() >= deadline:
                pytest.fail("Mirage HTTPS receiver failed to start")
            time.sleep(0.1)

    try:
        wait_ready()
        asyncio.run(run())
    finally:
        process.terminate()
        process.join(5)
        listener.close()
