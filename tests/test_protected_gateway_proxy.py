"""G4 隔離候選：Client→Gateway→Verifier／Sender 雙 mTLS 原生回應與拒絕鏈。"""

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
    GatewayNativeProxyUnverifiable, create_gateway_native_proxy_candidate_app,
    serve_gateway_native_proxy_loopback_tls,
)
from deception.security.protected_rpc import (
    create_receipt_proxy_sender_candidate_app, serve_direct_verifier_mtls,
    serve_fixed_sender_mtls,
)
from deception.world import (PostgresCandidatePromoter, PostgresProtectedAuthorizer,
                             PostgresProtectedSender)
from test_protected_rpc_mtls import _issue_mtls_certificates, _unused_local_port
from test_protected_grant import _login, _seed
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
