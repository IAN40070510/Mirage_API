"""G4 Receipt-only Sender→Gateway 原生 HTTP 代理候選的封閉與真 PG 驗收。"""

import asyncio
from contextlib import nullcontext
import hashlib
import json
import multiprocessing
from pathlib import Path
import ssl
import time
from uuid import UUID, uuid4

import pytest
import httpx
from fastapi.testclient import TestClient

from deception.security.protected_rpc import (create_receipt_proxy_sender_candidate_app,
                                               serve_fixed_sender_mtls)
from deception.world import (AdmissionOperationResult, AdmissionState,
                             PostgresProtectedAuthorizer, PostgresProtectedSender,
                             ProtectedSendLease)
from deception.world.protected_send import ProtectedReceiptSendPin
from deception.world.transmission import response_envelope
from test_postgres_conformance import isolated_test_dsn
from test_protected_grant import _login, _promote, _seed
from test_protected_rpc_mtls import _issue_mtls_certificates, _unused_local_port


def _candidate_sender(monkeypatch, receipt_id: UUID, *, status: int = 409):
    """建立不觸碰資料庫的獨立 Sender 模擬，保留真 Lease 的單次語義。"""
    envelope = response_envelope(status, [("content-type", "application/json"),
                                          ("x-native-pin", "yes")],
                                 b'{"native":"preserved"}')
    owner = "protected-sender-" + receipt_id.hex
    pin = ProtectedReceiptSendPin("a" * 32, receipt_id, owner, "b" * 64,
                                  int(time.time()) + 120, envelope)
    sender = PostgresProtectedSender("postgresql://unused.invalid/proxy", expected_login="sender_only")
    state = {"lookups": 0, "starts": 0, "finishes": [], "lease": None}

    def resolve(receipt):
        """只讓精確 Receipt 被查出，不藉由 Gateway 修改任何 Pin。"""
        state["lookups"] += 1
        return pin if receipt == receipt_id else None

    def start(*, admission_id, receipt_id: UUID, owner,
              request_fingerprint, expected_envelope):
        """只允許第一次完全匹配的 StartSend，第二次只回拒絕。"""
        state["starts"] += 1
        assert (admission_id, receipt_id, owner, request_fingerprint,
                expected_envelope) == (pin.admission_id, pin.receipt_id, pin.send_owner,
                                       pin.request_fingerprint, pin.envelope_bytes)
        if state["lease"] is not None:
            return None
        state["lease"] = ProtectedSendLease(
            uuid4(), pin.admission_id, pin.send_owner, pin.receipt_id,
            pin.request_fingerprint, hashlib.sha256(envelope).hexdigest(),
            envelope, pin.transmission_deadline,
        )
        return state["lease"]

    def restore_window():
        """只模擬窗口成功持有；真 PG 鎖另有專門回歸驗收。"""
        return nullcontext()

    def finish(**kwargs):
        """保存唯一 Lease 的終態，不容許第二次 Finish。"""
        state["finishes"].append(kwargs)
        return AdmissionOperationResult.SUCCESS

    monkeypatch.setattr(sender, "resolve_authorized_receipt", resolve)
    monkeypatch.setattr(sender, "start_send", start)
    monkeypatch.setattr(sender, "known_restore_delivery_window", restore_window)
    monkeypatch.setattr(sender, "finish_send", finish)
    return sender, pin, state


def test_proxy_candidate_receipt_only_native_response_and_replay_denied(monkeypatch):
    """Gateway 只給 Receipt，Sender 寫出原生 409、headers、bytes；重放不可重起。"""
    receipt = uuid4()
    sender, pin, state = _candidate_sender(monkeypatch, receipt)
    app = create_receipt_proxy_sender_candidate_app(sender=sender)
    with TestClient(app, base_url="https://sender.local") as client:
        result = client.post("/internal/v1/emit-receipt", json={"receipt_id": str(receipt)})
        assert result.status_code == 409
        assert result.content == b'{"native":"preserved"}'
        assert result.headers["x-native-pin"] == "yes"
        assert state["starts"] == 1 and len(state["finishes"]) == 1
        assert state["finishes"][0]["outcome"] == AdmissionState.SEND_COMPLETED
        denied = client.post("/internal/v1/emit-receipt", json={"receipt_id": str(receipt)})
        assert denied.status_code == 503 and state["starts"] == 2
        assert len(state["finishes"]) == 1
        sealed = client.post("/internal/v1/send", json={"receipt_id": str(receipt)})
        assert sealed.status_code == 503 and state["starts"] == 2
    assert pin.receipt_id == receipt


@pytest.mark.parametrize("body", [
    b'{}', b'{"receipt_id":"malformed"}',
    b'{"receipt_id":"00000000-0000-0000-0000-000000000000"}',
    b'{"receipt_id":"x","owner":"runtime"}',
    b'{"receipt_id":"x","receipt_id":"x"}',
    b'{"receipt_id":NaN}', b'{"receipt_id":null}', b'[]', b'0',
])
def test_proxy_candidate_rejects_untrusted_fields_before_lease(monkeypatch, body):
    """重複鍵、非法 UUID、其他授權欄位及非物件 JSON 必須在查 Pin 前拒絕。"""
    sender, _, state = _candidate_sender(monkeypatch, uuid4())
    app = create_receipt_proxy_sender_candidate_app(sender=sender)
    with TestClient(app, base_url="https://sender.local") as client:
        response = client.post("/internal/v1/emit-receipt", content=body)
    assert response.status_code == 400
    assert state["starts"] == state["lookups"] == 0


def test_proxy_candidate_unauthorized_route_and_tls_deny_without_lease(monkeypatch):
    """不存在的 Receipt／非 HTTPS／錯路由及 QUERY 不能消費 Lease 或注入內容。"""
    receipt = uuid4()
    sender, _, state = _candidate_sender(monkeypatch, receipt)
    app = create_receipt_proxy_sender_candidate_app(sender=sender)
    with TestClient(app, base_url="https://sender.local") as client:
        unknown = client.post("/internal/v1/emit-receipt", json={"receipt_id": str(uuid4())})
        query = client.post("/internal/v1/emit-receipt?owner=runtime",
                            json={"receipt_id": str(receipt)})
        wrong_method = client.get("/internal/v1/emit-receipt")
    with TestClient(app, base_url="http://sender.local") as cleartext:
        plain = cleartext.post("/internal/v1/emit-receipt", json={"receipt_id": str(receipt)})
    assert (unknown.status_code, query.status_code, wrong_method.status_code,
            plain.status_code) == (503, 404, 404, 503)
    assert state["starts"] == 0


def test_proxy_candidate_unknown_commit_never_retries_or_emits_native_bytes(monkeypatch):
    """StartSend 的 COMMIT ACK 不明只回固定 503，不由代理執行第二次 StartSend。"""
    receipt = uuid4()
    sender, _, state = _candidate_sender(monkeypatch, receipt)

    def lose_ack(**kwargs):
        """假設資料庫交易可能已提交，模擬起送階段無法確認 ACK。"""
        state["starts"] += 1
        raise OSError("unknown commit outcome")

    monkeypatch.setattr(sender, "start_send", lose_ack)
    app = create_receipt_proxy_sender_candidate_app(sender=sender)
    with TestClient(app, base_url="https://sender.local") as client:
        result = client.post("/internal/v1/emit-receipt", json={"receipt_id": str(receipt)})
    assert result.status_code == 503
    assert result.json() == {"detail": "proxy_sender_delivery_unverifiable"}
    assert state["starts"] == 1 and state["finishes"] == []


def test_proxy_candidate_real_mtls_required_for_native_response(monkeypatch, tmp_path: Path):
    """真 TLS handshake 只允許專用 CA Client；匿名連線無法取得 Sender 原生 bytes。"""
    ca, cert, key, client_cert, client_key = _issue_mtls_certificates(tmp_path)
    receipt = uuid4()
    sender, _, state = _candidate_sender(monkeypatch, receipt)
    app = create_receipt_proxy_sender_candidate_app(sender=sender)
    port = _unused_local_port()
    worker = multiprocessing.Process(target=serve_fixed_sender_mtls, kwargs={
        "app": app, "host": "127.0.0.1", "port": port,
        "server_cert": cert, "server_key": key, "sender_client_ca": ca,
    })
    worker.start()
    try:
        context = ssl.create_default_context(cafile=str(ca))
        context.load_cert_chain(str(client_cert), str(client_key))
        with httpx.Client(verify=context, trust_env=False, timeout=2) as trusted:
            for _ in range(50):
                try:
                    response = trusted.post(f"https://127.0.0.1:{port}/internal/v1/emit-receipt",
                                            json={"receipt_id": str(receipt)})
                    break
                except httpx.ConnectError:
                    assert worker.is_alive(), "sender TLS worker terminated"
                    time.sleep(0.1)
            else:
                pytest.fail("candidate sender mTLS listener did not start")
            assert response.status_code == 409
            assert response.content == b'{"native":"preserved"}'
            assert response.headers["x-native-pin"] == "yes"
            repeat = trusted.post(f"https://127.0.0.1:{port}/internal/v1/emit-receipt",
                                  json={"receipt_id": str(receipt)})
            assert repeat.status_code == 503
        anonymous = ssl.create_default_context(cafile=str(ca))
        with httpx.Client(verify=anonymous, trust_env=False, timeout=2) as client:
            with pytest.raises(httpx.TransportError):
                client.post(f"https://127.0.0.1:{port}/internal/v1/emit-receipt",
                            json={"receipt_id": str(receipt)})
        # Forked worker 的 Lease state 只存在於子程序，不拿父程序 counter 當證據。
        assert state["starts"] == 0
    finally:
        worker.terminate()
        worker.join(timeout=5)
        if worker.is_alive():
            worker.kill()
            worker.join(timeout=5)


def test_proxy_candidate_partial_transport_failure_never_emits_second_start(monkeypatch):
    """原生 start 已交付而 body 斷線時僅標 partial，不能再補發 503。"""
    receipt = uuid4()
    sender, _, state = _candidate_sender(monkeypatch, receipt)
    app = create_receipt_proxy_sender_candidate_app(sender=sender)
    messages = []

    async def receive():
        """只供單次 POST 的完整 Receipt JSON 接收。"""
        return {"type": "http.request", "body": json.dumps({"receipt_id": str(receipt)}).encode(),
                "more_body": False}

    async def fail_on_body(message):
        """第一個 ASGI start 可見，第二個 body 被代理傳輸層拒絕。"""
        messages.append(message)
        if message["type"] == "http.response.body":
            raise OSError("proxy client write lost")

    scope = {"type": "http", "http_version": "1.1", "method": "POST", "scheme": "https",
             "path": "/internal/v1/emit-receipt", "raw_path": b"/internal/v1/emit-receipt",
             "query_string": b"", "root_path": "", "headers": []}
    with pytest.raises(OSError, match="proxy client write lost"):
        asyncio.run(app(scope, receive, fail_on_body))
    assert [message["type"] for message in messages] == [
        "http.response.start", "http.response.body"]
    assert state["starts"] == 1
    assert state["finishes"][0]["outcome"] == AdmissionState.SEND_PARTIAL_FAILURE


def test_receipt_only_proxy_resolves_real_pg_authorized_pin_without_creating_lease(isolated_test_dsn):
    """真 PG Grant 鏈只輸入 Receipt 查回不可變 Pin，且不預先消費 Send Lease。"""
    import psycopg

    seeded = _seed(isolated_test_dsn)
    assert _promote(isolated_test_dsn, seeded) == 1
    authorizer = PostgresProtectedAuthorizer(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    admission, owner = authorizer.authorize_promoted_receipt_once(seeded[3])
    sender = PostgresProtectedSender(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    pin = sender.resolve_authorized_receipt(seeded[3])
    assert pin is not None
    assert (pin.admission_id, pin.receipt_id, pin.send_owner, pin.request_fingerprint,
            pin.transmission_deadline) == (
                admission.admission_id, seeded[3], owner, admission.request_binding_digest,
                admission.transmission_deadline)
    assert pin.envelope_bytes == response_envelope(
        200, [("content-type", "application/json")], b'{"synthetic":true}')
    assert sender.resolve_authorized_receipt(uuid4()) is None
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM protected_send_leases").fetchone() == (0,)
    app = create_receipt_proxy_sender_candidate_app(sender=sender)
    with TestClient(app, base_url="https://sender.local") as client:
        response = client.post("/internal/v1/emit-receipt", json={"receipt_id": str(seeded[3])})
        assert response.status_code == 200
        assert response.content == b'{"synthetic":true}'
        assert client.post("/internal/v1/emit-receipt", json={"receipt_id": str(seeded[3])}).status_code == 503
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM protected_send_leases").fetchone() == (1,)
        assert connection.execute("SELECT state FROM response_admissions WHERE admission_id=%s",
                                  (admission.admission_id,)).fetchone() == ("SEND_COMPLETED",)
