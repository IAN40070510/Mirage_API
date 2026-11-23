"""G4 獨立 Sender 的精確 Payload Pin、一次性 Lease 與真 ASGI 發送前守衛。"""

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from uuid import uuid4

import pytest

from deception.api.fingerprint import fingerprint_request
from deception.core.renderer import ResponseRenderer
from deception.world import (
    AdmissionOperationResult, AdmissionState, PostgresProtectedAuthorizer,
    PostgresProtectedSender, ProtectedLeaseTransmission, ProtectedSendLease,
)
from deception.world.transmission import TransmissionError, response_envelope, response_hashes
from test_protected_grant import _grant, _login, _promote, _seed
from test_renderer import pipeline_result, render_request
from test_candidate_handoff import candidate_and_gate
from test_postgres_conformance import isolated_test_dsn


def _authorized_pin(dsn):
    """以真 PostgreSQL Promotion→Grant→Claim→Authorize 建立單次 Sender 測試資料。"""
    seeded = _seed(dsn)
    _promote(dsn, seeded)
    admission = _grant(dsn, seeded)
    authorizer = PostgresProtectedAuthorizer(dsn, expected_login=_login(dsn))
    owner = "sender-lease-test"
    assert authorizer.claim(admission.admission_id, owner=owner) is AdmissionOperationResult.SUCCESS
    assert authorizer.authorize_send(admission.admission_id, owner=owner) is AdmissionOperationResult.SUCCESS
    envelope = response_envelope(200, [("content-type", "application/json")], b'{"synthetic":true}')
    return admission, owner, envelope, seeded


def test_single_send_lease_claims_exact_snapshot_and_never_rearms(isolated_test_dsn):
    """只有完整 Receipt／owner／fingerprint／bytes 相符可起送，完成後不可重拿 Lease。"""
    import psycopg

    admission, owner, envelope, seeded = _authorized_pin(isolated_test_dsn)
    sender = PostgresProtectedSender(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    args = dict(admission_id=admission.admission_id, receipt_id=seeded[3], owner=owner,
                request_fingerprint=admission.request_binding_digest, expected_envelope=envelope)
    assert sender.start_send(**{**args, "owner": "not-owner"}) is None
    assert sender.start_send(**{**args, "receipt_id": uuid4()}) is None
    assert sender.start_send(**{**args, "request_fingerprint": "b" * 64}) is None
    assert sender.start_send(**{**args, "expected_envelope": envelope + b"evil"}) is None
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT state FROM response_admissions WHERE admission_id=%s",
                                  (admission.admission_id,)).fetchone()[0] == "SEND_AUTHORIZED"
    lease = sender.start_send(**args)
    assert lease is not None and lease.receipt_id == seeded[3]
    assert lease.envelope_bytes == envelope and lease.candidate_hash == admission.candidate_hash
    assert sender.start_send(**args) is None
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM protected_send_leases").fetchone()[0] == 1
        assert connection.execute("SELECT state FROM response_admissions WHERE admission_id=%s",
                                  (admission.admission_id,)).fetchone()[0] == "SEND_STARTED"
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            connection.execute("UPDATE protected_send_leases SET send_owner='attacker' WHERE admission_id=%s",
                               (admission.admission_id,))
    terminal = dict(admission_id=admission.admission_id, owner=owner,
                    lease_id=lease.lease_id, outcome=AdmissionState.SEND_COMPLETED, attempted=True)
    assert sender.finish_send(**{**terminal, "lease_id": uuid4()}) is AdmissionOperationResult.REJECTED
    assert sender.finish_send(**terminal) is AdmissionOperationResult.SUCCESS
    assert sender.finish_send(**terminal) is AdmissionOperationResult.REJECTED
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute(
            "SELECT sequence,event_name FROM response_audit WHERE admission_id=%s ORDER BY sequence",
            (admission.admission_id,),
        ).fetchall() == [(0, "send_started"), (1, "response_send_attempted"), (2, "asgi_send_completed")]


def test_send_lease_insert_error_rolls_back_send_started(isolated_test_dsn):
    """單次 Lease 寫入失敗時，SEND_STARTED 和 send_started audit 均不可留下。"""
    import psycopg

    admission, owner, envelope, seeded = _authorized_pin(isolated_test_dsn)
    sender = PostgresProtectedSender(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    with psycopg.connect(isolated_test_dsn) as connection:
        connection.execute(
            """CREATE TRIGGER injected_lease_failure BEFORE INSERT ON protected_send_leases
               FOR EACH ROW EXECUTE FUNCTION reject_protected_mutation()""",
        )
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        sender.start_send(admission_id=admission.admission_id, receipt_id=seeded[3],
                          owner=owner,
                          request_fingerprint=admission.request_binding_digest,
                          expected_envelope=envelope)
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT state FROM response_admissions WHERE admission_id=%s",
                                  (admission.admission_id,)).fetchone()[0] == "SEND_AUTHORIZED"
        assert connection.execute("SELECT count(*) FROM protected_send_leases").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM response_audit").fetchone()[0] == 0


def test_concurrent_send_starts_only_one_lease(isolated_test_dsn):
    """兩個獨立 PostgreSQL 連線同時起送時，Row Lock＋唯一鍵只核准一方。"""
    import psycopg

    admission, owner, envelope, seeded = _authorized_pin(isolated_test_dsn)
    sender = PostgresProtectedSender(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    args = dict(admission_id=admission.admission_id, receipt_id=seeded[3], owner=owner,
                request_fingerprint=admission.request_binding_digest, expected_envelope=envelope)
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: sender.start_send(**args), range(2)))
    assert sum(lease is not None for lease in outcomes) == 1
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM protected_send_leases").fetchone()[0] == 1


def test_asgi_emits_nothing_without_valid_sender_lease(candidate_and_gate):
    """Renderer 在首個 ASGI start 前取得精確 Pin；重發和錯誤 Pin 都不外洩 bytes。"""
    candidate, gate = candidate_and_gate
    request = render_request()
    events = []

    class RecordingSender:
        """以隔離的預先核准 Pin 模擬 Sender，記錄 Lease 與 ASGI 訊息先後順序。"""

        def __init__(self):
            """控制本次測試提供相符或故意錯誤的已授權封套。"""
            self.corrupt = False
            self.wrong_receipt = False
            self.transport_failure = False

        def start_send(self, *, admission_id, receipt_id, owner, request_fingerprint,
                       expected_envelope):
            """只有精確封套存在才發放一次性測試 Lease，起送呼叫留下順序證據。"""
            events.append("lease")
            if self.transport_failure:
                raise ConnectionError("simulated COMMIT ACK loss")
            return ProtectedSendLease(
                lease_id=uuid4(), admission_id=admission_id, send_owner=owner,
                receipt_id=uuid4() if self.wrong_receipt else receipt_id,
                request_fingerprint=request_fingerprint,
                candidate_hash=admission.candidate_hash,
                envelope_bytes=(expected_envelope + b"attacker" if self.corrupt else expected_envelope),
                transmission_deadline=admission.transmission_deadline,
            )

        def finish_send(self, **kwargs):
            """確認 ASGI 已嘗試發送後才記錄持久化終態，模擬 DB 成功結果。"""
            events.append("finish")
            return AdmissionOperationResult.SUCCESS

    sender = RecordingSender()
    receipt = uuid4()

    def factory(final, normalized):
        """以最終 Candidate 精確 bytes 建立要求原始 Request Fingerprint 的測試 Lease。"""
        nonlocal admission
        hashes = response_hashes(final.status_code, final.headers, final.body_bytes)
        admission = SimpleNamespace(admission_id=uuid4().hex,
                                    request_binding_digest=fingerprint_request(normalized),
                                    candidate_hash=hashes[0], immutable_body_hash=hashes[1],
                                    semantic_headers_hash=hashes[2],
                                    transmission_deadline=int(time.time()) + 30)
        return ProtectedLeaseTransmission(sender=sender, admission=admission,
                                          receipt_id=receipt, owner="sender-1")

    admission = None
    response = ResponseRenderer(gate, transmission_factory=factory).render(
        pipeline_result(candidate, gate, request), request,
    )
    scope = {"type": "http", "method": request.method, "scheme": "https", "path": request.path,
             "raw_path": request.raw_path, "query_string": request.query_string,
             "headers": [(k.encode("latin-1"), v.encode("latin-1")) for k, v in request.headers],
             "server": ("shop.test", 443)}

    async def receive():
        """提供已處理的空 HTTP request，Sender 不重新讀取不可信 body。"""
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        """實際記下 ASGI start／body 的先後順序，供 Lease 原子性測試。"""
        events.append(message["type"])

    asyncio.run(response(scope, receive, send))
    assert events == ["lease", "http.response.start", "http.response.body", "finish"]
    with pytest.raises(TransmissionError, match="already_prepared"):
        asyncio.run(response(scope, receive, send))
    assert events == ["lease", "http.response.start", "http.response.body", "finish"]
    response2 = ResponseRenderer(gate, transmission_factory=factory).render(
        pipeline_result(candidate, gate, request), request,
    )
    sender.corrupt = True
    events.clear()
    with pytest.raises(TransmissionError, match="lease_refused"):
        asyncio.run(response2(scope, receive, send))
    assert events == ["lease"]
    with pytest.raises(TransmissionError, match="not_prepared_or_reused"):
        response2._transmission.start()
    assert events == ["lease"]
    response3 = ResponseRenderer(gate, transmission_factory=factory).render(
        pipeline_result(candidate, gate, request), request,
    )
    sender.corrupt = False
    sender.wrong_receipt = True
    events.clear()
    with pytest.raises(TransmissionError, match="lease_refused"):
        asyncio.run(response3(scope, receive, send))
    assert events == ["lease"]
    response4 = ResponseRenderer(gate, transmission_factory=factory).render(
        pipeline_result(candidate, gate, request), request,
    )
    sender.wrong_receipt = False
    sender.transport_failure = True
    events.clear()
    with pytest.raises(ConnectionError, match="COMMIT ACK loss"):
        asyncio.run(response4(scope, receive, send))
    with pytest.raises(TransmissionError, match="not_prepared_or_reused"):
        response4._transmission.start()
    assert events == ["lease"]
