"""真實 PostgreSQL Key Guard／Replay／Ingress Receipt 單交易驗收。"""

import base64
import time
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deception.security import TrustedSessionError
from deception.security.ingress_receipt import IngressReceiptError, PostgresIngressReceiptWriter
from deception.api.fingerprint import fingerprint_request
from test_operation_binding import original_request
from deception.world import PostgresReplayStore
from deception.world.replay import ReplayConsumeResult
from test_key_revocation import verifier
from test_postgres_conformance import isolated_test_dsn
from test_trusted_session import encode


def signed(key, *, jti: str, reference_time: int | None = None,
           fingerprint: str = "a" * 64) -> str:
    """依目前時間簽發有效 JWS，讓 DB lock 後的權威時鐘檢查能實測。"""
    now = int(time.time()) if reference_time is None else reference_time
    prefix = encode(dict(alg="Ed25519", kid="old", protocol_version="1.1",
                         typ="mirage-trusted-session+jwt")) + "." + encode(dict(
        iss="gateway", aud="mirage", iat=now - 5, nbf=now - 5, exp=now + 45,
        jti=jti, environment_id="env", deployment_id="deploy", session_id="session",
        session_epoch=1, request_fingerprint=fingerprint, assessment_id="assessment",
        assessment_digest="b" * 64))
    return prefix + "." + base64.urlsafe_b64encode(key.sign(prefix.encode())).decode().rstrip("=")


def verify_with_receipt(checker, token, writer, *, now: int | None = None,
                        fingerprint: str = "a" * 64):
    """以固定測試環境對完整 JWS 驗章並產生同交易 Receipt。"""
    return checker.verify_with_receipt(token, expected_issuer="gateway", expected_audience="mirage",
                                       request_fingerprint=fingerprint, environment_id="env",
                                       deployment_id="deploy", receipt_writer=writer,
                                       now=int(time.time()) if now is None else now)


def test_ingress_receipt_is_atomic_with_replay_and_single_use(isolated_test_dsn):
    """有效 JWS 同時持久化 Replay 與 Receipt，重放不能建立第二份 Receipt。"""
    import psycopg

    private_key = Ed25519PrivateKey.generate()
    checker = verifier(isolated_test_dsn, {"old": private_key})
    writer = PostgresIngressReceiptWriter(isolated_test_dsn, environment_id="env", deployment_id="deploy")
    jti = uuid4().hex
    token = signed(private_key, jti=jti)
    claims, receipt_id = verify_with_receipt(checker, token, writer)
    assert claims.jti == jti
    with psycopg.connect(isolated_test_dsn) as connection:
        rows = connection.execute(
            """SELECT r.receipt_id, r.key_id, r.session_id, r.request_fingerprint,
                      e.jti FROM ingress_receipts r JOIN replay_entries e
                        ON (r.issuer, r.audience, r.jti) = (e.issuer, e.audience, e.jti)
               WHERE r.jti=%s""", (jti,)).fetchall()
    assert rows == [(receipt_id, "old", "session", "a" * 64, jti)]
    with pytest.raises(TrustedSessionError, match="replay"):
        verify_with_receipt(checker, token, writer)
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM ingress_receipts WHERE jti=%s", (jti,)).fetchone()[0] == 1


def test_verified_http_operation_is_atomic_with_ingress_receipt(isolated_test_dsn):
    """原始 HTTP Operation 與 JTI／Receipt 同交易提交；不匹配則一起回滾。"""
    import psycopg

    key = Ed25519PrivateKey.generate()
    checker = verifier(isolated_test_dsn, {"old": key})
    request = original_request()
    fingerprint = fingerprint_request(request)
    writer = PostgresIngressReceiptWriter(
        isolated_test_dsn, environment_id="env", deployment_id="deploy",
        verified_request=request,
    )
    jti = uuid4().hex
    _, receipt = verify_with_receipt(
        checker, signed(key, jti=jti, fingerprint=fingerprint), writer,
        fingerprint=fingerprint,
    )
    with psycopg.connect(isolated_test_dsn) as connection:
        row = connection.execute(
            """SELECT operation_id,method,path_template,request_fingerprint,
                      request_path,request_content_type
               FROM protected_http_operation_bindings WHERE receipt_id=%s""", (receipt,),
        ).fetchone()
        assert row == ("reserveSyntheticInventory", "POST", "/synthetic/inventory/reservations",
                       fingerprint, request.path, "application/json")
    wrong_jti = uuid4().hex
    with pytest.raises(IngressReceiptError, match="fingerprint_mismatch"):
        verify_with_receipt(
            checker, signed(key, jti=wrong_jti, fingerprint="a" * 64), writer,
            fingerprint="a" * 64,
        )
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM replay_entries WHERE jti=%s",
                                  (wrong_jti,)).fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM ingress_receipts WHERE jti=%s",
                                  (wrong_jti,)).fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM protected_http_operation_bindings").fetchone()[0] == 1


def test_ingress_receipt_failure_rolls_back_consumed_replay(isolated_test_dsn):
    """Receipt 寫入失敗時，同一連線已 INSERT 的 Replay 必須一同回滾。"""
    import psycopg

    private_key = Ed25519PrivateKey.generate()
    checker = verifier(isolated_test_dsn, {"old": private_key})
    jti = uuid4().hex
    token = signed(private_key, jti=jti)

    class FailingWriter(PostgresIngressReceiptWriter):
        """於 Replay 寫入成功後、Receipt 寫入前注入明確交易失敗。"""

        def _write_on_cursor(self, cursor, *, claims, kid):
            """在共享交易內故意拋錯，要求 Coordinator 自動 rollback。"""
            raise IngressReceiptError("injected_receipt_write_failure")

    failing = FailingWriter(isolated_test_dsn, environment_id="env", deployment_id="deploy")
    with pytest.raises(IngressReceiptError, match="injected_receipt_write_failure"):
        verify_with_receipt(checker, token, failing)
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM replay_entries WHERE jti=%s", (jti,)).fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM ingress_receipts WHERE jti=%s", (jti,)).fetchone()[0] == 0


def test_ingress_receipt_rejects_cross_database_writer_before_consumption(isolated_test_dsn):
    """Writer 與 Replay/Key Guard 不同 DSN 時，拒絕且不消費合法 JTI。"""
    import psycopg
    from deception.security.key_revocation import KeyRevocationError

    private_key = Ed25519PrivateKey.generate()
    checker = verifier(isolated_test_dsn, {"old": private_key})
    jti = uuid4().hex
    writer = PostgresIngressReceiptWriter("postgresql://different.invalid/db",
                                          environment_id="env", deployment_id="deploy")
    with pytest.raises(KeyRevocationError, match="same_postgres_connection_domain"):
        verify_with_receipt(checker, signed(private_key, jti=jti), writer)
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM replay_entries WHERE jti=%s", (jti,)).fetchone()[0] == 0


def test_ingress_receipt_rejects_revoked_key_without_consuming_jti(isolated_test_dsn):
    """Key Revocation 在 IngressTx 前已提交時，不能得到 Receipt 或消費 Replay。"""
    import psycopg
    from deception.security.key_revocation import PostgresTrustedKeyRevocations

    private_key = Ed25519PrivateKey.generate()
    checker = verifier(isolated_test_dsn, {"old": private_key})
    writer = PostgresIngressReceiptWriter(isolated_test_dsn, environment_id="env", deployment_id="deploy")
    jti = uuid4().hex
    PostgresTrustedKeyRevocations(isolated_test_dsn, environment_id="env",
                                   deployment_id="deploy").revoke("gateway", "old", revision=1)
    with pytest.raises(TrustedSessionError, match="trusted_key_revoked"):
        verify_with_receipt(checker, signed(private_key, jti=jti), writer)
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM replay_entries WHERE jti=%s", (jti,)).fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM ingress_receipts WHERE jti=%s", (jti,)).fetchone()[0] == 0


def test_ingress_receipt_rechecks_db_clock_after_key_lock(isolated_test_dsn):
    """即使 Runtime 偽造舊 Python now，資料庫時間仍拒絕已過期的 Receipt。"""
    import psycopg
    from deception.security.key_revocation import KeyRevocationError

    key = Ed25519PrivateKey.generate()
    checker = verifier(isolated_test_dsn, {"old": key})
    writer = PostgresIngressReceiptWriter(isolated_test_dsn, environment_id="env", deployment_id="deploy")
    jti = uuid4().hex
    forged_now = int(time.time()) - 120
    with pytest.raises(KeyRevocationError, match="ingress_receipt_db_time_invalid"):
        verify_with_receipt(checker, signed(key, jti=jti, reference_time=forged_now), writer, now=forged_now)
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM replay_entries WHERE jti=%s", (jti,)).fetchone()[0] == 0


def test_replay_gc_preserves_ingress_receipt_evidence_and_cleans_unreferenced(isolated_test_dsn):
    """Replay GC 不被 Receipt FK 阻塞所有過期清理，也不得刪掉可信引用墓碑。"""
    import psycopg

    key = Ed25519PrivateKey.generate()
    checker = verifier(isolated_test_dsn, {"old": key})
    writer = PostgresIngressReceiptWriter(isolated_test_dsn, environment_id="env", deployment_id="deploy")
    retained_jti, unbound_jti = uuid4().hex, uuid4().hex
    verify_with_receipt(checker, signed(key, jti=retained_jti), writer)
    replay = PostgresReplayStore(isolated_test_dsn)
    now = int(time.time())
    assert replay.consume(issuer="gateway", audience="mirage", jti=unbound_jti,
                          expires_at=now + 20, now=now) is ReplayConsumeResult.ACCEPTED
    assert replay.gc(now=now + 100) == 1
    with psycopg.connect(isolated_test_dsn) as connection:
        jtis = {row[0] for row in connection.execute("SELECT jti FROM replay_entries WHERE jti=ANY(%s)",
                                                     ([retained_jti, unbound_jti],))}
    assert jtis == {retained_jti}
