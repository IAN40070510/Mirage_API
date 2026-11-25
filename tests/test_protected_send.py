"""G4 獨立 Sender 的精確 Payload Pin、一次性 Lease 與真 ASGI 發送前守衛。"""

import asyncio
import os
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from deception.api.fingerprint import fingerprint_request
from deception.core.renderer import ResponseRenderer
from deception.world import (
    AdmissionOperationResult, AdmissionState, PostgresProtectedAuthorizer,
    PostgresKnownRestoreRecorder, PostgresProtectedSender, PostgresProtectedSnapshotPurger,
    ProtectedGrantError, ProtectedLeaseTransmission, ProtectedPinnedASGIResponse,
    ProtectedSendLease,
    ProtectedSendReconciliation,
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


def _lose_commit_ack_after_database_commit(monkeypatch, actor):
    """先確實提交真 PostgreSQL 交易，再讓呼叫端收到模擬的 COMMIT ACK 遺失。"""
    import psycopg

    original_connection = actor._connection

    class LostCommitAcknowledgement:
        """攔截單次受保護連線的 context exit，保留已成功提交的資料。"""

        def __enter__(self):
            """開啟受保護的真連線，由原方法完成物理登入身分檢查。"""
            self.connection = original_connection()
            return self.connection

        def __exit__(self, error_type, error, traceback):
            """對成功操作先 COMMIT 再故意遺失 ACK；失敗操作正常回滾。"""
            try:
                if error_type is not None:
                    self.connection.rollback()
                    return False
                self.connection.commit()
                raise psycopg.OperationalError("simulated_commit_ack_lost")
            finally:
                self.connection.close()

    monkeypatch.setattr(actor, "_connection", LostCommitAcknowledgement)


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


def test_pinned_sender_emits_original_native_asgi_only_after_committed_lease(isolated_test_dsn):
    """真 PG Lease 已提交後，Sender 才發出 DB Pin 的原生 HTTP 與完全相同的 body bytes。"""
    import psycopg

    admission, owner, envelope, seeded = _authorized_pin(isolated_test_dsn)
    sender = PostgresProtectedSender(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    response = ProtectedPinnedASGIResponse(
        sender=sender, admission_id=admission.admission_id, receipt_id=seeded[3],
        owner=owner, request_fingerprint=admission.request_binding_digest,
        expected_envelope=envelope,
    )
    messages = []

    async def record(message):
        """在 ASGI 第一訊息時驗證資料庫已存在唯一 Lease 與必要 Audit。"""
        if not messages:
            with psycopg.connect(isolated_test_dsn) as connection:
                assert connection.execute(
                    "SELECT state FROM response_admissions WHERE admission_id=%s",
                    (admission.admission_id,),
                ).fetchone() == ("SEND_STARTED",)
                assert connection.execute("SELECT count(*) FROM protected_send_leases").fetchone() == (1,)
                assert connection.execute(
                    "SELECT event_name FROM response_audit WHERE admission_id=%s AND sequence=0",
                    (admission.admission_id,),
                ).fetchone() == ("send_started",)
        messages.append(message)

    asyncio.run(response({"type": "http", "scheme": "https"}, None, record))
    assert messages == [
        {"type": "http.response.start", "status": 200,
         "headers": [(b"content-type", b"application/json")]},
        {"type": "http.response.body", "body": b'{"synthetic":true}'},
    ]
    with pytest.raises(TransmissionError, match="protected_pinned_asgi_reused"):
        asyncio.run(response({"type": "http", "scheme": "https"}, None, record))
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute(
            "SELECT state FROM response_admissions WHERE admission_id=%s",
            (admission.admission_id,),
        ).fetchone() == ("SEND_COMPLETED",)
        assert connection.execute("SELECT count(*) FROM protected_send_leases").fetchone() == (1,)


def test_pinned_sender_partial_asgi_failure_keeps_lease_nonretryable(isolated_test_dsn):
    """真 PostgreSQL 首個 ASGI 訊息後 Body 傳輸失敗，保留不可重發的部分失敗終態。"""
    import psycopg

    admission, owner, envelope, seeded = _authorized_pin(isolated_test_dsn)
    sender = PostgresProtectedSender(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    selectors = dict(admission_id=admission.admission_id, receipt_id=seeded[3],
                     owner=owner, request_fingerprint=admission.request_binding_digest)
    response = ProtectedPinnedASGIResponse(
        sender=sender, expected_envelope=envelope, **selectors,
    )
    messages = []

    async def fail_on_body(message):
        """保留已輸出的 Header，再模擬 Body 的非同步傳輸通道失敗。"""
        if message["type"] == "http.response.body":
            raise ConnectionError("simulated_body_send_failure")
        messages.append(message)

    with pytest.raises(ConnectionError, match="simulated_body_send_failure"):
        asyncio.run(response({"type": "http", "scheme": "https"}, None, fail_on_body))
    assert len(messages) == 1 and messages[0]["type"] == "http.response.start"
    observation = sender.reconcile_send(**selectors)
    assert observation == ProtectedSendReconciliation(
        "TERMINAL_RECORDED", AdmissionState.SEND_PARTIAL_FAILURE, True)
    assert not observation.retry_permitted
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM protected_send_leases").fetchone() == (1,)
        assert connection.execute(
            "SELECT sequence,event_name,outcome FROM response_audit "
            "WHERE admission_id=%s ORDER BY sequence", (admission.admission_id,),
        ).fetchall() == [
            (0, "send_started", None), (1, "response_send_attempted", None),
            (2, "asgi_send_failed", AdmissionState.SEND_PARTIAL_FAILURE.value),
        ]
    assert sender.start_send(**selectors, expected_envelope=envelope) is None


def test_pinned_sender_denies_untrusted_transport_and_restore_before_first_asgi(isolated_test_dsn):
    """HTTPS 缺失或已知 Restore 均必須零 ASGI 訊息、零新 Lease，且不可重用回應實例。"""
    import psycopg

    admission, owner, envelope, seeded = _authorized_pin(isolated_test_dsn)
    login = _login(isolated_test_dsn)
    sender = PostgresProtectedSender(isolated_test_dsn, expected_login=login)
    selectors = dict(admission_id=admission.admission_id, receipt_id=seeded[3],
                     owner=owner, request_fingerprint=admission.request_binding_digest)
    messages = []

    async def record(message):
        """任何被拒絕的 Sender 路徑都不准呼叫這個 ASGI 傳輸函式。"""
        messages.append(message)

    untrusted = ProtectedPinnedASGIResponse(
        sender=sender, expected_envelope=envelope, **selectors,
    )
    with pytest.raises(TransmissionError, match="protected_pinned_asgi_tls_required"):
        asyncio.run(untrusted({"type": "http", "scheme": "http"}, None, record))
    with pytest.raises(TransmissionError, match="protected_pinned_asgi_reused"):
        asyncio.run(untrusted({"type": "http", "scheme": "https"}, None, record))
    recorder = PostgresKnownRestoreRecorder(isolated_test_dsn, expected_login=login)
    assert recorder.mark_known_restore(uuid4())
    quarantined = ProtectedPinnedASGIResponse(
        sender=sender, expected_envelope=envelope, **selectors,
    )
    with pytest.raises(TransmissionError, match="protected_pinned_asgi_lease_refused"):
        asyncio.run(quarantined({"type": "http", "scheme": "https"}, None, record))
    assert messages == []
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM protected_send_leases").fetchone() == (0,)
        assert connection.execute(
            "SELECT state FROM response_admissions WHERE admission_id=%s",
            (admission.admission_id,),
        ).fetchone() == ("SEND_AUTHORIZED",)


def test_known_local_restore_blocks_future_send_lease_persistently(isolated_test_dsn):
    """已知 Restore 事件一旦落盤，換 Sender 連線或重啟仍不得取得新的 Lease。"""
    import psycopg

    admission, owner, envelope, seeded = _authorized_pin(isolated_test_dsn)
    login = _login(isolated_test_dsn)
    recorder = PostgresKnownRestoreRecorder(isolated_test_dsn, expected_login=login)
    event_id = uuid4()
    assert recorder.mark_known_restore(event_id)
    assert not recorder.mark_known_restore(event_id)
    assert recorder.mark_known_restore(uuid4())
    with pytest.raises(ProtectedGrantError, match="known_restore_event_id_invalid"):
        recorder.mark_known_restore(UUID(int=0))
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM protected_local_restore_events").fetchone() == (2,)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            connection.execute("DELETE FROM protected_local_restore_events")
    sender = PostgresProtectedSender(isolated_test_dsn, expected_login=login)
    assert sender.start_send(
        admission_id=admission.admission_id, receipt_id=seeded[3], owner=owner,
        request_fingerprint=admission.request_binding_digest, expected_envelope=envelope,
    ) is None
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT state FROM response_admissions WHERE admission_id=%s",
                                  (admission.admission_id,)).fetchone() == ("SEND_AUTHORIZED",)
        assert connection.execute("SELECT count(*) FROM protected_send_leases").fetchone() == (0,)


def test_known_restore_commit_ack_lost_remains_quarantined_and_idempotent(isolated_test_dsn,
                                                                           monkeypatch):
    """真實事件已 COMMIT 但 Recorder 收到失敗時，同 ID 重查仍不得解除隔離。"""
    import psycopg

    admission, owner, envelope, seeded = _authorized_pin(isolated_test_dsn)
    login = _login(isolated_test_dsn)
    event_id = uuid4()
    recorder = PostgresKnownRestoreRecorder(isolated_test_dsn, expected_login=login)
    _lose_commit_ack_after_database_commit(monkeypatch, recorder)
    with pytest.raises(psycopg.OperationalError, match="simulated_commit_ack_lost"):
        recorder.mark_known_restore(event_id)
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute(
            "SELECT restore_event_id FROM protected_local_restore_events"
        ).fetchall() == [(event_id,)]
    restarted = PostgresKnownRestoreRecorder(isolated_test_dsn, expected_login=login)
    assert not restarted.mark_known_restore(event_id)
    sender = PostgresProtectedSender(isolated_test_dsn, expected_login=login)
    assert sender.start_send(
        admission_id=admission.admission_id, receipt_id=seeded[3], owner=owner,
        request_fingerprint=admission.request_binding_digest, expected_envelope=envelope,
    ) is None
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM protected_local_restore_events").fetchone() == (1,)
        assert connection.execute("SELECT count(*) FROM protected_send_leases").fetchone() == (0,)


def test_known_restore_recorder_and_sender_use_distinct_real_scram_acl(isolated_test_dsn):
    """真正隔離的 Recorder 僅可 INSERT，Sender 僅可 SELECT，不得切換對方角色。"""
    if os.environ.get("MIRAGE_WORLD_ROLE_TEST_ISOLATED") != "true":
        pytest.skip("requires disposable PostgreSQL cluster for login role creation")
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    roles = {name: (f"mirage_restore_{name}_{uuid4().hex[:10]}", secrets.token_urlsafe(32))
             for name in ("recorder", "sender")}
    schema = conninfo_to_dict(isolated_test_dsn)["options"].split("search_path=", 1)[1].split(" ", 1)[0]
    with psycopg.connect(isolated_test_dsn, autocommit=True) as admin:
        try:
            for role, password in roles.values():
                admin.execute(sql.SQL("CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER "
                                      "NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD {}").format(
                                          sql.Identifier(role), sql.Literal(password)))
                admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                    sql.Identifier(schema), sql.Identifier(role)))
            admin.execute(sql.SQL("GRANT INSERT ON protected_local_restore_events TO {}").format(
                sql.Identifier(roles["recorder"][0])))
            admin.execute(sql.SQL("GRANT SELECT ON protected_local_restore_events TO {}").format(
                sql.Identifier(roles["sender"][0])))
            dsn = {name: make_conninfo(isolated_test_dsn, user=role, password=password)
                   for name, (role, password) in roles.items()}
            recorder = PostgresKnownRestoreRecorder(dsn["recorder"],
                                                     expected_login=roles["recorder"][0])
            event_id = uuid4()
            assert recorder.mark_known_restore(event_id)
            assert not recorder.mark_known_restore(event_id)
            with psycopg.connect(dsn["recorder"]) as connection:
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    connection.execute("SELECT count(*) FROM protected_local_restore_events")
            with psycopg.connect(dsn["sender"]) as connection:
                assert connection.execute(
                    "SELECT count(*) FROM protected_local_restore_events").fetchone() == (1,)
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    connection.execute("INSERT INTO protected_local_restore_events VALUES (%s)",
                                       (uuid4(),))
            with psycopg.connect(dsn["sender"]) as connection:
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    connection.execute(sql.SQL("SET ROLE {}").format(
                        sql.Identifier(roles["recorder"][0])))
        finally:
            for role, _ in roles.values():
                admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
                admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


def test_known_restore_lock_serializes_concurrent_sender_start(isolated_test_dsn):
    """Restore 排他交易鎖先取得時，並行 StartSend 必等事件提交並拒絕新 Lease。"""
    import psycopg

    admission, owner, envelope, seeded = _authorized_pin(isolated_test_dsn)
    sender = PostgresProtectedSender(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    args = dict(admission_id=admission.admission_id, receipt_id=seeded[3], owner=owner,
                request_fingerprint=admission.request_binding_digest, expected_envelope=envelope)
    with ThreadPoolExecutor(max_workers=1) as pool:
        with psycopg.connect(isolated_test_dsn) as mark_transaction:
            mark_transaction.execute("SELECT pg_advisory_xact_lock(%s,%s)",
                                     (1296650823, 1380275028))
            pending = pool.submit(sender.start_send, **args)
            time.sleep(0.1)
            assert not pending.done()
            mark_transaction.execute("INSERT INTO protected_local_restore_events "
                                     "(restore_event_id) VALUES (%s)", (uuid4(),))
        assert pending.result(timeout=8) is None
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM protected_send_leases").fetchone() == (0,)
        assert connection.execute("SELECT state FROM response_admissions WHERE admission_id=%s",
                                  (admission.admission_id,)).fetchone() == ("SEND_AUTHORIZED",)


def test_known_restore_database_trigger_blocks_legacy_sender_sql(isolated_test_dsn):
    """即使舊 Sender 不做 Python Restore 查核，原本直接寫 Lease 的交易仍須回滾。"""
    import psycopg

    admission, owner, _, seeded = _authorized_pin(isolated_test_dsn)
    recorder = PostgresKnownRestoreRecorder(
        isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    assert recorder.mark_known_restore(uuid4())
    with psycopg.connect(isolated_test_dsn) as connection:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="known restore quarantine"):
            connection.execute(
                "UPDATE response_admissions SET state='SEND_STARTED' WHERE admission_id=%s",
                (admission.admission_id,),
            )
            connection.execute(
                "INSERT INTO protected_send_leases ("
                "admission_id,lease_id,receipt_id,send_owner,request_fingerprint,"
                "candidate_hash,transmission_deadline) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (admission.admission_id, uuid4(), seeded[3], owner,
                 admission.request_binding_digest, admission.candidate_hash,
                 admission.transmission_deadline),
            )
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT state FROM response_admissions WHERE admission_id=%s",
                                  (admission.admission_id,)).fetchone() == ("SEND_AUTHORIZED",)
        assert connection.execute("SELECT count(*) FROM protected_send_leases").fetchone() == (0,)


def test_known_restore_trigger_allows_legacy_login_until_marker_and_ignores_temp_shadow(isolated_test_dsn):
    """舊 SCRAM Sender 不具 Marker SELECT 仍可正常起送，Restore 後同名 TEMP 表無法繞過 DB Fence。"""
    if os.environ.get("MIRAGE_WORLD_ROLE_TEST_ISOLATED") != "true":
        pytest.skip("requires disposable PostgreSQL cluster for login role creation")
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    first, owner, _, seeded_first = _authorized_pin(isolated_test_dsn)
    # 第二次使用不同的正式 Registry Contract，不能重複註冊 revision=1。
    seeded_second = _seed(isolated_test_dsn, contract_hash=uuid4().hex * 2)
    _promote(isolated_test_dsn, seeded_second)
    second = _grant(isolated_test_dsn, seeded_second)
    authorizer = PostgresProtectedAuthorizer(isolated_test_dsn,
                                            expected_login=_login(isolated_test_dsn))
    assert authorizer.claim(second.admission_id, owner=owner) is AdmissionOperationResult.SUCCESS
    assert authorizer.authorize_send(second.admission_id, owner=owner) is AdmissionOperationResult.SUCCESS
    admin_login = _login(isolated_test_dsn)
    role = "mirage_legacy_sender_" + uuid4().hex[:12]
    password = secrets.token_urlsafe(32)
    schema = conninfo_to_dict(isolated_test_dsn)["options"].split("search_path=", 1)[1].split(" ", 1)[0]
    with psycopg.connect(isolated_test_dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER "
                              "NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD {}").format(
                                  sql.Identifier(role), sql.Literal(password)))
        try:
            admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                sql.Identifier(schema), sql.Identifier(role)))
            admin.execute(sql.SQL("GRANT SELECT ON response_admissions TO {}").format(
                sql.Identifier(role)))
            admin.execute(sql.SQL("GRANT UPDATE (state) ON response_admissions TO {}").format(
                sql.Identifier(role)))
            admin.execute(sql.SQL("GRANT INSERT ON protected_send_leases,response_audit TO {}").format(
                sql.Identifier(role)))
            legacy_dsn = make_conninfo(isolated_test_dsn, user=role, password=password)
            with psycopg.connect(legacy_dsn) as connection:
                assert connection.execute(
                    "SELECT has_table_privilege('protected_local_restore_events','SELECT')"
                ).fetchone() == (False,)
                connection.execute("UPDATE response_admissions SET state='SEND_STARTED' "
                                   "WHERE admission_id=%s", (first.admission_id,))
                connection.execute(
                    "INSERT INTO protected_send_leases ("
                    "admission_id,lease_id,receipt_id,send_owner,request_fingerprint,"
                    "candidate_hash,transmission_deadline) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    (first.admission_id, uuid4(), seeded_first[3], owner,
                     first.request_binding_digest, first.candidate_hash,
                     first.transmission_deadline),
                )
                connection.execute(
                    "INSERT INTO response_audit (admission_id,sequence,event_name,final_response_hash) "
                    "VALUES (%s,0,'send_started',%s)", (first.admission_id, first.candidate_hash),
                )
            recorder = PostgresKnownRestoreRecorder(isolated_test_dsn,
                                                     expected_login=admin_login)
            assert recorder.mark_known_restore(uuid4())
            with psycopg.connect(legacy_dsn) as connection:
                connection.execute("CREATE TEMP TABLE protected_local_restore_events "
                                   "(restore_event_id UUID)")
                with pytest.raises(psycopg.errors.InsufficientPrivilege,
                                   match="known restore quarantine"):
                    connection.execute("UPDATE response_admissions SET state='SEND_STARTED' "
                                       "WHERE admission_id=%s", (second.admission_id,))
                    connection.execute(
                        "INSERT INTO protected_send_leases ("
                        "admission_id,lease_id,receipt_id,send_owner,request_fingerprint,"
                        "candidate_hash,transmission_deadline) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                        (second.admission_id, uuid4(), seeded_second[3], owner,
                         second.request_binding_digest, second.candidate_hash,
                         second.transmission_deadline),
                    )
            with psycopg.connect(isolated_test_dsn) as connection:
                assert connection.execute("SELECT count(*) FROM protected_send_leases").fetchone() == (1,)
                assert connection.execute(
                    "SELECT state FROM response_admissions WHERE admission_id=%s",
                    (second.admission_id,),
                ).fetchone() == ("SEND_AUTHORIZED",)
        finally:
            admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


def test_missing_local_restore_evidence_table_fails_closed(isolated_test_dsn):
    """本機隔離證據表缺失不能默認安全，StartSend 必拒絕且回滾全部起送動作。"""
    import psycopg

    admission, owner, envelope, seeded = _authorized_pin(isolated_test_dsn)
    with psycopg.connect(isolated_test_dsn) as connection:
        connection.execute("DROP TABLE protected_local_restore_events")
    sender = PostgresProtectedSender(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    with pytest.raises(psycopg.errors.UndefinedTable):
        sender.start_send(
            admission_id=admission.admission_id, receipt_id=seeded[3], owner=owner,
            request_fingerprint=admission.request_binding_digest, expected_envelope=envelope,
        )
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM protected_send_leases").fetchone() == (0,)
        assert connection.execute("SELECT state FROM response_admissions WHERE admission_id=%s",
                                  (admission.admission_id,)).fetchone() == ("SEND_AUTHORIZED",)


@pytest.mark.parametrize("field,changed", [
    ("admission_id", "forged-admission"),
    ("authorization_deadline", "earlier"),
    ("transmission_deadline", "later"),
])
def test_start_send_rejects_mismatched_admission_identity_or_deadlines(isolated_test_dsn, field, changed):
    """精確 Pin 仍在也不可對 Admission 原始身分或任何期限遭修改的記錄起送。"""
    import psycopg

    admission, owner, envelope, seeded = _authorized_pin(isolated_test_dsn)
    if changed == "earlier":
        changed_value = admission.authorization_deadline - 1
    elif changed == "later":
        changed_value = admission.transmission_deadline + 100
    else:
        changed_value = changed
    cast = "text" if changed == "forged-admission" else "bigint"
    with psycopg.connect(isolated_test_dsn) as connection:
        connection.execute(
            f"UPDATE response_admissions "
            f"SET admission=jsonb_set(admission,ARRAY[%s],to_jsonb(%s::{cast})) "
            f"WHERE admission_id=%s",
            (field, changed_value, admission.admission_id),
        )
    sender = PostgresProtectedSender(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    with pytest.raises(ProtectedGrantError, match="protected_send_pinned_payload_invalid"):
        sender.start_send(
            admission_id=admission.admission_id, receipt_id=seeded[3], owner=owner,
            request_fingerprint=admission.request_binding_digest, expected_envelope=envelope,
        )
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT state FROM response_admissions WHERE admission_id=%s",
                                  (admission.admission_id,)).fetchone() == ("SEND_AUTHORIZED",)
        assert connection.execute("SELECT count(*) FROM protected_send_leases").fetchone() == (0,)


def test_sender_reconciliation_is_readonly_and_never_reauthorizes_send(isolated_test_dsn):
    """模擬 COMMIT ACK 遺失，僅查可見 Lease／終態，不把查無 Lease 當安全重試。"""
    import psycopg

    admission, owner, envelope, seeded = _authorized_pin(isolated_test_dsn)
    sender = PostgresProtectedSender(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    selectors = dict(admission_id=admission.admission_id, receipt_id=seeded[3],
                     owner=owner, request_fingerprint=admission.request_binding_digest)
    before = sender.reconcile_send(**selectors)
    assert before == ProtectedSendReconciliation(
        "NO_LEASE_OBSERVED", AdmissionState.SEND_AUTHORIZED, False)
    assert not before.retry_permitted
    for forged in ({"owner": "forged"}, {"receipt_id": uuid4()},
                   {"request_fingerprint": "b" * 64}, {"admission_id": "missing-admission"}):
        denied = sender.reconcile_send(**{**selectors, **forged})
        assert denied.observation == "UNVERIFIABLE" and denied.state is None
        assert not denied.retry_permitted
    with pytest.raises(ProtectedGrantError, match="reconciliation_request_invalid"):
        sender.reconcile_send(**{**selectors, "request_fingerprint": "invalid"})
    lease = sender.start_send(**{**selectors, "expected_envelope": envelope})
    assert lease is not None
    started = sender.reconcile_send(**selectors)
    assert started == ProtectedSendReconciliation(
        "STARTED_DELIVERY_UNKNOWN", AdmissionState.SEND_STARTED, True)
    assert not started.retry_permitted
    assert sender.start_send(**{**selectors, "expected_envelope": envelope}) is None
    assert sender.finish_send(admission_id=admission.admission_id, owner=owner,
                              lease_id=lease.lease_id, outcome=AdmissionState.SEND_COMPLETED,
                              attempted=True) is AdmissionOperationResult.SUCCESS
    terminal = sender.reconcile_send(**selectors)
    assert terminal == ProtectedSendReconciliation(
        "TERMINAL_RECORDED", AdmissionState.SEND_COMPLETED, True)
    assert not terminal.retry_permitted
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM protected_send_leases").fetchone() == (1,)
        assert connection.execute(
            "SELECT sequence FROM response_audit WHERE admission_id=%s ORDER BY sequence",
            (admission.admission_id,),
        ).fetchall() == [(0,), (1,), (2,)]


def test_sender_commit_ack_lost_after_actual_lease_commit_never_resends(isolated_test_dsn,
                                                                          monkeypatch):
    """起送交易已真正提交但客戶端遺失 COMMIT ACK，只能觀察不明並保持一次性。"""
    import psycopg

    admission, owner, envelope, seeded = _authorized_pin(isolated_test_dsn)
    sender = PostgresProtectedSender(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    selectors = dict(admission_id=admission.admission_id, receipt_id=seeded[3],
                     owner=owner, request_fingerprint=admission.request_binding_digest)
    _lose_commit_ack_after_database_commit(monkeypatch, sender)
    with pytest.raises(psycopg.OperationalError, match="simulated_commit_ack_lost"):
        sender.start_send(**selectors, expected_envelope=envelope)
    restarted = PostgresProtectedSender(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    observation = restarted.reconcile_send(**selectors)
    assert observation == ProtectedSendReconciliation(
        "STARTED_DELIVERY_UNKNOWN", AdmissionState.SEND_STARTED, True)
    assert not observation.retry_permitted
    assert restarted.start_send(**selectors, expected_envelope=envelope) is None
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute(
            "SELECT state FROM response_admissions WHERE admission_id=%s",
            (admission.admission_id,),
        ).fetchone() == ("SEND_STARTED",)
        assert connection.execute("SELECT count(*) FROM protected_send_leases").fetchone() == (1,)
        assert connection.execute(
            "SELECT sequence,event_name FROM response_audit WHERE admission_id=%s",
            (admission.admission_id,),
        ).fetchall() == [(0, "send_started")]


@pytest.mark.parametrize("field", ["admission_id", "request_binding_digest", "candidate_hash",
                                   "world_generation_id", "candidate_ref"])
def test_sender_reconciliation_rejects_tampered_immutable_admission(isolated_test_dsn, field):
    """即使狀態仍顯示已授權，Admission JSON 與受保護 Pin 不一致就只能回不明。"""
    import psycopg

    admission, owner, _, seeded = _authorized_pin(isolated_test_dsn)
    sender = PostgresProtectedSender(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    selectors = dict(admission_id=admission.admission_id, receipt_id=seeded[3],
                     owner=owner, request_fingerprint=admission.request_binding_digest)
    assert sender.reconcile_send(**selectors).observation == "NO_LEASE_OBSERVED"
    wrong_value = "f" * 64 if field in {"candidate_hash", "request_binding_digest"} else "forged"
    with psycopg.connect(isolated_test_dsn) as connection:
        connection.execute(
            "UPDATE response_admissions SET admission=jsonb_set(admission,ARRAY[%s],to_jsonb(%s::text)) "
            "WHERE admission_id=%s", (field, wrong_value, admission.admission_id),
        )
    result = sender.reconcile_send(**selectors)
    assert result == ProtectedSendReconciliation("UNVERIFIABLE", None, False)
    assert not result.retry_permitted


def test_sender_reconciliation_rejects_mismatched_deadline(isolated_test_dsn):
    """不可變 Admission 期限遭竄改，唯讀對帳不可把可見的授權狀態當成安全證據。"""
    import psycopg

    admission, owner, _, seeded = _authorized_pin(isolated_test_dsn)
    sender = PostgresProtectedSender(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    with psycopg.connect(isolated_test_dsn) as connection:
        connection.execute(
            "UPDATE response_admissions "
            "SET admission=jsonb_set(admission,'{transmission_deadline}',to_jsonb(%s::bigint)) "
            "WHERE admission_id=%s",
            (admission.transmission_deadline + 100, admission.admission_id),
        )
    result = sender.reconcile_send(
        admission_id=admission.admission_id, receipt_id=seeded[3], owner=owner,
        request_fingerprint=admission.request_binding_digest,
    )
    assert result == ProtectedSendReconciliation("UNVERIFIABLE", None, False)
    assert not result.retry_permitted


def test_sender_reconciliation_uses_real_readonly_scram_login(isolated_test_dsn):
    """實體獨立 SELECT-only SCRAM Login 能對帳，不能起送、修改 Admission 或扮成管理者。"""
    if os.environ.get("MIRAGE_WORLD_ROLE_TEST_ISOLATED") != "true":
        pytest.skip("requires disposable PostgreSQL cluster for login role creation")
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    admission, owner, envelope, seeded = _authorized_pin(isolated_test_dsn)
    admin_login = _login(isolated_test_dsn)
    role = "mirage_reconcile_" + uuid4().hex[:12]
    password = secrets.token_urlsafe(32)
    schema = conninfo_to_dict(isolated_test_dsn)["options"].split("search_path=", 1)[1].split(" ", 1)[0]
    with psycopg.connect(isolated_test_dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB "
                              "NOCREATEROLE NOBYPASSRLS PASSWORD {}").format(
                                  sql.Identifier(role), sql.Literal(password)))
        try:
            admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                sql.Identifier(schema), sql.Identifier(role)))
            admin.execute(sql.SQL("GRANT SELECT ON response_admissions,"
                                  "protected_authorized_http_snapshots,protected_grant_bindings,"
                                  "protected_send_leases TO {}").format(sql.Identifier(role)))
            readonly_dsn = make_conninfo(isolated_test_dsn, user=role, password=password)
            readonly = PostgresProtectedSender(readonly_dsn, expected_login=role)
            selectors = dict(admission_id=admission.admission_id, receipt_id=seeded[3],
                             owner=owner, request_fingerprint=admission.request_binding_digest)
            observation = readonly.reconcile_send(**selectors)
            assert observation == ProtectedSendReconciliation(
                "NO_LEASE_OBSERVED", AdmissionState.SEND_AUTHORIZED, False)
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                readonly.start_send(**{**selectors, "expected_envelope": envelope})
            with psycopg.connect(readonly_dsn) as connection:
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    connection.execute("UPDATE response_admissions SET state='SEND_STARTED' "
                                       "WHERE admission_id=%s", (admission.admission_id,))
            with psycopg.connect(readonly_dsn) as connection:
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    connection.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(admin_login)))
        finally:
            admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


@pytest.mark.parametrize("outcome", [AdmissionState.SEND_FAILED,
                                     AdmissionState.SEND_PARTIAL_FAILURE])
def test_sender_reconciliation_records_failed_and_partial_terminal_without_retry(isolated_test_dsn, outcome):
    """ASGI 傳輸失敗／部分送出後的持久終態只能回報，不可重新取得 Lease。"""
    admission, owner, envelope, seeded = _authorized_pin(isolated_test_dsn)
    sender = PostgresProtectedSender(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    selectors = dict(admission_id=admission.admission_id, receipt_id=seeded[3],
                     owner=owner, request_fingerprint=admission.request_binding_digest)
    lease = sender.start_send(**{**selectors, "expected_envelope": envelope})
    assert lease is not None
    assert sender.finish_send(admission_id=admission.admission_id, owner=owner,
                              lease_id=lease.lease_id, outcome=outcome,
                              attempted=outcome is AdmissionState.SEND_PARTIAL_FAILURE,
                              ) is AdmissionOperationResult.SUCCESS
    observation = sender.reconcile_send(**selectors)
    assert observation == ProtectedSendReconciliation("TERMINAL_RECORDED", outcome, True)
    assert not observation.retry_permitted
    assert sender.start_send(**{**selectors, "expected_envelope": envelope}) is None


def test_irreversible_snapshot_purge_fence_denies_new_send_without_rewriting_grant(isolated_test_dsn):
    """先有 GC Fence 後 StartSend 必須拒絕，但原 Authorization／Bytes／Audit 不可被覆寫。"""
    import psycopg

    admission, owner, envelope, seeded = _authorized_pin(isolated_test_dsn)
    purger = PostgresProtectedSnapshotPurger(isolated_test_dsn,
                                             expected_login=_login(isolated_test_dsn))
    sender = PostgresProtectedSender(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    operation = uuid4()
    assert purger.fence_snapshot(admission_id=admission.admission_id, gc_operation_id=operation,
                                 purge_reason="retention_expired")
    assert purger.fence_snapshot(admission_id=admission.admission_id, gc_operation_id=operation,
                                 purge_reason="retention_expired")
    with pytest.raises(ProtectedGrantError, match="purge_rebound"):
        purger.fence_snapshot(admission_id=admission.admission_id, gc_operation_id=uuid4(),
                              purge_reason="snapshot_corrupt")
    assert sender.start_send(admission_id=admission.admission_id, receipt_id=seeded[3],
                             owner=owner, request_fingerprint=admission.request_binding_digest,
                             expected_envelope=envelope) is None
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute(
            "SELECT state FROM response_admissions WHERE admission_id=%s",
            (admission.admission_id,),
        ).fetchone() == ("SEND_AUTHORIZED",)
        assert bytes(connection.execute(
            "SELECT envelope_bytes FROM protected_authorized_http_snapshots WHERE admission_id=%s",
            (admission.admission_id,),
        ).fetchone()[0]) == envelope
        assert connection.execute(
            "SELECT gc_operation_id,purge_reason FROM protected_authorized_snapshot_purge_fences "
            "WHERE admission_id=%s", (admission.admission_id,),
        ).fetchone() == (operation, "retention_expired")
        assert connection.execute("SELECT count(*) FROM protected_send_leases").fetchone() == (0,)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            connection.execute(
                "DELETE FROM protected_authorized_snapshot_purge_fences WHERE admission_id=%s",
                (admission.admission_id,),
            )


def test_active_send_lease_prevents_snapshot_purge_fence(isolated_test_dsn):
    """Sender 已開始或 ACK 未知時 GC 不能在其 Pin 之下刪除執行資格。"""
    import psycopg

    admission, owner, envelope, seeded = _authorized_pin(isolated_test_dsn)
    sender = PostgresProtectedSender(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    purger = PostgresProtectedSnapshotPurger(isolated_test_dsn,
                                             expected_login=_login(isolated_test_dsn))
    lease = sender.start_send(admission_id=admission.admission_id, receipt_id=seeded[3],
                              owner=owner, request_fingerprint=admission.request_binding_digest,
                              expected_envelope=envelope)
    assert lease is not None
    with pytest.raises(psycopg.errors.InsufficientPrivilege,
                       match="protected_snapshot_purge_active_or_unknown_send"):
        purger.fence_snapshot(admission_id=admission.admission_id, gc_operation_id=uuid4(),
                              purge_reason="retention_expired")
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute(
            "SELECT count(*) FROM protected_authorized_snapshot_purge_fences",
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT state FROM response_admissions WHERE admission_id=%s",
            (admission.admission_id,),
        ).fetchone() == ("SEND_STARTED",)


def test_terminal_send_allows_retention_fence_without_rearming_lease(isolated_test_dsn):
    """真實 ASGI 終態落盤後可建立清理 Fence，但不可撤銷過去 Lease 或重送。"""
    import psycopg

    admission, owner, envelope, seeded = _authorized_pin(isolated_test_dsn)
    sender = PostgresProtectedSender(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    purger = PostgresProtectedSnapshotPurger(isolated_test_dsn,
                                             expected_login=_login(isolated_test_dsn))
    args = dict(admission_id=admission.admission_id, receipt_id=seeded[3],
                owner=owner, request_fingerprint=admission.request_binding_digest,
                expected_envelope=envelope)
    lease = sender.start_send(**args)
    assert lease is not None
    assert sender.finish_send(admission_id=admission.admission_id, owner=owner,
                              lease_id=lease.lease_id, outcome=AdmissionState.SEND_COMPLETED,
                              attempted=True) is AdmissionOperationResult.SUCCESS
    assert purger.fence_snapshot(admission_id=admission.admission_id,
                                 gc_operation_id=uuid4(), purge_reason="retention_expired")
    assert sender.start_send(**args) is None
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute(
            "SELECT state FROM response_admissions WHERE admission_id=%s",
            (admission.admission_id,),
        ).fetchone() == ("SEND_COMPLETED",)
        assert connection.execute("SELECT count(*) FROM protected_send_leases").fetchone() == (1,)
        assert connection.execute(
            "SELECT count(*) FROM protected_authorized_snapshot_purge_fences",
        ).fetchone() == (1,)


def test_concurrent_snapshot_purge_and_start_send_are_serialized(isolated_test_dsn):
    """GC／Sender 競爭只能 Fence 或 StartSend 擇一成功，不能同時提交。"""
    import psycopg

    admission, owner, envelope, seeded = _authorized_pin(isolated_test_dsn)
    sender = PostgresProtectedSender(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    purger = PostgresProtectedSnapshotPurger(isolated_test_dsn,
                                             expected_login=_login(isolated_test_dsn))

    def attempt_purge():
        """以專用 GC 身份寫入同筆 Admission 的不可逆 Fence。"""
        try:
            return purger.fence_snapshot(admission_id=admission.admission_id,
                                         gc_operation_id=uuid4(),
                                         purge_reason="retention_expired")
        except psycopg.errors.InsufficientPrivilege:
            return False

    def attempt_send():
        """以唯一 Sender 身份嘗試消費同筆 Admission。"""
        return sender.start_send(admission_id=admission.admission_id,
                                 receipt_id=seeded[3], owner=owner,
                                 request_fingerprint=admission.request_binding_digest,
                                 expected_envelope=envelope)

    with ThreadPoolExecutor(max_workers=2) as pool:
        purge_future, send_future = pool.submit(attempt_purge), pool.submit(attempt_send)
        fenced, lease = purge_future.result(), send_future.result()
    assert int(fenced) + int(lease is not None) == 1
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute(
            "SELECT count(*) FROM protected_authorized_snapshot_purge_fences",
        ).fetchone() == (int(fenced),)
        assert connection.execute(
            "SELECT count(*) FROM protected_send_leases",
        ).fetchone() == (int(lease is not None),)


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


def test_send_started_audit_failure_rolls_back_lease_and_state(isolated_test_dsn):
    """首筆必要 Audit 寫入故障時回滾一次性 Lease 與 SEND_STARTED，不放出起送結果。"""
    import psycopg

    admission, owner, envelope, seeded = _authorized_pin(isolated_test_dsn)
    sender = PostgresProtectedSender(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    with psycopg.connect(isolated_test_dsn) as connection:
        connection.execute(
            """CREATE TRIGGER injected_first_audit_failure BEFORE INSERT ON response_audit
               FOR EACH ROW EXECUTE FUNCTION reject_protected_mutation()""",
        )
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        sender.start_send(
            admission_id=admission.admission_id, receipt_id=seeded[3], owner=owner,
            request_fingerprint=admission.request_binding_digest,
            expected_envelope=envelope,
        )
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute(
            "SELECT state FROM response_admissions WHERE admission_id=%s",
            (admission.admission_id,),
        ).fetchone()[0] == "SEND_AUTHORIZED"
        assert connection.execute(
            "SELECT count(*) FROM protected_send_leases WHERE admission_id=%s",
            (admission.admission_id,),
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT count(*) FROM response_audit WHERE admission_id=%s",
            (admission.admission_id,),
        ).fetchone()[0] == 0


def test_terminal_audit_failure_keeps_prior_lease_nonretryable(isolated_test_dsn):
    """終態 Audit INSERT 失敗時完整回滾狀態，保留原 Lease 且禁止重新起送。"""
    import psycopg

    admission, owner, envelope, seeded = _authorized_pin(isolated_test_dsn)
    sender = PostgresProtectedSender(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    args = dict(admission_id=admission.admission_id, receipt_id=seeded[3], owner=owner,
                request_fingerprint=admission.request_binding_digest,
                expected_envelope=envelope)
    lease = sender.start_send(**args)
    assert lease is not None
    with psycopg.connect(isolated_test_dsn) as connection:
        connection.execute(
            """CREATE TRIGGER injected_terminal_audit_failure BEFORE INSERT ON response_audit
               FOR EACH ROW WHEN (NEW.sequence = 2)
               EXECUTE FUNCTION reject_protected_mutation()""",
        )
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        sender.finish_send(
            admission_id=admission.admission_id, owner=owner, lease_id=lease.lease_id,
            outcome=AdmissionState.SEND_COMPLETED, attempted=True,
        )
    reconciliation = sender.reconcile_send(
        admission_id=admission.admission_id, receipt_id=seeded[3],
        owner=owner, request_fingerprint=admission.request_binding_digest)
    assert reconciliation.observation == "STARTED_DELIVERY_UNKNOWN"
    assert not reconciliation.retry_permitted
    assert sender.start_send(**args) is None
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute(
            "SELECT state FROM response_admissions WHERE admission_id=%s",
            (admission.admission_id,),
        ).fetchone()[0] == "SEND_STARTED"
        assert connection.execute(
            "SELECT count(*) FROM protected_send_leases WHERE admission_id=%s",
            (admission.admission_id,),
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT sequence,event_name FROM response_audit WHERE admission_id=%s ORDER BY sequence",
            (admission.admission_id,),
        ).fetchall() == [(0, "send_started")]


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
            self.wrong_deadline = False
            self.invalid_lease_id = False
            self.transport_failure = False

        def start_send(self, *, admission_id, receipt_id, owner, request_fingerprint,
                       expected_envelope):
            """只有精確封套存在才發放一次性測試 Lease，起送呼叫留下順序證據。"""
            events.append("lease")
            if self.transport_failure:
                raise ConnectionError("simulated COMMIT ACK loss")
            return ProtectedSendLease(
                lease_id=UUID(int=0) if self.invalid_lease_id else uuid4(),
                admission_id=admission_id, send_owner=owner,
                receipt_id=uuid4() if self.wrong_receipt else receipt_id,
                request_fingerprint=request_fingerprint,
                candidate_hash=admission.candidate_hash,
                envelope_bytes=(expected_envelope + b"attacker" if self.corrupt else expected_envelope),
                transmission_deadline=(admission.transmission_deadline - 1
                                       if self.wrong_deadline else admission.transmission_deadline),
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
    sender.wrong_deadline = True
    events.clear()
    response_bad_deadline = ResponseRenderer(gate, transmission_factory=factory).render(
        pipeline_result(candidate, gate, request), request,
    )
    with pytest.raises(TransmissionError, match="lease_refused"):
        asyncio.run(response_bad_deadline(scope, receive, send))
    assert events == ["lease"]
    sender.wrong_deadline = False
    sender.invalid_lease_id = True
    events.clear()
    response_bad_lease_id = ResponseRenderer(gate, transmission_factory=factory).render(
        pipeline_result(candidate, gate, request), request,
    )
    with pytest.raises(TransmissionError, match="lease_refused"):
        asyncio.run(response_bad_lease_id(scope, receive, send))
    assert events == ["lease"]
    sender.invalid_lease_id = False
    sender.transport_failure = True
    events.clear()
    with pytest.raises(ConnectionError, match="COMMIT ACK loss"):
        asyncio.run(response4(scope, receive, send))
    with pytest.raises(TransmissionError, match="not_prepared_or_reused"):
        response4._transmission.start()
    assert events == ["lease"]
