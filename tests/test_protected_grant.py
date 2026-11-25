"""MIR-SEC-WORLD-001：Receipt、Candidate Promotion 與 Grant Binding 的真實 PG 負面驗收。"""

import hashlib
import os
import secrets
import time
from uuid import uuid4

import pytest

from deception.world import (
    AdmissionOperationResult, CommitSource, PostgresCandidatePromoter, PostgresCandidateStore,
    PostgresProtectedAuthorizer, PostgresProjectionRegistry, ProtectedGrantError,
    SnapshotSource,
)
from deception.world.transmission import response_envelope, response_hashes
from test_postgres_conformance import digest, isolated_test_dsn, projection_evidence, scope


def _login(dsn):
    """從實際物理連線取得本案例管理角色，僅供隔離測試使用。"""
    import psycopg

    with psycopg.connect(dsn) as connection:
        return connection.execute("SELECT session_user").fetchone()[0]


def _seed(dsn, *, fingerprint=None, candidate_scope=None, contract_hash=None):
    """在獨立 schema 佈建 Receipt/快照，允許連續案例選不同的契約雜湊。"""
    import psycopg

    selected = candidate_scope or scope(uuid4().hex)
    fingerprint = fingerprint or digest("a")
    now = int(time.time())
    evidence = projection_evidence(contract_hash)
    registry = PostgresProjectionRegistry(dsn)
    registry.register(evidence, registry_revision=1)
    source = SnapshotSource(read_admission_id=uuid4().hex,
                            world_generation_id=selected.world_generation_id,
                            state_version=1, state_hash=digest("f"))
    body = b'{"synthetic":true}'
    headers = [("content-type", "application/json")]
    envelope = response_envelope(200, headers, body)
    hashes = response_hashes(200, headers, body)
    ref = uuid4().hex
    PostgresCandidateStore(dsn).put(selected, ref, envelope, expires_at=now + 120)
    receipt_id = uuid4()
    with psycopg.connect(dsn) as connection:
        connection.execute("INSERT INTO session_heads VALUES (%s,%s,%s,1)",
                           (selected.environment_id, selected.deployment_id, selected.session_id))
        connection.execute("INSERT INTO session_world_bindings "
                           "(environment_id,deployment_id,session_id,session_epoch,world_generation_id) "
                           "VALUES (%s,%s,%s,1,%s)",
                           (selected.environment_id, selected.deployment_id,
                            selected.session_id, selected.world_generation_id))
        connection.execute("INSERT INTO generation_controls VALUES (%s,0,FALSE,NULL)",
                           (selected.world_generation_id,))
        connection.execute("INSERT INTO read_admissions VALUES (%s,%s,%s,%s,%s,%s,1,%s,%s)",
                           (source.read_admission_id, selected.environment_id, selected.deployment_id,
                            selected.session_id, selected.world_generation_id,
                            fingerprint, source.state_hash, now + 120))
        jti = uuid4().hex
        connection.execute("INSERT INTO replay_entries VALUES ('gateway','mirage',%s,%s)",
                           (jti, now + 120))
        connection.execute(
            """INSERT INTO ingress_receipts (
                   receipt_id,issuer,audience,jti,key_id,environment_id,deployment_id,
                   session_id,session_epoch,request_fingerprint,assessment_digest,
                   claims_digest,verification_policy_version,token_issued_at,
                   token_not_before,token_expires_at,access_mode)
               VALUES (%s,'gateway','mirage',%s,'kid',%s,%s,%s,1,%s,%s,%s,'trusted-session-v1.1',%s,%s,%s,'read_only')""",
            (receipt_id, jti, selected.environment_id, selected.deployment_id,
             selected.session_id, fingerprint, digest("b"), digest("c"),
             now - 5, now - 5, now + 60),
        )
        connection.execute(
            """INSERT INTO protected_world_read_sources (
                   read_admission_id,receipt_id,environment_id,deployment_id,session_id,
                   world_generation_id,request_fingerprint,state_version,state_hash)
               VALUES (%s,%s,%s,%s,%s,%s,%s,1,%s)""",
            (source.read_admission_id, receipt_id, *(
                selected.environment_id, selected.deployment_id,
                selected.session_id, selected.world_generation_id), fingerprint,
             source.state_hash),
        )
    return selected, source, evidence, receipt_id, ref, hashes, now


def _promote(dsn, seeded):
    """由隔離測試管理身分執行可信 Candidate Promotion，回傳 version。"""
    selected, source, evidence, receipt_id, ref, hashes, _ = seeded
    return PostgresCandidatePromoter(dsn, expected_login=_login(dsn)).promote(
        receipt_id=receipt_id, scope=selected, candidate_ref=ref,
        request_fingerprint=digest("a"),
        envelope_hash=hashes[0], immutable_body_hash=hashes[1],
        semantic_headers_hash=hashes[2], evidence=evidence, source=source,
    )


def _grant(dsn, seeded, *, operation_id=None, receipt_id=None, candidate_ref=None):
    """以同一批可信輸入呼叫獨立 Authorizer，供正反面測試比對。"""
    selected, _, evidence, receipt, ref, _, now = seeded
    return PostgresProtectedAuthorizer(dsn, expected_login=_login(dsn)).grant(
        operation_id=operation_id or uuid4(), receipt_id=receipt_id or receipt,
        scope=selected, candidate_ref=candidate_ref or ref, candidate_version=1,
        authorization_revision="reviewed-v1",
        authorization_deadline=now + 30, transmission_deadline=now + 50,
        evidence=evidence,
    )


def test_protected_grant_binds_receipt_promotion_and_admission_atomically(isolated_test_dsn):
    """正向 Promotion／Grant 必須產生一對一 Receipt／Candidate／Admission 及可查回 Operation。"""
    import psycopg

    seeded = _seed(isolated_test_dsn)
    assert _promote(isolated_test_dsn, seeded) == 1
    operation_id = uuid4()
    admission = _grant(isolated_test_dsn, seeded, operation_id=operation_id)
    assert admission.candidate_hash == seeded[5][0]
    authorizer = PostgresProtectedAuthorizer(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    input_digest = authorizer.intent_digest(
        operation_id=operation_id, receipt_id=seeded[3], scope=seeded[0],
        candidate_ref=seeded[4], candidate_version=1,
        authorization_revision="reviewed-v1", authorization_deadline=seeded[6] + 30,
        transmission_deadline=seeded[6] + 50, evidence=seeded[2],
    )
    assert authorizer.lookup(operation_id, input_digest=input_digest) == admission
    with pytest.raises(ProtectedGrantError, match="operation_input_digest_conflict"):
        authorizer.lookup(operation_id, input_digest=digest("0"))
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM protected_grant_bindings WHERE receipt_id=%s",
                                  (seeded[3],)).fetchone()[0] == 1
        assert connection.execute("SELECT control_revision FROM generation_controls WHERE world_generation_id=%s",
                                  (seeded[0].world_generation_id,)).fetchone()[0] == 1


def test_receipt_only_authorizer_pins_snapshot_and_sends_native_asgi(isolated_test_dsn):
    """只提供已驗證 Receipt，從原始可信 Promotion 建立授權並實際輸出真 DB Pin HTTP。"""
    import asyncio
    import psycopg
    from deception.world import PostgresProtectedSender, ProtectedPinnedASGIResponse

    seeded = _seed(isolated_test_dsn)
    assert _promote(isolated_test_dsn, seeded) == 1
    authorizer = PostgresProtectedAuthorizer(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    admission, owner = authorizer.authorize_promoted_receipt_once(seeded[3])
    assert owner == "protected-sender-" + seeded[3].hex
    expected = response_envelope(200, [("content-type", "application/json")], b'{"synthetic":true}')
    sender = PostgresProtectedSender(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    response = ProtectedPinnedASGIResponse(
        sender=sender, admission_id=admission.admission_id,
        receipt_id=seeded[3], owner=owner,
        request_fingerprint=admission.request_binding_digest, expected_envelope=expected,
    )
    messages = []

    async def record(message):
        """保留 Sender 真正發出的 ASGI 訊息以驗證狀態、標頭與精確內容。"""
        messages.append(message)

    asyncio.run(response({"type": "http", "scheme": "https"}, None, record))
    assert messages == [
        {"type": "http.response.start", "status": 200,
         "headers": [(b"content-type", b"application/json")]},
        {"type": "http.response.body", "body": b'{"synthetic":true}'},
    ]
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM protected_grant_bindings").fetchone() == (1,)
        assert connection.execute("SELECT count(*) FROM protected_authorized_http_snapshots").fetchone() == (1,)
        assert connection.execute("SELECT count(*) FROM protected_send_leases").fetchone() == (1,)
        assert connection.execute(
            "SELECT state FROM response_admissions WHERE admission_id=%s",
            (admission.admission_id,),
        ).fetchone() == ("SEND_COMPLETED",)
    with pytest.raises(psycopg.errors.UniqueViolation):
        authorizer.authorize_promoted_receipt_once(seeded[3])


def test_receipt_only_authorizer_database_prevents_ambiguous_promotions(isolated_test_dsn):
    """真 PostgreSQL 唯一索引禁止同 Receipt 另插 Promotion，沒有並發幻影可被授權。"""
    import psycopg

    seeded = _seed(isolated_test_dsn)
    assert _promote(isolated_test_dsn, seeded) == 1
    selected, source, evidence, receipt_id, _, hashes, now = seeded
    other_ref = uuid4().hex
    PostgresCandidateStore(isolated_test_dsn).put(
        selected, other_ref,
        response_envelope(200, [("content-type", "application/json")], b'{"synthetic":true}'),
        expires_at=now + 120,
    )
    promoter = PostgresCandidatePromoter(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    with pytest.raises(psycopg.errors.UniqueViolation):
        promoter.promote(
            receipt_id=receipt_id, scope=selected, candidate_ref=other_ref,
            request_fingerprint=digest("a"), envelope_hash=hashes[0],
            immutable_body_hash=hashes[1], semantic_headers_hash=hashes[2],
            evidence=evidence, source=source,
        )
    authorizer = PostgresProtectedAuthorizer(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    admission, owner = authorizer.authorize_promoted_receipt_once(receipt_id)
    assert owner == "protected-sender-" + receipt_id.hex
    assert admission.candidate_ref == seeded[4]
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM protected_candidate_promotions").fetchone() == (1,)
        assert connection.execute("SELECT count(*) FROM protected_grant_bindings").fetchone() == (1,)
        assert connection.execute("SELECT count(*) FROM response_admissions").fetchone() == (1,)


def test_send_authorization_pins_immutable_http_envelope(isolated_test_dsn):
    """SEND_AUTHORIZED 與精確 Payload Pin 同交易落地，不能改寫或拿其他 Receipt 借用。"""
    import psycopg

    seeded = _seed(isolated_test_dsn)
    _promote(isolated_test_dsn, seeded)
    admission = _grant(isolated_test_dsn, seeded)
    authorizer = PostgresProtectedAuthorizer(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    assert authorizer.claim(admission.admission_id, owner="pinned-sender") is AdmissionOperationResult.SUCCESS
    assert authorizer.authorize_send(admission.admission_id, owner="pinned-sender") is AdmissionOperationResult.SUCCESS
    with psycopg.connect(isolated_test_dsn) as connection:
        row = connection.execute(
            """SELECT receipt_id,candidate_hash,envelope_bytes,send_owner,transmission_deadline
               FROM protected_authorized_http_snapshots WHERE admission_id=%s""",
            (admission.admission_id,),
        ).fetchone()
        assert row is not None
        assert row[0] == seeded[3] and row[1] == seeded[5][0]
        assert bytes(row[2]) == response_envelope(200, [("content-type", "application/json")], b'{"synthetic":true}')
        assert (row[3], row[4]) == ("pinned-sender", admission.transmission_deadline)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            connection.execute("UPDATE protected_authorized_http_snapshots SET send_owner='attacker' WHERE admission_id=%s",
                               (admission.admission_id,))


def test_snapshot_insert_failure_rolls_back_send_authorization(isolated_test_dsn):
    """Pin 資料庫寫入失敗時 SEND_AUTHORIZED 不得留存，Claim 保持可核對狀態。"""
    import psycopg

    seeded = _seed(isolated_test_dsn)
    _promote(isolated_test_dsn, seeded)
    admission = _grant(isolated_test_dsn, seeded)
    authorizer = PostgresProtectedAuthorizer(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    assert authorizer.claim(admission.admission_id, owner="pinned-sender") is AdmissionOperationResult.SUCCESS
    with psycopg.connect(isolated_test_dsn) as connection:
        connection.execute(
            """CREATE TRIGGER injected_http_snapshot_failure
               BEFORE INSERT ON protected_authorized_http_snapshots FOR EACH ROW
               EXECUTE FUNCTION reject_protected_mutation()""",
        )
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        authorizer.authorize_send(admission.admission_id, owner="pinned-sender")
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT state FROM response_admissions WHERE admission_id=%s",
                                  (admission.admission_id,)).fetchone()[0] == "CLAIMED"
        assert connection.execute("SELECT count(*) FROM protected_authorized_http_snapshots").fetchone()[0] == 0


def test_protected_grant_cannot_reuse_receipt_or_leave_partial_state(isolated_test_dsn):
    """同一 Receipt 並行或再授權第二次應觸發唯一約束且整筆交易回滾。"""
    import psycopg

    seeded = _seed(isolated_test_dsn)
    _promote(isolated_test_dsn, seeded)
    first = _grant(isolated_test_dsn, seeded)
    with pytest.raises(psycopg.errors.UniqueViolation):
        _grant(isolated_test_dsn, seeded)
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM response_admissions").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM protected_grant_bindings").fetchone()[0] == 1
        assert connection.execute("SELECT control_revision FROM generation_controls WHERE world_generation_id=%s",
                                  (seeded[0].world_generation_id,)).fetchone()[0] == 1
        assert connection.execute("SELECT state FROM response_admissions WHERE admission_id=%s",
                                  (first.admission_id,)).fetchone()[0] == "GRANTED"


def test_protected_grant_rejects_fingerprint_and_scope_substitution(isolated_test_dsn):
    """不同 Request Fingerprint 或跨 Candidate Scope 均不可挪用合法 Receipt。"""
    import psycopg

    seeded = _seed(isolated_test_dsn)
    selected, source, evidence, receipt, ref, hashes, _ = seeded
    promoter = PostgresCandidatePromoter(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    with pytest.raises(ProtectedGrantError, match="candidate_source_unverifiable"):
        promoter.promote(receipt_id=receipt, scope=selected, candidate_ref=ref,
                         request_fingerprint=digest("b"),
                         envelope_hash=hashes[0], immutable_body_hash=hashes[1],
                         semantic_headers_hash=hashes[2], evidence=evidence, source=source)
    _promote(isolated_test_dsn, seeded)
    with psycopg.connect(isolated_test_dsn) as connection:
        connection.execute("UPDATE ingress_receipts SET request_fingerprint=%s WHERE receipt_id=%s",
                           (digest("b"), receipt))
    with pytest.raises(ProtectedGrantError, match="unbound_or_corrupt_candidate"):
        _grant(isolated_test_dsn, seeded)
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM protected_grant_bindings").fetchone()[0] == 0


def test_grant_cannot_borrow_same_fingerprint_from_another_receipt(isolated_test_dsn):
    """兩份 JWS 即使 Session 與指紋相同，也不能以另一份 Receipt 偷渡 Candidate。"""
    import psycopg

    seeded = _seed(isolated_test_dsn)
    _promote(isolated_test_dsn, seeded)
    original = seeded[3]
    unrelated = uuid4()
    jti = uuid4().hex
    with psycopg.connect(isolated_test_dsn) as connection:
        connection.execute("INSERT INTO replay_entries VALUES ('gateway','mirage',%s,%s)",
                           (jti, seeded[6] + 120))
        connection.execute(
            """INSERT INTO ingress_receipts (
                   receipt_id,issuer,audience,jti,key_id,environment_id,deployment_id,
                   session_id,session_epoch,request_fingerprint,assessment_digest,
                   claims_digest,verification_policy_version,token_issued_at,
                   token_not_before,token_expires_at,access_mode,resource_id)
               SELECT %s,issuer,audience,%s,key_id,environment_id,deployment_id,
                      session_id,session_epoch,request_fingerprint,assessment_digest,
                      claims_digest,verification_policy_version,token_issued_at,
                      token_not_before,token_expires_at,access_mode,resource_id
               FROM ingress_receipts WHERE receipt_id=%s""",
            (unrelated, jti, original),
        )
    with pytest.raises(ProtectedGrantError, match="unbound_or_corrupt_candidate"):
        _grant(isolated_test_dsn, seeded, receipt_id=unrelated)
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM protected_grant_bindings").fetchone()[0] == 0


def test_runtime_world_commit_row_is_not_trusted_source(isolated_test_dsn):
    """舊 World Runtime 可寫的 Commit 結果不得在受保護 Executor 未完成前提升為來源權威。"""
    seeded = _seed(isolated_test_dsn)
    selected, _, evidence, receipt_id, ref, hashes, _ = seeded
    source = CommitSource(world_generation_id=selected.world_generation_id,
                          operation_result_digest=digest("e"), committed_state_version=1,
                          committed_state_hash=digest("f"))
    with pytest.raises(ProtectedGrantError, match="candidate_source_unverifiable"):
        PostgresCandidatePromoter(isolated_test_dsn, expected_login=_login(isolated_test_dsn)).promote(
            receipt_id=receipt_id, scope=selected, candidate_ref=ref,
            request_fingerprint=digest("a"),
            envelope_hash=hashes[0], immutable_body_hash=hashes[1],
            semantic_headers_hash=hashes[2], evidence=evidence, source=source,
        )


def test_protected_grant_requires_promotion_and_db_role(isolated_test_dsn):
    """未 Promotion／錯誤實體 Login／舊 Admission 均不能進入 Protected Grant。"""
    seeded = _seed(isolated_test_dsn)
    with pytest.raises(ProtectedGrantError, match="unbound_or_corrupt_candidate"):
        _grant(isolated_test_dsn, seeded)
    with pytest.raises(ProtectedGrantError, match="protected_service_login_mismatch"):
        PostgresProtectedAuthorizer(isolated_test_dsn, expected_login="mirage_http_runtime").lookup(
            uuid4(), input_digest=digest("a"))


def test_protected_authorizer_claim_and_freeze_linearization(isolated_test_dsn):
    """只有已 Binding 的 Admission 能 Claim→Authorize；同 owner 不能重複授權。"""
    import psycopg

    seeded = _seed(isolated_test_dsn)
    _promote(isolated_test_dsn, seeded)
    admission = _grant(isolated_test_dsn, seeded)
    authorizer = PostgresProtectedAuthorizer(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    assert authorizer.claim(admission.admission_id, owner="sender-1") is AdmissionOperationResult.SUCCESS
    assert authorizer.claim(admission.admission_id, owner="sender-2") is AdmissionOperationResult.REJECTED
    assert authorizer.authorize_send(admission.admission_id, owner="sender-2") is AdmissionOperationResult.REJECTED
    assert authorizer.authorize_send(admission.admission_id, owner="sender-1") is AdmissionOperationResult.SUCCESS
    assert authorizer.authorize_send(admission.admission_id, owner="sender-1") is AdmissionOperationResult.REJECTED
    with psycopg.connect(isolated_test_dsn) as connection:
        state, claim, revision = connection.execute(
            "SELECT state,claim_owner,send_authorization_revision FROM response_admissions "
            "WHERE admission_id=%s", (admission.admission_id,)).fetchone()
    assert (state, claim, revision) == ("SEND_AUTHORIZED", "sender-1", 3)


def test_protected_authorizer_rechecks_revocation_before_authorized(isolated_test_dsn):
    """Grant 和最終授權之間若 Key 撤銷，禁止新 SEND_AUTHORIZED。"""
    import psycopg
    from deception.security.key_revocation import PostgresTrustedKeyRevocations

    seeded = _seed(isolated_test_dsn)
    _promote(isolated_test_dsn, seeded)
    admission = _grant(isolated_test_dsn, seeded)
    authorizer = PostgresProtectedAuthorizer(isolated_test_dsn, expected_login=_login(isolated_test_dsn))
    assert authorizer.claim(admission.admission_id, owner="sender-1") is AdmissionOperationResult.SUCCESS
    PostgresTrustedKeyRevocations(isolated_test_dsn,
                                  environment_id=seeded[0].environment_id,
                                  deployment_id=seeded[0].deployment_id).revoke(
                                      "gateway", "kid", revision=1)
    assert authorizer.authorize_send(admission.admission_id, owner="sender-1") is AdmissionOperationResult.REJECTED
    with psycopg.connect(isolated_test_dsn) as connection:
        state = connection.execute("SELECT state FROM response_admissions WHERE admission_id=%s",
                                   (admission.admission_id,)).fetchone()[0]
    assert state == "ABANDONED"


def test_candidate_gc_cannot_delete_promoted_payload(isolated_test_dsn):
    """即使原始 Candidate 到期，GC 不得依 Runtime 的 protected_refs 刪除已 Promotion bytes。"""
    import psycopg

    seeded = _seed(isolated_test_dsn)
    _promote(isolated_test_dsn, seeded)
    assert PostgresCandidateStore(isolated_test_dsn).gc(now=seeded[6] + 150,
                                                        protected_refs=()) == ()
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM candidate_records").fetchone()[0] == 1
        with pytest.raises(psycopg.errors.InsufficientPrivilege) as error:
            connection.execute("UPDATE protected_candidate_promotions SET candidate_version=2")
        assert error.value.sqlstate == "42501"


def test_protected_grant_real_role_acl_and_authorizer(isolated_test_dsn):
    """真實 SCRAM Login 驗證 Runtime 不能修改；Validator/Authorizer 只持所需 ACL。"""
    if os.environ.get("MIRAGE_WORLD_ROLE_TEST_ISOLATED") != "true":
        pytest.skip("requires disposable PostgreSQL cluster for login role creation")
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    suffix = uuid4().hex[:12]
    users = {kind: (f"mirage_g3_{kind}_{suffix}", secrets.token_urlsafe(32))
             for kind in ("runtime", "validator", "authorizer")}
    options = conninfo_to_dict(isolated_test_dsn).get("options", "")
    schema = options.split("search_path=", 1)[1].split(" ", 1)[0]

    with psycopg.connect(isolated_test_dsn, autocommit=True) as admin:
        try:
            for login, password in users.values():
                admin.execute(sql.SQL("CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB "
                                      "NOCREATEROLE NOBYPASSRLS PASSWORD {}").format(
                                          sql.Identifier(login), sql.Literal(password)))
                admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                    sql.Identifier(schema), sql.Identifier(login)))

            validator = sql.Identifier(users["validator"][0])
            authorizer = sql.Identifier(users["authorizer"][0])
            runtime = sql.Identifier(users["runtime"][0])
            admin.execute(sql.SQL("GRANT SELECT ON candidate_records,read_admissions,world_operations,"
                                  "protected_world_read_sources,protected_world_commit_sources,"
                                  "projection_registry,projection_profile_revocations TO {}").format(validator))
            admin.execute(sql.SQL("GRANT INSERT,SELECT ON protected_candidate_promotions TO {}").format(validator))
            admin.execute(sql.SQL("GRANT EXECUTE ON FUNCTION protected_lock_reference(text,jsonb) TO {}").format(
                validator))
            admin.execute(sql.SQL("GRANT SELECT ON session_heads,session_world_bindings,ingress_receipts,"
                                  "protected_candidate_promotions,generation_controls,response_admissions,"
                                  "trusted_key_revocations,projection_registry,projection_profile_revocations,"
                                  "protected_grant_bindings TO {}").format(authorizer))
            admin.execute(sql.SQL("GRANT UPDATE ON generation_controls,response_admissions TO {}").format(
                authorizer))
            admin.execute(sql.SQL("GRANT INSERT ON response_admissions,protected_grant_bindings TO {}").format(
                authorizer))
            admin.execute(sql.SQL("GRANT EXECUTE ON FUNCTION protected_lock_reference(text,jsonb) TO {}").format(
                authorizer))

            logins = {kind: make_conninfo(isolated_test_dsn, user=login, password=password)
                      for kind, (login, password) in users.items()}
            seeded = _seed(isolated_test_dsn)
            promoter = PostgresCandidatePromoter(
                logins["validator"], expected_login=users["validator"][0])
            assert promoter.promote(
                receipt_id=seeded[3], scope=seeded[0], candidate_ref=seeded[4],
                request_fingerprint=digest("a"),
                envelope_hash=seeded[5][0], immutable_body_hash=seeded[5][1],
                semantic_headers_hash=seeded[5][2], evidence=seeded[2], source=seeded[1],
            ) == 1
            authorizer_service = PostgresProtectedAuthorizer(
                logins["authorizer"], expected_login=users["authorizer"][0])
            admission = authorizer_service.grant(
                operation_id=uuid4(), receipt_id=seeded[3], scope=seeded[0],
                candidate_ref=seeded[4], candidate_version=1,
                authorization_revision="reviewed-v1",
                authorization_deadline=seeded[6] + 30,
                transmission_deadline=seeded[6] + 50, evidence=seeded[2],
            )
            assert admission.request_binding_digest == digest("a")

            for dsn, statements in ((logins["runtime"], (
                    "UPDATE response_admissions SET state='SEND_AUTHORIZED' WHERE false",
                    "INSERT INTO protected_grant_bindings(operation_id) VALUES(gen_random_uuid())",
                    "UPDATE session_heads SET session_epoch=0 WHERE false",
                    "INSERT INTO read_admissions(read_admission_id) VALUES('forged')",
                    "INSERT INTO protected_world_read_sources(read_admission_id) VALUES('forged')",
                    "INSERT INTO protected_world_commit_sources(operation) VALUES('forged')",
                    "SELECT protected_lock_reference('session_head','{}'::jsonb)",
                    )), (logins["validator"], (
                    "UPDATE response_admissions SET state='SEND_AUTHORIZED' WHERE false",
                    "INSERT INTO protected_grant_bindings(operation_id) VALUES(gen_random_uuid())",
                    )), (logins["authorizer"], (
                    "UPDATE ingress_receipts SET session_epoch=0 WHERE false",
                    "INSERT INTO protected_candidate_promotions(candidate_ref) VALUES('forged')",
                    ))):
                for statement in statements:
                    with psycopg.connect(dsn) as low:
                        with pytest.raises(psycopg.errors.InsufficientPrivilege) as error:
                            low.execute(statement)
                        assert error.value.sqlstate == "42501"

            for role in (validator, authorizer):
                with psycopg.connect(logins["runtime"]) as low:
                    with pytest.raises(psycopg.errors.InsufficientPrivilege) as error:
                        low.execute(sql.SQL("SET ROLE {}").format(role))
                    assert error.value.sqlstate == "42501"
        finally:
            # 每個測試只撤除自己建立的三個一次性 Role，不觸碰既有 Lab Login。
            for login, _ in users.values():
                admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(login)))
                admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(login)))


def test_receipt_only_authorizer_real_scram_least_privilege(isolated_test_dsn):
    """真實隔離 PG Login 以欄位級 UPDATE 運行 Receipt 授權，且不得讀 Snapshot bytes。"""
    if os.environ.get("MIRAGE_WORLD_ROLE_TEST_ISOLATED") != "true":
        pytest.skip("requires disposable PostgreSQL cluster for login role creation")
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    from deception.security.protected_services import _login_preflight

    seeded = _seed(isolated_test_dsn)
    assert _promote(isolated_test_dsn, seeded) == 1
    login = "mirage_auth_" + uuid4().hex[:12]
    password = secrets.token_urlsafe(32)
    options = conninfo_to_dict(isolated_test_dsn).get("options", "")
    schema = options.split("search_path=", 1)[1].split(" ", 1)[0]
    identity = sql.Identifier(login)
    with psycopg.connect(isolated_test_dsn, autocommit=True) as admin:
        try:
            admin.execute(sql.SQL("CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB "
                                  "NOCREATEROLE NOBYPASSRLS PASSWORD {}").format(
                                      identity, sql.Literal(password)))
            admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                sql.Identifier(schema), identity))
            admin.execute(sql.SQL(
                "GRANT SELECT ON protected_candidate_promotions,ingress_receipts,"
                "projection_registry,session_heads,session_world_bindings,"
                "generation_controls,trusted_key_revocations,projection_profile_revocations,"
                "response_admissions,protected_grant_bindings TO {}"
            ).format(identity))
            admin.execute(sql.SQL(
                "GRANT INSERT ON response_admissions,protected_grant_bindings,"
                "protected_authorized_http_snapshots TO {}"
            ).format(identity))
            admin.execute(sql.SQL(
                "GRANT UPDATE (control_revision) ON generation_controls TO {}"
            ).format(identity))
            admin.execute(sql.SQL(
                "GRANT UPDATE (state,claim_owner,claim_revision,send_authorization_revision) "
                "ON response_admissions TO {}"
            ).format(identity))
            admin.execute(sql.SQL(
                "GRANT EXECUTE ON FUNCTION protected_lock_reference(text,jsonb) TO {}"
            ).format(identity))

            dsn = make_conninfo(isolated_test_dsn, user=login, password=password)
            _login_preflight(dsn, login, role="authorizer", schema=schema)
            authorizer = PostgresProtectedAuthorizer(dsn, expected_login=login)
            admission, owner = authorizer.authorize_promoted_receipt_once(seeded[3])
            assert owner == "protected-sender-" + seeded[3].hex
            with psycopg.connect(dsn) as least:
                assert least.execute(
                    "SELECT state FROM response_admissions WHERE admission_id=%s",
                    (admission.admission_id,),
                ).fetchone() == ("SEND_AUTHORIZED",)
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    least.execute("SELECT envelope_bytes FROM protected_authorized_http_snapshots")
            with psycopg.connect(isolated_test_dsn) as privileged:
                assert privileged.execute(
                    "SELECT count(*) FROM protected_authorized_http_snapshots"
                ).fetchone() == (1,)
        finally:
            admin.execute(sql.SQL("DROP OWNED BY {}").format(identity))
            admin.execute(sql.SQL("DROP ROLE {}").format(identity))
