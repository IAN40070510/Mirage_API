"""MIR-SEC-WORLD-001：Receipt、Candidate Promotion 與 Grant Binding 的真實 PG 負面驗收。"""

import hashlib
import os
import secrets
import time
from uuid import uuid4

import pytest

from deception.world import (
    PostgresAdmissionControl, PostgresCandidatePromoter, PostgresCandidateStore,
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


def _seed(dsn, *, fingerprint=None, candidate_scope=None):
    """在獨立 schema 佈建受保護 Receipt 與可驗證的 Snapshot 測試來源。"""
    import psycopg

    selected = candidate_scope or scope(uuid4().hex)
    fingerprint = fingerprint or digest("a")
    now = int(time.time())
    evidence = projection_evidence()
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
                   token_not_before,token_expires_at)
               VALUES (%s,'gateway','mirage',%s,'kid',%s,%s,%s,1,%s,%s,%s,'trusted-session-v1.1',%s,%s,%s)""",
            (receipt_id, jti, selected.environment_id, selected.deployment_id,
             selected.session_id, fingerprint, digest("b"), digest("c"),
             now - 5, now - 5, now + 60),
        )
    return selected, source, evidence, receipt_id, ref, hashes, now


def _promote(dsn, seeded):
    """由隔離測試管理身分執行可信 Candidate Promotion，回傳 version。"""
    selected, source, evidence, _, ref, hashes, _ = seeded
    return PostgresCandidatePromoter(dsn, expected_login=_login(dsn)).promote(
        scope=selected, candidate_ref=ref, request_fingerprint=digest("a"),
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
        promoter.promote(scope=selected, candidate_ref=ref, request_fingerprint=digest("b"),
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


def test_protected_grant_requires_promotion_and_db_role(isolated_test_dsn):
    """未 Promotion／錯誤實體 Login／舊 Admission 均不能進入 Protected Grant。"""
    seeded = _seed(isolated_test_dsn)
    with pytest.raises(ProtectedGrantError, match="unbound_or_corrupt_candidate"):
        _grant(isolated_test_dsn, seeded)
    with pytest.raises(ProtectedGrantError, match="protected_service_login_mismatch"):
        PostgresProtectedAuthorizer(isolated_test_dsn, expected_login="mirage_http_runtime").lookup(
            uuid4(), input_digest=digest("a"))


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
                scope=seeded[0], candidate_ref=seeded[4], request_fingerprint=digest("a"),
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
