"""MIR-SEC-WORLD-001：Receipt、Candidate Promotion 與 Grant Binding 的真實 PG 負面驗收。"""

import hashlib
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
    assert authorizer.lookup(operation_id) == admission
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
        PostgresProtectedAuthorizer(isolated_test_dsn, expected_login="mirage_http_runtime").lookup(uuid4())


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
