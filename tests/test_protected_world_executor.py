"""MIR-SEC-WORLD-001：以同一 PostgreSQL 交易保護 Read／Commit 來源的測試。"""

import time
import os
import secrets
from copy import deepcopy
from uuid import uuid4

import pytest

from deception.world import (CommitSource, PostgresCandidatePromoter, PostgresCandidateStore,
                             PostgresEventWorldStore, PostgresProtectedWorldExecutor,
                             PostgresProjectionRegistry, ProtectedGrantError)
from deception.world.session import SessionBinding
from deception.world.transmission import response_envelope, response_hashes
from test_postgres_conformance import (digest, isolated_test_dsn, projection_evidence)


def _counter_add(state, command):
    """以固定純函式增加合成庫存計數，不呼叫外部系統或執行 SQL。"""
    updated = deepcopy(state)
    updated["value"] += command["amount"]
    return updated, {"value": updated["value"]}, True


def _real_login(dsn):
    """從物理 PostgreSQL 連線取得目前測試登入身份，避免 SET ROLE 偽裝。"""
    import psycopg

    with psycopg.connect(dsn) as connection:
        return connection.execute("SELECT session_user").fetchone()[0]


def _trusted_world(dsn):
    """建立專用 Session／原生固定 handler／有效 JWS Receipt 的測試世界。"""
    import psycopg

    now = int(time.time())
    session = uuid4().hex
    binding = SessionBinding(environment_id="world-protected", deployment_id="isolated",
                             session_id=session, session_epoch=1, access_mode="inventory")
    store = PostgresEventWorldStore(dsn, handlers={"counter.add": _counter_add},
                                    write_modes={"inventory"})
    snapshot = store.resolve(binding, {"value": 0}, now=now, ttl=120)
    receipt_id = uuid4()
    fingerprint = digest("a")
    with psycopg.connect(dsn) as connection:
        jti = uuid4().hex
        connection.execute("INSERT INTO replay_entries VALUES ('gateway','mirage',%s,%s)",
                           (jti, now + 120))
        connection.execute(
            """INSERT INTO ingress_receipts (
                   receipt_id,issuer,audience,jti,key_id,environment_id,deployment_id,
                   session_id,session_epoch,request_fingerprint,assessment_digest,
                   claims_digest,verification_policy_version,token_issued_at,
                   token_not_before,token_expires_at,access_mode)
               VALUES (%s,'gateway','mirage',%s,'kid',%s,%s,%s,1,%s,%s,%s,
                       'trusted-session-v1.1',%s,%s,%s,'inventory')""",
            (receipt_id, jti, binding.environment_id, binding.deployment_id,
             binding.session_id, fingerprint, digest("b"), digest("c"),
             now - 5, now - 5, now + 90),
        )
    executor = PostgresProtectedWorldExecutor(
        dsn, expected_login=_real_login(dsn), world_store=store,
    )
    return executor, store, binding, snapshot, receipt_id, fingerprint, now


def _candidate(dsn, *, scope, source, receipt_id, fingerprint):
    """將本交易的受保護來源交由 Candidate Validator 綁定，不採信舊業務列。"""
    evidence = projection_evidence()
    PostgresProjectionRegistry(dsn).ensure_registered_batch((evidence,))
    envelope = response_envelope(200, [("content-type", "application/json")], b'{"ok":true}')
    hashes = response_hashes(200, [("content-type", "application/json")], b'{"ok":true}')
    ref = uuid4().hex
    PostgresCandidateStore(dsn).put(scope, ref, envelope, expires_at=int(time.time()) + 80)
    validator = PostgresCandidatePromoter(dsn, expected_login=_real_login(dsn))
    return validator.promote(
        receipt_id=receipt_id, scope=scope, candidate_ref=ref,
        request_fingerprint=fingerprint, envelope_hash=hashes[0],
        immutable_body_hash=hashes[1], semantic_headers_hash=hashes[2],
        evidence=evidence, source=source,
    )


def test_protected_read_and_commit_sources_remain_distinct_and_usable(isolated_test_dsn):
    """可信 ReadAdmission 與完整 World Mutation 都產生同交易證據，可供 Validator 使用。"""
    import psycopg

    executor, store, binding, snapshot, receipt, fingerprint, now = _trusted_world(isolated_test_dsn)
    read = executor.admit_read(receipt_id=receipt, binding=binding,
                               request_fingerprint=fingerprint, expires_at=now + 30)
    assert read.snapshot.scope == snapshot.scope
    assert _candidate(isolated_test_dsn, scope=snapshot.scope, source=read.source,
                      receipt_id=receipt, fingerprint=fingerprint) == 1
    attempt = uuid4()
    outcome = executor.commit_event(
        receipt_id=receipt, binding=binding, request_fingerprint=fingerprint,
        authorized_scope=snapshot.scope, operation="counter.add", command={"amount": 1},
        expected_version=1, idempotency_key="add-once", commit_attempt_id=attempt,
    )
    assert outcome.status == "committed" and outcome.committed_state_version == 2
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM protected_world_read_sources").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM protected_world_commit_sources").fetchone()[0] == 1
    # CommitSource 對應另一份 Candidate，不能把同一 Candidate/Hash 偷換成第二份來源。
    source = CommitSource(world_generation_id=snapshot.scope.world_generation_id,
                          operation_result_digest=outcome.result_digest,
                          committed_state_version=outcome.committed_state_version,
                          committed_state_hash=outcome.committed_state_hash)
    assert _candidate(isolated_test_dsn, scope=snapshot.scope, source=source,
                      receipt_id=receipt, fingerprint=fingerprint) == 1


def test_protected_world_refuses_forged_mode_and_request_fingerprint(isolated_test_dsn):
    """Runtime 自填 cart 能力或不同 Request Fingerprint 無法創造可信業務副作用。"""
    import psycopg

    executor, _, binding, snapshot, receipt, fingerprint, now = _trusted_world(isolated_test_dsn)
    forged_mode = binding.model_copy(update={"access_mode": "cart"})
    with pytest.raises(ProtectedGrantError, match="capability_mismatch"):
        executor.admit_read(receipt_id=receipt, binding=forged_mode,
                            request_fingerprint=fingerprint, expires_at=now + 30)
    with pytest.raises(ProtectedGrantError, match="capability_mismatch"):
        executor.admit_read(receipt_id=receipt, binding=binding,
                            request_fingerprint=digest("d"), expires_at=now + 30)
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM protected_world_read_sources").fetchone()[0] == 0
        assert connection.execute("SELECT version FROM world_snapshots WHERE world_generation_id=%s",
                                  (snapshot.scope.world_generation_id,)).fetchone()[0] == 1


def test_protected_world_commit_proof_failure_rolls_back_business_mutation(isolated_test_dsn):
    """提交證據被拒絕時整個 World 事件／快照更新回滾，不留下未證明的 Mutation。"""
    import psycopg

    executor, _, binding, snapshot, receipt, fingerprint, now = _trusted_world(isolated_test_dsn)
    executor.admit_read(receipt_id=receipt, binding=binding,
                        request_fingerprint=fingerprint, expires_at=now + 30)
    with psycopg.connect(isolated_test_dsn) as connection:
        connection.execute(
            """CREATE TRIGGER injected_protected_source_failure
               BEFORE INSERT ON protected_world_commit_sources FOR EACH ROW
               EXECUTE FUNCTION reject_protected_mutation()""",
        )
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        executor.commit_event(
            receipt_id=receipt, binding=binding, request_fingerprint=fingerprint,
            authorized_scope=snapshot.scope, operation="counter.add", command={"amount": 1},
            expected_version=1, idempotency_key="fail-provenance", commit_attempt_id=uuid4(),
        )
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM world_operations").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM world_events").fetchone()[0] == 0
        assert connection.execute("SELECT version FROM world_snapshots WHERE world_generation_id=%s",
                                  (snapshot.scope.world_generation_id,)).fetchone()[0] == 1


def test_unprotected_world_commit_cannot_be_promoted(isolated_test_dsn):
    """保留舊業務方法相容性，但管理身份產生的舊列沒有新的來源證據就不能授權。"""
    executor, store, binding, snapshot, receipt, fingerprint, now = _trusted_world(isolated_test_dsn)
    read = executor.admit_read(receipt_id=receipt, binding=binding,
                               request_fingerprint=fingerprint, expires_at=now + 30)
    old = store.commit_event(
        binding, authorized_scope=snapshot.scope, operation="counter.add",
        command={"amount": 1}, expected_version=1, idempotency_key="legacy-key",
        commit_attempt_id=uuid4(), now=now,
    )
    assert old.status == "committed"
    source = CommitSource(world_generation_id=snapshot.scope.world_generation_id,
                          operation_result_digest=old.result_digest,
                          committed_state_version=old.committed_state_version,
                          committed_state_hash=old.committed_state_hash)
    with pytest.raises(ProtectedGrantError, match="candidate_source_unverifiable"):
        _candidate(isolated_test_dsn, scope=snapshot.scope, source=source,
                   receipt_id=receipt, fingerprint=fingerprint)


def test_world_executor_uses_separate_real_login_and_minimum_acl(isolated_test_dsn):
    """實體 SCRAM 角色證明 Runtime 不能偽造證據，而 Executor 可保留正常業務寫入。"""
    if os.environ.get("MIRAGE_WORLD_ROLE_TEST_ISOLATED") != "true":
        pytest.skip("requires disposable PostgreSQL cluster for login role creation")
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    _, _, binding, snapshot, receipt, fingerprint, now = _trusted_world(isolated_test_dsn)
    suffix = uuid4().hex[:12]
    users = {kind: (f"mirage_world_{kind}_{suffix}", secrets.token_urlsafe(32))
             for kind in ("runtime", "executor")}
    schema = conninfo_to_dict(isolated_test_dsn)["options"].split("search_path=", 1)[1].split(" ", 1)[0]
    with psycopg.connect(isolated_test_dsn, autocommit=True) as admin:
        try:
            for login, password in users.values():
                admin.execute(sql.SQL("CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB "
                                      "NOCREATEROLE NOBYPASSRLS PASSWORD {}").format(
                                          sql.Identifier(login), sql.Literal(password)))
                admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                    sql.Identifier(schema), sql.Identifier(login)))
            executor_role = sql.Identifier(users["executor"][0])
            admin.execute(sql.SQL("GRANT SELECT ON ingress_receipts,session_heads,session_world_bindings,"
                                  "generation_controls,trusted_key_revocations,world_snapshots,"
                                  "world_operations,protected_world_read_sources,"
                                  "protected_world_commit_sources TO {}").format(executor_role))
            admin.execute(sql.SQL("GRANT UPDATE ON session_heads,session_world_bindings,"
                                  "generation_controls,world_snapshots TO {}").format(executor_role))
            admin.execute(sql.SQL("GRANT INSERT ON read_admissions,protected_world_read_sources,"
                                  "world_operations,world_events,world_commit_receipts,"
                                  "protected_world_commit_sources TO {}").format(executor_role))
            admin.execute(sql.SQL("GRANT EXECUTE ON FUNCTION "
                                  "protected_lock_reference(text,jsonb) TO {}").format(executor_role))
            dsns = {kind: make_conninfo(isolated_test_dsn, user=login, password=password)
                    for kind, (login, password) in users.items()}
            world_store = PostgresEventWorldStore(dsns["executor"],
                handlers={"counter.add": _counter_add}, write_modes={"inventory"})
            protected = PostgresProtectedWorldExecutor(dsns["executor"],
                expected_login=users["executor"][0], world_store=world_store)
            read = protected.admit_read(receipt_id=receipt, binding=binding,
                                       request_fingerprint=fingerprint, expires_at=now + 30)
            assert read.snapshot.scope == snapshot.scope
            result = protected.commit_event(
                receipt_id=receipt, binding=binding, request_fingerprint=fingerprint,
                authorized_scope=snapshot.scope, operation="counter.add",
                command={"amount": 1}, expected_version=1,
                idempotency_key="role-commit", commit_attempt_id=uuid4(),
            )
            assert result.status == "committed"
            with psycopg.connect(dsns["runtime"]) as connection:
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    connection.execute("INSERT INTO protected_world_read_sources(read_admission_id) "
                                       "VALUES ('forged')")
            with psycopg.connect(dsns["runtime"]) as connection:
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    connection.execute(sql.SQL("SET ROLE {}").format(executor_role))
        finally:
            for login, _ in users.values():
                admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(login)))
                admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(login)))
