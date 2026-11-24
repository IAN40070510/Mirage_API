"""請求觀察的假名化欄位、Grant 原子性與未知回覆恢復驗收。"""

from uuid import uuid4

from pydantic import ValidationError
import pytest

from deception.world import (CartCreationSource, PostgresAdmissionControl,
                             PostgresProjectionRegistry, PostgresWorldStore,
                             SnapshotSource, SecurityErrorSource)
from deception.world.request_audit import PostgresRequestAudit, RequestAuditLink, RequestObservation
from test_postgres_conformance import isolated_test_dsn, projection_evidence, scope


@pytest.fixture
def audit_case(isolated_test_dsn):
    """建立獨立世界與已保存請求觀察，內容 canary 不得進入 Audit 表。"""
    snapshot = PostgresWorldStore(isolated_test_dsn).create_if_absent(scope(uuid4().hex), {"private": "audit-business-canary"})
    observation = RequestObservation.from_snapshot(snapshot, request_id_digest="a" * 64,
        trusted_context_digest="b" * 64, request_binding_digest="c" * 64)
    audit = PostgresRequestAudit(isolated_test_dsn)
    audit.begin(observation)
    evidence = projection_evidence(uuid4().hex * 2)
    registry = PostgresProjectionRegistry(isolated_test_dsn)
    registry.register(evidence, registry_revision=1)
    return audit, observation, snapshot, evidence, registry


def audited_grant(case, *, link=None, control=None, registry=None, source=None):
    """以明確的已驗證結果 attestation 核發原型 Grant，實際 HTTP Gate 另行驗收。"""
    audit, observation, snapshot, evidence, original_registry = case
    if link is None:
        link = RequestAuditLink(observation=observation, target_scope=snapshot.scope,
                                domain_validation="passed", contract_validation="passed")
    return (control or PostgresAdmissionControl(audit._dsn)).grant(
        world_generation_id=snapshot.scope.world_generation_id, request_binding_digest=observation.request_binding_digest,
        candidate_ref="candidate-audit", candidate_hash="d" * 64, immutable_body_hash="e" * 64,
        semantic_headers_hash="f" * 64, projection_contract_hash=evidence.projection_contract_hash,
        authorization_revision="prototype-policy-1", authorization_deadline=2_000_000_000, transmission_deadline=2_000_000_010,
        source=source or SnapshotSource(read_admission_id="prototype-read", world_generation_id=snapshot.scope.world_generation_id,
            state_version=snapshot.version, state_hash=snapshot.state_hash), projection_evidence=evidence,
        projection_registry=registry or original_registry, request_audit=link)


def test_request_observation_links_validation_and_grant_without_payload(audit_case):
    """Audit 僅保留摘要與來源關聯；觀察不產生業務事件，正向結果與 Grant 同交易。"""
    import psycopg

    audit, observation, snapshot, _, _ = audit_case
    admission = audited_grant(audit_case)
    assert admission is not None
    audit.close_unverifiable(observation)
    with psycopg.connect(audit._dsn) as connection:
        row = connection.execute("SELECT row_to_json(r)::text FROM request_observations AS r").fetchone()[0]
        assert "audit-business-canary" not in row and "request_observed" in row
        assert connection.execute("SELECT outcome,domain_validation,contract_validation,admission_id,committed_state_version "
            "FROM request_observation_results").fetchone() == ("admitted", "passed", "passed", admission.admission_id, None)
        assert connection.execute("SELECT count(*) FROM world_events").fetchone() == (0,)
    assert PostgresWorldStore(audit._dsn).load(snapshot.scope) == snapshot


def test_mismatched_observation_rolls_back_grant_and_control_revision(audit_case):
    """已保存觀察不能被換成另一個可信上下文，失敗時不留下 Grant 或消耗 revision。"""
    import psycopg

    audit, observation, snapshot, _, _ = audit_case
    wrong = observation.model_copy(update={"trusted_context_digest": "9" * 64})
    link = RequestAuditLink(observation=wrong, target_scope=snapshot.scope,
                            domain_validation="passed", contract_validation="passed")
    with pytest.raises(ValueError, match="request audit observation mismatch"):
        audited_grant(audit_case, link=link)
    with psycopg.connect(audit._dsn) as connection:
        assert connection.execute("SELECT count(*) FROM response_admissions").fetchone() == (0,)
        assert connection.execute("SELECT count(*) FROM request_observation_results").fetchone() == (0,)
    assert audited_grant(audit_case).grant_revision == 1


def test_audit_storage_failure_rolls_back_grant(audit_case):
    """以真正 SQL 約束故障阻止結果保存，不能留下未稽核的發送准入。"""
    import psycopg

    audit, _, _, _, _ = audit_case
    with psycopg.connect(audit._dsn) as connection:
        connection.execute("ALTER TABLE request_observation_results ADD CONSTRAINT refuse_test_result CHECK (false)")
    with pytest.raises(psycopg.errors.CheckViolation):
        audited_grant(audit_case)
    with psycopg.connect(audit._dsn) as connection:
        assert connection.execute("SELECT count(*) FROM response_admissions").fetchone() == (0,)
        assert connection.execute("SELECT count(*) FROM request_observation_results").fetchone() == (0,)
        assert connection.execute("SELECT count(*) FROM request_observations").fetchone() == (1,)


def test_stopped_observation_cannot_acquire_new_admission(audit_case):
    """已標無法確認的請求不可再拿同一觀察核發新 Grant，避免覆寫已停止的結果。"""
    import psycopg

    audit, observation, _, _, _ = audit_case
    audit.close_unverifiable(observation)
    with pytest.raises(psycopg.errors.UniqueViolation):
        audited_grant(audit_case)
    with psycopg.connect(audit._dsn) as connection:
        assert connection.execute("SELECT count(*) FROM response_admissions").fetchone() == (0,)
        assert connection.execute("SELECT outcome FROM request_observation_results").fetchone() == ("unverifiable",)


def test_audit_and_grant_survive_real_commit_reply_loss(audit_case):
    """真正遺失 COMMIT 回覆後不重核 Grant，獨立讀取仍查得同一准入與觀察關聯。"""
    import psycopg
    from test_postgres_network import lost_commit_proxy

    audit, observation, _, _, _ = audit_case
    with lost_commit_proxy(audit._dsn) as (proxied, dropped):
        with pytest.raises(psycopg.OperationalError):
            audited_grant(audit_case, control=PostgresAdmissionControl(proxied), registry=PostgresProjectionRegistry(proxied))
        assert dropped.is_set()
    audit.close_unverifiable(observation)
    with psycopg.connect(audit._dsn) as connection:
        assert connection.execute("SELECT count(*) FROM response_admissions").fetchone() == (1,)
        assert connection.execute("SELECT r.outcome,r.admission_id=a.admission_id FROM request_observation_results r "
            "JOIN response_admissions a USING(admission_id)").fetchone() == ("admitted", True)


def test_audit_models_reject_unverified_versions_or_validation_attestations(audit_case):
    """不可變觀察仍須重驗複製更新，未通過的驗證值不能冒充正向 Grant 關聯。"""
    _, observation, snapshot, _, _ = audit_case
    with pytest.raises(ValidationError):
        observation.model_copy(update={"base_state_version": True})
    with pytest.raises(ValidationError):
        RequestAuditLink(observation=observation, target_scope=snapshot.scope,
                         domain_validation="unverifiable", contract_validation="passed")
    with pytest.raises(ValidationError):
        RequestAuditLink(observation=observation, target_scope=snapshot.scope.model_copy(update={"deployment_id": "other"}),
                         domain_validation="passed", contract_validation="passed")


def test_mismatched_observation_cannot_close_another_request(audit_case):
    """知道觀察 ID 也不能以其他 request 摘要把它標為未知，避免錯誤關閉阻止合法 Grant。"""
    import psycopg

    audit, observation, _, _, _ = audit_case
    wrong = observation.model_copy(update={"request_id_digest": "9" * 64})
    with pytest.raises(ValueError, match="request audit observation mismatch"):
        audit.close_unverifiable(wrong)
    with psycopg.connect(audit._dsn) as connection:
        assert connection.execute("SELECT count(*) FROM request_observation_results").fetchone() == (0,)
    assert audited_grant(audit_case) is not None


def test_validated_security_error_has_audit_link_without_fake_committed_state(audit_case):
    """已核准的業務拒絕也能關聯驗證與發送權，但安全錯誤來源不提供快照或提交證據。"""
    import psycopg

    audit, _, _, _, _ = audit_case
    admission = audited_grant(audit_case, source=SecurityErrorSource(template_id="synthetic-conflict", contract_revision="1"))
    assert admission is not None
    with psycopg.connect(audit._dsn) as connection:
        assert connection.execute("SELECT source_kind,committed_state_version,committed_state_hash FROM request_observation_results").fetchone() == ("security_error", None, None)


def test_legacy_request_audit_cannot_accept_unprotected_cross_scope_creation(audit_case):
    """舊型 Prototype Grant 不可繞過 Protected Creator Lineage 來放行新型 Source。"""
    import psycopg

    audit, _, snapshot, _, _ = audit_case
    source = CartCreationSource(derived_session_id=uuid4().hex,
                                derived_world_generation_id=uuid4().hex,
                                resource_id="cart_" + uuid4().hex,
                                commit_attempt_id=str(uuid4()), state_version=1,
                                state_hash="d" * 64)
    assert source.derived_world_generation_id != snapshot.scope.world_generation_id
    with pytest.raises(ValueError, match="cart creation requires protected authorizer"):
        audited_grant(audit_case, source=source)
    with psycopg.connect(audit._dsn) as connection:
        assert connection.execute("SELECT count(*) FROM response_admissions").fetchone() == (0,)
        assert connection.execute("SELECT count(*) FROM request_observation_results").fetchone() == (0,)


@pytest.mark.parametrize("first", ["grant", "stop"])
def test_concurrent_stop_and_grant_follow_real_database_commit_order(audit_case, first):
    """確認第二交易實際等待第一交易的結果鍵，再依提交順序保留正向或未知終態。"""
    from concurrent.futures import ThreadPoolExecutor
    from contextlib import nullcontext
    from threading import Event
    import time
    from unittest.mock import patch
    import psycopg

    audit, observation, _, _, _ = audit_case
    ready = Event()
    backend = []

    def waiting_connection():
        """公開第二連線 backend PID，並設定有限 SQL 等待，避免失敗案例留下阻塞 worker。"""
        connection = psycopg.connect(audit._dsn)
        connection.execute("SET LOCAL statement_timeout='10s'")
        backend.append(connection.info.backend_pid)
        ready.set()
        return connection

    def second_transaction():
        """使用另一個控制器執行相反操作，讓真正唯一鍵決定最終贏家。"""
        writer = PostgresRequestAudit(audit._dsn) if first == "grant" else PostgresAdmissionControl(audit._dsn)
        with patch.object(writer, "_connection", side_effect=waiting_connection):
            if first == "grant":
                return writer.close_unverifiable(observation)
            return audited_grant(audit_case, control=writer)

    leader = psycopg.connect(audit._dsn)
    try:
        if first == "grant":
            writer = PostgresAdmissionControl(audit._dsn)
            with patch.object(writer, "_connection", return_value=nullcontext(leader)):
                assert audited_grant(audit_case, control=writer) is not None
        else:
            writer = PostgresRequestAudit(audit._dsn)
            with patch.object(writer, "_connection", return_value=nullcontext(leader)):
                writer.close_unverifiable(observation)
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(second_transaction)
            try:
                assert ready.wait(10), "second transaction did not connect"
                waiting = False
                with psycopg.connect(audit._dsn) as observer:
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        if leader.info.backend_pid in observer.execute("SELECT pg_blocking_pids(%s)", (backend[0],)).fetchone()[0]:
                            waiting = True
                            break
                        time.sleep(.02)
                assert waiting, "second transaction did not wait on the first"
            finally:
                leader.commit()
            if first == "grant":
                assert future.result(timeout=15) is None
            else:
                with pytest.raises(psycopg.errors.UniqueViolation):
                    future.result(timeout=15)
    finally:
        leader.close()
    with psycopg.connect(audit._dsn) as connection:
        assert connection.execute("SELECT outcome FROM request_observation_results").fetchone() == (
            "admitted" if first == "grant" else "unverifiable",)
        assert connection.execute("SELECT count(*) FROM response_admissions").fetchone() == (1 if first == "grant" else 0,)
