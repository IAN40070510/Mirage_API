"""PostgreSQL 共享 Store 與雙 Instance 准入一致性驗收。"""

import os
from pathlib import Path
from uuid import uuid4

import pytest

from deception.world import (
    AdmissionOperationResult,
    AdmissionState,
    PostgresCandidateStore,
    PostgresReplayStore,
    PostgresAdmissionControl,
    PostgresWorldStore,
    ProjectionCompatibilityProfile,
    ProjectionEvidence,
    PostgresProjectionRegistry,
    SnapshotSource,
    WorldScope,
    WorldStoreError,
)


def digest(char: str) -> str:
    """建立符合 SHA-256 欄位格式的測試摘要。"""
    return char * 64


def postgres_dsn() -> str:
    """取得 Conformance 使用的 DSN，缺少時明確跳過而不偽造通過。"""
    dsn = os.environ.get("MIRAGE_POSTGRES_TEST_DSN") or os.environ.get("MIRAGE_POSTGRES_DSN")
    if not dsn:
        pytest.skip("MIRAGE_POSTGRES_TEST_DSN or MIRAGE_POSTGRES_DSN is not configured")
    pytest.importorskip("psycopg")
    return dsn


def apply_schema(dsn: str) -> None:
    """在測試資料庫套用版本化 World Runtime migration。"""
    import psycopg

    migration = Path(__file__).parents[1] / "migrations" / "001_world_runtime.sql"
    with psycopg.connect(dsn) as connection:
        connection.execute(migration.read_text(encoding="utf-8"))


def scope(suffix: str) -> WorldScope:
    """建立本次測試專用的完整隔離 scope。"""
    return WorldScope(
        environment_id="conformance",
        deployment_id="pytest",
        session_id=f"session-{suffix}",
        world_generation_id=f"generation-{suffix}",
    )


def projection_evidence(contract_hash: str | None = None) -> ProjectionEvidence:
    """建立可被 ResponseAdmission 引用的官方投影證據。"""
    selected_contract = contract_hash or digest("3")
    return ProjectionEvidence(
        source_spec_sha256=digest("1"),
        compatibility_profile=ProjectionCompatibilityProfile(
            profile_id="conformance",
            profile_version="1",
            profile_sha256=digest("2"),
            platform_id="test",
            platform_version="1",
            source_spec_sha256=digest("1"),
            world_schema_version="1",
            domain_adapter_version="1",
        ),
        projection_contract_hash=selected_contract,
        official_schema_valid=True,
        effective_projection_valid=True,
    )


def grant(control: PostgresAdmissionControl, generation_id: str):
    """建立跨 Instance Claim 測試使用的一次性准入。"""
    evidence = projection_evidence(uuid4().hex * 2)
    registry = PostgresProjectionRegistry(postgres_dsn_without_skip())
    registry.register(evidence, registry_revision=1)
    return control.grant(
        world_generation_id=generation_id,
        request_binding_digest=digest("a"),
        candidate_ref="candidate-conformance",
        candidate_hash=digest("b"),
        immutable_body_hash=digest("c"),
        semantic_headers_hash=digest("d"),
        projection_contract_hash=evidence.projection_contract_hash,
        authorization_revision="auth-1",
        authorization_deadline=2_000_000_000,
        transmission_deadline=2_000_000_100,
        source=SnapshotSource(
            read_admission_id="read-conformance",
            world_generation_id=generation_id,
            state_version=1,
            state_hash=digest("e"),
        ),
        projection_evidence=evidence,
        projection_registry=registry,
    )


def postgres_dsn_without_skip() -> str:
    """讀取已由測試前置條件確認存在的 PostgreSQL DSN。"""
    return os.environ.get("MIRAGE_POSTGRES_TEST_DSN") or os.environ["MIRAGE_POSTGRES_DSN"]


def test_postgres_world_store_is_shared_across_two_instances():
    """確認兩個獨立 Store 物件共用 Snapshot 並拒絕 stale CAS。"""
    dsn = postgres_dsn()
    apply_schema(dsn)
    test_scope = scope(uuid4().hex)
    first_instance = PostgresWorldStore(dsn)
    second_instance = PostgresWorldStore(dsn)
    created = first_instance.create_if_absent(test_scope, {"owner": "first"})
    assert second_instance.load(test_scope) == created
    updated = first_instance.compare_and_swap(test_scope, expected_version=1, state={"owner": "updated"})
    assert second_instance.load(test_scope) == updated
    with pytest.raises(WorldStoreError, match="version_conflict"):
        second_instance.compare_and_swap(test_scope, expected_version=1, state={"owner": "stale"})


def test_postgres_admission_claim_is_single_use_across_two_instances():
    """確認兩個獨立控制器對同一 Admission 只能有一個成功 Claim。"""
    dsn = postgres_dsn()
    apply_schema(dsn)
    generation_id = f"generation-{uuid4().hex}"
    first_instance = PostgresAdmissionControl(dsn)
    second_instance = PostgresAdmissionControl(dsn)
    admission = grant(first_instance, generation_id)
    assert admission is not None
    results = {
        first_instance.claim(admission.admission_id, owner="renderer-a", now=1),
        second_instance.claim(admission.admission_id, owner="renderer-b", now=1),
    }
    assert results == {
        AdmissionOperationResult.SUCCESS,
        AdmissionOperationResult.ALREADY_CLAIMED,
    }
    assert second_instance.state(admission.admission_id) is AdmissionState.CLAIMED


def test_postgres_candidate_retention_uses_shared_admission_references():
    """確認共享 Admission 引用可阻止另一個 Candidate Store 提前 GC。"""
    dsn = postgres_dsn()
    apply_schema(dsn)
    suffix = uuid4().hex
    test_scope = scope(suffix)
    admission_control = PostgresAdmissionControl(dsn)
    candidate_store = PostgresCandidateStore(dsn)
    admission = grant(admission_control, test_scope.world_generation_id)
    assert admission is not None
    candidate_store.put(test_scope, admission.candidate_ref, b"candidate-body", expires_at=10)
    protected = admission_control.active_candidate_refs(now=1)
    assert protected == frozenset({admission.candidate_ref})
    assert candidate_store.gc(now=10, protected_refs=protected) == ()
    assert candidate_store.load(
        test_scope,
        admission.candidate_ref,
        expected_hash="0" * 64,
        now=9,
    ).status.value == "candidate_hash_mismatch"
    assert len(candidate_store.gc(now=10, protected_refs=())) == 1


def test_postgres_admission_state_survives_new_instance_after_claim():
    """確認 Claim 提交後重新建立控制器仍拒絕重放，模擬程序重啟恢復。"""
    dsn = postgres_dsn()
    apply_schema(dsn)
    generation_id = f"generation-{uuid4().hex}"
    first_instance = PostgresAdmissionControl(dsn)
    second_instance = PostgresAdmissionControl(dsn)
    admission = grant(first_instance, generation_id)
    assert admission is not None
    assert first_instance.claim(admission.admission_id, owner="renderer-a", now=1) is AdmissionOperationResult.SUCCESS
    assert second_instance.state(admission.admission_id) is AdmissionState.CLAIMED
    assert second_instance.claim(admission.admission_id, owner="renderer-b", now=1) is AdmissionOperationResult.ALREADY_CLAIMED


def test_postgres_emergency_revocation_blocks_send_across_instances():
    """確認 Emergency Revocation 在 Send Authorization 前跨 Instance 阻止發送。"""
    dsn = postgres_dsn()
    apply_schema(dsn)
    generation_id = f"generation-{uuid4().hex}"
    first_instance = PostgresAdmissionControl(dsn)
    second_instance = PostgresAdmissionControl(dsn)
    admission = grant(first_instance, generation_id)
    assert admission is not None
    assert first_instance.claim(admission.admission_id, owner="renderer-a", now=1) is AdmissionOperationResult.SUCCESS
    assert second_instance.authorize_send(admission.admission_id, now=2, revoked=True) is AdmissionOperationResult.REJECTED
    assert first_instance.authorize_send(admission.admission_id, now=3) is AdmissionOperationResult.REJECTED
    assert second_instance.state(admission.admission_id) is AdmissionState.ABANDONED


def test_postgres_unavailable_store_is_fail_closed():
    """確認 PostgreSQL 無法連線時不會建立替代世界或准入。"""
    invalid_dsn = "postgresql://invalid:invalid@127.0.0.1:1/unavailable?connect_timeout=1"
    store = PostgresWorldStore(invalid_dsn)
    with pytest.raises(WorldStoreError, match="storage_unavailable"):
        store.create_if_absent(scope(uuid4().hex), {"state": "must-not-exist"})


def test_postgres_replay_is_single_use_across_instances():
    """確認兩個獨立 Replay Store 對同一 JTI 只有一個成功消費。"""
    from deception.world import ReplayConsumeResult

    dsn = postgres_dsn()
    apply_schema(dsn)
    first_instance = PostgresReplayStore(dsn)
    second_instance = PostgresReplayStore(dsn)
    values = {
        "issuer": "gateway",
        "audience": "mirage",
        "jti": f"jti-{uuid4().hex}",
        "expires_at": 2_000_000_000,
    }
    results = {
        first_instance.consume(**values, now=1),
        second_instance.consume(**values, now=1),
    }
    assert results == {ReplayConsumeResult.ACCEPTED, ReplayConsumeResult.REPLAY}
    assert first_instance.gc(now=2_000_000_000) == 1
