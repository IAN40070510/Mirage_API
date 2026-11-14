"""唯讀 Synthetic World、CAS 與 ResponseAdmission 的核心行為驗收。"""

import pytest

from deception.world import (
    AdmissionControl,
    AdmissionOperationResult,
    AdmissionState,
    InMemoryWorldStore,
    SecurityErrorSource,
    SnapshotSource,
    WorldScope,
    WorldStoreError,
    WorldSnapshot,
)


def scope(**changes):
    """建立測試用的完整 WorldScope，避免測試省略隔離維度。"""
    values = {
        "environment_id": "env-test",
        "deployment_id": "deploy-test",
        "session_id": "session-test",
        "world_generation_id": "generation-test",
    }
    values.update(changes)
    return WorldScope(**values)


def digest(char: str) -> str:
    """建立符合模型格式的測試摘要。"""
    return char * 64


def source():
    """建立只引用已知 Snapshot 完整性證據的測試來源。"""
    return SnapshotSource(
        read_admission_id="read-1",
        world_generation_id="generation-test",
        state_version=1,
        state_hash=digest("a"),
    )


def grant(control: AdmissionControl):
    """建立一份可測試 Claim 與 Send Authorization 的准入。"""
    return control.grant(
        world_generation_id="generation-test",
        request_binding_digest=digest("b"),
        candidate_ref="candidate-1",
        candidate_hash=digest("c"),
        immutable_body_hash=digest("d"),
        semantic_headers_hash=digest("e"),
        projection_contract_hash=digest("f"),
        authorization_revision="auth-1",
        authorization_deadline=100,
        transmission_deadline=200,
        source=source(),
    )


def test_snapshot_hash_and_scope_are_verified():
    """確認 Snapshot 會驗證內容雜湊，且 scope 變更不會被忽略。"""
    snapshot = WorldSnapshot.create(scope(), {"product_id": "prod-1"})
    assert snapshot.version == 1
    with pytest.raises(ValueError):
        WorldSnapshot(
            scope=scope(),
            version=1,
            state={"product_id": "tampered"},
            state_hash=snapshot.state_hash,
        )


def test_store_create_if_absent_and_cas_reject_conflicts():
    """確認並行初始化只保留第一份 World，CAS 衝突不覆寫現有版本。"""
    store = InMemoryWorldStore()
    first = store.create_if_absent(scope(), {"version": "first"})
    same = store.create_if_absent(scope(), {"version": "second"})
    assert same == first
    updated = store.compare_and_swap(scope(), expected_version=1, state={"version": "updated"})
    assert updated.version == 2
    assert store.load(scope()).state == {"version": "updated"}
    with pytest.raises(WorldStoreError, match="version_conflict"):
        store.compare_and_swap(scope(), expected_version=1, state={"version": "stale"})


def test_admission_allows_pre_cutover_grant_to_claim_after_cutover():
    """確認 admission_scoped_v1 允許 Cutover 前 Grant 在期限內於 Cutover 後 Claim。"""
    control = AdmissionControl()
    admission = grant(control)
    assert admission is not None
    cutover_revision = control.cutover("generation-test")
    assert admission.grant_revision < cutover_revision
    assert control.cutover_revision("generation-test") == cutover_revision
    assert control.claim(admission.admission_id, owner="renderer-1", now=99) is AdmissionOperationResult.SUCCESS
    assert control.state(admission.admission_id) is AdmissionState.CLAIMED


def test_admission_rejects_new_grant_after_cutover_and_reuses_no_claim():
    """確認舊世代 Cutover 後不能新 Grant，且同一准入不能被第二個 Renderer 重用。"""
    control = AdmissionControl()
    control.cutover("generation-test")
    assert grant(control) is None

    other = AdmissionControl()
    admission = grant(other)
    assert admission is not None
    assert other.claim(admission.admission_id, owner="renderer-1", now=99) is AdmissionOperationResult.SUCCESS
    assert other.claim(admission.admission_id, owner="renderer-2", now=99) is AdmissionOperationResult.ALREADY_CLAIMED


def test_emergency_revocation_blocks_send_authorization():
    """確認 Emergency Revocation 在 Send Authorization 前阻止發送。"""
    control = AdmissionControl()
    admission = grant(control)
    assert admission is not None
    assert control.claim(admission.admission_id, owner="renderer-1", now=99) is AdmissionOperationResult.SUCCESS
    assert control.authorize_send(admission.admission_id, now=100, revoked=True) is AdmissionOperationResult.REJECTED
    assert control.state(admission.admission_id) is AdmissionState.ABANDONED


def test_unknown_admission_never_rebuilds_itself():
    """確認未知 Admission 只回拒絕，不因查詢而自動建立新准入。"""
    control = AdmissionControl()
    assert control.state("missing") is None
    assert control.claim("missing", owner="renderer-1", now=1) is AdmissionOperationResult.REJECTED
    assert control.state("missing") is None
