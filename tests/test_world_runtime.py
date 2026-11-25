"""唯讀 Synthetic World、CAS 與 ResponseAdmission 的核心行為驗收。"""

import pytest

from deception.world import (
    AdmissionControl,
    AdmissionOperationResult,
    AdmissionState,
    DeviationApproval,
    InMemoryWorldStore,
    ProjectionCompatibilityProfile,
    ProjectionEvidence,
    ProjectionRegistry,
    SecurityErrorSource,
    SnapshotSource,
    WorldScope,
    WorldStoreError,
    WorldSnapshot,
    WorldStoreStatus,
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


def projection_evidence(*, official_schema_valid: bool = True):
    """建立含官方規格與有效投影核准證據的測試資料。"""
    return ProjectionEvidence(
        source_spec_sha256=digest("1"),
        compatibility_profile=ProjectionCompatibilityProfile(
            profile_id="medusa-store",
            profile_version="1",
            profile_sha256=digest("2"),
            platform_id="medusa",
            platform_version="2.22.4",
            source_spec_sha256=digest("1"),
            world_schema_version="1",
            domain_adapter_version="1",
        ),
        projection_contract_hash=digest("3"),
        official_schema_valid=official_schema_valid,
        effective_projection_valid=True,
        deviation_approval=(
            DeviationApproval(
                approval_id="approval-1",
                approval_revision="1",
                source_spec_sha256=digest("1"),
                projection_contract_hash=digest("3"),
                approved_profile_sha256=digest("2"),
                reason="reviewed nullable difference",
            )
            if not official_schema_valid
            else None
        ),
    )


def grant(control: AdmissionControl, registry: ProjectionRegistry | None = None):
    """建立一份可測試 Claim 與 Send Authorization 的准入。"""
    evidence = projection_evidence()
    if registry is None:
        registry = ProjectionRegistry()
        registry.register(evidence, registry_revision=1)
    return control.grant(
        world_generation_id="generation-test",
        request_binding_digest=digest("b"),
        candidate_ref="candidate-1",
        candidate_hash=digest("c"),
        immutable_body_hash=digest("d"),
        semantic_headers_hash=digest("e"),
        projection_contract_hash=digest("3"),
        authorization_revision="auth-1",
        authorization_deadline=100,
        transmission_deadline=200,
        source=source(),
        projection_evidence=evidence,
        projection_registry=registry,
    )


def test_admission_rejects_projection_not_authorized_by_registry():
    """確認未知或撤銷的 Projection 不會取得 ResponseAdmission。"""
    control = AdmissionControl()
    assert grant(control, ProjectionRegistry()) is None


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


def test_store_reports_expired_and_unavailable_without_creating_a_world():
    """確認 Store 對過期與不可用狀態明確回報，且故障時不建立替代世界。"""
    store = InMemoryWorldStore()
    store.create_if_absent(scope(), {"version": "first"}, expires_at=10)
    assert store.load_result(scope(), now=10).status is WorldStoreStatus.EXPIRED
    assert (
        store.load_result(scope(), authorized_scope=scope(session_id="other")).status
        is WorldStoreStatus.SCOPE_MISMATCH
    )
    store.set_availability(False)
    assert store.load_result(scope()).status is WorldStoreStatus.STORAGE_UNAVAILABLE
    with pytest.raises(WorldStoreError, match="storage_unavailable"):
        store.create_if_absent(scope(session_id="other"), {"version": "replacement"})


def test_projection_evidence_requires_approval_for_effective_deviation():
    """確認官方 Schema 不符時，沒有核准差異證據就拒絕有效投影。"""
    with pytest.raises(ValueError, match="deviation approval"):
        ProjectionEvidence(
            source_spec_sha256=digest("1"),
            compatibility_profile=ProjectionCompatibilityProfile(
                profile_id="medusa-store",
                profile_version="1",
                profile_sha256=digest("2"),
                platform_id="medusa",
                platform_version="2.22.4",
                source_spec_sha256=digest("1"),
                world_schema_version="1",
                domain_adapter_version="1",
            ),
            projection_contract_hash=digest("3"),
            official_schema_valid=False,
            effective_projection_valid=True,
        )


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


def test_admission_events_share_a_verifiable_control_sequence():
    """確認 Grant、Claim 與 Send Authorization 都留下同一序列的單調 revision。"""
    control = AdmissionControl()
    admission = grant(control)
    assert admission is not None
    assert control.claim(admission.admission_id, owner="renderer-1", now=99) is AdmissionOperationResult.SUCCESS
    cutover_revision = control.cutover("generation-test")
    assert control.authorize_send(admission.admission_id, now=100) is AdmissionOperationResult.SUCCESS
    revisions = [
        control.event_revision(admission.admission_id, event)
        for event in ("grant", "claim", "cutover", "send_authorization")
    ]
    assert revisions[2] == cutover_revision
    assert revisions == sorted(revisions)
    assert len(set(revisions)) == 4


def test_unknown_admission_never_rebuilds_itself():
    """確認未知 Admission 只回拒絕，不因查詢而自動建立新准入。"""
    control = AdmissionControl()
    assert control.state("missing") is None
    assert control.claim("missing", owner="renderer-1", now=1) is AdmissionOperationResult.REJECTED
    assert control.state("missing") is None


def test_admission_exposes_candidate_references_for_retention_gc():
    """確認有效准入會提供 Candidate GC 必須保護的引用。"""
    control = AdmissionControl()
    admission = grant(control)
    assert admission is not None
    assert control.active_candidate_refs(now=99) == frozenset({"candidate-1"})
    assert control.claim(admission.admission_id, owner="renderer-1", now=99) is AdmissionOperationResult.SUCCESS
    assert control.active_candidate_refs(now=199) == frozenset({"candidate-1"})
    assert control.active_candidate_refs(now=200) == frozenset()


def test_admission_deadline_equality_is_fail_closed():
    """確認時鐘剛好到達期限時 Claim 與發送授權都拒絕。"""
    control = AdmissionControl()
    admission = grant(control)
    assert admission is not None
    assert control.claim(admission.admission_id, owner="renderer", now=100) is AdmissionOperationResult.EXPIRED

    other = AdmissionControl()
    second = grant(other)
    assert second is not None
    assert other.claim(second.admission_id, owner="renderer", now=99) is AdmissionOperationResult.SUCCESS
    assert other.authorize_send(second.admission_id, now=200) is AdmissionOperationResult.REJECTED


def test_emergency_revocation_is_persistent_terminal_boundary():
    """確認 Emergency Revocation 後 Admission 進入終止狀態且不能重新發送。"""
    control = AdmissionControl()
    admission = grant(control)
    assert admission is not None
    assert control.claim(admission.admission_id, owner="renderer", now=99) is AdmissionOperationResult.SUCCESS
    assert control.authorize_send(admission.admission_id, now=100, revoked=True) is AdmissionOperationResult.REJECTED
    assert control.state(admission.admission_id) is AdmissionState.ABANDONED
    assert control.authorize_send(admission.admission_id, now=101) is AdmissionOperationResult.REJECTED


@pytest.mark.parametrize("send_first", [True, False])
def test_memory_emergency_boundary(send_first):
    """程序內原型與共享 Store 都以發送授權作緊急撤銷邊界。"""
    control = AdmissionControl()
    admission = grant(control)
    assert control.claim(admission.admission_id, owner="test", now=1) is AdmissionOperationResult.SUCCESS
    if send_first:
        assert control.authorize_send(admission.admission_id, now=2) is AdmissionOperationResult.SUCCESS
    revision = control.emergency_revoke(admission.world_generation_id)
    assert control.emergency_revoke(admission.world_generation_id) == revision
    assert control.authorize_send(admission.admission_id, now=3) is AdmissionOperationResult.REJECTED
    assert control.state(admission.admission_id) is (
        AdmissionState.SEND_AUTHORIZED if send_first else AdmissionState.ABANDONED)
    assert grant(control) is None

@pytest.mark.parametrize("at_deadline", [False, True])
def test_memory_post_authorization_revoke_preserves_owner_and_deadline(at_deadline):
    """Auth 先提交後撤銷不可取消起送，但不延長期限或允許非原 Claim owner。"""
    control = AdmissionControl()
    admission = grant(control)
    assert admission is not None
    identifier = admission.admission_id
    assert control.claim(identifier, owner="sender", now=1) is AdmissionOperationResult.SUCCESS
    assert control.authorize_send(identifier, now=2) is AdmissionOperationResult.SUCCESS
    control.emergency_revoke(admission.world_generation_id)
    assert control.start_send(identifier, owner="other", now=3) is AdmissionOperationResult.REJECTED
    now = admission.transmission_deadline if at_deadline else admission.transmission_deadline - 1
    result = control.start_send(identifier, owner="sender", now=now)
    assert result is (AdmissionOperationResult.EXPIRED if at_deadline else AdmissionOperationResult.SUCCESS)
    assert control.state(identifier) is (
        AdmissionState.EXPIRED if at_deadline else AdmissionState.SEND_STARTED
    )
    assert control.start_send(identifier, owner="sender", now=now) is AdmissionOperationResult.REJECTED


def test_snapshot_nested_state_and_scope_are_immutable():
    """凍結巢狀 JSON 與 scope，明確 deepcopy 只產生可變提案，不改原快照。"""
    from copy import deepcopy

    original = {"items": [{"quantity": 2}]}
    snapshot = WorldSnapshot.create(scope(), original)
    original["items"][0]["quantity"] = 9
    assert snapshot.state["items"][0]["quantity"] == 2
    with pytest.raises(TypeError):
        snapshot.state["items"][0]["quantity"] = 3
    with pytest.raises(TypeError):
        snapshot.state["items"].append({})
    with pytest.raises(ValueError):
        snapshot.scope.session_id = "other"
    proposal = deepcopy(snapshot.state)
    proposal["items"][0]["quantity"] = 1
    assert snapshot.state["items"][0]["quantity"] == 2
    copied = snapshot.model_copy(deep=True)
    with pytest.raises(TypeError):
        copied.state["items"].clear()
    assert WorldSnapshot.model_validate_json(snapshot.model_dump_json()) == snapshot


def test_memory_commit_lookup_preserves_original_version_and_expiry():
    """原型 Store 保存原提交收據與原期限，不因後續 CAS 或查詢改寫狀態。"""
    from uuid import uuid4

    store = InMemoryWorldStore()
    target = scope()
    store.create_if_absent(target, {"quantity": 3}, expires_at=100)
    attempt = uuid4()
    committed = store.compare_and_swap(target, expected_version=1, state={"quantity": 2}, commit_attempt_id=attempt)
    later = store.compare_and_swap(target, expected_version=2, state={"quantity": 1})
    receipt = store.get_commit_result(target, attempt, authorized_scope=target)
    assert (receipt.status, receipt.state_version, receipt.state_hash) == ("committed", 2, committed.state_hash)
    assert later.expires_at == 100
    assert store.get_commit_result(target, uuid4(), authorized_scope=target).status == "not_found"
    assert store.get_commit_result(target, attempt, authorized_scope=scope(session_id="other")).status == "unverifiable"
    with pytest.raises(WorldStoreError, match="already_used"):
        store.compare_and_swap(target, expected_version=3, state={"quantity": 0}, commit_attempt_id=attempt)
    assert store.load(target) == later


@pytest.mark.parametrize("changes", [
    {"hash_encoding_version": 2},
    {"candidate_serialization_version": 2},
    {"hash_encoding_version": True},
    {"hash_encoding_version": 1.0},
    {"candidate_serialization_version": True},
    {"candidate_serialization_version": 1.0},
    {"world_generation_id": "another-generation"},
    {"projection_contract_hash": "f" * 64},
])
def test_admission_rejects_unknown_encoding_or_mixed_evidence(changes):
    """持久化准入拒絕未知封套版本、跨世代來源及另一份投影契約。"""
    from deception.world.models import ResponseAdmission

    admission = grant(AdmissionControl())
    assert admission.hash_encoding_version == admission.candidate_serialization_version == 1
    values = admission.model_dump()
    values.update(changes)
    with pytest.raises(ValueError):
        ResponseAdmission.model_validate(values)


def test_admission_rejects_invalid_effective_projection():
    """即使契約 hash 相同，也不能把未通過有效投影的證據保存成准入。"""
    from deception.world.models import ResponseAdmission

    values = grant(AdmissionControl()).model_dump()
    values["projection_evidence"]["effective_projection_valid"] = False
    with pytest.raises(ValueError, match="valid effective projection"):
        ResponseAdmission.model_validate(values)


def test_admission_nested_evidence_is_immutable():
    """Grant 保存後不能藉共享來源或 Profile 物件原地改寫准入的證據。"""
    admission = grant(AdmissionControl())
    with pytest.raises(ValueError):
        admission.source.state_hash = "f" * 64
    with pytest.raises(ValueError):
        admission.projection_evidence.official_schema_valid = False
    with pytest.raises(ValueError):
        admission.projection_evidence.compatibility_profile.platform_version = "other"
    assert admission.source.state_hash == "a" * 64
