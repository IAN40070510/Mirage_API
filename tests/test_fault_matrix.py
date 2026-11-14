"""第一版 Fault Matrix：Store、Projection Registry 與 Admission 的拒絕路徑。"""

import pytest

from deception.world import (
    AdmissionControl,
    AdmissionOperationResult,
    ProjectionAuthorizationResult,
    ProjectionRegistry,
    WorldScope,
    InMemoryWorldStore,
)


def scope() -> WorldScope:
    """建立 Fault Matrix 使用的固定隔離 scope。"""
    return WorldScope(
        environment_id="fault",
        deployment_id="pytest",
        session_id="session-1",
        world_generation_id="generation-1",
    )


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        ("missing", "session_not_found"),
        ("scope", "scope_mismatch"),
        ("unavailable", "storage_unavailable"),
    ],
)
def test_world_store_fault_matrix(failure: str, expected: str):
    """確認 Store 故障分類不會回傳替代 World。"""
    store = InMemoryWorldStore()
    if failure == "scope":
        result = store.load_result(scope(), authorized_scope=scope())
        assert result.status.value == "session_not_found"
        result = store.load_result(scope(), authorized_scope=scope_with_other_session())
    else:
        if failure == "unavailable":
            store.set_availability(False)
        result = store.load_result(scope())
    assert result.status.value == expected


def scope_with_other_session() -> WorldScope:
    """建立不具授權關聯的替代 Session scope。"""
    return scope().model_copy(update={"session_id": "session-other"})


def test_unknown_admission_and_revoked_projection_fail_closed():
    """確認未知 Admission 與撤銷 Projection 都拒絕，不自動重建或回退。"""
    control = AdmissionControl()
    assert control.claim("missing", owner="renderer", now=1) is AdmissionOperationResult.REJECTED
    registry = ProjectionRegistry()
    decision = registry.authorize(
        projection_contract_hash="a" * 64,
        source_spec_sha256="b" * 64,
        compatibility_profile_sha256="c" * 64,
    )
    assert decision.result is ProjectionAuthorizationResult.UNKNOWN_CONTRACT
