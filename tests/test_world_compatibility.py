"""世界政策固定、契約切換、舊世界拒絕及事件不可變邊界的驗收。"""

from copy import deepcopy

import pytest
from pydantic import ValidationError

from deception.world import InMemoryWorldStore, PostgresWorldStore, WorldCompatibility, WorldScope, WorldSnapshot, WorldStoreError
from deception.world.models import WORLD_COMPATIBILITY_KEY
from deception.world.session import PostgresSessionWorlds
from test_postgres_conformance import isolated_test_dsn, projection_evidence
from test_session_worlds import binding


def compatibility(*, adapter="engine-1", include_second=True):
    """建立兩個經部署明列允許的投影；其 operation 契約 hash 不屬於世界政策。"""
    first = projection_evidence()
    second_profile = first.compatibility_profile.model_copy(update={"profile_id": "second", "profile_sha256": "4" * 64})
    profiles = [first.compatibility_profile]
    if include_second:
        profiles.append(second_profile)
    return WorldCompatibility.create(world_schema_version="1", domain_adapter_version=adapter,
                                    source_spec_sha256="1" * 64, profiles=profiles)


def test_policy_allows_reviewed_contracts_without_rebinding_world():
    """同一 Profile 的不同契約及明列的跨投影可沿用世界，未登錄 Profile 則拒絕。"""
    policy = compatibility()
    first = projection_evidence()
    assert policy.permits(first)
    assert policy.permits(first.model_copy(update={"projection_contract_hash": "5" * 64}))
    second = first.model_copy(update={"compatibility_profile": first.compatibility_profile.model_copy(
        update={"profile_id": "second", "profile_sha256": "4" * 64})})
    assert policy.permits(second)
    assert not compatibility(include_second=False).permits(second)
    assert not policy.permits(first.model_copy(update={"compatibility_profile":
        first.compatibility_profile.model_copy(update={"domain_adapter_version": "unreviewed"})}))
    with pytest.raises(TypeError):
        policy.projection_profiles.clear()


def test_policy_is_bound_to_snapshot_hash_and_cannot_change_in_cas():
    """政策欄位與全部允許 Profile 受摘要及快照 hash 保護，CAS 只更新業務資料。"""
    scope = WorldScope(environment_id="test", deployment_id="isolated", session_id="session", world_generation_id="world")
    state = {"stock": 5, WORLD_COMPATIBILITY_KEY: compatibility().model_dump(mode="json")}
    store = InMemoryWorldStore()
    created = store.create_if_absent(scope, state)
    assert created.compatibility == compatibility()
    changed = deepcopy(state)
    changed[WORLD_COMPATIBILITY_KEY]["domain_adapter_version"] = "other"
    with pytest.raises(ValidationError, match="world compatibility policy hash"):
        WorldSnapshot.create(scope, changed)
    updated = store.compare_and_swap(scope, expected_version=1, state={**state, "stock": 4})
    assert updated.compatibility == created.compatibility
    for proposed in ({"stock": 3}, {"stock": 3, WORLD_COMPATIBILITY_KEY: compatibility(adapter="engine-2").model_dump(mode="json")}):
        with pytest.raises(WorldStoreError, match="world_compatibility_change_forbidden"):
            store.compare_and_swap(scope, expected_version=2, state=proposed)
    assert store.load(scope) == updated


def test_session_rejects_policy_changes_without_reinitialization(isolated_test_dsn):
    """部署更換引擎或允許集合後，舊世界讀取與解析皆拒絕且無新世代／事件。"""
    import psycopg

    original = PostgresSessionWorlds(isolated_test_dsn, compatibility=compatibility())
    snapshot = original.resolve(binding(), {"stock": 5}, now=100, ttl=60)
    assert snapshot.compatibility == compatibility()
    assert original.admit_read(binding(), request_binding_digest="a" * 64, now=101, expires_at=110).snapshot == snapshot
    for policy in (compatibility(adapter="engine-2"), compatibility(include_second=False)):
        changed = PostgresSessionWorlds(isolated_test_dsn, compatibility=policy)
        with pytest.raises(WorldStoreError, match="world_compatibility_mismatch"):
            changed.resolve(binding(), {"stock": 999}, now=101, ttl=600)
        with pytest.raises(WorldStoreError, match="world_compatibility_mismatch"):
            changed.inspect_binding(binding(), now=101)
        with pytest.raises(WorldStoreError, match="world_compatibility_mismatch"):
            changed.admit_read(binding(), request_binding_digest="b" * 64, now=101, expires_at=110)
    assert original.inspect_binding(binding(), now=101) == snapshot
    with psycopg.connect(isolated_test_dsn) as observer:
        assert observer.execute("SELECT count(*) FROM world_snapshots").fetchone() == (1,)
        assert observer.execute("SELECT count(*) FROM world_initializations").fetchone() == (1,)
        assert observer.execute("SELECT count(*) FROM read_admissions").fetchone() == (1,)


def test_legacy_world_is_not_automatically_approved(isolated_test_dsn):
    """未保存世界政策的舊快照不能因新程式啟動便獲得版本證據，也不被自動替換。"""
    old = PostgresSessionWorlds(isolated_test_dsn)
    snapshot = old.resolve(binding(), {"stock": 5}, now=100, ttl=60)
    assert snapshot.compatibility is None
    strict = PostgresSessionWorlds(isolated_test_dsn, compatibility=compatibility())
    with pytest.raises(WorldStoreError, match="world_compatibility_mismatch"):
        strict.resolve(binding(), {"stock": 999}, now=101, ttl=600)
    assert old.inspect_binding(binding(), now=101) == snapshot


def test_postgres_cas_preserves_world_policy_and_receipts(isolated_test_dsn):
    """共享 CAS 拒絕移除／替換政策，失敗不留收據或前進版本；正常業務更新保留政策。"""
    from uuid import uuid4

    service = PostgresSessionWorlds(isolated_test_dsn, compatibility=compatibility())
    current = service.resolve(binding(), {"stock": 5}, now=100, ttl=60)
    store = PostgresWorldStore(isolated_test_dsn)
    for state in ({"stock": 3}, {"stock": 3, WORLD_COMPATIBILITY_KEY: compatibility(adapter="engine-2").model_dump(mode="json")}):
        attempt = uuid4()
        with pytest.raises(WorldStoreError, match="world_compatibility_change_forbidden"):
            store.compare_and_swap(current.scope, expected_version=1, state=state, commit_attempt_id=attempt)
        assert store.get_commit_result(current.scope, attempt, authorized_scope=current.scope).status == "not_found"
        assert service.inspect_binding(binding(), now=101) == current
    updated = store.compare_and_swap(current.scope, expected_version=1,
                                     state={**deepcopy(current.state), "stock": 4}, commit_attempt_id=uuid4())
    assert updated.version == 2 and updated.compatibility == current.compatibility
