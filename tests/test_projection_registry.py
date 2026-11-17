"""Projection Registry 核准、版本與撤銷行為驗收。"""

import os
import uuid

import pytest
from test_postgres_conformance import isolated_test_dsn

from deception.world import (
    PostgresProjectionRegistry,
    ProjectionAuthorizationResult,
    ProjectionCompatibilityProfile,
    ProjectionEvidence,
    ProjectionRegistry,
    ProjectionRegistryError,
)


def digest(char: str) -> str:
    """建立符合 SHA-256 欄位格式的測試摘要。"""
    return char * 64


def evidence() -> ProjectionEvidence:
    """建立一份可登錄的官方 Projection Evidence。"""
    return ProjectionEvidence(
        source_spec_sha256=digest("1"),
        compatibility_profile=ProjectionCompatibilityProfile(
            profile_id="registry-test",
            profile_version="1",
            profile_sha256=digest("2"),
            platform_id="test",
            platform_version="1",
            source_spec_sha256=digest("1"),
            world_schema_version="1",
            domain_adapter_version="1",
        ),
        projection_contract_hash=digest("3"),
        official_schema_valid=True,
        effective_projection_valid=True,
    )


def test_registry_requires_matching_source_and_profile():
    """確認 Registry 不接受來源規格或 Profile 不一致的授權。"""
    registry = ProjectionRegistry()
    registry.register(evidence(), registry_revision=1)
    assert registry.authorize(
        projection_contract_hash=digest("3"),
        source_spec_sha256=digest("1"),
        compatibility_profile_sha256=digest("2"),
    ).result is ProjectionAuthorizationResult.AUTHORIZED
    assert registry.authorize(
        projection_contract_hash=digest("3"),
        source_spec_sha256=digest("4"),
        compatibility_profile_sha256=digest("2"),
    ).result is ProjectionAuthorizationResult.SOURCE_MISMATCH


def test_registry_revocation_is_monotonic_and_fail_closed():
    """確認撤銷後契約拒絕授權，且 revision 不可倒退。"""
    registry = ProjectionRegistry()
    registry.register(evidence(), registry_revision=1)
    registry.revoke(digest("3"), registry_revision=2)
    assert registry.authorize(
        projection_contract_hash=digest("3"),
        source_spec_sha256=digest("1"),
        compatibility_profile_sha256=digest("2"),
    ).result is ProjectionAuthorizationResult.REVOKED
    with pytest.raises(ProjectionRegistryError, match="revoked_contract"):
        registry.register(evidence(), registry_revision=3)


def test_postgres_registry_shares_authorization_and_revocation(isolated_test_dsn):
    """確認 PostgreSQL Registry 可跨連線保存授權與撤銷結果。"""
    dsn = isolated_test_dsn
    registry = PostgresProjectionRegistry(dsn)
    contract_hash = uuid.uuid4().hex * 2
    test_evidence = evidence().model_copy(update={"projection_contract_hash": contract_hash})
    registry.register(test_evidence, registry_revision=1)
    assert registry.authorize(
        projection_contract_hash=contract_hash,
        source_spec_sha256=digest("1"),
        compatibility_profile_sha256=digest("2"),
    ).result is ProjectionAuthorizationResult.AUTHORIZED
    registry.revoke(contract_hash, registry_revision=2)
    assert registry.authorize(
        projection_contract_hash=contract_hash,
        source_spec_sha256=digest("1"),
        compatibility_profile_sha256=digest("2"),
    ).result is ProjectionAuthorizationResult.REVOKED


def test_postgres_bootstrap_batch_is_atomic_and_never_revives_revocation(isolated_test_dsn):
    """兩個 instance 並行初始化不重複，撤銷契約使整批新登記回滾且 revision 不變。"""
    from concurrent.futures import ThreadPoolExecutor
    import psycopg

    first = evidence().model_copy(update={"projection_contract_hash": "a" * 64})
    second = evidence().model_copy(update={"projection_contract_hash": "b" * 64})
    extra = evidence().model_copy(update={"projection_contract_hash": "c" * 64})
    registry = PostgresProjectionRegistry(isolated_test_dsn)

    def initialize(_):
        """由獨立連線競爭相同核准集合，使用資料庫交易核對結果。"""
        PostgresProjectionRegistry(isolated_test_dsn).ensure_registered_batch([first, second])

    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(initialize, (1, 2)))
    registry.revoke(first.projection_contract_hash, registry_revision=2)
    with pytest.raises(ProjectionRegistryError, match="not_authorized"):
        registry.ensure_registered_batch([extra, first])
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM projection_registry").fetchone() == (2,)
        assert connection.execute("SELECT registry_revision,revoked FROM projection_registry "
            "WHERE projection_contract_hash=%s", (first.projection_contract_hash,)).fetchone() == (2, True)
