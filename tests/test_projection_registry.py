"""Projection Registry 核准、版本與撤銷行為驗收。"""

import os
import uuid

import pytest

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


def test_postgres_registry_shares_authorization_and_revocation():
    """確認 PostgreSQL Registry 可跨連線保存授權與撤銷結果。"""
    dsn = os.environ.get("MIRAGE_POSTGRES_TEST_DSN") or os.environ.get("MIRAGE_POSTGRES_DSN")
    if not dsn:
        pytest.skip("MIRAGE_POSTGRES_TEST_DSN or MIRAGE_POSTGRES_DSN is not configured")
    registry = PostgresProjectionRegistry(dsn)
    contract_hash = uuid.uuid4().hex * 2
    test_evidence = evidence().model_copy(update={"projection_contract_hash": contract_hash})
    registry.register(test_evidence, registry_revision=1)
    assert registry.authorize(
        projection_contract_hash=contract_hash,
        source_spec_sha256=digest("1"),
        compatibility_profile_sha256=digest("2"),
    ).result is ProjectionAuthorizationResult.AUTHORIZED
    registry.revoke(digest("3"), registry_revision=2)
    assert registry.authorize(
        projection_contract_hash=contract_hash,
        source_spec_sha256=digest("1"),
        compatibility_profile_sha256=digest("2"),
    ).result is ProjectionAuthorizationResult.REVOKED
