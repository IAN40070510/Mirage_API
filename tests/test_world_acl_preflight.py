"""WORLD-ACL-PREFLIGHT-01：現有共用 DB 身分不得誤開正式 Trusted Send。"""

import pytest

from deception.security.world_acl import (WorldAclAssessment, WorldAclPreflightError,
                                          inspect_runtime_world_acl, require_restricted_world_runtime)
from test_postgres_conformance import isolated_test_dsn


def test_world_acl_preflight_rejects_unverifiable_configuration():
    """無 DSN、無效 schema 或無法查證權限時一律 Fail-Closed。"""
    for dsn, schema in (("", "public"), ("postgresql://unused.invalid/db", "wrong;drop")):
        with pytest.raises(WorldAclPreflightError):
            inspect_runtime_world_acl(dsn, schema=schema)


def test_world_acl_preflight_detects_existing_privileged_connection(isolated_test_dsn):
    """真 PostgreSQL 的既有 Migration/Admin DSN 不可被誤當低權限 Runtime。"""
    from psycopg.conninfo import conninfo_to_dict

    # Fixture 把每個案例放進獨立 schema，不能因 search_path 改變而使用影子表檢查。
    options = conninfo_to_dict(isolated_test_dsn).get("options", "")
    assert "search_path=" in options
    schema = options.split("search_path=", 1)[1].split(" ", 1)[0]
    assessment = inspect_runtime_world_acl(isolated_test_dsn, schema=schema)
    assert not assessment.restricted
    assert "unapproved_login_or_role" in assessment.unsafe_capabilities
    assert "direct_update:response_admissions" in assessment.unsafe_capabilities
    assert "direct_update:session_heads" in assessment.unsafe_capabilities
    assert "direct_delete:replay_entries" in assessment.unsafe_capabilities
    with pytest.raises(WorldAclPreflightError, match="world_acl_runtime_not_restricted"):
        require_restricted_world_runtime(isolated_test_dsn, schema=schema)


def test_world_acl_formal_entrypoint_cannot_bypass_missing_services(monkeypatch):
    """即使 Runtime ACL 通過，Verifier／Authorizer 尚未隔離前部署工廠必拒絕。"""
    from deception.domains.ecommerce import trusted_http

    monkeypatch.setenv("MIRAGE_TRUSTED_SETTINGS_FILE", "/unused/not_read.json")
    monkeypatch.setenv("MIRAGE_POSTGRES_DSN", "postgresql://unused.invalid/db")
    monkeypatch.setenv("MIRAGE_DEMO_ORIGIN", "https://invalid.example")
    # 模擬 ACL 檢查已回傳 OK，保護服務尚未接入的 Release Fuse 仍須獨立存在。
    monkeypatch.setattr("deception.security.world_acl.require_restricted_world_runtime",
                        lambda *_args, **_kwargs: None)
    with pytest.raises(WorldAclPreflightError, match="protected_world_services_not_wired"):
        trusted_http.from_environment()


def test_world_acl_assessment_only_claims_checked_capabilities():
    """ACL 結果不冒充 Secret Mount、pg_hba 或完整 R1/R4 安全驗收。"""
    safe = WorldAclAssessment(login="mirage_http_runtime", effective_role="mirage_http_runtime",
                              unsafe_capabilities=())
    exposed = WorldAclAssessment(login="mirage_http_runtime", effective_role="mirage_http_runtime",
                                 unsafe_capabilities=("direct_update:response_admissions",))
    assert safe.restricted and not exposed.restricted
