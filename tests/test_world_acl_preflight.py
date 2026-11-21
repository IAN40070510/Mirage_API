"""WORLD-ACL-06 子案例：現有共用 DB 身分不得誤開正式 Trusted Send。"""

import os
import secrets

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
    assert "direct_insert:ingress_receipts" in assessment.unsafe_capabilities
    assert "direct_select:ingress_receipts" in assessment.unsafe_capabilities
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


def test_world_acl_real_scram_login_denies_protected_dml(isolated_test_dsn):
    """WORLD-ACL-06 子案例：隔離 PG 17 真實 LOGIN 能 SELECT，但關鍵 DML 與 SET ROLE 必須拒絕。"""
    if os.environ.get("MIRAGE_WORLD_ROLE_TEST_ISOLATED") != "true":
        pytest.skip("global PostgreSQL role test requires disposable CI database")

    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    options = conninfo_to_dict(isolated_test_dsn).get("options", "")
    assert "search_path=" in options
    schema = options.split("search_path=", 1)[1].split(" ", 1)[0]
    password = secrets.token_urlsafe(36)
    runtime_login = make_conninfo(isolated_test_dsn, user="mirage_http_runtime", password=password)
    with psycopg.connect(isolated_test_dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE ROLE mirage_http_runtime LOGIN NOINHERIT PASSWORD {}").format(
            sql.Literal(password)))
        admin.execute("CREATE ROLE mirage_ingress_verifier NOLOGIN NOINHERIT")
        try:
            admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO mirage_http_runtime").format(
                sql.Identifier(schema)))
            for table in ("response_admissions", "generation_controls", "session_heads",
                          "session_world_bindings", "replay_entries", "trusted_key_revocations",
                          "projection_registry", "candidate_records"):
                admin.execute(sql.SQL("GRANT SELECT ON {}.{} TO mirage_http_runtime").format(
                    sql.Identifier(schema), sql.Identifier(table)))
            assessment = inspect_runtime_world_acl(runtime_login, schema=schema)
            assert assessment.login == assessment.effective_role == "mirage_http_runtime"
            assert assessment.restricted, assessment.unsafe_capabilities
            with psycopg.connect(runtime_login) as runtime:
                assert not runtime.execute(
                    "SELECT has_table_privilege(current_user,'ingress_receipts','SELECT')"
                ).fetchone()[0]
            for statement in (
                "UPDATE response_admissions SET state='SEND_AUTHORIZED' WHERE false",
                "UPDATE session_heads SET session_epoch=0 WHERE false",
                "DELETE FROM replay_entries WHERE false",
                "SET ROLE mirage_ingress_verifier",
            ):
                with psycopg.connect(runtime_login) as runtime:
                    with pytest.raises(psycopg.errors.InsufficientPrivilege) as error:
                        runtime.execute(statement)
                    assert error.value.sqlstate == "42501"
        finally:
            # 限定於專用 disposable CI PG，精確移除本案例建立的帳號及授權。
            admin.execute("DROP OWNED BY mirage_http_runtime")
            admin.execute("DROP ROLE mirage_http_runtime")
            admin.execute("DROP ROLE mirage_ingress_verifier")
