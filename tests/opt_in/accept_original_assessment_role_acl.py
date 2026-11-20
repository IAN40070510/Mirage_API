"""P2 disposable PostgreSQL: distinct SCRAM-authenticated EXECUTE-only service roles.

Explicit opt-in only. Never run these SQL probes against staging or a shared DB.
"""

# ruff: noqa: S101, ANN

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import psycopg
import pytest
from deception.scenarios.models import AttackAssessment
from deception.security.original_assessment_store import (
    OriginalAssessmentStoreError,
    PostgresOriginalAssessmentStore,
)
from psycopg.conninfo import conninfo_to_dict, make_conninfo

SCOPE = dict(
    environment_id="isolated-demo",
    deployment_id="isolated-demo",
    source_id="local-demo-detector",
    service_id="synthetic-store",
    site_id="demo-store",
)

PUBLISH_FUNCTION = (
    "public.msdss_publish_original_assessment("
    "text,text,text,text,text,text,timestamp with time zone,timestamp with time zone)"
)
TAKE_FUNCTION = "public.msdss_take_original_assessment(text,text,text)"


@pytest.fixture(scope="module")
def accounts() -> dict[str, str]:
    """Require exact disposable namespace and distinct authenticated DB identities."""
    if os.environ.get("P2_ISOLATED_ORIGINAL_ASSESSMENT_TEST") != "true":
        pytest.skip("requires isolated disposable PostgreSQL")
    expected = {
        "writer": ("P2_ORIGINAL_TEST_PUBLISHER_DSN", "p2_acl_writer"),
        "reader": ("P2_ORIGINAL_TEST_CONSUMER_DSN", "p2_acl_reader"),
        "observer": ("P2_ORIGINAL_TEST_OBSERVER_DSN", "p2_acl_observer"),
    }
    result = {}
    for key, (env, user) in expected.items():
        dsn = os.environ.get(env, "")
        details = conninfo_to_dict(dsn)
        if (
            details.get("dbname") != "p2_acceptance_acl"
            or details.get("user") != user
            or details.get("host") != "127.0.0.1"
            or not details.get("password")
        ):
            pytest.fail(f"invalid disposable test identity: {key}")
        result[key] = dsn
    with psycopg.connect(result["writer"]) as conn:
        assert conn.execute("SELECT current_user").fetchone() == ("p2_acl_writer",)
    with psycopg.connect(result["reader"]) as conn:
        assert conn.execute("SELECT current_user").fetchone() == ("p2_acl_reader",)
    with psycopg.connect(result["observer"]) as conn:
        assert conn.execute("SELECT current_user").fetchone() == ("p2_acl_observer",)
    return result


def synthetic_assessment() -> AttackAssessment:
    """Create synthetic, noncustomer original assessment data."""
    now = datetime.now(UTC)
    return AttackAssessment(
        assessment_id=str(uuid4()),
        request_id=f"synthetic-{uuid4()}",
        request_fingerprint="b" * 64,
        verdict="malicious",
        attack_types=["sql-injection"],
        observed_at=now,
        expires_at=now + timedelta(seconds=25),
        **SCOPE,
    )


def test_ledger_migration_is_dedicated_not_auto_discovered() -> None:
    """Original assessment DDL must never auto-run in a Mirage World schema."""
    from pathlib import Path

    mirage_root = Path(__file__).resolve().parents[2]
    dedicated = (
        mirage_root / "migrations" / "original_assessment" / "017_original_assessment_ledger.sql"
    )
    assert dedicated.is_file()
    assert not (mirage_root / "migrations" / "017_original_assessment_ledger.sql").exists()
    assert dedicated not in tuple((mirage_root / "migrations").glob("*.sql"))


def test_security_definer_owner_is_nologin_non_superuser(accounts: dict[str, str]) -> None:
    """Neither function may silently become owned by postgres or an HTTP LOGIN role."""
    with psycopg.connect(accounts["observer"]) as conn:
        table_owner, publisher_owner, consumer_owner = conn.execute(
            """SELECT
                   (SELECT pg_get_userbyid(relowner) FROM pg_class
                    WHERE oid='public.msdss_original_assessments'::regclass),
                   (SELECT pg_get_userbyid(proowner) FROM pg_proc
                    WHERE oid=%s::regprocedure),
                   (SELECT pg_get_userbyid(proowner) FROM pg_proc
                    WHERE oid=%s::regprocedure)""",
            (PUBLISH_FUNCTION, TAKE_FUNCTION),
        ).fetchone()
        assert (table_owner, publisher_owner, consumer_owner) == (
            "p2_acl_owner",
            "p2_acl_owner",
            "p2_acl_owner",
        )
        props = conn.execute(
            """SELECT rolcanlogin,rolsuper,rolcreaterole,rolcreatedb
               FROM pg_roles WHERE rolname='p2_acl_owner'"""
        ).fetchone()
        assert props == (False, False, False, False)
        for signature in (PUBLISH_FUNCTION, TAKE_FUNCTION):
            assert conn.execute(
                "SELECT prosecdef FROM pg_proc WHERE oid=%s::regprocedure",
                (signature,),
            ).fetchone() == (True,)


@pytest.mark.parametrize("role", ["writer", "reader", "observer"])
def test_roles_are_distinct_nonprivileged_logins(accounts: dict[str, str], role: str) -> None:
    """Neither service nor bystander may inherit DDL/superuser/owner permissions."""
    with psycopg.connect(accounts[role]) as conn:
        current, superuser, create_role, create_db, bypass_rls = conn.execute(
            """SELECT current_user, rolsuper, rolcreaterole, rolcreatedb, rolbypassrls
               FROM pg_roles WHERE rolname=current_user"""
        ).fetchone()
        assert current == f"p2_acl_{role}"
        assert not (superuser or create_role or create_db or bypass_rls)
        assert conn.execute(
            "SELECT pg_has_role(current_user,'p2_acl_owner','MEMBER')"
        ).fetchone() == (False,)
        assert conn.execute(
            "SELECT has_schema_privilege(current_user,'public','CREATE')"
        ).fetchone() == (False,)


@pytest.mark.parametrize(
    ("role", "can_publish", "can_take"),
    [("writer", True, False), ("reader", False, True), ("observer", False, False)],
)
def test_only_expected_function_is_executable(
    accounts: dict[str, str], role: str, can_publish: bool, can_take: bool
) -> None:
    """Check PostgreSQL ACL, not just Python's mode flag."""
    with psycopg.connect(accounts[role]) as conn:
        grants = conn.execute(
            """SELECT has_function_privilege(current_user,%s,'EXECUTE'),
                      has_function_privilege(current_user,%s,'EXECUTE')""",
            (PUBLISH_FUNCTION, TAKE_FUNCTION),
        ).fetchone()
        assert grants == (can_publish, can_take)
        for privilege in (
            "SELECT",
            "INSERT",
            "UPDATE",
            "DELETE",
            "TRUNCATE",
            "REFERENCES",
            "TRIGGER",
        ):
            (granted,) = conn.execute(
                "SELECT has_table_privilege(current_user,'public.msdss_original_assessments',%s)",
                (privilege,),
            ).fetchone()
            assert granted is False, (role, privilege)


@pytest.mark.parametrize("role", ["writer", "reader", "observer"])
@pytest.mark.parametrize(
    "forbidden_sql",
    [
        "SELECT consumed_at FROM public.msdss_original_assessments",
        "UPDATE public.msdss_original_assessments SET consumed_at=NULL",
        "DELETE FROM public.msdss_original_assessments",
        "INSERT INTO public.msdss_original_assessments DEFAULT VALUES",
        "TRUNCATE public.msdss_original_assessments",
    ],
)
def test_direct_ledger_dml_denied(accounts: dict[str, str], role: str, forbidden_sql: str) -> None:
    """Consumer must not reset replay tombstones, even through raw SQL."""
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with psycopg.connect(accounts[role]) as conn:
            conn.execute(forbidden_sql)


@pytest.mark.parametrize(
    ("role", "sql"),
    [
        (
            "writer",
            "SELECT public.msdss_take_original_assessment(NULL::text,NULL::text,NULL::text)",
        ),
        (
            "reader",
            "SELECT public.msdss_publish_original_assessment("
            "NULL::text,NULL::text,NULL::text,NULL::text,NULL::text,NULL::text,"
            "NULL::timestamptz,NULL::timestamptz)",
        ),
        (
            "observer",
            "SELECT public.msdss_take_original_assessment(NULL::text,NULL::text,NULL::text)",
        ),
        (
            "observer",
            "SELECT public.msdss_publish_original_assessment("
            "NULL::text,NULL::text,NULL::text,NULL::text,NULL::text,NULL::text,"
            "NULL::timestamptz,NULL::timestamptz)",
        ),
    ],
)
def test_wrong_role_cannot_execute_other_function(
    accounts: dict[str, str], role: str, sql: str
) -> None:
    """The forbidden path must fail inside PostgreSQL, not just Python."""
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with psycopg.connect(accounts[role]) as conn:
            conn.execute(sql)


@pytest.mark.parametrize("role", ["writer", "reader", "observer"])
def test_service_roles_cannot_become_schema_owner(accounts: dict[str, str], role: str) -> None:
    """No SET ROLE privilege escalation to SECURITY DEFINER function owner."""
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with psycopg.connect(accounts[role]) as conn:
            conn.execute("SET ROLE p2_acl_owner")


def test_password_authentication_is_enforced(accounts: dict[str, str]) -> None:
    """Independent credentials genuinely authenticate, not PostgreSQL trust mode."""
    for role in ("writer", "reader", "observer"):
        invalid = make_conninfo(accounts[role], password=uuid4().hex)
        with pytest.raises(psycopg.OperationalError):
            psycopg.connect(invalid, connect_timeout=2)


def test_writer_publishes_reader_consumes_once(accounts: dict[str, str]) -> None:
    """Actual app paths use independently authenticated nonprivileged roles."""
    original = synthetic_assessment()
    writer = PostgresOriginalAssessmentStore(accounts["writer"], mode="publisher", **SCOPE)
    reader = PostgresOriginalAssessmentStore(accounts["reader"], mode="consumer", **SCOPE)
    digest = writer.publish(original)
    assert len(digest) == 64
    assert reader(original.assessment_id) == original
    assert reader(original.assessment_id) is None
    with pytest.raises(OriginalAssessmentStoreError, match="duplicate"):
        writer.publish(original)


def test_eight_consumer_connections_only_one_can_take(accounts: dict[str, str]) -> None:
    """Row update remains atomic even with different DB principals across services."""
    original = synthetic_assessment()
    writer = PostgresOriginalAssessmentStore(accounts["writer"], mode="publisher", **SCOPE)
    reader = PostgresOriginalAssessmentStore(accounts["reader"], mode="consumer", **SCOPE)
    writer.publish(original)
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(reader, [original.assessment_id] * 8))
    assert sum(result == original for result in results) == 1
    assert sum(result is None for result in results) == 7


def test_role_separation_rejects_cross_scope_consumption(accounts: dict[str, str]) -> None:
    """Wrong environment cannot consume or mutate the legitimate record."""
    original = synthetic_assessment()
    writer = PostgresOriginalAssessmentStore(accounts["writer"], mode="publisher", **SCOPE)
    reader = PostgresOriginalAssessmentStore(accounts["reader"], mode="consumer", **SCOPE)
    wrong = PostgresOriginalAssessmentStore(
        accounts["reader"], mode="consumer", **{**SCOPE, "environment_id": "other"}
    )
    writer.publish(original)
    assert wrong(original.assessment_id) is None
    assert reader(original.assessment_id) == original
