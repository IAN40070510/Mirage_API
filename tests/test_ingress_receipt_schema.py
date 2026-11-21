"""MIR-SEC-WORLD-001：隔離 PostgreSQL 的 Receipt 與 Replay 原子約束測試。"""

from __future__ import annotations

import os
import secrets
from uuid import uuid4

import pytest

from test_postgres_conformance import isolated_test_dsn


def _record(jti: str) -> tuple[object, ...]:
    """建立可供 DB 約束檢查的固定格式 Receipt 測資；不聲稱已完成 JWS 驗證。"""
    return ("test-issuer", "test-audience", jti, "kid-1", "test-env", "test-deploy",
            "test-session", 2, "a" * 64, "b" * 64, "c" * 64,
            "v1-test", 1_700_000_000, 1_700_000_000, 2_000_000_000)


def _insert_receipt(connection, jti: str) -> str:
    """在既有交易中寫入 Receipt，不自行開新連線或提交。"""
    row = connection.execute(
        """INSERT INTO ingress_receipts (
               issuer,audience,jti,key_id,environment_id,deployment_id,session_id,session_epoch,
               request_fingerprint,assessment_digest,claims_digest,verification_policy_version,
               token_issued_at,token_not_before,token_expires_at
           ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           RETURNING receipt_id""",
        _record(jti),
    ).fetchone()
    assert row is not None
    return str(row[0])


def test_receipt_and_replay_must_commit_or_rollback_together(isolated_test_dsn):
    """驗證同交易成功與失敗原子性；單獨 Receipt 不可越過 Replay FK。"""
    import psycopg

    accepted = "receipt-committed-" + uuid4().hex
    aborted = "receipt-aborted-" + uuid4().hex
    missing = "receipt-missing-" + uuid4().hex
    with psycopg.connect(isolated_test_dsn) as connection:
        with pytest.raises(psycopg.errors.ForeignKeyViolation) as error:
            _insert_receipt(connection, missing)
        assert error.value.sqlstate == "23503"
        connection.rollback()
        connection.execute("INSERT INTO replay_entries VALUES (%s,%s,%s,%s)",
                           ("test-issuer", "test-audience", accepted, 2_000_000_030))
        receipt_id = _insert_receipt(connection, accepted)
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT receipt_id::text FROM ingress_receipts WHERE jti=%s",
                                  (accepted,)).fetchone() == (receipt_id,)
        connection.execute("INSERT INTO replay_entries VALUES (%s,%s,%s,%s)",
                           ("test-issuer", "test-audience", aborted, 2_000_000_030))
        _insert_receipt(connection, aborted)
        connection.rollback()
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM ingress_receipts WHERE jti=%s",
                                  (aborted,)).fetchone() == (0,)
        assert connection.execute("SELECT count(*) FROM replay_entries WHERE jti=%s",
                                  (aborted,)).fetchone() == (0,)


def test_receipt_is_one_per_jti_and_preserves_replay_tombstone(isolated_test_dsn):
    """同一 JTI 不得建立第二個 Receipt，仍被 Receipt 引用時 Replay GC 必須拒絕。"""
    import psycopg

    jti = "receipt-unique-" + uuid4().hex
    with psycopg.connect(isolated_test_dsn) as connection:
        connection.execute("INSERT INTO replay_entries VALUES (%s,%s,%s,%s)",
                           ("test-issuer", "test-audience", jti, 2_000_000_030))
        _insert_receipt(connection, jti)
    with psycopg.connect(isolated_test_dsn) as connection:
        with pytest.raises(psycopg.errors.UniqueViolation) as error:
            _insert_receipt(connection, jti)
        assert error.value.sqlstate == "23505"
        connection.rollback()
    with psycopg.connect(isolated_test_dsn) as connection:
        with pytest.raises(psycopg.errors.ForeignKeyViolation) as error:
            connection.execute("DELETE FROM replay_entries WHERE issuer=%s AND audience=%s AND jti=%s",
                               ("test-issuer", "test-audience", jti))
        assert error.value.sqlstate == "23503"


def test_receipt_runtime_sql_is_denied_by_real_scram_role(isolated_test_dsn):
    """只在拋棄式 CI 資料庫建立真正的低權限 LOGIN，確認無 Receipt INSERT/UPDATE/DELETE。"""
    if os.environ.get("MIRAGE_WORLD_ROLE_TEST_ISOLATED") != "true":
        pytest.skip("global PostgreSQL role test requires disposable CI database")
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    schema = conninfo_to_dict(isolated_test_dsn)["options"].split("search_path=", 1)[1].split(" ", 1)[0]
    role = "receipt_runtime_" + uuid4().hex[:12]
    password = secrets.token_urlsafe(36)
    dsn = make_conninfo(isolated_test_dsn, user=role, password=password)
    with psycopg.connect(isolated_test_dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS PASSWORD {}").format(
            sql.Identifier(role), sql.Literal(password)))
        try:
            admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                sql.Identifier(schema), sql.Identifier(role)))
            with psycopg.connect(dsn) as runtime:
                assert runtime.execute("SELECT current_user,session_user").fetchone() == (role, role)
                for statement in (
                    "INSERT INTO ingress_receipts (issuer) VALUES ('forged')",
                    "UPDATE ingress_receipts SET key_id='new-key' WHERE false",
                    "DELETE FROM ingress_receipts WHERE false",
                ):
                    with pytest.raises(psycopg.errors.InsufficientPrivilege) as error:
                        runtime.execute(statement)
                    assert error.value.sqlstate == "42501"
                    runtime.rollback()
        finally:
            admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


def test_receipt_verifier_role_can_insert_but_cannot_rewrite(isolated_test_dsn):
    """測試獨立 Verifier 真 LOGIN：受限 INSERT 正常，不能自填 DB 時間或改寫 Receipt。"""
    if os.environ.get("MIRAGE_WORLD_ROLE_TEST_ISOLATED") != "true":
        pytest.skip("global PostgreSQL role test requires disposable CI database")
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    schema = conninfo_to_dict(isolated_test_dsn)["options"].split("search_path=", 1)[1].split(" ", 1)[0]
    role = "receipt_verifier_" + uuid4().hex[:12]
    password = secrets.token_urlsafe(36)
    dsn = make_conninfo(isolated_test_dsn, user=role, password=password)
    columns = ("issuer,audience,jti,key_id,environment_id,deployment_id,session_id,session_epoch,"
               "request_fingerprint,assessment_digest,claims_digest,verification_policy_version,"
               "token_issued_at,token_not_before,token_expires_at")
    with psycopg.connect(isolated_test_dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS PASSWORD {}").format(
            sql.Identifier(role), sql.Literal(password)))
        try:
            admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                sql.Identifier(schema), sql.Identifier(role)))
            admin.execute(sql.SQL("GRANT INSERT ON {}.replay_entries TO {}").format(
                sql.Identifier(schema), sql.Identifier(role)))
            admin.execute(sql.SQL("GRANT INSERT ({}) ON {}.ingress_receipts TO {}").format(
                sql.SQL(columns), sql.Identifier(schema), sql.Identifier(role)))
            admin.execute(sql.SQL("GRANT SELECT (receipt_id) ON {}.ingress_receipts TO {}").format(
                sql.Identifier(schema), sql.Identifier(role)))
            jti = "verifier-fixture-" + uuid4().hex
            with psycopg.connect(dsn) as verifier:
                verifier.execute("INSERT INTO replay_entries VALUES (%s,%s,%s,%s)",
                                 ("test-issuer", "test-audience", jti, 2_000_000_030))
                receipt_id = _insert_receipt(verifier, jti)
            with psycopg.connect(dsn) as verifier:
                for statement in (
                    "UPDATE ingress_receipts SET key_id='forged' WHERE false",
                    "DELETE FROM ingress_receipts WHERE false",
                    "INSERT INTO ingress_receipts (issuer,verified_at) VALUES ('forged',clock_timestamp())",
                ):
                    with pytest.raises(psycopg.errors.InsufficientPrivilege) as error:
                        verifier.execute(statement)
                    assert error.value.sqlstate == "42501"
                    verifier.rollback()
            with psycopg.connect(isolated_test_dsn) as admin_check:
                assert admin_check.execute("SELECT receipt_id::text FROM ingress_receipts WHERE jti=%s",
                                           (jti,)).fetchone() == (receipt_id,)
        finally:
            admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
