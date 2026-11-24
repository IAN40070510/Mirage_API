"""用實體 Verifier SCRAM 登入驗證 Receipt 原子寫入及有效權限。"""

from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deception.security import TrustedKeyRegistry, TrustedSessionVerifier
from deception.security.ingress_receipt import PostgresIngressReceiptWriter
from deception.security.key_revocation import PostgresTrustedKeyRevocations
from deception.world import PostgresReplayStore

from receipt_atomic_probe import _token, _verify


def _secret(name: str) -> str:
    """只讀取已掛載的隔離 Lab 角色 Secret，不輸出憑證。"""
    path = Path("/run/secrets") / name
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("missing_isolated_role_secret")
    return path.read_text(encoding="ascii").strip()


def main() -> None:
    """在拋棄式 Schema 施加最小 ACL，分別執行授權與拒絕測試。"""
    if os.environ.get("MIRAGE_LAB_EXPLICIT") != "mir-sec-world001-lab":
        raise RuntimeError("role_probe_requires_isolated_lab")
    if (os.environ.get("PGHOST"), os.environ.get("PGDATABASE")) != (
        "mir-sec-world001-pg", "mir_sec_world_lab"
    ):
        raise RuntimeError("role_probe_wrong_database")
    admin_dsn = make_conninfo(host="mir-sec-world001-pg", dbname="mir_sec_world_lab",
                              user="mir_sec_owner", password=_secret("pg_admin_password"),
                              connect_timeout=5)
    verifier_dsn = make_conninfo(host="mir-sec-world001-pg", dbname="mir_sec_world_lab",
                                 user="mir_sec_verifier", password=_secret("verifier_password"),
                                 connect_timeout=5)
    schema = "mir_receipt_role_" + uuid4().hex
    with psycopg.connect(admin_dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        try:
            scoped_admin = make_conninfo(admin_dsn, options=f"-c search_path={schema}")
            scoped_verifier = make_conninfo(verifier_dsn, options=f"-c search_path={schema}")
            migrations = Path(__file__).parents[2] / "migrations"
            with psycopg.connect(scoped_admin) as connection:
                for migration in sorted(migrations.glob("[0-9]*.sql")):
                    connection.execute(migration.read_text(encoding="utf-8"))
                cursor = connection.cursor()
                cursor.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO mir_sec_verifier")
                               .format(sql.Identifier(schema)))
                cursor.execute("GRANT SELECT ON trusted_key_revocations, replay_entries, "
                               "ingress_receipts TO mir_sec_verifier")
                cursor.execute("GRANT INSERT ON replay_entries, ingress_receipts TO mir_sec_verifier")

            with psycopg.connect(scoped_verifier) as connection:
                identity = connection.execute("SELECT session_user, current_user").fetchone()
                assert identity == ("mir_sec_verifier", "mir_sec_verifier")
                for table, statement in (
                    ("response_admissions", "UPDATE response_admissions SET state='SEND_AUTHORIZED'"),
                    ("ingress_receipts", "DELETE FROM ingress_receipts"),
                    ("generation_controls", "UPDATE generation_controls SET control_revision=0"),
                ):
                    try:
                        connection.execute(statement)
                    except psycopg.errors.InsufficientPrivilege as exc:
                        assert exc.sqlstate == "42501", table
                        connection.rollback()
                    else:
                        raise AssertionError(f"verifier_illicit_dml_allowed:{table}")
                try:
                    connection.execute("SET ROLE mir_sec_authorizer")
                except psycopg.errors.InsufficientPrivilege as exc:
                    assert exc.sqlstate == "42501"
                    connection.rollback()
                else:
                    raise AssertionError("verifier_set_role_authorizer_allowed")

            key = Ed25519PrivateKey.generate()
            checker = TrustedSessionVerifier(
                keys=TrustedKeyRegistry({("probe-gateway", "probe-key"):
                                          key.public_key().public_bytes_raw()}),
                replay_store=PostgresReplayStore(scoped_verifier),
                key_revocations=PostgresTrustedKeyRevocations(
                    scoped_verifier, environment_id="probe-env", deployment_id="probe-deploy"))
            writer = PostgresIngressReceiptWriter(scoped_verifier, environment_id="probe-env",
                                                  deployment_id="probe-deploy")
            jti = uuid4().hex
            claims, receipt_id = _verify(checker, _token(key, jti), writer)
            assert claims.jti == jti
            with psycopg.connect(scoped_verifier) as connection:
                assert connection.execute("SELECT receipt_id FROM ingress_receipts WHERE jti=%s",
                                          (jti,)).fetchone() == (receipt_id,)
                assert connection.execute("SELECT count(*) FROM replay_entries WHERE jti=%s",
                                          (jti,)).fetchone() == (1,)
            print("LAB_VERIFIER_RECEIPT_ROLE_OK scram=verifier receipt=inserted "
                  "replay=inserted protected_dml=42501 set_role=42501")
        finally:
            admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


if __name__ == "__main__":
    main()
