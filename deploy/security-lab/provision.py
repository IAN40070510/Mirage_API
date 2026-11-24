"""僅於全新隔離 PostgreSQL 17 驗收庫建立低權限角色與 World schema。"""

from __future__ import annotations

import os
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo

from deception.world.migrations import apply_migrations


LAB_ROLES = {
    "mir_sec_verifier": "verifier_password",
    "mir_sec_authorizer": "authorizer_password",
    "mir_sec_http_runtime": "runtime_password",
}


def _password(name: str) -> str:
    """從精確掛載的測試 Secret 讀取密碼，拒絕連結及空值且不寫入日誌。"""
    path = Path("/lab/secrets") / name
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("missing_isolated_lab_secret")
    value = path.read_text(encoding="ascii").strip()
    if len(value) < 40:
        raise RuntimeError("weak_isolated_lab_secret")
    return value


def main() -> None:
    """核對專用連線後套用 migration、建立互不繼承的 SCRAM Role 與最小授權。"""
    if os.environ.get("MIRAGE_LAB_EXPLICIT") != "mir-sec-world001-lab":
        raise RuntimeError("isolation_marker_required")
    if (os.environ.get("PGHOST"), os.environ.get("PGDATABASE"), os.environ.get("PGUSER")) != (
        "mir-sec-world001-pg", "mir_sec_world_lab", "mir_sec_owner"
    ):
        raise RuntimeError("wrong_lab_database_target")
    dsn = make_conninfo(host="mir-sec-world001-pg", dbname="mir_sec_world_lab",
                        user="mir_sec_owner", password=_password("pg_admin_password"),
                        connect_timeout=5)
    applied = apply_migrations(dsn, Path("/lab/source/migrations"))
    with psycopg.connect(dsn) as connection:
        with connection.cursor() as cursor:
            if cursor.execute("SELECT count(*) FROM pg_roles WHERE rolname = ANY(%s)",
                              (list(LAB_ROLES),)).fetchone()[0]:
                raise RuntimeError("isolated_lab_roles_already_exist")
            cursor.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
            cursor.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC")
            for role, secret_name in LAB_ROLES.items():
                cursor.execute(sql.SQL(
                    "CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 6 PASSWORD {}"
                ).format(sql.Identifier(role), sql.Literal(_password(secret_name))))
                cursor.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(role)))
            cursor.execute("GRANT SELECT ON trusted_key_revocations, replay_entries "
                           "TO mir_sec_verifier")
            cursor.execute("GRANT INSERT ON replay_entries TO mir_sec_verifier")
            cursor.execute("GRANT SELECT ON trusted_key_revocations, replay_entries, "
                           "response_admissions, generation_controls TO mir_sec_authorizer")
            cursor.execute("SELECT count(*) FROM pg_auth_members WHERE member IN "
                           "(SELECT oid FROM pg_roles WHERE rolname = ANY(%s))",
                           (list(LAB_ROLES),))
            if cursor.fetchone()[0] != 0:
                raise RuntimeError("unexpected_lab_role_membership")
    print(f"LAB_PROVISION_OK migrations={len(applied)} roles={len(LAB_ROLES)} secrets=redacted")


if __name__ == "__main__":
    main()
