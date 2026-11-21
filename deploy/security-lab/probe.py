"""在獨立非特權容器內以真正 SCRAM LOGIN 驗證 World DB 身分邊界。"""

from __future__ import annotations

import sys
from pathlib import Path
from uuid import uuid4

import psycopg


ROLES = {
    "verifier": "mir_sec_verifier",
    "authorizer": "mir_sec_authorizer",
    "runtime": "mir_sec_http_runtime",
}


def _connection(role: str):
    """只讀取本角色專用 Secret 並以 SCRAM 建立新連線，不共用 DSN 或 Pool。"""
    if role not in ROLES:
        raise RuntimeError("unknown_lab_role")
    secret = Path("/run/secrets") / f"{role}_password"
    if secret.is_symlink() or not secret.is_file():
        raise RuntimeError("missing_own_role_secret")
    return psycopg.connect(host="mir-sec-world001-pg", dbname="mir_sec_world_lab",
                           user=ROLES[role], password=secret.read_text(encoding="ascii").strip(),
                           connect_timeout=5)


def _deny(role: str, statement: str) -> None:
    """以新真實連線執行無副作用負面 SQL，嚴格要求 PostgreSQL SQLSTATE 42501。"""
    with _connection(role) as connection:
        try:
            connection.execute(statement)
        except psycopg.errors.InsufficientPrivilege as error:
            if error.sqlstate != "42501":
                raise AssertionError("wrong_denial_sqlstate") from error
            # 42501 會使交易進入 aborted 狀態；明確清除後才歸還連線。
            connection.rollback()
        else:
            raise AssertionError("unauthorized_sql_was_accepted")


def main(role: str) -> None:
    """驗證角色隔離、秘密不可互讀、正向可用交易與受保護 DML 拒絕。"""
    if role not in ROLES:
        raise RuntimeError("invalid_role_argument")
    own_secret = f"{role}_password"
    for other in ROLES:
        if other != role and (Path("/run/secrets") / f"{other}_password").exists():
            raise AssertionError("cross_role_secret_mount_detected")
    if not (Path("/run/secrets") / own_secret).is_file():
        raise AssertionError("own_secret_not_mounted")
    with _connection(role) as connection:
        current, session = connection.execute("SELECT current_user, session_user").fetchone()
        if (current, session) != (ROLES[role], ROLES[role]):
            raise AssertionError("wrong_database_login_identity")
        attributes = connection.execute(
            "SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolinherit "
            "FROM pg_roles WHERE rolname=current_user"
        ).fetchone()
        if attributes != (False, False, False, False, False):
            raise AssertionError("unexpected_role_capability")
        for other in ROLES:
            if other != role and connection.execute(
                "SELECT pg_has_role(current_user,%s,'MEMBER')", (ROLES[other],)
            ).fetchone()[0]:
                raise AssertionError("unexpected_role_membership")
        if role == "verifier":
            if not connection.execute("SELECT has_table_privilege(current_user," 
                                      "'public.replay_entries','INSERT')").fetchone()[0]:
                raise AssertionError("verifier_replay_insert_missing")
            connection.execute(
                "INSERT INTO replay_entries (issuer,audience,jti,expires_at) "
                "VALUES (%s,%s,%s,%s)",
                ("lab", "mirage", "probe-" + uuid4().hex, 2000000000)
            )
            connection.rollback()
        elif role == "authorizer":
            connection.execute("SELECT count(*) FROM response_admissions").fetchone()
            if connection.execute("SELECT has_table_privilege(current_user," 
                                  "'public.response_admissions','UPDATE')").fetchone()[0]:
                raise AssertionError("authorizer_direct_dml_allowed")
        else:
            if connection.execute("SELECT has_table_privilege(current_user," 
                                  "'public.response_admissions','UPDATE')").fetchone()[0]:
                raise AssertionError("runtime_direct_dml_allowed")
    for statement in (
        "UPDATE response_admissions SET state='SEND_AUTHORIZED' WHERE false",
        "UPDATE session_world_bindings SET session_epoch=0 WHERE false",
        "DELETE FROM replay_entries WHERE false",
    ):
        _deny(role, statement)
    for other in ROLES:
        if other != role:
            _deny(role, f"SET ROLE {ROLES[other]}")
    print(f"LAB_ROLE_PROBE_OK role={role} sqlstate=42501 separate_login=true")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python probe.py verifier|authorizer|runtime")
    main(sys.argv[1])
