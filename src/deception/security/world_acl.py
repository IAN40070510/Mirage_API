"""正式 World Runtime 啟動前的唯讀 PostgreSQL 有效權限檢查。"""

from __future__ import annotations

import re
from dataclasses import dataclass


class WorldAclPreflightError(RuntimeError):
    """表示資料庫連線身分或關鍵表有效權限未達正式發送最低門檻。"""


@dataclass(frozen=True)
class WorldAclAssessment:
    """記錄唯讀 ACL 檢查結果；不把此結果視為容器或 Secret 隔離證明。"""

    login: str
    effective_role: str
    unsafe_capabilities: tuple[str, ...]

    @property
    def restricted(self) -> bool:
        """僅表示本次檢查的有效 SQL 權限沒有發現既知越權能力。"""
        return not self.unsafe_capabilities


def inspect_runtime_world_acl(dsn: str, *, schema: str = "public") -> WorldAclAssessment:
    """以真實 Runtime 登入連線查詢有效 DML、Role membership 及特權屬性。

    此檢查不執行任何修改，不查詢秘密內容。必須由部署控制面另外驗證
    Verifier／Authorizer 的容器 Secret Mount、pg_hba、連線來源與獨立 DSN。
    本函式若無法查全必要證據，必須拒絕而不是放行。
    """
    if not isinstance(dsn, str) or not dsn.strip():
        raise WorldAclPreflightError("world_acl_missing_runtime_dsn")
    if not isinstance(schema, str) or re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", schema) is None:
        raise WorldAclPreflightError("world_acl_invalid_schema")

    try:
        import psycopg

        with psycopg.connect(dsn, connect_timeout=5) as connection:
            with connection.cursor() as cursor:
                cursor.execute("""SELECT session_user, current_user, rolsuper, rolbypassrls,
                                         rolcreaterole, rolcreatedb, rolreplication
                                  FROM pg_catalog.pg_roles WHERE rolname = session_user""")
                row = cursor.fetchone()
                if row is None:
                    raise WorldAclPreflightError("world_acl_unknown_login")
                login, effective_role, superuser, bypass_rls, can_create_role, can_create_db, replication = row
                unsafe = []
                if login != "mirage_http_runtime" or effective_role != login:
                    unsafe.append("unapproved_login_or_role")
                if superuser or bypass_rls or can_create_role or can_create_db or replication:
                    unsafe.append("privileged_role_attribute")
                cursor.execute("""SELECT role.rolname FROM pg_catalog.pg_roles role
                                  WHERE role.rolname = ANY(%s)
                                    AND pg_catalog.pg_has_role(session_user, role.oid, 'MEMBER')""",
                               (["mirage_ingress_verifier", "mirage_authorizer", "mirage_replay_gc",
                                 "mirage_schema_owner"],))
                if cursor.fetchall():
                    unsafe.append("privileged_role_membership")
                # 以明確 schema-qualified relation 名稱，避免 search_path 影子表偽造 PASS。
                for table, operations in (
                    ("response_admissions", ("INSERT", "UPDATE", "DELETE", "TRUNCATE")),
                    ("generation_controls", ("INSERT", "UPDATE", "DELETE", "TRUNCATE")),
                    ("session_heads", ("INSERT", "UPDATE", "DELETE", "TRUNCATE")),
                    ("session_world_bindings", ("INSERT", "UPDATE", "DELETE", "TRUNCATE")),
                    ("replay_entries", ("INSERT", "UPDATE", "DELETE", "TRUNCATE")),
                    ("trusted_key_revocations", ("INSERT", "UPDATE", "DELETE", "TRUNCATE")),
                    ("projection_registry", ("INSERT", "UPDATE", "DELETE", "TRUNCATE")),
                    ("candidate_records", ("UPDATE", "DELETE", "TRUNCATE")),
                    ("ingress_receipts", ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")),
                ):
                    qualified = f"{schema}.{table}"
                    cursor.execute("SELECT pg_catalog.to_regclass(%s)", (qualified,))
                    if cursor.fetchone()[0] is None:
                        unsafe.append(f"missing_protected_table:{table}")
                        continue
                    for operation in operations:
                        cursor.execute("SELECT pg_catalog.has_table_privilege(session_user, %s, %s)",
                                       (qualified, operation))
                        if cursor.fetchone()[0] is not False:
                            unsafe.append(f"direct_{operation.lower()}:{table}")
                return WorldAclAssessment(login=login, effective_role=effective_role,
                                          unsafe_capabilities=tuple(unsafe))
    except WorldAclPreflightError:
        raise
    except Exception:
        # 不向日誌或 HTTP 暴露可能含 DSN／憑證的底層例外內容。
        raise WorldAclPreflightError("world_acl_unverifiable") from None


def require_restricted_world_runtime(dsn: str, *, schema: str = "public") -> None:
    """正式入口 Fail-Closed：未證明 Runtime 低權限便不得啟用 Trusted HTTP 發送。"""
    if not inspect_runtime_world_acl(dsn, schema=schema).restricted:
        raise WorldAclPreflightError("world_acl_runtime_not_restricted")
