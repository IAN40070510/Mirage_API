"""僅在已核准隔離 Lab 的既有資料庫追加 Receipt Migration／白名單 Role ACL。"""

from __future__ import annotations

import os
from pathlib import Path

import psycopg
from psycopg.conninfo import make_conninfo

from deception.world.migrations import apply_migrations
from provision import _password


def main() -> None:
    """嚴格核對 Lab 身分，前向套用 Migration，保留原有 Role 與秘密不變。"""
    if os.environ.get("MIRAGE_LAB_EXPLICIT") != "mir-sec-world001-lab":
        raise RuntimeError("lab_marker_required")
    if (os.environ.get("PGHOST"), os.environ.get("PGDATABASE"), os.environ.get("PGUSER")) != (
        "mir-sec-world001-pg", "mir_sec_world_lab", "mir_sec_owner"
    ):
        raise RuntimeError("lab_database_identity_mismatch")
    dsn = make_conninfo(host="mir-sec-world001-pg", dbname="mir_sec_world_lab",
                        user="mir_sec_owner", password=_password("pg_admin_password"), connect_timeout=5)
    applied = apply_migrations(dsn, Path("/lab/source/migrations"))
    with psycopg.connect(dsn) as connection:
        with connection.cursor() as cursor:
            names = ["mir_sec_verifier", "mir_sec_authorizer", "mir_sec_http_runtime"]
            cursor.execute("SELECT count(*) FROM pg_roles WHERE rolname = ANY(%s)", (names,))
            if cursor.fetchone()[0] != len(names):
                raise RuntimeError("lab_roles_missing")
            cursor.execute("SELECT to_regclass('public.ingress_receipts')")
            if cursor.fetchone()[0] is None:
                raise RuntimeError("receipt_migration_not_applied")
            cursor.execute("REVOKE ALL ON TABLE public.ingress_receipts FROM PUBLIC, mir_sec_http_runtime")
            cursor.execute("GRANT INSERT (issuer,audience,jti,key_id,environment_id,deployment_id,"
                           "session_id,session_epoch,request_fingerprint,assessment_digest,"
                           "claims_digest,verification_policy_version,token_issued_at,"
                           "token_not_before,token_expires_at) ON public.ingress_receipts TO mir_sec_verifier")
            cursor.execute("GRANT SELECT ON public.ingress_receipts TO mir_sec_verifier, mir_sec_authorizer")
    print(f"LAB_RECEIPT_MIGRATION_OK new_migrations={len(applied)} roles=3 secrets=redacted")


if __name__ == "__main__":
    main()
