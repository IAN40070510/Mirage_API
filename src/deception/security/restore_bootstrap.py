"""G5 單機受控還原後的 Marker 落盤與獨立 Sender 唯讀確認入口。"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
from typing import Sequence
from uuid import UUID

import psycopg
from psycopg.conninfo import conninfo_to_dict

from deception.world.protected_send import PostgresKnownRestoreRecorder


class RestoreBootstrapError(ValueError):
    """表示 Restore 入口的安全前提、實體權限或落盤核對失敗。"""


def _checked_login(connection: psycopg.Connection, *, login: str, schema: str,
                   may_insert: bool) -> None:
    """核對實體 SCRAM Login、固定 Schema、NOINHERIT 與 Marker 最小權限。"""
    identity = connection.execute(
        """SELECT session_user,current_user,current_schema(),
                  r.rolinherit,r.rolsuper,r.rolbypassrls,
                  r.rolcreaterole,r.rolcreatedb,r.rolreplication
           FROM pg_roles r WHERE r.rolname=session_user"""
    ).fetchone()
    if identity != (login, login, schema, False, False, False, False, False, False):
        raise RestoreBootstrapError("g5_restore_physical_login_invalid")
    privileges = connection.execute(
        """SELECT has_table_privilege('protected_local_restore_events','INSERT'),
                  has_table_privilege('protected_local_restore_events','SELECT'),
                  has_table_privilege('protected_local_restore_events','UPDATE'),
                  has_table_privilege('protected_local_restore_events','DELETE'),
                  has_schema_privilege(%s,'CREATE')""", (schema,),
    ).fetchone()
    expected = (True, False, False, False, False) if may_insert else (
        False, True, False, False, False)
    if privileges != expected:
        raise RestoreBootstrapError("g5_restore_marker_role_acl_invalid")
    memberships = connection.execute(
        "SELECT count(*) FROM pg_auth_members WHERE member="
        "(SELECT oid FROM pg_roles WHERE rolname=session_user)"
    ).fetchone()
    if memberships != (0,):
        raise RestoreBootstrapError("g5_restore_marker_role_membership_denied")


def _without_identity(conninfo: dict[str, str]) -> dict[str, str]:
    """保留 PG 目標／Schema／安全選項，僅允許兩個實體角色帳密不同。"""
    return {key: value for key, value in conninfo.items()
            if key not in {"user", "password"}}


def quarantine_restored_world(*, restore_event_id: UUID, recorder_dsn: str,
                              recorder_login: str, sender_dsn: str, sender_login: str,
                              schema: str, ingress_stopped: bool,
                              restore_complete: bool) -> bool:
    """在受控 Restore 完成及入口停用後，用獨立角色落盤並讀回不可逆 Marker。

    True 表示本次新寫入，False 表示相同 UUID 已存在；都必須經獨立 Sender
    SELECT 確認才算成功。這是人工控制面的 post-restore 步驟，並不會偵測
    未通報的整機還原，也無法阻止控制面不誠實宣稱 ingress 已停止。
    """
    if not (ingress_stopped is True and restore_complete is True):
        raise RestoreBootstrapError("g5_restore_quiescence_confirmation_required")
    if not isinstance(restore_event_id, UUID) or restore_event_id.version != 4:
        raise RestoreBootstrapError("g5_restore_uuid4_required")
    if (not isinstance(schema, str)
            or re.fullmatch(r"[a-z][a-z0-9_]{0,62}", schema) is None):
        raise RestoreBootstrapError("g5_restore_schema_invalid")
    if (not isinstance(recorder_login, str) or not isinstance(sender_login, str)
            or recorder_login == sender_login
            or any(re.fullmatch(r"[a-z][a-z0-9_]{2,62}", x) is None
                   for x in (recorder_login, sender_login))):
        raise RestoreBootstrapError("g5_restore_separate_logins_required")
    try:
        recorder_info = conninfo_to_dict(recorder_dsn)
        sender_info = conninfo_to_dict(sender_dsn)
        if (_without_identity(recorder_info) != _without_identity(sender_info)
                or recorder_info.get("user") != recorder_login
                or sender_info.get("user") != sender_login):
            raise RestoreBootstrapError("g5_restore_database_rebound")
        with psycopg.connect(recorder_dsn, connect_timeout=5) as recorder_connection:
            _checked_login(recorder_connection, login=recorder_login, schema=schema,
                           may_insert=True)
        with psycopg.connect(sender_dsn, connect_timeout=5) as sender_connection:
            _checked_login(sender_connection, login=sender_login, schema=schema,
                           may_insert=False)
        inserted = PostgresKnownRestoreRecorder(
            recorder_dsn, expected_login=recorder_login,
        ).mark_known_restore(restore_event_id)
        with psycopg.connect(sender_dsn, connect_timeout=5) as sender_connection:
            _checked_login(sender_connection, login=sender_login, schema=schema,
                           may_insert=False)
            count = sender_connection.execute(
                "SELECT count(*) FROM protected_local_restore_events WHERE restore_event_id=%s",
                (restore_event_id,),
            ).fetchone()
        if count != (1,):
            raise RestoreBootstrapError("g5_restore_marker_readback_failed")
        return inserted
    except (psycopg.Error, TypeError, ValueError) as exc:
        if isinstance(exc, RestoreBootstrapError):
            raise
        # psycopg 的底層訊息可能包含伺服器位置／DSN；控制面一律只輸出代碼。
        raise RestoreBootstrapError("g5_restore_storage_or_identity_unavailable") from None


def _read_dsn_file(path: str) -> str:
    """從單一非符號連結的受限掛載檔案讀取 DSN，不在 CLI 或日誌列出密碼。"""
    try:
        if not isinstance(path, str) or not os.path.isabs(path):
            raise RestoreBootstrapError("g5_restore_dsn_file_invalid")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as stream:
            identity = os.fstat(stream.fileno())
            if (not stat.S_ISREG(identity.st_mode) or not 0 < identity.st_size <= 4096
                    or stat.S_IMODE(identity.st_mode) & 0o027):
                raise RestoreBootstrapError("g5_restore_dsn_file_invalid")
            raw = stream.read(4097)
        if len(raw) > 4096:
            raise RestoreBootstrapError("g5_restore_dsn_file_invalid")
        value = raw.decode("utf-8").strip()
        if not value:
            raise RestoreBootstrapError("g5_restore_dsn_file_invalid")
        return value
    except (OSError, UnicodeError):
        raise RestoreBootstrapError("g5_restore_dsn_file_unavailable") from None


def main(argv: Sequence[str] | None = None) -> int:
    """執行明確兩項人工停流確認、受限 SCRAM ACL 預檢、落盤及讀回；失敗封閉。"""
    parser = argparse.ArgumentParser(description="Mirage isolated post-restore quarantine")
    parser.add_argument("--recorder-dsn-file", required=True)
    parser.add_argument("--recorder-login", required=True)
    parser.add_argument("--sender-dsn-file", required=True)
    parser.add_argument("--sender-login", required=True)
    parser.add_argument("--schema", required=True)
    parser.add_argument("--restore-event-id", required=True)
    parser.add_argument("--ingress-stopped-confirmed", action="store_true")
    parser.add_argument("--restore-complete-confirmed", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        inserted = quarantine_restored_world(
            restore_event_id=UUID(arguments.restore_event_id),
            recorder_dsn=_read_dsn_file(arguments.recorder_dsn_file),
            recorder_login=arguments.recorder_login,
            sender_dsn=_read_dsn_file(arguments.sender_dsn_file),
            sender_login=arguments.sender_login, schema=arguments.schema,
            ingress_stopped=arguments.ingress_stopped_confirmed,
            restore_complete=arguments.restore_complete_confirmed,
        )
    except (RestoreBootstrapError, ValueError) as exc:
        # 所有可診斷欄位固定為錯誤代碼；不轉印原始連線錯誤或秘密內容。
        print(json.dumps({"status": "denied", "reason": str(exc)
                          if isinstance(exc, RestoreBootstrapError)
                          else "g5_restore_uuid4_required"}))
        return 1
    print(json.dumps({"status": "quarantined", "new_marker": inserted,
                      "restore_event_id": str(arguments.restore_event_id),
                      "whole_host_rollback_guarantee": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
