"""G5 已知 Restore 操作入口的無資料庫 fail-closed 前置條件驗證。"""

import json
from uuid import UUID, uuid4

import pytest

from deception.security.restore_bootstrap import (
    RestoreBootstrapError, _read_dsn_file, main, quarantine_restored_world,
)


def test_restore_bootstrap_requires_both_confirmations_and_uuid4():
    """不允許缺少停流／已還原確認、空事件或非 UUIDv4 進入真資料庫。"""
    inputs = {
        "restore_event_id": uuid4(), "recorder_dsn": "postgresql://recorder@host/db",
        "recorder_login": "recorder", "sender_dsn": "postgresql://sender@host/db",
        "sender_login": "sender", "schema": "world_data",
        "ingress_stopped": False, "restore_complete": True,
    }
    with pytest.raises(RestoreBootstrapError, match="quiescence_confirmation_required"):
        quarantine_restored_world(**inputs)
    inputs["ingress_stopped"] = True
    inputs["restore_complete"] = False
    with pytest.raises(RestoreBootstrapError, match="quiescence_confirmation_required"):
        quarantine_restored_world(**inputs)
    inputs["restore_complete"] = True
    inputs["restore_event_id"] = UUID(int=0)
    with pytest.raises(RestoreBootstrapError, match="uuid4_required"):
        quarantine_restored_world(**inputs)


def test_restore_bootstrap_denies_rebound_or_reused_logins_before_network():
    """獨立 DSN 只能有帳密差異，跨資料庫／重用實體身分在連線前就拒絕。"""
    inputs = {
        "restore_event_id": uuid4(), "recorder_dsn": "postgresql://recorder@host/db1",
        "recorder_login": "recorder", "sender_dsn": "postgresql://sender@host/db2",
        "sender_login": "sender", "schema": "world_data",
        "ingress_stopped": True, "restore_complete": True,
    }
    with pytest.raises(RestoreBootstrapError, match="database_rebound"):
        quarantine_restored_world(**inputs)
    inputs["sender_login"] = "recorder"
    with pytest.raises(RestoreBootstrapError, match="separate_logins_required"):
        quarantine_restored_world(**inputs)
    inputs["sender_login"] = "sender"
    inputs["schema"] = "public;DROP TABLE x"
    with pytest.raises(RestoreBootstrapError, match="schema_invalid"):
        quarantine_restored_world(**inputs)


def test_restore_bootstrap_secret_mounts_fail_closed(tmp_path):
    """拒絕 symlink、太大／寬鬆的 DSN 檔與相對路徑，限定可信 Linux 掛載。"""
    secret = tmp_path / "restore.dsn"
    secret.write_text("postgresql://recorder:secret@host/db", encoding="utf-8")
    secret.chmod(0o644)
    with pytest.raises(RestoreBootstrapError, match="dsn_file_invalid"):
        _read_dsn_file(str(secret))
    secret.chmod(0o600)
    assert _read_dsn_file(str(secret)) == "postgresql://recorder:secret@host/db"
    link = tmp_path / "redirect.dsn"
    link.symlink_to(secret)
    with pytest.raises(RestoreBootstrapError, match="dsn_file_unavailable"):
        _read_dsn_file(str(link))
    with pytest.raises(RestoreBootstrapError, match="dsn_file_invalid"):
        _read_dsn_file("relative.dsn")
    secret.write_bytes(b"x" * 4097)
    with pytest.raises(RestoreBootstrapError, match="dsn_file_invalid"):
        _read_dsn_file(str(secret))


def test_restore_bootstrap_cli_reports_only_denied_code(tmp_path, capsys):
    """CLI 的錯誤輸出不包含 Secret 檔內密碼，且不可能回報成功。"""
    secret = tmp_path / "restore.dsn"
    secret.write_text("postgresql://recorder:do-not-log-me@host/db", encoding="utf-8")
    secret.chmod(0o600)
    assert main([
        "--recorder-dsn-file", str(secret), "--recorder-login", "recorder",
        "--sender-dsn-file", str(secret), "--sender-login", "sender",
        "--schema", "world_data", "--restore-event-id", str(uuid4()),
    ]) == 1
    result = capsys.readouterr().out
    assert json.loads(result)["status"] == "denied"
    assert "do-not-log-me" not in result
