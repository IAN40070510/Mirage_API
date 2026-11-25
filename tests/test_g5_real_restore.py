"""G5 標準單機：真 PostgreSQL Schema 備份／跨資料庫還原後先隔離 Sender。"""

import os
import re
import secrets
import subprocess
import json
from uuid import uuid4

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
import pytest

from deception.world import (
    PostgresKnownRestoreRecorder, PostgresProtectedSender,
)
from deception.security.restore_bootstrap import main as restore_bootstrap_main
from test_postgres_conformance import isolated_test_dsn
from test_protected_grant import _login
from test_protected_send import _authorized_pin


def _docker_pg17(args, *, input_bytes=None):
    """只在明確指定的一次性 PostgreSQL 容器執行無互動備份／還原程式。

    不向命令列傳入 DSN 密碼、不允許任意 Docker 容器或 shell 指令，
    將失敗訊息限制為 500 bytes，且超時時禁止宣稱 Restore 已完成。
    """
    container = os.environ["MIRAGE_G5_RESTORE_PG_TOOL_CONTAINER"]
    if container != "mirage-g3b-ci-db":
        pytest.skip("real restore requires the explicitly approved disposable PG17 tool container")
    command = ["docker", "exec", "-i", container, *args]
    result = subprocess.run(
        command, input=input_bytes, capture_output=True, check=False, timeout=90,
    )
    if result.returncode != 0:
        pytest.fail("isolated_pg17_dump_restore_failed: " +
                    result.stderr.decode("utf-8", errors="replace")[:500])
    return result.stdout


def test_real_schema_dump_restore_quarantines_sender_before_any_new_lease(
        isolated_test_dsn, tmp_path, capsys):
    """真 pg_dump -Fc／pg_restore 至新命名 DB，先標記 Restore 再封閉新舊 Sender。

    僅限顯式 opt-in、隔離 CI PostgreSQL 及自動產生的一次性目標 DB；
    只刪除本函式建立的目標資料庫。證明依流程還原後的已知隔離子項，
    不聲稱可偵測未通知的整機磁碟／VM 快照倒退或已起送的網路傳輸。
    """
    if os.environ.get("MIRAGE_G5_REAL_RESTORE_ISOLATED") != "true":
        pytest.skip("requires explicit disposable G5 real backup/restore opt-in")
    source = conninfo_to_dict(isolated_test_dsn)
    schema = source.get("options", "").split("search_path=", 1)[-1]
    source_db, login = source.get("dbname"), source.get("user")
    if (source_db != "mirage_g3b_ci" or login != "mirage_ci_owner"
            or re.fullmatch(r"replay_test_[0-9a-f]{32}", schema) is None):
        pytest.skip("G5 real restore is restricted to the named disposable CI database")
    if os.environ.get("MIRAGE_G5_RESTORE_PG_TOOL_CONTAINER") != "mirage-g3b-ci-db":
        pytest.skip("requires explicit disposable PG17 tool container")

    admission, owner, envelope, seeded = _authorized_pin(isolated_test_dsn)
    with psycopg.connect(isolated_test_dsn) as before:
        assert before.execute(
            "SELECT state FROM response_admissions WHERE admission_id=%s",
            (admission.admission_id,),
        ).fetchone() == ("SEND_AUTHORIZED",)
        assert before.execute("SELECT count(*) FROM protected_send_leases").fetchone() == (0,)
        assert before.execute("SELECT count(*) FROM protected_local_restore_events").fetchone() == (0,)

    backup = _docker_pg17([
        "pg_dump", "-Fc", "--no-owner", "--no-acl", "-U", login,
        "-d", source_db, "-n", schema,
    ])
    assert 0 < len(backup) <= 32 * 1024 * 1024
    # 備份之後才有的事件不會神奇出現在舊備份裡；這正是恢復控制面必須
    # 在 pg_restore 完成後、任何 Sender 啟動前重新寫入 Marker 的原因。
    assert PostgresKnownRestoreRecorder(
        isolated_test_dsn, expected_login=_login(isolated_test_dsn),
    ).mark_known_restore(uuid4())

    restored_name = "mirage_g5_restore_" + uuid4().hex[:14]
    assert re.fullmatch(r"mirage_g5_restore_[0-9a-f]{14}", restored_name)
    restored_dsn = make_conninfo(isolated_test_dsn, dbname=restored_name)
    with psycopg.connect(isolated_test_dsn, autocommit=True) as admin:
        assert admin.execute(
            "SELECT 1 FROM pg_database WHERE datname=%s", (restored_name,),
        ).fetchone() is None
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(restored_name)))
    roles = {
        name: ("mirage_g5_" + name + "_" + uuid4().hex[:10], secrets.token_urlsafe(32))
        for name in ("recorder", "sender")
    }
    try:
        _docker_pg17([
            "pg_restore", "--exit-on-error", "--no-owner", "--no-acl",
            "-U", login, "-d", restored_name,
        ], input_bytes=backup)
        with psycopg.connect(restored_dsn) as restored:
            assert restored.execute(
                "SELECT state FROM response_admissions WHERE admission_id=%s",
                (admission.admission_id,),
            ).fetchone() == ("SEND_AUTHORIZED",)
            assert restored.execute("SELECT count(*) FROM protected_send_leases").fetchone() == (0,)
            assert restored.execute(
                "SELECT count(*) FROM protected_local_restore_events",
            ).fetchone() == (0,)

        # 還原完成後由部署控制面使用兩把不同實體 NOINHERIT SCRAM Login；
        # Recorder 只有 INSERT、獨立 Sender 只有 SELECT，不能共用 Owner。
        with psycopg.connect(isolated_test_dsn, autocommit=True) as admin:
            for role, password in roles.values():
                admin.execute(sql.SQL(
                    "CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB "
                    "NOCREATEROLE NOBYPASSRLS PASSWORD {}"
                ).format(sql.Identifier(role), sql.Literal(password)))
        with psycopg.connect(restored_dsn, autocommit=True) as restored_admin:
            for role, _ in roles.values():
                restored_admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                    sql.Identifier(schema), sql.Identifier(role)))
            restored_admin.execute(sql.SQL(
                "GRANT INSERT ON protected_local_restore_events TO {}"
            ).format(sql.Identifier(roles["recorder"][0])))
            restored_admin.execute(sql.SQL(
                "GRANT SELECT ON protected_local_restore_events TO {}"
            ).format(sql.Identifier(roles["sender"][0])))
        dsn_paths = {}
        for name, (role, password) in roles.items():
            path = tmp_path / (name + ".dsn")
            path.write_text(make_conninfo(restored_dsn, user=role, password=password),
                            encoding="utf-8")
            path.chmod(0o600)
            dsn_paths[name] = path
        restore_event = uuid4()
        args = [
            "--recorder-dsn-file", str(dsn_paths["recorder"]),
            "--recorder-login", roles["recorder"][0],
            "--sender-dsn-file", str(dsn_paths["sender"]),
            "--sender-login", roles["sender"][0],
            "--schema", schema,
            "--restore-event-id", str(restore_event),
        ]
        assert restore_bootstrap_main(args) == 1
        assert json.loads(capsys.readouterr().out)["reason"] == (
            "g5_restore_quiescence_confirmation_required")
        confirmed = [*args, "--ingress-stopped-confirmed", "--restore-complete-confirmed"]
        # 只要 Recorder 取得不該有的 UPDATE，或 Sender 取得可 SET ROLE
        # 的 membership，即使操作員聲明停流也不得寫入 Marker。
        with psycopg.connect(restored_dsn, autocommit=True) as restored_admin:
            restored_admin.execute(sql.SQL(
                "GRANT UPDATE ON protected_local_restore_events TO {}"
            ).format(sql.Identifier(roles["recorder"][0])))
        assert restore_bootstrap_main(confirmed) == 1
        assert json.loads(capsys.readouterr().out)["reason"] == (
            "g5_restore_marker_role_acl_invalid")
        with psycopg.connect(restored_dsn, autocommit=True) as restored_admin:
            restored_admin.execute(sql.SQL(
                "REVOKE UPDATE ON protected_local_restore_events FROM {}"
            ).format(sql.Identifier(roles["recorder"][0])))
            restored_admin.execute(sql.SQL("GRANT {} TO {}").format(
                sql.Identifier(roles["recorder"][0]),
                sql.Identifier(roles["sender"][0]),
            ))
        assert restore_bootstrap_main(confirmed) == 1
        assert json.loads(capsys.readouterr().out)["reason"] == (
            "g5_restore_marker_role_membership_denied")
        with psycopg.connect(restored_dsn, autocommit=True) as restored_admin:
            restored_admin.execute(sql.SQL("REVOKE {} FROM {}").format(
                sql.Identifier(roles["recorder"][0]),
                sql.Identifier(roles["sender"][0]),
            ))
        with psycopg.connect(restored_dsn) as unmarked:
            assert unmarked.execute(
                "SELECT count(*) FROM protected_local_restore_events"
            ).fetchone() == (0,)
        for expected_new in (True, False):
            assert restore_bootstrap_main(confirmed) == 0
            report = json.loads(capsys.readouterr().out)
            assert report == {
                "status": "quarantined", "new_marker": expected_new,
                "restore_event_id": str(restore_event),
                "whole_host_rollback_guarantee": False,
            }
        restored_login = _login(restored_dsn)
        sender = PostgresProtectedSender(restored_dsn, expected_login=restored_login)
        assert sender.start_send(
            admission_id=admission.admission_id, receipt_id=seeded[3], owner=owner,
            request_fingerprint=admission.request_binding_digest,
            expected_envelope=envelope,
        ) is None
        # 就算舊版 Sender 略過 Python 檢查、直接從 SQL 進入 Lease，
        # PostgreSQL 的不可逆 Known Restore Trigger 仍須拒絕。
        with psycopg.connect(restored_dsn) as legacy:
            with pytest.raises(psycopg.errors.InsufficientPrivilege,
                               match="known restore quarantine"):
                legacy.execute(
                    "UPDATE response_admissions SET state='SEND_STARTED' "
                    "WHERE admission_id=%s", (admission.admission_id,),
                )
                legacy.execute(
                    "INSERT INTO protected_send_leases ("
                    "admission_id,lease_id,receipt_id,send_owner,request_fingerprint,"
                    "candidate_hash,transmission_deadline) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    (admission.admission_id, uuid4(), seeded[3], owner,
                     admission.request_binding_digest, admission.candidate_hash,
                     admission.transmission_deadline),
                )
        with psycopg.connect(restored_dsn) as verified:
            assert verified.execute(
                "SELECT restore_event_id FROM protected_local_restore_events",
            ).fetchall() == [(restore_event,)]
            assert verified.execute("SELECT count(*) FROM protected_send_leases").fetchone() == (0,)
            assert verified.execute(
                "SELECT state FROM response_admissions WHERE admission_id=%s",
                (admission.admission_id,),
            ).fetchone() == ("SEND_AUTHORIZED",)
    finally:
        # 只刪除本函式的隨機、名稱前綴嚴格核對的還原副本；
        # 原始 isolated_test_dsn 的 Schema 由原 Fixture 回收。
        with psycopg.connect(isolated_test_dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(
                sql.Identifier(restored_name),
            ))
            for role, _ in roles.values():
                if admin.execute(
                    "SELECT 1 FROM pg_roles WHERE rolname=%s", (role,),
                ).fetchone():
                    admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
