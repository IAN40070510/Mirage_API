"""以隔離 Verifier SCRAM 角色實測 Key Revocation 與 Replay 同交易語意。"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from uuid import uuid4

from psycopg.conninfo import make_conninfo

sys.path.insert(0, "/lab/source/src")

from deception.security.key_revocation import PostgresTrustedKeyRevocations  # noqa: E402
from deception.world.postgres_replay import PostgresReplayStore  # noqa: E402
from deception.world.replay import ReplayConsumeResult  # noqa: E402


class _RollbackProbe(RuntimeError):
    """只在測試中注入的受控 Rollback，不表示未知 COMMIT。"""


def _dsn() -> str:
    """只能讀取本 Verifier 探針的 0600 Secret，不輸出完整連線字串。"""
    secret = Path("/run/secrets/verifier_password")
    if secret.is_symlink() or not secret.is_file():
        raise RuntimeError("verifier_secret_missing")
    return make_conninfo(host="mir-sec-world001-pg", dbname="mir_sec_world_lab",
                         user="mir_sec_verifier", password=secret.read_text(encoding="ascii").strip(),
                         connect_timeout=5)


def main() -> None:
    """驗證成功消費、重放拒絕及明確回滾，保持未實作 Receipt 的 Gate 為 NOT_RUN。"""
    dsn = _dsn()
    guard = PostgresTrustedKeyRevocations(dsn, environment_id="lab", deployment_id="isolated")
    replay = PostgresReplayStore(dsn)
    now = int(time.time())
    first = "lab-accepted-" + uuid4().hex
    issuer, audience, kid = "lab-issuer", "lab-audience", "lab-kid"
    accepted = guard.consume_guarded_replay(replay, issuer=issuer, kid=kid, audience=audience,
                                            jti=first, expires_at=now + 120, now=now)
    if accepted != (None, ReplayConsumeResult.ACCEPTED):
        raise AssertionError("guarded_replay_was_not_accepted")
    repeated = guard.consume_guarded_replay(replay, issuer=issuer, kid=kid, audience=audience,
                                            jti=first, expires_at=now + 120, now=now)
    if repeated != (None, ReplayConsumeResult.REPLAY):
        raise AssertionError("same_jti_replayed")

    rollback_jti = "lab-rollback-" + uuid4().hex
    try:
        with guard._connection() as connection:
            with connection.cursor() as cursor:
                guard._lock(cursor, issuer, kid)
                if guard._select(cursor, issuer, kid) is not None:
                    raise AssertionError("unexpected_test_key_revocation")
                result = replay._consume_on_cursor(cursor, issuer=issuer, audience=audience,
                                                    jti=rollback_jti, expires_at=now + 120, now=now)
                if result != ReplayConsumeResult.ACCEPTED:
                    raise AssertionError("rollback_injection_not_reached")
                raise _RollbackProbe("force_rollback_before_commit")
    except _RollbackProbe:
        pass

    with guard._connection() as connection:
        row = connection.execute(
            "SELECT count(*) FROM replay_entries WHERE issuer=%s AND audience=%s AND jti=%s",
            (issuer, audience, rollback_jti)
        ).fetchone()
        if row != (0,):
            raise AssertionError("replay_tombstone_survived_rollback")
    print("LAB_INGRESS_TX_PROBE_OK guarded_replay=accepted replay=denied explicit_rollback=atomic")


if __name__ == "__main__":
    main()
