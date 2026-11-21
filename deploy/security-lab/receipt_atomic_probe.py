"""在完全隔離的 PostgreSQL Schema 驗證 JWS／Replay／Receipt 交易原子性。"""

from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from uuid import uuid4

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deception.security import TrustedKeyRegistry, TrustedSessionError, TrustedSessionVerifier
from deception.security.ingress_receipt import IngressReceiptError, PostgresIngressReceiptWriter
from deception.security.key_revocation import PostgresTrustedKeyRevocations
from deception.world import PostgresReplayStore
from deception.world.replay import ReplayConsumeResult


def _token(key: Ed25519PrivateKey, jti: str, *, reference_time: int | None = None) -> str:
    """以隔離測試私鑰產生短效、可驗證 Fingerprint 的一次性 JWS。"""
    now = int(time.time()) if reference_time is None else reference_time
    header = {"alg": "Ed25519", "typ": "mirage-trusted-session+jwt", "kid": "probe-key",
              "protocol_version": "1.1"}
    claims = {"iss": "probe-gateway", "aud": "probe-mirage", "iat": now - 5, "nbf": now - 5,
              "exp": now + 45, "jti": jti, "environment_id": "probe-env", "deployment_id": "probe-deploy",
              "session_id": "probe-session", "session_epoch": 1, "request_fingerprint": "a" * 64,
              "assessment_id": "probe-assessment", "assessment_digest": "b" * 64}

    def encode(value: dict) -> str:
        """將固定 JSON 欄位編成 Canonical Compact JWS Base64URL 區段。"""
        return base64.urlsafe_b64encode(json.dumps(value, sort_keys=True,
            separators=(",", ":")).encode("utf-8")).decode("ascii").rstrip("=")

    prefix = encode(header) + "." + encode(claims)
    signature = base64.urlsafe_b64encode(key.sign(prefix.encode("ascii"))).decode("ascii").rstrip("=")
    return prefix + "." + signature


def _verify(checker, token: str, writer: PostgresIngressReceiptWriter, *, now: int | None = None):
    """以現在時間驗證 JWS；容許注入舊時鐘以測試資料庫獨立拒絕。"""
    return checker.verify_with_receipt(token, expected_issuer="probe-gateway",
        expected_audience="probe-mirage", request_fingerprint="a" * 64,
        environment_id="probe-env", deployment_id="probe-deploy",
        now=int(time.time()) if now is None else now,
        receipt_writer=writer)


def run() -> None:
    """一次性建立/清理測試 Schema；正常、重放、回滾與跨登入域皆須符合預期。"""
    if os.environ.get("MIRAGE_LAB_EXPLICIT") != "mir-sec-world001-lab":
        raise RuntimeError("receipt_probe_requires_isolated_lab")
    password_file = os.environ.get("PGPASSWORD_FILE")
    if not password_file or not Path(password_file).is_file():
        raise RuntimeError("receipt_probe_requires_password_file")
    password = Path(password_file).read_text(encoding="utf-8").strip()
    dsn = make_conninfo("", host=os.environ["PGHOST"], port=os.environ.get("PGPORT", "5432"),
                        dbname=os.environ["PGDATABASE"], user=os.environ["PGUSER"], password=password)
    schema = "mir_receipt_probe_" + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        try:
            scoped = make_conninfo(dsn, options=f"-c search_path={schema}")
            migrations = Path(__file__).parents[2] / "migrations"
            with psycopg.connect(scoped) as connection:
                for path in sorted(migrations.glob("[0-9]*.sql")):
                    connection.execute(path.read_text(encoding="utf-8"))
            key = Ed25519PrivateKey.generate()
            checker = TrustedSessionVerifier(
                keys=TrustedKeyRegistry({("probe-gateway", "probe-key"): key.public_key().public_bytes_raw()}),
                replay_store=PostgresReplayStore(scoped),
                key_revocations=PostgresTrustedKeyRevocations(scoped, environment_id="probe-env",
                                                             deployment_id="probe-deploy"))
            writer = PostgresIngressReceiptWriter(scoped, environment_id="probe-env",
                                                  deployment_id="probe-deploy")
            first = uuid4().hex
            claims, receipt_id = _verify(checker, _token(key, first), writer)
            assert claims.jti == first
            with psycopg.connect(scoped) as connection:
                row = connection.execute("SELECT receipt_id FROM ingress_receipts WHERE jti=%s", (first,)).fetchone()
                assert row == (receipt_id,)
                assert connection.execute("SELECT count(*) FROM replay_entries WHERE jti=%s",
                                          (first,)).fetchone()[0] == 1
            try:
                _verify(checker, _token(key, first), writer)
            except TrustedSessionError as exc:
                assert str(exc) == "trusted_session_replay"
            else:
                raise AssertionError("replay_was_not_rejected")

            class FailingWriter(PostgresIngressReceiptWriter):
                """Replay INSERT 之後製造受保護 Receipt 寫入錯誤。"""

                def _write_on_cursor(self, cursor, *, claims, kid):
                    """逼迫 Coordinator 回滾整筆 IngressTx，而非孤兒 JTI。"""
                    raise IngressReceiptError("injected_failure")

            second = uuid4().hex
            try:
                _verify(checker, _token(key, second),
                    FailingWriter(scoped, environment_id="probe-env", deployment_id="probe-deploy"))
            except IngressReceiptError as exc:
                assert str(exc) == "injected_failure"
            else:
                raise AssertionError("receipt_failure_was_not_propagated")
            with psycopg.connect(scoped) as connection:
                assert connection.execute("SELECT count(*) FROM replay_entries WHERE jti=%s",
                                          (second,)).fetchone()[0] == 0
                assert connection.execute("SELECT count(*) FROM ingress_receipts WHERE jti=%s",
                                          (second,)).fetchone()[0] == 0
            third = uuid4().hex
            stale_time = int(time.time()) - 120
            try:
                _verify(checker, _token(key, third, reference_time=stale_time), writer, now=stale_time)
            except Exception as exc:
                assert str(exc) == "ingress_receipt_db_time_invalid", str(exc)
            else:
                raise AssertionError("db_clock_failed_to_reject_stale_token")
            with psycopg.connect(scoped) as connection:
                assert connection.execute("SELECT count(*) FROM replay_entries WHERE jti=%s",
                                          (third,)).fetchone()[0] == 0
            gc_jti = uuid4().hex
            clock_now = int(time.time())
            replay = PostgresReplayStore(scoped)
            assert replay.consume(issuer="probe-gateway", audience="probe-mirage", jti=gc_jti,
                                  expires_at=clock_now + 20,
                                  now=clock_now) is ReplayConsumeResult.ACCEPTED
            assert replay.gc(now=clock_now + 100) == 1
            with psycopg.connect(scoped) as connection:
                assert connection.execute("SELECT count(*) FROM replay_entries WHERE jti=%s",
                                          (first,)).fetchone()[0] == 1
                assert connection.execute("SELECT count(*) FROM replay_entries WHERE jti=%s",
                                          (gc_jti,)).fetchone()[0] == 0
            print("LAB_RECEIPT_TX_PROBE_OK normal=atomic replay=denied explicit_rollback=atomic "
                  "db_time=denied gc=protected_receipt_retained")
        finally:
            admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


if __name__ == "__main__":
    run()
