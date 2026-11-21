"""使用真正隔離 Verifier SCRAM 帳號驗證 Replay 與 Receipt 的資料庫約束。"""

from __future__ import annotations

import sys
from uuid import uuid4

import psycopg

from probe import _connection, _deny


def _insert_receipt(connection, jti: str) -> None:
    """只使用合成資料測試 Receipt Schema；此函式不簽署或驗證真實 JWS。"""
    connection.execute(
        """INSERT INTO public.ingress_receipts (
               issuer,audience,jti,key_id,environment_id,deployment_id,session_id,session_epoch,
               request_fingerprint,assessment_digest,claims_digest,verification_policy_version,
               token_issued_at,token_not_before,token_expires_at
           ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        ("lab-issuer", "lab-audience", jti, "lab-kid", "lab", "isolated",
         "lab-session", 1, "a" * 64, "b" * 64, "c" * 64,
         "lab-test-v1", 1_700_000_000, 1_700_000_000, 2_000_000_000),
    )


def main(role: str) -> None:
    """只以本容器自己持有的身分測試 Receipt 權限及 Replay 原子性。"""
    if role not in ("verifier", "runtime"):
        raise RuntimeError("invalid_lab_role")
    if role == "runtime":
        _deny("runtime", "UPDATE public.ingress_receipts SET key_id='x' WHERE false")
        _deny("runtime", "DELETE FROM public.ingress_receipts WHERE false")
        _deny("runtime", "INSERT INTO public.ingress_receipts (issuer) VALUES ('forged')")
        print("LAB_RECEIPT_SCHEMA_PROBE_OK role=runtime direct_dml=42501")
        return
    _deny("verifier", "UPDATE public.ingress_receipts SET key_id='x' WHERE false")
    _deny("verifier", "DELETE FROM public.ingress_receipts WHERE false")
    _deny("verifier", "INSERT INTO public.ingress_receipts (issuer,verified_at) "
          "VALUES ('forged',clock_timestamp())")

    orphan = "lab-orphan-" + uuid4().hex
    with _connection("verifier") as connection:
        try:
            _insert_receipt(connection, orphan)
        except psycopg.errors.ForeignKeyViolation as error:
            if error.sqlstate != "23503":
                raise AssertionError("unexpected_orphan_error") from error
            connection.rollback()
        else:
            raise AssertionError("orphan_receipt_was_accepted")

    jti = "lab-receipt-" + uuid4().hex
    with _connection("verifier") as connection:
        connection.execute("INSERT INTO public.replay_entries VALUES (%s,%s,%s,%s)",
                           ("lab-issuer", "lab-audience", jti, 2_000_000_030))
        _insert_receipt(connection, jti)
        # 驗證 DB 可接受同交易的兩筆操作，但不留不可清理的測試墓碑。
        connection.rollback()
    with _connection("verifier") as connection:
        count = connection.execute("SELECT count(*) FROM public.ingress_receipts WHERE jti=%s",
                                   (jti,)).fetchone()
        replay = connection.execute("SELECT count(*) FROM public.replay_entries WHERE jti=%s",
                                    (jti,)).fetchone()
        if count != (0,) or replay != (0,):
            raise AssertionError("rollback_left_partial_ingress")
    print("LAB_RECEIPT_SCHEMA_PROBE_OK orphan=23503 role_denial=42501 pair_rollback=atomic")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python receipt_schema_probe.py verifier|runtime")
    main(sys.argv[1])
