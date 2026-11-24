"""只對一次性 Oracle G3b／G4 實驗網路發送簽章查詢，驗證 DB 中斷故障類別。"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import ssl
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import httpx

from deception.api.fingerprint import fingerprint_httpx_request
from g3b_ci_probe import _sign


def _probe(*, phase: str, recovery_session: str | None) -> None:
    """同一隔離身分於故障時須拒絕，恢復後允許單次查詢且重播必須拒絕。"""
    root = Path("/lab/probe")
    key = Ed25519PrivateKey.from_private_bytes((root / "signing.key").read_bytes())
    context = ssl.create_default_context(cafile=str(root / "gateway-ca.pem"))
    context.load_cert_chain(str(root / "gateway-client.pem"),
                            str(root / "gateway-client.key"))
    origin = "https://verifier:8443"
    request_id = "g3b-ci-oracle-fault-" + uuid4().hex
    with httpx.Client(verify=context, trust_env=False, timeout=6.0) as gateway:
        request = gateway.build_request(
            "GET", origin + "/synthetic/inventory/sku-1",
            headers={"x-request-id": request_id},
        )
        # 長時間 Oracle 操作可能讓 420s 初始 World 自然過期；復原只使用
        # 由原生 World 介面另外建好的隔離合成 Session，不人工改 expires_at。
        session = recovery_session if phase == "recovered" else "session"
        request.headers["x-trusted-session"] = _sign(
            key, fingerprint=fingerprint_httpx_request(request, request_id),
            session=session, mode="inventory",
        )
        response = gateway.send(request)
        if phase == "degraded":
            if response.status_code != 503:
                raise RuntimeError("g3b_oracle_db_outage_not_failed_closed:" +
                                   str(response.status_code))
            if b"sku-1" in response.content or b"mirage_ci_owner" in response.content:
                raise RuntimeError("g3b_oracle_db_outage_leaked_internal_data")
            print("G3B_ORACLE_DB_OUTAGE_PASS signed_get=503 no_state_leak=1 "
                  "trusted_send=off")
            return
        if response.status_code != 200:
            raise RuntimeError("g3b_oracle_db_recovery_failed:" + str(response.status_code))
        payload = response.json()
        if (payload.get("operation_id") != "getSyntheticInventory"
                or payload.get("native_projection", {}).get("status_code") != 200
                or gateway.send(request).status_code != 403):
            raise RuntimeError("g3b_oracle_db_recovery_or_replay_violation")
        readiness = gateway.get(origin + "/internal/ready")
        if (readiness.status_code != 200
                or readiness.json().get("trusted_send") != "disabled"):
            raise RuntimeError("g3b_oracle_db_recovery_trusted_send_violation")
        print("G3B_ORACLE_DB_RECOVERY_PASS signed_get=200 replay=403 "
              "trusted_send=off")


def main() -> None:
    """僅允許指定的故障階段，避免誤向真實部署或其他業務端點發送。"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("degraded", "recovered"), required=True)
    parser.add_argument("--recovery-session")
    args = parser.parse_args()
    if args.phase == "recovered" and (not isinstance(args.recovery_session, str)
                                      or not re.fullmatch(r"[a-z0-9-]{3,80}", args.recovery_session)):
        parser.error("isolated recovery session required")
    _probe(phase=args.phase, recovery_session=args.recovery_session)


if __name__ == "__main__":
    main()
