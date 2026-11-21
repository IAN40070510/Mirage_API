"""可信 Verifier 專用的 Ingress Receipt 交易內寫入介面。"""

from __future__ import annotations

import hashlib
from uuid import UUID

from .trusted_session import TrustedSessionClaims


class IngressReceiptError(ValueError):
    """表示 Verifier 交易上下文或驗證對象不符合 Receipt 寫入契約。"""


class PostgresIngressReceiptWriter:
    """僅供持有獨立 Verifier DB 身分的驗證程序在 IngressTx 內使用。"""

    def __init__(self, dsn: str, *, environment_id: str, deployment_id: str) -> None:
        """固定與 Replay／Key Guard 相同的物理資料庫登入域及部署範圍。"""
        if not isinstance(dsn, str) or not dsn.strip():
            raise IngressReceiptError("ingress_receipt_requires_dsn")
        if any(not isinstance(value, str) or not value or len(value) > 128
               for value in (environment_id, deployment_id)):
            raise IngressReceiptError("ingress_receipt_invalid_deployment")
        self._dsn = dsn
        self._environment_id = environment_id
        self._deployment_id = deployment_id

    def _write_on_cursor(self, cursor, *, claims: TrustedSessionClaims, kid: str) -> UUID:
        """在既有 Key Guard／Replay 交易寫入 Receipt，不建立連線、不自行提交。

        此方法僅接受同一可信 Verifier 程序內**實際完成驗章**的 claims；Python
        型別不是跨程序認證。DB 可信性尚須靠 Verifier 專用 Login、表 ACL、容器
        Secret 與網路來源隔離。不可把此方法暴露為任意 claims JSON 的公共 API。
        """
        if cursor.connection.autocommit:
            raise IngressReceiptError("ingress_receipt_requires_transaction")
        if not isinstance(claims, TrustedSessionClaims) or not isinstance(kid, str) or not 1 <= len(kid) <= 128:
            raise IngressReceiptError("ingress_receipt_invalid_verified_input")
        if (claims.environment_id, claims.deployment_id) != (self._environment_id, self._deployment_id):
            raise IngressReceiptError("ingress_receipt_scope_mismatch")
        claims_digest = hashlib.sha256(claims.model_dump_json().encode("utf-8")).hexdigest()
        cursor.execute(
            """INSERT INTO ingress_receipts (
                   issuer, audience, jti, key_id, environment_id, deployment_id,
                   session_id, session_epoch, request_fingerprint, assessment_digest,
                   claims_digest, verification_policy_version, token_issued_at,
                   token_not_before, token_expires_at
               ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               RETURNING receipt_id""",
            (claims.iss, claims.aud, claims.jti, kid, self._environment_id,
             self._deployment_id, claims.session_id, claims.session_epoch,
             claims.request_fingerprint, claims.assessment_digest, claims_digest,
             "trusted-session-v1.1", claims.iat, claims.nbf, claims.exp),
        )
        return cursor.fetchone()[0]
