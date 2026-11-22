"""可信 Verifier 專用的 Ingress Receipt 交易內寫入介面。"""

from __future__ import annotations

import hashlib
from uuid import UUID

from deception.api.ingress import NormalizedRequest

from .operation_binding import VerifiedOperationBinding, derive_verified_operation
from .trusted_session import TrustedSessionClaims


class IngressReceiptError(ValueError):
    """表示 Verifier 交易上下文或驗證對象不符合 Receipt 寫入契約。"""


class PostgresIngressReceiptWriter:
    """僅供持有獨立 Verifier DB 身分的驗證程序在 IngressTx 內使用。"""

    def __init__(self, dsn: str, *, environment_id: str, deployment_id: str,
                 verified_request: NormalizedRequest | None = None) -> None:
        """固定物理資料庫登入域及部署範圍，可從 Verifier 原始 HTTP 快照核准操作。

        `verified_request` 僅能由獨立 Verifier 的受保護入口注入。缺少時相容
        舊 Receipt 流程，但不建立可信 Operation Binding，也不能解封業務 RPC。
        """
        if not isinstance(dsn, str) or not dsn.strip():
            raise IngressReceiptError("ingress_receipt_requires_dsn")
        if any(not isinstance(value, str) or not value or len(value) > 128
               for value in (environment_id, deployment_id)):
            raise IngressReceiptError("ingress_receipt_invalid_deployment")
        self._dsn = dsn
        self._environment_id = environment_id
        self._deployment_id = deployment_id
        self._operation: VerifiedOperationBinding | None = (
            derive_verified_operation(verified_request) if verified_request is not None else None
        )

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
        operation = self._operation
        if operation is not None and operation.request_fingerprint != claims.request_fingerprint:
            raise IngressReceiptError("ingress_operation_fingerprint_mismatch")
        claims_digest = hashlib.sha256(claims.model_dump_json().encode("utf-8")).hexdigest()
        cursor.execute(
            """INSERT INTO ingress_receipts (
                   issuer, audience, jti, key_id, environment_id, deployment_id,
                   session_id, session_epoch, request_fingerprint, assessment_digest,
                   claims_digest, verification_policy_version, token_issued_at,
                   token_not_before, token_expires_at, access_mode, resource_id
               ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               RETURNING receipt_id""",
            (claims.iss, claims.aud, claims.jti, kid, self._environment_id,
             self._deployment_id, claims.session_id, claims.session_epoch,
             claims.request_fingerprint, claims.assessment_digest, claims_digest,
             "trusted-session-v1.1", claims.iat, claims.nbf, claims.exp,
             claims.access_mode, claims.resource_id),
        )
        receipt_id = cursor.fetchone()[0]
        if operation is not None:
            cursor.execute(
                """INSERT INTO protected_http_operation_bindings (
                       receipt_id,platform,operation_id,method,path_template,
                       request_fingerprint,request_body_sha256,request_path,request_content_type)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (receipt_id, operation.platform, operation.operation_id,
                 operation.method, operation.path_template,
                 operation.request_fingerprint, operation.request_body_sha256,
                 operation.request_path, operation.request_content_type),
            )
        return receipt_id
