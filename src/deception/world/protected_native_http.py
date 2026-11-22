"""獨立 Validator 從不可變 DB 拒絕來源重建原生 Medusa 400／404 候選封套。"""

from __future__ import annotations

from dataclasses import dataclass
import json
from uuid import UUID

from deception.security.key_revocation import PostgresTrustedKeyRevocations

from .models import SecurityErrorSource, WorldScope
from .protected_grant import _ProtectedConnection, ProtectedGrantError
from .transmission import response_hashes


def fixed_medusa_rejection_bytes(status_code: int, template_id: str) -> tuple[tuple[tuple[str, str], ...], bytes]:
    """只按不可變拒絕類型重建 Medusa 原生固定 JSON，禁止任意錯誤字串。"""
    if (status_code, template_id) == (400, "native-cart-invalid"):
        payload = {"type": "invalid_data", "message": "The requested cart operation is not supported."}
    elif (status_code, template_id) == (404, "native-cart-rejected"):
        payload = {"type": "not_found", "message": "The requested cart operation could not be completed."}
    else:
        raise ProtectedGrantError("protected_native_template_unapproved")
    return (("content-type", "application/json"),), json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


@dataclass(frozen=True)
class ProtectedNativeProjection:
    """只供獨立 Candidate Validator 的未發送候選，已固定來源、Scope 與原生 bytes。"""

    receipt_id: UUID
    scope: WorldScope
    operation_id: str
    request_fingerprint: str
    status_code: int
    headers: tuple[tuple[str, str], ...]
    body_bytes: bytes
    envelope_hash: str
    source: SecurityErrorSource


class PostgresProtectedNativeProjector(_ProtectedConnection):
    """以與 Verifier／Executor 不同的讀取 Login 查核拒絕及固定 HTTP Envelope。"""

    def project_medusa_rejection(self, receipt_id: UUID) -> ProtectedNativeProjection:
        """從不可變 Rejection→Proof→Read→Epoch／Key 重建 Medusa 400／404。

        不接收 Caller 自填 Status、Template、Body、Source、World Scope；資料庫
        若不存在完整同一 Receipt 與有效來源，固定拒絕。這只產生候選，不能
        繞過 Candidate Promoter／G4 Authorized Snapshot／Sender 最終重驗。
        """
        if not isinstance(receipt_id, UUID) or receipt_id.version != 4:
            raise ProtectedGrantError("protected_native_receipt_invalid")
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET LOCAL statement_timeout='5s'")
                cursor.execute(
                    """SELECT environment_id,deployment_id,session_id,world_generation_id,
                              request_fingerprint,operation_id,status_code,reason_code,
                              template_id,contract_revision,envelope_hash,read_admission_id
                       FROM protected_medusa_rejection_sources WHERE receipt_id=%s""",
                    (receipt_id,),
                )
                source = cursor.fetchone()
                if source is None:
                    raise ProtectedGrantError("protected_native_source_missing")
                (environment, deployment, session, generation, fingerprint, operation,
                 status, reason, template, revision, envelope, read_id) = source
                if (operation != "PostCartsIdLineItems" or revision != "medusa-cart-1"
                        or (status, reason, template) not in {
                            (400, "native_bad_key", "native-cart-invalid"),
                            (400, "native_bad_item_body", "native-cart-invalid"),
                            (404, "native_variant_absent", "native-cart-rejected"),
                        }):
                    raise ProtectedGrantError("protected_native_source_policy_denied")
                cursor.execute(
                    """SELECT environment_id,deployment_id,session_id,session_epoch,
                              request_fingerprint,issuer,key_id,token_expires_at,
                              access_mode,resource_id
                       FROM ingress_receipts WHERE receipt_id=%s""",
                    (receipt_id,),
                )
                ingress = cursor.fetchone()
                if (ingress is None or ingress[:3] != (environment, deployment, session)
                        or ingress[4] != fingerprint or ingress[8] != "cart"
                        or ingress[9] is None):
                    raise ProtectedGrantError("protected_native_ingress_mismatch")
                cursor.execute(
                    """SELECT platform,operation_id,method,path_template,request_fingerprint,
                              request_path FROM protected_http_operation_bindings
                       WHERE receipt_id=%s""", (receipt_id,),
                )
                proof = cursor.fetchone()
                if (proof is None or proof[:5] != (
                        "medusa-native-cart", operation, "POST",
                        "/store/carts/{id}/line-items", fingerprint)
                        or proof[5] != "/store/carts/" + ingress[9] + "/line-items"):
                    raise ProtectedGrantError("protected_native_operation_mismatch")
                cursor.execute(
                    """SELECT environment_id,deployment_id,session_id,world_generation_id,
                              request_fingerprint,state_version,state_hash,receipt_id
                       FROM protected_world_read_sources WHERE read_admission_id=%s""",
                    (read_id,),
                )
                read = cursor.fetchone()
                if (read is None or read[:5] != (
                        environment, deployment, session, generation, fingerprint)
                        or read[7] != receipt_id):
                    raise ProtectedGrantError("protected_native_read_source_mismatch")
                cursor.execute(
                    """SELECT environment_id,deployment_id,session_id,world_generation_id,
                              request_binding_digest,state_version,state_hash,expires_at
                       FROM read_admissions WHERE read_admission_id=%s""",
                    (read_id,),
                )
                admission = cursor.fetchone()
                if (admission is None or admission[:5] != (
                        environment, deployment, session, generation, fingerprint)
                        or admission[5:7] != read[5:7]):
                    raise ProtectedGrantError("protected_native_read_admission_mismatch")
                cursor.execute("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                now = cursor.fetchone()[0]
                if ingress[7] <= now or admission[7] <= now:
                    raise ProtectedGrantError("protected_native_source_expired")
                cursor.execute(
                    """SELECT session_epoch FROM session_heads
                       WHERE environment_id=%s AND deployment_id=%s AND session_id=%s""",
                    (environment, deployment, session),
                )
                head = cursor.fetchone()
                if head != (ingress[3],):
                    raise ProtectedGrantError("protected_native_epoch_stale")
                cursor.execute(
                    """SELECT world_generation_id FROM session_world_bindings
                       WHERE environment_id=%s AND deployment_id=%s AND session_id=%s
                         AND session_epoch=%s""",
                    (environment, deployment, session, ingress[3]),
                )
                if cursor.fetchone() != (generation,):
                    raise ProtectedGrantError("protected_native_generation_mismatch")
                cursor.execute(
                    """SELECT sealed,emergency_revision FROM generation_controls
                       WHERE world_generation_id=%s""", (generation,),
                )
                if cursor.fetchone() != (False, None):
                    raise ProtectedGrantError("protected_native_generation_revoked")
                key_control = PostgresTrustedKeyRevocations(
                    self._dsn, environment_id=environment, deployment_id=deployment,
                )
                key_control._lock(cursor, ingress[5], ingress[6])
                if key_control._select(cursor, ingress[5], ingress[6]) is not None:
                    raise ProtectedGrantError("protected_native_key_revoked")
        headers, body = fixed_medusa_rejection_bytes(status, template)
        if response_hashes(status, headers, body)[0] != envelope:
            raise ProtectedGrantError("protected_native_envelope_hash_mismatch")
        return ProtectedNativeProjection(
            receipt_id=receipt_id,
            scope=WorldScope(environment_id=environment, deployment_id=deployment,
                             session_id=session, world_generation_id=generation),
            operation_id=operation, request_fingerprint=fingerprint, status_code=status,
            headers=headers, body_bytes=body, envelope_hash=envelope,
            source=SecurityErrorSource(template_id=template, contract_revision=revision),
        )
