"""獨立 Validator 從不可變 DB 拒絕來源重建原生 Medusa 400／404 候選封套。"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from uuid import UUID

from deception.security.key_revocation import PostgresTrustedKeyRevocations
from deception.world.commit import operation_result_digest

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


_SYNTHETIC_MUTATION_HANDLERS = {
    "reserveSyntheticInventory": ("synthetic-inventory", "POST", "/synthetic/inventory/reservations", "reserve"),
    "cancelSyntheticInventory": ("synthetic-inventory", "POST", "/synthetic/inventory/reservations/{reservation_id}/cancel", "cancel"),
    "addGuestCartItem": ("synthetic-carts", "POST", "/synthetic/carts/{cart_id}/line-items", "cart.add"),
    "updateGuestCartItem": ("synthetic-carts", "POST", "/synthetic/carts/{cart_id}/line-items/{item_id}", "cart.update"),
    "removeGuestCartItem": ("synthetic-carts", "DELETE", "/synthetic/carts/{cart_id}/line-items/{item_id}", "cart.remove"),
    "completeGuestCart": ("synthetic-carts", "POST", "/synthetic/carts/{cart_id}/complete", "cart.complete"),
    "cancelSyntheticOrder": ("synthetic-carts", "POST", "/synthetic/orders/{order_id}/cancel", "cart.cancel_order"),
}

_SYNTHETIC_MUTATION_PATHS = {
    "reserveSyntheticInventory": r"/synthetic/inventory/reservations",
    "cancelSyntheticInventory": r"/synthetic/inventory/reservations/([0-9a-f]{32})/cancel",
    "addGuestCartItem": r"/synthetic/carts/(cart_[0-9a-f]{32})/line-items",
    "updateGuestCartItem": r"/synthetic/carts/(cart_[0-9a-f]{32})/line-items/item_[0-9a-f]{32}",
    "removeGuestCartItem": r"/synthetic/carts/(cart_[0-9a-f]{32})/line-items/item_[0-9a-f]{32}",
    "completeGuestCart": r"/synthetic/carts/(cart_[0-9a-f]{32})/complete",
    "cancelSyntheticOrder": r"/synthetic/orders/(order_[0-9a-f]{32})/cancel",
}


def fixed_synthetic_rejection_bytes(platform: str, code: str) -> tuple[tuple[tuple[str, str], ...], bytes]:
    """只將兩份固定 Synthetic OpenAPI 核准的 Handler 拒絕碼投影為 409 JSON。"""
    from deception.domains.ecommerce.cart_http import CART_ERRORS
    from deception.domains.ecommerce.inventory_http import ERROR_CODES

    allowed = ERROR_CODES if platform == "synthetic-inventory" else (
        CART_ERRORS if platform == "synthetic-carts" else ())
    if not isinstance(code, str) or code not in allowed:
        raise ProtectedGrantError("protected_synthetic_rejection_code_unapproved")
    return (("content-type", "application/json"),), json.dumps(
        {"code": code}, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
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

    def project_synthetic_rejection(self, receipt_id: UUID) -> ProtectedNativeProjection:
        """只由真 Handler 的不可變 409 來源和原始 Proof 重建 Synthetic 候選。

        與 Medusa 400／404 使用同一個獨立唯讀實體 Login；不接受 Status、
        Handler、Error Code、Scope 或 Body 等 Caller 欄位。驗證 Receipt、
        ReadAdmission、World Result、Epoch、Key 與精確 Envelope，失敗一律無候選。
        """
        if not isinstance(receipt_id, UUID) or receipt_id.version != 4:
            raise ProtectedGrantError("protected_synthetic_receipt_invalid")
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET LOCAL statement_timeout='5s'")
                cursor.execute(
                    """SELECT p.environment_id,p.deployment_id,p.session_id,p.world_generation_id,
                              p.request_fingerprint,p.operation,p.result_digest,p.template_id,
                              p.contract_revision,p.envelope_hash,p.commit_attempt_id,
                              o.status,o.result,o.state_version,o.state_hash,
                              o.result_encoding_version,o.result_digest,o.operation,
                              o.environment_id,o.deployment_id,o.session_id,o.world_generation_id
                       FROM protected_world_rejection_sources p
                       JOIN world_operations o ON o.commit_attempt_id=p.commit_attempt_id
                       WHERE p.receipt_id=%s""",
                    (receipt_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    raise ProtectedGrantError("protected_synthetic_rejection_source_missing")
                (environment, deployment, session, generation, fingerprint, action,
                 result_digest, code, revision, envelope, attempt, status, result,
                 version, state_hash, encoding, saved_digest, saved_action,
                 result_environment, result_deployment, result_session, result_generation) = row
                if (status != "rejected" or not isinstance(result, dict)
                        or result.get("code") != code or set(result) != {"code"}
                        or saved_action != action or saved_digest != result_digest
                        or (result_environment, result_deployment, result_session, result_generation)
                        != (environment, deployment, session, generation)
                        or encoding != 1
                        or operation_result_digest(result, version, state_hash, attempt, status)
                        != result_digest):
                    raise ProtectedGrantError("protected_synthetic_result_unverifiable")
                cursor.execute(
                    """SELECT environment_id,deployment_id,session_id,session_epoch,
                              request_fingerprint,issuer,key_id,token_expires_at,
                              access_mode,resource_id
                       FROM ingress_receipts WHERE receipt_id=%s""", (receipt_id,),
                )
                ingress = cursor.fetchone()
                if (ingress is None or ingress[:3] != (environment, deployment, session)
                        or ingress[4] != fingerprint):
                    raise ProtectedGrantError("protected_synthetic_ingress_mismatch")
                cursor.execute(
                    """SELECT platform,operation_id,method,path_template,request_fingerprint,
                              request_path,request_content_type
                       FROM protected_http_operation_bindings WHERE receipt_id=%s""",
                    (receipt_id,),
                )
                proof = cursor.fetchone()
                if proof is None or proof[1] not in _SYNTHETIC_MUTATION_HANDLERS:
                    raise ProtectedGrantError("protected_synthetic_operation_missing")
                platform, method, template, expected_action = _SYNTHETIC_MUTATION_HANDLERS[proof[1]]
                matched_path = re.fullmatch(_SYNTHETIC_MUTATION_PATHS[proof[1]], proof[5]) if (
                    isinstance(proof[5], str)) else None
                if (proof[:5] != (platform, proof[1], method, template, fingerprint)
                        or matched_path is None
                        or not isinstance(proof[6], str)
                        or proof[6].split(";", 1)[0].strip().lower() != "application/json"
                        or action != expected_action
                        or revision != platform + "-1"
                        or (platform == "synthetic-inventory" and
                            (ingress[8], ingress[9]) != ("inventory", None))
                        or (platform == "synthetic-carts" and
                            (ingress[8] != "cart" or not ingress[9]
                             or matched_path[1] != ingress[9]))):
                    raise ProtectedGrantError("protected_synthetic_operation_mismatch")
                headers, body = fixed_synthetic_rejection_bytes(platform, code)
                if response_hashes(409, headers, body)[0] != envelope:
                    raise ProtectedGrantError("protected_synthetic_envelope_mismatch")
                cursor.execute(
                    """SELECT p.environment_id,p.deployment_id,p.session_id,p.world_generation_id,
                              p.request_fingerprint,p.state_version,p.state_hash,
                              a.request_binding_digest,a.state_version,a.state_hash,a.expires_at,
                              a.environment_id,a.deployment_id,a.session_id,a.world_generation_id
                       FROM protected_world_read_sources p
                       JOIN read_admissions a ON a.read_admission_id=p.read_admission_id
                       WHERE p.receipt_id=%s""", (receipt_id,),
                )
                read = cursor.fetchone()
                if (read is None or read[:5] != (
                        environment, deployment, session, generation, fingerprint)
                        or read[5:7] != read[8:10] or read[7] != fingerprint
                        or read[11:15] != (environment, deployment, session, generation)):
                    raise ProtectedGrantError("protected_synthetic_read_source_mismatch")
                cursor.execute("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                now = cursor.fetchone()[0]
                if ingress[7] <= now or read[10] <= now:
                    raise ProtectedGrantError("protected_synthetic_source_expired")
                cursor.execute(
                    """SELECT session_epoch FROM session_heads WHERE environment_id=%s
                       AND deployment_id=%s AND session_id=%s""",
                    (environment, deployment, session),
                )
                if cursor.fetchone() != (ingress[3],):
                    raise ProtectedGrantError("protected_synthetic_epoch_stale")
                cursor.execute(
                    """SELECT world_generation_id FROM session_world_bindings
                       WHERE environment_id=%s AND deployment_id=%s AND session_id=%s
                         AND session_epoch=%s""",
                    (environment, deployment, session, ingress[3]),
                )
                if cursor.fetchone() != (generation,):
                    raise ProtectedGrantError("protected_synthetic_generation_mismatch")
                cursor.execute("SELECT sealed,emergency_revision FROM generation_controls WHERE world_generation_id=%s",
                               (generation,))
                if cursor.fetchone() != (False, None):
                    raise ProtectedGrantError("protected_synthetic_generation_revoked")
                key_guard = PostgresTrustedKeyRevocations(
                    self._dsn, environment_id=environment, deployment_id=deployment,
                )
                key_guard._lock(cursor, ingress[5], ingress[6])
                if key_guard._select(cursor, ingress[5], ingress[6]) is not None:
                    raise ProtectedGrantError("protected_synthetic_key_revoked")
        return ProtectedNativeProjection(
            receipt_id=receipt_id,
            scope=WorldScope(environment_id=environment, deployment_id=deployment,
                             session_id=session, world_generation_id=generation),
            operation_id=proof[1], request_fingerprint=fingerprint, status_code=409,
            headers=headers, body_bytes=body, envelope_hash=envelope,
            source=SecurityErrorSource(template_id=code, contract_revision=revision),
        )

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
