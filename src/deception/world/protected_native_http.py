"""獨立 Validator 從不可變 DB 拒絕來源重建原生 Medusa 400／404 候選封套。"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from uuid import UUID

from deception.security.key_revocation import PostgresTrustedKeyRevocations
from deception.world.commit import operation_result_digest

from .models import (CartCreationSource, CommitSource, ResponseSource, SecurityErrorSource,
                     SnapshotSource, WorldScope, WorldSnapshot)
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


def _verified_cart_result_matches_snapshot(
    *, resource: str, result: dict, snapshot_state: dict,
) -> bool:
    """將 C-03～C-05 的結果逐欄比對已驗 Hash 的當前 Cart，拒絕跨品項重綁。

    WorldSnapshot 的 items 以 ID 為鍵；Result 的 items 是原生陣列，順序
    不能當權威，因此須先驗重複 ID，再比較完整 Cart 內容與 URL 資源身分。
    """
    if (not isinstance(resource, str) or not isinstance(result, dict)
            or not isinstance(snapshot_state, dict)):
        return False
    cart = snapshot_state.get("cart")
    items = result.get("items")
    if (not isinstance(cart, dict) or cart.get("id") != resource
            or result.get("id") != resource or not isinstance(items, list)
            or not isinstance(cart.get("items"), dict)):
        return False
    normalized_items = {}
    for item in items:
        if (not isinstance(item, dict) or not isinstance(item.get("id"), str)
                or item["id"] in normalized_items):
            return False
        normalized_items[item["id"]] = item
    return {**result, "items": normalized_items} == cart


def _verified_order_result_matches_snapshot(
    *, action: str, resource: str, result: dict, snapshot_state: dict,
) -> bool:
    """依 complete/cart ID 或 cancel/order ID 分別綁定原始路徑與實體訂單。

    必須證明結果存在於同世代當前 Snapshot，且訂單從同一 Cart 衍生；
    防止以重算合法 Envelope 的其他 Cart 或 Order 結果冒用本次 Receipt。
    """
    if (action not in {"cart.complete", "cart.cancel_order"}
            or not isinstance(resource, str) or not isinstance(result, dict)
            or not isinstance(snapshot_state, dict)):
        return False
    cart = snapshot_state.get("cart")
    orders = snapshot_state.get("orders")
    order_id = result.get("id")
    if (not isinstance(cart, dict) or not isinstance(orders, dict)
            or not isinstance(order_id, str)
            or re.fullmatch(r"order_[0-9a-f]{32}", order_id) is None
            or not isinstance(result.get("items"), list)
            or result.get("cart_id") != cart.get("id")
            or orders.get(order_id) != result):
        return False
    return (resource == cart.get("id") if action == "cart.complete"
            else resource == order_id)


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
    source: ResponseSource


def _medusa_cart_creation_platform(cursor, receipt_id: UUID) -> bool:
    """只從不可變 Operation Proof 區分合成 C-01 與原生 M-01 建立來源。"""
    cursor.execute(
        "SELECT platform,operation_id,method,path_template FROM protected_http_operation_bindings "
        "WHERE receipt_id=%s", (receipt_id,),
    )
    route = cursor.fetchone()
    if route == ("medusa-native-cart", "PostCarts", "POST", "/store/carts"):
        return True
    if route == ("synthetic-carts", "createGuestCart", "POST", "/synthetic/carts"):
        return False
    raise ProtectedGrantError("protected_cart_creation_platform_unapproved")


def _verified_cart_creation(cursor, receipt_id: UUID, *, expected_scope: WorldScope | None = None,
                            expected_fingerprint: str | None = None,
                            expected_source: CartCreationSource | None = None,
                            medusa: bool = False,
                            ) -> tuple[WorldScope, str, CartCreationSource, dict]:
    """從 Creator Receipt 與不可變 Lineage 獨立驗證派生世界的一次建立結果。

    Promotion 維持 Creator Scope；只有這個固定來源能引用 Derived Scope，
    不允許以派生 Session 的 Receipt 偽裝 Creator 或將一般 Commit 跨 Scope。
    舊版未受保護的建立列、漂移的世界或被調整的 JSON 都不能形成 200。
    """
    from deception.domains.ecommerce.carts import SyntheticCarts

    cursor.execute("SET LOCAL statement_timeout='5s'")
    cursor.execute(
        """SELECT p.environment_id,p.deployment_id,p.creator_session_id,p.creator_epoch,
                  p.request_fingerprint,p.idempotency_key,p.commit_attempt_id,p.operation_digest,
                  p.derived_session_id,p.derived_world_generation_id,p.resource_id,
                  r.environment_id,r.deployment_id,r.session_id,r.session_epoch,
                  r.request_fingerprint,r.access_mode,r.resource_id,r.token_expires_at,r.issuer,r.key_id
           FROM protected_cart_creations p JOIN ingress_receipts r USING (receipt_id)
           WHERE p.receipt_id=%s""", (receipt_id,),
    )
    row = cursor.fetchone()
    if row is None:
        raise ProtectedGrantError("protected_cart_creation_source_missing")
    (environment, deployment, creator_session, creator_epoch, fingerprint, key,
     attempt, creation_digest, derived_session, generation, resource,
     receipt_environment, receipt_deployment, receipt_session, receipt_epoch,
     receipt_fingerprint, mode, receipt_resource, token_deadline, issuer, key_id) = row
    if ((environment, deployment, creator_session, creator_epoch, fingerprint) != (
            receipt_environment, receipt_deployment, receipt_session, receipt_epoch,
            receipt_fingerprint)
            or mode != "cart" or receipt_resource is not None
            or not isinstance(resource, str)
            or re.fullmatch(r"cart_[0-9a-f]{32}", resource) is None
            or expected_fingerprint is not None and fingerprint != expected_fingerprint):
        raise ProtectedGrantError("protected_cart_creation_receipt_mismatch")
    cursor.execute(
        """SELECT platform,operation_id,method,path_template,request_fingerprint,
                  request_path,request_content_type,request_body_sha256
           FROM protected_http_operation_bindings WHERE receipt_id=%s""", (receipt_id,),
    )
    proof = cursor.fetchone()
    route = (("medusa-native-cart", "PostCarts", "POST", "/store/carts") if medusa
             else ("synthetic-carts", "createGuestCart", "POST", "/synthetic/carts"))
    if (proof is None or proof[:4] != route
            or proof[4:6] != (fingerprint, route[3])
            or not isinstance(proof[6], str)
            or proof[6].split(";", 1)[0].strip().lower() != "application/json"
            or not isinstance(proof[7], str)
            or re.fullmatch(r"[0-9a-f]{64}", proof[7]) is None):
        raise ProtectedGrantError("protected_cart_creation_proof_mismatch")
    cursor.execute(
        """SELECT world_generation_id FROM session_world_bindings
           WHERE environment_id=%s AND deployment_id=%s AND session_id=%s
             AND session_epoch=%s""",
        (environment, deployment, creator_session, creator_epoch),
    )
    current_creator = cursor.fetchone()
    if current_creator is None:
        raise ProtectedGrantError("protected_cart_creation_creator_generation_missing")
    creator_scope = WorldScope(environment_id=environment, deployment_id=deployment,
                               session_id=creator_session, world_generation_id=current_creator[0])
    if expected_scope is not None and creator_scope != expected_scope:
        raise ProtectedGrantError("protected_cart_creation_creator_scope_mismatch")
    cursor.execute(
        """SELECT cart_id,operation_result,state_version,state_hash,commit_attempt_id,operation_digest
           FROM guest_cart_creations
           WHERE environment_id=%s AND deployment_id=%s AND creator_session_id=%s
             AND creator_epoch=%s AND idempotency_key=%s""",
        (environment, deployment, creator_session, creator_epoch, key),
    )
    creation = cursor.fetchone()
    if (creation is None or creation[0] != resource or creation[4] != attempt
            or creation[5] != creation_digest or creation[2] != 1):
        raise ProtectedGrantError("protected_cart_creation_derived_commit_mismatch")
    cursor.execute(
        """SELECT session_id,session_epoch,world_generation_id,expires_at
           FROM synthetic_resources WHERE resource_id=%s AND resource_kind='cart'
             AND environment_id=%s AND deployment_id=%s""",
        (resource, environment, deployment),
    )
    resource_row = cursor.fetchone()
    if resource_row is None or resource_row[:3] != (derived_session, 1, generation):
        raise ProtectedGrantError("protected_cart_creation_resource_mismatch")
    for session, epoch, current_generation in (
            (creator_session, creator_epoch, creator_scope.world_generation_id),
            (derived_session, 1, generation)):
        cursor.execute(
            """SELECT h.session_epoch,b.world_generation_id,g.sealed,g.emergency_revision
               FROM session_heads h
               JOIN session_world_bindings b ON (b.environment_id,b.deployment_id,b.session_id,b.session_epoch)
                   =(h.environment_id,h.deployment_id,h.session_id,h.session_epoch)
               JOIN generation_controls g ON g.world_generation_id=b.world_generation_id
               WHERE h.environment_id=%s AND h.deployment_id=%s AND h.session_id=%s""",
            (environment, deployment, session),
        )
        if cursor.fetchone() != (epoch, current_generation, False, None):
            raise ProtectedGrantError("protected_cart_creation_generation_stale")
    cursor.execute(
        """SELECT version,state_hash,state,expires_at FROM world_snapshots
           WHERE environment_id=%s AND deployment_id=%s AND session_id=%s
             AND world_generation_id=%s""",
        (environment, deployment, derived_session, generation),
    )
    saved = cursor.fetchone()
    if saved is None:
        raise ProtectedGrantError("protected_cart_creation_snapshot_missing")
    derived_scope = WorldScope(environment_id=environment, deployment_id=deployment,
                               session_id=derived_session, world_generation_id=generation)
    try:
        snapshot = WorldSnapshot(scope=derived_scope, version=saved[0], state_hash=saved[1],
                                 state=saved[2], expires_at=saved[3])
    except ValueError as exc:
        raise ProtectedGrantError("protected_cart_creation_snapshot_invalid") from exc
    if (snapshot.version, snapshot.state_hash) != (creation[2], creation[3]):
        raise ProtectedGrantError("protected_cart_creation_snapshot_stale")
    cart = snapshot.state.get("cart")
    if (not isinstance(cart, dict) or cart.get("id") != resource
            or cart.get("items") != {} or cart.get("total") != 0
            or cart.get("status") != "active" or cart.get("currency_code") != "usd"
            or set(cart) != {"id", "items", "total", "status", "currency_code"}
            or creation[1] != SyntheticCarts.public_cart(cart)):
        raise ProtectedGrantError("protected_cart_creation_result_mismatch")
    cursor.execute(
        """SELECT state_version,state_hash FROM world_commit_receipts
           WHERE environment_id=%s AND deployment_id=%s AND session_id=%s
             AND world_generation_id=%s AND commit_attempt_id=%s""",
        (environment, deployment, derived_session, generation, attempt),
    )
    if cursor.fetchone() != (snapshot.version, snapshot.state_hash):
        raise ProtectedGrantError("protected_cart_creation_commit_receipt_mismatch")
    cursor.execute("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
    now = cursor.fetchone()[0]
    if (token_deadline <= now or resource_row[3] <= now
            or snapshot.expires_at is not None and snapshot.expires_at <= now):
        raise ProtectedGrantError("protected_cart_creation_expired")
    guard = PostgresTrustedKeyRevocations(
        cursor.connection.info.dsn, environment_id=environment, deployment_id=deployment,
    )
    guard._lock(cursor, issuer, key_id)
    if guard._select(cursor, issuer, key_id) is not None:
        raise ProtectedGrantError("protected_cart_creation_key_revoked")
    source = CartCreationSource(derived_session_id=derived_session,
                                derived_world_generation_id=generation, resource_id=resource,
                                commit_attempt_id=str(attempt), state_version=snapshot.version,
                                state_hash=snapshot.state_hash)
    if expected_source is not None and source != expected_source:
        raise ProtectedGrantError("protected_cart_creation_source_mismatch")
    if medusa:
        from deception.domains.ecommerce.medusa_cart_projection import cart_view

        context = snapshot.state.get("native_context")
        catalog = snapshot.state.get("catalog")
        if not isinstance(context, dict) or not isinstance(catalog, dict):
            raise ProtectedGrantError("protected_medusa_creation_context_missing")
        try:
            payload = {"cart": cart_view(
                creation[1], {**context, "catalog": catalog},
            )}
        except (ValueError, KeyError, TypeError, OverflowError) as exc:
            raise ProtectedGrantError("protected_medusa_creation_projection_invalid") from exc
    else:
        payload = {"cart": creation[1], "state_version": snapshot.version,
                   "state_hash": snapshot.state_hash, "commit_attempt_id": str(attempt)}
    return creator_scope, fingerprint, source, payload


class PostgresProtectedNativeProjector(_ProtectedConnection):
    """以與 Verifier／Executor 不同的讀取 Login 查核拒絕及固定 HTTP Envelope。"""

    def __init__(self, dsn: str, *, expected_login: str,
                 medusa_source: Path | None = None) -> None:
        """以唯讀實體 Login 建立來源驗證器；Medusa 成功投影另須 SHA 固定契約。

        未提供受審核的 Medusa 來源時，舊 Synthetic／原生拒絕路徑保持可用，
        但 M-02／M-07 原生 200 一律 fail closed；不從 Runtime 下載規格。
        """
        super().__init__(dsn, expected_login=expected_login)
        self._medusa_specification = None
        if medusa_source is not None:
            from deception.domains.ecommerce.medusa_cart_projection import load_contract

            if not isinstance(medusa_source, Path):
                raise ProtectedGrantError("protected_medusa_source_path_invalid")
            self._medusa_specification = load_contract(medusa_source)[1]

    def project_cart_creation(self, receipt_id: UUID) -> ProtectedNativeProjection:
        """以獨立唯讀證據建立 C-01 200：授權 Scope 保持原始 Creator。"""
        from jsonschema import Draft202012Validator
        from deception.domains.ecommerce.cart_http import cart_specification

        if not isinstance(receipt_id, UUID) or receipt_id.version != 4:
            raise ProtectedGrantError("protected_cart_creation_receipt_invalid")
        with self._connection() as connection:
            with connection.cursor() as cursor:
                scope, fingerprint, source, payload = _verified_cart_creation(cursor, receipt_id)
        schema = cart_specification()["paths"]["/carts"]["post"]["responses"]["200"][
            "content"]["application/json"]["schema"]
        if not Draft202012Validator(schema).is_valid(payload):
            raise ProtectedGrantError("protected_cart_creation_contract_invalid")
        headers = (("content-type", "application/json"),)
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")
        return ProtectedNativeProjection(
            receipt_id=receipt_id, scope=scope, operation_id="createGuestCart",
            request_fingerprint=fingerprint, status_code=200, headers=headers,
            body_bytes=body, envelope_hash=response_hashes(200, headers, body)[0],
            source=source,
        )

    def project_medusa_creation(self, receipt_id: UUID) -> ProtectedNativeProjection:
        """M-01：唯讀 Validator 只從固定 Creator Lineage 重建原生空 Cart 200 候選。"""
        if self._medusa_specification is None:
            raise ProtectedGrantError("protected_medusa_creation_contract_not_configured")
        if not isinstance(receipt_id, UUID) or receipt_id.version != 4:
            raise ProtectedGrantError("protected_medusa_creation_receipt_invalid")
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT4
        from openapi_schema_validator import OAS30Validator

        with self._connection() as connection:
            with connection.cursor() as cursor:
                scope, fingerprint, source, payload = _verified_cart_creation(
                    cursor, receipt_id, medusa=True,
                )
        registry = Registry().with_resource(
            "urn:mirage:medusa-contract", Resource.from_contents(
                self._medusa_specification, default_specification=DRAFT4,
            ),
        )
        schema = {"$ref": "urn:mirage:medusa-contract#/components/schemas/StoreCartResponse"}
        if not OAS30Validator(schema, registry=registry).is_valid(payload):
            raise ProtectedGrantError("protected_medusa_creation_contract_invalid")
        headers = (("content-type", "application/json"),)
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")
        return ProtectedNativeProjection(
            receipt_id=receipt_id, scope=scope, operation_id="PostCarts",
            request_fingerprint=fingerprint, status_code=200, headers=headers,
            body_bytes=body, envelope_hash=response_hashes(200, headers, body)[0],
            source=source,
        )

    def project_cart_read(self, receipt_id: UUID) -> ProtectedNativeProjection:
        """由獨立唯讀證據重建 C-02／C-07／C-09 的 Cart／Order／Operation 200 候選。

        只接受真 GET Proof、同一 Receipt 的 ReadAdmission、未到期的派生資源
        與已驗 Hash 的當前快照；找不到資源、版本漂移或任何 ACL 不明時
        拒絕產生候選，絕不將無法查證的 409 當成合法業務拒絕。
        """
        return self._project_cart_read(receipt_id, medusa=False)

    def project_medusa_read(self, receipt_id: UUID) -> ProtectedNativeProjection:
        """M-02／M-07：從同一 Read Source 建立經固定 Medusa 契約驗證的 200 候選。

        只接受唯讀 Connector 取得的 Snapshot、真原始 GET Proof、派生資源與
        獨立 Validator 的 SHA 固定 OpenAPI；不降級至 Synthetic JSON 或 409。
        """
        if self._medusa_specification is None:
            raise ProtectedGrantError("protected_medusa_read_contract_not_configured")
        return self._project_cart_read(receipt_id, medusa=True)

    def _project_cart_read(self, receipt_id: UUID, *, medusa: bool) -> ProtectedNativeProjection:
        """共用 Cart/Order 可信來源、Scope／Key／Epoch／Head 檢查，分離原生格式。"""
        from jsonschema import Draft202012Validator

        from deception.domains.ecommerce.cart_http import cart_specification
        from deception.domains.ecommerce.carts import SyntheticCarts

        if not isinstance(receipt_id, UUID) or receipt_id.version != 4:
            raise ProtectedGrantError("protected_cart_read_receipt_invalid")
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET LOCAL statement_timeout='5s'")
                cursor.execute(
                    """SELECT r.environment_id,r.deployment_id,r.session_id,r.session_epoch,
                              r.request_fingerprint,r.issuer,r.key_id,r.token_expires_at,
                              r.access_mode,r.resource_id,
                              p.read_admission_id,p.world_generation_id,p.state_version,p.state_hash,
                              a.request_binding_digest,a.state_version,a.state_hash,a.expires_at,
                              a.environment_id,a.deployment_id,a.session_id,a.world_generation_id
                       FROM ingress_receipts r
                       JOIN protected_world_read_sources p ON p.receipt_id=r.receipt_id
                         AND (p.environment_id,p.deployment_id,p.session_id)
                             =(r.environment_id,r.deployment_id,r.session_id)
                       JOIN read_admissions a ON a.read_admission_id=p.read_admission_id
                         AND (a.environment_id,a.deployment_id,a.session_id,a.world_generation_id)
                             =(p.environment_id,p.deployment_id,p.session_id,p.world_generation_id)
                       WHERE r.receipt_id=%s""", (receipt_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    raise ProtectedGrantError("protected_cart_read_source_missing")
                (environment, deployment, session, epoch, fingerprint, issuer, key_id,
                 token_deadline, mode, resource, read_id, generation, version, state_hash,
                 binding_digest, admission_version, admission_hash, read_deadline,
                 read_environment, read_deployment, read_session, read_generation) = row
                if (mode != "cart" or not isinstance(resource, str)
                        or re.fullmatch(r"(?:cart|order)_[0-9a-f]{32}", resource) is None
                        or fingerprint != binding_digest
                        or (version, state_hash) != (admission_version, admission_hash)
                        or (environment, deployment, session, generation) != (
                            read_environment, read_deployment, read_session, read_generation)):
                    raise ProtectedGrantError("protected_cart_read_source_mismatch")
                cursor.execute(
                    """SELECT platform,operation_id,method,path_template,request_fingerprint,
                              request_path,request_body_sha256
                       FROM protected_http_operation_bindings WHERE receipt_id=%s""",
                    (receipt_id,),
                )
                proof = cursor.fetchone()
                choices = ({
                    "GetCartsId": ("/store/carts/{id}", "/store/carts/", "cart"),
                    "GetOrdersId": ("/store/orders/{id}", "/store/orders/", "order"),
                } if medusa else {
                    "getGuestCart": ("/synthetic/carts/{cart_id}", "/synthetic/carts/", "cart"),
                    "getSyntheticOrder": ("/synthetic/orders/{order_id}", "/synthetic/orders/", "order"),
                    "getCartOperation": ("/synthetic/carts/{cart_id}/operations/{attempt}",
                                         "/synthetic/carts/", "cart"),
                })
                selected = choices.get(proof[1]) if proof is not None else None
                attempt = None
                if selected is not None and proof[1] == "getCartOperation":
                    path_match = re.fullmatch(
                        re.escape(selected[1] + resource) + r"/operations/([0-9a-f-]{36})",
                        proof[5],
                    ) if isinstance(proof[5], str) else None
                    if path_match is not None:
                        try:
                            attempt = UUID(path_match[1])
                        except ValueError:
                            attempt = None
                    path_matches = (attempt is not None and attempt.version == 4
                                    and str(attempt) == path_match[1])
                else:
                    path_matches = selected is not None and proof[5] == selected[1] + resource
                if (selected is None or proof[:3] != (
                        "medusa-native-cart" if medusa else "synthetic-carts", proof[1], "GET")
                        or proof[3:5] != (selected[0], fingerprint)
                        or not path_matches
                        or not resource.startswith(selected[2] + "_")
                        or proof[6] != hashlib.sha256(b"").hexdigest()):
                    raise ProtectedGrantError("protected_cart_read_proof_mismatch")
                cursor.execute(
                    """SELECT world_generation_id,expires_at FROM synthetic_resources
                       WHERE resource_id=%s AND environment_id=%s AND deployment_id=%s
                         AND session_id=%s AND session_epoch=%s""",
                    (resource, environment, deployment, session, epoch),
                )
                resource_row = cursor.fetchone()
                if resource_row is None or resource_row[0] != generation:
                    raise ProtectedGrantError("protected_cart_read_lineage_mismatch")
                cursor.execute(
                    """SELECT version,state_hash,state,expires_at FROM world_snapshots
                       WHERE environment_id=%s AND deployment_id=%s AND session_id=%s
                         AND world_generation_id=%s""",
                    (environment, deployment, session, generation),
                )
                snapshot_row = cursor.fetchone()
                if snapshot_row is None:
                    raise ProtectedGrantError("protected_cart_read_snapshot_missing")
                scope = WorldScope(environment_id=environment, deployment_id=deployment,
                                   session_id=session, world_generation_id=generation)
                try:
                    snapshot = WorldSnapshot(scope=scope, version=snapshot_row[0],
                                             state_hash=snapshot_row[1], state=snapshot_row[2],
                                             expires_at=snapshot_row[3])
                except ValueError as exc:
                    raise ProtectedGrantError("protected_cart_read_snapshot_invalid") from exc
                if snapshot.version != version or snapshot.state_hash != state_hash:
                    raise ProtectedGrantError("protected_cart_read_snapshot_stale")
                if proof[1] in {"getGuestCart", "getCartOperation", "GetCartsId"}:
                    saved_cart = snapshot.state.get("cart")
                    if (not isinstance(saved_cart, dict) or saved_cart.get("id") != resource
                            or set(saved_cart) != {"id", "items", "currency_code", "total", "status"}
                            or not isinstance(saved_cart.get("items"), dict)):
                        raise ProtectedGrantError("protected_cart_read_entity_invalid")
                    entity = SyntheticCarts.public_cart(saved_cart)
                    kind = "cart"
                    path = "/carts/{cart_id}"
                else:
                    orders = snapshot.state.get("orders")
                    entity = orders.get(resource) if isinstance(orders, dict) else None
                    if not isinstance(entity, dict) or entity.get("id") != resource:
                        raise ProtectedGrantError("protected_cart_read_entity_missing")
                    kind = "order"
                    path = "/orders/{order_id}"
                missing_operation = False
                if proof[1] == "getCartOperation":
                    # 歷史操作不得由 Client 提交結果；三份獨立持久來源必須指向同世代成功 Commit。
                    cursor.execute(
                        """SELECT operation,status,result,state_version,state_hash,
                                  result_encoding_version,result_digest
                           FROM world_operations WHERE environment_id=%s AND deployment_id=%s
                             AND session_id=%s AND world_generation_id=%s AND commit_attempt_id=%s""",
                        (environment, deployment, session, generation, attempt),
                    )
                    stored = cursor.fetchone()
                    missing_operation = stored is None
                    if not missing_operation:
                        action, status, committed_result, committed_version, committed_hash, encoding, digest = stored
                        if (action not in {"cart.add", "cart.update", "cart.remove", "cart.complete",
                                           "cart.cancel_order"} or status != "committed"
                                or encoding != 1 or not isinstance(committed_result, dict)
                                or type(committed_version) is not int or committed_version < 1
                                or not isinstance(committed_hash, str)
                                or re.fullmatch(r"[0-9a-f]{64}", committed_hash) is None
                                or operation_result_digest(committed_result, committed_version,
                                                           committed_hash, attempt, status) != digest):
                            raise ProtectedGrantError("protected_cart_operation_unverifiable")
                        cursor.execute(
                            """SELECT c.result_digest,c.state_version,c.state_hash
                               FROM protected_world_commit_sources c
                               WHERE c.commit_attempt_id=%s AND c.environment_id=%s
                                 AND c.deployment_id=%s AND c.session_id=%s
                                 AND c.world_generation_id=%s AND c.operation=%s""",
                            (attempt, environment, deployment, session, generation, action),
                        )
                        if cursor.fetchone() != (digest, committed_version, committed_hash):
                            raise ProtectedGrantError("protected_cart_operation_source_mismatch")
                        cursor.execute(
                            """SELECT state_version,state_hash FROM world_commit_receipts
                               WHERE environment_id=%s AND deployment_id=%s AND session_id=%s
                                 AND world_generation_id=%s AND commit_attempt_id=%s""",
                            (environment, deployment, session, generation, attempt),
                        )
                        if cursor.fetchone() != (committed_version, committed_hash):
                            raise ProtectedGrantError("protected_cart_operation_receipt_mismatch")
                        if (not isinstance(committed_result.get("id"), str)
                                or re.fullmatch(r"(?:cart|order)_[0-9a-f]{32}",
                                                committed_result["id"]) is None):
                            raise ProtectedGrantError("protected_cart_operation_entity_invalid")
                        kind = "order" if committed_result["id"].startswith("order_") else "cart"
                        if committed_version > version:
                            raise ProtectedGrantError("protected_cart_operation_future_version")
                        if kind == "cart":
                            if committed_result["id"] != resource:
                                raise ProtectedGrantError("protected_cart_operation_resource_mismatch")
                            if isinstance(committed_result.get("items"), dict):
                                historical_entity = SyntheticCarts.public_cart(committed_result)
                            elif isinstance(committed_result.get("items"), list):
                                historical_entity = committed_result
                            else:
                                raise ProtectedGrantError("protected_cart_operation_items_invalid")
                        else:
                            if committed_result.get("cart_id") != resource:
                                raise ProtectedGrantError("protected_cart_operation_order_lineage_mismatch")
                            historical_entity = committed_result
                        payload = {kind: historical_entity, "state_version": committed_version,
                                   "state_hash": committed_hash, "commit_attempt_id": str(attempt)}
                        path = "/carts/{cart_id}/operations/{attempt}"
                    if missing_operation:
                        # 只有同世代、已驗證 ReadAdmission 下確定查無 UUID4 才有 409。
                        payload = {"code": "operation_not_found"}
                        path = "/carts/{cart_id}/operations/{attempt}"
                elif not medusa:
                    payload = {kind: entity, "state_version": version,
                               "state_hash": state_hash, "commit_attempt_id": None}
                if medusa:
                    from referencing import Registry, Resource
                    from referencing.jsonschema import DRAFT4
                    from openapi_schema_validator import OAS30Validator
                    from deception.domains.ecommerce.medusa_cart_projection import cart_view, order_view

                    context = snapshot.state.get("native_context")
                    catalog = snapshot.state.get("catalog")
                    if (not isinstance(context, dict) or not isinstance(catalog, dict)):
                        raise ProtectedGrantError("protected_medusa_read_context_missing")
                    try:
                        context = {**context, "catalog": catalog}
                        payload = ({"cart": cart_view(entity, context)} if kind == "cart"
                                   else {"order": order_view(entity, context)})
                    except (ValueError, KeyError, TypeError, OverflowError) as exc:
                        raise ProtectedGrantError("protected_medusa_read_projection_invalid") from exc
                    registry = Registry().with_resource(
                        "urn:mirage:medusa-contract", Resource.from_contents(
                            self._medusa_specification, default_specification=DRAFT4,
                        ),
                    )
                    schema_name = "StoreCartResponse" if kind == "cart" else "StoreOrderResponse"
                    schema = {"$ref": "urn:mirage:medusa-contract#/components/schemas/" + schema_name}
                    if not OAS30Validator(schema, registry=registry).is_valid(payload):
                        raise ProtectedGrantError("protected_medusa_read_contract_invalid")
                else:
                    native_status = 409 if missing_operation else 200
                    schema = cart_specification()["paths"][path]["get"]["responses"][
                        str(native_status)]["content"]["application/json"]["schema"]
                    if not Draft202012Validator(schema).is_valid(payload):
                        raise ProtectedGrantError("protected_cart_read_contract_invalid")
                native_status = 200 if medusa else 409 if missing_operation else 200
                cursor.execute("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                now = cursor.fetchone()[0]
                if (token_deadline <= now or read_deadline <= now or resource_row[1] <= now
                        or snapshot.expires_at is not None and snapshot.expires_at <= now):
                    raise ProtectedGrantError("protected_cart_read_source_expired")
                cursor.execute(
                    """SELECT session_epoch FROM session_heads WHERE environment_id=%s
                       AND deployment_id=%s AND session_id=%s""",
                    (environment, deployment, session),
                )
                if cursor.fetchone() != (epoch,):
                    raise ProtectedGrantError("protected_cart_read_epoch_stale")
                cursor.execute(
                    """SELECT world_generation_id FROM session_world_bindings
                       WHERE environment_id=%s AND deployment_id=%s AND session_id=%s
                         AND session_epoch=%s""",
                    (environment, deployment, session, epoch),
                )
                if cursor.fetchone() != (generation,):
                    raise ProtectedGrantError("protected_cart_read_generation_mismatch")
                cursor.execute(
                    """SELECT sealed,emergency_revision FROM generation_controls
                       WHERE world_generation_id=%s""", (generation,),
                )
                if cursor.fetchone() != (False, None):
                    raise ProtectedGrantError("protected_cart_read_generation_revoked")
                guard = PostgresTrustedKeyRevocations(
                    self._dsn, environment_id=environment, deployment_id=deployment,
                )
                guard._lock(cursor, issuer, key_id)
                if guard._select(cursor, issuer, key_id) is not None:
                    raise ProtectedGrantError("protected_cart_read_key_revoked")
        headers = (("content-type", "application/json"),)
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")
        return ProtectedNativeProjection(
            receipt_id=receipt_id, scope=scope, operation_id=proof[1],
            request_fingerprint=fingerprint, status_code=native_status, headers=headers,
            body_bytes=body, envelope_hash=response_hashes(native_status, headers, body)[0],
            source=SnapshotSource(read_admission_id=read_id, world_generation_id=generation,
                                  state_version=version, state_hash=state_hash),
        )

    def project_inventory_operation(self, receipt_id: UUID) -> ProtectedNativeProjection:
        """由原始 GET 與受保護 ReadAdmission 重建 I-03 真 200 或確定缺操作的 409。

        200 需要同世代 committed WorldOperation／真 Commit Receipt；
        409 只能由查不到該 UUID4 的歷史操作、當前有效快照及唯讀來源推得。
        rejected 或不完整 Commit 一律固定拒絕，不能偷換成 operation_not_found。
        此方法沒有任何對外傳輸／Send Lease 權。
        """
        if not isinstance(receipt_id, UUID) or receipt_id.version != 4:
            raise ProtectedGrantError("protected_inventory_operation_receipt_invalid")
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET LOCAL statement_timeout='5s'")
                cursor.execute(
                    """SELECT r.environment_id,r.deployment_id,r.session_id,r.session_epoch,
                              r.request_fingerprint,r.issuer,r.key_id,r.token_expires_at,
                              r.access_mode,r.resource_id,
                              p.read_admission_id,p.world_generation_id,p.state_version,p.state_hash,
                              a.request_binding_digest,a.state_version,a.state_hash,a.expires_at,
                              a.environment_id,a.deployment_id,a.session_id,a.world_generation_id
                       FROM ingress_receipts r
                       JOIN protected_world_read_sources p ON p.receipt_id=r.receipt_id
                         AND (p.environment_id,p.deployment_id,p.session_id)
                             =(r.environment_id,r.deployment_id,r.session_id)
                       JOIN read_admissions a ON a.read_admission_id=p.read_admission_id
                         AND (a.environment_id,a.deployment_id,a.session_id,a.world_generation_id)
                             =(p.environment_id,p.deployment_id,p.session_id,p.world_generation_id)
                       WHERE r.receipt_id=%s""", (receipt_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    raise ProtectedGrantError("protected_inventory_operation_read_source_missing")
                (environment, deployment, session, epoch, fingerprint, issuer, key_id,
                 token_deadline, mode, resource_id, read_id, generation, version, state_hash,
                 binding_digest, admission_version, admission_hash, read_deadline,
                 read_environment, read_deployment, read_session, read_generation) = row
                if (mode != "inventory" or resource_id is not None
                        or fingerprint != binding_digest
                        or (version, state_hash) != (admission_version, admission_hash)
                        or (environment, deployment, session, generation) != (
                            read_environment, read_deployment, read_session, read_generation)):
                    raise ProtectedGrantError("protected_inventory_operation_read_source_mismatch")
                cursor.execute(
                    """SELECT platform,operation_id,method,path_template,request_fingerprint,
                              request_path,request_body_sha256
                       FROM protected_http_operation_bindings WHERE receipt_id=%s""",
                    (receipt_id,),
                )
                proof = cursor.fetchone()
                matched = re.fullmatch(r"/synthetic/operations/([0-9a-f-]{36})", proof[5]) if (
                    proof is not None and isinstance(proof[5], str)) else None
                if (proof is None or proof[:5] != (
                        "synthetic-inventory", "getSyntheticOperation", "GET",
                        "/synthetic/operations/{attempt}", fingerprint)
                        or matched is None or proof[6] != hashlib.sha256(b"").hexdigest()):
                    raise ProtectedGrantError("protected_inventory_operation_proof_mismatch")
                try:
                    attempt = UUID(matched[1])
                except ValueError as exc:
                    raise ProtectedGrantError("protected_inventory_operation_attempt_invalid") from exc
                if attempt.version != 4 or str(attempt) != matched[1]:
                    raise ProtectedGrantError("protected_inventory_operation_attempt_invalid")
                scope = WorldScope(environment_id=environment, deployment_id=deployment,
                                   session_id=session, world_generation_id=generation)
                cursor.execute(
                    """SELECT version,state_hash,state,expires_at FROM world_snapshots
                       WHERE environment_id=%s AND deployment_id=%s AND session_id=%s
                         AND world_generation_id=%s""",
                    (environment, deployment, session, generation),
                )
                snapshot_row = cursor.fetchone()
                if snapshot_row is None:
                    raise ProtectedGrantError("protected_inventory_operation_snapshot_missing")
                try:
                    snapshot = WorldSnapshot(scope=scope, version=snapshot_row[0],
                                             state_hash=snapshot_row[1], state=snapshot_row[2],
                                             expires_at=snapshot_row[3])
                except ValueError as exc:
                    raise ProtectedGrantError("protected_inventory_operation_snapshot_invalid") from exc
                if snapshot.version != version or snapshot.state_hash != state_hash:
                    raise ProtectedGrantError("protected_inventory_operation_snapshot_stale")
                cursor.execute(
                    """SELECT operation,status,result,state_version,state_hash,
                              result_encoding_version,result_digest
                       FROM world_operations WHERE environment_id=%s AND deployment_id=%s
                         AND session_id=%s AND world_generation_id=%s AND commit_attempt_id=%s""",
                    (environment, deployment, session, generation, attempt),
                )
                operation = cursor.fetchone()
                missing_operation = operation is None
                if not missing_operation:
                    action, status, result, result_version, result_hash, encoding, digest = operation
                if not missing_operation and (action not in {"reserve", "cancel"} or status != "committed"
                        or encoding != 1 or not isinstance(result, dict)
                        or set(result) != {"reservation_id", "sku", "quantity", "status"}
                        or not isinstance(result["reservation_id"], str)
                        or re.fullmatch(r"[0-9a-f]{32}", result["reservation_id"]) is None
                        or not isinstance(result["sku"], str)
                        or not 1 <= len(result["sku"]) <= 128
                        or type(result["quantity"]) is not int or result["quantity"] < 1
                        or result["status"] != ("reserved" if action == "reserve" else "cancelled")
                        or type(result_version) is not int or result_version < 1
                        or not isinstance(result_hash, str)
                        or re.fullmatch(r"[0-9a-f]{64}", result_hash) is None
                        or operation_result_digest(result, result_version, result_hash, attempt, status)
                        != digest):
                    raise ProtectedGrantError("protected_inventory_operation_result_unverifiable")
                if not missing_operation:
                    cursor.execute(
                        """SELECT state_version,state_hash FROM world_commit_receipts
                           WHERE environment_id=%s AND deployment_id=%s AND session_id=%s
                             AND world_generation_id=%s AND commit_attempt_id=%s""",
                        (environment, deployment, session, generation, attempt),
                    )
                    if cursor.fetchone() != (result_version, result_hash):
                        raise ProtectedGrantError("protected_inventory_operation_commit_receipt_mismatch")
                cursor.execute("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                now = cursor.fetchone()[0]
                if (token_deadline <= now or read_deadline <= now
                        or snapshot.expires_at is not None and snapshot.expires_at <= now):
                    raise ProtectedGrantError("protected_inventory_operation_source_expired")
                cursor.execute(
                    """SELECT session_epoch FROM session_heads WHERE environment_id=%s
                       AND deployment_id=%s AND session_id=%s""",
                    (environment, deployment, session),
                )
                if cursor.fetchone() != (epoch,):
                    raise ProtectedGrantError("protected_inventory_operation_epoch_stale")
                cursor.execute(
                    """SELECT world_generation_id FROM session_world_bindings
                       WHERE environment_id=%s AND deployment_id=%s AND session_id=%s
                         AND session_epoch=%s""",
                    (environment, deployment, session, epoch),
                )
                if cursor.fetchone() != (generation,):
                    raise ProtectedGrantError("protected_inventory_operation_generation_mismatch")
                cursor.execute(
                    """SELECT sealed,emergency_revision FROM generation_controls
                       WHERE world_generation_id=%s""", (generation,),
                )
                if cursor.fetchone() != (False, None):
                    raise ProtectedGrantError("protected_inventory_operation_generation_revoked")
                key_guard = PostgresTrustedKeyRevocations(
                    self._dsn, environment_id=environment, deployment_id=deployment,
                )
                key_guard._lock(cursor, issuer, key_id)
                if key_guard._select(cursor, issuer, key_id) is not None:
                    raise ProtectedGrantError("protected_inventory_operation_key_revoked")
        native_status = 409 if missing_operation else 200
        if missing_operation:
            headers, body = fixed_synthetic_rejection_bytes("synthetic-inventory", "operation_not_found")
        else:
            headers = (("content-type", "application/json"),)
            body = json.dumps({
                "commit_attempt_id": str(attempt), "state_version": result_version,
                "state_hash": result_hash, "reservation": result,
            }, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return ProtectedNativeProjection(
            receipt_id=receipt_id, scope=scope, operation_id="getSyntheticOperation",
            request_fingerprint=fingerprint, status_code=native_status, headers=headers,
            body_bytes=body, envelope_hash=response_hashes(native_status, headers, body)[0],
            source=SnapshotSource(read_admission_id=read_id, world_generation_id=generation,
                                  state_version=version, state_hash=state_hash),
        )

    def project_inventory_snapshot(self, receipt_id: UUID) -> ProtectedNativeProjection:
        """以獨立唯讀 Login 重建 I-04 Snapshot 的 200 或已證明缺 SKU 的 409。

        只接受固定 GET SKU 與空 Body；真正缺少 SKU 時輸出固定業務 409，
        但版本已移動、快照損壞、簽章過期或 Epoch／Generation／Key 改變，
        一律直接拒絕，不能將安全故障包裝成業務 409。
        此函式沒有 Send 權，快照到實際傳輸的競態仍須由 G4/G5 關閉。
        """
        from deception.security.operation_binding import (
            OperationBindingError, decode_verified_inventory_sku_path,
        )

        if not isinstance(receipt_id, UUID) or receipt_id.version != 4:
            raise ProtectedGrantError("protected_inventory_receipt_invalid")
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET LOCAL statement_timeout='5s'")
                cursor.execute(
                    """SELECT r.environment_id,r.deployment_id,r.session_id,r.session_epoch,
                              r.request_fingerprint,r.issuer,r.key_id,r.token_expires_at,
                              r.access_mode,r.resource_id,
                              p.read_admission_id,p.world_generation_id,p.state_version,p.state_hash,
                              a.request_binding_digest,a.state_version,a.state_hash,a.expires_at,
                              a.environment_id,a.deployment_id,a.session_id,a.world_generation_id
                       FROM ingress_receipts r
                       JOIN protected_world_read_sources p ON p.receipt_id=r.receipt_id
                         AND (p.environment_id,p.deployment_id,p.session_id)
                             =(r.environment_id,r.deployment_id,r.session_id)
                       JOIN read_admissions a ON a.read_admission_id=p.read_admission_id
                         AND (a.environment_id,a.deployment_id,a.session_id,a.world_generation_id)
                             =(p.environment_id,p.deployment_id,p.session_id,p.world_generation_id)
                       WHERE r.receipt_id=%s""", (receipt_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    raise ProtectedGrantError("protected_inventory_read_source_missing")
                (environment, deployment, session, epoch, fingerprint, issuer, key_id,
                 token_deadline, mode, resource_id, read_id, generation, version, state_hash,
                 binding_digest, admission_version, admission_hash, read_deadline,
                 read_environment, read_deployment, read_session, read_generation) = row
                if (mode != "inventory" or resource_id is not None
                        or fingerprint != binding_digest
                        or (version, state_hash) != (admission_version, admission_hash)
                        or (environment, deployment, session, generation) != (
                            read_environment, read_deployment, read_session, read_generation)):
                    raise ProtectedGrantError("protected_inventory_read_source_mismatch")
                cursor.execute(
                    """SELECT platform,operation_id,method,path_template,request_fingerprint,
                              request_path,request_body_sha256,request_content_type
                       FROM protected_http_operation_bindings WHERE receipt_id=%s""", (receipt_id,),
                )
                proof = cursor.fetchone()
                if proof is None or not isinstance(proof[5], str):
                    raise ProtectedGrantError("protected_inventory_operation_missing")
                try:
                    sku = decode_verified_inventory_sku_path(proof[5].encode("utf-8"))
                except (OperationBindingError, UnicodeError) as exc:
                    raise ProtectedGrantError("protected_inventory_operation_mismatch") from exc
                # GET 的原始 Content-Type 可以不存在，也可能由既有 Client 設定；
                # 只要仍為空 Body 且原始 Proof/Fingerprint 已驗證，不能誤拒合法查詢。
                if (proof[:5] != ("synthetic-inventory", "getSyntheticInventory", "GET",
                                   "/synthetic/inventory/{sku}", fingerprint)
                        or proof[6] != hashlib.sha256(b"").hexdigest()):
                    raise ProtectedGrantError("protected_inventory_operation_mismatch")
                cursor.execute(
                    """SELECT version,state_hash,state,expires_at FROM world_snapshots
                       WHERE environment_id=%s AND deployment_id=%s AND session_id=%s
                         AND world_generation_id=%s""",
                    (environment, deployment, session, generation),
                )
                snapshot_row = cursor.fetchone()
                if snapshot_row is None:
                    raise ProtectedGrantError("protected_inventory_snapshot_missing")
                scope = WorldScope(environment_id=environment, deployment_id=deployment,
                                   session_id=session, world_generation_id=generation)
                try:
                    snapshot = WorldSnapshot(
                        scope=scope, version=snapshot_row[0], state_hash=snapshot_row[1],
                        state=snapshot_row[2], expires_at=snapshot_row[3],
                    )
                except ValueError as exc:
                    raise ProtectedGrantError("protected_inventory_snapshot_invalid") from exc
                stock = snapshot.state.get("inventory")
                if (snapshot.version != version or snapshot.state_hash != state_hash
                        or not isinstance(stock, dict)
                        or any(not isinstance(item, str) or type(quantity) is not int
                               or quantity < 0 for item, quantity in stock.items())):
                    raise ProtectedGrantError("protected_inventory_snapshot_not_projectable")
                available = stock.get(sku)
                if sku in stock and (type(available) is not int or available < 0):
                    raise ProtectedGrantError("protected_inventory_snapshot_not_projectable")
                cursor.execute("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                now = cursor.fetchone()[0]
                if (token_deadline <= now or read_deadline <= now
                        or snapshot.expires_at is not None and snapshot.expires_at <= now):
                    raise ProtectedGrantError("protected_inventory_source_expired")
                cursor.execute(
                    """SELECT session_epoch FROM session_heads WHERE environment_id=%s
                       AND deployment_id=%s AND session_id=%s""",
                    (environment, deployment, session),
                )
                if cursor.fetchone() != (epoch,):
                    raise ProtectedGrantError("protected_inventory_epoch_stale")
                cursor.execute(
                    """SELECT world_generation_id FROM session_world_bindings
                       WHERE environment_id=%s AND deployment_id=%s AND session_id=%s
                         AND session_epoch=%s""",
                    (environment, deployment, session, epoch),
                )
                if cursor.fetchone() != (generation,):
                    raise ProtectedGrantError("protected_inventory_generation_mismatch")
                cursor.execute(
                    "SELECT sealed,emergency_revision FROM generation_controls WHERE world_generation_id=%s",
                    (generation,),
                )
                if cursor.fetchone() != (False, None):
                    raise ProtectedGrantError("protected_inventory_generation_revoked")
                key_guard = PostgresTrustedKeyRevocations(
                    self._dsn, environment_id=environment, deployment_id=deployment,
                )
                key_guard._lock(cursor, issuer, key_id)
                if key_guard._select(cursor, issuer, key_id) is not None:
                    raise ProtectedGrantError("protected_inventory_key_revoked")
        status = 200 if sku in stock else 409
        if status == 200:
            headers = (("content-type", "application/json"),)
            body = json.dumps({"sku": sku, "available": available, "state_version": version},
                              ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        else:
            headers, body = fixed_synthetic_rejection_bytes(
                "synthetic-inventory", "unknown_synthetic_sku")
        return ProtectedNativeProjection(
            receipt_id=receipt_id, scope=scope, operation_id="getSyntheticInventory",
            request_fingerprint=fingerprint, status_code=status, headers=headers,
            body_bytes=body, envelope_hash=response_hashes(status, headers, body)[0],
            source=SnapshotSource(read_admission_id=read_id, world_generation_id=generation,
                                  state_version=version, state_hash=state_hash),
        )

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

    def project_synthetic_success(self, receipt_id: UUID) -> ProtectedNativeProjection:
        """以唯讀 Login 核對同 Receipt 成功 Commit、原始 HTTP 與目前 World，再重建固定 200 候選。

        此方法只讀取可信 Executor 同一交易寫出的 Protected Commit Source，
        對照已提交業務結果、Commit Receipt、ReadAdmission、Epoch、Key，
        並驗證合成 OpenAPI。世界移動、來源缺失或操作不符時一律失敗；
        不回傳已授權 Send，也不以未知 COMMIT 猜測成功。
        """
        return self._project_mutation_success(receipt_id, medusa=False)

    def project_medusa_add_success(self, receipt_id: UUID) -> ProtectedNativeProjection:
        """M-03 唯讀重建原生 Cart 200，必須有真 Commit 與同次固定 Native Context。"""
        if self._medusa_specification is None:
            raise ProtectedGrantError("protected_medusa_add_contract_not_configured")
        return self._project_mutation_success(receipt_id, medusa=True)

    def _project_mutation_success(
        self, receipt_id: UUID, *, medusa: bool,
    ) -> ProtectedNativeProjection:
        """共用不可變 Commit／Read／Epoch／Key 查核，按固定路由分別驗原生契約。"""
        from jsonschema import Draft202012Validator
        from deception.domains.ecommerce.cart_http import cart_specification
        from deception.domains.ecommerce.inventory_http import inventory_specification

        if not isinstance(receipt_id, UUID) or receipt_id.version != 4:
            raise ProtectedGrantError("protected_synthetic_success_receipt_invalid")
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET LOCAL statement_timeout='5s'")
                cursor.execute(
                    """SELECT c.environment_id,c.deployment_id,c.session_id,c.world_generation_id,
                              c.request_fingerprint,c.operation,c.commit_attempt_id,c.result_digest,
                              c.state_version,c.state_hash,
                              o.status,o.operation,o.result,o.state_version,o.state_hash,
                              o.result_encoding_version,o.result_digest,
                              r.session_epoch,r.issuer,r.key_id,r.token_expires_at,
                              r.access_mode,r.resource_id,
                              p.operation_id,p.platform,p.method,p.path_template,
                              p.request_path,p.request_content_type,p.request_fingerprint
                       FROM protected_world_commit_sources c
                       JOIN world_operations o ON o.commit_attempt_id=c.commit_attempt_id
                         AND (o.environment_id,o.deployment_id,o.session_id,o.world_generation_id)
                             =(c.environment_id,c.deployment_id,c.session_id,c.world_generation_id)
                       JOIN ingress_receipts r ON r.receipt_id=c.receipt_id
                         AND (r.environment_id,r.deployment_id,r.session_id)
                             =(c.environment_id,c.deployment_id,c.session_id)
                       JOIN protected_http_operation_bindings p ON p.receipt_id=c.receipt_id
                       WHERE c.receipt_id=%s""", (receipt_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    raise ProtectedGrantError("protected_synthetic_success_source_missing")
                (environment, deployment, session, generation, fingerprint, action, attempt,
                 saved_digest, saved_version, saved_hash, status, actual_action, result,
                 actual_version, actual_hash, encoding, actual_digest, epoch, issuer,
                 key_id, token_deadline, mode, resource, operation_id, platform, method,
                 template, raw_path, content_type, proof_fingerprint) = row
                medusa_handlers = {
                    "PostCartsIdLineItems": (
                        "medusa-native-cart", "POST", "/store/carts/{id}/line-items", "cart.add",
                        r"/store/carts/(cart_[0-9a-f]{32})/line-items",
                    ),
                    "PostCartsIdLineItemsLine_id": (
                        "medusa-native-cart", "POST", "/store/carts/{id}/line-items/{line_id}",
                        "cart.update",
                        r"/store/carts/(cart_[0-9a-f]{32})/line-items/item_[0-9a-f]{32}",
                    ),
                    "DeleteCartsIdLineItemsLine_id": (
                        "medusa-native-cart", "DELETE", "/store/carts/{id}/line-items/{line_id}",
                        "cart.remove",
                        r"/store/carts/(cart_[0-9a-f]{32})/line-items/(item_[0-9a-f]{32})",
                    ),
                }
                medusa_handler = medusa_handlers.get(operation_id) if medusa else None
                selected = (_SYNTHETIC_MUTATION_HANDLERS.get(operation_id) if not medusa else
                            medusa_handler[:4] if medusa_handler is not None else None)
                path_pattern = (_SYNTHETIC_MUTATION_PATHS.get(operation_id) if not medusa else
                                medusa_handler[4] if medusa_handler is not None else None)
                match = re.fullmatch(path_pattern, raw_path) if (
                    path_pattern is not None and isinstance(raw_path, str)) else None
                if (selected is None or match is None
                        or (platform, method, template, action) != selected
                        or fingerprint != proof_fingerprint
                        or (status, actual_action, encoding) != ("committed", action, 1)
                        or (saved_version, saved_hash, saved_digest)
                            != (actual_version, actual_hash, actual_digest)
                        or not isinstance(result, dict)
                        or operation_result_digest(result, actual_version, actual_hash, attempt, status)
                            != saved_digest
                        or not isinstance(content_type, str)
                        or content_type.split(";", 1)[0].strip().lower() != "application/json"
                        or (platform == "synthetic-inventory" and (mode, resource) != ("inventory", None))
                        or (platform in {"synthetic-carts", "medusa-native-cart"} and (
                            mode != "cart" or not resource or match[1] != resource))):
                    raise ProtectedGrantError("protected_synthetic_success_proof_mismatch")
                if medusa:
                    cursor.execute(
                        """SELECT 1 FROM protected_cart_creations
                           WHERE environment_id=%s AND deployment_id=%s
                             AND derived_session_id=%s AND derived_world_generation_id=%s
                             AND resource_id=%s""",
                        (environment, deployment, session, generation, resource),
                    )
                    if cursor.fetchone() is None:
                        raise ProtectedGrantError("protected_medusa_add_derived_lineage_missing")
                cursor.execute(
                    """SELECT state_version,state_hash FROM world_commit_receipts
                       WHERE environment_id=%s AND deployment_id=%s AND session_id=%s
                         AND world_generation_id=%s AND commit_attempt_id=%s""",
                    (environment, deployment, session, generation, attempt),
                )
                if cursor.fetchone() != (saved_version, saved_hash):
                    raise ProtectedGrantError("protected_synthetic_success_commit_receipt_mismatch")
                cursor.execute(
                    """SELECT a.request_binding_digest,p.state_version,p.state_hash,
                              a.state_version,a.state_hash,a.expires_at,
                              p.environment_id,p.deployment_id,p.session_id,p.world_generation_id
                       FROM protected_world_read_sources p
                       JOIN read_admissions a ON a.read_admission_id=p.read_admission_id
                         AND (a.environment_id,a.deployment_id,a.session_id,a.world_generation_id)
                             =(p.environment_id,p.deployment_id,p.session_id,p.world_generation_id)
                       WHERE p.receipt_id=%s""", (receipt_id,),
                )
                read = cursor.fetchone()
                if (read is None or read[0] != fingerprint
                        or read[1:3] != read[3:5]
                        or read[6:] != (environment, deployment, session, generation)):
                    raise ProtectedGrantError("protected_synthetic_success_read_source_mismatch")
                cursor.execute(
                    """SELECT version,state_hash,state,expires_at FROM world_snapshots
                       WHERE environment_id=%s AND deployment_id=%s AND session_id=%s
                         AND world_generation_id=%s""",
                    (environment, deployment, session, generation),
                )
                snapshot_row = cursor.fetchone()
                if snapshot_row is None:
                    raise ProtectedGrantError("protected_synthetic_success_snapshot_missing")
                scope = WorldScope(environment_id=environment, deployment_id=deployment,
                                   session_id=session, world_generation_id=generation)
                try:
                    snapshot = WorldSnapshot(scope=scope, version=snapshot_row[0],
                                             state_hash=snapshot_row[1], state=snapshot_row[2],
                                             expires_at=snapshot_row[3])
                except ValueError as exc:
                    raise ProtectedGrantError("protected_synthetic_success_snapshot_invalid") from exc
                if (snapshot.version, snapshot.state_hash) != (saved_version, saved_hash):
                    raise ProtectedGrantError("protected_synthetic_success_snapshot_stale")
                if platform == "synthetic-inventory":
                    if (not isinstance(result.get("reservation_id"), str)
                            or not re.fullmatch(r"[0-9a-f]{32}", result["reservation_id"])
                            or not isinstance(result.get("sku"), str)
                            or type(result.get("quantity")) is not int
                            or result["quantity"] < 1
                            or result.get("status") != ("reserved" if action == "reserve" else "cancelled")):
                        raise ProtectedGrantError("protected_synthetic_success_inventory_invalid")
                    payload = {"commit_attempt_id": str(attempt), "state_version": saved_version,
                               "state_hash": saved_hash, "reservation": result}
                    spec = inventory_specification()
                else:
                    kind = "order" if action in {"cart.complete", "cart.cancel_order"} else "cart"
                    if kind == "cart":
                        if not _verified_cart_result_matches_snapshot(
                                resource=resource, result=result, snapshot_state=snapshot.state):
                            raise ProtectedGrantError("protected_synthetic_success_cart_identity_denied")
                        entity = result
                    else:
                        if not _verified_order_result_matches_snapshot(
                                action=action, resource=resource, result=result,
                                snapshot_state=snapshot.state):
                            raise ProtectedGrantError("protected_synthetic_success_order_identity_denied")
                        entity = result
                    if medusa:
                        from deception.domains.ecommerce.medusa_cart_projection import cart_view
                        from .models import canonical_state_hash

                        cursor.execute(
                            """SELECT context,context_hash FROM native_response_contexts
                               WHERE environment_id=%s AND deployment_id=%s AND session_id=%s
                                 AND world_generation_id=%s AND commit_attempt_id=%s""",
                            (environment, deployment, session, generation, attempt),
                        )
                        context_row = cursor.fetchone()
                        native_context = snapshot.state.get("native_context")
                        if (context_row is None or not isinstance(context_row[0], dict)
                                or not isinstance(native_context, dict)
                                or canonical_state_hash(context_row[0]) != context_row[1]
                                or context_row[0].get("catalog") != snapshot.state.get("catalog")
                                or any(context_row[0].get(field) != native_context.get(field)
                                    for field in ("region_id", "sales_channel_id", "email", "metadata"))):
                            raise ProtectedGrantError("protected_medusa_add_context_unverifiable")
                        try:
                            native_cart = cart_view(entity, context_row[0])
                            if operation_id == "DeleteCartsIdLineItemsLine_id":
                                deleted_item_id = match[2]
                                if any(item.get("id") == deleted_item_id
                                       for item in native_cart["items"]):
                                    raise ValueError("deleted item remains in committed cart")
                                payload = {"id": deleted_item_id, "object": "line-item",
                                           "deleted": True, "parent": native_cart}
                            else:
                                payload = {"cart": native_cart}
                        except (ValueError, TypeError, KeyError, OverflowError) as exc:
                            raise ProtectedGrantError("protected_medusa_add_projection_invalid") from exc
                        from referencing import Registry, Resource
                        from referencing.jsonschema import DRAFT4
                        from openapi_schema_validator import OAS30Validator

                        registry = Registry().with_resource(
                            "urn:mirage:medusa-contract", Resource.from_contents(
                                self._medusa_specification, default_specification=DRAFT4),
                        )
                        schema = ({"$ref": "urn:mirage:medusa-contract#/paths/"
                                   "~1store~1carts~1{id}~1line-items~1{line_id}/delete/"
                                   "responses/200/content/application~1json/schema"}
                                  if operation_id == "DeleteCartsIdLineItemsLine_id" else
                                  {"$ref": "urn:mirage:medusa-contract#/components/schemas/StoreCartResponse"})
                        if not OAS30Validator(schema, registry=registry).is_valid(payload):
                            raise ProtectedGrantError("protected_medusa_add_contract_invalid")
                    else:
                        payload = {kind: entity, "state_version": saved_version,
                                   "state_hash": saved_hash, "commit_attempt_id": str(attempt)}
                        spec = cart_specification()
                if not medusa:
                    schema = spec["paths"][template.removeprefix("/synthetic")][method.lower()][
                        "responses"]["200"]["content"]["application/json"]["schema"]
                    if not Draft202012Validator(schema).is_valid(payload):
                        raise ProtectedGrantError("protected_synthetic_success_contract_invalid")
                cursor.execute("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                now = cursor.fetchone()[0]
                if (token_deadline <= now or read[5] <= now
                        or snapshot.expires_at is not None and snapshot.expires_at <= now):
                    raise ProtectedGrantError("protected_synthetic_success_expired")
                cursor.execute(
                    """SELECT session_epoch FROM session_heads WHERE environment_id=%s
                       AND deployment_id=%s AND session_id=%s""",
                    (environment, deployment, session),
                )
                if cursor.fetchone() != (epoch,):
                    raise ProtectedGrantError("protected_synthetic_success_epoch_stale")
                cursor.execute(
                    """SELECT world_generation_id FROM session_world_bindings
                       WHERE environment_id=%s AND deployment_id=%s AND session_id=%s
                         AND session_epoch=%s""",
                    (environment, deployment, session, epoch),
                )
                if cursor.fetchone() != (generation,):
                    raise ProtectedGrantError("protected_synthetic_success_generation_stale")
                cursor.execute("SELECT sealed,emergency_revision FROM generation_controls WHERE world_generation_id=%s",
                               (generation,))
                if cursor.fetchone() != (False, None):
                    raise ProtectedGrantError("protected_synthetic_success_generation_revoked")
                guard = PostgresTrustedKeyRevocations(
                    self._dsn, environment_id=environment, deployment_id=deployment,
                )
                guard._lock(cursor, issuer, key_id)
                if guard._select(cursor, issuer, key_id) is not None:
                    raise ProtectedGrantError("protected_synthetic_success_key_revoked")
        headers = (("content-type", "application/json"),)
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")
        return ProtectedNativeProjection(
            receipt_id=receipt_id, scope=scope, operation_id=operation_id,
            request_fingerprint=fingerprint, status_code=200, headers=headers,
            body_bytes=body, envelope_hash=response_hashes(200, headers, body)[0],
            source=CommitSource(world_generation_id=generation,
                                operation_result_digest=saved_digest,
                                committed_state_version=saved_version,
                                committed_state_hash=saved_hash),
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
                if (operation not in {"PostCartsIdLineItems", "PostCartsIdLineItemsLine_id"}
                        or revision != "medusa-cart-1"
                        or (status, reason, template) not in {
                            (400, "native_bad_key", "native-cart-invalid"),
                            (400, "native_bad_item_body", "native-cart-invalid"),
                            (404, "native_variant_absent", "native-cart-rejected"),
                        } or operation == "PostCartsIdLineItemsLine_id" and status != 400):
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
                route = ("/store/carts/{id}/line-items" if operation == "PostCartsIdLineItems"
                         else "/store/carts/{id}/line-items/{line_id}")
                path_pattern = (r"/store/carts/(cart_[0-9a-f]{32})/line-items" if
                                operation == "PostCartsIdLineItems" else
                                r"/store/carts/(cart_[0-9a-f]{32})/line-items/item_[0-9a-f]{32}")
                path_match = (re.fullmatch(path_pattern, proof[5]) if
                              proof is not None and isinstance(proof[5], str) else None)
                if (proof is None or proof[:5] != (
                        "medusa-native-cart", operation, "POST", route, fingerprint)
                        or path_match is None or path_match[1] != ingress[9]):
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
