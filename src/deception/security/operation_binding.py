"""由可信 Ingress 的原始 HTTP 快照推導固定業務 Operation，拒絕路由歧義。"""

from dataclasses import dataclass
import hashlib
import hmac
import json
import re
from urllib.parse import quote, unquote_to_bytes
from uuid import UUID

from deception.api.fingerprint import fingerprint_request
from deception.api.ingress import MAX_BODY_BYTES, NormalizedRequest
from mirage_validator.json_utils import reject_constant, unique_object


class OperationBindingError(ValueError):
    """表示請求路徑、方法或固定業務契約不能唯一對應可信 Operation。"""


@dataclass(frozen=True)
class VerifiedOperationBinding:
    """不可變的 HTTP Operation 來源，不能由 Runtime 指定 Handler 名稱。"""

    platform: str
    operation_id: str
    method: str
    path_template: str
    request_fingerprint: str
    request_body_sha256: str
    request_path: str
    request_content_type: str | None


@dataclass(frozen=True)
class VerifiedInventoryMutation:
    """由可信 Operation Proof 與完全相符的 HTTP body 解出的固定庫存命令。"""

    operation: str
    command: dict
    expected_version: int
    idempotency_key: str
    commit_attempt_id: UUID


@dataclass(frozen=True)
class VerifiedCartMutation:
    """由原始 Cart／Order HTTP Proof 推導的固定世界事件，不接受 RPC 自選 action。"""

    operation: str
    command: dict
    expected_version: int
    idempotency_key: str
    commit_attempt_id: UUID


@dataclass(frozen=True)
class VerifiedCartCreation:
    """受保護 Creator Receipt 的一次性 Cart 建立意圖與穩定提交識別碼。"""

    idempotency_key: UUID
    commit_attempt_id: UUID
    creation_digest: str


@dataclass(frozen=True)
class VerifiedCartRead:
    """從原始 GET Receipt 綁定的合成 Cart／Order 查詢，含可選操作結果 ID。"""

    operation: str
    resource_id: str
    attempt_id: UUID | None


@dataclass(frozen=True)
class VerifiedInventoryRead:
    """原始 GET Proof 固定的合成庫存或 Operation 查詢，不含可偽造回應。"""

    operation: str
    resource_id: str
    attempt_id: UUID | None


def decode_verified_inventory_sku_path(raw_path: bytes) -> str:
    """只接受 I-04 原始 UTF-8 或唯一 RFC3986 percent-encoded SKU，拒絕別名。

    客戶端可按 URL 規則編碼非 ASCII／空白，但不得 percent-encode 一般
    ASCII 字元、混用 raw UTF-8 與編碼、編碼分隔符、雙重編碼或改變大小寫。
    此處只解碼受限 SKU，不改寫原始 Fingerprint 或賦予 HTTP Send 權。
    """
    if not isinstance(raw_path, bytes):
        raise OperationBindingError("verified_inventory_read_operation_or_resource_denied")
    prefix = b"/synthetic/inventory/"
    matched = re.fullmatch(rb"/synthetic/inventory/([^/?#\x00-\x1f\x7f]{1,1536})", raw_path)
    if matched is None:
        raise OperationBindingError("verified_inventory_read_operation_or_resource_denied")
    decoded = unquote_to_bytes(matched[1])
    if (re.fullmatch(rb"[^/%?#\\\x00-\x1f\x7f]{1,512}", decoded) is None
            or decoded in {b".", b".."}):
        raise OperationBindingError("verified_inventory_read_operation_or_resource_denied")
    try:
        sku = decoded.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise OperationBindingError("verified_inventory_read_operation_or_resource_denied") from exc
    canonical_encoded = quote(sku, safe="!$&'()*+,-._~:;=@").encode("ascii")
    if (len(sku) > 128 or raw_path not in {
            prefix + decoded, prefix + canonical_encoded}):
        raise OperationBindingError("verified_inventory_read_operation_or_resource_denied")
    return sku


def _inventory_sku_path_matches_decoded(raw_path: bytes, decoded_path: str) -> bool:
    """核對真正原始 URL bytes 與 ASGI 解碼路徑一致且沒有替代編碼別名。"""
    prefix = "/synthetic/inventory/"
    if not isinstance(decoded_path, str) or not decoded_path.startswith(prefix):
        return False
    try:
        return decode_verified_inventory_sku_path(raw_path) == decoded_path[len(prefix):]
    except OperationBindingError:
        return False


def decode_verified_inventory_read(
    proof: VerifiedOperationBinding, *, raw_path: bytes, raw_body: bytes,
) -> VerifiedInventoryRead:
    """嚴格解出已受保護的 Inventory GET，拒絕有歧義的 URI／Body／UUID。

    只驗證已由獨立 Verifier 固定的路由快照；呼叫者仍須以 Executor 物理
    Login 查回 Receipt，並另行執行受保護 ReadAdmission 與來源驗證。
    """
    if (not isinstance(proof, VerifiedOperationBinding)
            or proof.platform != "synthetic-inventory" or proof.method != "GET"
            or not isinstance(raw_path, bytes) or not isinstance(raw_body, bytes)
            or not isinstance(proof.request_path, str)
            or raw_path != proof.request_path.encode("utf-8")
            or raw_body != b"" or proof.request_body_sha256 != hashlib.sha256(b"").hexdigest()):
        raise OperationBindingError("verified_inventory_read_snapshot_mismatch")
    if (proof.operation_id, proof.path_template) == (
            "getSyntheticInventory", "/synthetic/inventory/{sku}"):
        return VerifiedInventoryRead("getSyntheticInventory",
                                     decode_verified_inventory_sku_path(raw_path), None)
    elif (proof.operation_id, proof.path_template) == (
            "getSyntheticOperation", "/synthetic/operations/{attempt}"):
        matched = re.fullmatch(rb"/synthetic/operations/([0-9a-f-]{36})", raw_path)
        if matched is not None:
            try:
                attempt = UUID(matched[1].decode("ascii"))
            except ValueError as exc:
                raise OperationBindingError("verified_inventory_read_attempt_invalid") from exc
            if attempt.version == 4 and str(attempt).encode("ascii") == matched[1]:
                return VerifiedInventoryRead("getSyntheticOperation", str(attempt), attempt)
    raise OperationBindingError("verified_inventory_read_operation_or_resource_denied")


def decode_verified_cart_read(
    proof: VerifiedOperationBinding, *, resource_id: str,
    raw_path: bytes, raw_body: bytes,
) -> VerifiedCartRead:
    """只從 Verifier 已固定的原始 GET 路徑推導查詢及資源身份。

    GET 不應造成事件，也不能憑 Runtime 選擇另一個 Cart、Order 或操作查詢。
    舊 Operation Proof 不帶原始路徑時，與非空 body 都固定拒絕。
    """
    if (not isinstance(proof, VerifiedOperationBinding)
            or proof.platform != "synthetic-carts" or proof.method != "GET"
            or not isinstance(raw_path, bytes) or not isinstance(raw_body, bytes)
            or not isinstance(proof.request_path, str)
            or raw_path != proof.request_path.encode("utf-8")
            or raw_body != b"" or proof.request_body_sha256 != hashlib.sha256(b"").hexdigest()
            or not isinstance(resource_id, str)):
        raise OperationBindingError("verified_cart_read_snapshot_mismatch")
    operations = (
        ("getGuestCart", "/synthetic/carts/{cart_id}",
         rb"/synthetic/carts/(cart_[0-9a-f]{32})"),
        ("getSyntheticOrder", "/synthetic/orders/{order_id}",
         rb"/synthetic/orders/(order_[0-9a-f]{32})"),
        ("getCartOperation", "/synthetic/carts/{cart_id}/operations/{attempt}",
         rb"/synthetic/carts/(cart_[0-9a-f]{32})/operations/([0-9a-f-]{36})"),
    )
    for operation_id, template, pattern in operations:
        if (proof.operation_id, proof.path_template) != (operation_id, template):
            continue
        matched = re.fullmatch(pattern, raw_path)
        if matched is None or matched[1].decode("ascii") != resource_id:
            break
        attempt = None
        if len(matched.groups()) == 2:
            try:
                attempt = UUID(matched[2].decode("ascii"))
            except ValueError as exc:
                raise OperationBindingError("verified_cart_read_attempt_invalid") from exc
            if str(attempt).encode("ascii") != matched[2] or attempt.version != 4:
                raise OperationBindingError("verified_cart_read_attempt_invalid")
        return VerifiedCartRead(operation_id, resource_id, attempt)
    raise OperationBindingError("verified_cart_read_operation_or_resource_denied")


def decode_verified_cart_creation(
    proof: VerifiedOperationBinding, *, receipt_id: UUID,
    raw_path: bytes, raw_body: bytes,
) -> VerifiedCartCreation:
    """從原始 POST /synthetic/carts 還原單次 Creator 意圖，不信任 RPC 提交鍵。"""
    from deception.domains.ecommerce.cart_http import CreateCartBody

    _receipt_uuid4(receipt_id, b"cart-create")
    if (not isinstance(proof, VerifiedOperationBinding)
            or (proof.platform, proof.operation_id, proof.method, proof.path_template) != (
                "synthetic-carts", "createGuestCart", "POST", "/synthetic/carts")
            or not isinstance(raw_path, bytes) or raw_path != b"/synthetic/carts"
            or raw_path != proof.request_path.encode("utf-8")
            or not isinstance(raw_body, bytes) or len(raw_body) > MAX_BODY_BYTES
            or not hmac.compare_digest(hashlib.sha256(raw_body).hexdigest(), proof.request_body_sha256)
            or proof.request_content_type is None
            or proof.request_content_type.split(";", 1)[0].strip().lower() != "application/json"):
        raise OperationBindingError("verified_cart_creation_snapshot_mismatch")
    try:
        parsed = json.loads(raw_body, object_pairs_hook=unique_object, parse_constant=reject_constant)
        if not isinstance(parsed, dict):
            raise ValueError("cart JSON object required")
        parsed.setdefault("idempotency_key", str(_receipt_uuid4(receipt_id, b"cart-create-idempotency")))
        parsed.setdefault("commit_attempt_id", str(_receipt_uuid4(receipt_id, b"cart-create-attempt")))
        validated = CreateCartBody.model_validate_json(json.dumps(
            parsed, ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8"))
        data = validated.model_dump(mode="json")
    except (ValueError, UnicodeError) as exc:
        raise OperationBindingError("verified_cart_creation_body_invalid") from exc
    return VerifiedCartCreation(
        idempotency_key=validated.idempotency_key,
        commit_attempt_id=validated.commit_attempt_id,
        creation_digest=hashlib.sha256(json.dumps(
            data, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest(),
    )


def _pinned_medusa_operations() -> tuple[tuple[str, str, str], ...]:
    """回傳已審核的七個固定路由，不在實際容器由工作目錄動態選擇業務 Handler。

    官方來源的 SHA-256 與每條 operationId 在契約測試核對；CI image 只執行
    內建映射，避免 wheel 安裝路徑與 source-tree 的不同導致隱性容器失敗。
    """
    return (
        ("/store/carts", "post", "PostCarts"),
        ("/store/carts/{id}", "get", "GetCartsId"),
        ("/store/carts/{id}/line-items", "post", "PostCartsIdLineItems"),
        ("/store/carts/{id}/line-items/{line_id}", "post", "PostCartsIdLineItemsLine_id"),
        ("/store/carts/{id}/line-items/{line_id}", "delete", "DeleteCartsIdLineItemsLine_id"),
        ("/store/carts/{id}/complete", "post", "PostCartsIdComplete"),
        ("/store/orders/{id}", "get", "GetOrdersId"),
    )


def _receipt_uuid4(receipt_id: UUID, purpose: bytes) -> UUID:
    """為省略可選 UUIDv4 的合法 Cart 請求建立穩定重試 ID，不重新隨機起送。"""
    if not isinstance(receipt_id, UUID) or receipt_id.version != 4:
        raise OperationBindingError("verified_cart_receipt_id_invalid")
    return UUID(bytes=hashlib.sha256(receipt_id.bytes + purpose).digest()[:16], version=4)


def decode_verified_cart_mutation(
    proof: VerifiedOperationBinding, *, receipt_id: UUID, resource_id: str,
    raw_path: bytes, raw_body: bytes,
) -> VerifiedCartMutation:
    """對照受保護 Receipt 的唯一 Cart／Order Operation，嚴格解析原始 Body。

    這是獨立 Executor 的內部映射：Client 可略過可選 commit_attempt_id，
    重試值從一次性 Receipt 決定。對應的實際 resource_id 必須與 Verifier
    收到的 URL 相符。非法 409 尚缺獨立驗證記錄，因此此處固定拒絕執行。
    """
    from deception.domains.ecommerce.cart_http import AddItemBody, CartMutationBody, UpdateItemBody

    _receipt_uuid4(receipt_id, b"cart-mutation")
    if (not isinstance(proof, VerifiedOperationBinding)
            or proof.platform != "synthetic-carts"
            or not isinstance(raw_path, bytes) or not isinstance(raw_body, bytes)
            or len(raw_body) > MAX_BODY_BYTES
            or raw_path != proof.request_path.encode("utf-8")
            or not hmac.compare_digest(hashlib.sha256(raw_body).hexdigest(), proof.request_body_sha256)
            or proof.request_content_type is None
            or proof.request_content_type.split(";", 1)[0].strip().lower() != "application/json"
            or not isinstance(resource_id, str)):
        raise OperationBindingError("verified_cart_http_snapshot_mismatch")
    operations = (
        ("addGuestCartItem", "POST", "/synthetic/carts/{cart_id}/line-items",
         rb"/synthetic/carts/(cart_[0-9a-f]{32})/line-items", "cart.add", AddItemBody),
        ("updateGuestCartItem", "POST", "/synthetic/carts/{cart_id}/line-items/{item_id}",
         rb"/synthetic/carts/(cart_[0-9a-f]{32})/line-items/(item_[0-9a-f]{32})", "cart.update", UpdateItemBody),
        ("removeGuestCartItem", "DELETE", "/synthetic/carts/{cart_id}/line-items/{item_id}",
         rb"/synthetic/carts/(cart_[0-9a-f]{32})/line-items/(item_[0-9a-f]{32})", "cart.remove", CartMutationBody),
        ("completeGuestCart", "POST", "/synthetic/carts/{cart_id}/complete",
         rb"/synthetic/carts/(cart_[0-9a-f]{32})/complete", "cart.complete", CartMutationBody),
        ("cancelSyntheticOrder", "POST", "/synthetic/orders/{order_id}/cancel",
         rb"/synthetic/orders/(order_[0-9a-f]{32})/cancel", "cart.cancel_order", CartMutationBody),
    )
    chosen = None
    for operation_id, method, template, pattern, action, model in operations:
        if (proof.operation_id, proof.method, proof.path_template) != (operation_id, method, template):
            continue
        match = re.fullmatch(pattern, raw_path)
        if match is not None and match[1].decode("ascii") == resource_id:
            chosen = action, model, match
            break
    if chosen is None:
        raise OperationBindingError("verified_cart_operation_or_resource_denied")
    action, model, match = chosen
    try:
        parsed = json.loads(raw_body, object_pairs_hook=unique_object, parse_constant=reject_constant)
        if not isinstance(parsed, dict):
            raise ValueError("cart JSON object required")
        parsed.setdefault("commit_attempt_id", str(_receipt_uuid4(receipt_id, b"cart-mutation")))
        body = model.model_validate_json(json.dumps(parsed, ensure_ascii=False,
                                                   separators=(",", ":")).encode("utf-8")).model_dump()
    except (ValueError, UnicodeError) as exc:
        raise OperationBindingError("verified_cart_body_invalid") from exc
    command = {key: value for key, value in body.items()
               if key not in {"expected_version", "idempotency_key", "commit_attempt_id"}}
    command["resource_id"] = resource_id
    if len(match.groups()) == 2:
        command["item_id"] = match[2].decode("ascii")
    return VerifiedCartMutation(
        operation=action, command=command,
        expected_version=body["expected_version"],
        idempotency_key=body["idempotency_key"],
        commit_attempt_id=body["commit_attempt_id"],
    )


def decode_verified_inventory_mutation(
    proof: VerifiedOperationBinding, *, raw_path: bytes, raw_body: bytes,
) -> VerifiedInventoryMutation:
    """以資料庫原始路徑、內容摘要與固定模型選定 Handler，禁止 Runtime 自選操作。

    此函式不認證 `proof` 的來源；呼叫者必須先用獨立 Executor 的資料庫登入，
    按 Receipt ID 查回不可變的受保護列。拒絕 Body／Path／Content-Type 與
    原始請求有任何差異。非法 Body 的 409 可信證據尚未接線，因此只拒絕執行。
    """
    from deception.domains.ecommerce.inventory_http import CancelBody, ReserveBody

    if (not isinstance(proof, VerifiedOperationBinding)
            or proof.platform != "synthetic-inventory" or proof.method != "POST"
            or not isinstance(raw_path, bytes) or not isinstance(raw_body, bytes)
            or len(raw_body) > MAX_BODY_BYTES
            or raw_path != proof.request_path.encode("utf-8")
            or not hmac.compare_digest(hashlib.sha256(raw_body).hexdigest(), proof.request_body_sha256)
            or proof.request_content_type is None
            or proof.request_content_type.split(";", 1)[0].strip().lower() != "application/json"):
        raise OperationBindingError("verified_inventory_http_snapshot_mismatch")
    if (proof.operation_id == "reserveSyntheticInventory"
            and proof.path_template == "/synthetic/inventory/reservations"
            and raw_path == b"/synthetic/inventory/reservations"):
        operation, model, params = "reserve", ReserveBody, {}
    elif (proof.operation_id == "cancelSyntheticInventory"
            and proof.path_template == "/synthetic/inventory/reservations/{reservation_id}/cancel"):
        match = re.fullmatch(rb"/synthetic/inventory/reservations/([0-9a-f]{32})/cancel", raw_path)
        if match is None:
            raise OperationBindingError("verified_inventory_path_parameter_invalid")
        operation, model, params = "cancel", CancelBody, {"reservation_id": match[1].decode("ascii")}
    else:
        raise OperationBindingError("verified_inventory_operation_not_approved")
    try:
        json.loads(raw_body, object_pairs_hook=unique_object, parse_constant=reject_constant)
        body = model.model_validate_json(raw_body).model_dump()
    except (ValueError, UnicodeError) as exc:
        raise OperationBindingError("verified_inventory_body_invalid") from exc
    return VerifiedInventoryMutation(
        operation=operation,
        command={**params, **{key: value for key, value in body.items()
                              if key not in {"expected_version", "idempotency_key", "commit_attempt_id"}}},
        expected_version=body["expected_version"],
        idempotency_key=body["idempotency_key"],
        commit_attempt_id=body["commit_attempt_id"],
    )


def derive_verified_operation(request: NormalizedRequest) -> VerifiedOperationBinding:
    """使用固定 Synthetic API 規格及實際接收的原始 path 導出唯一 Operation。

    I-04 只容許唯一 RFC3986 SKU 編碼；其他路由不接受百分比別名，
    所有路由拒絕非空 query、斜線或方法替代、重複／重疊路由。
    Medusa 只建立來自固定 SHA-256 審核來源的 Operation 證據；目前仍不得
    用它直接執行 Native Handler 或生成未核准的 400／404 回應。
    """
    if not isinstance(request, NormalizedRequest):
        raise OperationBindingError("verified_operation_requires_http_snapshot")
    if (not isinstance(request.path, str) or not isinstance(request.raw_path, bytes)
            or (request.raw_path != request.path.encode("utf-8")
                and (request.method != "GET" or not _inventory_sku_path_matches_decoded(
                    request.raw_path, request.path)))
            or not isinstance(request.method, str)
            or not re.fullmatch(r"[A-Z]+", request.method)
            or request.query_string or request.query
            or not 1 <= len(request.path) <= 2048
            or not isinstance(request.body, bytes) or len(request.body) > MAX_BODY_BYTES):
        raise OperationBindingError("verified_operation_ambiguous_route")

    from deception.domains.ecommerce.cart_http import cart_specification
    from deception.domains.ecommerce.inventory_http import inventory_specification

    matches = []
    for platform, specification in (
        ("synthetic-inventory", inventory_specification()),
        ("synthetic-carts", cart_specification()),
    ):
        for template, methods in specification["paths"].items():
            concrete = "/synthetic" + template
            expression = re.sub(r"\{[a-z_]+\}", r"[^/]+", concrete)
            if re.fullmatch(expression, request.path) and request.method.lower() in methods:
                matches.append((platform, methods[request.method.lower()]["operationId"], concrete))
    for template, method, operation_id in _pinned_medusa_operations():
        expression = re.sub(r"\{[a-z_]+\}", r"[^/]+", template)
        if re.fullmatch(expression, request.path) and request.method.lower() == method:
            matches.append(("medusa-native-cart", operation_id, template))
    if len(matches) != 1:
        raise OperationBindingError("verified_operation_unknown_or_ambiguous")
    platform, operation_id, path_template = matches[0]
    types = [value for name, value in request.headers if name.lower() == "content-type"]
    content_type = types[0] if len(types) == 1 and 1 <= len(types[0]) <= 256 else None
    return VerifiedOperationBinding(
        platform=platform, operation_id=operation_id, method=request.method,
        path_template=path_template,
        request_fingerprint=fingerprint_request(request),
        request_body_sha256=hashlib.sha256(request.body).hexdigest(),
        # I-04 ASGI path 已解碼；Proof 必須留存唯一原始 URL 編碼形式，
        # Executor 才能逐 byte 拒絕同 SKU 的不同 raw-path 重新綁定。
        request_path=(request.raw_path.decode("utf-8")
                      if (operation_id == "getSyntheticInventory" and
                          request.raw_path != request.path.encode("utf-8"))
                      else request.path),
        request_content_type=content_type,
    )
