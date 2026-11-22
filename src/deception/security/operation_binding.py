"""由可信 Ingress 的原始 HTTP 快照推導固定業務 Operation，拒絕路由歧義。"""

from dataclasses import dataclass
import hashlib
import hmac
import json
import re
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

    不接受百分比編碼路徑、非空 query、斜線或方法替代、重複／重疊路由。
    Medusa 映射須另外加入固定已審核的 native contract，未完成前 Fail-Closed。
    """
    if not isinstance(request, NormalizedRequest):
        raise OperationBindingError("verified_operation_requires_http_snapshot")
    if (not isinstance(request.path, str) or not isinstance(request.raw_path, bytes)
            or request.raw_path != request.path.encode("utf-8")
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
        request_path=request.path, request_content_type=content_type,
    )
