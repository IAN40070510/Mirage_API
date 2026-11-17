"""合成訪客購物車與訂單的固定 HTTP 契約及投影。"""

import json
import re
from uuid import uuid4, UUID

from pydantic import Field, UUID4

from deception.common.models import SyntheticModel
from deception.core.models import CandidateIdentity, CandidateResponse
from deception.world import CommitSource, SecurityErrorSource, WorldStoreError
from .carts import SyntheticCarts
from .inventory_http import InventoryHTTP


class CreateCartBody(SyntheticModel):
    """可選的建立重試鍵，不接受 Client 提供價格、庫存或世界 ID。"""

    idempotency_key: UUID4 = Field(default_factory=uuid4)
    commit_attempt_id: UUID4 = Field(default_factory=uuid4)


class CartMutationBody(SyntheticModel):
    """購物車變更的 CAS 版本與重試識別。"""

    expected_version: int = Field(ge=1)
    idempotency_key: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    commit_attempt_id: UUID4 = Field(default_factory=uuid4)


class AddItemBody(CartMutationBody):
    """品項身份與數量；單價由合成 catalog 決定。"""

    variant_id: str = Field(min_length=1, max_length=128)
    quantity: int = Field(ge=1)


class UpdateItemBody(CartMutationBody):
    """更新現有購物車品項的正整數數量。"""

    quantity: int = Field(ge=1)


CART_ERRORS = ["cart_not_active", "cart_item_not_found", "unknown_synthetic_variant", "empty_synthetic_cart",
               "order_not_cancellable", "insufficient_synthetic_inventory", "version_conflict",
               "idempotency_content_conflict", "invalid_synthetic_cart_operation", "operation_not_found"]


def cart_specification() -> dict:
    """宣告合成 API 的完整最小輸出結構，不借用 Medusa 原生規格的符合性名稱。"""
    item = {"type": "object", "additionalProperties": False,
        "required": ["id", "variant_id", "sku", "unit_price", "quantity"], "properties": {
            "id": {"type": "string"}, "variant_id": {"type": "string"}, "sku": {"type": "string"},
            "unit_price": {"type": "integer", "minimum": 0}, "quantity": {"type": "integer", "minimum": 1}}}
    common = {"id": {"type": "string"}, "items": {"type": "array", "items": item},
              "currency_code": {"type": "string", "enum": ["usd"]}, "total": {"type": "integer", "minimum": 0}}
    cart = {"type": "object", "additionalProperties": False, "required": [*common, "status"],
            "properties": {**common, "status": {"type": "string", "enum": ["active", "completed"]}}}
    order = {"type": "object", "additionalProperties": False, "required": [*common, "cart_id", "status"],
             "properties": {**common, "cart_id": {"type": "string"},
                            "status": {"type": "string", "enum": ["placed", "cancelled"]}}}
    responses = {}
    for name, schema in (("cart", cart), ("order", order)):
        responses[name] = {"type": "object", "additionalProperties": False,
            "required": [name, "state_version", "state_hash", "commit_attempt_id"], "properties": {
                name: schema, "state_version": {"type": "integer", "minimum": 1},
                "state_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "commit_attempt_id": {"type": ["string", "null"], "format": "uuid"}}}
    error = {"type": "object", "required": ["code"], "additionalProperties": False,
             "properties": {"code": {"type": "string", "enum": CART_ERRORS}}}
    definitions = [
        ("/carts", "post", "createGuestCart", CreateCartBody, responses["cart"]),
        ("/carts/{cart_id}", "get", "getGuestCart", None, responses["cart"]),
        ("/carts/{cart_id}/line-items", "post", "addGuestCartItem", AddItemBody, responses["cart"]),
        ("/carts/{cart_id}/line-items/{item_id}", "post", "updateGuestCartItem", UpdateItemBody, responses["cart"]),
        ("/carts/{cart_id}/line-items/{item_id}", "delete", "removeGuestCartItem", CartMutationBody, responses["cart"]),
        ("/carts/{cart_id}/complete", "post", "completeGuestCart", CartMutationBody, responses["order"]),
        ("/orders/{order_id}", "get", "getSyntheticOrder", None, responses["order"]),
        ("/orders/{order_id}/cancel", "post", "cancelSyntheticOrder", CartMutationBody, responses["order"]),
        ("/carts/{cart_id}/operations/{attempt}", "get", "getCartOperation", None,
         {"oneOf": [responses["cart"], responses["order"]]}),
    ]
    paths = {}
    for path, method, operation, body, schema in definitions:
        value = {"operationId": operation, "responses": {
            "200": {"description": "Synthetic result", "content": {"application/json": {"schema": schema}}},
            "409": {"description": "Fixed synthetic error", "content": {"application/json": {"schema": error}}}},
            "parameters": [{"name": name, "in": "path", "required": True, "schema": {"type": "string"}}
                           for name in re.findall(r"\{([^}]+)\}", path)]}
        if body:
            value["requestBody"] = {"required": True, "content": {"application/json": {"schema": body.model_json_schema()}}}
        paths.setdefault(path, {})[method] = value
    return {"openapi": "3.1.0", "info": {"title": "Mirage synthetic guest carts", "version": "1"}, "paths": paths}


class CartHTTP(InventoryHTTP):
    """沿用合成契約載入與嚴格 JSON 檢查，提供 cart.id／order.id 路由。"""

    def __init__(self, *, dsn, origin, output):
        """建立固定 cart 規格與 Gate；價格及 catalog 由服務端供應。"""
        super().__init__(dsn=dsn, origin=origin, output=output,
                         specification=cart_specification(), platform_id="synthetic-carts")
        self.service = SyntheticCarts(dsn)

    def execute(self, request, binding, read, *, now, initial_state):
        """執行一個合成購物車操作，輸出可交由正常 Renderer 驗證的候選與來源。"""
        path = request.path.removeprefix("/synthetic")
        matched = None
        for template, methods in self.specification["paths"].items():
            expression = re.sub(r"\{[^}]+\}", r"([^/]+)", template)
            match = re.fullmatch(expression, path)
            if match and request.method.lower() in methods:
                matched = template, methods[request.method.lower()]["operationId"], match.groups()
                break
        if matched is None or request.query_string:
            raise ValueError("unsupported synthetic cart route")
        template, operation, identifiers = matched
        status, source, payload = 200, read.source, None
        output_binding, snapshot = binding, read.snapshot
        try:
            if operation == "createGuestCart":
                body = self._json_body(request, CreateCartBody)
                created = self.service.create_cart(binding, catalog=initial_state["catalog"],
                    inventory=initial_state["inventory"], now=now, ttl=3600, **body.model_dump())
                result = created.outcome
                output_binding = created.binding
                snapshot = self.service.inspect_binding(output_binding, now=now)
            else:
                if binding.access_mode != "cart" or binding.resource_id != identifiers[0]:
                    raise ValueError("resource binding mismatch")
                if operation == "getGuestCart":
                    result = None
                    entity = self.service.public_cart(snapshot.state["cart"])
                elif operation == "getSyntheticOrder":
                    result = None
                    entity = snapshot.state["orders"][identifiers[0]]
                elif operation == "getCartOperation":
                    result = self.service.operation_result(binding, UUID(identifiers[1]), now=now)
                    if result is None:
                        raise WorldStoreError("operation_not_found")
                else:
                    model = AddItemBody if operation == "addGuestCartItem" else (
                        UpdateItemBody if operation == "updateGuestCartItem" else CartMutationBody)
                    body = self._json_body(request, model).model_dump()
                    metadata = {name: body.pop(name) for name in ("expected_version", "idempotency_key", "commit_attempt_id")}
                    if len(identifiers) > 1:
                        body["item_id"] = identifiers[1]
                    action = {"addGuestCartItem": "add", "updateGuestCartItem": "update", "removeGuestCartItem": "remove",
                              "completeGuestCart": "complete", "cancelSyntheticOrder": "cancel_order"}[operation]
                    result = self.service.mutate_cart(binding, action=action, command=body, now=now, **metadata)
            if result is None:
                version, state_hash, attempt = snapshot.version, snapshot.state_hash, None
            else:
                if result.status == "rejected":
                    raise WorldStoreError(result.result["code"])
                entity = result.result
                version, state_hash, attempt = result.state_version, result.state_hash, str(result.commit_attempt_id)
                digest = self._result_digest(result)
                source = CommitSource(world_generation_id=snapshot.scope.world_generation_id, operation_result_digest=digest,
                                      committed_state_version=version, committed_state_hash=state_hash)
            kind = "order" if entity["id"].startswith("order_") else "cart"
            payload = {kind: entity, "state_version": version, "state_hash": state_hash, "commit_attempt_id": attempt}
        except (ValueError, WorldStoreError, KeyError) as exc:
            code = str(exc) if str(exc) in CART_ERRORS else "invalid_synthetic_cart_operation"
            payload, status = {"code": code}, 409
            source = SecurityErrorSource(template_id=code, contract_revision="synthetic-carts-1")
        candidate = CandidateResponse(CandidateIdentity(site_id="demo-store", platform_id="synthetic-carts",
            platform_version="1", spec_sha256=self.spec_hash, scenario_id="synthetic-carts", run_id="synthetic-carts-1",
            operation_id=operation, method=request.method, path=template, source_approved=True), status,
            (("content-type", "application/json"),), json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return candidate, source, output_binding, snapshot

    @staticmethod
    def _result_digest(result) -> str:
        """摘要完整的已保存操作結果，排除只表示查詢重用的 replayed 旗標。"""
        import hashlib

        data = {"result": result.result, "version": result.state_version, "hash": result.state_hash,
                "attempt": str(result.commit_attempt_id), "status": result.status}
        return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
