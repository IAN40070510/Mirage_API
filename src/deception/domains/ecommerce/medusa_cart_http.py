"""Medusa 原生購物車入口，直接呼叫合成交易，不重新導向或回退真實商店。"""

import hashlib
import hmac
import json
from pathlib import Path
import re
from uuid import UUID, uuid4

from pydantic import Field

from deception.common.models import SyntheticModel
from deception.core.models import CandidateIdentity, CandidateResponse
from deception.world import CommitSource, SecurityErrorSource, WorldStoreError
from mirage_validator.gate import OfficialResponseGate, PlatformRegistry
from .cart_http import CartHTTP, CART_ERRORS
from .carts import SyntheticCarts
from .inventory_http import InventoryHTTP
from .medusa_cart_projection import SOURCE_SHA256, cart_view, load_contract, order_view


class NativeItemBody(SyntheticModel):
    """接受原生 variant_id 與正整數 quantity，不接受 Client 提供單價或庫存。"""

    variant_id: str = Field(min_length=1, max_length=128)
    quantity: int = Field(ge=1, le=10000)


class NativeQuantityBody(SyntheticModel):
    """原生品項更新只接受數量，不要求額外 CAS 或提交識別欄位。"""

    quantity: int = Field(ge=1, le=10000)


class NativeCreateBody(SyntheticModel):
    """接受固定 USD 合成地區的原生建立欄位；未實作地址、metadata 或 additional_data 時明確拒絕。"""

    region_id: str = "reg_mirage_usd"
    sales_channel_id: str = "sc_mirage"
    currency_code: str = "usd"
    email: str = Field(default="guest@example.invalid", min_length=3, max_length=320)
    items: list[NativeItemBody] = Field(default_factory=list, max_length=100)


class MedusaCartHTTP:
    """固定來源的原生操作與受控投影；只有明確啟用的隔離部署可註冊。"""

    platform_id = "medusa-native-cart"
    platform_version = "2.22.4"
    source_sha256 = SOURCE_SHA256
    response_statuses = (200, 400, 404, 409)

    def __init__(self, *, dsn: str, origin: str, output: Path, source: Path, publishable_key: str):
        """核對來源並保存獨立有效契約；公開 key 由部署者注入，不從 Client 猜測身份。"""
        if not publishable_key:
            raise ValueError("native Medusa cart requires a fixed publishable key")
        self._publishable_key = publishable_key
        self.service = SyntheticCarts(dsn)
        self.official_specification, self.specification = load_contract(source)
        raw = json.dumps(self.specification, ensure_ascii=False, sort_keys=True).encode()
        self.spec_hash = hashlib.sha256(raw).hexdigest()
        self.profile_data = dict(profile_id="medusa-native-cart-1", source_sha256=SOURCE_SHA256,
            effective_spec_sha256=self.spec_hash, target_version=self.platform_version,
            source_info_version=self.official_specification["info"]["version"],
            amount_policy="usd-major-from-integer-minor-div100", query_contexts=[{}],
            checkout_policy="synthetic-pending-unpaid-order", customer_identity="anonymous-null",
            world_schema_version="1", domain_adapter_version="medusa-cart-1",
            unsupported_inputs="reject", operations={path: list(methods) for path, methods in self.specification["paths"].items()})
        self.profile_sha256 = hashlib.sha256(json.dumps(self.profile_data, sort_keys=True).encode()).hexdigest()
        directory = output / self.platform_id
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "openapi.yaml").write_bytes(raw)
        (directory / "profile.json").write_text(json.dumps(self.profile_data, sort_keys=True, indent=2), encoding="utf-8")
        manifest = dict(platform_id=self.platform_id, platform_version=self.platform_version,
            spec_sha256=self.spec_hash, approved=True, openapi_file="openapi.yaml", base_urls=[origin], query_contexts=[{}],
            source_url="https://github.com/medusajs/medusa/tree/81edb06c323812773c9c0dcc4da2d9784f3b3319",
            source_revision="81edb06c323812773c9c0dcc4da2d9784f3b3319")
        (directory / "manifest.yaml").write_text(json.dumps(manifest), encoding="utf-8")
        self.gate = OfficialResponseGate(PlatformRegistry(output))

    @staticmethod
    def _key(request, *, complete: bool = False) -> str:
        """可選的 Idempotency-Key 必須唯一且已被 JWS 綁定；完成操作使用資源內固定鍵。"""
        values = [value for name, value in request.headers if name.lower() == "idempotency-key"]
        if len(values) > 1 or (values and not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", values[0])):
            raise ValueError("invalid idempotency header")
        if complete:
            return "medusa-complete"
        return "medusa-" + (hashlib.sha256(values[0].encode()).hexdigest() if values else uuid4().hex)

    def execute(self, request, binding, read, *, now: int, initial_state: dict):
        """保留原始請求身份，轉成合成事件，再輸出原生候選、來源與實際世界。

        目前拒絕非空 query 及未實作欄位；資料庫／身份無法確認交由外層安全錯誤。
        Client 不提供 expected_version：以本次可信讀取版本做 CAS，衝突不自動重試。
        """
        matched = None
        for template, methods in self.specification["paths"].items():
            match = re.fullmatch(re.sub(r"\{[^}]+\}", "([^/]+)", template), request.path)
            if match and request.method.lower() in methods:
                matched = template, methods[request.method.lower()]["operationId"], match.groups()
                break
        if matched is None:
            raise ValueError("unsupported native cart route")
        template, operation, identifiers = matched
        snapshot, output_binding, source = read.snapshot, binding, read.source
        status, payload = 200, None
        try:
            keys = [value for name, value in request.headers if name.lower() == "x-publishable-api-key"]
            if len(keys) != 1 or not hmac.compare_digest(keys[0], self._publishable_key):
                raise ValueError("invalid native publishable key")
            if request.query_string:
                raise ValueError("unsupported native query context")
            key = self._key(request, complete=operation == "PostCartsIdComplete")
            result = None
            if operation == "PostCarts":
                body = InventoryHTTP._json_body(request, NativeCreateBody)
                if (body.region_id, body.sales_channel_id, body.currency_code) != (
                        "reg_mirage_usd", "sc_mirage", "usd"):
                    raise ValueError("unsupported synthetic region or currency")
                if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", body.email):
                    raise ValueError("invalid email")
                data = body.model_dump()
                context = {name: data[name] for name in ("region_id", "sales_channel_id", "email")}
                context["metadata"] = {}
                digest = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                creation = self.service.create_cart(binding, catalog=initial_state["catalog"],
                    inventory=initial_state["inventory"], idempotency_key=UUID(bytes=hashlib.sha256(key.encode()).digest()[:16], version=4),
                    commit_attempt_id=uuid4(), now=now, ttl=3600, native_context=context,
                    initial_items=[item.model_dump() for item in body.items], creation_digest=digest)
                output_binding, result = creation.binding, creation.outcome
                snapshot = self.service.inspect_binding(output_binding, now=now)
            else:
                if binding.access_mode != "cart" or binding.resource_id != identifiers[0]:
                    raise WorldStoreError("synthetic_resource_unverifiable")
                if "native_context" not in snapshot.state:
                    raise WorldStoreError("native cart context unavailable")
                if operation in {"GetCartsId", "GetOrdersId"}:
                    if request.body:
                        raise ValueError("GET body is unsupported")
                else:
                    command = {}
                    if operation == "PostCartsIdLineItems":
                        action = "add"
                        command = InventoryHTTP._json_body(request, NativeItemBody).model_dump()
                    elif operation == "PostCartsIdLineItemsLine_id":
                        action = "update"
                        command = InventoryHTTP._json_body(request, NativeQuantityBody).model_dump()
                        command["item_id"] = identifiers[1]
                    else:
                        if request.body not in (b"", b"{}"):
                            raise ValueError("operation accepts no JSON fields")
                        action = "remove" if request.method == "DELETE" else "complete"
                        if action == "remove":
                            command["item_id"] = identifiers[1]
                    result = self.service.mutate_cart(binding, action=action, command=command,
                        expected_version=snapshot.version, idempotency_key=key, commit_attempt_id=uuid4(), now=now)
                    snapshot = self.service.inspect_binding(binding, now=now)
            if result is not None and result.status != "committed":
                raise WorldStoreError(result.result["code"])
            context = (self.service.native_response_context(output_binding, result.commit_attempt_id, now=now)
                       if result is not None else {**snapshot.state["native_context"], "catalog": snapshot.state["catalog"]})
            if result is not None:
                source = CommitSource(world_generation_id=snapshot.scope.world_generation_id,
                    operation_result_digest=CartHTTP._result_digest(result), committed_state_version=result.state_version,
                    committed_state_hash=result.state_hash)
            if operation == "GetOrdersId" or operation == "PostCartsIdComplete":
                entity = snapshot.state["orders"][identifiers[0]] if operation == "GetOrdersId" else result.result
                payload = {"order": order_view(entity, context)}
                if operation == "PostCartsIdComplete":
                    payload["type"] = "order"
            else:
                entity = result.result if result is not None else self.service.public_cart(snapshot.state["cart"])
                if operation == "DeleteCartsIdLineItemsLine_id":
                    payload = {"id": identifiers[1], "object": "line-item", "deleted": True,
                               "parent": cart_view(entity, context)}
                else:
                    payload = {"cart": cart_view(entity, context)}
        except ValueError:
            status, payload = 400, {"type": "invalid_data", "message": "The requested cart operation is not supported."}
            source = SecurityErrorSource(template_id="native-cart-invalid", contract_revision="medusa-cart-1")
        except WorldStoreError as exc:
            code = str(exc)
            if code not in CART_ERRORS:
                raise
            status = 409 if code in {"version_conflict", "idempotency_content_conflict"} else (
                404 if code in {"cart_item_not_found", "unknown_synthetic_variant"} else 400)
            payload = {"type": "not_found" if status == 404 else "invalid_data",
                       "message": "The requested cart operation could not be completed."}
            source = SecurityErrorSource(template_id="native-cart-rejected", contract_revision="medusa-cart-1")
        candidate = CandidateResponse(CandidateIdentity(site_id="demo-store", platform_id=self.platform_id,
            platform_version=self.platform_version, spec_sha256=self.spec_hash, scenario_id="medusa-native-cart",
            run_id="medusa-native-cart-1", operation_id=operation, method=request.method, path=template,
            source_approved=True), status, (("content-type", "application/json"),),
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return candidate, source, output_binding, snapshot
