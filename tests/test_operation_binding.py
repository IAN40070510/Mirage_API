"""G3b 固定業務 Operation 由原始 HTTP Snapshot 唯一推導的安全測試。"""

from dataclasses import replace
import json
from uuid import uuid4

import pytest

from deception.api.ingress import NormalizedRequest
from deception.security.operation_binding import (
    OperationBindingError, decode_verified_cart_creation, decode_verified_cart_mutation,
    decode_verified_cart_read,
    decode_verified_inventory_mutation,
    derive_verified_operation,
)


def original_request(*, path="/synthetic/inventory/reservations", method="POST") -> NormalizedRequest:
    """建立不經 Runtime 修改的固定 HTTP 測試快照，保留 raw path 與原始 body。"""
    return NormalizedRequest(
        request_id="fixed-request", method=method, raw_url="https://mirage.test" + path,
        path=path, raw_path=path.encode("utf-8"), query_string=b"", query=(),
        headers=(("host", "mirage.test"), ("content-type", "application/json")),
        body=b'{"sku":"sku1","quantity":1}',
    )


def test_trusted_operation_is_fixed_from_http_route_and_body():
    """正規 Inventory／Cart 請求推導固定 handler，body 更改只影響原始請求綁定。"""
    request = original_request()
    first = derive_verified_operation(request)
    assert (first.platform, first.operation_id, first.path_template) == (
        "synthetic-inventory", "reserveSyntheticInventory", "/synthetic/inventory/reservations")
    assert derive_verified_operation(replace(request, body=b"{}")).request_fingerprint != first.request_fingerprint
    cart = derive_verified_operation(original_request(path="/synthetic/carts"))
    assert (cart.platform, cart.operation_id) == ("synthetic-carts", "createGuestCart")


@pytest.mark.parametrize("change", [
    {"method": "PUT"},
    {"path": "/synthetic/inventory/reservations/", "raw_path": b"/synthetic/inventory/reservations/"},
    {"raw_path": b"/synthetic/inventory/%72eservations"},
    {"query_string": b"id=1", "query": (("id", "1"),)},
    {"path": "/store/unsupported", "raw_path": b"/store/unsupported"},
])
def test_verified_operation_rejects_alias_and_unknown_routes(change):
    """拒絕方法替換、尾斜線、百分比編碼別名、Query 與不存在的 Medusa 路由。"""
    with pytest.raises(OperationBindingError):
        derive_verified_operation(replace(original_request(), **change))


def test_inventory_command_cannot_be_selected_or_rewritten_by_rpc_caller():
    """原始 Body／Path／固定 Proof 才能還原 Handler；改寫命令和跨操作偽裝均失敗。"""
    body = json.dumps(dict(sku="sku-1", quantity=2, expected_version=1,
                           idempotency_key="reserve-1", commit_attempt_id=str(uuid4()))).encode()
    request = replace(original_request(), body=body)
    proof = derive_verified_operation(request)
    command = decode_verified_inventory_mutation(proof, raw_path=request.raw_path, raw_body=body)
    assert (command.operation, command.command, command.expected_version) == (
        "reserve", {"sku": "sku-1", "quantity": 2}, 1,
    )
    with pytest.raises(OperationBindingError, match="snapshot_mismatch"):
        decode_verified_inventory_mutation(proof, raw_path=request.raw_path,
                                           raw_body=body.replace(b"sku-1", b"sku-2"))
    with pytest.raises(OperationBindingError, match="snapshot_mismatch"):
        decode_verified_inventory_mutation(proof, raw_path=b"/synthetic/inventory/other", raw_body=body)
    with pytest.raises(OperationBindingError, match="operation_not_approved"):
        decode_verified_inventory_mutation(replace(proof, operation_id="cancelSyntheticInventory"),
                                           raw_path=request.raw_path, raw_body=body)
    with pytest.raises(OperationBindingError, match="snapshot_mismatch"):
        decode_verified_inventory_mutation(replace(proof, request_content_type=None),
                                           raw_path=request.raw_path, raw_body=body)


def test_inventory_command_denies_duplicate_keys_and_bad_path_parameters():
    """禁止重複 JSON key 被不同解析器解讀成不同命令，取消路徑必須精確。"""
    attempt = str(uuid4())
    body = (b'{"sku":"sku-1","sku":"sku-2","quantity":1,"expected_version":1,'
            b'"idempotency_key":"reserve-1","commit_attempt_id":"' + attempt.encode() + b'"}')
    request = replace(original_request(), body=body)
    with pytest.raises(OperationBindingError, match="body_invalid"):
        decode_verified_inventory_mutation(derive_verified_operation(request),
                                           raw_path=request.raw_path, raw_body=body)
    cancel_path = "/synthetic/inventory/reservations/not-hex/cancel"
    cancel = original_request(path=cancel_path)
    with pytest.raises(OperationBindingError, match="path_parameter_invalid"):
        decode_verified_inventory_mutation(derive_verified_operation(cancel),
                                           raw_path=cancel.raw_path, raw_body=cancel.body)


@pytest.mark.parametrize("path,method,operation,action", [
    ("/synthetic/carts/cart_" + "a" * 32 + "/line-items", "POST", "addGuestCartItem", "cart.add"),
    ("/synthetic/carts/cart_" + "a" * 32 + "/line-items/item_" + "b" * 32,
     "POST", "updateGuestCartItem", "cart.update"),
    ("/synthetic/carts/cart_" + "a" * 32 + "/line-items/item_" + "b" * 32,
     "DELETE", "removeGuestCartItem", "cart.remove"),
    ("/synthetic/carts/cart_" + "a" * 32 + "/complete", "POST", "completeGuestCart", "cart.complete"),
    ("/synthetic/orders/order_" + "c" * 32 + "/cancel", "POST", "cancelSyntheticOrder", "cart.cancel_order"),
])
def test_cart_order_commands_derive_from_verified_resource_and_retry(path, method, operation, action):
    """合成 Cart／Order 五個固定寫入路由只按證據選 action，省略 UUID 仍穩定重試。"""
    body = {"expected_version": 1, "idempotency_key": "cart-once"}
    if action == "cart.add":
        body.update(variant_id="variant-1", quantity=2)
    elif action == "cart.update":
        body["quantity"] = 3
    request = replace(original_request(path=path, method=method), body=json.dumps(body).encode())
    proof = derive_verified_operation(request)
    assert proof.operation_id == operation
    resource = path.split("/")[3]
    receipt = uuid4()
    args = dict(proof=proof, receipt_id=receipt, resource_id=resource,
                raw_path=request.raw_path, raw_body=request.body)
    result = decode_verified_cart_mutation(**args)
    assert result.operation == action and result.command["resource_id"] == resource
    assert result.commit_attempt_id.version == 4
    assert decode_verified_cart_mutation(**args).commit_attempt_id == result.commit_attempt_id
    with pytest.raises(OperationBindingError, match="resource_denied"):
        decode_verified_cart_mutation(**{**args, "resource_id": "cart_" + "f" * 32})
    with pytest.raises(OperationBindingError, match="snapshot_mismatch"):
        decode_verified_cart_mutation(**{**args, "raw_body": request.body + b" "})


def test_cart_body_rejects_duplicates_and_operation_substitution():
    """雙重 JSON key 或 Receipt Operation 改成別的業務動作，都不能產生 World 命令。"""
    path = "/synthetic/carts/cart_" + "a" * 32 + "/line-items"
    body = (b'{"expected_version":1,"idempotency_key":"once","quantity":1,'
            b'"quantity":2,"variant_id":"v1"}')
    request = replace(original_request(path=path), body=body)
    proof = derive_verified_operation(request)
    args = dict(proof=proof, receipt_id=uuid4(), resource_id="cart_" + "a" * 32,
                raw_path=request.raw_path, raw_body=body)
    with pytest.raises(OperationBindingError, match="body_invalid"):
        decode_verified_cart_mutation(**args)
    with pytest.raises(OperationBindingError, match="resource_denied"):
        decode_verified_cart_mutation(**{**args, "proof": replace(proof, operation_id="completeGuestCart")})


def test_cart_creator_receipt_derives_stable_cart_keys_without_runtime_choice():
    """合成 Cart 建立省略兩個可選 UUID 仍同 Receipt 固定；錯 Body 或其他操作不得改選建立。"""
    request = replace(original_request(path="/synthetic/carts"), body=b"{}")
    proof = derive_verified_operation(request)
    args = dict(proof=proof, receipt_id=uuid4(),
                raw_path=request.raw_path, raw_body=request.body)
    first = decode_verified_cart_creation(**args)
    second = decode_verified_cart_creation(**args)
    assert first == second
    assert first.idempotency_key.version == first.commit_attempt_id.version == 4
    assert first.idempotency_key != first.commit_attempt_id
    with pytest.raises(OperationBindingError, match="snapshot_mismatch"):
        decode_verified_cart_creation(**{**args, "raw_body": b'{"other":1}'})
    with pytest.raises(OperationBindingError, match="snapshot_mismatch"):
        decode_verified_cart_creation(**{**args, "proof": replace(proof, operation_id="getGuestCart")})


def test_cart_creator_does_not_accept_duplicate_json_or_extra_world_settings():
    """Creator 無法透過雙重欄位或加上任意 World／價格資料改變服務端初始狀態。"""
    for body in (b'{"idempotency_key":"x","idempotency_key":"y"}',
                 b'{"inventory":{"sku-1":999}}'):
        request = replace(original_request(path="/synthetic/carts"), body=body)
        with pytest.raises(OperationBindingError, match="body_invalid"):
            decode_verified_cart_creation(
                derive_verified_operation(request), receipt_id=uuid4(),
                raw_path=request.raw_path, raw_body=body,
            )


@pytest.mark.parametrize("path,operation", [
    ("/synthetic/carts/cart_" + "a" * 32, "getGuestCart"),
    ("/synthetic/orders/order_" + "b" * 32, "getSyntheticOrder"),
    ("/synthetic/carts/cart_" + "a" * 32 + "/operations/" + str(uuid4()), "getCartOperation"),
])
def test_cart_reads_bind_exact_get_and_derived_resource(path, operation):
    """GET 查詢必須固定 Cart／Order／操作 ID，範圍不能與 JWS Resource 不同。"""
    request = replace(original_request(path=path, method="GET"), body=b"", headers=(("host", "mirage.test"),))
    proof = derive_verified_operation(request)
    resource = path.split("/")[3]
    query = decode_verified_cart_read(proof, resource_id=resource,
                                     raw_path=request.raw_path, raw_body=request.body)
    assert query.operation == operation and query.resource_id == resource
    assert (query.attempt_id is not None) == (operation == "getCartOperation")
    with pytest.raises(OperationBindingError, match="resource_denied"):
        decode_verified_cart_read(proof, resource_id="cart_" + "f" * 32,
                                  raw_path=request.raw_path, raw_body=request.body)
    with pytest.raises(OperationBindingError, match="snapshot_mismatch"):
        decode_verified_cart_read(proof, resource_id=resource,
                                  raw_path=request.raw_path, raw_body=b"{}")
    with pytest.raises(OperationBindingError, match="snapshot_mismatch"):
        decode_verified_cart_read(proof, resource_id=resource,
                                  raw_path=b"/synthetic/other", raw_body=b"")
    with pytest.raises(OperationBindingError, match="snapshot_mismatch"):
        decode_verified_cart_read(replace(proof, request_path=None), resource_id=resource,
                                  raw_path=request.raw_path, raw_body=b"")


def test_cart_read_refuses_invalid_attempt_and_operation_rebinding():
    """不可用非標準 UUID 或替換 Operation ID 改變 GET 的目標結果。"""
    path = "/synthetic/carts/cart_" + "a" * 32 + "/operations/not-a-uuid"
    request = replace(original_request(path=path, method="GET"), body=b"")
    proof = derive_verified_operation(request)
    with pytest.raises(OperationBindingError, match="operation_or_resource_denied"):
        decode_verified_cart_read(proof, resource_id="cart_" + "a" * 32,
                                  raw_path=request.raw_path, raw_body=b"")
    good = replace(original_request(path="/synthetic/carts/cart_" + "a" * 32,
                                    method="GET"), body=b"")
    derived = derive_verified_operation(good)
    with pytest.raises(OperationBindingError, match="operation_or_resource_denied"):
        decode_verified_cart_read(replace(derived, operation_id="getSyntheticOrder"),
                                  resource_id="cart_" + "a" * 32,
                                  raw_path=good.raw_path, raw_body=b"")


@pytest.mark.parametrize("path,method,operation", [
    ("/store/carts", "POST", "PostCarts"),
    ("/store/carts/cart_" + "a" * 32 + "/complete", "POST", "PostCartsIdComplete"),
    ("/store/orders/order_" + "b" * 32, "GET", "GetOrdersId"),
])
def test_medusa_verified_route_comes_from_pinned_native_contract(path, method, operation):
    """只綁定固定來源 SHA-256 的原生 Medusa 契約，不自動開放業務 RPC。"""
    proof = derive_verified_operation(original_request(path=path, method=method))
    assert (proof.platform, proof.operation_id, proof.path_template.startswith("/store/")) == (
        "medusa-native-cart", operation, True,
    )
