"""G3b 固定業務 Operation 由原始 HTTP Snapshot 唯一推導的安全測試。"""

from dataclasses import replace
import json
from urllib.parse import unquote
from uuid import uuid4

import pytest

from deception.api.ingress import NormalizedRequest
from deception.security.operation_binding import (
    OperationBindingError, decode_verified_cart_creation, decode_verified_cart_mutation,
    decode_verified_cart_read, decode_verified_medusa_read, decode_verified_inventory_read,
    decode_verified_inventory_mutation,
    derive_verified_operation, _pinned_medusa_operations,
)


PINNED_HTTP_CASES = (
    ("I-01", "synthetic-inventory", "POST", "/synthetic/inventory/reservations",
     "/synthetic/inventory/reservations", "reserveSyntheticInventory"),
    ("I-02", "synthetic-inventory", "POST", "/synthetic/inventory/reservations/" + "a" * 32 + "/cancel",
     "/synthetic/inventory/reservations/{reservation_id}/cancel", "cancelSyntheticInventory"),
    ("I-03", "synthetic-inventory", "GET", "/synthetic/operations/" + str(uuid4()),
     "/synthetic/operations/{attempt}", "getSyntheticOperation"),
    ("I-04", "synthetic-inventory", "GET", "/synthetic/inventory/sku-1",
     "/synthetic/inventory/{sku}", "getSyntheticInventory"),
    ("C-01", "synthetic-carts", "POST", "/synthetic/carts",
     "/synthetic/carts", "createGuestCart"),
    ("C-02", "synthetic-carts", "GET", "/synthetic/carts/cart_" + "a" * 32,
     "/synthetic/carts/{cart_id}", "getGuestCart"),
    ("C-03", "synthetic-carts", "POST", "/synthetic/carts/cart_" + "a" * 32 + "/line-items",
     "/synthetic/carts/{cart_id}/line-items", "addGuestCartItem"),
    ("C-04", "synthetic-carts", "POST", "/synthetic/carts/cart_" + "a" * 32 + "/line-items/item_" + "b" * 32,
     "/synthetic/carts/{cart_id}/line-items/{item_id}", "updateGuestCartItem"),
    ("C-05", "synthetic-carts", "DELETE", "/synthetic/carts/cart_" + "a" * 32 + "/line-items/item_" + "b" * 32,
     "/synthetic/carts/{cart_id}/line-items/{item_id}", "removeGuestCartItem"),
    ("C-06", "synthetic-carts", "POST", "/synthetic/carts/cart_" + "a" * 32 + "/complete",
     "/synthetic/carts/{cart_id}/complete", "completeGuestCart"),
    ("C-07", "synthetic-carts", "GET", "/synthetic/orders/order_" + "c" * 32,
     "/synthetic/orders/{order_id}", "getSyntheticOrder"),
    ("C-08", "synthetic-carts", "POST", "/synthetic/orders/order_" + "c" * 32 + "/cancel",
     "/synthetic/orders/{order_id}/cancel", "cancelSyntheticOrder"),
    ("C-09", "synthetic-carts", "GET", "/synthetic/carts/cart_" + "a" * 32 + "/operations/" + str(uuid4()),
     "/synthetic/carts/{cart_id}/operations/{attempt}", "getCartOperation"),
    ("M-01", "medusa-native-cart", "POST", "/store/carts", "/store/carts", "PostCarts"),
    ("M-02", "medusa-native-cart", "GET", "/store/carts/cart_" + "a" * 32,
     "/store/carts/{id}", "GetCartsId"),
    ("M-03", "medusa-native-cart", "POST", "/store/carts/cart_" + "a" * 32 + "/line-items",
     "/store/carts/{id}/line-items", "PostCartsIdLineItems"),
    ("M-04", "medusa-native-cart", "POST", "/store/carts/cart_" + "a" * 32 + "/line-items/" + "b" * 32,
     "/store/carts/{id}/line-items/{line_id}", "PostCartsIdLineItemsLine_id"),
    ("M-05", "medusa-native-cart", "DELETE", "/store/carts/cart_" + "a" * 32 + "/line-items/" + "b" * 32,
     "/store/carts/{id}/line-items/{line_id}", "DeleteCartsIdLineItemsLine_id"),
    ("M-06", "medusa-native-cart", "POST", "/store/carts/cart_" + "a" * 32 + "/complete",
     "/store/carts/{id}/complete", "PostCartsIdComplete"),
    ("M-07", "medusa-native-cart", "GET", "/store/orders/order_" + "c" * 32,
     "/store/orders/{id}", "GetOrdersId"),
)


@pytest.mark.parametrize("case", PINNED_HTTP_CASES, ids=lambda case: case[0])
def test_each_pinned_http_operation_has_unique_original_request_proof(case):
    """逐一核對二十條 HTTP 入口的 Method／Path／Operation，不能只抽測路由。"""
    _, platform, method, path, template, operation = case
    request = original_request(path=path, method=method)
    if method == "GET":
        request = replace(request, body=b"")
    proof = derive_verified_operation(request)
    assert (proof.platform, proof.method, proof.path_template, proof.operation_id) == (
        platform, method, template, operation,
    )
    assert proof.request_path == path


def test_pinned_http_matrix_exhausts_all_three_contract_registries():
    """固定二十路由來源集合；規格新增操作時必須更新逐項驗收而不能默默繞過。"""
    from deception.domains.ecommerce.cart_http import cart_specification
    from deception.domains.ecommerce.inventory_http import inventory_specification

    actual = {
        (platform, method.upper(), "/synthetic" + path, data["operationId"])
        for platform, specification in (
            ("synthetic-inventory", inventory_specification()),
            ("synthetic-carts", cart_specification()),
        )
        for path, methods in specification["paths"].items()
        for method, data in methods.items()
    }
    actual.update(("medusa-native-cart", method.upper(), path, operation)
                  for path, method, operation in _pinned_medusa_operations())
    expected = {(platform, method, template, operation)
                for _, platform, method, _, template, operation in PINNED_HTTP_CASES}
    assert len(PINNED_HTTP_CASES) == len(expected) == 20
    assert actual == expected


def test_pinned_medusa_operations_match_reviewed_source_bytes():
    """逐項比對 SHA-256 固定的官方 Medusa 來源與 wheel 內建七路由，防止手抄漂移。"""
    from pathlib import Path

    from deception.domains.ecommerce.medusa_cart_projection import load_contract

    source = (Path(__file__).resolve().parents[1]
              / "domains/ecommerce/inputs/sources/medusa/openapi.yaml")
    _, specification = load_contract(source)
    from_reviewed_source = tuple(
        (path, method, operation["operationId"])
        for path, methods in specification["paths"].items()
        for method, operation in methods.items()
    )
    assert _pinned_medusa_operations() == from_reviewed_source


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


@pytest.mark.parametrize("path,operation,resource", [
    ("/synthetic/inventory/sku-1", "getSyntheticInventory", "sku-1"),
    ("/synthetic/inventory/品項+特別:版", "getSyntheticInventory", "品項+特別:版"),
    ("/synthetic/operations/" + str(uuid4()), "getSyntheticOperation", None),
])
def test_inventory_reads_derive_exact_get_without_rpc_selected_resource(path, operation, resource):
    """I-03／I-04 由原始 GET 路徑固定 SKU 或 UUID，保留合法 Unicode SKU。"""
    request = replace(original_request(path=path, method="GET"), body=b"")
    proof = derive_verified_operation(request)
    query = decode_verified_inventory_read(proof, raw_path=request.raw_path, raw_body=b"")
    assert query.operation == operation
    assert query.resource_id == (resource if resource is not None else path.rsplit("/", 1)[-1])
    assert (query.attempt_id is not None) == (operation == "getSyntheticOperation")
    with pytest.raises(OperationBindingError, match="snapshot_mismatch"):
        decode_verified_inventory_read(proof, raw_path=request.raw_path, raw_body=b"{}")
    with pytest.raises(OperationBindingError, match="snapshot_mismatch"):
        decode_verified_inventory_read(proof, raw_path=request.raw_path + b"x", raw_body=b"")
    with pytest.raises(OperationBindingError, match="operation_or_resource_denied"):
        decode_verified_inventory_read(replace(proof, operation_id="reserveSyntheticInventory"),
                                       raw_path=request.raw_path, raw_body=b"")


@pytest.mark.parametrize("encoded,sku", [
    ("%E5%93%81%E9%A0%85+%E7%89%B9%E5%88%A5:%E7%89%88", "品項+特別:版"),
    ("sku%20with%20space", "sku with space"),
    ("%F0%9F%93%A6", "📦"),
])
def test_inventory_sku_accepts_only_canonical_client_url_encoding(encoded, sku):
    """I-04 標準 HTTP URL 只能以唯一 percent 編碼綁回相同 SKU／Proof。"""
    path = "/synthetic/inventory/" + sku
    raw_path = ("/synthetic/inventory/" + encoded).encode("ascii")
    request = replace(original_request(path=path, method="GET"),
                      raw_path=raw_path, body=b"")
    proof = derive_verified_operation(request)
    assert proof.request_path == "/synthetic/inventory/" + encoded
    assert decode_verified_inventory_read(
        proof, raw_path=raw_path, raw_body=b"").resource_id == sku
    with pytest.raises(OperationBindingError, match="snapshot_mismatch"):
        decode_verified_inventory_read(proof, raw_path=path.encode("utf-8") + b"x", raw_body=b"")
    with pytest.raises(OperationBindingError, match="snapshot_mismatch"):
        decode_verified_inventory_read(proof, raw_path=path.encode("utf-8"), raw_body=b"")


@pytest.mark.parametrize("encoded", [
    "sku%2Falternate", "sku%2falternate", "sku%2e", "%73ku", "sku%25",
    "sku%3Fother", "sku%23other", "sku%252F", "sku%", "%E5%93",
    "%e5%93%81", "品%E9%A0%85", "sku%5Cbackslash", "..%2e",
])
def test_inventory_sku_rejects_alias_invalid_utf8_and_encoded_separators(encoded):
    """I-04 拒絕路徑拆分、大小寫、雙重編碼、混搭與截斷 UTF-8。"""
    path = "/synthetic/inventory/" + unquote(encoded)
    request = replace(original_request(path=path, method="GET"),
                      raw_path=("/synthetic/inventory/" + encoded).encode("utf-8"), body=b"")
    with pytest.raises(OperationBindingError):
        proof = derive_verified_operation(request)
        decode_verified_inventory_read(proof, raw_path=request.raw_path, raw_body=b"")


@pytest.mark.parametrize("path", [
    "/synthetic/inventory/..",
    "/synthetic/inventory/sku%2Faltered",
    "/synthetic/inventory/sku?change",
    "/synthetic/inventory/" + "s" * 129,
    "/synthetic/operations/not-a-uuid",
    "/synthetic/operations/00000000-0000-0000-0000-000000000000",
])
def test_inventory_read_rejects_ambiguous_sku_and_noncanonical_attempt(path):
    """拒絕正規化歧義、過長 SKU、無效或非 UUID4 的 Operation 查詢。"""
    request = replace(original_request(path=path, method="GET"), body=b"")
    proof = derive_verified_operation(request)
    with pytest.raises(OperationBindingError, match="operation_or_resource_denied"):
        decode_verified_inventory_read(proof, raw_path=request.raw_path, raw_body=b"")


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


@pytest.mark.parametrize("prefix,operation,identifier", [
    ("/store/carts/", "GetCartsId", "cart_" + "a" * 32),
    ("/store/orders/", "GetOrdersId", "order_" + "b" * 32),
])
def test_medusa_read_decoder_binds_native_resource_and_exact_empty_body(prefix, operation, identifier):
    """M-02／M-07 原生 GET 只能讀取與固定 Proof 相同的派生 Cart／Order。"""
    path = prefix + identifier
    incoming = replace(original_request(path=path, method="GET"), body=b"")
    proof = derive_verified_operation(incoming)
    read = decode_verified_medusa_read(
        proof, resource_id=identifier, raw_path=incoming.raw_path, raw_body=b"",
    )
    assert (read.operation, read.resource_id, read.attempt_id) == (operation, identifier, None)
    for resource, raw_path, raw_body in (
        ("cart_" + "c" * 32, incoming.raw_path, b""),
        (identifier, incoming.raw_path + b"/", b""),
        (identifier, incoming.raw_path, b"{}"),
        (identifier, incoming.raw_path.replace(b"/store/", b"/synthetic/"), b""),
    ):
        with pytest.raises(OperationBindingError):
            decode_verified_medusa_read(
                proof, resource_id=resource, raw_path=raw_path, raw_body=raw_body,
            )
    with pytest.raises(OperationBindingError):
        decode_verified_medusa_read(
            replace(proof, platform="synthetic-carts"), resource_id=identifier,
            raw_path=incoming.raw_path, raw_body=b"",
        )
