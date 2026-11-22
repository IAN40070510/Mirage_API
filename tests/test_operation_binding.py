"""G3b 固定業務 Operation 由原始 HTTP Snapshot 唯一推導的安全測試。"""

from dataclasses import replace
import json
from uuid import uuid4

import pytest

from deception.api.ingress import NormalizedRequest
from deception.security.operation_binding import (
    OperationBindingError, decode_verified_inventory_mutation, derive_verified_operation,
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
    {"path": "/store/carts", "raw_path": b"/store/carts"},
])
def test_verified_operation_rejects_alias_and_unknown_routes(change):
    """拒絕方法替換、尾斜線、百分比編碼別名、Query 與未核准 Medusa 路由。"""
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
