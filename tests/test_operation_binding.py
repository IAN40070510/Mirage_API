"""G3b 固定業務 Operation 由原始 HTTP Snapshot 唯一推導的安全測試。"""

from dataclasses import replace

import pytest

from deception.api.ingress import NormalizedRequest
from deception.security.operation_binding import OperationBindingError, derive_verified_operation


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
