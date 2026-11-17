"""原生 Medusa 合成投影、官方／有效契約差異與金額單位驗收。"""

from pathlib import Path

import pytest
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT4
from openapi_schema_validator import OAS30Validator

from deception.domains.ecommerce.medusa_cart_projection import amount, cart_view, load_contract, order_view


@pytest.fixture(scope="module")
def contracts():
    """讀取固定來源一次，保留兩份獨立契約供差異與 schema 驗收。"""
    source = Path(__file__).resolve().parents[1] / "domains/ecommerce/inputs/sources/medusa/openapi.yaml"
    return load_contract(source)


def context():
    """提供純合成的地區、時間與部署 catalog，不含客戶或真實商店資料。"""
    return dict(region_id="reg_mirage_usd", sales_channel_id="sc_mirage", email="guest@example.invalid", metadata={},
        created_at="2026-11-16T00:00:00.000Z", updated_at="2026-11-16T00:00:01.000Z",
        catalog={"variant-test": {"sku": "SKU-TEST", "unit_price": 2509, "title": "Synthetic product"}})


def entity():
    """建立未預留的兩件合成商品，價格以整數分保留精確性。"""
    return dict(id="cart_" + "a" * 32, items=[dict(id="item_test", variant_id="variant-test", sku="SKU-TEST",
        unit_price=2509, quantity=2)], currency_code="usd", total=5018, status="active")


def errors(spec, name, payload):
    """依原始 OpenAPI 3.0 nullable 語意驗證資料，不把有效投影當成官方原文。"""
    registry = Registry().with_resource("urn:mirage:medusa-spec", Resource.from_contents(spec, default_specification=DRAFT4))
    schema = {"$ref": "urn:mirage:medusa-spec#/components/schemas/" + name}
    return list(OAS30Validator(schema, registry=registry).iter_errors(payload))


def test_cart_projection_passes_original_contract_and_hides_internal_state(contracts):
    """購物車原生投影直接通過固定官方 schema，元／分轉換且不洩漏內部控制欄位。"""
    cart = entity()
    cart["state_version"] = 99
    result = cart_view(cart, context())
    assert result["total"] == 50.18 and result["items"][0]["unit_price"] == 25.09
    assert not errors(contracts[0], "StoreCartResponse", {"cart": result})
    assert "state_version" not in result and "status" not in result
    assert result["items"][0]["cart"] == {"id": cart["id"]}


def test_guest_order_has_explicit_nullable_deviation_and_no_fake_payment(contracts):
    """匿名 customer_id 只通過核准的有效投影，訂單不捏造顧客或已付款紀錄。"""
    order = {**entity(), "id": "order_" + "b" * 32, "cart_id": "cart_" + "a" * 32, "status": "placed"}
    result = {"order": order_view(order, context())}
    assert errors(contracts[0], "StoreOrderResponse", result)
    assert not errors(contracts[1], "StoreOrderResponse", result)
    assert result["order"]["customer_id"] is None
    assert result["order"]["payment_status"] == "not_paid"
    assert result["order"]["summary"]["paid_total"] == 0
    assert not contracts[0]["components"]["schemas"]["StoreOrder"]["properties"]["customer_id"].get("nullable")


@pytest.mark.parametrize("value", [True, -1, 1.5, 10**20])
def test_money_projection_rejects_ambiguous_or_unbounded_values(value):
    """價格不接受 bool、浮點、負值或超出原生投影政策的數字。"""
    with pytest.raises(ValueError):
        amount(value)


def test_contract_rejects_unreviewed_source(tmp_path):
    """來源檔異動後必須重新審查，不能沿用已固定的規格批准。"""
    source = tmp_path / "modified.yaml"
    source.write_text("openapi: 3.0.0", encoding="utf-8")
    with pytest.raises(ValueError, match="source hash"):
        load_contract(source)
