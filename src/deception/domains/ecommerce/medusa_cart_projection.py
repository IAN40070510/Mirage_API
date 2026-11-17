"""固定 Medusa v2.22.4 購物車契約與明確的合成資料投影，不從 schema 猜資料。"""

from copy import deepcopy
from decimal import Decimal
import hashlib
from pathlib import Path

import yaml


SOURCE_SHA256 = "ced300a2de92b9829e6e600964588e894b760f07f8d79c1df657e1abe0529058"
NATIVE_OPERATIONS = {
    "/store/carts": ("post",),
    "/store/carts/{id}": ("get",),
    "/store/carts/{id}/line-items": ("post",),
    "/store/carts/{id}/line-items/{line_id}": ("post", "delete"),
    "/store/carts/{id}/complete": ("post",),
    "/store/orders/{id}": ("get",),
}
TOTAL_FIELDS = (
    "original_item_total", "original_item_subtotal", "original_item_tax_total", "item_total", "item_subtotal",
    "item_tax_total", "original_total", "original_subtotal", "original_tax_total", "total", "subtotal", "tax_total",
    "discount_total", "discount_tax_total", "gift_card_total", "gift_card_tax_total", "shipping_total",
    "shipping_subtotal", "shipping_tax_total", "original_shipping_total", "original_shipping_subtotal",
    "original_shipping_tax_total",
)
VALUE_TOTALS = frozenset({"original_item_total", "original_item_subtotal", "item_total", "item_subtotal",
                          "original_total", "original_subtotal", "total", "subtotal"})


def load_contract(source: Path) -> tuple[dict, dict]:
    """核對固定來源 bytes，保留官方規格並建立只放寬匿名 customer_id 的獨立有效投影。"""
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
        raise ValueError("Medusa cart source hash is not the reviewed version")
    official = yaml.safe_load(raw)
    official["paths"] = {path: {method: official["paths"][path][method] for method in methods}
                         for path, methods in NATIVE_OPERATIONS.items()}
    effective = deepcopy(official)
    effective["components"]["schemas"]["StoreOrder"]["properties"]["customer_id"]["nullable"] = True
    return official, effective


def amount(minor: int) -> float:
    """把已驗證的 USD 整數分轉為 Medusa v2 主貨幣單位；不重新計價或讀真實價格。"""
    if type(minor) is not int or not 0 <= minor <= 9_000_000_000_000:
        raise ValueError("unsupported synthetic money amount")
    return float(Decimal(minor) / Decimal(100))


def totals(minor: int) -> dict:
    """投影無稅、運費、折扣及禮卡的固定合成價格政策。"""
    value = amount(minor)
    return {name: value if name in VALUE_TOTALS else 0 for name in TOTAL_FIELDS}


def cart_view(cart: dict, context: dict) -> dict:
    """將內部購物車投影成 Medusa 回應，隱藏版本、hash、業務鍵及世界身份。

    已保存原生時間的格式或順序不合法時先拒絕，不輸出看似合法的回應或修補歷史。
    """
    from .native_time import validate_native_times

    validate_native_times(context)
    base = {"id": cart["id"], "currency_code": cart["currency_code"], "promotions": [], **totals(cart["total"]),
            "region_id": context["region_id"], "sales_channel_id": context["sales_channel_id"],
            "email": context["email"], "metadata": deepcopy(context["metadata"]),
            "created_at": context["created_at"], "updated_at": context["updated_at"]}
    base["items"] = [cart_item(item, cart["id"], context) for item in cart["items"]]
    if cart["status"] == "completed":
        base["completed_at"] = context["order_created_at"]
    return base


def cart_item(item: dict, cart_id: str, context: dict) -> dict:
    """建立原生品項欄位；cart 關聯只放身份，不遞迴複製整張購物車。"""
    definition = context["catalog"][item["variant_id"]]
    return {"id": item["id"], "cart_id": cart_id, "cart": {"id": cart_id},
            "title": definition.get("title", definition["sku"]), "variant_id": item["variant_id"],
            "product_id": definition.get("product_id", "synthetic-product"),
            "variant_title": definition.get("variant_title", ""),
            "variant_sku": item["sku"], "unit_price": amount(item["unit_price"]), "quantity": item["quantity"],
            "requires_shipping": False, "is_discountable": False, "is_tax_inclusive": False,
            "metadata": {}, **totals(item["unit_price"] * item["quantity"])}


def order_item(item: dict, context: dict) -> dict:
    """投影未履約、未退款的合成訂單品項；缺少的描述用明確空字串，不推測商店內容。"""
    definition = context["catalog"][item["variant_id"]]
    created, updated = context.get("order_created_at", context["created_at"]), context["updated_at"]
    result = {"id": item["id"], "title": definition.get("title", definition["sku"]), "metadata": {},
              "created_at": created, "updated_at": updated, "variant_id": item["variant_id"],
              "product_id": definition.get("product_id", "synthetic-product"),
              "product_title": definition.get("title", definition["sku"]), "variant_sku": item["sku"],
              "variant_option_values": {},
              "requires_shipping": False, "is_discountable": False, "is_tax_inclusive": False,
              "unit_price": amount(item["unit_price"]), "quantity": item["quantity"],
              "refundable_total": 0, "refundable_total_per_unit": 0,
              **totals(item["unit_price"] * item["quantity"])}
    result.update({name: "" for name in ("subtitle", "thumbnail", "product_description", "product_subtitle",
        "product_type_id", "product_type", "product_collection", "product_handle", "variant_barcode", "variant_title")})
    result["product_handle"] = definition.get("handle", "")
    result["variant_title"] = definition.get("variant_title", "")
    result["detail"] = {"id": "orditem_" + item["id"], "item_id": item["id"], "item": {"id": item["id"]},
        "quantity": item["quantity"], "metadata": {}, "created_at": created, "updated_at": updated,
        **{name: 0 for name in ("fulfilled_quantity", "delivered_quantity", "shipped_quantity",
                               "return_requested_quantity", "return_received_quantity", "return_dismissed_quantity",
                               "written_off_quantity")}}
    return result


def order_view(order: dict, context: dict) -> dict:
    """投影待付款、未履約合成訂單；匿名 customer_id 為 null，絕不捏造顧客帳號或已付款事實。

    已保存時間必須為一致的 UTC 毫秒表示且符合建立／訂單／更新順序，失敗時拒絕投影。
    """
    from .native_time import validate_native_times

    validate_native_times(context)
    value = amount(order["total"])
    cancelled = order["status"] == "cancelled"
    return {"id": order["id"], "items": [order_item(item, context) for item in order["items"]],
        "shipping_methods": [], "region_id": context["region_id"], "sales_channel_id": context["sales_channel_id"],
        "customer_id": None, "email": context["email"], "currency_code": order["currency_code"],
        "status": "canceled" if cancelled else "pending", "payment_status": "not_paid",
        "fulfillment_status": "canceled" if cancelled else "not_fulfilled",
        "created_at": context.get("order_created_at", context["created_at"]), "updated_at": context["updated_at"],
        **totals(order["total"]), "item_discount_total": 0, "shipping_discount_total": 0, "credit_line_total": 0,
        "summary": {"pending_difference": 0 if cancelled else value, "current_order_total": value,
                    "original_order_total": value, "transaction_total": 0, "paid_total": 0,
                    "refunded_total": 0, "accounting_total": value}}
