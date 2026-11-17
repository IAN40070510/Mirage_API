"""驗證原生資源邏輯時間單調、Lease 不變與已提交上下文重播。"""

from copy import deepcopy

import pytest

from test_postgres_conformance import isolated_test_dsn
from deception.domains.ecommerce.carts import SyntheticCarts
from deception.domains.ecommerce import medusa_cart_projection as projection


def cart_service(dsn="unused"):
    """建立時間規則或獨立 PostgreSQL 驗收使用的購物車服務，呼叫時不建立世界。"""
    return SyntheticCarts(dsn)


def test_native_event_time_does_not_move_backwards():
    """接收端時鐘回撥時，已保存資源不能變成 updated_at 早於 created_at。"""
    service = cart_service()
    state = {"orders": {}, "native_context": {"created_at": service._event_time(100), "updated_at": service._event_time(102)}}
    result = service._after_event(deepcopy(state), now=101)
    assert result["native_context"]["updated_at"] == state["native_context"]["updated_at"]


def test_new_order_time_is_not_earlier_than_cart():
    """回撥期間下單仍沿用世界的單調時間，不產生早於購物車的訂單。"""
    service = cart_service()
    state = {"orders": {"order": {}}, "native_context": {"created_at": service._event_time(100), "updated_at": service._event_time(102)}}
    result = service._after_event(state, now=99)
    assert result["native_context"]["order_created_at"] >= result["native_context"]["created_at"]
    assert result["native_context"]["updated_at"] >= result["native_context"]["order_created_at"]


@pytest.mark.parametrize("value", [None, "invalid", "1970-01-01T00:01:40", "1970-01-01T01:01:40.000+01:00"])
def test_invalid_native_time_rejects_without_mutating_proposal(value):
    """時間資料毀損或不是固定 UTC 表示時停止，不把部分更新寫進提案。"""
    service = cart_service()
    state = {"orders": {}, "native_context": {"created_at": value, "updated_at": service._event_time(102)}}
    before = deepcopy(state)
    with pytest.raises(ValueError):
        service._after_event(state, now=103)
    assert state == before


@pytest.mark.parametrize("view", ["cart_view", "order_view"])
@pytest.mark.parametrize("updated,ordered", [(99, None), (102, 99), (102, 103)])
def test_projection_refuses_invalid_saved_time_before_returning_body(view, updated, ordered):
    """唯讀原生回應也拒絕不合法的保存時間，不能只保護新業務寫入。"""
    service = cart_service()
    context = {"created_at": service._event_time(100), "updated_at": service._event_time(updated)}
    if ordered is not None:
        context["order_created_at"] = service._event_time(ordered)
    with pytest.raises(ValueError, match="time order"):
        getattr(projection, view)({}, context)


def test_persisted_native_time_order_survives_checkout_cancel_and_replay(isolated_test_dsn):
    """在真實 PG 交易確認回撥下單／取消仍單調，原生重播上下文與原收據版本保持不變。"""
    from uuid import uuid4
    from test_guest_carts import create

    service = cart_service(isolated_test_dsn)
    created = create(service, native_context={"region_id": "reg_synthetic", "sales_channel_id": "sc_synthetic",
        "email": None, "metadata": {}}, initial_items=[{"variant_id": "variant-test", "quantity": 1}])
    binding = created.binding
    original_expiry = service.inspect_binding(binding, now=102).expires_at
    original = service.native_response_context(binding, created.outcome.commit_attempt_id, now=102)
    item = created.outcome.result["items"][0]["id"]
    updated = service.mutate_cart(binding, action="update", command={"item_id": item, "quantity": 2},
        expected_version=1, idempotency_key="clock-update", commit_attempt_id=uuid4(), now=104)
    assert updated.status == "committed"
    order = service.mutate_cart(binding, action="complete", command={}, expected_version=2,
        idempotency_key="clock-complete", commit_attempt_id=uuid4(), now=103)
    assert order.status == "committed"
    context = service.native_response_context(binding, order.commit_attempt_id, now=103)
    assert context["order_created_at"] == context["updated_at"] == service._event_time(104)
    assert service.native_response_context(binding, created.outcome.commit_attempt_id, now=103) == original
    order_binding = service.resource_binding(order.result["id"], environment_id="test", deployment_id="local", now=102)
    cancelled = service.mutate_cart(order_binding, action="cancel_order", command={}, expected_version=3,
        idempotency_key="clock-cancel", commit_attempt_id=uuid4(), now=102)
    assert cancelled.status == "committed"
    replay = service.mutate_cart(binding, action="complete", command={}, expected_version=2,
        idempotency_key="clock-complete", commit_attempt_id=uuid4(), now=105)
    assert replay.replayed and replay.state_version == order.state_version
    assert service.native_response_context(binding, replay.commit_attempt_id, now=105) == context
    saved = service.inspect_binding(binding, now=105)
    assert saved.state["native_context"]["updated_at"] == service._event_time(104)
    assert saved.state["inventory"] == {"SKU": 5}
    assert saved.expires_at == original_expiry


@pytest.mark.parametrize("created,updated,ordered", [(102, 100, None), (100, 102, 99), (100, 102, 103)])
def test_saved_invalid_time_order_is_not_silently_repaired(created, updated, ordered):
    """舊資料已出現更新早於建立或訂單超出邊界時拒絕，不回填假的歷史時間。"""
    service = cart_service()
    context = {"created_at": service._event_time(created), "updated_at": service._event_time(updated)}
    if ordered is not None:
        context["order_created_at"] = service._event_time(ordered)
    state = {"orders": {}, "native_context": context}
    before = deepcopy(state)
    with pytest.raises(ValueError, match="time order"):
        service._after_event(state, now=110)
    assert state == before
