"""未登入的資源 ID 購物車、合成訂單與庫存連續性驗收。"""

from dataclasses import replace
from uuid import uuid4

import pytest

from deception.domains.ecommerce.carts import SyntheticCarts
from deception.world import PostgresAdmissionControl, WorldStoreError
from test_postgres_conformance import isolated_test_dsn
from test_session_worlds import binding


def create(service, **changes):
    """以唯讀匿名建立者提出新購物車，權威 catalog 由服務端固定提供。"""
    values = dict(catalog={"variant-test": {"sku": "SKU", "unit_price": 250}}, inventory={"SKU": 5},
                  idempotency_key=uuid4(), commit_attempt_id=uuid4(), now=101, ttl=60)
    values.update(changes)
    service.resolve(binding(), {"public_catalog": "fixed"}, now=100, ttl=600)
    return service.create_cart(binding(), **values)


def mutate(service, resource, action, command, version, key):
    """提交指定資源的合成事件，價格及庫存不由 Client 指定。"""
    return service.mutate_cart(resource, action=action, command=command, expected_version=version,
                               idempotency_key=key, commit_attempt_id=uuid4(), now=102)


def test_guest_cart_add_remove_does_not_reserve_inventory(isolated_test_dsn):
    """未登入者以 cart.id 延續購物車，增減品項只改購物車，不占庫存。"""
    service = SyntheticCarts(isolated_test_dsn)
    created = create(service)
    cart_id = created.outcome.result["id"]
    resource = service.resource_binding(cart_id, environment_id="test", deployment_id="local", now=102)
    assert resource.access_mode == "cart" and created.binding == resource
    added = mutate(service, resource, "add", {"variant_id": "variant-test", "quantity": 2}, 1, "add-1")
    assert added.result["total"] == 500
    assert service.inspect_binding(resource, now=102).state["inventory"] == {"SKU": 5}
    item_id = added.result["items"][0]["id"]
    updated = mutate(service, resource, "update", {"item_id": item_id, "quantity": 3}, 2, "update-1")
    assert updated.result["total"] == 750
    removed = mutate(service, resource, "remove", {"item_id": item_id}, 3, "remove-1")
    assert removed.result["items"] == [] and removed.result["total"] == 0
    assert service.inspect_binding(resource, now=103).state["inventory"] == {"SKU": 5}


def test_guest_checkout_reserves_once_and_cancel_releases_once(isolated_test_dsn):
    """合成下單才扣可用庫存，取消訂單歸還一次，所有重試重用原結果。"""
    service = SyntheticCarts(isolated_test_dsn)
    created = create(service)
    resource = created.binding
    added = mutate(service, resource, "add", {"variant_id": "variant-test", "quantity": 2}, 1, "add")
    order = mutate(service, resource, "complete", {}, 2, "checkout")
    assert order.result["status"] == "placed" and order.result["total"] == 500
    assert mutate(service, resource, "complete", {}, 2, "checkout") == replace(order, replayed=True)
    assert service.inspect_binding(resource, now=103).state["inventory"] == {"SKU": 3}
    order_binding = service.resource_binding(order.result["id"], environment_id="test", deployment_id="local", now=103)
    cancelled = mutate(service, order_binding, "cancel_order", {}, 3, "cancel")
    assert cancelled.result["status"] == "cancelled"
    assert service.inspect_binding(resource, now=104).state["inventory"] == {"SKU": 5}
    assert mutate(service, order_binding, "cancel_order", {}, 3, "cancel") == replace(cancelled, replayed=True)
    refused = mutate(service, order_binding, "cancel_order", {}, 4, "second-cancel")
    assert refused.status == "rejected"


def test_guest_resource_scope_and_creation_idempotency(isolated_test_dsn):
    """同一建立鍵返回同一 cart，不同 cart 及部署無法藉指定 ID 進入彼此世界。"""
    service = SyntheticCarts(isolated_test_dsn)
    key = uuid4()
    first = create(service, idempotency_key=key)
    repeat = create(service, idempotency_key=key)
    second = create(service)
    assert repeat.outcome == replace(first.outcome, replayed=True)
    assert first.binding.session_id != second.binding.session_id
    with pytest.raises(WorldStoreError):
        service.resource_binding(first.outcome.result["id"], environment_id="other", deployment_id="local", now=102)
    fake = second.binding.model_copy(update={"resource_id": first.outcome.result["id"]})
    assert mutate(service, fake, "add", {"variant_id": "variant-test", "quantity": 1}, 1, "fake").status == "rejected"
    PostgresAdmissionControl(isolated_test_dsn).emergency_revoke(
        service.inspect_binding(first.binding, now=102).scope.world_generation_id)
    with pytest.raises(WorldStoreError):
        service.resource_binding(first.outcome.result["id"], environment_id="test", deployment_id="local", now=103)


def test_native_creation_context_is_atomic_and_retained_for_retries(isolated_test_dsn):
    """初始品項與原生上下文同交易保存，後續更新不改舊回應，相同建立鍵換內容拒絕。"""
    import psycopg

    service = SyntheticCarts(isolated_test_dsn)
    key = uuid4()
    arguments = dict(idempotency_key=key, creation_digest="a" * 64,
        native_context={"region_id": "reg_mirage_usd", "sales_channel_id": "sc_mirage",
                        "email": "guest@example.invalid", "metadata": {}},
        initial_items=[{"variant_id": "variant-test", "quantity": 2}])
    created = create(service, **arguments)
    assert created.outcome.result["total"] == 500
    assert service.inspect_binding(created.binding, now=102).state["inventory"] == {"SKU": 5}
    original = service.native_response_context(created.binding, created.outcome.commit_attempt_id, now=102)
    item = created.outcome.result["items"][0]["id"]
    mutate(service, created.binding, "update", {"item_id": item, "quantity": 3}, 1, "update-native")
    assert service.native_response_context(created.binding, created.outcome.commit_attempt_id, now=103) == original
    assert create(service, **arguments).outcome.result == created.outcome.result
    with pytest.raises(WorldStoreError, match="content_conflict"):
        create(service, **{**arguments, "creation_digest": "b" * 64})
    with psycopg.connect(isolated_test_dsn) as connection:
        connection.execute("UPDATE native_response_contexts SET context=context || %s::jsonb "
            "WHERE commit_attempt_id=%s", ('{"email":"changed@example.invalid"}', created.outcome.commit_attempt_id))
    with pytest.raises(WorldStoreError, match="corrupted"):
        service.native_response_context(created.binding, created.outcome.commit_attempt_id, now=104)


def test_native_initial_item_failure_does_not_leave_cart_resources(isolated_test_dsn):
    """建立時庫存不足會回滾整張 cart、收據與上下文，不留下半完成資源。"""
    import psycopg

    service = SyntheticCarts(isolated_test_dsn)
    with pytest.raises(WorldStoreError, match="insufficient"):
        create(service, initial_items=[{"variant_id": "variant-test", "quantity": 99}])
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM synthetic_resources").fetchone() == (0,)
        assert connection.execute("SELECT count(*) FROM world_commit_receipts").fetchone() == (0,)
