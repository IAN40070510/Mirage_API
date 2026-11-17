"""合成庫存事件的並行安全、冪等、取消與提交恢復驗收。"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from unittest.mock import patch
from uuid import uuid4

import pytest

from deception.domains.ecommerce.inventory import SyntheticInventory
from deception.world import PostgresAdmissionControl, WorldStoreError
from test_session_worlds import binding as read_binding
from test_postgres_conformance import isolated_test_dsn


def binding(epoch=1):
    """只有已驗證顧客的測試 binding 取得合成庫存能力。"""
    return read_binding(epoch).model_copy(update={"access_mode": "inventory"})


def inventory(dsn):
    """以兩件合成庫存建立固定可信 Session 的世界。"""
    service = SyntheticInventory(dsn)
    service.resolve(binding(), {"inventory": {"sku-test": 2}, "reservations": {}}, now=100, ttl=60)
    return service


def reserve(service, key="reserve-1", **changes):
    """建立可覆寫的預留輸入，每次呼叫使用新提交 ID 以模擬合法重試。"""
    values = dict(sku="sku-test", quantity=1, expected_version=1, idempotency_key=key,
                  commit_attempt_id=uuid4(), now=101)
    values.update(changes)
    return service.reserve(binding(), **values)


def test_reservation_and_cancellation_are_idempotent(isolated_test_dsn):
    """相同內容重試沿用提交結果，重複取消不會歸還第二次庫存。"""
    import psycopg

    service = inventory(isolated_test_dsn)
    first = reserve(service)
    replay = reserve(service, expected_version=99)
    assert replay == replace(first, replayed=True)
    with pytest.raises(WorldStoreError, match="idempotency_content_conflict"):
        reserve(service, quantity=2)
    cancelled = service.cancel(binding(), reservation_id=first.result["reservation_id"], expected_version=2,
                               idempotency_key="cancel-1", commit_attempt_id=uuid4(), now=102)
    assert cancelled.status == "committed" and cancelled.state_version == 3
    repeated = service.cancel(binding(), reservation_id=first.result["reservation_id"], expected_version=3,
                              idempotency_key="cancel-2", commit_attempt_id=uuid4(), now=103)
    assert repeated.status == "rejected" and repeated.state_version == 3
    assert service.inspect_binding(binding(), now=104).state["inventory"] == {"sku-test": 2}
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM world_events").fetchone() == (2,)
        assert connection.execute("SELECT watermark_version FROM session_world_bindings").fetchone() == (3,)


def test_concurrent_reservations_do_not_oversell(isolated_test_dsn):
    """兩個 Instance 以同一版本預留全部庫存時，只准一個提交。"""
    service = inventory(isolated_test_dsn)

    def submit(index):
        """由獨立服務物件提交不同業務鍵，記錄合法 CAS 衝突。"""
        try:
            return reserve(SyntheticInventory(isolated_test_dsn), key=f"key-{index}", quantity=2).status
        except WorldStoreError as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sorted(executor.map(submit, [1, 2])) == ["committed", "version_conflict"]
    rejected = reserve(service, key="insufficient", expected_version=2)
    assert rejected.status == "rejected"
    assert service.inspect_binding(binding(), now=103).state["inventory"] == {"sku-test": 0}


@pytest.mark.parametrize("stop", ["epoch", "cutover", "emergency", "expired"])
def test_inventory_rejects_invalid_world_authority(isolated_test_dsn, stop):
    """舊 epoch、封存、緊急撤銷或過期時拒絕產生任何庫存事件。"""
    import psycopg

    service = inventory(isolated_test_dsn)
    current = service.inspect_binding(binding(), now=100)
    control = PostgresAdmissionControl(isolated_test_dsn)
    if stop == "epoch":
        service.resolve(binding(2), {"inventory": {"sku-test": 2}}, now=101, ttl=60)
    elif stop == "cutover":
        control.cutover(current.scope.world_generation_id)
    elif stop == "emergency":
        control.emergency_revoke(current.scope.world_generation_id)
    with pytest.raises(WorldStoreError):
        reserve(service, now=160 if stop == "expired" else 102)
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM world_events").fetchone() == (0,)


def test_inventory_commit_result_loss_has_one_event(isolated_test_dsn):
    """提交成功卻失去回覆時，唯讀查詢與業務鍵重試都指向同一結果且只有一個事件。"""
    import psycopg

    service = inventory(isolated_test_dsn)
    attempt = uuid4()
    connection = psycopg.connect(isolated_test_dsn)

    class LostResult:
        def __enter__(self):
            """交出真實連線給完整事件交易。"""
            return connection.__enter__()

        def __exit__(self, *args):
            """先提交真實 SQL，再丟失成功結果。"""
            connection.__exit__(*args)
            raise psycopg.OperationalError("injected lost operation result")

    with patch.object(service, "_connection", return_value=LostResult()):
        with pytest.raises(psycopg.OperationalError):
            reserve(service, commit_attempt_id=attempt)
    observer = SyntheticInventory(isolated_test_dsn)
    recovered = observer.operation_result(binding(), attempt, now=102)
    assert recovered.status == "committed" and recovered.state_version == 2
    assert reserve(observer) == recovered
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM world_events").fetchone() == (1,)


def test_inventory_idempotent_retry_requires_unexpired_world(isolated_test_dsn):
    """原業務鍵已成功也不能繞過世界到期，拒絕重試不改庫存或新增事件。"""
    import psycopg

    service = inventory(isolated_test_dsn)
    original = reserve(service)
    assert reserve(service, now=159).replayed
    with pytest.raises(WorldStoreError, match="session_world_expired"):
        reserve(service, now=160)
    with psycopg.connect(isolated_test_dsn) as observer:
        assert observer.execute("SELECT count(*) FROM world_events").fetchone() == (1,)
        assert observer.execute("SELECT version,state_hash FROM world_snapshots").fetchone() == (
            original.state_version, original.state_hash)
