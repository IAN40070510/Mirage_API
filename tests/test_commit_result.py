"""共用 CommitResult 的五類結果、原子事件、相容轉換與唯讀恢復驗收。"""

from copy import deepcopy
from unittest.mock import patch
from uuid import uuid4

import pytest
from pydantic import ValidationError

from deception.world import CommitResult, PostgresEventWorldStore, WorldScope
from deception.world.commit import operation_result_digest
from deception.world.session import SessionBinding
from test_postgres_conformance import isolated_test_dsn


def counter_add(state, command):
    """提供非電商純提案函式，限制總值並返回已核准的結果，不在 callback 執行 SQL。"""
    proposed = deepcopy(state)
    amount = command["amount"]
    if type(amount) is not int or amount < 1 or proposed["value"] + amount > proposed["limit"]:
        return state, {"code": "counter_limit"}, False
    proposed["value"] += amount
    return proposed, {"value": proposed["value"], "nested": {"tags": ["synthetic"]}}, True


def event_store(dsn):
    """只以部署端設定的同步 handler 及寫入能力建立非電商事件引擎。"""
    return PostgresEventWorldStore(dsn, handlers={"counter.add": counter_add}, write_modes=frozenset({"inventory"}))


def example_scope():
    """建立離線模型測試的固定授權範圍，實際資料庫案例使用伺服器生成的世代。"""
    return WorldScope(environment_id="commit-test", deployment_id="isolated", session_id="session", world_generation_id="generation")


def committed_result():
    """以明確已保存紀錄建立有效標準結果，供反例驗證摘要、來源及不變性。"""
    return CommitResult.from_record(scope=example_scope(), operation="counter.add", idempotency_key="key-1",
        status="committed", result={"value": 1, "nested": {"tags": ["synthetic"]}}, state_version=2,
        state_hash="a" * 64, commit_attempt_id=uuid4())


def test_commit_result_is_immutable_and_replay_preserves_original_digest():
    """巢狀 payload 不可改寫，重播狀態及 JSON 往返仍指向相同原始結果與 attempt。"""
    first = committed_result()
    replay = first.model_copy(update={"status": "already_committed", "replayed": True})
    assert replay.result_digest == first.result_digest and replay.commit_attempt_id == first.commit_attempt_id
    assert CommitResult.model_validate_json(first.model_dump_json()) == first
    with pytest.raises(TypeError):
        first.result["nested"]["tags"].append("changed")
    with pytest.raises(ValidationError):
        first.model_copy(update={"result": {"value": 2}})
    assert operation_result_digest(first.result, 2, "a" * 64, first.commit_attempt_id, "committed") == first.result_digest


@pytest.mark.parametrize("changes", [{"status": "committed", "failure_code": "wrong"},
    {"status": "already_committed"}, {"committed_state_hash": None}, {"result_digest": "b" * 64},
    {"result_encoding_version": True}, {"committed_state_version": True},
    {"status": "unverifiable", "failure_code": "commit_unverifiable"}, {"replayed": True}])
def test_commit_result_rejects_contradictory_evidence(changes):
    """成功／未知結果不能混用證據、缺摘要或以 bool 偽造版本。"""
    values = committed_result().model_dump(mode="python")
    values.update(changes)
    with pytest.raises((ValidationError, ValueError)):
        CommitResult.model_validate(values)


@pytest.mark.parametrize("changes", [{"expected_version": True}, {"expected_version": 0},
    {"idempotency_key": "unsafe key"}, {"commit_attempt_id": "not-a-uuid"}, {"now": -1}, {"operation": ""}])
def test_invalid_metadata_never_opens_a_connection(changes):
    """不合法 metadata 必須在任何資料庫或 handler 呼叫前拒絕。"""
    store = event_store("postgresql://unused.invalid/db")
    binding = SessionBinding(environment_id="commit-test", deployment_id="isolated", session_id="session", session_epoch=1, access_mode="inventory")
    values = dict(authorized_scope=example_scope(), operation="counter.add", command={"amount": 1},
        expected_version=1, idempotency_key="key", commit_attempt_id=uuid4(), now=100)
    values.update(changes)
    with patch.object(store, "_connection", side_effect=AssertionError("must not connect")):
        with pytest.raises(ValueError):
            store.commit_event(binding, **values)


@pytest.fixture
def counter(isolated_test_dsn):
    """在專用 schema 建立非電商世界，所有提交都明確帶入已驗證的原 scope。"""
    store = event_store(isolated_test_dsn)
    binding = SessionBinding(environment_id="commit-test", deployment_id="isolated", session_id=uuid4().hex,
                             session_epoch=1, access_mode="inventory")
    snapshot = store.resolve(binding, {"value": 0, "limit": 3}, now=100, ttl=60)
    return store, binding, snapshot.scope


def submit(counter, key="add-1", **changes):
    """固定原授權範圍與純命令；每次新 attempt 讓重播判定來自業務鍵而不是 nonce。"""
    store, binding, scope = counter
    values = dict(authorized_scope=scope, operation="counter.add", command={"amount": 1}, expected_version=1,
                  idempotency_key=key, commit_attempt_id=uuid4(), now=101)
    values.update(changes)
    return store.commit_event(binding, **values)


def test_generic_event_store_returns_committed_replayed_conflict_and_rejected(counter):
    """同一共用交易核心提供四類已知結果；衝突不覆寫，業務拒絕留結果但不新增事件。"""
    import psycopg

    store, binding, scope = counter
    first = submit(counter)
    assert first.status == "committed" and first.committed_state_version == 2 and first.failure_code is None
    replay = submit(counter, expected_version=99)
    assert replay.status == "already_committed" and replay.result_digest == first.result_digest
    assert replay.commit_attempt_id == first.commit_attempt_id and replay.idempotency_key == "add-1"
    stale = submit(counter, key="stale")
    assert stale.status == "conflict" and stale.failure_code == "version_conflict"
    changed = submit(counter, command={"amount": 2})
    assert changed.status == "conflict" and changed.failure_code == "idempotency_content_conflict"
    rejected = submit(counter, key="reject", command={"amount": 4}, expected_version=2)
    assert rejected.status == "rejected" and rejected.failure_code == "counter_limit"
    assert rejected.committed_state_version is None and rejected.observed_state_version == 2
    retried = submit(counter, key="reject", command={"amount": 4}, expected_version=99)
    assert retried.status == "rejected" and retried.replayed and retried.result_digest == rejected.result_digest
    with psycopg.connect(store._dsn) as connection:
        assert connection.execute("SELECT count(*) FROM world_events").fetchone() == (1,)
        assert connection.execute("SELECT count(*) FROM world_operations").fetchone() == (2,)
        assert connection.execute("SELECT count(*) FROM world_commit_receipts").fetchone() == (1,)
    assert store.inspect_binding(binding, now=102).state["value"] == 1


def test_unverifiable_result_preserves_scope_and_attempt_without_retry(counter):
    """儲存故障不假稱未提交，不洩漏例外文字，且只嘗試一次原本的交易。"""
    import psycopg

    store, _, scope = counter
    attempt = uuid4()
    with patch.object(store, "_connection", side_effect=psycopg.OperationalError("secret-dsn-canary")) as connect:
        outcome = submit(counter, commit_attempt_id=attempt)
    assert connect.call_count == 1 and outcome.status == "unverifiable"
    assert outcome.scope == scope and outcome.commit_attempt_id == attempt and outcome.idempotency_key == "add-1"
    assert outcome.committed_state_version is None and outcome.result_digest is None
    assert "secret-dsn" not in outcome.model_dump_json()


@pytest.mark.parametrize("stop", ["scope", "epoch", "expired", "sealed", "mode"])
def test_common_commit_refuses_invalid_authority_without_new_world(counter, stop):
    """錯 scope／epoch／lease／世代／能力均明確拒絕，不能自動初始化替代世界。"""
    import psycopg
    from deception.world import PostgresAdmissionControl

    store, binding, scope = counter
    changes = {}
    if stop == "scope":
        changes["authorized_scope"] = scope.model_copy(update={"world_generation_id": "wrong"})
    elif stop == "epoch":
        store.resolve(binding.model_copy(update={"session_epoch": 2}), {"value": 0, "limit": 3}, now=101, ttl=60)
    elif stop == "expired":
        changes["now"] = 160
    elif stop == "sealed":
        PostgresAdmissionControl(store._dsn).cutover(scope.world_generation_id)
    else:
        counter = store, binding.model_copy(update={"access_mode": "read_only"}), scope
    outcome = submit(counter, **changes)
    assert outcome.status == "rejected" and outcome.failure_code is not None and outcome.result is None
    with psycopg.connect(store._dsn) as connection:
        assert connection.execute("SELECT count(*) FROM world_events").fetchone() == (0,)
        assert connection.execute("SELECT count(*) FROM world_operations").fetchone() == (0,)
        assert connection.execute("SELECT count(*) FROM world_snapshots").fetchone() == (2 if stop == "epoch" else 1,)


def test_readonly_event_recovery_checks_command_and_has_no_new_events(counter):
    """唯讀恢復回完整結果；不同命令或業務鍵不能借用其他已提交操作的摘要。"""
    import psycopg

    store, binding, scope = counter
    first = submit(counter)
    values = dict(authorized_scope=scope, operation="counter.add", command={"amount": 1}, idempotency_key="add-1",
                  commit_attempt_id=first.commit_attempt_id, now=102)
    found = store.get_event_result(binding, **values)
    assert found.status == "committed" and found.commit_result.status == "already_committed"
    assert found.commit_result.result_digest == first.result_digest and found.state_hash == first.committed_state_hash
    assert store.get_event_result(binding, **{**values, "command": {"amount": 2}}).status == "unverifiable"
    assert store.get_event_result(binding, **{**values, "idempotency_key": "other"}).status == "unverifiable"
    assert store.get_event_result(binding, **{**values, "commit_attempt_id": uuid4()}).status == "not_found"
    with psycopg.connect(store._dsn) as connection:
        assert connection.execute("SELECT count(*) FROM world_events").fetchone() == (1,)


def test_real_commit_reply_loss_returns_unverifiable_then_readonly_recovery(counter):
    """真實丟棄 COMMIT 回覆後回傳 unverifiable，新連線只讀查回同一摘要、版本及單筆事件。"""
    from test_postgres_network import lost_commit_proxy

    store, binding, scope = counter
    attempt = uuid4()
    with lost_commit_proxy(store._dsn) as (proxied, dropped):
        outcome = submit((event_store(proxied), binding, scope), commit_attempt_id=attempt)
        assert dropped.is_set() and outcome.status == "unverifiable" and outcome.commit_attempt_id == attempt
    recovered = store.get_event_result(binding, authorized_scope=scope, operation="counter.add", command={"amount": 1},
        idempotency_key="add-1", commit_attempt_id=attempt, now=102)
    assert recovered.status == "committed" and recovered.commit_result.committed_state_version == 2
    assert store.get_commit_result(scope, attempt, authorized_scope=scope).state_hash == recovered.state_hash


@pytest.mark.parametrize("target", ["snapshot", "operation_payload"])
def test_corrupted_persisted_evidence_never_becomes_success_or_business_rejection(counter, target):
    """保存資料毀損不能重算新摘要冒充原結果，也不能把已提交但不可驗證誤說成業務拒絕。"""
    import psycopg

    store, binding, scope = counter
    first = submit(counter)
    with psycopg.connect(store._dsn) as connection:
        if target == "snapshot":
            connection.execute("UPDATE world_snapshots SET state=jsonb_set(state,'{value}','99'::jsonb)")
        else:
            connection.execute("UPDATE world_operations SET result=jsonb_set(result,'{value}','99'::jsonb)")
    replay = submit(counter)
    assert replay.status == "unverifiable" and replay.failure_code == "commit_unverifiable"
    recovered = store.get_event_result(binding, authorized_scope=scope, operation="counter.add", command={"amount": 1},
        idempotency_key="add-1", commit_attempt_id=first.commit_attempt_id, now=102)
    assert recovered.status == "unverifiable" and recovered.commit_result is None


@pytest.mark.parametrize("version,digest", [(None, "a" * 64), (1, None), (2, "a" * 64), (1, "invalid")])
def test_database_rejects_partial_or_unknown_result_digest_encoding(counter, version, digest):
    """資料庫只接受完整的 v1 摘要或明確雙 NULL 舊紀錄，禁止 SQL NULL 三值邏輯放行半套證據。"""
    import psycopg

    store, _, _ = counter
    submit(counter)
    with psycopg.connect(store._dsn) as connection:
        with pytest.raises(psycopg.errors.CheckViolation):
            connection.execute("UPDATE world_operations SET result_encoding_version=%s,result_digest=%s", (version, digest))


def test_legacy_results_are_not_silently_attested_by_modern_api(counter):
    """舊紀錄無已保存摘要時新介面拒絕背書，唯讀查詢與重試不會自動補寫結果證據。"""
    import psycopg

    store, binding, scope = counter
    first = submit(counter)
    with psycopg.connect(store._dsn) as connection:
        connection.execute("UPDATE world_operations SET result_encoding_version=NULL,result_digest=NULL")
    assert submit(counter).status == "unverifiable"
    found = store.get_event_result(binding, authorized_scope=scope, operation="counter.add", command={"amount": 1},
        idempotency_key="add-1", commit_attempt_id=first.commit_attempt_id, now=102)
    assert found.status == "unverifiable" and found.commit_result is None
    with psycopg.connect(store._dsn) as connection:
        assert connection.execute("SELECT result_encoding_version,result_digest FROM world_operations").fetchone() == (None, None)
        assert connection.execute("SELECT count(*) FROM world_events").fetchone() == (1,)


def test_event_lookup_reports_pending_then_not_found_without_business_writes(counter):
    """真正交易鎖尚未釋放時回 pending，釋放後查無紀錄回 not_found，兩次都不產生業務寫入。"""
    import psycopg

    store, binding, scope = counter
    attempt = uuid4()
    values = dict(authorized_scope=scope, operation="counter.add", command={"amount": 1},
        idempotency_key="pending", commit_attempt_id=attempt, now=102)
    with psycopg.connect(store._dsn) as blocker:
        blocker.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", (store._attempt_key(scope, attempt),))
        assert store.get_event_result(binding, **values).status == "pending"
    assert store.get_event_result(binding, **values).status == "not_found"
    with psycopg.connect(store._dsn) as connection:
        assert connection.execute("SELECT count(*) FROM world_operations").fetchone() == (0,)
        assert connection.execute("SELECT count(*) FROM world_events").fetchone() == (0,)


@pytest.mark.parametrize("stop", ["scope", "epoch", "expired", "sealed"])
def test_event_recovery_requires_current_authorized_world(counter, stop):
    """已知 attempt 不是歷史讀取能力；scope 不符、換代、到期與封存均不能查出業務結果。"""
    from deception.world import PostgresAdmissionControl

    store, binding, scope = counter
    first = submit(counter)
    values = dict(authorized_scope=scope, operation="counter.add", command={"amount": 1},
        idempotency_key="add-1", commit_attempt_id=first.commit_attempt_id, now=102)
    if stop == "scope":
        values["authorized_scope"] = scope.model_copy(update={"world_generation_id": "other-generation"})
    elif stop == "epoch":
        store.resolve(binding.model_copy(update={"session_epoch": 2}), {"value": 0, "limit": 3}, now=102, ttl=60)
    elif stop == "expired":
        values["now"] = 160
    else:
        PostgresAdmissionControl(store._dsn).cutover(scope.world_generation_id)
    found = store.get_event_result(binding, **values)
    assert found.status == "unverifiable" and found.commit_result is None and found.state_hash is None


def test_same_attempt_with_other_business_key_rolls_back_all_state(counter):
    """重用 UUID 到另一業務鍵時整個交易回滾，不能把原收據當成第二個命令的成功證據。"""
    import psycopg

    store, binding, scope = counter
    first = submit(counter)
    collided = submit(counter, key="different", expected_version=2, commit_attempt_id=first.commit_attempt_id)
    assert collided.status == "conflict" and collided.committed_state_version is None
    assert store.inspect_binding(binding, now=102).version == 2
    found = store.get_event_result(binding, authorized_scope=scope, operation="counter.add", command={"amount": 1},
        idempotency_key="different", commit_attempt_id=first.commit_attempt_id, now=102)
    assert found.status == "unverifiable" and found.commit_result is None
    with psycopg.connect(store._dsn) as connection:
        assert connection.execute("SELECT count(*) FROM world_operations").fetchone() == (1,)
        assert connection.execute("SELECT count(*) FROM world_events").fetchone() == (1,)


def test_replayed_read_commit_reply_loss_preserves_original_attempt(counter):
    """重播讀取交易的 COMMIT 回覆也可能遺失；未知結果必須帶原紀錄 attempt，不能帶未保存的新 UUID。"""
    from test_postgres_network import lost_commit_proxy

    store, binding, scope = counter
    first = submit(counter)
    with lost_commit_proxy(store._dsn) as (proxied, dropped):
        outcome = submit((event_store(proxied), binding, scope))
        assert dropped.is_set() and outcome.status == "unverifiable"
        assert outcome.commit_attempt_id == first.commit_attempt_id
    found = store.get_event_result(binding, authorized_scope=scope, operation="counter.add", command={"amount": 1},
        idempotency_key="add-1", commit_attempt_id=outcome.commit_attempt_id, now=102)
    assert found.status == "committed" and found.commit_result.result_digest == first.result_digest


def test_default_event_store_denies_writes_before_connecting():
    """未配置寫入能力或 handler 的基礎 Store 不因 SessionBinding 自稱可寫而開啟交易。"""
    store = PostgresEventWorldStore("postgresql://unused.invalid/db")
    binding = SessionBinding(environment_id="commit-test", deployment_id="isolated", session_id="session",
                             session_epoch=1, access_mode="inventory")
    with patch.object(store, "_connection", side_effect=AssertionError("must not connect")):
        outcome = submit((store, binding, example_scope()))
    assert outcome.status == "rejected" and outcome.failure_code == "world_write_not_authorized"


def test_command_is_frozen_before_connection_and_digest_matches_executed_input(counter):
    """呼叫端在開連線時改寫原 dict 不能改變已固定的命令、事件摘要或執行結果。"""
    import psycopg
    from deception.world.event_store import prepare_event_command

    store, binding, scope = counter
    command = {"amount": 1}
    expected_digest = prepare_event_command(command)[1]
    connect = store._connection

    def mutate_original_then_connect():
        """模擬排隊期間另一持有者改寫命令；實際交易仍應使用先前固定的副本。"""
        command["amount"] = 3
        return connect()

    with patch.object(store, "_connection", side_effect=mutate_original_then_connect):
        outcome = submit(counter, command=command)
    assert outcome.status == "committed" and outcome.result["value"] == 1 and command["amount"] == 3
    with psycopg.connect(store._dsn) as connection:
        assert connection.execute("SELECT operation_digest FROM world_operations").fetchone() == (expected_digest,)
        assert connection.execute("SELECT operation_digest FROM world_events").fetchone() == (expected_digest,)
    assert store.get_event_result(binding, authorized_scope=scope, operation="counter.add", command={"amount": 1},
        idempotency_key="add-1", commit_attempt_id=outcome.commit_attempt_id, now=102).status == "committed"


def test_rejected_operation_is_recovered_with_original_digest_without_commit_receipt(counter):
    """保存的業務拒絕可讀回固定結果與 observed 版本，不能因此宣稱狀態已提交或產生成功收據。"""
    import psycopg

    store, binding, scope = counter
    rejected = submit(counter, command={"amount": 4})
    found = store.get_event_result(binding, authorized_scope=scope, operation="counter.add", command={"amount": 4},
        idempotency_key="add-1", commit_attempt_id=rejected.commit_attempt_id, now=102)
    assert found.status == "rejected" and found.commit_result.status == "rejected"
    assert found.commit_result.replayed and found.commit_result.result_digest == rejected.result_digest
    assert found.commit_result.committed_state_version is None and found.commit_result.observed_state_version == 1
    with psycopg.connect(store._dsn) as connection:
        assert connection.execute("SELECT count(*) FROM world_commit_receipts").fetchone() == (0,)
        assert connection.execute("SELECT count(*) FROM world_events").fetchone() == (0,)


def test_legacy_inventory_facade_can_read_unsigned_old_results_without_backfill(isolated_test_dsn):
    """既有領域 DTO 可相容讀取雙 NULL 舊紀錄，但新共用契約仍拒絕將它當成有摘要的成功。"""
    import psycopg
    from deception.domains.ecommerce.inventory import SyntheticInventory

    store = SyntheticInventory(isolated_test_dsn)
    binding = SessionBinding(environment_id="commit-test", deployment_id="isolated", session_id=uuid4().hex,
                             session_epoch=1, access_mode="inventory")
    scope = store.resolve(binding, {"inventory": {"SKU": 2}, "reservations": {}}, now=100, ttl=60).scope
    first = store.reserve(binding, sku="SKU", quantity=1, expected_version=1, idempotency_key="legacy",
        commit_attempt_id=uuid4(), now=101)
    with psycopg.connect(store._dsn) as connection:
        connection.execute("UPDATE world_operations SET result_encoding_version=NULL,result_digest=NULL")
    replay = store.reserve(binding, sku="SKU", quantity=1, expected_version=99, idempotency_key="legacy",
        commit_attempt_id=uuid4(), now=102)
    assert replay.replayed and replay.result == first.result and replay.commit_attempt_id == first.commit_attempt_id
    assert store.operation_result(binding, first.commit_attempt_id, now=102).result == first.result
    modern = store.commit_event(binding, authorized_scope=scope, operation="reserve", command={"sku": "SKU", "quantity": 1},
        expected_version=99, idempotency_key="legacy", commit_attempt_id=uuid4(), now=102)
    assert modern.status == "unverifiable"
    with psycopg.connect(store._dsn) as connection:
        assert connection.execute("SELECT result_encoding_version,result_digest FROM world_operations").fetchone() == (None, None)
        assert connection.execute("SELECT count(*) FROM world_events").fetchone() == (1,)


@pytest.mark.parametrize("number", [1e20, -0.0])
def test_result_numbers_remain_verifiable_after_jsonb_storage(counter, number):
    """JSONB 會正規化指數與負零，首次結果須與實際保存表示一致，才能穩定重播及查回摘要。"""
    store, binding, scope = counter

    def numeric_result(state, command):
        """只在結果攜帶待測浮點數，狀態維持整數以獨立驗證結果的保存邊界。"""
        return {**state, "value": state["value"] + 1}, {"number": number}, True

    numeric = PostgresEventWorldStore(store._dsn, handlers={"counter.add": numeric_result},
                                     write_modes=frozenset({"inventory"}))
    first = submit((numeric, binding, scope))
    assert first.status == "committed"
    replay = submit((numeric, binding, scope))
    assert replay.status == "already_committed" and replay.result_digest == first.result_digest
    found = numeric.get_event_result(binding, authorized_scope=scope, operation="counter.add", command={"amount": 1},
        idempotency_key="add-1", commit_attempt_id=first.commit_attempt_id, now=102)
    assert found.status == "committed" and found.commit_result.result_digest == first.result_digest


@pytest.mark.parametrize("writer", ["initialize", "cas", "session", "event"])
@pytest.mark.parametrize("number", [1e20, -0.0])
def test_snapshot_numbers_remain_readable_across_all_postgres_writers(isolated_test_dsn, writer, number):
    """所有 PostgreSQL 快照寫入路徑都須先固定 JSONB 表示再計算 hash，避免合法數值生成不可讀世界。"""
    from deception.world import PostgresWorldStore

    store = event_store(isolated_test_dsn)
    binding = SessionBinding(environment_id="commit-test", deployment_id="isolated", session_id=uuid4().hex,
                             session_epoch=1, access_mode="inventory")
    if writer in {"initialize", "cas"}:
        store = PostgresWorldStore(isolated_test_dsn)
        scope = example_scope().model_copy(update={"session_id": binding.session_id})
        created = store.create_if_absent(scope, {"number": number} if writer == "initialize" else {"number": 1})
        snapshot = created if writer == "initialize" else store.compare_and_swap(scope, expected_version=1, state={"number": number})
    elif writer == "session":
        snapshot = store.resolve(binding, {"number": number}, now=100, ttl=60)
        scope = snapshot.scope
    else:
        snapshot = store.resolve(binding, {"value": 0, "limit": 3}, now=100, ttl=60)
        scope = snapshot.scope

        def set_number(state, command):
            """只在狀態寫入待測數值，結果保持固定字串以隔離快照 hash 驗證。"""
            return {"number": number}, {"accepted": True}, True

        store = PostgresEventWorldStore(isolated_test_dsn, handlers={"counter.add": set_number},
                                        write_modes=frozenset({"inventory"}))
        outcome = submit((store, binding, scope))
        assert outcome.status == "committed"
        snapshot = store.load(scope)
        assert snapshot is not None and snapshot.state_hash == outcome.committed_state_hash
    loaded = store.load(scope)
    assert loaded is not None and loaded.state_hash == snapshot.state_hash and loaded.state["number"] == number
