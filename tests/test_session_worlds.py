"""共享 Session 世界映射、ReadAdmission、Watermark 與恢復驗收。"""

from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest

from deception.world import PostgresAdmissionControl, WorldStoreError
from deception.world.session import PostgresSessionWorlds, SessionBinding
from test_postgres_conformance import isolated_test_dsn


def binding(epoch=1):
    """建立合成可信身份，epoch 由測試模擬身份服務變更。"""
    return SessionBinding(environment_id="test", deployment_id="local", session_id="session", session_epoch=epoch)


def test_concurrent_session_creation_preserves_world_after_restart(isolated_test_dsn):
    """兩個 Instance 同時初始化只建立同一世界，重建物件與新 JTI 不改身份。"""
    first = PostgresSessionWorlds(isolated_test_dsn)
    second = PostgresSessionWorlds(isolated_test_dsn)

    def initialize(value):
        """由不同 Store 提供不同候選初始資料，只有一份資料能提交。"""
        store, name = value
        return store.resolve(binding(), {"owner": name}, now=100, ttl=60)

    with ThreadPoolExecutor(max_workers=2) as executor:
        snapshots = list(executor.map(initialize, [(first, "first"), (second, "second")]))
    assert snapshots[0] == snapshots[1]
    assert second.inspect_binding(binding(), now=101) == snapshots[0]
    assert second.resolve(binding(), {"owner": "replacement"}, now=101, ttl=600) == snapshots[0]
    with pytest.raises(WorldStoreError, match="expired"):
        first.resolve(binding(), {"owner": "replacement"}, now=160, ttl=600)


def test_epoch_rotation_rejects_old_binding(isolated_test_dsn):
    """較新 epoch 原子建立新世代，舊 epoch 不能再解析或讀取當前世界。"""
    runtime = PostgresSessionWorlds(isolated_test_dsn)
    old = runtime.resolve(binding(), {"owner": "old"}, now=100, ttl=60)
    new = runtime.resolve(binding(2), {"owner": "new"}, now=101, ttl=60)
    assert old.scope.world_generation_id != new.scope.world_generation_id
    import psycopg
    with psycopg.connect(isolated_test_dsn) as observer:
        sealed, revision = observer.execute(
            "SELECT sealed,cutover_revision FROM generation_controls WHERE world_generation_id=%s",
            (old.scope.world_generation_id,)).fetchone()
    assert sealed and revision > 0
    with pytest.raises(WorldStoreError, match="stale"):
        runtime.resolve(binding(), {"owner": "replay"}, now=102, ttl=60)
    with pytest.raises(WorldStoreError, match="unverifiable"):
        runtime.inspect_binding(binding(), now=102)
    with pytest.raises(WorldStoreError, match="stale"):
        runtime.admit_read(binding(), request_binding_digest="a" * 64, now=102, expires_at=110)


@pytest.mark.parametrize("stop", ["cutover", "emergency", "watermark", "expired"])
def test_read_admission_checks_consistency_and_generation(isolated_test_dsn, stop):
    """成功讀取保存快照版本與 Watermark，封存、撤銷、倒退及到期時停止。"""
    import psycopg

    runtime = PostgresSessionWorlds(isolated_test_dsn)
    initial = runtime.resolve(binding(), {"stock": 3}, now=100, ttl=60)
    snapshot = runtime.compare_and_swap(initial.scope, expected_version=1, state={"stock": 2})
    read = runtime.admit_read(binding(), request_binding_digest="a" * 64, now=101, expires_at=110)
    assert read.snapshot == snapshot
    assert (read.source.state_version, read.source.state_hash) == (snapshot.version, snapshot.state_hash)
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT watermark_version FROM session_world_bindings").fetchone() == (2,)
        assert connection.execute("SELECT request_binding_digest FROM read_admissions").fetchone() == ("a" * 64,)
        if stop == "watermark":
            connection.execute("UPDATE world_snapshots SET version=1")
    control = PostgresAdmissionControl(isolated_test_dsn)
    if stop == "cutover":
        control.cutover(initial.scope.world_generation_id)
    elif stop == "emergency":
        control.emergency_revoke(initial.scope.world_generation_id)
    now = 160 if stop == "expired" else 102
    with pytest.raises(WorldStoreError):
        runtime.admit_read(binding(), request_binding_digest="b" * 64, now=now, expires_at=now + 10)
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM read_admissions").fetchone() == (1,)


def test_session_commit_reply_loss_recovers_read_only(isolated_test_dsn):
    """綁定與快照提交後失去結果時，以新物件唯讀查回同一世界且只建立一份。"""
    import psycopg

    runtime = PostgresSessionWorlds(isolated_test_dsn)
    connection = psycopg.connect(isolated_test_dsn)

    class LostCommit:
        def __enter__(self):
            """將實際連線交給世界初始化交易。"""
            return connection.__enter__()

        def __exit__(self, *args):
            """先讓真實交易提交，再注入呼叫端失去成功結果的錯誤。"""
            connection.__exit__(*args)
            raise psycopg.OperationalError("injected lost commit result")

    with patch.object(runtime, "_connection", return_value=LostCommit()) as calls:
        with pytest.raises(psycopg.OperationalError):
            runtime.resolve(binding(), {"owner": "original"}, now=100, ttl=60)
        calls.assert_called_once_with()
    recovered = PostgresSessionWorlds(isolated_test_dsn).inspect_binding(binding(), now=101)
    assert recovered.state == {"owner": "original"}
    with psycopg.connect(isolated_test_dsn) as observer:
        assert observer.execute("SELECT count(*) FROM world_snapshots").fetchone() == (1,)
        assert observer.execute("SELECT count(*) FROM session_world_bindings").fetchone() == (1,)
