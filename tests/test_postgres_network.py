"""實際 PostgreSQL COMMIT 回覆被 TCP 代理丟棄時的恢復驗收。"""

import asyncio
from contextlib import contextmanager
from queue import Queue
from threading import Event, Thread
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from uuid import uuid4

import pytest

from deception.world import PostgresWorldStore
from deception.domains.ecommerce.inventory import SyntheticInventory
from test_postgres_conformance import isolated_test_dsn, scope
from test_inventory_events import binding


@contextmanager
def lost_commit_proxy(dsn):
    """啟動 loopback TCP 代理，收到後端第一個 COMMIT 成功訊息後斷開 Client。

    只用於隔離 SSH 隧道。測試連線關閉內層 SSL 以辨識 PostgreSQL 封包，
    主機間仍由 SSH 加密。丟棄的是實際回覆，不改寫 Store 的 Python 方法。
    """
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    parameters = conninfo_to_dict(dsn)
    host, port = parameters.get("host", "127.0.0.1"), int(parameters.get("port", 5432))
    if host not in {"127.0.0.1", "::1", "localhost"}:
        pytest.skip("network fault proxy requires loopback test database or SSH tunnel")
    ready, dropped, errors = Queue(), Event(), []

    async def serve():
        """在獨立事件迴圈雙向轉送封包，只丟棄已確認提交的第一次成功回覆。"""
        stop = asyncio.Event()
        active = set()

        async def handle(reader, writer):
            """轉送單條真實連線，保留 PostgreSQL 協定封包邊界。"""
            active.add(asyncio.current_task())
            backend_reader, backend_writer = await asyncio.open_connection(host, port)

            async def upstream():
                """原樣轉送 Client 的啟動、驗證及 SQL 請求。"""
                while data := await reader.read(65536):
                    backend_writer.write(data)
                    await backend_writer.drain()

            async def downstream():
                """只在收到真實 COMMIT CommandComplete 時製造回覆遺失。"""
                while True:
                    header = await backend_reader.readexactly(5)
                    size = int.from_bytes(header[1:], "big")
                    if not 4 <= size <= 16 * 1024 * 1024:
                        raise ValueError("unexpected PostgreSQL packet length")
                    payload = await backend_reader.readexactly(size - 4)
                    if header[:1] == b"C" and payload == b"COMMIT\x00" and not dropped.is_set():
                        dropped.set()
                        return
                    writer.write(header + payload)
                    await writer.drain()

            tasks = [asyncio.create_task(upstream()), asyncio.create_task(downstream())]
            try:
                completed, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in completed:
                    task.result()
            except (asyncio.IncompleteReadError, OSError):
                pass
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                writer.close()
                backend_writer.close()
                await asyncio.gather(writer.wait_closed(), backend_writer.wait_closed(), return_exceptions=True)
                active.discard(asyncio.current_task())

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        ready.put((asyncio.get_running_loop(), stop, server.sockets[0].getsockname()[1]))
        await stop.wait()
        server.close()
        await server.wait_closed()
        for task in tuple(active):
            task.cancel()
        await asyncio.gather(*active, return_exceptions=True)

    def worker():
        """保存代理自身錯誤，避免測試把代理崩潰誤判為預期故障。"""
        try:
            asyncio.run(serve())
        except BaseException as exc:
            errors.append(exc)

    thread = Thread(target=worker, daemon=True)
    thread.start()
    loop, stop, local_port = ready.get(timeout=10)
    try:
        yield make_conninfo(dsn, host="127.0.0.1", port=local_port, sslmode="disable", connect_timeout=5), dropped
    finally:
        loop.call_soon_threadsafe(stop.set)
        thread.join(10)
        assert not thread.is_alive() and not errors


def test_initialization_recovers_after_real_commit_reply_drop(isolated_test_dsn):
    """實際丟棄 COMMIT 回覆後，初始化以新連線恢復原世界且只保留一筆。"""
    import psycopg

    target = scope(uuid4().hex)
    with lost_commit_proxy(isolated_test_dsn) as (fault_dsn, dropped):
        snapshot = PostgresWorldStore(fault_dsn).create_if_absent(target, {"synthetic": "network-recovery"})
        assert dropped.is_set()
    assert PostgresWorldStore(isolated_test_dsn).load(target) == snapshot
    with psycopg.connect(isolated_test_dsn) as observer:
        assert observer.execute("SELECT count(*) FROM world_snapshots").fetchone() == (1,)
        assert observer.execute("SELECT count(*) FROM world_initializations").fetchone() == (1,)


def test_inventory_recovers_after_real_commit_reply_drop(isolated_test_dsn):
    """真實提交回覆遺失後查回原事件，合法業務鍵重試不再扣一次庫存。"""
    import psycopg

    service = SyntheticInventory(isolated_test_dsn)
    service.resolve(binding(), {"inventory": {"SKU": 2}}, now=100, ttl=60)
    attempt = uuid4()
    arguments = dict(sku="SKU", quantity=1, expected_version=1, idempotency_key="network-reservation",
                     commit_attempt_id=attempt, now=101)
    with lost_commit_proxy(isolated_test_dsn) as (fault_dsn, dropped):
        with pytest.raises(psycopg.OperationalError):
            SyntheticInventory(fault_dsn).reserve(binding(), **arguments)
        assert dropped.is_set()
    recovered = service.operation_result(binding(), attempt, now=102)
    assert recovered.status == "committed"
    retried = service.reserve(binding(), **{**arguments, "commit_attempt_id": uuid4()})
    assert retried == recovered
    assert service.inspect_binding(binding(), now=103).state["inventory"] == {"SKU": 1}
    with psycopg.connect(isolated_test_dsn) as observer:
        assert observer.execute("SELECT count(*) FROM world_events").fetchone() == (1,)


def test_commit_lookup_distinguishes_pending_and_rejected(isolated_test_dsn):
    """寫入交易尚未完成時回 pending，提交後回原收據，業務拒絕有獨立分類。"""
    import psycopg

    target, attempt = scope(uuid4().hex), uuid4()
    store = PostgresWorldStore(isolated_test_dsn)
    store.create_if_absent(target, {"quantity": 2})
    ready, release = Event(), Event()
    connection = psycopg.connect(isolated_test_dsn)

    class PausedCommit:
        def __enter__(self):
            """將真實連線交給 CAS，交易鎖由 PostgreSQL 持有。"""
            return connection.__enter__()

        def __exit__(self, *args):
            """待唯讀觀察者確認 pending 後才完成 COMMIT。"""
            ready.set()
            if not release.wait(10):
                connection.rollback()
                raise TimeoutError("pending lookup observer did not complete")
            return connection.__exit__(*args)

    with patch.object(store, "_connection", return_value=PausedCommit()), ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(store.compare_and_swap, target, expected_version=1,
                                  state={"quantity": 1}, commit_attempt_id=attempt)
        try:
            assert ready.wait(10)
            observer = PostgresWorldStore(isolated_test_dsn)
            assert observer.get_commit_result(target, attempt, authorized_scope=target).status == "pending"
        finally:
            release.set()
        result = future.result(timeout=10)
    receipt = observer.get_commit_result(target, attempt, authorized_scope=target)
    assert (receipt.status, receipt.state_version, receipt.state_hash) == ("committed", 2, result.state_hash)

    inventory = SyntheticInventory(isolated_test_dsn)
    initial = inventory.resolve(binding(), {"inventory": {"SKU": 1}}, now=100, ttl=60)
    rejected_attempt = uuid4()
    inventory.reserve(binding(), sku="SKU", quantity=2, expected_version=1, idempotency_key="reject",
                      commit_attempt_id=rejected_attempt, now=101)
    rejected = inventory.get_commit_result(initial.scope, rejected_attempt, authorized_scope=initial.scope)
    assert rejected.status == "rejected" and rejected.state_version == 1
