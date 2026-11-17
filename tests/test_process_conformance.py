"""以真正獨立程序與共享 PostgreSQL 驗證競爭，不以同程序物件代替多程序。"""

import multiprocessing
import os
from uuid import uuid4

import pytest

from deception.world import PostgresAdmissionControl, PostgresProjectionRegistry, PostgresReplayStore
from deception.world.session import PostgresSessionWorlds, SessionBinding
from test_postgres_conformance import isolated_test_dsn, projection_evidence, grant_registered


def process_worker(dsn, action, identifier, ready, start, results):
    """等待父程序確認兩個 worker 存活後，獨立建連線並回傳非機密合成結果。"""
    ready.put(os.getpid())
    if not start.wait(30):
        results.put((os.getpid(), "error", "start_timeout"))
        return
    try:
        if action == "replay":
            value = PostgresReplayStore(dsn).consume(issuer="process-test", audience="mirage",
                jti=identifier, expires_at=200, now=100).value
        elif action == "claim":
            value = PostgresAdmissionControl(dsn).claim(identifier, owner=f"worker-{os.getpid()}", now=100).value
        elif action == "session":
            binding = SessionBinding(environment_id="process-test", deployment_id="isolated",
                                     session_id=identifier, session_epoch=1)
            snapshot = PostgresSessionWorlds(dsn).resolve(binding, {"owner": os.getpid()}, now=100, ttl=60)
            value = snapshot.model_dump(mode="json")
        else:
            raise ValueError("unknown test worker action")
        results.put((os.getpid(), "ok", value))
    except Exception as error:
        # 不將包含連線設定的例外全文寫入報告；父程序仍會因 worker error 判定失敗。
        results.put((os.getpid(), "error", type(error).__name__))


def compete_in_processes(dsn, action, identifier):
    """啟動兩個 spawn 程序並同步釋放，檢查不同 PID、完整結果與正常退出。"""
    context = multiprocessing.get_context("spawn")
    ready, results, start = context.Queue(), context.Queue(), context.Event()
    workers = [context.Process(target=process_worker, args=(dsn, action, identifier, ready, start, results))
               for _ in range(2)]
    try:
        for worker in workers:
            worker.start()
        pids = {ready.get(timeout=30) for _ in workers}
        assert len(pids) == 2 and os.getpid() not in pids
        assert all(worker.is_alive() for worker in workers)
        start.set()
        outcomes = [results.get(timeout=90) for _ in workers]
        assert {row[0] for row in outcomes} == pids
        assert all(row[1] == "ok" for row in outcomes), outcomes
        for worker in workers:
            worker.join(10)
            assert worker.exitcode == 0
        return [row[2] for row in outcomes]
    finally:
        # 只清理本 helper 建立的 worker，不依程序名稱掃描或終止其他驗收。
        start.set()
        for worker in workers:
            if worker.pid is not None:
                if worker.is_alive():
                    worker.terminate()
                worker.join(5)
                worker.close()
        for queue in (ready, results):
            queue.close()
            queue.join_thread()


@pytest.mark.parametrize("action", ["replay", "claim", "session"])
def test_shared_runtime_competition_survives_worker_exit(isolated_test_dsn, action):
    """兩個獨立程序競爭後全部退出，第三個控制器仍讀到唯一消費／Claim／世界。"""
    identifier = uuid4().hex
    admission = None
    if action == "claim":
        evidence = projection_evidence(uuid4().hex * 2)
        registry = PostgresProjectionRegistry(isolated_test_dsn)
        registry.register(evidence, registry_revision=1)
        admission = grant_registered(PostgresAdmissionControl(isolated_test_dsn), identifier, evidence, registry)
        assert admission is not None
        identifier = admission.admission_id
    outcomes = compete_in_processes(isolated_test_dsn, action, identifier)
    if action == "replay":
        assert sorted(outcomes) == ["accepted", "replay"]
        assert PostgresReplayStore(isolated_test_dsn).consume(issuer="process-test", audience="mirage",
            jti=identifier, expires_at=200, now=101).value == "replay"
    elif action == "claim":
        assert sorted(outcomes) == ["ALREADY_CLAIMED", "SUCCESS"]
        observer = PostgresAdmissionControl(isolated_test_dsn)
        assert observer.state(identifier).value == "CLAIMED"
        assert observer.claim(identifier, owner="third-process-observer", now=101).value == "ALREADY_CLAIMED"
    else:
        assert outcomes[0] == outcomes[1]
        binding = SessionBinding(environment_id="process-test", deployment_id="isolated",
                                 session_id=identifier, session_epoch=1)
        observer = PostgresSessionWorlds(isolated_test_dsn)
        assert observer.inspect_binding(binding, now=101).model_dump(mode="json") == outcomes[0]
        assert observer.resolve(binding, {"owner": "replacement"}, now=101, ttl=600).model_dump(mode="json") == outcomes[0]
