"""以不同 PID 與真實資料庫鎖等待驗證 Grant／Cutover／撤銷的控制排序。"""

from contextlib import nullcontext
import multiprocessing
import os
import time
from unittest.mock import patch
from uuid import uuid4

import pytest

from deception.world import (AdmissionOperationResult, AdmissionState, PostgresAdmissionControl,
    PostgresProjectionRegistry, ProjectionEvidence)
from test_postgres_conformance import isolated_test_dsn, projection_evidence, grant_registered


def ordered_process_worker(dsn, action, payload, ready, results, start, release):
    """在獨立程序持有單一控制交易，操作完成後等父程序確認鎖等待才提交。"""
    import psycopg

    try:
        with psycopg.connect(dsn) as connection:
            control, registry = PostgresAdmissionControl(dsn), PostgresProjectionRegistry(dsn)
            ready.put(("ready", os.getpid(), connection.info.backend_pid))
            if not start.wait(30):
                raise TimeoutError("worker_start_timeout")
            with (patch.object(control, "_connection", return_value=nullcontext(connection)),
                  patch.object(registry, "_connection", return_value=nullcontext(connection))):
                if action == "grant":
                    evidence = ProjectionEvidence.model_validate(payload["evidence"])
                    admission = grant_registered(control, payload["generation"], evidence, registry)
                    value = None if admission is None else admission.model_dump(mode="json")
                elif action == "cutover":
                    value = control.cutover(payload["generation"])
                elif action == "emergency":
                    value = control.emergency_revoke(payload["generation"])
                elif action == "authorize_send":
                    value = control.authorize_send(payload["admission"], now=100).value
                elif action == "authorize_epoch_bound":
                    # Real Session Head locking and one shared commit per worker.
                    epoch_control = PostgresAdmissionControl(dsn, require_session_binding=True)
                    with patch.object(epoch_control, "_connection", return_value=nullcontext(connection)):
                        value = epoch_control.authorize_send(payload["admission"], now=101).value
                elif action == "epoch_advance":
                    from deception.world.session import PostgresSessionWorlds, SessionBinding

                    worlds = PostgresSessionWorlds(dsn)
                    new_binding = SessionBinding.model_validate(payload["next_binding"])
                    with patch.object(worlds, "_connection", return_value=nullcontext(connection)):
                        value = worlds.resolve(new_binding, {"state": "after-cutover"},
                                               now=101, ttl=600).scope.world_generation_id
                elif action == "start_send":
                    value = control.start_send(payload["admission"], owner="process-sender", now=100).value
                elif action == "revoke_contract":
                    registry.revoke(payload["evidence"]["projection_contract_hash"], registry_revision=2)
                    value = "revoked"
                elif action == "revoke_profile":
                    registry.revoke_profile(payload["evidence"]["compatibility_profile"]["profile_sha256"], registry_revision=1)
                    value = "revoked"
                else:
                    raise ValueError("unknown_control_action")
            ready.put(("done", os.getpid(), value))
            if not release.wait(30):
                raise TimeoutError("worker_release_timeout")
            connection.commit()
        results.put((os.getpid(), "committed"))
    except Exception as error:
        # 不傳遞可能包含 DSN 的例外全文，父程序看到錯誤型別仍判定驗收失敗。
        results.put((os.getpid(), "error", type(error).__name__))


def order_in_processes(dsn, first_action, second_action, payload):
    """確認兩個不同 worker 與 backend PID 存活，實際看到第二交易被第一交易阻塞後依序提交。"""
    import psycopg

    context = multiprocessing.get_context("spawn")
    ready, results = context.Queue(), context.Queue()
    starts, releases = [context.Event() for _ in range(2)], [context.Event() for _ in range(2)]
    workers = [context.Process(target=ordered_process_worker,
        args=(dsn, action, payload, ready, results, starts[index], releases[index]))
        for index, action in enumerate((first_action, second_action))]
    try:
        for worker in workers:
            worker.start()
        identities = [ready.get(timeout=30) for _ in workers]
        assert all(row[0] == "ready" for row in identities), identities
        backend = {row[1]: row[2] for row in identities}
        assert len(backend) == 2 and os.getpid() not in backend and len(set(backend.values())) == 2
        assert set(backend) == {worker.pid for worker in workers} and all(worker.is_alive() for worker in workers)
        starts[0].set()
        first = ready.get(timeout=30)
        assert first[:2] == ("done", workers[0].pid), first
        starts[1].set()
        with psycopg.connect(dsn, autocommit=True) as observer:
            deadline = time.monotonic() + 15
            while True:
                blockers, = observer.execute("SELECT pg_blocking_pids(%s)", (backend[workers[1].pid],)).fetchone()
                if backend[workers[0].pid] in blockers:
                    break
                assert all(worker.is_alive() for worker in workers) and time.monotonic() < deadline, "no actual lock wait"
                time.sleep(0.02)
        releases[0].set()
        second = ready.get(timeout=30)
        assert second[:2] == ("done", workers[1].pid), second
        releases[1].set()
        committed = [results.get(timeout=30) for _ in workers]
        assert {row[0] for row in committed} == set(backend)
        assert all(row[1] == "committed" for row in committed), committed
        for worker in workers:
            worker.join(10)
            assert worker.exitcode == 0
        return first[2], second[2]
    finally:
        for event in (*starts, *releases):
            event.set()
        for worker in workers:
            if worker.pid is not None:
                if worker.is_alive():
                    worker.terminate()
                worker.join(5)
                worker.close()
        for queue in (ready, results):
            queue.close()
            queue.join_thread()


def run_one_process_control_action(dsn, action, payload):
    """在獨立 PID + PostgreSQL backend 執行單筆控制操作；不假設無關 row lock 應互擋。"""
    context = multiprocessing.get_context("spawn")
    ready, results = context.Queue(), context.Queue()
    start, release = context.Event(), context.Event()
    worker = context.Process(
        target=ordered_process_worker,
        args=(dsn, action, payload, ready, results, start, release),
    )
    try:
        worker.start()
        first = ready.get(timeout=30)
        assert first[0] == "ready" and first[1] == worker.pid and first[1] != os.getpid()
        start.set()
        done = ready.get(timeout=30)
        assert done[:2] == ("done", worker.pid)
        release.set()
        result = results.get(timeout=30)
        assert result == (worker.pid, "committed"), result
        worker.join(10)
        assert worker.exitcode == 0
        return done[2]
    finally:
        start.set()
        release.set()
        if worker.pid is not None:
            if worker.is_alive():
                worker.terminate()
            worker.join(5)
            worker.close()
        for queue in (ready, results):
            queue.close()
            queue.join_thread()


@pytest.mark.parametrize("grant_first", [True, False])
def test_distinct_processes_order_grant_and_cutover(isolated_test_dsn, grant_first):
    """跨程序核發與封存採同一世代序列；封存前准入可領一次，封存後不能新 Grant。"""
    import psycopg

    evidence, generation = projection_evidence(uuid4().hex * 2), uuid4().hex
    registry = PostgresProjectionRegistry(isolated_test_dsn)
    registry.register(evidence, registry_revision=1)
    payload = dict(evidence=evidence.model_dump(mode="json"), generation=generation)
    actions = ("grant", "cutover") if grant_first else ("cutover", "grant")
    first, second = order_in_processes(isolated_test_dsn, *actions, payload)
    admission, cutover = (first, second) if grant_first else (second, first)
    control = PostgresAdmissionControl(isolated_test_dsn)
    assert grant_registered(control, generation, evidence, registry) is None
    if grant_first:
        assert admission["grant_revision"] + 1 == cutover
        identifier = admission["admission_id"]
        assert control.claim(identifier, owner="third-observer", now=101) is AdmissionOperationResult.SUCCESS
        assert control.claim(identifier, owner="fourth-observer", now=101) is AdmissionOperationResult.ALREADY_CLAIMED
    else:
        assert admission is None
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM response_admissions").fetchone() == (int(grant_first),)


@pytest.mark.parametrize("send_first", [True, False])
@pytest.mark.parametrize("boundary", ["authorize_send", "start_send"])
def test_distinct_processes_order_emergency_and_send_boundary(isolated_test_dsn, send_first, boundary):
    """跨程序：撤銷與授權共用交易鎖；已授權起送只核對唯一 owner／期限。"""
    evidence, generation = projection_evidence(uuid4().hex * 2), uuid4().hex
    registry, control = PostgresProjectionRegistry(isolated_test_dsn), PostgresAdmissionControl(isolated_test_dsn)
    registry.register(evidence, registry_revision=1)
    admission = grant_registered(control, generation, evidence, registry)
    assert control.claim(admission.admission_id, owner="process-sender", now=100) is AdmissionOperationResult.SUCCESS
    payload = dict(generation=generation, admission=admission.admission_id)
    if boundary == "authorize_send":
        actions = (boundary, "emergency") if send_first else ("emergency", boundary)
        first, second = order_in_processes(isolated_test_dsn, *actions, payload)
        assert (first if send_first else second) == ("SUCCESS" if send_first else "REJECTED")
        observer = PostgresAdmissionControl(isolated_test_dsn)
        if send_first:
            assert observer.state(admission.admission_id) is AdmissionState.SEND_AUTHORIZED
            # The previous authorization remains usable even when revoke was committed next.
            assert run_one_process_control_action(isolated_test_dsn, "start_send", payload) == "SUCCESS"
            assert observer.state(admission.admission_id) is AdmissionState.SEND_STARTED
        else:
            assert observer.state(admission.admission_id) is AdmissionState.ABANDONED
            assert observer.event_revision(admission.admission_id, "send_authorization") is None
            return
    else:
        assert control.authorize_send(admission.admission_id, now=100) is AdmissionOperationResult.SUCCESS
        # start_send intentionally does NOT acquire the generation/profile revocation lock.
        # Verify both real process orderings without manufacturing a nonexistent lock wait.
        actions = ("start_send", "emergency") if send_first else ("emergency", "start_send")
        first = run_one_process_control_action(isolated_test_dsn, actions[0], payload)
        second = run_one_process_control_action(isolated_test_dsn, actions[1], payload)
        assert (first if send_first else second) == "SUCCESS"
        observer = PostgresAdmissionControl(isolated_test_dsn)
        assert observer.state(admission.admission_id) is AdmissionState.SEND_STARTED
    assert observer.event_revision(admission.admission_id, "send_authorization") is not None
    assert observer.event_revision(admission.admission_id, "emergency_revocation") is not None
    assert observer.start_send(admission.admission_id, owner="process-sender", now=101) is AdmissionOperationResult.REJECTED
    assert observer.finish_send(admission.admission_id, owner="process-sender",
        outcome=AdmissionState.SEND_COMPLETED, attempted=True) is AdmissionOperationResult.SUCCESS
    assert observer.state(admission.admission_id) is AdmissionState.SEND_COMPLETED


@pytest.mark.parametrize("authorize_first", [True, False],
                         ids=["authorize-before-epoch", "epoch-before-authorize"])
def test_distinct_processes_order_session_epoch_and_final_authorization(isolated_test_dsn, authorize_first):
    """真實 Session Head 鎖：不同 PID 的 epoch 切換與授權只能有一個先提交。"""
    from deception.world.session import PostgresSessionWorlds, SessionBinding

    dsn = isolated_test_dsn
    original = SessionBinding(environment_id="epoch-contract", deployment_id="isolated",
                              session_id=uuid4().hex, session_epoch=1)
    worlds = PostgresSessionWorlds(dsn)
    initial = worlds.resolve(original, {"state": "before-cutover"}, now=100, ttl=600)
    registry = PostgresProjectionRegistry(dsn)
    evidence = projection_evidence(uuid4().hex * 2)
    registry.register(evidence, registry_revision=1)
    control = PostgresAdmissionControl(dsn, require_session_binding=True)
    admission = grant_registered(control, initial.scope.world_generation_id, evidence, registry)
    assert admission is not None
    assert control.claim(admission.admission_id, owner="process-sender", now=100) is AdmissionOperationResult.SUCCESS

    next_binding = original.model_copy(update={"session_epoch": 2})
    payload = dict(admission=admission.admission_id, next_binding=next_binding.model_dump(mode="json"))
    first, second = order_in_processes(dsn,
        "authorize_epoch_bound" if authorize_first else "epoch_advance",
        "epoch_advance" if authorize_first else "authorize_epoch_bound",
        payload,
    )
    authorization = first if authorize_first else second
    assert authorization == ("SUCCESS" if authorize_first else "REJECTED")
    observed = PostgresAdmissionControl(dsn, require_session_binding=True)
    assert worlds.inspect_binding(next_binding, now=102).scope.world_generation_id != initial.scope.world_generation_id
    cutover_revision = observed.event_revision(admission.admission_id, "cutover")
    assert cutover_revision is not None
    from deception.world import WorldStoreError

    with pytest.raises(WorldStoreError, match="session_binding_unverifiable"):
        worlds.inspect_binding(original, now=102)

    if authorize_first:
        assert observed.state(admission.admission_id) is AdmissionState.SEND_AUTHORIZED
        # Auth committed before epoch rollover: it is not retroactively revoked.
        assert observed.start_send(admission.admission_id, owner="process-sender", now=102) is AdmissionOperationResult.SUCCESS
        assert observed.start_send(admission.admission_id, owner="process-sender", now=102) is AdmissionOperationResult.REJECTED
        send_revision = observed.event_revision(admission.admission_id, "send_authorization")
        assert send_revision is not None and send_revision < cutover_revision
    else:
        assert observed.state(admission.admission_id) is AdmissionState.CLAIMED
        assert observed.event_revision(admission.admission_id, "send_authorization") is None
        assert observed.authorize_send(admission.admission_id, now=103) is AdmissionOperationResult.REJECTED
        assert observed.start_send(admission.admission_id, owner="process-sender", now=103) is AdmissionOperationResult.REJECTED


@pytest.mark.parametrize("grant_first", [True, False])
@pytest.mark.parametrize("kind", ["contract", "profile"])
def test_distinct_processes_order_registry_revocation_and_grant(isolated_test_dsn, grant_first, kind):
    """契約／整體 Profile 撤銷與 Grant 在不同程序鎖排序，舊准入保留核准版本，撤銷後無新准入。"""
    evidence, generation = projection_evidence(uuid4().hex * 2), uuid4().hex
    registry = PostgresProjectionRegistry(isolated_test_dsn)
    registry.register(evidence, registry_revision=1)
    payload = dict(evidence=evidence.model_dump(mode="json"), generation=generation)
    revoke = "revoke_contract" if kind == "contract" else "revoke_profile"
    actions = ("grant", revoke) if grant_first else (revoke, "grant")
    first, second = order_in_processes(isolated_test_dsn, *actions, payload)
    admission = first if grant_first else second
    control = PostgresAdmissionControl(isolated_test_dsn)
    assert grant_registered(control, generation, evidence, registry) is None
    if grant_first:
        assert admission["projection_registry_revision"] == 1
        assert control.claim(admission["admission_id"], owner="post-revoke-observer", now=101) is AdmissionOperationResult.SUCCESS
    else:
        assert admission is None


def read_boundary_worker(dsn, binding, now, results):
    """獨立程序只以伺服器 binding 取得 ReadAdmission，已知安全拒絕只回固定錯誤碼。"""
    from deception.world import WorldStoreError
    from deception.world.session import PostgresSessionWorlds, SessionBinding

    try:
        read = PostgresSessionWorlds(dsn).admit_read(SessionBinding.model_validate(binding),
            request_binding_digest="a" * 64, now=now, expires_at=now+5)
        results.put((os.getpid(), "accepted", read.source.state_version))
    except WorldStoreError as error:
        code = str(error)
        allowed = {"world_below_watermark", "session_world_expired", "session_epoch_stale"}
        results.put((os.getpid(), "rejected", code if code in allowed else "unexpected_store_error"))
    except Exception as error:
        results.put((os.getpid(), "error", type(error).__name__))


def read_in_new_process(dsn, binding, now):
    """等待本 helper 建立的 reader 回報並正常退出，不以父程序物件快取代替跨程序證據。"""
    context = multiprocessing.get_context("spawn")
    results = context.Queue()
    worker = context.Process(target=read_boundary_worker, args=(dsn, binding.model_dump(mode="json"), now, results))
    try:
        worker.start()
        outcome = results.get(timeout=45)
        assert outcome[0] == worker.pid and worker.pid != os.getpid()
        worker.join(10)
        assert worker.exitcode == 0
        return outcome
    finally:
        if worker.pid is not None:
            if worker.is_alive():
                worker.terminate()
            worker.join(5)
            worker.close()
        results.close()
        results.join_thread()


@pytest.mark.parametrize("stop", ["watermark", "expiry", "epoch"])
def test_read_boundary_survives_independent_reader_exit(isolated_test_dsn, stop):
    """第一 reader 退出後，另一程序仍遵守持久 Watermark、Lease 及 epoch，拒絕不新增讀取准入。"""
    import psycopg
    from deception.world.session import PostgresSessionWorlds, SessionBinding

    binding = SessionBinding(environment_id="process-test", deployment_id="isolated", session_id=uuid4().hex, session_epoch=1)
    store = PostgresSessionWorlds(isolated_test_dsn)
    initial = store.resolve(binding, {"stock": 3}, now=100, ttl=60)
    updated = store.compare_and_swap(initial.scope, expected_version=1, state={"stock": 2})
    first = read_in_new_process(isolated_test_dsn, binding, 101)
    assert first[1:] == ("accepted", updated.version)
    now = 102
    expected = {"watermark": "world_below_watermark", "expiry": "session_world_expired", "epoch": "session_epoch_stale"}[stop]
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT watermark_version FROM session_world_bindings").fetchone() == (2,)
        if stop == "watermark":
            # 故意只讓 version 倒退，保留有效內容 hash，確認拒絕原因來自 Watermark 而非完整性錯誤。
            connection.execute("UPDATE world_snapshots SET version=1")
    if stop == "expiry":
        now = 160
    elif stop == "epoch":
        store.resolve(binding.model_copy(update={"session_epoch": 2}), {"stock": 9}, now=102, ttl=60)
    second = read_in_new_process(isolated_test_dsn, binding, now)
    assert first[0] != second[0] and second[1:] == ("rejected", expected)
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM read_admissions").fetchone() == (1,)
        assert connection.execute("SELECT count(*) FROM world_snapshots").fetchone() == (2 if stop == "epoch" else 1,)
