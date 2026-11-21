"""PostgreSQL 共享 Store 與雙 Instance 准入一致性驗收。"""

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import pytest
from test_candidate_handoff import candidate_and_gate

from deception.world import (
    AdmissionOperationResult,
    AdmissionState,
    PostgresCandidateStore,
    PostgresReplayStore,
    PostgresAdmissionControl,
    PostgresWorldStore,
    ProjectionCompatibilityProfile,
    ProjectionEvidence,
    PostgresProjectionRegistry,
    SnapshotSource,
    WorldScope,
    WorldStoreError,
)


def test_postgres_two_ingress_instances_accept_jws_once():
    """兩個獨立入口競爭同一簽章授權時，共享資料庫只准一次成功。"""
    from test_trusted_ingress import VECTOR, vector_request
    from deception.security import TrustedSessionError
    from deception.security.trusted_deployment import TrustedDeploymentSettings

    dsn = postgres_dsn()
    apply_schema(dsn)
    settings = TrustedDeploymentSettings(
        issuer="gateway", audience="mirage", environment_id="env-1",
        deployment_id="deploy-1", source_id="reviewed-detector", service_id="store",
        site_id="shop", public_keys={"gateway-1": VECTOR["public_key_hex"]},
    )
    # 固定向量使用獨立交易清理自己的唯一鍵，不影響其他測試授權。
    import psycopg
    with psycopg.connect(dsn) as connection:
        connection.execute("DELETE FROM replay_entries WHERE issuer=%s AND audience=%s AND jti=%s",
                           ("gateway", "mirage", "jti-vector-1"))
    providers = [settings.build_provider(postgres_dsn=dsn) for _ in range(2)]
    for provider in providers:
        provider._now = VECTOR["now"]

    def consume(provider):
        """記錄每個入口的驗證結果，不把重放拒絕視為測試錯誤。"""
        try:
            return provider(vector_request()).verdict
        except TrustedSessionError as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sorted(executor.map(consume, providers)) == ["malicious", "trusted_session_replay"]


def digest(char: str) -> str:
    """建立符合 SHA-256 欄位格式的測試摘要。"""
    return char * 64


def postgres_dsn() -> str:
    """取得 Conformance 使用的 DSN，缺少時明確跳過而不偽造通過。"""
    dsn = os.environ.get("MIRAGE_POSTGRES_TEST_DSN") or os.environ.get("MIRAGE_POSTGRES_DSN")
    if not dsn:
        pytest.skip("MIRAGE_POSTGRES_TEST_DSN or MIRAGE_POSTGRES_DSN is not configured")
    pytest.importorskip("psycopg")
    return dsn


def apply_schema(dsn: str) -> None:
    """在測試資料庫套用版本化 World Runtime migration。"""
    import psycopg

    migrations = Path(__file__).parents[1] / "migrations"
    with psycopg.connect(dsn) as connection:
        for migration in sorted(migrations.glob("[0-9]*.sql")):
            connection.execute(migration.read_text(encoding="utf-8"))


def scope(suffix: str) -> WorldScope:
    """建立本次測試專用的完整隔離 scope。"""
    return WorldScope(
        environment_id="conformance",
        deployment_id="pytest",
        session_id=f"session-{suffix}",
        world_generation_id=f"generation-{suffix}",
    )


def projection_evidence(contract_hash: str | None = None) -> ProjectionEvidence:
    """建立可被 ResponseAdmission 引用的官方投影證據。"""
    selected_contract = contract_hash or digest("3")
    return ProjectionEvidence(
        source_spec_sha256=digest("1"),
        compatibility_profile=ProjectionCompatibilityProfile(
            profile_id="conformance",
            profile_version="1",
            profile_sha256=digest("2"),
            platform_id="test",
            platform_version="1",
            source_spec_sha256=digest("1"),
            world_schema_version="1",
            domain_adapter_version="1",
        ),
        projection_contract_hash=selected_contract,
        official_schema_valid=True,
        effective_projection_valid=True,
    )


def grant(control: PostgresAdmissionControl, generation_id: str):
    """建立跨 Instance Claim 測試使用的一次性准入。"""
    evidence = projection_evidence(uuid4().hex * 2)
    registry = PostgresProjectionRegistry(postgres_dsn_without_skip())
    registry.register(evidence, registry_revision=1)
    return grant_registered(control, generation_id, evidence, registry)


def grant_registered(control, generation_id, evidence, registry):
    """對指定的已登錄證據建立准入，讓並行測試可重用同一契約。"""
    return control.grant(
        world_generation_id=generation_id,
        request_binding_digest=digest("a"),
        candidate_ref="candidate-conformance",
        candidate_hash=digest("b"),
        immutable_body_hash=digest("c"),
        semantic_headers_hash=digest("d"),
        projection_contract_hash=evidence.projection_contract_hash,
        authorization_revision="auth-1",
        authorization_deadline=2_000_000_000,
        transmission_deadline=2_000_000_100,
        source=SnapshotSource(
            read_admission_id="read-conformance",
            world_generation_id=generation_id,
            state_version=1,
            state_hash=digest("e"),
        ),
        projection_evidence=evidence,
        projection_registry=registry,
    )


def postgres_dsn_without_skip() -> str:
    """讀取已由測試前置條件確認存在的 PostgreSQL DSN。"""
    return os.environ.get("MIRAGE_POSTGRES_TEST_DSN") or os.environ["MIRAGE_POSTGRES_DSN"]


def test_postgres_world_store_is_shared_across_two_instances():
    """確認兩個獨立 Store 物件共用 Snapshot 並拒絕 stale CAS。"""
    dsn = postgres_dsn()
    apply_schema(dsn)
    test_scope = scope(uuid4().hex)
    first_instance = PostgresWorldStore(dsn)
    second_instance = PostgresWorldStore(dsn)
    created = first_instance.create_if_absent(test_scope, {"owner": "first"})
    assert second_instance.load(test_scope) == created
    updated = first_instance.compare_and_swap(test_scope, expected_version=1, state={"owner": "updated"})
    assert second_instance.load(test_scope) == updated
    with pytest.raises(WorldStoreError, match="version_conflict"):
        second_instance.compare_and_swap(test_scope, expected_version=1, state={"owner": "stale"})


def test_postgres_admission_claim_is_single_use_across_two_instances():
    """確認兩個獨立控制器對同一 Admission 只能有一個成功 Claim。"""
    dsn = postgres_dsn()
    apply_schema(dsn)
    generation_id = f"generation-{uuid4().hex}"
    first_instance = PostgresAdmissionControl(dsn)
    second_instance = PostgresAdmissionControl(dsn)
    admission = grant(first_instance, generation_id)
    assert admission is not None
    results = {
        first_instance.claim(admission.admission_id, owner="renderer-a", now=1),
        second_instance.claim(admission.admission_id, owner="renderer-b", now=1),
    }
    assert results == {
        AdmissionOperationResult.SUCCESS,
        AdmissionOperationResult.ALREADY_CLAIMED,
    }
    assert second_instance.state(admission.admission_id) is AdmissionState.CLAIMED


def test_postgres_candidate_retention_uses_shared_admission_references():
    """確認共享 Admission 引用可阻止另一個 Candidate Store 提前 GC。"""
    dsn = postgres_dsn()
    apply_schema(dsn)
    suffix = uuid4().hex
    test_scope = scope(suffix)
    admission_control = PostgresAdmissionControl(dsn)
    candidate_store = PostgresCandidateStore(dsn)
    admission = grant(admission_control, test_scope.world_generation_id)
    assert admission is not None
    candidate_store.put(test_scope, admission.candidate_ref, b"candidate-body", expires_at=10)
    protected = admission_control.active_candidate_refs(now=1)
    assert protected == frozenset({admission.candidate_ref})
    assert candidate_store.gc(now=10, protected_refs=protected) == ()
    assert candidate_store.load(
        test_scope,
        admission.candidate_ref,
        expected_hash="0" * 64,
        now=9,
    ).status.value == "candidate_hash_mismatch"
    assert len(candidate_store.gc(now=10, protected_refs=())) == 1


def test_postgres_admission_state_survives_new_instance_after_claim():
    """確認 Claim 提交後重新建立控制器仍拒絕重放，模擬程序重啟恢復。"""
    dsn = postgres_dsn()
    apply_schema(dsn)
    generation_id = f"generation-{uuid4().hex}"
    first_instance = PostgresAdmissionControl(dsn)
    second_instance = PostgresAdmissionControl(dsn)
    admission = grant(first_instance, generation_id)
    assert admission is not None
    import psycopg
    with psycopg.connect(dsn) as connection:
        saved, = connection.execute("SELECT admission FROM response_admissions WHERE admission_id=%s",
                                     (admission.admission_id,)).fetchone()
        assert saved["hash_encoding_version"] == saved["candidate_serialization_version"] == 1
        connection.execute("UPDATE response_admissions SET admission=admission-'hash_encoding_version'"
                           "-'candidate_serialization_version' WHERE admission_id=%s", (admission.admission_id,))
    assert second_instance.get_admission(admission.admission_id) == admission
    assert first_instance.claim(admission.admission_id, owner="renderer-a", now=1) is AdmissionOperationResult.SUCCESS
    assert second_instance.state(admission.admission_id) is AdmissionState.CLAIMED
    assert second_instance.claim(admission.admission_id, owner="renderer-b", now=1) is AdmissionOperationResult.ALREADY_CLAIMED


def test_postgres_emergency_revocation_blocks_send_across_instances():
    """確認 Emergency Revocation 在 Send Authorization 前跨 Instance 阻止發送。"""
    dsn = postgres_dsn()
    apply_schema(dsn)
    generation_id = f"generation-{uuid4().hex}"
    first_instance = PostgresAdmissionControl(dsn)
    second_instance = PostgresAdmissionControl(dsn)
    admission = grant(first_instance, generation_id)
    assert admission is not None
    assert first_instance.claim(admission.admission_id, owner="renderer-a", now=1) is AdmissionOperationResult.SUCCESS
    assert second_instance.authorize_send(admission.admission_id, now=2, revoked=True) is AdmissionOperationResult.REJECTED
    assert first_instance.authorize_send(admission.admission_id, now=3) is AdmissionOperationResult.REJECTED
    assert second_instance.state(admission.admission_id) is AdmissionState.ABANDONED


def test_postgres_unavailable_store_is_fail_closed():
    """確認 PostgreSQL 無法連線時不會建立替代世界或准入。"""
    invalid_dsn = "postgresql://invalid:invalid@127.0.0.1:1/unavailable?connect_timeout=1"
    store = PostgresWorldStore(invalid_dsn)
    with pytest.raises(WorldStoreError, match="storage_unavailable"):
        store.create_if_absent(scope(uuid4().hex), {"state": "must-not-exist"})


def test_postgres_replay_is_single_use_across_instances(isolated_test_dsn):
    """確認兩個獨立 Replay Store 對同一 JTI 只有一個成功消費。"""
    from deception.world import ReplayConsumeResult

    dsn = isolated_test_dsn
    first_instance = PostgresReplayStore(dsn)
    second_instance = PostgresReplayStore(dsn)
    values = {
        "issuer": "gateway",
        "audience": "mirage",
        "jti": f"jti-{uuid4().hex}",
        "expires_at": 2_000_000_000,
    }
    results = {
        first_instance.consume(**values, now=1),
        second_instance.consume(**values, now=1),
    }
    assert results == {ReplayConsumeResult.ACCEPTED, ReplayConsumeResult.REPLAY}
    assert first_instance.gc(now=2_000_000_000) == 1


@pytest.fixture
def isolated_test_dsn():
    """在明確指定的測試資料庫建立獨立 schema，以隔離鎖、GC、JTI 與 World 快照，測後清理。"""
    dsn = os.environ.get("MIRAGE_POSTGRES_TEST_DSN")
    if not dsn:
        pytest.skip("requires isolated MIRAGE_POSTGRES_TEST_DSN")
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    name = "replay_test_" + uuid4().hex
    schema = sql.Identifier(name)
    scoped = make_conninfo(dsn, options=f"-c search_path={name}")
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(schema))
        try:
            apply_schema(scoped)
            yield scoped
        finally:
            admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(schema))


@pytest.mark.parametrize("fault", ["write_timeout", "lost_commit_result"])
def test_replay_fault_stops_http_before_orchestration(fault, isolated_test_dsn):
    """用隔離 schema 注入寫入逾時或提交後遺失結果，核對 HTTP、消費次數與持久化狀態。"""
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from fastapi.testclient import TestClient
    from deception.api.pipeline import create_app
    from deception.world import PostgresReplayStore, ReplayConsumeResult
    from test_trusted_ingress import VECTOR, provider, token, vector_request

    import psycopg

    scoped = isolated_test_dsn
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    options = conninfo_to_dict(scoped)["options"]
    store = PostgresReplayStore(make_conninfo(scoped, options=f"{options} -c statement_timeout=1000"))
    attempts = []
    outcomes = []

    class FaultConsumer:
        def consume(self, **values):
            """呼叫真實交易一次，分別記錄伺服器取消寫入或遮蔽已提交的成功結果。"""
            attempts.append(values)
            try:
                result = store.consume(**values)
            except psycopg.errors.QueryCanceled:
                outcomes.append("server_timeout")
                raise
            outcomes.append(result)
            if fault == "lost_commit_result":
                raise ConnectionError("injected lost commit acknowledgement")
            return result

    run = AsyncMock()
    app = create_app(SimpleNamespace(gate=object(), run=run), runtime=None,
                     generation_config=None, assessment_provider=provider(FaultConsumer()))
    request = vector_request()
    with psycopg.connect(scoped) as blocker, TestClient(app) as client:
        if fault == "write_timeout":
            blocker.execute("LOCK TABLE replay_entries IN ACCESS EXCLUSIVE MODE")
        response = client.get(request.raw_url, headers={
            "X-Request-ID": request.request_id, "X-Trusted-Session": token()})
    assert response.status_code == 503
    assert response.json() == {"code": "pipeline_unavailable", "request_id": request.request_id}
    run.assert_not_called()
    assert len(attempts) == 1
    expected = ["server_timeout"] if fault == "write_timeout" else [ReplayConsumeResult.ACCEPTED]
    assert outcomes == expected
    with psycopg.connect(scoped) as observer:
        rows = observer.execute("SELECT jti FROM replay_entries").fetchall()
    assert rows == ([] if fault == "write_timeout" else [(VECTOR["claims"]["jti"],)])
    if fault == "lost_commit_result":
        assert PostgresReplayStore(scoped).consume(**attempts[0]) is ReplayConsumeResult.REPLAY


@pytest.mark.parametrize("committed", [True, False], ids=["commit-applied", "commit-not-applied"])
def test_unknown_world_initialization_reads_once_without_recreating(isolated_test_dsn, committed):
    """在 COMMIT 邊界注入失聯，核對恢復只讀一次、無第二次建立且快照完整。"""
    from unittest.mock import MagicMock, patch
    import psycopg
    from deception.world import WorldSnapshot

    store = PostgresWorldStore(isolated_test_dsn)
    target = scope(uuid4().hex)
    state = {"owner": "synthetic-init"}
    expected = WorldSnapshot.create(target, state)
    write = psycopg.connect(isolated_test_dsn)
    wrapped = MagicMock(wraps=write)

    def uncertain_commit():
        """選擇實際提交或保持未提交，並向呼叫端注入相同的未知結果。"""
        if committed:
            write.commit()
        raise psycopg.OperationalError("injected missing commit reply")

    wrapped.commit.side_effect = uncertain_commit
    with psycopg.connect(isolated_test_dsn) as observer:
        observer.read_only = True
        with patch.object(store, "_connection", side_effect=[wrapped, observer]) as connect:
            if committed:
                assert store.create_if_absent(target, state) == expected
            else:
                with pytest.raises(WorldStoreError, match="world_initialization_unverifiable:session_not_found"):
                    store.create_if_absent(target, state)
            assert connect.call_count == 2
        wrapped.commit.assert_called_once_with()
    with psycopg.connect(isolated_test_dsn) as independent:
        rows = independent.execute("SELECT version, state_hash FROM world_snapshots").fetchall()
    assert rows == ([(1, expected.state_hash)] if committed else [])


def test_committed_cas_survives_interrupted_http_response(isolated_test_dsn):
    """透過本機 HTTP 半截回應驗證提交後斷線、歷史收據查詢與重複 ID 回滾。"""
    from http.client import HTTPConnection, IncompleteRead
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from threading import Thread

    store = PostgresWorldStore(isolated_test_dsn)
    target = scope(uuid4().hex)
    store.create_if_absent(target, {"stock": 5})
    attempt = uuid4()
    committed = []

    class InterruptedResponse(BaseHTTPRequestHandler):
        def do_POST(self):
            """執行一次合成 CAS，提交後送出 HTTP 標頭與部分本文並結束連線。"""
            committed.append(store.compare_and_swap(target, expected_version=1,
                             state={"stock": 4}, commit_attempt_id=attempt))
            self.send_response(200)
            self.send_header("Content-Length", "8")
            self.end_headers()
            self.wfile.write(b"part")
            self.close_connection = True

    with HTTPServer(("127.0.0.1", 0), InterruptedResponse) as server:
        worker = Thread(target=server.handle_request, daemon=True)
        worker.start()
        client = HTTPConnection(*server.server_address, timeout=10)
        try:
            client.request("POST", "/synthetic-operation")
            response = client.getresponse()
            assert response.status == 200
            with pytest.raises(IncompleteRead) as error:
                response.read()
            assert error.value.partial == b"part"
        finally:
            client.close()
            worker.join(10)
    original, = committed
    observer = PostgresWorldStore(isolated_test_dsn)
    assert observer.load(target) == original
    # 使目前快照前進，檢查 lookup 仍指向原提交。
    later = store.compare_and_swap(target, expected_version=2, state={"stock": 3})
    receipt = observer.get_commit_result(target, attempt, authorized_scope=target)
    assert (receipt.status, receipt.state_version, receipt.state_hash) == (
        "committed", 2, original.state_hash)
    assert observer.get_commit_result(target, uuid4(), authorized_scope=target).status == "not_found"
    assert observer.get_commit_result(target, attempt, authorized_scope=scope(uuid4().hex)).status == "unverifiable"
    with pytest.raises(WorldStoreError, match="commit_attempt_already_used"):
        store.compare_and_swap(target, expected_version=3, state={"stock": 2}, commit_attempt_id=attempt)
    assert observer.load(target) == later


def ordered_transactions(dsn, first_store, first, second_store, second):
    """持有先行交易，確認另一連線正在等它的鎖，再依序提交並回傳兩個結果。"""
    from contextlib import nullcontext
    from time import monotonic, sleep
    from unittest.mock import patch
    import psycopg

    with psycopg.connect(dsn) as leader, psycopg.connect(dsn) as waiter:
        with (
            patch.object(first_store, "_connection", return_value=nullcontext(leader)),
            patch.object(second_store, "_connection", return_value=nullcontext(waiter)),
        ):
            first_result = first()
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(second)
                try:
                    deadline = monotonic() + 10
                    while True:
                        blockers, = leader.execute("SELECT pg_blocking_pids(%s)",
                                                   (waiter.info.backend_pid,)).fetchone()
                        if leader.info.backend_pid in blockers:
                            break
                        assert not future.done() and monotonic() < deadline, "second transaction did not wait"
                        sleep(0.02)
                finally:
                    leader.commit()
                second_result = future.result(timeout=10)
            waiter.commit()
    return first_result, second_result


@pytest.mark.parametrize("grant_first", [True, False], ids=["grant-first", "revoke-first"])
def test_registry_revoke_orders_concurrent_grant(isolated_test_dsn, grant_first):
    """持有先行交易直到資料庫確認第二條連線正在等鎖，再檢查兩種提交順序。"""
    registry = PostgresProjectionRegistry(isolated_test_dsn)
    control = PostgresAdmissionControl(isolated_test_dsn)
    evidence = projection_evidence(uuid4().hex * 2)
    registry.register(evidence, registry_revision=1)
    generation = uuid4().hex

    def issue():
        """使用同一世代和 Registry 證據嘗試取得新的 Grant。"""
        return grant_registered(control, generation, evidence, registry)

    def revoke():
        """從另一個資料庫交易把同一契約撤銷至 revision 2。"""
        registry.revoke(evidence.projection_contract_hash, registry_revision=2)

    operations = (control, issue, registry, revoke) if grant_first else (registry, revoke, control, issue)
    first_result, second_result = ordered_transactions(isolated_test_dsn, *operations)
    import psycopg
    assert issue() is None
    with psycopg.connect(isolated_test_dsn) as observer:
        rows = observer.execute("SELECT admission_id FROM response_admissions").fetchall()
        revision, revoked = observer.execute("SELECT registry_revision, revoked FROM projection_registry").fetchone()
    assert (revision, revoked) == (2, True)
    if grant_first:
        assert first_result.projection_registry_revision == 1
        assert rows == [(first_result.admission_id,)]
    else:
        assert second_result is None
        assert rows == []


@pytest.mark.parametrize("grant_first", [True, False], ids=["grant-first", "cutover-first"])
def test_generation_cutover_orders_grant_and_claim(isolated_test_dsn, grant_first):
    """確認世代封存與准入的鎖順序、期限與並行 Claim 的單次使用。"""
    import psycopg

    issuer = PostgresAdmissionControl(isolated_test_dsn)
    controller = PostgresAdmissionControl(isolated_test_dsn)
    registry = PostgresProjectionRegistry(isolated_test_dsn)
    evidence = projection_evidence(uuid4().hex * 2)
    registry.register(evidence, registry_revision=1)
    generation = uuid4().hex

    def issue():
        """在指定世代以已登錄的合成證據申請准入。"""
        return grant_registered(issuer, generation, evidence, registry)

    def seal():
        """以另一個控制器封存同一世代，取得封存 revision。"""
        return controller.cutover(generation)

    # 預建一張准入，同時驗證競爭發生在既有世代列，並測期限相等。
    earlier = issue()
    if grant_first:
        admission, cutover = ordered_transactions(isolated_test_dsn, issuer, issue, controller, seal)
    else:
        cutover, admission = ordered_transactions(isolated_test_dsn, controller, seal, issuer, issue)
    assert seal() == cutover
    assert issue() is None
    assert controller.claim(earlier.admission_id, owner="late", now=earlier.authorization_deadline
                            ) is AdmissionOperationResult.EXPIRED
    with psycopg.connect(isolated_test_dsn) as observer:
        count, = observer.execute("SELECT count(*) FROM response_admissions").fetchone()
    if not grant_first:
        assert admission is None and count == 1 and cutover == earlier.grant_revision + 1
        return
    assert count == 2 and earlier.grant_revision < admission.grant_revision < cutover
    before_deadline = admission.authorization_deadline - 1

    def first_claim():
        """由先取得鎖的控制器，在期限內領取封存前的准入。"""
        return issuer.claim(admission.admission_id, owner="first", now=before_deadline)

    def competing_claim():
        """由另一條連線競爭同一准入，確認不能重複領取。"""
        return controller.claim(admission.admission_id, owner="second", now=before_deadline)

    assert ordered_transactions(isolated_test_dsn, issuer, first_claim, controller, competing_claim) == (
        AdmissionOperationResult.SUCCESS, AdmissionOperationResult.ALREADY_CLAIMED)
    assert controller.event_revision(admission.admission_id, "claim") == cutover + 1
    assert controller.state(admission.admission_id) is AdmissionState.CLAIMED


@pytest.mark.parametrize("send_first", [True, False], ids=["send-first", "revoke-first"])
def test_emergency_revocation_orders_send_authorization(isolated_test_dsn, send_first):
    """以真實鎖等待驗證緊急撤銷的發送邊界、持久化結果及世代隔離。"""
    sender = PostgresAdmissionControl(isolated_test_dsn)
    admin = PostgresAdmissionControl(isolated_test_dsn)
    registry = PostgresProjectionRegistry(isolated_test_dsn)
    evidence = projection_evidence(uuid4().hex * 2)
    registry.register(evidence, registry_revision=1)
    generation = uuid4().hex
    first = grant_registered(sender, generation, evidence, registry)
    waiting = grant_registered(sender, generation, evidence, registry)
    assert sender.claim(first.admission_id, owner="sender", now=1) is AdmissionOperationResult.SUCCESS

    def authorize():
        """以一般發送路徑查核共享撤銷狀態，呼叫端不傳 revoked 旗標。"""
        return sender.authorize_send(first.admission_id, now=2)

    def revoke():
        """從另一個交易撤銷世代並取得其持久化 revision。"""
        return admin.emergency_revoke(generation)

    if send_first:
        result, revision = ordered_transactions(isolated_test_dsn, sender, authorize, admin, revoke)
    else:
        revision, result = ordered_transactions(isolated_test_dsn, admin, revoke, sender, authorize)
    observer = PostgresAdmissionControl(isolated_test_dsn)
    assert observer.emergency_revoke(generation) == revision
    assert observer.event_revision(first.admission_id, "emergency_revocation") == revision
    if send_first:
        assert result is AdmissionOperationResult.SUCCESS
        assert observer.event_revision(first.admission_id, "send_authorization") == revision - 1
        assert observer.state(first.admission_id) is AdmissionState.SEND_AUTHORIZED
    else:
        assert result is AdmissionOperationResult.REJECTED
        assert observer.event_revision(first.admission_id, "send_authorization") is None
        assert observer.state(first.admission_id) is AdmissionState.ABANDONED
    assert authorize() is AdmissionOperationResult.REJECTED
    assert observer.claim(waiting.admission_id, owner="late", now=3) is AdmissionOperationResult.REJECTED
    assert observer.state(waiting.admission_id) is AdmissionState.ABANDONED
    assert grant_registered(observer, generation, evidence, registry) is None
    assert grant_registered(observer, uuid4().hex, evidence, registry) is not None


def test_freeze_v1_start_send_after_generation_emergency_keeps_owner_and_single_use(isolated_test_dsn):
    """授權後才撤銷 Generation 不回溯拒絕，但仍拒絕錯 owner、過期及重送。"""
    control = PostgresAdmissionControl(isolated_test_dsn)
    registry = PostgresProjectionRegistry(isolated_test_dsn)
    evidence = projection_evidence(uuid4().hex * 2)
    registry.register(evidence, registry_revision=1)
    generation = uuid4().hex
    admission = grant_registered(control, generation, evidence, registry)
    identifier = admission.admission_id

    assert control.claim(identifier, owner="sender", now=100) is AdmissionOperationResult.SUCCESS
    assert control.authorize_send(identifier, now=100) is AdmissionOperationResult.SUCCESS
    still_valid = grant_registered(control, generation, evidence, registry)
    assert control.claim(still_valid.admission_id, owner="sender", now=100) is AdmissionOperationResult.SUCCESS
    assert control.authorize_send(still_valid.admission_id, now=100) is AdmissionOperationResult.SUCCESS
    control.emergency_revoke(generation)
    assert control.state(identifier) is AdmissionState.SEND_AUTHORIZED
    assert control.start_send(identifier, owner="intruder", now=101) is AdmissionOperationResult.REJECTED
    assert control.start_send(identifier, owner="sender", now=admission.transmission_deadline) is AdmissionOperationResult.REJECTED
    assert control.state(identifier) is AdmissionState.EXPIRED

    assert control.start_send(still_valid.admission_id, owner="sender", now=101) is AdmissionOperationResult.SUCCESS
    assert control.start_send(still_valid.admission_id, owner="sender", now=101) is AdmissionOperationResult.REJECTED


@pytest.mark.parametrize("at_deadline", [False, True])
def test_postgres_send_uses_transmission_deadline(isolated_test_dsn, at_deadline):
    """Claim 期限之後仍依發送期限授權，期限相等則拒絕。"""
    control = PostgresAdmissionControl(isolated_test_dsn)
    registry = PostgresProjectionRegistry(isolated_test_dsn)
    evidence = projection_evidence(uuid4().hex * 2)
    registry.register(evidence, registry_revision=1)
    admission = grant_registered(control, uuid4().hex, evidence, registry)
    assert control.claim(admission.admission_id, owner="test", now=1) is AdmissionOperationResult.SUCCESS
    now = admission.transmission_deadline if at_deadline else admission.authorization_deadline
    assert control.authorize_send(admission.admission_id, now=now) is (
        AdmissionOperationResult.REJECTED if at_deadline else AdmissionOperationResult.SUCCESS)


@pytest.mark.parametrize("fail", [False, True], ids=["completed", "interrupted"])
def test_renderer_persists_transmission_across_instances(isolated_test_dsn, candidate_and_gate, fail):
    """Renderer 的完成及部分失敗由另一個控制器讀回，重送及錯誤 owner 均拒絕。"""
    from unittest.mock import patch
    from test_renderer import emit_response
    from test_renderer_admission import response_fixture
    from deception.world.transmission import TransmissionError

    control = PostgresAdmissionControl(isolated_test_dsn)
    candidates = PostgresCandidateStore(isolated_test_dsn)
    response, request, _, handle, _ = response_fixture(
        candidate_and_gate, control=control, candidates=candidates,
        registry=PostgresProjectionRegistry(isolated_test_dsn))
    observer = PostgresAdmissionControl(isolated_test_dsn)
    real_start = control.start_send

    def observe_start(*args, **kwargs):
        """確認開始狀態已提交、Candidate 受保護，並模擬 ASGI 送出時中斷。"""
        result = real_start(*args, **kwargs)
        assert observer.state(handle.admission.admission_id) is AdmissionState.SEND_STARTED
        assert handle.admission.candidate_ref in observer.active_candidate_refs(now=2)
        assert observer.finish_send(handle.admission.admission_id, owner="other",
                                    outcome=AdmissionState.SEND_COMPLETED) is AdmissionOperationResult.REJECTED
        return result

    with patch.object(control, "start_send", side_effect=observe_start):
        if fail:
            # 讓 start 訊息發送前的傳輸期限檢查失敗，已啟動但未嘗試發送。
            with patch.object(type(handle), "check_deadline", side_effect=TimeoutError("injected deadline")):
                with pytest.raises(TimeoutError):
                    emit_response(response, request)
            expected = AdmissionState.SEND_FAILED
        else:
            emit_response(response, request)
            expected = AdmissionState.SEND_COMPLETED
    assert observer.state(handle.admission.admission_id) is expected
    assert handle.admission.candidate_ref not in observer.active_candidate_refs(now=2)
    with pytest.raises(TransmissionError):
        emit_response(response, request)
