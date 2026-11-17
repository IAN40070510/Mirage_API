"""Profile 墓碑、一般／緊急准入邊界與 PostgreSQL 競爭排序的驗收。"""

from uuid import uuid4

import pytest

from deception.world import (AdmissionControl, AdmissionOperationResult, AdmissionState,
    PostgresAdmissionControl, PostgresProjectionRegistry, ProjectionRegistry, ProjectionRegistryError)
from test_postgres_conformance import isolated_test_dsn, grant_registered, ordered_transactions, projection_evidence
from test_http_world_isolation import http_worlds


@pytest.fixture(params=["memory", "postgres"])
def controls(request):
    """提供原型或兩個共用隔離 PostgreSQL 的控制器，缺少資料庫時只跳過持久化分支。"""
    if request.param == "memory":
        registry, control = ProjectionRegistry(), AdmissionControl()
        return registry, registry, control, control
    dsn = request.getfixturevalue("isolated_test_dsn")
    return (PostgresProjectionRegistry(dsn), PostgresProjectionRegistry(dsn),
            PostgresAdmissionControl(dsn), PostgresAdmissionControl(dsn))


def authorize(registry, evidence):
    """以完整的契約／來源／Profile 三元組查當前授權，不只比較契約名稱。"""
    return registry.authorize(projection_contract_hash=evidence.projection_contract_hash,
        source_spec_sha256=evidence.source_spec_sha256,
        compatibility_profile_sha256=evidence.compatibility_profile.profile_sha256).result.value


def issue(control, registry, evidence):
    """在新的合成世代建立准入，避免跨案例共享狀態或把 Profile revision 當世代序列。"""
    return grant_registered(control, uuid4().hex, evidence, registry)


def test_profile_tombstone_covers_present_and_future_contracts(controls):
    """整體撤銷涵蓋目前與未來契約；另一 Profile 不受影響，版本不能倒退或降級緊急模式。"""
    registry, reader, control, _ = controls
    first, second, future = [projection_evidence(uuid4().hex * 2) for _ in range(3)]
    other = projection_evidence(uuid4().hex * 2)
    other = other.model_copy(update={"compatibility_profile": other.compatibility_profile.model_copy(
        update={"profile_sha256": "4" * 64, "profile_id": "unaffected"})})
    for item in (first, second, other):
        registry.register(item, registry_revision=1)
    profile = first.compatibility_profile.profile_sha256
    state = registry.revoke_profile(profile, registry_revision=1)
    assert reader.profile_revocation(profile) == state and not state.emergency
    assert authorize(reader, first) == authorize(reader, second) == "REVOKED"
    assert authorize(reader, other) == "AUTHORIZED"
    assert issue(control, reader, first) is None
    for item in (first, future):
        with pytest.raises(ProjectionRegistryError, match="revoked_profile_cannot_be_reused"):
            registry.register(item, registry_revision=99)
    with pytest.raises(ProjectionRegistryError, match="not_monotonic"):
        registry.revoke_profile(profile, registry_revision=1)
    upgraded = registry.revoke_profile(profile, registry_revision=2, emergency=True)
    with pytest.raises(ProjectionRegistryError, match="cannot_be_downgraded"):
        registry.revoke_profile(profile, registry_revision=3)
    assert reader.profile_revocation(profile) == upgraded


def test_normal_revocation_preserves_preexisting_admission_lease(controls):
    """一般 Profile 撤銷只擋新 Grant；期限內既有准入仍能 Claim、起送與保存完成。"""
    registry, _, control, observer = controls
    evidence = projection_evidence(uuid4().hex * 2)
    registry.register(evidence, registry_revision=1)
    admission = issue(control, registry, evidence)
    registry.revoke_profile(evidence.compatibility_profile.profile_sha256, registry_revision=1)
    assert issue(control, registry, evidence) is None
    assert observer.claim(admission.admission_id, owner="sender", now=100) is AdmissionOperationResult.SUCCESS
    assert observer.authorize_send(admission.admission_id, now=100) is AdmissionOperationResult.SUCCESS
    assert observer.start_send(admission.admission_id, owner="sender", now=100) is AdmissionOperationResult.SUCCESS
    assert observer.finish_send(admission.admission_id, owner="sender", outcome=AdmissionState.SEND_COMPLETED) is AdmissionOperationResult.SUCCESS


def test_unknown_profile_can_be_banned_before_first_registration(controls):
    """尚無契約的精確 Profile 也能先設墓碑，之後首次登記不得繞過撤銷。"""
    registry, reader, _, _ = controls
    evidence = projection_evidence(uuid4().hex * 2)
    profile = evidence.compatibility_profile.profile_sha256
    registry.revoke_profile(profile, registry_revision=1)
    assert reader.profile_revocation(profile) is not None
    with pytest.raises(ProjectionRegistryError, match="revoked_profile_cannot_be_reused"):
        reader.register(evidence, registry_revision=1)


@pytest.mark.parametrize("profile,revision,emergency", [("name", 1, False), ("A" * 64, 1, False),
    ("2" * 64, True, False), ("2" * 64, 0, False), ("2" * 64, 2**63, False), ("2" * 64, 1, "true")])
def test_profile_management_rejects_ambiguous_values_before_storage(profile, revision, emergency):
    """兩個後端採同一嚴格管理輸入；不讓 bool、超界版本或字串模式變成有效撤銷。"""
    for registry in (ProjectionRegistry(), PostgresProjectionRegistry("postgresql://unused.invalid/mirage")):
        with pytest.raises(ValueError):
            registry.revoke_profile(profile, registry_revision=revision, emergency=emergency)


@pytest.mark.parametrize("stage", ["granted", "claimed", "authorized", "started"])
def test_emergency_profile_revocation_stops_unsent_output(controls, stage):
    """緊急撤銷阻止未完成的發送邊界；已起送仍記真實終態，不假稱追回已送 bytes。"""
    registry, _, control, observer = controls
    evidence = projection_evidence(uuid4().hex * 2)
    registry.register(evidence, registry_revision=1)
    admission = issue(control, registry, evidence)
    identifier = admission.admission_id
    if stage != "granted":
        assert control.claim(identifier, owner="sender", now=100) is AdmissionOperationResult.SUCCESS
    if stage in {"authorized", "started"}:
        assert control.authorize_send(identifier, now=100) is AdmissionOperationResult.SUCCESS
    if stage == "started":
        assert control.start_send(identifier, owner="sender", now=100) is AdmissionOperationResult.SUCCESS
    previous = observer.state(identifier)
    registry.revoke_profile(evidence.compatibility_profile.profile_sha256, registry_revision=1, emergency=True)
    assert observer.state(identifier) == previous
    assert issue(control, registry, evidence) is None
    if stage == "granted":
        outcome = observer.claim(identifier, owner="sender", now=100)
    elif stage == "claimed":
        outcome = observer.authorize_send(identifier, now=100)
    elif stage == "authorized":
        outcome = observer.start_send(identifier, owner="sender", now=100)
    else:
        assert observer.finish_send(identifier, owner="sender", outcome=AdmissionState.SEND_COMPLETED) is AdmissionOperationResult.SUCCESS
        assert observer.state(identifier) is AdmissionState.SEND_COMPLETED
        return
    assert outcome is AdmissionOperationResult.REJECTED
    assert observer.state(identifier) is AdmissionState.ABANDONED


def test_postgres_startup_does_not_resurrect_revoked_profile(isolated_test_dsn):
    """即使新程序提供原規格或新契約，墓碑仍讓整批啟動登記回滾，既有證據不被改寫。"""
    import psycopg

    registry = PostgresProjectionRegistry(isolated_test_dsn)
    evidence = projection_evidence(uuid4().hex * 2)
    registry.register(evidence, registry_revision=1)
    registry.revoke_profile(evidence.compatibility_profile.profile_sha256, registry_revision=1)
    restarted = PostgresProjectionRegistry(isolated_test_dsn)
    with pytest.raises(ProjectionRegistryError, match="bootstrap_profile_not_authorized"):
        restarted.ensure_registered_batch([evidence, projection_evidence(uuid4().hex * 2)])
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM projection_registry").fetchone() == (1,)
    assert authorize(restarted, evidence) == "REVOKED"


@pytest.mark.parametrize("grant_first", [True, False])
def test_postgres_profile_revoke_orders_new_grant(isolated_test_dsn, grant_first):
    """等待 pg_blocking_pids 證明兩交易競爭同一 Profile，確認一般撤銷與 Grant 的兩種先後。"""
    registry, control = PostgresProjectionRegistry(isolated_test_dsn), PostgresAdmissionControl(isolated_test_dsn)
    evidence = projection_evidence(uuid4().hex * 2)
    registry.register(evidence, registry_revision=1)

    def grant():
        """使用同一已核准 Profile 嘗試建立新的准入。"""
        return issue(control, registry, evidence)

    def revoke():
        """持有 Profile 排他鎖直到測試允許交易提交。"""
        return registry.revoke_profile(evidence.compatibility_profile.profile_sha256, registry_revision=1)

    operations = (control, grant, registry, revoke) if grant_first else (registry, revoke, control, grant)
    first, second = ordered_transactions(isolated_test_dsn, *operations)
    assert grant() is None
    if grant_first:
        assert control.claim(first.admission_id, owner="sender", now=100) is AdmissionOperationResult.SUCCESS
    else:
        assert second is None


@pytest.mark.parametrize("send_first", [True, False])
def test_postgres_emergency_profile_revoke_orders_send_authorization(isolated_test_dsn, send_first):
    """以共享／排他 Profile 控制鎖線性排序緊急撤銷與 Send Authorization，不混用世代 revision。"""
    registry, control = PostgresProjectionRegistry(isolated_test_dsn), PostgresAdmissionControl(isolated_test_dsn)
    evidence = projection_evidence(uuid4().hex * 2)
    registry.register(evidence, registry_revision=1)
    admission = issue(control, registry, evidence)
    assert control.claim(admission.admission_id, owner="sender", now=100) is AdmissionOperationResult.SUCCESS

    def authorize_send():
        """在呼叫端交易持有共享 Profile 鎖，直到發送授權提交。"""
        return control.authorize_send(admission.admission_id, now=100)

    def revoke():
        """提交會影響全部相關世代的緊急 Profile 墓碑。"""
        return registry.revoke_profile(evidence.compatibility_profile.profile_sha256, registry_revision=1, emergency=True)

    operations = (control, authorize_send, registry, revoke) if send_first else (registry, revoke, control, authorize_send)
    first, second = ordered_transactions(isolated_test_dsn, *operations)
    if send_first:
        assert first is AdmissionOperationResult.SUCCESS
        assert control.state(admission.admission_id) is AdmissionState.SEND_AUTHORIZED
        assert control.start_send(admission.admission_id, owner="sender", now=100) is AdmissionOperationResult.REJECTED
    else:
        assert second is AdmissionOperationResult.REJECTED
    assert control.state(admission.admission_id) is AdmissionState.ABANDONED


def test_profile_revocation_is_queryable_after_real_commit_reply_loss(isolated_test_dsn):
    """TCP 代理丟棄真實 COMMIT 回覆後只查墓碑，確認已提交而不盲目重做管理寫入。"""
    import psycopg
    from test_postgres_network import lost_commit_proxy

    evidence = projection_evidence(uuid4().hex * 2)
    registry = PostgresProjectionRegistry(isolated_test_dsn)
    registry.register(evidence, registry_revision=1)
    profile = evidence.compatibility_profile.profile_sha256
    with lost_commit_proxy(isolated_test_dsn) as (proxied, dropped):
        writer = PostgresProjectionRegistry(proxied)
        with pytest.raises((psycopg.OperationalError, psycopg.InterfaceError)):
            writer.revoke_profile(profile, registry_revision=1, emergency=True)
        assert dropped.is_set()
    state = PostgresProjectionRegistry(isolated_test_dsn).profile_revocation(profile)
    assert state is not None and state.registry_revision == 1 and state.emergency
    assert authorize(registry, evidence) == "REVOKED"


@pytest.mark.parametrize("bootstrap_first", [True, False])
def test_bootstrap_and_revocation_do_not_allow_profile_resurrection(isolated_test_dsn, bootstrap_first):
    """以實際鎖等待驗證首次批次登錄和 Profile 墓碑先後，不讓不存在的契約穿越撤銷。"""
    import psycopg

    writer, manager = PostgresProjectionRegistry(isolated_test_dsn), PostgresProjectionRegistry(isolated_test_dsn)
    evidence = projection_evidence(uuid4().hex * 2)

    def bootstrap():
        """模擬重啟程序原子登錄固定 Profile；拒絕回傳標記而不重試寫入。"""
        try:
            writer.ensure_registered_batch([evidence])
        except ProjectionRegistryError:
            return "rejected"
        return "registered"

    def revoke():
        """即使尚無契約仍提交墓碑，讓等待中的啟動程序看見停用事實。"""
        return manager.revoke_profile(evidence.compatibility_profile.profile_sha256, registry_revision=1)

    operations = (writer, bootstrap, manager, revoke) if bootstrap_first else (manager, revoke, writer, bootstrap)
    first, second = ordered_transactions(isolated_test_dsn, *operations)
    assert (first if bootstrap_first else second) == ("registered" if bootstrap_first else "rejected")
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM projection_registry").fetchone() == (int(bootstrap_first),)
    assert authorize(writer, evidence) == "REVOKED"


def test_profile_control_locks_are_isolated_between_schemas(isolated_test_dsn):
    """同一 DB 的不同 Registry schema 不共用撤銷鎖或墓碑；另一域不需等待管理交易。"""
    from contextlib import nullcontext
    from unittest.mock import patch
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo
    from test_postgres_conformance import apply_schema

    name = "profile_domain_" + uuid4().hex
    other_dsn = make_conninfo(isolated_test_dsn, options=f"-c search_path={name}")
    evidence = projection_evidence(uuid4().hex * 2)
    first, other = PostgresProjectionRegistry(isolated_test_dsn), PostgresProjectionRegistry(other_dsn)
    with psycopg.connect(isolated_test_dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(name)))
        try:
            apply_schema(other_dsn)
            with psycopg.connect(isolated_test_dsn) as leader, psycopg.connect(other_dsn) as independent:
                independent.execute("SET LOCAL lock_timeout='250ms'")
                with patch.object(first, "_connection", return_value=nullcontext(leader)):
                    first.revoke_profile(evidence.compatibility_profile.profile_sha256, registry_revision=1)
                with patch.object(other, "_connection", return_value=nullcontext(independent)):
                    other.register(evidence, registry_revision=1)
            assert first.profile_revocation(evidence.compatibility_profile.profile_sha256) is not None
            assert other.profile_revocation(evidence.compatibility_profile.profile_sha256) is None
            assert authorize(other, evidence) == "AUTHORIZED"
        finally:
            admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(name)))


def test_running_services_reject_pinned_revoked_profile_without_replacing_world(http_worlds, tmp_path):
    """兩個完整服務都拒絕已停用原生 Profile，其他已核准投影仍可讀同一世界；重啟不復活。"""
    import psycopg
    from deception.domains.ecommerce.http_demo import DemoConfig
    from deception.domains.ecommerce.trusted_http import create_app
    from deception.security.trusted_deployment import TrustedDeploymentSettings

    lab = http_worlds
    binding = lab.create(0, "profile-http-creator")
    path = "/store/carts/" + binding.resource_id
    assert lab.send(1, binding, "GET", path).status_code == 200
    before = lab.snapshot(binding)
    with psycopg.connect(lab.dsn) as connection:
        profile, = connection.execute("SELECT admission#>>'{projection_evidence,compatibility_profile,profile_sha256}' "
            "FROM response_admissions WHERE world_generation_id=%s ORDER BY admission_id LIMIT 1",
            (before.scope.world_generation_id,)).fetchone()
    registry = PostgresProjectionRegistry(lab.dsn)
    state = registry.revoke_profile(profile, registry_revision=1)
    for number in range(2):
        refused = lab.send(number, binding, "GET", path)
        assert refused.status_code == 503 and refused.json()["code"] == "pipeline_unavailable"
        safe = lab.send(number, binding, "GET", "/synthetic/carts/" + binding.resource_id)
        assert safe.status_code == 200 and safe.json()["cart"]["id"] == binding.resource_id
    assert lab.snapshot(binding) == before

    settings = TrustedDeploymentSettings(issuer="gateway", audience="mirage", environment_id="isolated-demo",
        deployment_id="isolated-demo", source_id="local-demo-detector", service_id="synthetic-store",
        site_id="demo-store", public_keys={"test": lab.signing.public_key().public_bytes_raw().hex()})
    with pytest.raises(ProjectionRegistryError, match="bootstrap_profile_not_authorized"):
        create_app(settings=settings, postgres_dsn=lab.dsn, output_root=tmp_path / "restart",
            config=DemoConfig(origin="https://shop.test"), enable_business=True,
            enable_medusa_store=True, medusa_publishable_key="pk_synthetic_isolation")
    assert registry.profile_revocation(profile) == state
    assert lab.snapshot(binding) == before


@pytest.mark.parametrize("level", ["REPEATABLE_READ", "SERIALIZABLE"])
def test_snapshot_isolation_cannot_hide_committed_profile_revocation(isolated_test_dsn, level):
    """先建立舊快照再提交撤銷，控制查詢必須拒絕設定或回撤銷，不能讀舊快照當成授權。"""
    from contextlib import nullcontext
    from unittest.mock import patch
    import psycopg
    from psycopg import IsolationLevel

    evidence = projection_evidence(uuid4().hex * 2)
    manager, reader = PostgresProjectionRegistry(isolated_test_dsn), PostgresProjectionRegistry(isolated_test_dsn)
    manager.register(evidence, registry_revision=1)
    with psycopg.connect(isolated_test_dsn) as connection:
        connection.isolation_level = getattr(IsolationLevel, level)
        assert connection.execute("SELECT count(*) FROM projection_profile_revocations").fetchone() == (0,)
        manager.revoke_profile(evidence.compatibility_profile.profile_sha256, registry_revision=1)
        with patch.object(reader, "_connection", return_value=nullcontext(connection)):
            try:
                decision = authorize(reader, evidence)
            except ProjectionRegistryError as error:
                assert "requires_read_committed" in str(error)
            else:
                assert decision == "REVOKED", "old transaction snapshot authorized a committed revocation"


@pytest.mark.parametrize("mode", ["REPEATABLE_READ", "SERIALIZABLE", "AUTOCOMMIT"])
def test_profile_writer_rejects_unsupported_transaction_mode(isolated_test_dsn, mode):
    """撤銷寫入拒絕舊快照或立即釋鎖設定，既有緊急墓碑的版本與模式不得被覆寫。"""
    from contextlib import nullcontext
    from unittest.mock import patch
    import psycopg
    from psycopg import IsolationLevel

    manager = PostgresProjectionRegistry(isolated_test_dsn)
    profile = uuid4().hex * 2
    original = manager.revoke_profile(profile, registry_revision=2, emergency=True)
    with psycopg.connect(isolated_test_dsn, autocommit=mode == "AUTOCOMMIT") as connection:
        if mode != "AUTOCOMMIT":
            connection.isolation_level = getattr(IsolationLevel, mode)
        with patch.object(manager, "_connection", return_value=nullcontext(connection)):
            with pytest.raises(ProjectionRegistryError, match="profile_control_requires_"):
                manager.revoke_profile(profile, registry_revision=3, emergency=True)
    assert manager.profile_revocation(profile) == original
