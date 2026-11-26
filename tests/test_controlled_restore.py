"""G5 Docker 實體停流、身分綁定及 Known Restore 順序失敗封閉測試。"""

import json
import os
import subprocess
from uuid import UUID, uuid4

import pytest

from deception.security import controlled_restore
from deception.security.controlled_restore import (
    ControlledRestoreError, DockerRestoreIsolation, RestoreContainer,
    run_controlled_known_restore,
)


INGRESS_ID = "a" * 64
SENDER_ID = "b" * 64
CONTAINERS = (
    RestoreContainer(INGRESS_ID, "/mirage-test-ingress", "ingress"),
    RestoreContainer(SENDER_ID, "/mirage-test-sender", "sender"),
)


def _inspection(spec: RestoreContainer, *, running: bool = True,
                eligible: bool = True, restart: str = "no") -> dict:
    """產生完整 Docker inspect 的隔離模擬；不存入任何真身分或機密。"""
    return {
        "Id": spec.container_id, "Name": spec.name,
        "Config": {"Labels": {
            "mirage.restore.role": spec.role,
            "mirage.restore.stop_eligible": "true" if eligible else "false",
        }},
        "HostConfig": {"RestartPolicy": {"Name": restart}, "AutoRemove": False},
        "State": {"Status": "running" if running else "exited", "Running": running,
                  "Restarting": False, "Dead": False, "Pid": 195 if running else 0},
    }


def test_docker_manifest_rejects_ambiguous_or_weak_container_identity():
    """不允許短 ID、名稱重綁、角色缺失、重複 ID 或任意 Docker 路徑。"""
    for manifest in (
        (), CONTAINERS[:1], (CONTAINERS[0], CONTAINERS[0]),
        (RestoreContainer("a" * 12, "/mirage-test-ingress", "ingress"), CONTAINERS[1]),
        (RestoreContainer(INGRESS_ID, "/not-safe/ingress", "ingress"), CONTAINERS[1]),
        (RestoreContainer(INGRESS_ID, CONTAINERS[1].name, "ingress"), CONTAINERS[1]),
    ):
        with pytest.raises(ControlledRestoreError, match="manifest_invalid"):
            DockerRestoreIsolation(manifest)
    with pytest.raises(ControlledRestoreError, match="binary_untrusted"):
        DockerRestoreIsolation(CONTAINERS, docker_binary="docker")


def test_docker_stop_verifies_both_exact_ids_and_never_starts(monkeypatch):
    """先一次核對身分再逐一停止兩個容器，重查 PID／Restart，沒有 start。"""
    states = {spec.container_id: True for spec in CONTAINERS}
    calls = []

    def fake_run(argv, **kwargs):
        """拒絕未綁定本機 daemon 的 Docker 呼叫，模擬精確 ID 停機。"""
        assert argv[:3] == ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"]
        assert kwargs["stdin"] == subprocess.DEVNULL
        calls.append(argv[3:])
        if argv[3:5] == ["container", "inspect"]:
            assert argv[5:] == [INGRESS_ID, SENDER_ID]
            payload = [_inspection(spec, running=states[spec.container_id])
                       for spec in CONTAINERS]
            return subprocess.CompletedProcess(argv, 0, json.dumps(payload).encode(), b"")
        assert argv[3:6] == ["container", "stop", "--time"]
        assert argv[6] == "10" and argv[7] in states
        states[argv[7]] = False
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(controlled_restore.subprocess, "run", fake_run)
    isolated = DockerRestoreIsolation(CONTAINERS)
    isolated.stop_and_verify()
    isolated.require_quiescent()
    assert states == {INGRESS_ID: False, SENDER_ID: False}
    assert len([command for command in calls if command[:2] == ["container", "stop"]]) == 2
    assert all(command[1] != "start" for command in calls)


@pytest.mark.parametrize("variation", ["wrong_label", "unexpected_name", "restart_policy",
                                          "replaced_id", "running_after_stop"])
def test_docker_proof_rejects_identity_or_quiescence_bypass(monkeypatch, variation):
    """身份被換、非 opt-in、daemon 自動重啟或停機後仍在運行都失敗。"""
    calls = []

    def fake_run(argv, **kwargs):
        """依攻擊類型回傳惡意 inspect 或停機無效情形。"""
        calls.append(argv[3:])
        if argv[3:5] == ["container", "inspect"]:
            payload = [_inspection(spec) for spec in CONTAINERS]
            if variation == "wrong_label":
                payload[0]["Config"]["Labels"]["mirage.restore.stop_eligible"] = "false"
            elif variation == "unexpected_name":
                payload[0]["Name"] = "/rebound-name"
            elif variation == "restart_policy":
                payload[0]["HostConfig"]["RestartPolicy"]["Name"] = "always"
            elif variation == "replaced_id":
                payload[0]["Id"] = "c" * 64
            return subprocess.CompletedProcess(argv, 0, json.dumps(payload).encode(), b"")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(controlled_restore.subprocess, "run", fake_run)
    with pytest.raises(ControlledRestoreError):
        DockerRestoreIsolation(CONTAINERS).stop_and_verify()
    assert variation == "running_after_stop" or not any(
        command[:2] == ["container", "stop"] for command in calls
    )


def test_controlled_restore_seals_before_and_after_restore_and_marker(monkeypatch):
    """先證實停流再 Restore、重查、寫入／讀回 Marker、再次查停流。"""
    calls = []
    event = uuid4()

    class Isolated:
        """記錄控制面被依正確順序呼叫，沒有啟動或 Release 方法。"""

        def stop_and_verify(self):
            """模擬經檢驗的 ingress/Sender 停用。"""
            calls.append("stop")

        def require_quiescent(self):
            """每個狀態轉換都應再次讀取程序運行狀態。"""
            calls.append("inspect")

    def restore():
        """僅在第一次正式停流核對後執行 Restore 回呼。"""
        calls.append("restore")

    def marker(**kwargs):
        """必須取得控制器完成的停流和 Restore 事實才能寫入。"""
        assert kwargs["restore_event_id"] == event
        assert kwargs["ingress_stopped"] is True
        assert kwargs["restore_complete"] is True
        calls.append("marker")
        return True

    monkeypatch.setattr(controlled_restore, "quarantine_restored_world", marker)
    assert run_controlled_known_restore(
        isolation=Isolated(), restore_world=restore, restore_event_id=event,
        recorder_dsn="sealed-recorder", recorder_login="recorder",
        sender_dsn="sealed-sender", sender_login="sender", schema="world_data",
    ) is True
    assert calls == ["stop", "inspect", "restore", "inspect", "marker", "inspect"]


@pytest.mark.parametrize("fail_stage", ["stop", "pre_restore", "restore",
                                            "post_restore", "marker", "post_marker"])
def test_controlled_restore_failure_never_rearms_or_skips_stages(monkeypatch, fail_stage):
    """每個錯誤分支都中止且不得再執行任何後續步驟或偷偷重啟。"""
    calls = []
    inspections = 0

    class Isolated:
        """在指定停機或驗證階段模擬單機故障。"""

        def stop_and_verify(self):
            """停機失敗時禁止 Restore。"""
            calls.append("stop")
            if fail_stage == "stop":
                raise OSError("unsafe daemon error")

        def require_quiescent(self):
            """重新啟動或查詢錯誤視為不安全，不容跳過。"""
            nonlocal inspections
            inspections += 1
            calls.append("inspect")
            if (fail_stage, inspections) in {
                ("pre_restore", 1), ("post_restore", 2), ("post_marker", 3),
            }:
                raise ControlledRestoreError("g5_restore_ingress_or_sender_not_quiescent")

    def restore():
        """僅停流確認後執行；即使未知 COMMIT 也不進 Marker。"""
        calls.append("restore")
        if fail_stage == "restore":
            raise RuntimeError("raw DSN / unwanted secret")

    def marker(**kwargs):
        """記錄落盤嘗試；失敗後不可繼續後續核對。"""
        calls.append("marker")
        if fail_stage == "marker":
            raise RuntimeError("raw DSN / unwanted secret")
        return False

    monkeypatch.setattr(controlled_restore, "quarantine_restored_world", marker)
    with pytest.raises(ControlledRestoreError) as failure:
        run_controlled_known_restore(
            isolation=Isolated(), restore_world=restore, restore_event_id=uuid4(),
            recorder_dsn="secret", recorder_login="recorder",
            sender_dsn="secret", sender_login="sender", schema="world_data",
        )
    assert "raw DSN" not in str(failure.value)
    assert not any(action in calls for action in ("start", "release", "resume"))
    if fail_stage in {"stop", "pre_restore"}:
        assert "restore" not in calls and "marker" not in calls
    if fail_stage in {"restore", "post_restore"}:
        assert "marker" not in calls


def test_controlled_restore_rejects_non_uuid4_before_stopping():
    """錯誤事件 ID 不得開始停機、資料庫還原或其他副作用。"""
    with pytest.raises(ControlledRestoreError, match="uuid4_required"):
        run_controlled_known_restore(
            isolation=None, restore_world=lambda: None, restore_event_id=UUID(int=0),
            recorder_dsn="", recorder_login="", sender_dsn="", sender_login="",
            schema="world_data",
        )


def test_real_disposable_docker_stop_only_two_labeled_containers():
    """明確 opt-in 才以無網路一次性容器測真正 PID 歸零與重啟策略。"""
    if os.environ.get("MIRAGE_G5_REAL_DOCKER_QUIESCE_ISOLATED") != "true":
        pytest.skip("requires explicitly isolated disposable Docker stop opt-in")
    image = "postgres:17.6-alpine"
    created = []
    try:
        for role in ("ingress", "sender"):
            name = "mirage-g5-stop-" + role + "-" + uuid4().hex[:12]
            command = [
                "/usr/bin/docker", "--host", "unix:///var/run/docker.sock",
                "container", "run", "--detach", "--network", "none", "--pull", "never",
                "--restart", "no", "--name", name,
                "--label", "mirage.restore.stop_eligible=true",
                "--label", "mirage.restore.role=" + role,
                "--entrypoint", "sleep", image, "120",
            ]
            result = subprocess.run(command, capture_output=True, check=False, timeout=30)
            assert result.returncode == 0, "isolated_disposable_container_start_failed"
            container_id = result.stdout.decode("ascii").strip()
            assert len(container_id) == 64
            created.append(RestoreContainer(container_id, "/" + name, role))
        isolation = DockerRestoreIsolation(created)
        isolation.stop_and_verify()
        isolation.require_quiescent()
    finally:
        # 僅精確回收本次已成功建立且記錄完整 ID 的一次性容器。
        for spec in created:
            subprocess.run([
                "/usr/bin/docker", "--host", "unix:///var/run/docker.sock",
                "container", "rm", "--force", "--volumes", spec.container_id,
            ], capture_output=True, check=False, timeout=30)


@pytest.mark.parametrize("variant", ["complete", "missing_gateway", "extra_replica", "mixed_project"])
def test_compose_restore_checks_project_inventory(monkeypatch, variant):
    """每次查停流應枚舉整個 Compose 專案，拒絕漏列服務、副本與混入其他專案。"""
    gateway = RestoreContainer("c" * 64, "/gateway", "ingress")
    specs = (*CONTAINERS, gateway)
    services = ("verifier", "sender", "gateway")
    inspected = []
    rows = []
    for spec, service in zip(specs, services):
        item = _inspection(spec, running=False)
        labels = item["Config"]["Labels"]
        labels["com.docker.compose.project"] = "demo"
        labels["com.docker.compose.service"] = service
        rows.append(f"{spec.container_id}|{service}|true")
        inspected.append(item)
    if variant == "missing_gateway":
        specs = specs[:-1]
        inspected.pop()
    elif variant == "mixed_project":
        inspected[-1]["Config"]["Labels"]["com.docker.compose.project"] = "other"
    elif variant == "extra_replica":
        rows.append(f"{'d' * 64}|gateway|true")
    isolation = DockerRestoreIsolation(specs)

    def docker(*args):
        """以固定清單回應 inspect 與專案查詢，禁止執行其他命令。"""
        if args[:2] == ("container", "inspect"):
            return json.dumps(inspected).encode()
        assert args[:6] == ("container", "ls", "--all", "--no-trunc", "--filter",
                            "label=com.docker.compose.project=demo")
        return "\n".join([*rows, "e" * 64 + "|postgres|"]).encode()

    monkeypatch.setattr(isolation, "_docker", docker)
    if variant == "complete":
        isolation.require_quiescent()
    else:
        with pytest.raises(ControlledRestoreError):
            isolation.require_quiescent()


def test_real_compose_restore_requires_stopped_replica_in_manifest():
    """以真 Docker 驗證同一 Compose 專案已停止的副本也必須列入停流清單。"""
    if os.environ.get("MIRAGE_G5_REAL_DOCKER_QUIESCE_ISOLATED") != "true":
        pytest.skip("requires explicitly isolated disposable Docker daemon")
    project = "mirage-restore-" + uuid4().hex
    docker = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "container"]
    created = []
    try:
        for service in ("gateway", "verifier", "sender", "gateway"):
            role = "sender" if service == "sender" else "ingress"
            name = f"{project}-{service}-{len(created)}"
            container_id = subprocess.check_output([
                *docker, "create", "--pull", "never", "--network", "none", "--name", name,
                "--label", "com.docker.compose.project=" + project,
                "--label", "com.docker.compose.service=" + service,
                "--label", "mirage.restore.role=" + role,
                "--label", "mirage.restore.stop_eligible=true",
                "postgres:17.6-alpine", "true",
            ], text=True, timeout=30).strip()
            created.append(RestoreContainer(container_id, "/" + name, role))
        with pytest.raises(ControlledRestoreError, match="^g5_restore_compose_manifest_incomplete$"):
            DockerRestoreIsolation(created[:-1]).require_quiescent()
        DockerRestoreIsolation(created).require_quiescent()
    finally:
        for spec in created:
            subprocess.run([*docker, "rm", "-v", spec.container_id], check=True, timeout=30)
