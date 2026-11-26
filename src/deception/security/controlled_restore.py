"""G5 已知單機 Restore 的 Docker 停流驗證與不可自動解封的順序控制。"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
import subprocess
from typing import Callable, Protocol, Sequence
from uuid import UUID

from deception.security.restore_bootstrap import (
    RestoreBootstrapError, quarantine_restored_world,
)


class ControlledRestoreError(ValueError):
    """表示容器身分、狀態、停流或受控還原順序未達安全前提。"""


@dataclass(frozen=True)
class RestoreContainer:
    """綁定完整不可變 Docker ID、預期名稱與 ingress/sender 角色。"""

    container_id: str
    name: str
    role: str


class RestoreIsolation(Protocol):
    """實際控制面必須提供可重複驗證的停流操作，不接受人工布林聲明。"""

    def stop_and_verify(self) -> None:
        """停用所有指定入口與 Sender，並核對程序已結束。"""

    def require_quiescent(self) -> None:
        """還原前後重新驗證指定所有程序都未運行。"""


class DockerRestoreIsolation:
    """使用本機 Docker socket、精確 ID 和 opt-in Label 操作指定容器。"""

    _LABEL_ROLE = "mirage.restore.role"
    _LABEL_ELIGIBLE = "mirage.restore.stop_eligible"

    def __init__(self, containers: Sequence[RestoreContainer], *,
                 docker_binary: str = "/usr/bin/docker") -> None:
        """在任何 Docker 操作前拒絕模糊 ID、名稱、重複身分及缺少角色。"""
        specs = tuple(containers)
        if (not specs or len(specs) > 16
                or any(not isinstance(spec, RestoreContainer) for spec in specs)):
            raise ControlledRestoreError("g5_restore_container_manifest_invalid")
        if ({spec.role for spec in specs} != {"ingress", "sender"}
                or len({spec.container_id for spec in specs}) != len(specs)
                or len({spec.name for spec in specs}) != len(specs)):
            raise ControlledRestoreError("g5_restore_container_manifest_invalid")
        for spec in specs:
            if (not isinstance(spec.container_id, str)
                    or not isinstance(spec.name, str)
                    or not isinstance(spec.role, str)
                    or re.fullmatch(r"[0-9a-f]{64}", spec.container_id) is None
                    or re.fullmatch(r"/[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", spec.name) is None
                    or spec.role not in {"ingress", "sender"}):
                raise ControlledRestoreError("g5_restore_container_manifest_invalid")
        if docker_binary != "/usr/bin/docker":
            raise ControlledRestoreError("g5_restore_docker_binary_untrusted")
        self._containers = specs
        self._docker_binary = docker_binary

    def _docker(self, *args: str) -> bytes:
        """只向本機 daemon 發送固定形式指令，失敗不暴露 stderr 或環境秘密。"""
        try:
            result = subprocess.run(
                [self._docker_binary, "--host", "unix:///var/run/docker.sock", *args],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=30, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise ControlledRestoreError("g5_restore_docker_unavailable") from None
        if result.returncode != 0 or len(result.stdout) > 256 * 1024:
            raise ControlledRestoreError("g5_restore_docker_unavailable")
        return result.stdout

    def _inspect(self) -> dict[str, dict]:
        """同批讀取完整 Docker 身分；綁定 opt-in 標籤與禁止自動重啟策略。"""
        try:
            payload = json.loads(self._docker(
                "container", "inspect", *(spec.container_id for spec in self._containers),
            ))
            if not isinstance(payload, list) or len(payload) != len(self._containers):
                raise ValueError("unexpected_container_set")
            inspected = {item["Id"]: item for item in payload}
            if len(inspected) != len(self._containers):
                raise ValueError("duplicate_container_identity")
            for spec in self._containers:
                entry = inspected[spec.container_id]
                if (entry["Name"] != spec.name
                        or entry["Config"]["Labels"].get(self._LABEL_ELIGIBLE) != "true"
                        or entry["Config"]["Labels"].get(self._LABEL_ROLE) != spec.role
                        or entry["HostConfig"]["RestartPolicy"]["Name"] != "no"
                        or entry["HostConfig"].get("AutoRemove") is True):
                    raise ValueError("container_not_opted_in")
            self._verify_compose_membership(inspected)
            return inspected
        except ControlledRestoreError:
            raise
        except (ValueError, KeyError, TypeError, AttributeError):
            raise ControlledRestoreError("g5_restore_container_identity_invalid") from None

    def _verify_compose_membership(self, inspected: dict[str, dict]) -> None:
        """標準 Compose 還原每次核對同一專案的 Gateway、Verifier 與 Sender 全部實例。"""
        labels = [entry["Config"]["Labels"] for entry in inspected.values()]
        project_key = "com.docker.compose.project"
        if all(project_key not in item for item in labels):
            return
        projects = {item.get(project_key) for item in labels}
        if len(projects) != 1:
            raise ControlledRestoreError("g5_restore_compose_project_invalid")
        project = projects.pop()
        if not isinstance(project, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", project):
            raise ControlledRestoreError("g5_restore_compose_project_invalid")
        roles = {"gateway": "ingress", "verifier": "ingress", "sender": "sender"}
        service_key = "com.docker.compose.service"
        if ({item.get(service_key) for item in labels} != set(roles)
                or any(roles[item[service_key]] != item[self._LABEL_ROLE] for item in labels)):
            raise ControlledRestoreError("g5_restore_compose_manifest_incomplete")
        rows = self._docker(
            "container", "ls", "--all", "--no-trunc", "--filter",
            f"label={project_key}={project}", "--format",
            '{{.ID}}|{{.Label "com.docker.compose.service"}}|{{.Label "mirage.restore.stop_eligible"}}',
        ).decode("ascii").splitlines()
        discovered = set()
        for row in rows:
            container_id, service, eligible = row.split("|")
            if service in roles or eligible == "true":
                discovered.add(container_id)
        if discovered != set(inspected):
            raise ControlledRestoreError("g5_restore_compose_manifest_incomplete")

    def stop_and_verify(self) -> None:
        """先驗證全部 opt-in 身分再依精確 ID 停機，之後確認無活躍 PID。"""
        inspected = self._inspect()
        for spec in self._containers:
            state = inspected[spec.container_id]["State"]
            if state.get("Running") or state.get("Restarting"):
                self._docker("container", "stop", "--time", "10", spec.container_id)
        self.require_quiescent()

    def require_quiescent(self) -> None:
        """每個既定完整 ID 必須已退出或尚未啟動，且沒有運行中的 PID。"""
        inspected = self._inspect()
        for spec in self._containers:
            state = inspected[spec.container_id]["State"]
            if (state.get("Status") not in {"exited", "created"}
                    or state.get("Running") is not False
                    or state.get("Restarting") is not False
                    or state.get("Dead") is not False
                    or state.get("Pid") != 0):
                raise ControlledRestoreError("g5_restore_ingress_or_sender_not_quiescent")


def run_controlled_known_restore(*, isolation: RestoreIsolation,
                                 restore_world: Callable[[], None],
                                 restore_event_id: UUID,
                                 recorder_dsn: str, recorder_login: str,
                                 sender_dsn: str, sender_login: str,
                                 schema: str) -> bool:
    """機器停流→再次驗證→指定 Restore→再驗證→Marker 雙帳號落盤及讀回。

    任何步驟失敗不會呼叫 Sender 啟動／恢復入口；成功也**不會解封**。
    僅涵蓋列出的 Docker 容器；沒有主機全程序發現、防止他人並行
    docker start 的鎖、在途封包處置或整機備份域外 Fence，不能直接 GO。
    """
    if not isinstance(restore_event_id, UUID) or restore_event_id.version != 4:
        raise ControlledRestoreError("g5_restore_uuid4_required")
    if not callable(restore_world):
        raise ControlledRestoreError("g5_restore_action_required")
    try:
        isolation.stop_and_verify()
        isolation.require_quiescent()
        restore_world()
        isolation.require_quiescent()
        inserted = quarantine_restored_world(
            restore_event_id=restore_event_id, recorder_dsn=recorder_dsn,
            recorder_login=recorder_login, sender_dsn=sender_dsn,
            sender_login=sender_login, schema=schema,
            ingress_stopped=True, restore_complete=True,
        )
        isolation.require_quiescent()
        return inserted
    except (ControlledRestoreError, RestoreBootstrapError):
        raise
    except Exception:
        # 操作型錯誤（包含 subprocess/DB）只使用固定碼；絕不重啟服務。
        raise ControlledRestoreError("g5_restore_action_failed_quarantine_required") from None
