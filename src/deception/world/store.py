"""唯讀 WorldSnapshot 保存與 CAS 更新的最小安全實作。"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Protocol, Literal
from uuid import UUID

from pydantic import JsonValue

from .models import WORLD_COMPATIBILITY_KEY, WorldScope, WorldSnapshot
from .commit import CommitResult


class WorldStoreError(RuntimeError):
    """表示 WorldStore 無法安全完成讀取或版本操作。"""


class SnapshotCorruptionError(WorldStoreError):
    """表示保存的快照完整性驗證失敗。"""


def require_unchanged_compatibility(current: WorldSnapshot, proposed: dict) -> None:
    """一般事件或 CAS 不得新增、移除或替換世界政策；遷移必須另有受審查流程。"""
    if current.state.get(WORLD_COMPATIBILITY_KEY) != proposed.get(WORLD_COMPATIBILITY_KEY):
        raise WorldStoreError("world_compatibility_change_forbidden")


class WorldStoreStatus(StrEnum):
    """描述 WorldStore 載入結果，避免以空值掩蓋安全失敗原因。"""

    WORLD_FOUND = "world_found"
    SESSION_NOT_FOUND = "session_not_found"
    EXPIRED = "expired"
    SCOPE_MISMATCH = "scope_mismatch"
    CORRUPTED = "corrupted"
    STORAGE_UNAVAILABLE = "storage_unavailable"


@dataclass(frozen=True)
class WorldLoadResult:
    """封裝快照載入狀態與成功時的不可變資料。"""

    status: WorldStoreStatus
    snapshot: WorldSnapshot | None = None


@dataclass(frozen=True)
class CommitLookupResult:
    """區分提交成功、拒絕、進行中、查無及無法確認，查詢不產生業務事件。"""

    status: Literal["committed", "rejected", "pending", "not_found", "unverifiable"]
    state_version: int | None = None
    state_hash: str | None = None
    commit_result: CommitResult | None = None


class WorldStore(Protocol):
    """定義共享或程序內 WorldStore 必須提供的唯讀與 CAS 操作。"""

    def create_if_absent(
        self,
        scope: WorldScope,
        state: dict[str, JsonValue],
        *,
        expires_at: int | None = None,
    ) -> WorldSnapshot:
        """以原子方式建立 scope 的第一個世界快照。"""

    def load(self, scope: WorldScope) -> WorldSnapshot | None:
        """依完整 scope 載入快照，失敗時不回傳其他 scope 的資料。"""

    def load_result(self, scope: WorldScope, *, authorized_scope: WorldScope | None = None,
                    now: int | None = None) -> WorldLoadResult:
        """區分找不到、過期、損毀及不可用，不以 None 代表全部失敗。"""

    def get_commit_result(self, scope: WorldScope, commit_attempt_id: UUID, *,
                          authorized_scope: WorldScope) -> CommitLookupResult:
        """在重新確認的完整 scope 內查詢提交結果，查無不表示從未執行。"""

    def compare_and_swap(
        self,
        scope: WorldScope,
        *,
        expected_version: int,
        state: dict[str, JsonValue],
        commit_attempt_id: UUID | None = None,
    ) -> WorldSnapshot:
        """以期望版本原子建立下一份快照。"""


class InMemoryWorldStore:
    """提供程序內、嚴格 scope 綁定的唯讀快照與 CAS 原子更新。"""

    def __init__(self) -> None:
        """建立空的 WorldStore；此實作供測試與單程序原型使用。"""
        self._lock = RLock()
        self._snapshots: dict[tuple[str, str, str, str], WorldSnapshot] = {}
        self._available = True
        self._receipts: dict[tuple[tuple[str, str, str, str], UUID], CommitLookupResult] = {}

    @staticmethod
    def _key(scope: WorldScope) -> tuple[str, str, str, str]:
        """將完整 WorldScope 轉為不可混淆的保存鍵。"""
        return (
            scope.environment_id,
            scope.deployment_id,
            scope.session_id,
            scope.world_generation_id,
        )

    def create_if_absent(
        self,
        scope: WorldScope,
        state: dict[str, JsonValue],
        *,
        expires_at: int | None = None,
    ) -> WorldSnapshot:
        """原子建立初始快照；並行建立只會保留第一個版本。"""
        with self._lock:
            self._ensure_available()
            key = self._key(scope)
            existing = self._snapshots.get(key)
            if existing is not None:
                return existing.model_copy(deep=True)
            snapshot = WorldSnapshot.create(scope, deepcopy(state), expires_at=expires_at)
            self._snapshots[key] = snapshot
            return snapshot.model_copy(deep=True)

    def load(self, scope: WorldScope) -> WorldSnapshot | None:
        """依完整 scope 載入快照，找不到時回傳明確的空結果。"""
        with self._lock:
            result = self.load_result(scope)
            return result.snapshot if result.status is WorldStoreStatus.WORLD_FOUND else None

    def load_result(
        self,
        scope: WorldScope,
        *,
        authorized_scope: WorldScope | None = None,
        now: int | None = None,
    ) -> WorldLoadResult:
        """回傳可區分找不到、過期、損毀與儲存不可用的載入結果。"""
        with self._lock:
            if not self._available:
                return WorldLoadResult(WorldStoreStatus.STORAGE_UNAVAILABLE)
            if authorized_scope is not None and authorized_scope != scope:
                return WorldLoadResult(WorldStoreStatus.SCOPE_MISMATCH)
            snapshot = self._snapshots.get(self._key(scope))
            if snapshot is None:
                return WorldLoadResult(WorldStoreStatus.SESSION_NOT_FOUND)
            if now is not None and snapshot.expires_at is not None and now >= snapshot.expires_at:
                return WorldLoadResult(WorldStoreStatus.EXPIRED)
            try:
                verified = WorldSnapshot.model_validate(snapshot.model_dump())
            except ValueError:
                return WorldLoadResult(WorldStoreStatus.CORRUPTED)
            return WorldLoadResult(WorldStoreStatus.WORLD_FOUND, verified.model_copy(deep=True))

    def set_availability(self, available: bool) -> None:
        """切換原型 Store 的可用性，供故障矩陣測試 fail-closed 行為。"""
        with self._lock:
            self._available = available

    def compare_and_swap(
        self,
        scope: WorldScope,
        *,
        expected_version: int,
        state: dict[str, JsonValue],
        commit_attempt_id: UUID | None = None,
    ) -> WorldSnapshot:
        """只有版本仍相等時建立下一快照，衝突就拒絕且不覆寫資料。"""
        if commit_attempt_id is not None and (
            not isinstance(commit_attempt_id, UUID) or commit_attempt_id.version != 4
        ):
            raise ValueError("commit_attempt_id must be UUIDv4")
        with self._lock:
            self._ensure_available()
            key = self._key(scope)
            if commit_attempt_id is not None and (key, commit_attempt_id) in self._receipts:
                raise WorldStoreError("commit_attempt_already_used")
            current = self._snapshots.get(key)
            if current is None:
                raise WorldStoreError("world_not_found")
            if current.version != expected_version:
                raise WorldStoreError("version_conflict")
            require_unchanged_compatibility(current, state)
            updated = WorldSnapshot.create(scope, deepcopy(state), version=current.version + 1,
                                           expires_at=current.expires_at)
            self._snapshots[key] = updated
            if commit_attempt_id is not None:
                self._receipts[(key, commit_attempt_id)] = CommitLookupResult(
                    "committed", updated.version, updated.state_hash)
            return updated.model_copy(deep=True)

    def get_commit_result(self, scope: WorldScope, commit_attempt_id: UUID, *,
                          authorized_scope: WorldScope) -> CommitLookupResult:
        """在原型鎖內唯讀取得該次提交，無權限或儲存不可用時回報無法確認。"""
        if (scope != authorized_scope or not isinstance(commit_attempt_id, UUID)
                or commit_attempt_id.version != 4):
            return CommitLookupResult("unverifiable")
        with self._lock:
            if not self._available:
                return CommitLookupResult("unverifiable")
            return self._receipts.get((self._key(scope), commit_attempt_id), CommitLookupResult("not_found"))

    def _ensure_available(self) -> None:
        """在寫入操作前拒絕不可用的 Store，避免建立替代世界。"""
        if not self._available:
            raise WorldStoreError(WorldStoreStatus.STORAGE_UNAVAILABLE.value)
