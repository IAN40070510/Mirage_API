"""唯讀 WorldSnapshot 保存與 CAS 更新的最小安全實作。"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Protocol

from pydantic import JsonValue

from .models import WorldScope, WorldSnapshot


class WorldStoreError(RuntimeError):
    """表示 WorldStore 無法安全完成讀取或版本操作。"""


class SnapshotCorruptionError(WorldStoreError):
    """表示保存的快照完整性驗證失敗。"""


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

    def compare_and_swap(
        self,
        scope: WorldScope,
        *,
        expected_version: int,
        state: dict[str, JsonValue],
    ) -> WorldSnapshot:
        """以期望版本原子建立下一份快照。"""


class InMemoryWorldStore:
    """提供程序內、嚴格 scope 綁定的唯讀快照與 CAS 原子更新。"""

    def __init__(self) -> None:
        """建立空的 WorldStore；此實作供測試與單程序原型使用。"""
        self._lock = RLock()
        self._snapshots: dict[tuple[str, str, str, str], WorldSnapshot] = {}
        self._available = True

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
    ) -> WorldSnapshot:
        """只有版本仍相等時建立下一快照，衝突就拒絕且不覆寫資料。"""
        with self._lock:
            self._ensure_available()
            key = self._key(scope)
            current = self._snapshots.get(key)
            if current is None:
                raise WorldStoreError("world_not_found")
            if current.version != expected_version:
                raise WorldStoreError("version_conflict")
            updated = WorldSnapshot.create(scope, deepcopy(state), version=current.version + 1)
            self._snapshots[key] = updated
            return updated.model_copy(deep=True)

    def _ensure_available(self) -> None:
        """在寫入操作前拒絕不可用的 Store，避免建立替代世界。"""
        if not self._available:
            raise WorldStoreError(WorldStoreStatus.STORAGE_UNAVAILABLE.value)
