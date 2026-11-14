"""唯讀 WorldSnapshot 保存與 CAS 更新的最小安全實作。"""

from __future__ import annotations

from copy import deepcopy
from threading import RLock

from pydantic import JsonValue

from .models import WorldScope, WorldSnapshot


class WorldStoreError(RuntimeError):
    """表示 WorldStore 無法安全完成讀取或版本操作。"""


class SnapshotCorruptionError(WorldStoreError):
    """表示保存的快照完整性驗證失敗。"""


class InMemoryWorldStore:
    """提供程序內、嚴格 scope 綁定的唯讀快照與 CAS 原子更新。"""

    def __init__(self) -> None:
        """建立空的 WorldStore；此實作供測試與單程序原型使用。"""
        self._lock = RLock()
        self._snapshots: dict[tuple[str, str, str, str], WorldSnapshot] = {}

    @staticmethod
    def _key(scope: WorldScope) -> tuple[str, str, str, str]:
        """將完整 WorldScope 轉為不可混淆的保存鍵。"""
        return (
            scope.environment_id,
            scope.deployment_id,
            scope.session_id,
            scope.world_generation_id,
        )

    def create_if_absent(self, scope: WorldScope, state: dict[str, JsonValue]) -> WorldSnapshot:
        """原子建立初始快照；並行建立只會保留第一個版本。"""
        with self._lock:
            key = self._key(scope)
            existing = self._snapshots.get(key)
            if existing is not None:
                return existing.model_copy(deep=True)
            snapshot = WorldSnapshot.create(scope, deepcopy(state))
            self._snapshots[key] = snapshot
            return snapshot.model_copy(deep=True)

    def load(self, scope: WorldScope) -> WorldSnapshot | None:
        """依完整 scope 載入快照，找不到時回傳明確的空結果。"""
        with self._lock:
            snapshot = self._snapshots.get(self._key(scope))
            return None if snapshot is None else snapshot.model_copy(deep=True)

    def compare_and_swap(
        self,
        scope: WorldScope,
        *,
        expected_version: int,
        state: dict[str, JsonValue],
    ) -> WorldSnapshot:
        """只有版本仍相等時建立下一快照，衝突就拒絕且不覆寫資料。"""
        with self._lock:
            key = self._key(scope)
            current = self._snapshots.get(key)
            if current is None:
                raise WorldStoreError("world_not_found")
            if current.version != expected_version:
                raise WorldStoreError("version_conflict")
            updated = WorldSnapshot.create(scope, deepcopy(state), version=current.version + 1)
            self._snapshots[key] = updated
            return updated.model_copy(deep=True)
