"""PostgreSQL 共享 WorldSnapshot 與 CAS 保存實作。"""

from __future__ import annotations

import json
from typing import Any

from pydantic import JsonValue

from .models import WorldScope, WorldSnapshot
from .store import WorldLoadResult, WorldStoreError, WorldStoreStatus

try:
    import psycopg
except ImportError:  # pragma: no cover - exercised by dependency installation
    psycopg = None


class PostgresWorldStore:
    """以 PostgreSQL 交易保存跨 Instance 共用的 WorldSnapshot。"""

    def __init__(self, dsn: str) -> None:
        """建立 PostgreSQL Store；實際連線延後到操作執行時。"""
        if not dsn.strip():
            raise ValueError("dsn must not be empty")
        self._dsn = dsn

    def create_if_absent(
        self,
        scope: WorldScope,
        state: dict[str, JsonValue],
        *,
        expires_at: int | None = None,
    ) -> WorldSnapshot:
        """以唯一 scope 約束原子建立第一份快照，並回傳已保存版本。"""
        snapshot = WorldSnapshot.create(scope, state, expires_at=expires_at)
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO world_snapshots (
                        environment_id, deployment_id, session_id,
                        world_generation_id, version, expires_at, state, state_hash
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                    ON CONFLICT (environment_id, deployment_id, session_id, world_generation_id)
                    DO NOTHING
                    """,
                    (
                        scope.environment_id,
                        scope.deployment_id,
                        scope.session_id,
                        scope.world_generation_id,
                        snapshot.version,
                        snapshot.expires_at,
                        json.dumps(snapshot.state, ensure_ascii=False),
                        snapshot.state_hash,
                    ),
                )
                row = self._select_row(cursor, scope)
        return self._snapshot_from_row(scope, row)

    def load(self, scope: WorldScope) -> WorldSnapshot | None:
        """依完整 scope 載入快照；任何非成功結果都不回傳資料。"""
        result = self.load_result(scope)
        return result.snapshot if result.status is WorldStoreStatus.WORLD_FOUND else None

    def load_result(
        self,
        scope: WorldScope,
        *,
        authorized_scope: WorldScope | None = None,
        now: int | None = None,
    ) -> WorldLoadResult:
        """回傳跨 Instance 可觀測的快照載入結果與故障分類。"""
        if authorized_scope is not None and authorized_scope != scope:
            return WorldLoadResult(WorldStoreStatus.SCOPE_MISMATCH)
        try:
            with self._connection() as connection:
                with connection.cursor() as cursor:
                    row = self._select_row(cursor, scope)
            if row is None:
                return WorldLoadResult(WorldStoreStatus.SESSION_NOT_FOUND)
            expires_at = row[1]
            if now is not None and expires_at is not None and now >= expires_at:
                return WorldLoadResult(WorldStoreStatus.EXPIRED)
            try:
                return WorldLoadResult(WorldStoreStatus.WORLD_FOUND, self._snapshot_from_row(scope, row))
            except ValueError:
                return WorldLoadResult(WorldStoreStatus.CORRUPTED)
        except WorldStoreError:
            return WorldLoadResult(WorldStoreStatus.STORAGE_UNAVAILABLE)

    def compare_and_swap(
        self,
        scope: WorldScope,
        *,
        expected_version: int,
        state: dict[str, JsonValue],
    ) -> WorldSnapshot:
        """在行鎖內驗證版本並更新，拒絕任何舊版本覆寫。"""
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT version, expires_at, state, state_hash
                    FROM world_snapshots
                    WHERE environment_id = %s AND deployment_id = %s
                      AND session_id = %s AND world_generation_id = %s
                    FOR UPDATE
                    """,
                    self._scope_params(scope),
                )
                row = cursor.fetchone()
                if row is None:
                    raise WorldStoreError("world_not_found")
                current_version = row[0]
                if current_version != expected_version:
                    raise WorldStoreError("version_conflict")
                updated = WorldSnapshot.create(
                    scope,
                    state,
                    version=current_version + 1,
                    expires_at=row[1],
                )
                cursor.execute(
                    """
                    UPDATE world_snapshots
                    SET version = %s, state = %s::jsonb, state_hash = %s
                    WHERE environment_id = %s AND deployment_id = %s
                      AND session_id = %s AND world_generation_id = %s
                    """,
                    (
                        updated.version,
                        json.dumps(updated.state, ensure_ascii=False),
                        updated.state_hash,
                        *self._scope_params(scope),
                    ),
                )
        return updated

    def _connection(self) -> Any:
        """建立 PostgreSQL 連線，將驅動缺失或不可用統一轉成安全錯誤。"""
        if psycopg is None:
            raise WorldStoreError(WorldStoreStatus.STORAGE_UNAVAILABLE.value)
        try:
            return psycopg.connect(self._dsn)
        except psycopg.Error as exc:
            raise WorldStoreError(WorldStoreStatus.STORAGE_UNAVAILABLE.value) from exc

    @staticmethod
    def _scope_params(scope: WorldScope) -> tuple[str, str, str, str]:
        """將 WorldScope 展開為固定 SQL 參數順序。"""
        return (
            scope.environment_id,
            scope.deployment_id,
            scope.session_id,
            scope.world_generation_id,
        )

    @classmethod
    def _select_row(cls, cursor: Any, scope: WorldScope) -> tuple[Any, ...] | None:
        """從游標讀取指定 scope 的最新保存列。"""
        cursor.execute(
            """
            SELECT version, expires_at, state, state_hash
            FROM world_snapshots
            WHERE environment_id = %s AND deployment_id = %s
              AND session_id = %s AND world_generation_id = %s
            """,
            cls._scope_params(scope),
        )
        return cursor.fetchone()

    @staticmethod
    def _snapshot_from_row(scope: WorldScope, row: tuple[Any, ...] | None) -> WorldSnapshot:
        """將資料庫列重新驗證為不可變 WorldSnapshot。"""
        if row is None:
            raise WorldStoreError("world_not_found")
        state = row[2] if isinstance(row[2], dict) else json.loads(row[2])
        return WorldSnapshot(
            scope=scope,
            version=row[0],
            expires_at=row[1],
            state=state,
            state_hash=row[3],
        )
