"""PostgreSQL 共享 WorldSnapshot 與 CAS 保存實作。"""

from __future__ import annotations

import json
import time
from contextlib import closing
from typing import Any
from uuid import UUID

from pydantic import JsonValue, TypeAdapter

from .models import WorldScope, WorldSnapshot
from .store import CommitLookupResult, WorldLoadResult, WorldStoreError, WorldStoreStatus, require_unchanged_compatibility

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

    @staticmethod
    def _normalize_jsonb(connection, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        """在同交易取得實際 JSONB 表示後才做摘要，避免指數與負零轉換造成已保存資料無法驗證。

        嚴格檢查 JSON 物件及有限數值，不接受非字串鍵或自訂型別；只執行 SELECT，
        不修改資料表、hash 編碼或既有快照。資料庫不支援的值直接失敗並讓呼叫交易回滾。
        """
        checked = TypeAdapter(dict[str, JsonValue]).validate_python(value, strict=True)
        encoded = json.dumps(checked, ensure_ascii=True, allow_nan=False)
        normalized, = connection.execute("SELECT %s::jsonb", (encoded,)).fetchone()
        return normalized

    def create_if_absent(
        self,
        scope: WorldScope,
        state: dict[str, JsonValue],
        *,
        expires_at: int | None = None,
    ) -> WorldSnapshot:
        """以唯一 scope 原子建立快照。若 COMMIT 連線中斷，以新連線查詢同一 scope。

        回傳已驗證的目前快照。恢復查無有效快照時拋出 WorldStoreError，
        呼叫端不得由此推定交易未提交或改用另一個 generation 建立世界。
        """
        snapshot = WorldSnapshot.create(scope, state, expires_at=expires_at)
        with closing(self._connection()) as connection:
            snapshot = WorldSnapshot.create(scope, self._normalize_jsonb(connection, snapshot.state), expires_at=expires_at)
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
            try:
                connection.commit()
            except (psycopg.OperationalError, psycopg.InterfaceError):
                pass  # 離開 closing 釋放結果未知的連線，再從另一條連線讀取。
            else:
                return self._snapshot_from_row(scope, row)

        result = self.load_result(scope, authorized_scope=scope, now=int(time.time()))
        if result.status is WorldStoreStatus.WORLD_FOUND and result.snapshot is not None:
            return result.snapshot
        raise WorldStoreError(f"world_initialization_unverifiable:{result.status.value}")

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
        except psycopg.Error:
            return WorldLoadResult(WorldStoreStatus.STORAGE_UNAVAILABLE)

    def compare_and_swap(
        self,
        scope: WorldScope,
        *,
        expected_version: int,
        state: dict[str, JsonValue],
        commit_attempt_id: UUID | None = None,
    ) -> WorldSnapshot:
        """以版本鎖更新快照；提供服務端 UUIDv4 時，在同一交易保存提交收據。

        已使用的 attempt ID 使整筆交易回滾。呼叫端須在寫入前保存該 ID，
        回應中斷後用 get_commit_result 查詢當次提交。
        """
        if commit_attempt_id is not None and (
            not isinstance(commit_attempt_id, UUID) or commit_attempt_id.version != 4
        ):
            raise ValueError("commit_attempt_id must be UUIDv4")
        with self._connection() as connection:
            with connection.cursor() as cursor:
                if commit_attempt_id is not None:
                    cursor.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                                   (self._attempt_key(scope, commit_attempt_id),))
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
                current = self._snapshot_from_row(scope, row)
                require_unchanged_compatibility(current, state)
                updated = WorldSnapshot.create(
                    scope,
                    self._normalize_jsonb(connection, state),
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
                if commit_attempt_id is not None:
                    cursor.execute(
                        """INSERT INTO world_commit_receipts
                           (environment_id, deployment_id, session_id, world_generation_id,
                            commit_attempt_id, state_version, state_hash)
                           VALUES (%s, %s, %s, %s, %s, %s, %s)
                           ON CONFLICT DO NOTHING RETURNING state_version""",
                        (*self._scope_params(scope), commit_attempt_id, updated.version, updated.state_hash),
                    )
                    if cursor.fetchone() is None:
                        raise WorldStoreError("commit_attempt_already_used")
        return updated

    def get_commit_result(self, scope: WorldScope, commit_attempt_id: UUID, *,
                          authorized_scope: WorldScope) -> CommitLookupResult:
        """依重新授權的 scope 唯讀查收據，區分進行中、拒絕、成功及無法確認。"""
        if (scope != authorized_scope or not isinstance(commit_attempt_id, UUID)
                or commit_attempt_id.version != 4):
            return CommitLookupResult("unverifiable")
        try:
            with self._connection() as connection:
                available, = connection.execute(
                    "SELECT pg_try_advisory_xact_lock(hashtextextended(%s,0))",
                    (self._attempt_key(scope, commit_attempt_id),)).fetchone()
                if not available:
                    return CommitLookupResult("pending")
                row = connection.execute(
                    """SELECT state_version,state_hash FROM world_commit_receipts
                       WHERE environment_id=%s AND deployment_id=%s AND session_id=%s
                       AND world_generation_id=%s AND commit_attempt_id=%s""",
                    (*self._scope_params(scope), commit_attempt_id)).fetchone()
                if row is not None:
                    return CommitLookupResult("committed", row[0], row[1])
                rejected = connection.execute(
                    "SELECT state_version,state_hash FROM world_operations WHERE environment_id=%s "
                    "AND deployment_id=%s AND session_id=%s AND world_generation_id=%s "
                    "AND commit_attempt_id=%s AND status='rejected'",
                    (*self._scope_params(scope), commit_attempt_id)).fetchone()
                if rejected is not None:
                    return CommitLookupResult("rejected", rejected[0], rejected[1])
        except WorldStoreError:
            return CommitLookupResult("unverifiable")
        except psycopg.Error:
            return CommitLookupResult("unverifiable")
        return CommitLookupResult("not_found")

    @classmethod
    def _attempt_key(cls, scope: WorldScope, attempt: UUID) -> str:
        """建立完整 scope 與 attempt 的鎖鍵，供寫入與 pending 查詢使用同一個交易邊界。"""
        return json.dumps([*cls._scope_params(scope), str(attempt)], separators=(",", ":"))

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
