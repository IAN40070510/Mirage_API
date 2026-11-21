"""PostgreSQL 共享 Trusted Session JTI Replay Store。"""

from __future__ import annotations

from typing import Any

from .postgres_store import psycopg
from .replay import ReplayConsumeResult
from .store import WorldStoreError, WorldStoreStatus


class PostgresReplayStore:
    """以 PostgreSQL 唯一鍵與交易提供跨 Instance 的一次性 JTI 消費。"""

    def __init__(self, dsn: str) -> None:
        """建立共享 Replay Store；連線延後到每次操作。"""
        if not dsn.strip():
            raise ValueError("dsn must not be empty")
        self._dsn = dsn

    def consume(
        self,
        *,
        issuer: str,
        audience: str,
        jti: str,
        expires_at: int,
        now: int,
    ) -> ReplayConsumeResult:
        """在資料庫唯一鍵內原子消費 JTI，衝突一律回報 Replay。"""
        if not issuer or not audience or not jti or expires_at <= now:
            return ReplayConsumeResult.EXPIRED
        with self._connection() as connection:
            with connection.cursor() as cursor:
                return self._consume_on_cursor(cursor, issuer=issuer, audience=audience,
                                               jti=jti, expires_at=expires_at, now=now)

    @staticmethod
    def _consume_on_cursor(cursor, *, issuer: str, audience: str, jti: str,
                           expires_at: int, now: int) -> ReplayConsumeResult:
        """在呼叫者已建立的 PostgreSQL 交易消費 JTI，不開第二條連線或自行提交。"""
        if not issuer or not audience or not jti or expires_at <= now:
            return ReplayConsumeResult.EXPIRED
        if cursor.connection.autocommit:
            raise ValueError("replay_consume_requires_transaction")
        cursor.execute(
            """
            INSERT INTO replay_entries (issuer, audience, jti, expires_at)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (issuer, audience, jti) DO NOTHING
            RETURNING issuer
            """,
            (issuer, audience, jti, expires_at),
        )
        return (ReplayConsumeResult.ACCEPTED if cursor.fetchone() is not None
                else ReplayConsumeResult.REPLAY)

    def gc(self, *, now: int) -> int:
        """刪除已過期 Replay 紀錄，保留仍可能有效的舊授權。"""
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("DELETE FROM replay_entries WHERE expires_at <= %s", (now,))
                return cursor.rowcount

    def _connection(self) -> Any:
        """建立 PostgreSQL 連線，故障時轉成明確 Fail-Closed 錯誤。"""
        if psycopg is None:
            raise WorldStoreError(WorldStoreStatus.STORAGE_UNAVAILABLE.value)
        try:
            return psycopg.connect(self._dsn)
        except psycopg.Error as exc:
            raise WorldStoreError(WorldStoreStatus.STORAGE_UNAVAILABLE.value) from exc
