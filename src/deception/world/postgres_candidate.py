"""PostgreSQL 共享 Candidate 保存、讀取與保留期限控制。"""

from __future__ import annotations

import hashlib
from typing import Any, Iterable

from .candidate import CandidateLoadResult, CandidateRecord, CandidateStoreStatus
from .models import WorldScope
from .postgres_store import psycopg
from .store import WorldStoreError, WorldStoreStatus


class PostgresCandidateStore:
    """以 PostgreSQL 交易保存跨 Instance 共用的不可變 Candidate。"""

    def __init__(self, dsn: str) -> None:
        """建立共享 Candidate Store；連線延後到每次操作。"""
        if not dsn.strip():
            raise ValueError("dsn must not be empty")
        self._dsn = dsn

    def put(
        self,
        scope: WorldScope,
        candidate_ref: str,
        body: bytes,
        *,
        expires_at: int,
    ) -> CandidateRecord:
        """以 scope 與 ref 唯一鍵保存 Candidate，拒絕不同內容覆寫。"""
        if not candidate_ref or not isinstance(body, bytes) or expires_at < 1:
            raise ValueError("candidate_ref, body and expires_at are invalid")
        candidate_hash = hashlib.sha256(body).hexdigest()
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO candidate_records (
                        environment_id, deployment_id, session_id,
                        world_generation_id, candidate_ref, candidate_hash,
                        body, expires_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (
                        environment_id, deployment_id, session_id,
                        world_generation_id, candidate_ref
                    ) DO NOTHING
                    """,
                    (*self._scope_params(scope), candidate_ref, candidate_hash, body, expires_at),
                )
                cursor.execute(
                    """
                    SELECT candidate_hash, body, expires_at
                    FROM candidate_records
                    WHERE environment_id = %s AND deployment_id = %s
                      AND session_id = %s AND world_generation_id = %s
                      AND candidate_ref = %s
                    FOR UPDATE
                    """,
                    (*self._scope_params(scope), candidate_ref),
                )
                row = cursor.fetchone()
        if row is None:
            raise WorldStoreError("candidate_not_found")
        if row[0] != candidate_hash or bytes(row[1]) != body or row[2] != expires_at:
            raise ValueError("candidate_ref_already_bound")
        return CandidateRecord(scope, candidate_ref, row[0], bytes(row[1]), row[2])

    def load(
        self,
        scope: WorldScope,
        candidate_ref: str,
        *,
        expected_hash: str,
        now: int,
    ) -> CandidateLoadResult:
        """依完整 scope、hash 與期限載入 Candidate，失敗時回傳明確分類。"""
        try:
            with self._connection() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT candidate_hash, body, expires_at
                        FROM candidate_records
                        WHERE environment_id = %s AND deployment_id = %s
                          AND session_id = %s AND world_generation_id = %s
                          AND candidate_ref = %s
                        """,
                        (*self._scope_params(scope), candidate_ref),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        cursor.execute(
                            "SELECT 1 FROM candidate_records WHERE candidate_ref = %s LIMIT 1",
                            (candidate_ref,),
                        )
                        status = (
                            CandidateStoreStatus.SCOPE_MISMATCH
                            if cursor.fetchone() is not None
                            else CandidateStoreStatus.NOT_FOUND
                        )
                        return CandidateLoadResult(status)
        except WorldStoreError:
            raise
        if now >= row[2]:
            return CandidateLoadResult(CandidateStoreStatus.EXPIRED)
        body = bytes(row[1])
        if row[0] != expected_hash or hashlib.sha256(body).hexdigest() != row[0]:
            return CandidateLoadResult(CandidateStoreStatus.HASH_MISMATCH)
        return CandidateLoadResult(
            CandidateStoreStatus.FOUND,
            CandidateRecord(scope, candidate_ref, row[0], body, row[2]),
        )

    def gc(self, *, now: int, protected_refs: Iterable[str]) -> tuple[CandidateRecord, ...]:
        """只刪除已過期且不再被任何有效 Admission 引用的 Candidate。"""
        protected = tuple(set(protected_refs))
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    DELETE FROM candidate_records
                    WHERE expires_at <= %s
                      AND NOT (candidate_ref = ANY(%s))
                    RETURNING environment_id, deployment_id, session_id,
                              world_generation_id, candidate_ref,
                              candidate_hash, body, expires_at
                    """,
                    (now, list(protected)),
                )
                rows = cursor.fetchall()
        return tuple(
            CandidateRecord(
                WorldScope(
                    environment_id=row[0],
                    deployment_id=row[1],
                    session_id=row[2],
                    world_generation_id=row[3],
                ),
                row[4],
                row[5],
                bytes(row[6]),
                row[7],
            )
            for row in rows
        )

    def _connection(self) -> Any:
        """建立 PostgreSQL 連線，缺少驅動或服務不可用時明確 Fail-Closed。"""
        if psycopg is None:
            raise WorldStoreError(WorldStoreStatus.STORAGE_UNAVAILABLE.value)
        try:
            return psycopg.connect(self._dsn)
        except psycopg.Error as exc:
            raise WorldStoreError(WorldStoreStatus.STORAGE_UNAVAILABLE.value) from exc

    @staticmethod
    def _scope_params(scope: WorldScope) -> tuple[str, str, str, str]:
        """將完整 WorldScope 展開為固定 SQL 參數順序。"""
        return (
            scope.environment_id,
            scope.deployment_id,
            scope.session_id,
            scope.world_generation_id,
        )
