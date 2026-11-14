"""受 scope 與 hash 保護的 Candidate 保存及保留期限控制。"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Iterable

from .models import WorldScope


class CandidateStoreStatus(StrEnum):
    """描述 Candidate 查詢結果，避免以空 bytes 掩蓋安全失敗。"""

    FOUND = "candidate_found"
    NOT_FOUND = "candidate_not_found"
    SCOPE_MISMATCH = "candidate_scope_mismatch"
    HASH_MISMATCH = "candidate_hash_mismatch"
    EXPIRED = "candidate_expired"


@dataclass(frozen=True)
class CandidateRecord:
    """保存不可變 Candidate bytes、scope、內容 hash 與最晚可讀時間。"""

    scope: WorldScope
    candidate_ref: str
    candidate_hash: str
    body: bytes
    expires_at: int


@dataclass(frozen=True)
class CandidateLoadResult:
    """封裝 Candidate 查詢狀態與成功時的原始 bytes。"""

    status: CandidateStoreStatus
    record: CandidateRecord | None = None


class CandidateStore:
    """以完整 WorldScope 保存 Candidate，並阻止有效准入期間的提前清理。"""

    def __init__(self) -> None:
        """建立空的程序內 Candidate Store，供原型與保留期限測試使用。"""
        self._lock = RLock()
        self._records: dict[tuple[tuple[str, str, str, str], str], CandidateRecord] = {}

    @staticmethod
    def _scope_key(scope: WorldScope) -> tuple[str, str, str, str]:
        """將完整 scope 轉成不可混淆的保存鍵。"""
        return (
            scope.environment_id,
            scope.deployment_id,
            scope.session_id,
            scope.world_generation_id,
        )

    @staticmethod
    def _hash(body: bytes) -> str:
        """以精確 Candidate bytes 計算 SHA-256，避免重新序列化改變內容。"""
        return hashlib.sha256(body).hexdigest()

    def put(
        self,
        scope: WorldScope,
        candidate_ref: str,
        body: bytes,
        *,
        expires_at: int,
    ) -> CandidateRecord:
        """保存不可變 Candidate；相同 ref 的不同內容或 scope 會拒絕覆寫。"""
        if not candidate_ref or not isinstance(body, bytes) or expires_at < 1:
            raise ValueError("candidate_ref, body and expires_at are invalid")
        record = CandidateRecord(scope, candidate_ref, self._hash(body), body, expires_at)
        key = (self._scope_key(scope), candidate_ref)
        with self._lock:
            existing = self._records.get(key)
            if existing is not None and existing != record:
                raise ValueError("candidate_ref_already_bound")
            self._records[key] = record
            return record

    def load(
        self,
        scope: WorldScope,
        candidate_ref: str,
        *,
        expected_hash: str,
        now: int,
    ) -> CandidateLoadResult:
        """依 scope、hash 與期限載入原始 Candidate，任何不符都拒絕使用。"""
        with self._lock:
            key = (self._scope_key(scope), candidate_ref)
            record = self._records.get(key)
            if record is None:
                if any(ref == candidate_ref for _, ref in self._records):
                    return CandidateLoadResult(CandidateStoreStatus.SCOPE_MISMATCH)
                return CandidateLoadResult(CandidateStoreStatus.NOT_FOUND)
            if now >= record.expires_at:
                return CandidateLoadResult(CandidateStoreStatus.EXPIRED)
            if record.candidate_hash != expected_hash or self._hash(record.body) != record.candidate_hash:
                return CandidateLoadResult(CandidateStoreStatus.HASH_MISMATCH)
            return CandidateLoadResult(CandidateStoreStatus.FOUND, record)

    def gc(
        self,
        *,
        now: int,
        protected_refs: Iterable[str],
    ) -> tuple[CandidateRecord, ...]:
        """只清理已過期且未被有效 Admission 保護的 Candidate。"""
        protected = set(protected_refs)
        removed: list[CandidateRecord] = []
        with self._lock:
            for key, record in tuple(self._records.items()):
                if record.expires_at <= now and record.candidate_ref not in protected:
                    removed.append(self._records.pop(key))
        return tuple(removed)
