"""Trusted Session JTI 的一次性消費與保留期限控制。"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from threading import RLock


class ReplayConsumeResult(StrEnum):
    """描述 Replay Store 對一次性授權消費的安全結果。"""

    ACCEPTED = "accepted"
    REPLAY = "replay"
    EXPIRED = "expired"


@dataclass(frozen=True)
class ReplayKey:
    """保存 issuer、audience 與 jti 的不可混淆重放唯一鍵。"""

    issuer: str
    audience: str
    jti: str


class ReplayStore:
    """以程序內原子鎖保存一次性 JTI，供測試與單程序原型使用。"""

    def __init__(self) -> None:
        """建立空的 Replay Store。"""
        self._lock = RLock()
        self._entries: dict[ReplayKey, int] = {}

    def consume(
        self,
        *,
        issuer: str,
        audience: str,
        jti: str,
        expires_at: int,
        now: int,
    ) -> ReplayConsumeResult:
        """在期限內原子消費 JTI；同一 issuer、audience、jti 永不重用。"""
        if not issuer or not audience or not jti or expires_at <= now:
            return ReplayConsumeResult.EXPIRED
        key = ReplayKey(issuer, audience, jti)
        with self._lock:
            if key in self._entries:
                return ReplayConsumeResult.REPLAY
            self._entries[key] = expires_at
            return ReplayConsumeResult.ACCEPTED

    def gc(self, *, now: int) -> int:
        """刪除已過期 Replay 紀錄，且不影響仍可能有效的授權。"""
        with self._lock:
            expired = [key for key, expires_at in self._entries.items() if expires_at <= now]
            for key in expired:
                del self._entries[key]
            return len(expired)
