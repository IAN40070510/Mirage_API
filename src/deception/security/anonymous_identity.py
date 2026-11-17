"""匿名查詢的短期 IP／UA 輔助分組；只授予固定合成資料的讀取能力。"""

import hashlib
import hmac
import ipaddress
import time

from deception.world.session import SessionBinding
from .medusa_identity import IdentitySessions, MedusaIdentityError


class AnonymousGroups(IdentitySessions):
    """保存不透明分組摘要及部署窗口限額，不保存原始 IP 或 User-Agent。"""

    def register_group(self, binding: SessionBinding, *, window_start: int, expires_at: int, limit: int) -> None:
        """在共享窗口鎖內登記新分組並限制建立數量，既有分組不重複計數。"""
        params = (binding.environment_id, binding.deployment_id, window_start)
        with self._connection() as connection:
            connection.execute("INSERT INTO anonymous_issuance VALUES (%s,%s,%s,0) ON CONFLICT DO NOTHING", params)
            issued, = connection.execute(
                "SELECT issued FROM anonymous_issuance WHERE environment_id=%s AND deployment_id=%s "
                "AND window_start=%s FOR UPDATE", params).fetchone()
            exists = connection.execute(
                "SELECT 1 FROM anonymous_groups WHERE environment_id=%s AND deployment_id=%s AND group_digest=%s "
                "AND window_start=%s", (binding.environment_id, binding.deployment_id, binding.session_id, window_start)
            ).fetchone()
            if exists:
                return
            if issued >= limit:
                raise MedusaIdentityError("anonymous_group_limit")
            connection.execute("INSERT INTO anonymous_groups VALUES (%s,%s,%s,%s,%s)",
                (binding.environment_id, binding.deployment_id, binding.session_id, window_start, expires_at))
            connection.execute("UPDATE anonymous_issuance SET issued=issued+1 WHERE environment_id=%s "
                               "AND deployment_id=%s AND window_start=%s", params)

    def gc_groups(self, *, now: int) -> int:
        """清理已過短期窗口的分組摘要，保留當前限額紀錄。"""
        with self._connection() as connection:
            count = connection.execute("DELETE FROM anonymous_groups WHERE expires_at<=%s", (now,)).rowcount
            connection.execute("DELETE FROM anonymous_issuance i WHERE NOT EXISTS "
                "(SELECT 1 FROM anonymous_groups g WHERE g.environment_id=i.environment_id "
                "AND g.deployment_id=i.deployment_id AND g.window_start=i.window_start) AND window_start<%s", (now,))
        return count


class AnonymousIdentityProvider:
    """只以 Gateway 實際來源 IP、UA 與固定短期窗口建立唯讀分組。"""

    def __init__(self, *, key: bytes, groups: AnonymousGroups, environment_id: str,
                 deployment_id: str, window_seconds: int = 300, group_limit: int = 1000, clock=None):
        """由部署者提供 HMAC key 與窗口政策；預設 5 分鐘，每部署每窗口 1000 組。"""
        if not isinstance(key, bytes) or len(key) < 32 or not 30 <= window_seconds <= 3600 or group_limit < 1:
            raise ValueError("invalid anonymous grouping policy")
        self._key, self._groups = key, groups
        self._environment_id, self._deployment_id = environment_id, deployment_id
        self._window, self._limit, self._clock = window_seconds, group_limit, clock or time.time

    async def __call__(self, request) -> SessionBinding:
        """忽略 Client 自填來源與身份 header，分組只提供 read_only，無個人身份保證。"""
        from deception.world.transmission import encode_fields

        if request.client is None:
            raise MedusaIdentityError("anonymous_peer_unavailable")
        try:
            peer = str(ipaddress.ip_address(request.client.host))
        except ValueError as exc:
            raise MedusaIdentityError("anonymous_peer_invalid") from exc
        values = request.headers.getlist("user-agent")
        if len(values) > 1:
            raise MedusaIdentityError("anonymous_user_agent_ambiguous")
        user_agent = values[0].strip() if values else ""
        if len(user_agent) > 512:
            raise MedusaIdentityError("anonymous_user_agent_too_long")
        now = int(self._clock())
        start = now // self._window * self._window
        message = encode_fields(self._environment_id.encode(), self._deployment_id.encode(), peer.encode(),
                                user_agent.encode("utf-8"), str(start).encode())
        digest = hmac.new(self._key, message, hashlib.sha256).hexdigest()
        binding = SessionBinding(environment_id=self._environment_id, deployment_id=self._deployment_id,
                                  session_id=digest, session_epoch=start, access_mode="read_only")
        self._groups.register_group(binding, window_start=start, expires_at=start + self._window, limit=self._limit)
        return binding


class HybridIdentityProvider:
    """有顧客憑證則驗證 Medusa，沒有憑證時才以匿名唯讀分組處理。"""

    def __init__(self, customer, anonymous: AnonymousIdentityProvider):
        """保存部署核准的兩種身份來源。"""
        self._customer, self._anonymous = customer, anonymous

    async def __call__(self, request):
        """無效顧客憑證直接失敗，不轉成具有不同隔離範圍的匿名請求。"""
        if request.headers.getlist("authorization") or any(
            part.strip().startswith("connect.sid=") for value in request.headers.getlist("cookie")
            for part in value.split(";")):
            return await self._customer(request)
        return await self._anonymous(request)
