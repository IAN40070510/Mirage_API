"""從固定 Medusa 身份端點建立最小化、可本地撤銷的可信 SessionBinding。"""

import hashlib
import hmac
import json
from http.cookies import SimpleCookie

import httpx

from deception.world.postgres_store import PostgresWorldStore
from deception.world.session import SessionBinding
from deception.world.store import WorldStoreError


class MedusaIdentityError(ValueError):
    """表示無法確認 Medusa 登入身份；對外只使用固定失敗回應。"""


class IdentitySessions(PostgresWorldStore):
    """只保存不透明 session ID、epoch 與撤銷旗標，不保存 token 或顧客資料。"""

    def resolve_identity(self, *, environment_id: str, deployment_id: str, session_id: str) -> SessionBinding:
        """在線上驗證成功後原子取得固定 epoch；已撤銷憑證不能重新啟用。"""
        params = (environment_id, deployment_id, session_id)
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO identity_sessions(environment_id,deployment_id,session_id) VALUES (%s,%s,%s) "
                "ON CONFLICT DO NOTHING", params)
            epoch, revoked = connection.execute(
                "SELECT session_epoch,revoked FROM identity_sessions WHERE environment_id=%s "
                "AND deployment_id=%s AND session_id=%s FOR SHARE", params).fetchone()
            if revoked:
                raise MedusaIdentityError("identity_session_revoked")
        return SessionBinding(environment_id=environment_id, deployment_id=deployment_id,
                              session_id=session_id, session_epoch=epoch, access_mode="inventory")

    def revoke_identity(self, binding: SessionBinding) -> bool:
        """由已授權管理端撤銷指定 session，epoch 只在第一次撤銷時前進。"""
        with self._connection() as connection:
            row = connection.execute(
                "UPDATE identity_sessions SET revoked=TRUE,session_epoch=session_epoch+1 "
                "WHERE environment_id=%s AND deployment_id=%s AND session_id=%s AND NOT revoked "
                "RETURNING session_id", (binding.environment_id, binding.deployment_id, binding.session_id)
            ).fetchone()
        return row is not None


class MedusaIdentityProvider:
    """只向核准 Medusa 取得當前 customer id，每次驗證都查核原服務與本地撤銷。"""

    def __init__(self, *, client: httpx.AsyncClient, origin: str, publishable_key: str,
                 identity_key: bytes, sessions: IdentitySessions,
                 environment_id: str, deployment_id: str, allow_loopback_http: bool = False):
        """設定固定身份服務與 HMAC key。HTTP 僅明確允許 loopback 測試隧道。

        呼叫端管理 client 生命週期，正式 HTTPS 保留預設憑證驗證。identity_key
        至少 32 bytes，由部署注入，輪替會建立不同 session 命名空間。
        """
        url = httpx.URL(origin)
        loopback = url.host in {"127.0.0.1", "::1", "localhost"}
        if (url.scheme != "https" and not (allow_loopback_http and loopback and url.scheme == "http")
                or not url.host or url.userinfo or url.raw_path != b"/" or url.fragment):
            raise ValueError("invalid fixed identity origin")
        if not isinstance(identity_key, bytes) or len(identity_key) < 32 or not publishable_key:
            raise ValueError("identity key and publishable key are required")
        SessionBinding(environment_id=environment_id, deployment_id=deployment_id,
                       session_id="configuration-check", session_epoch=1)
        self._client, self._origin, self._publishable_key = client, str(url).rstrip("/"), publishable_key
        self._key, self._sessions = identity_key, sessions
        self._environment_id, self._deployment_id = environment_id, deployment_id

    async def __call__(self, request) -> SessionBinding:
        """取唯一 Bearer 或 connect.sid，只對固定 GET 身份端點送出受控憑證。

        不轉送訪客 path、query、body 或自填身份。最多讀取 16 KiB 回應，
        只使用 customer.id 形成 HMAC session ID，所有錯誤 fail-closed。
        """
        headers = list(request.headers.items()) if hasattr(request.headers, "items") else list(request.headers)
        authorization = [value for name, value in headers if name.lower() == "authorization"]
        cookies = [value for name, value in headers if name.lower() == "cookie"]
        if len(authorization) > 1 or len(cookies) > 1:
            raise MedusaIdentityError("identity_credentials_ambiguous")
        credential = None
        forwarded = {"x-publishable-api-key": self._publishable_key}
        if authorization:
            value = authorization[0]
            if not value.startswith("Bearer ") or not value[7:].strip():
                raise MedusaIdentityError("identity_credentials_invalid")
            forwarded["authorization"] = value
            credential = value
        if cookies:
            raw = cookies[0]
            if sum(part.strip().startswith("connect.sid=") for part in raw.split(";")) > 1:
                raise MedusaIdentityError("identity_credentials_ambiguous")
            parsed = SimpleCookie()
            try:
                parsed.load(raw)
            except Exception as exc:
                raise MedusaIdentityError("identity_credentials_invalid") from exc
            if "connect.sid" in parsed:
                if credential is not None:
                    raise MedusaIdentityError("identity_credentials_ambiguous")
                credential = parsed["connect.sid"].value
                forwarded["cookie"] = parsed["connect.sid"].OutputString()
        if not credential or len(credential) > 8192:
            raise MedusaIdentityError("identity_credentials_missing")
        outgoing = httpx.Request("GET", self._origin + "/store/customers/me?fields=id", headers=forwarded)
        response = None
        try:
            # 明確設定 request timeout，且不合併 client cookie jar。
            outgoing.extensions["timeout"] = {"connect": 3.0, "read": 3.0, "write": 3.0, "pool": 3.0}
            response = await self._client.send(outgoing, stream=True, follow_redirects=False)
            if response.status_code != 200:
                raise MedusaIdentityError("identity_not_verified")
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > 16384:
                    raise MedusaIdentityError("identity_response_invalid")
            customer = json.loads(body).get("customer")
            subject = customer.get("id") if isinstance(customer, dict) else None
            if not isinstance(subject, str) or not 1 <= len(subject) <= 128:
                raise MedusaIdentityError("identity_response_invalid")
        except (httpx.HTTPError, ValueError, AttributeError) as exc:
            raise MedusaIdentityError("identity_not_verified") from exc
        finally:
            if response is not None:
                await response.aclose()
        message = json.dumps([self._origin, subject, credential], separators=(",", ":")).encode()
        session_id = hmac.new(self._key, message, hashlib.sha256).hexdigest()
        try:
            return self._sessions.resolve_identity(environment_id=self._environment_id,
                                                   deployment_id=self._deployment_id, session_id=session_id)
        except WorldStoreError as exc:
            raise MedusaIdentityError("identity_store_unavailable") from exc
