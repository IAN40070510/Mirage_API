"""MSDSS Gateway 可注入的 Trusted Session v1.1 發送器；不自動啟用。"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Literal
from uuid import uuid4

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from starlette.requests import Request

from msdss.adapters.attack_assessment import AssessmentScope, build_assessment
from msdss.adapters.request_binding import from_prepared_httpx_request
from msdss.common.time import epoch_millis
from msdss.decision.policy import DecisionOutcome


def encode(value: object) -> str:
    """以排序 JSON 與無 padding Base64URL 建立 Compact JWS 元件。"""
    return base64.urlsafe_b64encode(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode()).decode("ascii").rstrip("=")


def wire_fingerprint(outgoing: httpx.Request, request_id: str) -> str:
    """依 Mirage v1 核准標頭與原始 bytes 計算最終 HTTP/1.1 請求摘要。"""
    snapshot = from_prepared_httpx_request(outgoing, request_id=request_id)
    headers = []
    seen = set()
    for name, value in snapshot.headers:
        if name not in {"host", "content-type", "content-length", "x-request-id", "authorization",
                        "idempotency-key", "x-publishable-api-key"}:
            continue
        if name in seen:
            raise ValueError("ambiguous request fingerprint header")
        seen.add(name)
        if name == "authorization":
            value = hashlib.sha256(value.encode("latin-1")).hexdigest()
        headers.append((name, value))
    content = dict(
        request_id=snapshot.request_id, method=snapshot.method, raw_url=snapshot.raw_url,
        path=snapshot.path, raw_path=snapshot.raw_path.hex(),
        query_string=snapshot.query_string.hex(), query=snapshot.query, headers=headers,
        body_sha256=hashlib.sha256(snapshot.body).hexdigest(),
    )
    return hashlib.sha256(json.dumps(content, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":"), allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True)
class SessionBinding:
    """可信 gateway middleware 完成身份解析後，寫入該請求私有 ASGI state 的綁定。"""

    environment_id: str
    deployment_id: str
    session_id: str
    session_epoch: int
    resource_id: str | None = None
    access_mode: Literal["read_only", "inventory", "cart"] = "read_only"


class TrustedSessionDispatcher:
    """由部署程式注入簽章與可信 session；不消費 JTI、不切換 Gateway 政策。"""

    def __init__(self, *, private_key: Ed25519PrivateKey, kid: str, issuer: str,
                 audience: str, scope: AssessmentScope, mirage_origin: str, identity_provider=None) -> None:
        """保存部署金鑰與固定路由；拒絕不安全 origin 及超過 60 秒的政策。"""
        origin = httpx.URL(mirage_origin)
        if (origin.scheme != "https" or not origin.host or origin.userinfo
                or origin.raw_path != b"/" or origin.fragment):
            raise ValueError("trusted session requires a fixed HTTPS origin")
        if not all((kid, issuer, audience)) or scope.lifetime_seconds > 60:
            raise ValueError("invalid trusted session policy")
        self._key, self._kid = private_key, kid
        self._issuer, self._audience = issuer, audience
        self._scope, self._origin = scope, origin
        self._identity_provider = identity_provider

    @property
    def origin(self) -> httpx.URL:
        """提供 MSDSS proxy 建立最終請求時使用的固定 Mirage origin。"""
        return self._origin

    async def dispatch(self, *, incoming: Request, outgoing: httpx.Request, body: bytes,
                       request_id: str, label: Literal["sqli", "xss"],
                       decision: DecisionOutcome, client: httpx.AsyncClient) -> httpx.Response:
        """簽發核准決策並送出同一請求；session 必須由可信 resolver 注入。

        時間取自 MSDSS 毫秒時鐘，僅 JWS NumericDate 轉成協定要求的秒。
        不接受訪客自帶 JWS，不重試、不回退 Backend；傳輸失敗直接向上拋出。
        """
        if (outgoing.url.scheme, outgoing.url.netloc) != (self._origin.scheme, self._origin.netloc):
            raise ValueError("outgoing request targets another origin")
        if outgoing.content != body or "x-trusted-session" in outgoing.headers:
            raise ValueError("outgoing body or trusted header is invalid")
        fingerprint = wire_fingerprint(outgoing, request_id)
        assessment = build_assessment(decision=decision, label=label, scope=self._scope,
                                      request_id=request_id, wire_fingerprint=fingerprint)
        if self._identity_provider is not None:
            verified = await self._identity_provider(incoming)
            binding = SessionBinding(verified.environment_id, verified.deployment_id,
                                     verified.session_id, verified.session_epoch, verified.resource_id, verified.access_mode)
        else:
            binding = getattr(incoming.state, "trusted_session_binding", None)
        if not isinstance(binding, SessionBinding) or (
            binding.environment_id, binding.deployment_id
        ) != (self._scope.environment_id, self._scope.deployment_id):
            raise ValueError("missing or mismatched trusted session binding")
        session_id, session_epoch = binding.session_id, binding.session_epoch
        if not isinstance(session_id, str) or not session_id or len(session_id) > 128 or type(session_epoch) is not int or session_epoch < 0:
            raise ValueError("invalid trusted session binding")
        now = epoch_millis() // 1000
        claims = dict(
            iss=self._issuer, aud=self._audience, iat=now, nbf=now,
            exp=now + self._scope.lifetime_seconds, jti=str(uuid4()),
            environment_id=self._scope.environment_id, deployment_id=self._scope.deployment_id,
            session_id=session_id, session_epoch=session_epoch, access_mode=binding.access_mode,
            resource_id=binding.resource_id,
            request_fingerprint=fingerprint, assessment_id=assessment.assessment_id,
            assessment_digest=hashlib.sha256(assessment.model_dump_json().encode()).hexdigest(),
        )
        header = dict(alg="Ed25519", typ="mirage-trusted-session+jwt",
                      kid=self._kid, protocol_version="1.1")
        signing_input = f"{encode(header)}.{encode(claims)}"
        signature = base64.urlsafe_b64encode(self._key.sign(signing_input.encode("ascii")))
        outgoing.headers["X-Trusted-Session"] = signing_input + "." + signature.decode().rstrip("=")
        return await client.send(outgoing, stream=True, follow_redirects=False)
