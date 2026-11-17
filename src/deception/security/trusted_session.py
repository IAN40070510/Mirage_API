"""Ed25519 Trusted Session JWS 驗證與 Replay 一次性消費入口。"""

from __future__ import annotations

import base64
import binascii
import json
import re
from contextlib import nullcontext
from typing import ContextManager
from datetime import datetime, timezone
from typing import Literal, Mapping, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field
from deception.common.models import SyntheticModel
from deception.world.replay import ReplayConsumeResult


class TrustedSessionError(ValueError):
    """表示 Trusted Session JWS 未通過固定格式、簽章或政策驗證。"""


class ReplayConsumer(Protocol):
    """定義驗證器消費共享 Replay JTI 所需的最小介面。"""

    def consume(
        self,
        *,
        issuer: str,
        audience: str,
        jti: str,
        expires_at: int,
        now: int,
    ) -> ReplayConsumeResult:
        """原子消費一次性 JTI，回傳接受、重放或過期結果。"""
        ...


class KeyRevocationRegistry(Protocol):
    """定義共享撤銷控制邊界，公鑰查找本身仍由固定名冊負責。"""

    def guard(self, issuer: str, kid: str) -> ContextManager[object | None]:
        """持鎖直到驗證及 Replay 完成；有墓碑回傳物件，無墓碑才回 None。"""
        ...


class TrustedSessionHeader(SyntheticModel):
    """限制 JWS Header 只使用核准的 Ed25519 與固定型別。"""

    alg: Literal["Ed25519"]
    typ: Literal["mirage-trusted-session+jwt"]
    kid: str = Field(min_length=1, max_length=128)
    protocol_version: Literal["1.1"]


class TrustedSessionClaims(SyntheticModel):
    """保存已驗證的 Trusted Session claims，不代表尚未驗證的 JWT payload。"""

    iss: str = Field(min_length=1, max_length=128)
    aud: str = Field(min_length=1, max_length=128)
    iat: int = Field(ge=0)
    nbf: int = Field(ge=0)
    exp: int = Field(ge=1)
    jti: str = Field(min_length=1, max_length=128)
    environment_id: str = Field(min_length=1, max_length=128)
    deployment_id: str = Field(min_length=1, max_length=128)
    session_id: str = Field(min_length=1, max_length=128)
    session_epoch: int = Field(ge=0)
    resource_id: str | None = Field(default=None, max_length=128)
    access_mode: Literal["read_only", "inventory", "cart"] = "read_only"
    request_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    assessment_id: str = Field(min_length=1, max_length=128)
    assessment_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class TrustedKeyRegistry:
    """保存由部署者注入的 issuer／kid Ed25519 公開金鑰集合。"""

    def __init__(self, keys: Mapping[tuple[str, str], bytes]) -> None:
        """驗證公開金鑰長度並建立不可由 Token 任意擴充的固定集合。"""
        self._keys: dict[tuple[str, str], Ed25519PublicKey] = {}
        for identity, key_bytes in keys.items():
            if not isinstance(key_bytes, bytes) or len(key_bytes) != 32:
                raise ValueError("Ed25519 public keys must be exactly 32 bytes")
            self._keys[identity] = Ed25519PublicKey.from_public_bytes(key_bytes)

    def get(self, issuer: str, kid: str) -> Ed25519PublicKey:
        """依可信 issuer 與固定 kid 取得公開金鑰，未知組合即拒絕。"""
        try:
            return self._keys[(issuer, kid)]
        except KeyError as exc:
            raise TrustedSessionError("trusted_key_not_found") from exc


class TrustedSessionVerifier:
    """驗證固定 JWS v1.1 並在所有政策通過後消費 Replay JTI。"""

    def __init__(
        self,
        *,
        keys: TrustedKeyRegistry,
        replay_store: ReplayConsumer,
        key_revocations: KeyRevocationRegistry | None = None,
        max_clock_skew: int = 30,
        max_lifetime: int = 60,
    ) -> None:
        """建立驗證器；正式入口須注入共享 Replay 與金鑰撤銷，未提供撤銷僅保留原型相容。"""
        if max_clock_skew < 0 or max_lifetime < 1:
            raise ValueError("clock skew and lifetime policy are invalid")
        self._keys = keys
        self._replay_store = replay_store
        self._key_revocations = key_revocations
        self._max_clock_skew = max_clock_skew
        self._max_lifetime = max_lifetime

    def verify(
        self,
        token: str,
        *,
        expected_issuer: str,
        expected_audience: str,
        request_fingerprint: str,
        environment_id: str | None = None,
        deployment_id: str | None = None,
        now: int | None = None,
    ) -> TrustedSessionClaims:
        """驗證 Compact JWS 並回傳可信 claims，成功時原子消費一次性 JTI。

        issuer、audience、fingerprint 與可選部署身份須由可信呼叫端提供；
        正式 HTTP provider 必須提供環境與部署。now 是 Unix 秒，省略取 UTC。
        格式、身份、期限或簽章錯誤均於寫入 Replay 前拒絕；Replay 保存至
        exp 加 clock skew。重放與過期拋出 TrustedSessionError，儲存錯誤向上
        傳遞以停止輸出，呼叫端不得在結果未知時假設未消費而盲目重試。
        撤銷 guard 在有效簽章後取得並持有至 Replay 結束；已完成驗證的在途
        工作不因後來的 key 墓碑自動取消，仍須遵守世界與發送准入邊界。
        """
        header_segment, payload_segment, signature_segment = self._split(token)
        try:
            header = TrustedSessionHeader.model_validate(self._decode_json(header_segment))
            claims = TrustedSessionClaims.model_validate(self._decode_json(payload_segment))
        except ValueError as exc:
            raise TrustedSessionError("invalid_trusted_session_claims") from exc
        if claims.iss != expected_issuer or claims.aud != expected_audience:
            raise TrustedSessionError("issuer_or_audience_mismatch")
        if claims.request_fingerprint != request_fingerprint:
            raise TrustedSessionError("request_fingerprint_mismatch")
        if ((environment_id is not None and claims.environment_id != environment_id)
                or (deployment_id is not None and claims.deployment_id != deployment_id)):
            raise TrustedSessionError("trusted_session_context_mismatch")
        if not claims.iat <= claims.nbf < claims.exp:
            raise TrustedSessionError("trusted_session_invalid_time_order")
        current = int(datetime.now(timezone.utc).timestamp()) if now is None else now
        if claims.exp - claims.iat > self._max_lifetime:
            raise TrustedSessionError("trusted_session_lifetime_exceeded")
        if claims.iat > current + self._max_clock_skew or claims.nbf > current + self._max_clock_skew:
            raise TrustedSessionError("trusted_session_not_yet_valid")
        if claims.exp <= current - self._max_clock_skew:
            raise TrustedSessionError("trusted_session_expired")
        signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
        signature = self._decode_bytes(signature_segment)
        try:
            self._keys.get(claims.iss, header.kid).verify(signature, signing_input)
        except InvalidSignature as exc:
            raise TrustedSessionError("invalid_trusted_session_signature") from exc
        guard = (nullcontext(None) if self._key_revocations is None
                 else self._key_revocations.guard(claims.iss, header.kid))
        with guard as revoked:
            if revoked is not None:
                raise TrustedSessionError("trusted_key_revoked")
            replay_result = self._replay_store.consume(
                issuer=claims.iss,
                audience=claims.aud,
                jti=claims.jti,
                expires_at=claims.exp + self._max_clock_skew,
                now=current,
            )
            if replay_result is not ReplayConsumeResult.ACCEPTED:
                raise TrustedSessionError(f"trusted_session_{replay_result.value}")
        return claims

    @staticmethod
    def _split(token: str) -> tuple[str, str, str]:
        """分割 Compact JWS 並拒絕非 ASCII 或非三段格式。"""
        if not isinstance(token, str):
            raise TrustedSessionError("token_not_text")
        parts = token.split(".")
        if len(parts) != 3 or any(not part for part in parts):
            raise TrustedSessionError("invalid_compact_jws")
        try:
            for part in parts:
                part.encode("ascii")
        except UnicodeEncodeError as exc:
            raise TrustedSessionError("invalid_compact_jws") from exc
        return parts[0], parts[1], parts[2]

    @classmethod
    def _decode_json(cls, segment: str) -> dict[str, object]:
        """嚴格解碼 Base64URL JSON 物件，隱藏 parser 細節避免診斷洩漏。"""
        try:
            value = json.loads(cls._decode_bytes(segment), object_pairs_hook=cls._unique_object)
        except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
            raise TrustedSessionError("invalid_jws_json") from exc
        if not isinstance(value, dict):
            raise TrustedSessionError("jws_json_must_be_object")
        return value

    @staticmethod
    def _unique_object(pairs) -> dict[str, object]:
        """拒絕重複 JSON 欄位，避免 Gateway 與 Mirage 採用不同解析結果。"""
        result = {}
        for name, value in pairs:
            if name in result:
                raise TrustedSessionError("duplicate_jws_json_field")
            result[name] = value
        return result

    @staticmethod
    def _decode_bytes(segment: str) -> bytes:
        """只接受不含 padding 的 Base64URL 字元，拒絕模糊解碼。"""
        if not re.fullmatch(r"[A-Za-z0-9_-]+", segment):
            raise TrustedSessionError("invalid_base64url")
        try:
            decoded = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
            if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != segment:
                raise TrustedSessionError("noncanonical_base64url")
            return decoded
        except (ValueError, binascii.Error) as exc:
            raise TrustedSessionError("invalid_base64url") from exc
