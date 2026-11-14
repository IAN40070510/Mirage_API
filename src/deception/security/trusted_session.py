"""Ed25519 Trusted Session JWS 驗證與 Replay 一次性消費入口。"""

from __future__ import annotations

import base64
import binascii
import json
import re
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
        max_clock_skew: int = 30,
        max_lifetime: int = 60,
    ) -> None:
        """建立驗證器；Replay Store 必須由部署者注入共享持久化實作。"""
        if max_clock_skew < 0 or max_lifetime < 1:
            raise ValueError("clock skew and lifetime policy are invalid")
        self._keys = keys
        self._replay_store = replay_store
        self._max_clock_skew = max_clock_skew
        self._max_lifetime = max_lifetime

    def verify(
        self,
        token: str,
        *,
        expected_issuer: str,
        expected_audience: str,
        request_fingerprint: str,
        now: int | None = None,
    ) -> TrustedSessionClaims:
        """驗證 Compact JWS、claims、期限、請求綁定並原子消費 Replay JTI。"""
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
        replay_result = self._replay_store.consume(
            issuer=claims.iss,
            audience=claims.aud,
            jti=claims.jti,
            expires_at=claims.exp,
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
            value = json.loads(cls._decode_bytes(segment))
        except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
            raise TrustedSessionError("invalid_jws_json") from exc
        if not isinstance(value, dict):
            raise TrustedSessionError("jws_json_must_be_object")
        return value

    @staticmethod
    def _decode_bytes(segment: str) -> bytes:
        """只接受不含 padding 的 Base64URL 字元，拒絕模糊解碼。"""
        if not re.fullmatch(r"[A-Za-z0-9_-]+", segment):
            raise TrustedSessionError("invalid_base64url")
        try:
            return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        except (ValueError, binascii.Error) as exc:
            raise TrustedSessionError("invalid_base64url") from exc
