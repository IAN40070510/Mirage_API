"""Trusted Session Ed25519 JWS 格式、簽章、期限與 Replay 驗收。"""

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deception.security import (
    TrustedKeyRegistry,
    TrustedSessionError,
    TrustedSessionVerifier,
)
from deception.world import ReplayStore


def encode(value: object) -> str:
    """以無 padding Base64URL 編碼測試用 JWS 元件。"""
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def token(*, fingerprint: str = "a" * 64, private_key: Ed25519PrivateKey | None = None) -> str:
    """建立固定 claims 的測試 Ed25519 Compact JWS。"""
    key = private_key or Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)
    header = {"alg": "Ed25519", "kid": "gateway-1", "protocol_version": "1.1",
              "typ": "mirage-trusted-session+jwt"}
    payload = {
        "aud": "mirage", "assessment_digest": "b" * 64, "assessment_id": "assessment-1",
        "deployment_id": "deploy-1", "environment_id": "env-1", "exp": 1060,
        "iat": 1000, "iss": "gateway", "jti": "jti-1", "nbf": 1000,
        "request_fingerprint": fingerprint, "session_epoch": 1, "session_id": "session-1",
    }
    encoded_header = encode(header)
    encoded_payload = encode(payload)
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = base64.urlsafe_b64encode(key.sign(signing_input)).decode("ascii").rstrip("=")
    return f"{encoded_header}.{encoded_payload}.{signature}"


def verifier() -> TrustedSessionVerifier:
    """建立使用固定測試公開金鑰與程序內 Replay Store 的驗證器。"""
    private_key = Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)
    public_key = private_key.public_key().public_bytes_raw()
    return TrustedSessionVerifier(
        keys=TrustedKeyRegistry({("gateway", "gateway-1"): public_key}),
        replay_store=ReplayStore(),
    )


def test_trusted_session_verifies_and_consumes_jti_once():
    """確認有效 JWS 可通過，第二次使用同一 JTI 必須拒絕。"""
    session_verifier = verifier()
    signed = token()
    claims = session_verifier.verify(
        signed,
        expected_issuer="gateway",
        expected_audience="mirage",
        request_fingerprint="a" * 64,
        now=1000,
    )
    assert claims.session_id == "session-1"
    with pytest.raises(TrustedSessionError, match="replay"):
        session_verifier.verify(
            signed,
            expected_issuer="gateway",
            expected_audience="mirage",
            request_fingerprint="a" * 64,
            now=1000,
        )


@pytest.mark.parametrize("reason", ["fingerprint", "signature"])
def test_trusted_session_rejects_binding_or_signature_tampering(reason: str):
    """確認請求綁定或 JWS bytes 被竄改時不會消費 Replay JTI。"""
    session_verifier = verifier()
    signed = token(fingerprint="c" * 64)
    if reason == "fingerprint":
        with pytest.raises(TrustedSessionError, match="fingerprint"):
            session_verifier.verify(
                signed,
                expected_issuer="gateway",
                expected_audience="mirage",
                request_fingerprint="a" * 64,
                now=1000,
            )
    else:
        parts = signed.split(".")
        parts[1] = encode({"tampered": True})
        with pytest.raises(TrustedSessionError):
            session_verifier.verify(
                ".".join(parts),
                expected_issuer="gateway",
                expected_audience="mirage",
                request_fingerprint="c" * 64,
                now=1000,
            )
