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


def test_context_rejection_does_not_consume_authorization():
    """錯誤部署不能耗用 JTI；相同授權仍可由正確部署驗證一次。"""
    checked = verifier()
    arguments = dict(expected_issuer="gateway", expected_audience="mirage",
                     request_fingerprint="a" * 64, now=1000)
    with pytest.raises(TrustedSessionError, match="context_mismatch"):
        checked.verify(token(), environment_id="wrong", **arguments)
    assert checked.verify(token(), environment_id="env-1", **arguments).jti == "jti-1"


def test_replay_retention_covers_clock_skew():
    """授權在 exp 後寬限期仍可首次驗證，GC 不得使其再次成功。"""
    key = Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)
    store = ReplayStore()
    checked = TrustedSessionVerifier(
        keys=TrustedKeyRegistry({("gateway", "gateway-1"): key.public_key().public_bytes_raw()}),
        replay_store=store,
    )
    arguments = dict(expected_issuer="gateway", expected_audience="mirage",
                     request_fingerprint="a" * 64)
    checked.verify(token(), now=1061, **arguments)
    assert store.gc(now=1062) == 0
    with pytest.raises(TrustedSessionError, match="replay"):
        checked.verify(token(), now=1062, **arguments)
    with pytest.raises(TrustedSessionError, match="expired"):
        checked.verify(token(), now=1090, **arguments)


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


@pytest.mark.parametrize("segment", [0, 1])
def test_signed_jws_duplicate_json_fields_are_rejected(segment):
    """即使簽章有效，重複 Header 或 claims 欄位也必須在消費 JTI 前拒絕。"""
    parts = token().split(".")
    content = base64.urlsafe_b64decode(parts[segment] + "=" * (-len(parts[segment]) % 4)).decode()
    duplicate = '"kid":"gateway-1"' if segment == 0 else '"iss":"gateway"'
    content = content[:-1] + "," + duplicate + "}"
    parts[segment] = base64.urlsafe_b64encode(content.encode()).decode().rstrip("=")
    key = Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)
    parts[2] = base64.urlsafe_b64encode(key.sign(".".join(parts[:2]).encode())).decode().rstrip("=")
    checked = verifier()
    arguments = dict(expected_issuer="gateway", expected_audience="mirage",
                     request_fingerprint="a" * 64, now=1000)
    with pytest.raises(TrustedSessionError):
        checked.verify(".".join(parts), **arguments)
    assert checked.verify(token(), **arguments).jti == "jti-1"


def resign_vector(*, header_changes=None, claim_changes=None, missing_claim=None, wrong_key=False):
    """對固定測試授權的明確變異重新簽章，區分政策拒絕與單純簽章損壞。"""
    parts = token().split(".")
    header, claims = [json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))) for value in parts[:2]]
    header.update(header_changes or {})
    claims.update(claim_changes or {})
    if missing_claim is not None:
        del claims[missing_claim]
    content = encode(header) + "." + encode(claims)
    key = Ed25519PrivateKey.from_private_bytes((b"\x02" if wrong_key else b"\x01") * 32)
    signature = base64.urlsafe_b64encode(key.sign(content.encode())).decode().rstrip("=")
    return content + "." + signature


@pytest.mark.parametrize("header,claims,wrong_key,error", [
    ({"alg": "none"}, {}, False, "invalid_trusted_session_claims"),
    ({"alg": "HS256"}, {}, False, "invalid_trusted_session_claims"),
    ({"alg": "EdDSA"}, {}, False, "invalid_trusted_session_claims"),
    ({"alg": "RS256"}, {}, False, "invalid_trusted_session_claims"),
    ({"typ": "JWT"}, {}, False, "invalid_trusted_session_claims"),
    ({"protocol_version": "1.0"}, {}, False, "invalid_trusted_session_claims"),
    ({"kid": "unknown"}, {}, False, "trusted_key_not_found"),
    ({"jku": "https://attacker.invalid/keys"}, {}, False, "invalid_trusted_session_claims"),
    ({"jwk": {"kty": "OKP"}}, {}, False, "invalid_trusted_session_claims"),
    ({"b64": False, "crit": ["b64"]}, {}, False, "invalid_trusted_session_claims"),
    ({}, {"aud": "other-service"}, False, "issuer_or_audience_mismatch"),
    ({}, {"iss": "other-issuer"}, False, "issuer_or_audience_mismatch"),
    ({}, {"aud": ["mirage"]}, False, "invalid_trusted_session_claims"),
    ({}, {"iat": 1031, "nbf": 1031, "exp": 1091}, False, "trusted_session_not_yet_valid"),
    ({}, {"nbf": 1031}, False, "trusted_session_not_yet_valid"),
    ({}, {"iat": 910, "nbf": 910, "exp": 970}, False, "trusted_session_expired"),
    ({}, {"exp": 1061}, False, "trusted_session_lifetime_exceeded"),
    ({}, {"nbf": 1060}, False, "trusted_session_invalid_time_order"),
    ({}, {"session_epoch": True}, False, "invalid_trusted_session_claims"),
    ({}, {}, True, "invalid_trusted_session_signature"),
], ids=["none", "hmac", "eddsa-alias", "rsa", "type", "downgrade", "unknown-key", "remote-key-url",
        "embedded-key", "unencoded-payload", "audience", "issuer", "audience-array", "future-issued",
        "future-not-before", "expiry-equality", "long-lifetime", "time-order", "boolean-epoch", "wrong-key"])
def test_required_jws_policy_rejections_do_not_consume_valid_authorization(header, claims, wrong_key, error):
    """SEC-06：有效測試簽章不能繞過演算法／身份／期限政策，拒絕不耗用原授權。"""
    checked = verifier()
    arguments = dict(expected_issuer="gateway", expected_audience="mirage", request_fingerprint="a" * 64, now=1000)
    with pytest.raises(TrustedSessionError, match=error):
        checked.verify(resign_vector(header_changes=header, claim_changes=claims, wrong_key=wrong_key), **arguments)
    assert checked.verify(token(), **arguments).jti == "jti-1"


@pytest.mark.parametrize("field", ["iss", "aud", "iat", "nbf", "exp", "jti", "environment_id",
    "deployment_id", "session_id", "session_epoch", "request_fingerprint", "assessment_id", "assessment_digest"])
def test_required_claims_cannot_be_omitted_even_with_valid_signature(field):
    """固定協定必填集合缺一即拒絕；不因簽章有效便採用未知身份或補造欄位。"""
    checked = verifier()
    arguments = dict(expected_issuer="gateway", expected_audience="mirage", request_fingerprint="a" * 64, now=1000)
    with pytest.raises(TrustedSessionError, match="invalid_trusted_session_claims"):
        checked.verify(resign_vector(missing_claim=field), **arguments)
    assert checked.verify(token(), **arguments).jti == "jti-1"
