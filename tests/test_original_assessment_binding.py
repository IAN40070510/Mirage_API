"""嚴格原始判定查回的正負向契約；不使用 staging 或正式身分。"""

import base64
import hashlib
import json
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Never
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from deception.scenarios.models import AttackAssessment
from deception.security.trusted_ingress import TrustedSessionAssessmentProvider
from deception.security.trusted_session import (
    TrustedKeyRegistry,
    TrustedSessionClaims,
    TrustedSessionError,
    TrustedSessionVerifier,
)
from deception.world import ReplayStore
from fastapi.testclient import TestClient
from test_trusted_ingress import VECTOR, vector_request



def assessment() -> AttackAssessment:
    """建立與簽章宣告對應的私有原判定（僅用合成資料）。"""
    return AttackAssessment(
        assessment_id="assessment-vector-1",
        source_id="reviewed-detector",
        request_id=vector_request().request_id,
        request_fingerprint=VECTOR["claims"]["request_fingerprint"],
        environment_id="env-1",
        deployment_id="deploy-1",
        service_id="store",
        site_id="shop",
        verdict="malicious",
        attack_types=["trusted-session"],
        observed_at=datetime.fromtimestamp(1000, tz=UTC),
        expires_at=datetime.fromtimestamp(1050, tz=UTC),
    )


class SignedClaimsVerifier:
    """隔離原始摘要驗證；JWS 簽章本身由既有真向量測試驗證。"""

    def __init__(self, claims: TrustedSessionClaims) -> None:
        """保存已驗證的測試聲明，以隔離原判定綁定邏輯。"""
        self.claims = claims

    def verify(self, *_args: object, **_kwargs: object) -> TrustedSessionClaims:
        """傳回模擬已驗章的 claims，不可用作正式 JWS 驗證器。"""
        return self.claims


def strict_provider(
    original: AttackAssessment, *, lookup: Callable[[str], AttackAssessment | None] | None = None
) -> TrustedSessionAssessmentProvider:
    """注入可信私有 lookup，讓此測試只驗原判定綁定。"""
    digest = hashlib.sha256(original.model_dump_json().encode("utf-8")).hexdigest()
    claims = TrustedSessionClaims.model_validate({
        **VECTOR["claims"], "assessment_digest": digest,
    })
    return TrustedSessionAssessmentProvider(
        SignedClaimsVerifier(claims),
        expected_issuer="gateway",
        expected_audience="mirage",
        environment_id="env-1",
        deployment_id="deploy-1",
        source_id="reviewed-detector",
        service_id="store",
        site_id="shop",
        attack_types=("trusted-session",),
        now=1010,
        original_lookup=(lambda _id: original) if lookup is None else lookup,
        require_original_assessment=True,
    )


def test_signed_digest_rejection_prevents_http_orchestration() -> None:
    """真實簽章仍因原判定摘要不符得到固定 503，且不進入 Orchestrator。"""
    from deception.api.pipeline import create_app
    from test_trusted_ingress import token, verifier

    original = assessment()
    receiver = TrustedSessionAssessmentProvider(
        verifier(), expected_issuer="gateway", expected_audience="mirage",
        environment_id="env-1", deployment_id="deploy-1",
        source_id="reviewed-detector", service_id="store", site_id="shop",
        now=VECTOR["now"], require_original_assessment=True,
        original_lookup=lambda _id: original,
    )
    run = AsyncMock()
    app = create_app(SimpleNamespace(gate=object(), run=run), runtime=None,
                     generation_config=None, assessment_provider=receiver)
    request = vector_request()
    with TestClient(app, base_url="https://shop.test") as client:
        response = client.get(
            request.raw_url,
            headers={"X-Request-ID": request.request_id, "X-Trusted-Session": token()},
        )
    assert response.status_code == 503  # noqa: S101
    assert response.json() == {  # noqa: S101
        "code": "pipeline_unavailable", "request_id": request.request_id
    }
    run.assert_not_called()


def test_original_assessment_exact_digest_is_accepted() -> None:
    """精確來源、身份、原始 bytes 摘要均相符才接受。"""
    original = assessment()
    result = strict_provider(original).verify_with_claims(vector_request())
    assert result.assessment is original  # noqa: S101


@pytest.mark.parametrize(
    "change", ["id", "request", "source", "fingerprint", "scope", "verdict", "expired", "digest"]
)
def test_original_assessment_tampering_is_rejected(change: str) -> None:
    """簽章有效仍須拒絕缺失、過期、身份不同與摘要不符。"""
    original = assessment()
    provider = strict_provider(original)
    modified = original.model_copy(deep=True)
    if change == "id":
        modified.assessment_id = "another-assessment"
    elif change == "request":
        modified.request_id = "another-request"
    elif change == "source":
        modified.source_id = "other-detector"
    elif change == "fingerprint":
        modified.request_fingerprint = "f" * 64
    elif change == "scope":
        modified.deployment_id = "other-deploy"
    elif change == "verdict":
        modified.verdict = "benign"
    elif change == "expired":
        modified.expires_at = datetime.fromtimestamp(1009, tz=UTC)
    else:
        modified.attack_types = ["substituted"]
    provider._original_lookup = lambda _id: modified
    with pytest.raises(TrustedSessionError, match="original_assessment_"):
        provider(vector_request())


def test_real_ed25519_original_digest_and_single_use() -> None:
    """真正簽署原判定 digest 後接受一次；第二次則被 Replay 拒絕。"""
    original = assessment()
    private_key = Ed25519PrivateKey.generate()
    digest = hashlib.sha256(original.model_dump_json().encode("utf-8")).hexdigest()
    header = dict(alg="Ed25519", typ="mirage-trusted-session+jwt",
                  kid="gateway-1", protocol_version="1.1")
    claims = {**VECTOR["claims"], "assessment_digest": digest}

    def encode(value: dict) -> str:
        """將測試 JWS 的 JSON 欄位轉為不含填充字元的 Base64URL。"""
        return base64.urlsafe_b64encode(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).decode("ascii").rstrip("=")

    signing_input = encode(header) + "." + encode(claims)
    signature = base64.urlsafe_b64encode(
        private_key.sign(signing_input.encode("ascii"))
    ).decode("ascii").rstrip("=")
    request = vector_request()
    request = replace(
        request, headers=(*request.headers[:-1],
                          ("x-trusted-session", signing_input + "." + signature)),
    )
    trusted_verifier = TrustedSessionVerifier(
        keys=TrustedKeyRegistry({
            ("gateway", "gateway-1"): private_key.public_key().public_bytes_raw()
        }),
        replay_store=ReplayStore(),
    )
    ingress = TrustedSessionAssessmentProvider(
        trusted_verifier, expected_issuer="gateway", expected_audience="mirage",
        environment_id="env-1", deployment_id="deploy-1",
        source_id="reviewed-detector", service_id="store", site_id="shop",
        now=VECTOR["now"], original_lookup=lambda _id: original,
        require_original_assessment=True,
    )
    assert ingress(request) is original  # noqa: S101
    with pytest.raises(TrustedSessionError, match="replay"):
        ingress(request)


def test_real_ed25519_signed_vector_still_rejects_unbound_digest() -> None:
    """即使真實 Ed25519 驗章成功，缺原判定 digest 對應仍不可授權。"""
    from test_trusted_ingress import verifier

    original = assessment()
    trusted = TrustedSessionAssessmentProvider(
        verifier(),
        expected_issuer="gateway", expected_audience="mirage",
        environment_id="env-1", deployment_id="deploy-1",
        source_id="reviewed-detector", service_id="store", site_id="shop",
        attack_types=("trusted-session",), now=VECTOR["now"],
        original_lookup=lambda _id: original, require_original_assessment=True,
    )
    with pytest.raises(TrustedSessionError, match="original_assessment_digest_mismatch"):
        trusted(vector_request())


def test_invalid_lookup_return_type_fails_closed() -> None:
    """拒絕非正式 AttackAssessment 模型的任意私有 lookup 回應。"""
    original = assessment()
    with pytest.raises(TrustedSessionError, match="original_assessment_invalid"):
        strict_provider(original, lookup=lambda _id: {"assessment_id": "fake"})(vector_request())


def test_strict_mode_configuration_rejects_incomplete_or_ambiguous_values() -> None:
    """私有查回不允許誤設成已提供但沒有啟用嚴格模式。"""
    original = assessment()
    trusted = dict(
        expected_issuer="gateway", expected_audience="mirage",
        environment_id="env-1", deployment_id="deploy-1",
        source_id="reviewed-detector", service_id="store", site_id="shop",
    )
    claims = TrustedSessionClaims.model_validate(VECTOR["claims"])
    with pytest.raises(ValueError, match="requires strict mode"):
        TrustedSessionAssessmentProvider(
            SignedClaimsVerifier(claims), **trusted,
            original_lookup=lambda _id: original,
        )
    with pytest.raises(ValueError, match="must be boolean"):
        TrustedSessionAssessmentProvider(
            SignedClaimsVerifier(claims), **trusted,
            require_original_assessment=1,
        )


def test_missing_and_unavailable_lookup_fail_closed() -> None:
    """缺原始判定與儲存故障一律拒絕，不回退到重建 malicious 判定。"""
    original = assessment()
    with pytest.raises(ValueError, match="lookup required"):
        TrustedSessionAssessmentProvider(
            SignedClaimsVerifier(TrustedSessionClaims.model_validate({
                **VECTOR["claims"], "assessment_digest": "a" * 64,
            })),
            expected_issuer="gateway", expected_audience="mirage",
            environment_id="env-1", deployment_id="deploy-1",
            source_id="reviewed-detector", service_id="store", site_id="shop",
            require_original_assessment=True,
        )
    with pytest.raises(TrustedSessionError, match="original_assessment_missing"):
        strict_provider(original, lookup=lambda _id: None)(vector_request())

    def unavailable(_id: str) -> Never:
        """模擬可信私有原判定儲存層不可存取。"""
        raise ConnectionError("synthetic private storage unavailable")

    with pytest.raises(TrustedSessionError, match="original_assessment_unavailable"):
        strict_provider(original, lookup=unavailable)(vector_request())
