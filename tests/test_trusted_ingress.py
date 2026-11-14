"""Trusted Session HTTP ingress adapter 的固定向量與負向驗收。"""

import json
import base64
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from deception.api.fingerprint import fingerprint_request
from deception.api.ingress import NormalizedRequest
from deception.security import (
    TrustedKeyRegistry,
    TrustedSessionAssessmentProvider,
    TrustedSessionError,
    TrustedSessionVerifier,
)
from deception.world import ReplayStore


VECTOR = json.loads((Path(__file__).parent / "fixtures" / "golden_vectors" /
                     "trusted_session.json").read_text(encoding="utf-8"))


def token() -> str:
    """以固定 header、claims 與 signature 組合跨語言 JWS vector。"""
    def encode(value: object) -> str:
        """以 Compact JWS 規則編碼固定向量元件。"""
        return base64.urlsafe_b64encode(
            json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).decode("ascii").rstrip("=")

    return ".".join((encode(VECTOR["header"]), encode(VECTOR["claims"]), VECTOR["signature"]))


def vector_request() -> NormalizedRequest:
    """建立與固定 JWS vector 完全相同的原始 HTTP 請求快照。"""
    value = VECTOR["request"]
    return NormalizedRequest(
        request_id=value["request_id"],
        method=value["method"],
        raw_url=value["raw_url"],
        path=value["path"],
        raw_path=bytes.fromhex(value["raw_path_hex"]),
        query_string=bytes.fromhex(value["query_string_hex"]),
        query=tuple(map(tuple, value["query"])),
        headers=(*tuple(map(tuple, value["headers"])),
                 ("x-trusted-session", token())),
        body=value["body"].encode("utf-8"),
    )


def verifier() -> TrustedSessionVerifier:
    """建立固定向量使用的公開金鑰與程序內 Replay 驗證器。"""
    return TrustedSessionVerifier(
        keys=TrustedKeyRegistry({("gateway", "gateway-1"): bytes.fromhex(VECTOR["public_key_hex"])}),
        replay_store=ReplayStore(),
    )


def provider() -> TrustedSessionAssessmentProvider:
    """建立固定向量使用的共享 Replay 驗證 provider。"""
    return TrustedSessionAssessmentProvider(
        verifier(),
        expected_issuer="gateway",
        expected_audience="mirage",
        environment_id="env-1",
        deployment_id="deploy-1",
        source_id="reviewed-detector",
        service_id="store",
        site_id="shop",
        attack_types=("trusted-session",),
        now=VECTOR["now"],
    )


def test_fixed_jws_vector_becomes_pipeline_assessment():
    """固定跨語言 JWS 通過後，輸出既有 malicious assessment 且綁定同一請求。"""
    request = vector_request()
    assert fingerprint_request(request) == "a7e46fc29bd9ae1aeb3511ba08097ac6bdaed9d7bdee5873779d1457e3f99040"
    assessment = provider()(request)
    assert assessment.assessment_id == "assessment-vector-1"
    assert assessment.request_id == request.request_id
    assert assessment.request_fingerprint == fingerprint_request(request)
    assert assessment.verdict == "malicious"
    assert assessment.attack_types == ["trusted-session"]


@pytest.mark.parametrize("change", ["header", "duplicate", "context"])
def test_trusted_ingress_rejects_header_or_context_tampering(change: str):
    """缺少、重複或環境不符時拒絕，且不進入 assessment pipeline。"""
    request = vector_request()
    if change == "header":
        request = replace(request, headers=())
    elif change == "duplicate":
        request = replace(request, headers=(
            *request.headers, ("x-trusted-session", token()),
            ("x-trusted-session", token()),
        ))
    else:
        configured = TrustedSessionAssessmentProvider(
            verifier(),
            expected_issuer="gateway",
            expected_audience="mirage",
            environment_id="other-environment",
            deployment_id="deploy-1",
            source_id="reviewed-detector",
            service_id="store",
            site_id="shop",
            now=VECTOR["now"],
        )
        with pytest.raises(TrustedSessionError, match="context"):
            configured(request)
        return
    with pytest.raises(TrustedSessionError, match="header"):
        provider()(request)


def test_replayed_jws_is_rejected_by_provider():
    """同一固定 JTI 第二次送入 HTTP adapter 必須回報 Replay。"""
    adapter = provider()
    request = vector_request()
    adapter(request)
    with pytest.raises(TrustedSessionError, match="replay"):
        adapter(request)


def test_http_pipeline_consumes_verified_assessment_before_c():
    """真正 HTTP ingress 只在 JWS 驗證後呼叫 C，並把 benign 分支固定封套化。"""
    from deception.api.pipeline import create_app

    observed = []

    class StubOrchestrator:
        gate = object()

        async def run(self, request, assessment, **kwargs):
            """記錄已驗證判定，模擬 C 對不適用政策的固定結果。"""
            observed.append((request, assessment))
            return SimpleNamespace(decision="not_applicable")

    app = create_app(
        StubOrchestrator(),
        runtime=None,
        generation_config=None,
        assessment_provider=provider(),
    )
    request = vector_request()
    with TestClient(app, base_url="https://shop.test") as client:
        response = client.get(
            request.raw_url,
            headers={"X-Request-ID": request.request_id, "X-Trusted-Session": token()},
        )
    assert response.status_code == 409
    assert response.json() == {
        "code": "pipeline_not_applicable",
        "request_id": request.request_id,
    }
    assert len(observed) == 1
    assert observed[0][1].verdict == "malicious"
