"""跨元件 Golden Vector 的固定序列化與來源型別驗收。"""

import json
from pathlib import Path

import pytest

from deception.api.ingress import NormalizedRequest
from deception.world import ResponseAdmission, SecurityErrorSource, SnapshotSource
from deception.world.models import canonical_state_hash


def vector_path() -> Path:
    """定位版本控制中的 World Runtime Golden Vector fixture。"""
    return Path(__file__).parent / "fixtures" / "golden_vectors" / "world_runtime.json"


def test_world_runtime_golden_vector_matches_canonical_hash():
    """確認固定 JSON 狀態在不同執行環境得到相同 SHA-256。"""
    vector = json.loads(vector_path().read_text(encoding="utf-8"))
    assert canonical_state_hash(vector["canonical_state"]) == vector["canonical_state_sha256"]


def test_world_runtime_golden_vector_preserves_discriminated_sources():
    """確認 Snapshot 與 Security Error 不會被解讀成同一種回應來源。"""
    vector = json.loads(vector_path().read_text(encoding="utf-8"))
    snapshot = SnapshotSource.model_validate(vector["response_sources"][0])
    security_error = SecurityErrorSource.model_validate(vector["response_sources"][1])
    assert snapshot.kind == "snapshot"
    assert security_error.kind == "security_error"


def test_world_runtime_golden_vector_preserves_admission_registry_evidence():
    """確認 Admission 含有不可省略的 Projection Registry revision 與來源證據。"""
    vector = json.loads(vector_path().read_text(encoding="utf-8"))
    admission = ResponseAdmission.model_validate(vector["response_admission"])
    assert admission.grant_revision == 10
    assert admission.projection_registry_revision == 7
    assert admission.projection_evidence.projection_contract_hash == admission.projection_contract_hash


def test_http_error_golden_vectors_match_fixed_security_envelopes():
    """確認固定安全錯誤只回傳核准 code、status 與 request ID。"""
    pytest.importorskip("openapi_core")
    from deception.api.pipeline import _unavailable

    vector = json.loads(vector_path().read_text(encoding="utf-8"))
    request = NormalizedRequest(
        request_id="request-vector-1",
        method="GET",
        raw_url="https://vector.test/products/1",
        path="/products/1",
        raw_path=b"/products/1",
        query_string=b"",
        query=(),
        headers=(),
        body=b"",
    )
    responses = {
        "pipeline_unavailable": _unavailable(request),
        "pipeline_not_applicable": _unavailable(request, not_applicable=True),
    }
    for expected in vector["http_errors"]:
        response = responses[expected["name"]]
        assert response.status_code == expected["status"]
        assert json.loads(response.body) == expected["body"]
        assert response.headers["x-request-id"] == request.request_id
