"""跨元件 Golden Vector 的固定序列化與來源型別驗收。"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from deception.api.ingress import NormalizedRequest
from deception.world import ResponseAdmission, SecurityErrorSource, SnapshotSource
from deception.world.models import canonical_state_hash


def admission_projection_vectors():
    """載入包含已提交來源、匿名投影核准及固定拒絕變異的互通向量。"""
    path = Path(__file__).parent / "fixtures" / "golden_vectors" / "admission_projection.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("vector", admission_projection_vectors()["cases"], ids=lambda row: row["name"])
def test_admission_projection_interchange_vectors(vector):
    """核對公開 JSON 接口的接受／拒絕語意，避免差異核准或來源在序列化時遺失。"""
    # lambda 僅為 pytest 顯示 fixture 中固定案例名稱，不參與協定判定。
    if vector["accepted"]:
        admission = ResponseAdmission.model_validate(vector["admission"])
        # 舊 JSON 可省略可選核准；比較輸入明列欄位，再驗證補齊預設後的往返。
        assert admission.model_dump(mode="json", exclude_unset=True) == vector["admission"]
        assert ResponseAdmission.model_validate_json(admission.model_dump_json()) == admission
    else:
        with pytest.raises(ValidationError) as raised:
            ResponseAdmission.model_validate(vector["admission"])
        if vector["error_contains"]:
            assert vector["error_contains"] in str(raised.value)


def test_admission_projection_vectors_match_independent_node():
    """以 Node 獨立核對相同核准鏈、世代、編碼及期限向量，不冒稱完整語言 SDK。"""
    node = shutil.which("node")
    if node is None:
        pytest.skip("requires Node.js for independent admission/projection vectors")
    result = subprocess.run([node, str(vector_path().parent / "verify_admission_projection.mjs")],
                            check=True, capture_output=True, text=True, timeout=10)
    assert result.stdout == f"admission-projection-vectors-ok:{len(admission_projection_vectors()['cases'])}"


def test_world_policy_vector_binds_exact_profiles_and_state_hash():
    """固定世界政策摘要與快照 hash 同時涵蓋全部 Profile，JSON 往返不丟版本資料。"""
    from deception.world import WorldCompatibility, WorldScope, WorldSnapshot

    fixture = admission_projection_vectors()
    policy = WorldCompatibility.model_validate(fixture["world_policy"])
    assert policy.model_dump(mode="json") == fixture["world_policy"]
    scope = WorldScope(environment_id="vector", deployment_id="test", session_id="session", world_generation_id="world")
    snapshot = WorldSnapshot.create(scope, fixture["world_state"])
    assert snapshot.compatibility == policy
    assert snapshot.state_hash == fixture["world_state_sha256"]


def vector_path() -> Path:
    """定位版本控制中的 World Runtime Golden Vector fixture。"""
    return Path(__file__).parent / "fixtures" / "golden_vectors" / "world_runtime.json"


def test_response_transport_vector_matches_python_and_node():
    """固定封套由 Python 與 Node.js 獨立計算，核對順序、長度與三個 hash。"""
    from deception.world.transmission import response_envelope, response_hashes

    directory = vector_path().parent
    vector = json.loads((directory / "response_transport.json").read_text(encoding="utf-8"))
    arguments = (vector["status"], vector["headers"], vector["body"].encode())
    assert response_envelope(*arguments).hex() == vector["envelope_hex"]
    assert response_hashes(*arguments) == (vector["candidate_hash"], vector["body_hash"], vector["semantic_headers_hash"])
    node = shutil.which("node")
    if node is None:
        pytest.skip("requires Node.js for independent transport vector")
    result = subprocess.run([node, str(directory / "verify_transport.mjs")], check=True,
                            capture_output=True, text=True, timeout=10)
    assert result.stdout == "transport-vector-ok"


def test_request_fingerprint_vectors_match_python_and_node():
    """兩種語言從原始 bytes 欄位重算摘要，核對重複 query、標頭順序及歧義拒絕。"""
    from deception.api.fingerprint import fingerprint_request

    directory = vector_path().parent
    fixture = json.loads((directory / "request_fingerprint.json").read_text(encoding="utf-8"))
    assert fixture["canonicalization_version"] == 1
    for vector in fixture["cases"]:
        values = dict(vector["request"])
        for name in ("raw_path", "query_string", "body"):
            values[name] = bytes.fromhex(values[name])
        for name in ("query", "headers"):
            values[name] = tuple(tuple(row) for row in values[name])
        request = NormalizedRequest(**values)
        if "error" in vector:
            with pytest.raises(ValueError, match=vector["error"]):
                fingerprint_request(request)
        else:
            assert fingerprint_request(request) == vector["fingerprint"], vector["name"]
    node = shutil.which("node")
    if node is None:
        pytest.skip("requires Node.js for independent request fingerprint vectors")
    result = subprocess.run([node, str(directory / "verify_fingerprint.mjs")], check=True,
                            capture_output=True, text=True, timeout=10)
    assert result.stdout == "request-fingerprint-vectors-ok"


def test_request_vectors_match_actual_gateway_dispatcher(monkeypatch):
    """由實際 Gateway 的最終 HTTPX request 適配器核對同一批 wire 向量。"""
    import os
    import httpx

    root = Path(os.environ.get("MSDSS_ROOT", Path(__file__).resolve().parents[2] / "MSDSS"))
    if not (root / "src/msdss/adapters/request_binding.py").is_file():
        pytest.skip("requires MSDSS request binding adapter checkout")
    monkeypatch.syspath_prepend(str(root / "src"))
    from msdss.gateway_integration.trusted_session_dispatch import wire_fingerprint

    fixture = json.loads((vector_path().parent / "request_fingerprint.json").read_text(encoding="utf-8"))
    for vector in fixture["cases"]:
        values = vector["request"]
        request = httpx.Request(values["method"], values["raw_url"], content=bytes.fromhex(values["body"]))
        # 以向量明列的最終標頭覆蓋 client 建構時的自動補值，保留 case 與順序。
        request.headers = httpx.Headers([(name.encode("ascii"), value.encode("latin-1"))
                                        for name, value in values["headers"]])
        if "error" in vector:
            with pytest.raises(ValueError):
                wire_fingerprint(request, values["request_id"])
        else:
            assert wire_fingerprint(request, values["request_id"]) == vector["fingerprint"], vector["name"]


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
    assert admission.hash_encoding_version == admission.candidate_serialization_version == 1
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
