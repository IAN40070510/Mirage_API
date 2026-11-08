"""以真實 I 驗證器檢查 H 的身份交接，不核准任何實際平台來源。"""

import hashlib
from dataclasses import replace

import pytest
import yaml

from deception.core import CompositionPlan, ResponseComposer, verify_candidate
from deception.profile_builder import build_profile
from deception.synthetic import DatasetScope
from mirage_validator.gate import OfficialResponseGate, PlatformRegistry


@pytest.fixture
def candidate_and_gate(tmp_path):
    """兩個不同 operation 共用 response schema，用來重現錯誤 URL 也可能通過的情況。"""
    response = {"description": "Test only", "content": {"application/json": {"schema": {
        "type": "object", "required": ["id"], "additionalProperties": False,
        "properties": {"id": {"type": "string"}}}}}}
    paths = {}
    for path, operation in (("/products/{id}", "getProduct"), ("/other/{id}", "getOther")):
        paths[path] = {"get": {"operationId": operation, "parameters": [
            {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
            "responses": {"200": response}}}
    spec = {"openapi": "3.1.0", "info": {"title": "Handoff test only", "version": "1"}, "paths": paths}
    raw = yaml.safe_dump(spec).encode("utf-8")
    source = {"platform_id": "synthetic", "platform_version": "1",
              "source_url": "https://example.org/test-only", "source_revision": "test-only-fixed",
              "spec_sha256": hashlib.sha256(raw).hexdigest(), "approved": True, "openapi_file": "openapi.yaml"}
    directory = tmp_path / "contracts" / "test-only"
    directory.mkdir(parents=True)
    (directory / "openapi.yaml").write_bytes(raw)
    (directory / "source.yaml").write_text(yaml.safe_dump(source), encoding="utf-8")
    manifest = dict(source, base_urls=["https://shop.test"], query_contexts=[{}])
    (directory / "manifest.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    output = tmp_path / "generated"
    build_profile(directory / "source.yaml", output)
    scope = DatasetScope(site_id="shop-test", platform_id="synthetic", platform_version="1",
                         spec_sha256=source["spec_sha256"], scenario_id="product-found", run_id="test-run")
    candidate = ResponseComposer(output).compose(CompositionPlan(
        scope=scope, path="/products/{id}", status_code=200, body={"id": "synthetic-product"}))
    return candidate, OfficialResponseGate(PlatformRegistry(tmp_path / "contracts"))


def test_verify_candidate_passes_same_identity_and_preserves_triple(candidate_and_gate):
    candidate, gate = candidate_and_gate
    before = candidate.to_dict()
    result = verify_candidate(candidate, gate, "https://shop.test/products/synthetic-product")
    assert result.valid and result.decision == "pass"
    assert result.operation_id == candidate.identity.operation_id
    assert candidate.to_dict() == before


def test_another_operation_cannot_validate_this_candidate(candidate_and_gate):
    candidate, gate = candidate_and_gate
    url = "https://shop.test/other/synthetic-product"
    # 普通 I 判定只針對收到的 URL，兩個 operation 的 response schema 相同。
    assert gate.validate(candidate.to_gate_request(url)).decision == "pass"
    result = verify_candidate(candidate, gate, url)
    assert result.decision == "unverifiable" and result.valid is False
    assert result.operation_id == "getOther"
    assert result.errors[-1].code == "candidate_identity_mismatch"


@pytest.mark.parametrize("changes", [{"platform_id": "other"}, {"platform_version": "2"},
                                     {"spec_sha256": "0" * 64}])
def test_mismatched_contract_metadata_cannot_pass(candidate_and_gate, changes):
    candidate, gate = candidate_and_gate
    changed = replace(candidate, identity=replace(candidate.identity, **changes))
    result = verify_candidate(changed, gate, "https://shop.test/products/synthetic-product")
    assert result.valid is False
    assert result.errors[-1].code == "candidate_identity_mismatch"


def test_gate_rejection_remains_rejection(candidate_and_gate):
    candidate, gate = candidate_and_gate
    changed = replace(candidate, body='{"id":3}')
    result = verify_candidate(changed, gate, "https://shop.test/products/synthetic-product")
    assert result.decision == "reject" and result.valid is False
    assert any(issue.code == "type" for issue in result.errors)


def test_unknown_site_remains_unverifiable(candidate_and_gate):
    candidate, gate = candidate_and_gate
    result = verify_candidate(candidate, gate, "https://unknown.test/products/synthetic-product")
    assert result.decision == "unverifiable" and result.valid is False
    assert result.errors[0].code == "site_not_unique"
