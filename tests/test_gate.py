"""Synthetic contract tests; these do not certify WooCommerce or Medusa."""
import copy
import hashlib
import json

import pytest
import yaml
from fastapi.testclient import TestClient

from mirage_validator import api
from mirage_validator.gate import GateRequest, OfficialResponseGate, PlatformRegistry


def package(root, *, version="3.1.0", approved=True, base="https://shop.test/api", folder="test", spec_change=None):
    directory = root / folder
    directory.mkdir(parents=True, exist_ok=True)
    schema = {"type": "object", "required": ["id", "state"], "additionalProperties": False,
              "properties": {"id": {"type": "integer"}, "state": {"enum": ["active", "draft"]}}}
    spec = {"openapi": version, "info": {"title": "TEST ONLY", "version": "1"},
            "paths": {"/products/{id}": {"get": {"operationId": "getProduct", "parameters": [
                {"in": "path", "name": "id", "required": True, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "test", "headers": {"X-Total": {"required": True, "schema": {"type": "integer"}}},
                                      "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Product"}}}}}}}},
            "components": {"schemas": {"Product": schema}}}
    if spec_change:
        spec_change(spec)
    data = yaml.safe_dump(spec).encode()
    (directory / "openapi.yaml").write_bytes(data)
    manifest = {"platform_id": "test", "platform_version": "1.0", "source_url": "https://example.org/test-only",
                "source_revision": "test-only", "spec_sha256": hashlib.sha256(data).hexdigest(), "approved": approved,
                "base_urls": [base]}
    (directory / "manifest.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    return directory


def request(**changes):
    data = dict(request_url="https://shop.test/api/products/101", request_method="GET", status_code=200,
                headers={"Content-Type": "application/json; charset=utf-8", "X-Total": "1"},
                body='{"id":101,"state":"active"}')
    data.update(changes)
    return GateRequest(**data)


@pytest.mark.parametrize("version", ["3.0.3", "3.1.0"])
def test_openapi_versions_and_api(tmp_path, monkeypatch, version):
    package(tmp_path, version=version)
    gate = OfficialResponseGate(PlatformRegistry(tmp_path))
    result = gate.validate(request())
    assert result.decision == "pass", result
    assert result.operation_id == "getProduct"
    monkeypatch.setattr(api, "gate", gate)
    response = TestClient(api.app).post("/v1/validate", json=request().model_dump())
    assert response.status_code == 200
    assert response.json()["valid"] is True


@pytest.mark.parametrize("version", ["3.0.3", "3.1.0"])
@pytest.mark.parametrize("changes,code,path", [
    ({"body": '{"id":"101","state":"active"}'}, "type", "/id"),
    ({"body": '{"id":101,"state":"wrong"}'}, "enum", "/state"),
    ({"body": '{"id":101}'}, "required", ""),
    ({"body": '{"id":101,"state":"active","extra":1}'}, "additionalProperties", ""),
    ({"body": '{"id":true,"state":"active"}'}, "type", "/id"),
    ({"body": '{'}, "invalid_json", ""),
    ({"body": '{"id":1,"id":2}'}, "invalid_json", ""),
    ({"status_code": 201}, "unsupported_status", "/status_code"),
    ({"headers": {}}, "content_type", "/content-type"),
    ({"headers": {"Content-Type": "application/json"}}, "required", "/x-total"),
])
def test_reject(tmp_path, changes, code, path, version):
    package(tmp_path, version=version)
    result = OfficialResponseGate(PlatformRegistry(tmp_path)).validate(request(**changes))
    assert result.decision == "reject", result
    assert any(e.code == code and e.path == path for e in result.errors), result


@pytest.mark.parametrize("changes,code", [
    ({"request_url": "https://unknown.test/api/products/101"}, "site_not_unique"),
    ({"request_url": "https://shop.test/api/products/101?fields=id"}, "unsupported_context"),
    ({"request_url": "https://shop.test/api/orders/101"}, "operation_not_unique"),
    ({"request_method": "POST"}, "operation_not_unique"),
])
def test_unverifiable(tmp_path, changes, code):
    package(tmp_path)
    result = OfficialResponseGate(PlatformRegistry(tmp_path)).validate(request(**changes))
    assert result.decision == "unverifiable"
    assert result.errors[0].code == code


def test_unapproved_and_ambiguous(tmp_path):
    package(tmp_path, approved=False)
    gate = OfficialResponseGate(PlatformRegistry(tmp_path))
    assert gate.validate(request()).errors[0].code == "contract_not_approved"
    package(tmp_path, folder="other")
    assert OfficialResponseGate(PlatformRegistry(tmp_path)).validate(request()).errors[0].code == "site_not_unique"


def test_missing_schema(tmp_path):
    package(tmp_path, spec_change=lambda s: s["paths"]["/products/{id}"]["get"]["responses"]["200"].pop("content"))
    assert OfficialResponseGate(PlatformRegistry(tmp_path)).validate(request()).decision == "unverifiable"


def test_digest_and_remote_refs(tmp_path):
    directory = package(tmp_path)
    with (directory / "openapi.yaml").open("a") as f:
        f.write("\n# modified\n")
    with pytest.raises(ValueError, match="hash"):
        PlatformRegistry(tmp_path)
    package(tmp_path, spec_change=lambda s: s["components"]["schemas"].update(Product={"$ref": "https://example.org/schema"}))
    with pytest.raises(ValueError, match="bundled"):
        PlatformRegistry(tmp_path)


def test_no_mutation_and_header_types(tmp_path):
    package(tmp_path)
    gate = OfficialResponseGate(PlatformRegistry(tmp_path))
    value = request(headers={"CONTENT-TYPE": "application/json", "X-Total": "wrong"})
    original = copy.deepcopy(value)
    assert not gate.validate(value).valid
    assert value == original


def test_empty_registry_never_passes(tmp_path):
    assert not OfficialResponseGate(PlatformRegistry(tmp_path)).validate(request()).valid


def test_second_website_and_explicit_query_context(tmp_path):
    directory = package(tmp_path, base="https://second.test/store")
    path = directory / "manifest.yaml"
    manifest = yaml.safe_load(path.read_text(encoding="utf-8"))
    manifest["query_contexts"] = [{"limit": ["10"]}]
    path.write_text(yaml.safe_dump(manifest), encoding="utf-8")
    gate = OfficialResponseGate(PlatformRegistry(tmp_path))
    assert gate.validate(request(request_url="https://second.test/store/products/1?limit=10")).valid
    assert not gate.validate(request(request_url="https://second.test/store/products/1?limit=20")).valid


@pytest.mark.parametrize("version", ["3.0.3", "3.1.0"])
def test_additional_properties_come_from_spec(tmp_path, version):
    package(tmp_path, version=version, spec_change=lambda s: s["components"]["schemas"]["Product"].update(additionalProperties=True))
    gate = OfficialResponseGate(PlatformRegistry(tmp_path))
    assert gate.validate(request(body='{"id":1,"state":"active","extra":1}')).valid


def test_bad_url_returns_result(tmp_path):
    gate = OfficialResponseGate(PlatformRegistry(tmp_path))
    assert gate.validate(request(request_url="http://[bad")).decision == "unverifiable"
