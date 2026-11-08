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
    """建立含必要 response header 與固定雜湊的合成平台契約，可注入規格變更。"""
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
    """以合法的固定商品候選建立 GateRequest，並套用待驗證的欄位變更。"""
    data = dict(request_url="https://shop.test/api/products/101", request_method="GET", status_code=200,
                headers={"Content-Type": "application/json; charset=utf-8", "X-Total": "1"},
                body='{"id":101,"state":"active"}')
    data.update(changes)
    return GateRequest(**data)


@pytest.mark.parametrize("version", ["3.0.3", "3.1.0"])
def test_openapi_versions_and_api(tmp_path, monkeypatch, version):
    """OpenAPI 3.0／3.1 的合法候選須由 gate 及 FastAPI 驗證入口一致接受。"""
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
    """已選定契約下的 body、狀態或 header 違規須回 reject 及正確錯誤位置。"""
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
    """站點、query、路徑或方法無法唯一確認時，須回 unverifiable。"""
    package(tmp_path)
    result = OfficialResponseGate(PlatformRegistry(tmp_path)).validate(request(**changes))
    assert result.decision == "unverifiable"
    assert result.errors[0].code == code


def test_unapproved_and_ambiguous(tmp_path):
    """未核准來源不能放行，多份站點契約重疊時也不能任選其中一份。"""
    package(tmp_path, approved=False)
    gate = OfficialResponseGate(PlatformRegistry(tmp_path))
    assert gate.validate(request()).errors[0].code == "contract_not_approved"
    package(tmp_path, folder="other")
    assert OfficialResponseGate(PlatformRegistry(tmp_path)).validate(request()).errors[0].code == "site_not_unique"


def test_missing_schema(tmp_path):
    """操作缺少回應內容 schema 時，gate 不得聲稱候選已可驗證。"""
    package(tmp_path, spec_change=lambda s: s["paths"]["/products/{id}"]["get"]["responses"]["200"].pop("content"))
    assert OfficialResponseGate(PlatformRegistry(tmp_path)).validate(request()).decision == "unverifiable"


def test_digest_and_remote_refs(tmp_path):
    """來源 bytes 摘要不符或含遠端 schema 引用時，載入契約必須失敗。"""
    directory = package(tmp_path)
    with (directory / "openapi.yaml").open("a") as f:
        f.write("\n# modified\n")
    with pytest.raises(ValueError, match="hash"):
        PlatformRegistry(tmp_path)
    package(tmp_path, spec_change=lambda s: s["components"]["schemas"].update(Product={"$ref": "https://example.org/schema"}))
    with pytest.raises(ValueError, match="bundled"):
        PlatformRegistry(tmp_path)


def test_no_mutation_and_header_types(tmp_path):
    """無效 header 型別應被拒絕，且驗證過程不能改動原候選物件。"""
    package(tmp_path)
    gate = OfficialResponseGate(PlatformRegistry(tmp_path))
    value = request(headers={"CONTENT-TYPE": "application/json", "X-Total": "wrong"})
    original = copy.deepcopy(value)
    assert not gate.validate(value).valid
    assert value == original


def test_empty_registry_never_passes(tmp_path):
    """沒有任何平台契約時，gate 不得回傳有效結果。"""
    assert not OfficialResponseGate(PlatformRegistry(tmp_path)).validate(request()).valid


def test_second_website_and_explicit_query_context(tmp_path):
    """契約可綁定另一個網站，但只有明確審查過的 query 值才能放行。"""
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
    """額外欄位是否允許須依來源 schema，不能由 gate 統一禁止。"""
    package(tmp_path, version=version, spec_change=lambda s: s["components"]["schemas"]["Product"].update(additionalProperties=True))
    gate = OfficialResponseGate(PlatformRegistry(tmp_path))
    assert gate.validate(request(body='{"id":1,"state":"active","extra":1}')).valid


def test_bad_url_returns_result(tmp_path):
    """格式錯誤的 URL 須回傳無法確認的結果，而非讓解析例外逃出 gate。"""
    gate = OfficialResponseGate(PlatformRegistry(tmp_path))
    assert gate.validate(request(request_url="http://[bad")).decision == "unverifiable"
