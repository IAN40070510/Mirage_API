"""用臨時合成契約驗證 A/B/D/E/H/I；不核准 repo 的 Medusa 或 WooCommerce。"""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from deception.api.app import create_app
from deception.api.identified import make_identification_handler
from deception.core import CompositionPlan, DataBinding, ResponseComposer, verify_candidate
from deception.discovery import BindingConfig, DeploymentBinding, PlatformIdentifier, RuntimeContext
from deception.profile_builder import ProfileTool, build_profile
from deception.synthetic import DatasetScope, SyntheticConfig, SyntheticTool, generate_dataset
from mirage_validator.gate import OfficialResponseGate, PlatformRegistry


@pytest.fixture
def stack(tmp_path):
    """明確的假站點、來源及審查狀態，只存在本測試的暫存目錄。"""
    schema = {"type": "object", "required": ["product"], "additionalProperties": False,
              "properties": {"product": {"type": "object", "required": ["id", "title"],
                                         "additionalProperties": False,
                                         "properties": {"id": {"type": "string"}, "title": {"type": "string"}}}}}
    spec = {"openapi": "3.1.0", "info": {"title": "B integration test only", "version": "1.0"},
            "paths": {"/products/{id}": {"get": {"operationId": "getProduct", "parameters": [
                {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "Synthetic", "content": {"application/json": {"schema": schema}}}}}}}}
    spec["paths"]["x-source-note"] = "Synthetic annotation, not an operation"
    raw = yaml.safe_dump(spec).encode("utf-8")
    source = {"platform_id": "synthetic", "platform_version": "1.0", "source_url": "https://example.org/test-only",
              "source_revision": "test-only-fixed", "spec_sha256": hashlib.sha256(raw).hexdigest(),
              "openapi_file": "openapi.yaml", "approved": True}
    directory = tmp_path / "contracts" / "test-only"
    directory.mkdir(parents=True)
    (directory / "openapi.yaml").write_bytes(raw)
    (directory / "source.yaml").write_text(yaml.safe_dump(source), encoding="utf-8")
    manifest = dict(source, base_urls=["https://shop.test/api"], query_contexts=[{}])
    (directory / "manifest.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    registry = PlatformRegistry(tmp_path / "contracts")
    binding = DeploymentBinding(binding_id="test-binding", environment_id="test-env", deployment_id="test-deploy",
                                service_id="store", site_id="shop-test", base_url="https://shop.test/api",
                                platform_id="synthetic", platform_version="1.0", spec_sha256=source["spec_sha256"],
                                enabled=True)
    identifier = PlatformIdentifier(registry, BindingConfig(bindings=[binding]))
    return identifier, registry, source, directory, tmp_path / "generated"


def test_a_b_entry_uses_runtime_binding_and_keeps_c_pending(stack):
    """A/B 入口採伺服器環境綁定並保留請求 ID，尚未串接 C 時明確回 501。"""
    identifier, _, _, _, _ = stack
    runtime = RuntimeContext(environment_id="test-env", deployment_id="test-deploy", service_id="store")
    client = TestClient(create_app(make_identification_handler(identifier, context=runtime)), base_url="https://shop.test")
    response = client.get("/api/products/prod-test", headers={"X-Request-ID": "ab-001",
                          "X-Environment-ID": "fake-env", "X-Forwarded-Host": "unknown.test"})
    assert response.status_code == 501
    data = response.json()
    assert data["code"] == "orchestrator_not_implemented"
    assert data["request_id"] == response.headers["x-request-id"] == "ab-001"
    assert data["identification"]["operation_id"] == "getProduct"
    assert data["identification"]["environment_id"] == "test-env"
    assert "query" not in data["identification"]
    assert "path_parameters" not in data["identification"]


def test_a_b_failures_do_not_echo_private_request_data(stack):
    """識別失敗回應僅含診斷，不回顯商品參數、query token 或 Authorization。"""
    identifier, _, _, _, _ = stack
    client = TestClient(create_app(make_identification_handler(identifier)), base_url="https://shop.test")
    response = client.get("/api/products/prod-private?token=private-token", headers={"Authorization": "Bearer private-auth"})
    assert response.status_code == 409
    assert response.json()["errors"][0]["code"] == "unsupported_context"
    assert "private-token" not in response.text
    assert "private-auth" not in response.text
    assert "prod-private" not in response.text


def test_b_d_e_h_i_same_request_and_contract_identity(stack):
    """同一請求經 B/D/E/H/I 時持續使用相同契約、商品實體與來源摘要。"""
    identifier, registry, source, directory, output = stack
    build_profile(directory / "source.yaml", output)
    initial_scope = DatasetScope(site_id="shop-test", platform_id="synthetic", platform_version="1.0",
                                 spec_sha256=source["spec_sha256"], scenario_id="product-found", run_id="integration")
    settings = SyntheticConfig(scope=initial_scope, seed=20261108, product_count=2, variants_per_product=1)
    seeded = generate_dataset(settings)
    url = "https://shop.test/api/products/" + seeded.products[0].id
    identified = identifier.identify(url, "GET")
    assert identified.decision == "identified", identified
    identity = identified.identity
    context = ProfileTool(output).get_operation(**identity.profile_arguments())
    original_spec = (directory / "openapi.yaml").read_bytes()
    assert context.specification["paths"]["x-source-note"] == "Synthetic annotation, not an operation"
    scope = DatasetScope(site_id=identity.site_id, platform_id=identity.platform_id,
                         platform_version=identity.platform_version, spec_sha256=identity.spec_sha256,
                         scenario_id="product-found", run_id="integration")
    dataset = generate_dataset(SyntheticConfig(scope=scope, seed=20261108, product_count=2, variants_per_product=1))
    data_tool = SyntheticTool(dataset, expected_scope=scope, profile=context)
    assert data_tool.get_product(identity.path_parameters["id"]).id == seeded.products[0].id
    plan = CompositionPlan(scope=scope, method=identity.method, path=identity.path, status_code=200,
                           body={"product": {"id": "", "title": ""}}, bindings=[
                               DataBinding(source_pointer="/products/0/id", target_pointer="/product/id"),
                               DataBinding(source_pointer="/products/0/title", target_pointer="/product/title")])
    candidate = ResponseComposer(output).compose(plan, dataset=dataset)
    result = verify_candidate(candidate, OfficialResponseGate(registry), url)
    assert result.valid is True and result.decision == "pass", result
    assert result.operation_id == identity.operation_id == context.operation.operation_id
    assert result.spec_sha256 == identity.spec_sha256 == candidate.identity.spec_sha256
    assert (directory / "openapi.yaml").read_bytes() == original_spec


def test_repo_medusa_contract_is_not_approved_by_enabled_binding(tmp_path):
    """實際 Medusa 快照在臨時部署載入；enabled 不能把未審來源變成 approved。"""
    root = Path(__file__).resolve().parents[1]
    source = yaml.safe_load((root / "inputs/sources/medusa/source.yaml").read_bytes())
    raw = (root / "inputs/sources/medusa/openapi.yaml").read_bytes()
    directory = tmp_path / "contracts" / "medusa-test"
    directory.mkdir(parents=True)
    (directory / "openapi.yaml").write_bytes(raw)
    manifest = {key: source[key] for key in ("platform_id", "platform_version", "source_url",
                                            "source_revision", "spec_sha256", "approved", "openapi_file")}
    assert manifest["approved"] is False
    manifest.update(base_urls=["https://shop.example"], query_contexts=[{}])
    (directory / "manifest.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    binding = DeploymentBinding(binding_id="medusa-test", environment_id="test-env", deployment_id="test-deploy",
                                service_id="store", site_id="shop-test", base_url="https://shop.example",
                                platform_id=source["platform_id"], platform_version=source["platform_version"],
                                spec_sha256=source["spec_sha256"], enabled=True)
    identifier = PlatformIdentifier(PlatformRegistry(tmp_path / "contracts"), BindingConfig(bindings=[binding]))
    result = identifier.identify("https://shop.example/store/products/prod-test", "GET")
    assert result.decision == "unverifiable"
    assert result.errors[0].code == "contract_not_approved"
    assert (root / "inputs/sources/medusa/openapi.yaml").read_bytes() == raw


def test_a_b_factory_reads_explicit_server_configuration(stack, tmp_path, monkeypatch):
    """正式 --factory 入口使用伺服器環境變數，不依賴全域預設 registry。"""
    from deception.api.identified import create_app as identified_factory

    identifier, _, _, directory, _ = stack
    config_path = tmp_path / "bindings.yaml"
    config_path.write_text(yaml.safe_dump(identifier.bindings.model_dump(mode="json")), encoding="utf-8")
    monkeypatch.setenv("MIRAGE_PLATFORMS_DIR", str(directory.parent))
    monkeypatch.setenv("MIRAGE_BINDINGS_FILE", str(config_path))
    for name, value in (("MIRAGE_ENVIRONMENT_ID", "test-env"), ("MIRAGE_DEPLOYMENT_ID", "test-deploy"),
                        ("MIRAGE_SERVICE_ID", "store")):
        monkeypatch.setenv(name, value)
    response = TestClient(identified_factory(), base_url="https://shop.test").get("/api/products/test")
    assert response.status_code == 501
    assert response.json()["identification"]["binding_id"] == "test-binding"
    monkeypatch.delenv("MIRAGE_SERVICE_ID")
    with pytest.raises(ValueError, match="All three"):
        identified_factory()


@pytest.mark.parametrize("origin,expected_code,decision", [
    ("https://shop.test", 0, "identified"), ("https://unknown.test", 1, "unverifiable")])
def test_identifier_cli_returns_utf8_json_and_meaningful_exit_code(stack, tmp_path, origin, expected_code, decision):
    """執行真正的 CLI，確認成功／失敗結束碼及 Windows 中文 JSON 都可讀取。"""
    identifier, _, _, directory, _ = stack
    config_path = tmp_path / "bindings.yaml"
    config_path.write_text(yaml.safe_dump(identifier.bindings.model_dump(mode="json")), encoding="utf-8")
    root = Path(__file__).resolve().parents[1]
    environment = dict(os.environ, PYTHONPATH=str(root / "src"))
    result = subprocess.run([sys.executable, "-m", "deception.discovery", "--platforms", str(directory.parent),
                             "--bindings", str(config_path), "--url", origin + "/api/products/test"],
                            cwd=root, env=environment, capture_output=True, text=True, encoding="utf-8")
    assert result.returncode == expected_code, result.stderr
    data = json.loads(result.stdout)
    assert data["decision"] == decision
    if expected_code:
        assert data["errors"][0]["reason"] == "找不到唯一的環境／部署／站點綁定"
