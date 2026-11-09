"""弱點回應固定值與 OWASP 版次資料的獨立契約驗證。"""

import copy
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from deception.api.demo import create_app
from deception.domains.ecommerce.generation_demo import _specification
from deception.domains.ecommerce.http_demo import DemoConfig
from deception.domains.ecommerce.weaknesses import configure_specification
from deception.profile_builder.builder import read_yaml
from deception.security import SecurityTaxonomy, load_catalog
from mirage_validator.gate import GateRequest, OfficialResponseGate, PlatformRegistry

ROOT = Path(__file__).resolve().parents[1]
TAXONOMIES = ROOT / "inputs/security_taxonomies"
CATALOG = ROOT / "domains/ecommerce/security/owasp-scenarios.yaml"


def response_and_gate(tmp_path, scenario_id, status):
    """先取得真正 HTTP 候選，再獨立載入同一合成契約，避免重用先前的 gate pass。"""
    config = DemoConfig(weakness_scenario=scenario_id)
    with TestClient(create_app(config, output_root=tmp_path), base_url=config.origin) as client:
        info = client.get("/demo/info").json()
        identifier = info["product_ids"][0] if status == 200 else "missing-security-contract"
        path = "/api/products/" + identifier
        response = client.get(path)
        assert response.status_code == status, response.text
    run_root = next(tmp_path.iterdir())
    gate = OfficialResponseGate(PlatformRegistry(run_root / "contracts"))
    request = GateRequest(request_url=config.origin + path, request_method="GET", status_code=status,
                          headers=dict(response.headers), body=response.text)
    assert gate.validate(request).decision == "pass"
    return request, gate


@pytest.mark.parametrize("status", [200, 404])
@pytest.mark.parametrize("tampering", ["wrong-value", "missing"])
def test_debug_header_value_and_presence_are_enforced_by_contract(tmp_path, status, tampering):
    """除錯版本在成功與不存在分支均須符合固定值，刪除或修改後由真正契約驗證器拒絕。"""
    request, gate = response_and_gate(tmp_path, "api8-debug-header-disclosure", status)
    headers = dict(request.headers)
    if tampering == "missing":
        del headers["x-legacy-store-version"]
    else:
        headers["x-legacy-store-version"] = "tampered-version"
    result = gate.validate(request.model_copy(update={"headers": headers}))
    assert result.decision == "reject" and result.valid is False, result
    assert result.errors


@pytest.mark.parametrize("tampering", ["wrong-value", "missing"])
def test_internal_note_fixed_value_is_enforced_by_contract(tmp_path, tampering):
    """內部註記除了受生成政策保護，獨立契約驗證亦拒絕修改或刪除。"""
    request, gate = response_and_gate(tmp_path, "api3-internal-product-properties", 200)
    body = json.loads(request.body)
    if tampering == "missing":
        del body["product"]["internal_note"]
    else:
        body["product"]["internal_note"] = "A different but otherwise valid string"
    result = gate.validate(request.model_copy(update={"body": json.dumps(body)}))
    assert result.decision == "reject" and result.valid is False, result
    assert result.errors


@pytest.mark.parametrize("taxonomy", ["owasp-api-security-2023", "owasp-web-2025"])
def test_known_taxonomy_rejects_mismatched_edition(taxonomy):
    """榜單識別內的年份與 edition 不同時拒絕載入，不把版本當成純顯示文字。"""
    value = read_yaml((TAXONOMIES / (taxonomy + ".yaml")).read_bytes())
    value["edition"] = "2019"
    with pytest.raises(ValidationError, match="edition"):
        SecurityTaxonomy.model_validate(value)


@pytest.mark.parametrize("taxonomy", ["owasp-api-security-2023", "owasp-web-2025"])
@pytest.mark.parametrize("tampering", ["wrong-year", "wrong-family", "missing-category"])
def test_known_taxonomy_requires_its_exact_ten_versioned_ids(taxonomy, tampering):
    """已知榜單不能混入另一年份或 API／Web 分類，也不能少一項而冒充完整十項。"""
    value = read_yaml((TAXONOMIES / (taxonomy + ".yaml")).read_bytes())
    if tampering == "wrong-year":
        value["categories"][0]["category_id"] = value["categories"][0]["category_id"].split(":")[0] + ":2019"
    elif tampering == "wrong-family":
        value["categories"][0]["category_id"] = "A01:2023" if "api-security" in taxonomy else "API1:2025"
    else:
        value["categories"].pop()
    with pytest.raises(ValidationError, match="exact ten"):
        SecurityTaxonomy.model_validate(value)


def test_custom_taxonomy_can_use_its_own_version_and_category_format():
    """非已知 OWASP 榜單保留自訂分類與版本格式，不被電商或 OWASP 十項限制綁死。"""
    model = SecurityTaxonomy(taxonomy_id="custom-service-risks", title="Custom risk taxonomy", edition="release-1",
                             source_url="https://example.invalid/taxonomy", license="test-only",
                             categories=[{"category_id": "customer-isolation", "title_en": "Customer isolation",
                                          "title_zh": "客戶隔離", "url": "https://example.invalid/taxonomy/customer-isolation"}])
    assert model.categories[0].category_id == "customer-isolation"


@pytest.mark.parametrize("scenario_id", ["api3-internal-product-properties", "api8-debug-header-disclosure"])
def test_weakness_parameters_are_checked_before_specification_mutation(scenario_id):
    """額外弱點參數在任何 schema 變更前被拒絕，避免半套來源規格被留下。"""
    scenario = load_catalog(CATALOG, domain="ecommerce", taxonomy_root=TAXONOMIES).select(scenario_id)
    parameters = {**scenario.parameters, "unexpected": "ignored-value"}
    specification = _specification()
    original = copy.deepcopy(specification)
    with pytest.raises(ValidationError):
        configure_specification(specification, scenario.model_copy(update={"parameters": parameters}))
    assert specification == original
