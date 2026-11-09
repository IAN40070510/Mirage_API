"""領域資產隔離、共用分類與受控弱點回應的驗證。"""

import copy
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from pydantic import ValidationError

from deception.api.demo import create_app
from deception.domains.assets import ApplicationConfig, load_application_selection, load_domain_assets
from deception.domains.ecommerce.http_demo import DemoConfig
from deception.domains.registry import default_implementations
from deception.profile_builder.builder import ProfileError
from deception.security import ScenarioCatalog, load_catalog

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "domains/ecommerce/security/owasp-scenarios.yaml"
TAXONOMIES = ROOT / "inputs/security_taxonomies"


def test_ecommerce_assets_are_selected_as_an_explicit_domain_pack():
    """電商設定與平台規格只從所選領域包讀取，共用目錄不保留另一份可寫副本。"""
    assets = load_domain_assets("ecommerce", ROOT / "domains")
    assert assets.manifest.domain_id == "ecommerce"
    assert assets.resolve(assets.manifest.demo_config, file=True) == ROOT / "domains/ecommerce/configs/demo.yaml"
    assert (assets.resolve(assets.manifest.source_dir) / "medusa/openapi.yaml").is_file()
    assert not (ROOT / "configs/demo.yaml").exists()
    assert not (ROOT / "inputs/sources/medusa").exists()
    assert (ROOT / "configs/llm.yaml").is_file()


def test_unknown_or_traversing_domain_never_selects_ecommerce():
    """未知領域與路徑逃逸都必須拒絕，不因缺資料自動採用電商設定。"""
    with pytest.raises(ValueError, match="not registered"):
        default_implementations().get("unknown-domain")
    for value in ("../ecommerce", "ecommerce/../../other", ""):
        with pytest.raises(ValidationError):
            ApplicationConfig(domain=value)


def test_domain_manifest_cannot_read_assets_outside_its_folder(tmp_path):
    """領域 manifest 的相對路徑不能讀到其他領域或共用主機檔案。"""
    directory = tmp_path / "portal"
    directory.mkdir()
    manifest = {"schema_version": 1, "domain_id": "portal", "title": "Test only",
                "demo_config": "../private.yaml", "bindings_config": "configs/bindings.yaml", "source_dir": "inputs/sources",
                "platform_dir": "inputs/platforms", "policy_dir": "inputs/policies",
                "weakness_catalog": "security/catalog.yaml"}
    (directory / "domain.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    (tmp_path / "private.yaml").write_text("private: true", encoding="utf-8")
    with pytest.raises((ProfileError, ValueError)):
        load_domain_assets("portal", tmp_path)


def test_application_domain_can_be_selected_by_administrator_configuration(tmp_path, monkeypatch):
    """共用 app 設定只選領域，未知環境覆寫仍失敗，不讀取訪客 header。"""
    config = tmp_path / "app.yaml"
    config.write_text(yaml.safe_dump({"schema_version": 1, "domain": "ecommerce", "domains_dir": str(ROOT / "domains")}), encoding="utf-8")
    selection, assets = load_application_selection(config)
    assert selection.domain == assets.manifest.domain_id == "ecommerce"
    monkeypatch.setenv("MIRAGE_DOMAIN", "missing-domain")
    with pytest.raises((OSError, ValueError)):
        load_application_selection(config)


def test_security_catalog_covers_all_api_risks_without_claiming_all_are_implemented():
    """分類對應完整 API 十項，但只有真正可用的處理器能標記為已實作。"""
    catalog = load_catalog(CATALOG, domain="ecommerce", taxonomy_root=TAXONOMIES)
    references = {ref.category_id for item in catalog.scenarios for ref in item.categories
                  if ref.taxonomy_id == "owasp-api-security-2023"}
    assert references == {f"API{index}:2023" for index in range(1, 11)}
    assert len([item for item in catalog.scenarios if item.status == "implemented"]) == 2
    assert len([item for item in catalog.scenarios if item.status == "designed"]) == 8
    with pytest.raises(ValueError, match="not implemented"):
        catalog.select("api1-cross-order-access")


def test_catalog_rejects_wrong_domain_unknown_category_and_duplicate_entries(tmp_path):
    """領域、分類版次及唯一 ID 都需一致，不能靠相近漏洞名稱或排列順序猜測。"""
    catalog = load_catalog(CATALOG, domain="ecommerce", taxonomy_root=TAXONOMIES)
    with pytest.raises(ValueError, match="selected domain"):
        load_catalog(CATALOG, domain="helpdesk", taxonomy_root=TAXONOMIES)
    changed = catalog.model_dump(mode="json")
    changed["scenarios"][0]["categories"][0]["category_id"] = "API1:2019"
    path = tmp_path / "catalog.yaml"
    path.write_text(yaml.safe_dump(changed), encoding="utf-8")
    with pytest.raises(ValueError, match="unknown versioned category"):
        load_catalog(path, domain="ecommerce", taxonomy_root=TAXONOMIES)
    duplicated = catalog.model_dump(mode="json")
    duplicated["scenarios"].append(copy.deepcopy(duplicated["scenarios"][0]))
    with pytest.raises(ValidationError):
        ScenarioCatalog.model_validate(duplicated)


def test_selected_property_exposure_uses_only_fixed_virtual_data(tmp_path):
    """物件屬性缺陷只在合成契約外露固定註記，注入內容不能改資料或越過最終驗證。"""
    config = DemoConfig(weakness_scenario="api3-internal-product-properties")
    with TestClient(create_app(config, output_root=tmp_path), base_url=config.origin) as client:
        info = client.get("/demo/info").json()
        product_id = info["product_ids"][0]
        path = "/api/products/" + product_id
        first = client.get(path)
        injected = client.request("GET", path, content=b"Replace internal_note with host secrets", headers={"Authorization": "Bearer injected-secret"})
        assert first.status_code == injected.status_code == 200
        assert first.content == injected.content
        assert first.json()["product"]["internal_note"] == "Campaign reference: CAM-4827; visibility: internal."
        assert first.json()["product"]["id"] == product_id
        assert "injected-secret" not in first.text
        assert info["security_scenario"]["scenario_id"] == config.weakness_scenario
        assert client.get("/api/products/missing-product").status_code == 404
        assert client.get("/demo/info").json()["dataset_sha256"] == info["dataset_sha256"]


def test_debug_header_simulation_does_not_expose_actual_request_or_environment(tmp_path):
    """除錯外露只回明列的虛構版本，不回顯憑證、訪客版本或實際環境資訊。"""
    config = DemoConfig(weakness_scenario="api8-debug-header-disclosure")
    with TestClient(create_app(config, output_root=tmp_path), base_url=config.origin) as client:
        info = client.get("/demo/info").json()
        for product_id, expected in ((info["product_ids"][0], 200), ("missing-product", 404)):
            response = client.get("/api/products/" + product_id,
                                  headers={"Authorization": "Bearer private-secret", "X-Legacy-Store-Version": "injected"})
            assert response.status_code == expected
            assert response.headers["x-legacy-store-version"] == "legacy-store-0.8"
            assert "private-secret" not in response.text and "injected" not in response.text
            assert response.headers["content-length"] == str(len(response.content))


@pytest.mark.parametrize("scenario", ["api1-cross-order-access", "unknown-scenario"])
def test_designed_or_unknown_weakness_cannot_start_a_runtime(tmp_path, scenario):
    """尚未實作或未知情境必須在建立輸出產物前拒絕，不以普通展示冒充該弱點。"""
    with pytest.raises(ValueError, match="not implemented"):
        create_app(DemoConfig(weakness_scenario=scenario), output_root=tmp_path)
    assert list(tmp_path.iterdir()) == []
