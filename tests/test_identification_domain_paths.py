"""識別工具的預設輸入取自所選領域，明確覆寫仍可獨立使用。"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from deception.api.identified import create_app
from deception.domains.assets import load_domain_assets, resolve_identification_paths
from deception.profile_builder.builder import ProfileError
from test_identifier_integration import stack


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def selected_domain_paths(stack, tmp_path, monkeypatch):
    """建立非電商名稱及非標準子目錄的領域包，讓硬編路徑無法誤通過驗證。"""
    identifier, _, _, source_directory, _ = stack
    domain_root = tmp_path / "domain-packs"
    domain_directory = domain_root / "portal"
    platforms = domain_directory / "service-contracts"
    contract = platforms / "isolated"
    bindings = domain_directory / "settings" / "custom-bindings.yaml"
    for directory in (contract, bindings.parent, domain_directory / "sources",
                      domain_directory / "policies", domain_directory / "security"):
        directory.mkdir(parents=True, exist_ok=True)
    for name in ("manifest.yaml", "openapi.yaml"):
        (contract / name).write_bytes((source_directory / name).read_bytes())
    bindings.write_text(yaml.safe_dump(identifier.bindings.model_dump(mode="json")), encoding="utf-8")
    (domain_directory / "settings" / "demo.yaml").write_text("schema_version: 1\n", encoding="utf-8")
    (domain_directory / "security" / "catalog.yaml").write_text("schema_version: 1\n", encoding="utf-8")
    manifest = {"schema_version": 1, "domain_id": "portal", "title": "測試領域",
                "demo_config": "settings/demo.yaml", "source_dir": "sources",
                "platform_dir": "service-contracts", "bindings_config": "settings/custom-bindings.yaml",
                "policy_dir": "policies", "weakness_catalog": "security/catalog.yaml"}
    (domain_directory / "domain.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    application = tmp_path / "selected-app.yaml"
    application.write_text(yaml.safe_dump({"domain": "portal", "domains_dir": str(domain_root)}), encoding="utf-8")
    for name in ("MIRAGE_DOMAIN", "MIRAGE_DOMAINS_DIR", "MIRAGE_PLATFORMS_DIR", "MIRAGE_BINDINGS_FILE",
                 "MIRAGE_ENVIRONMENT_ID", "MIRAGE_DEPLOYMENT_ID", "MIRAGE_SERVICE_ID"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MIRAGE_APP_CONFIG", str(application))
    return domain_root, platforms, bindings


def test_identification_defaults_are_declared_by_selected_domain(selected_domain_paths):
    """沒有明確覆寫時，平台目錄與部署綁定都採用同一領域 manifest 宣告。"""
    _, platforms, bindings = selected_domain_paths
    assert resolve_identification_paths() == (platforms, bindings)


@pytest.mark.parametrize("override", ["platforms", "bindings"])
def test_one_explicit_path_keeps_other_manifest_default(selected_domain_paths, tmp_path, override):
    """只覆寫一項輸入時，另一項仍由所選領域提供，不回退舊共用資料夾。"""
    _, platforms, bindings = selected_domain_paths
    supplied = tmp_path / "explicit-path"
    if override == "platforms":
        assert resolve_identification_paths(platforms_dir=supplied) == (supplied, bindings)
    else:
        assert resolve_identification_paths(bindings_file=supplied) == (platforms, supplied)


@pytest.mark.parametrize("explicit", [False, True])
def test_identifier_cli_uses_domain_defaults_or_complete_overrides(selected_domain_paths, tmp_path, monkeypatch, explicit):
    """實際 CLI 可讀領域預設；完整覆寫不依賴存在的 app 設定檔。"""
    _, platforms, bindings = selected_domain_paths
    arguments = [sys.executable, "-m", "deception.discovery", "--url", "https://shop.test/api/products/test"]
    if explicit:
        arguments += ["--platforms", str(platforms), "--bindings", str(bindings)]
        monkeypatch.setenv("MIRAGE_APP_CONFIG", str(tmp_path / "missing-app.yaml"))
    result = subprocess.run(arguments, cwd=ROOT, env=dict(os.environ, PYTHONPATH=str(ROOT / "src")),
                            capture_output=True, text=True, encoding="utf-8")
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["decision"] == "identified"
    assert data["identity"]["operation_id"] == "getProduct"
    assert data["identity"]["binding_id"] == "test-binding"


@pytest.mark.parametrize("explicit", [False, True])
def test_identified_factory_uses_same_domain_defaults_or_overrides(selected_domain_paths, tmp_path, monkeypatch, explicit):
    """HTTP 診斷 factory 與 CLI 使用相同設定選擇，完整覆寫不讀 app。"""
    _, platforms, bindings = selected_domain_paths
    if explicit:
        monkeypatch.setenv("MIRAGE_PLATFORMS_DIR", str(platforms))
        monkeypatch.setenv("MIRAGE_BINDINGS_FILE", str(bindings))
        monkeypatch.setenv("MIRAGE_APP_CONFIG", str(tmp_path / "missing-app.yaml"))
    with TestClient(create_app(), base_url="https://shop.test") as client:
        response = client.get("/api/products/test")
    assert response.status_code == 501
    assert response.json()["identification"]["operation_id"] == "getProduct"
    assert response.json()["identification"]["binding_id"] == "test-binding"


def test_manifest_bindings_cannot_escape_selected_domain(selected_domain_paths):
    """新增的綁定資產欄位也必須留在領域包內，不能讀取相鄰主機檔案。"""
    domain_root, _, _ = selected_domain_paths
    path = domain_root / "portal" / "domain.yaml"
    manifest = yaml.safe_load(path.read_bytes())
    manifest["bindings_config"] = "../private-bindings.yaml"
    path.write_text(yaml.safe_dump(manifest), encoding="utf-8")
    (domain_root / "private-bindings.yaml").write_text("bindings: []\n", encoding="utf-8")
    with pytest.raises((ProfileError, ValueError)):
        load_domain_assets("portal", domain_root)
