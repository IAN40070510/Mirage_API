"""隔離展示的可部署入口、固定資料、設定與生命週期驗證。"""

import json
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from deception.api.demo import DemoConfig, create_app, load_demo_config


def test_demo_serves_consistent_fallback_and_records_its_true_source(tmp_path):
    """沒有模型時仍經完整契約驗證輸出固定內容，並明確標示備援而非模型生成。"""
    app = create_app(DemoConfig(), output_root=tmp_path)
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        health = client.get("/healthz")
        assert health.json() == {"status": "ok", "test_only": True, "mode": "fallback"}
        info = client.get("/demo/info").json()
        assert info["test_only"] is True and info["transactions_supported"] is False
        first_id = info["product_ids"][0]
        first = client.get("/api/products/" + first_id, headers={"X-Request-ID": "demo-first"})
        missing = client.get("/api/products/prod-missing", headers={"X-Request-ID": "demo-missing"})
        repeated = client.get("/api/products/" + first_id, headers={"X-Request-ID": "demo-repeated"})
        assert [first.status_code, missing.status_code, repeated.status_code] == [200, 404, 200]
        assert missing.json()["type"] == "not_found"
        assert "prod-missing" in missing.json()["message"]
        assert first.content == repeated.content
        assert first.json()["product"]["id"] == first_id
        assert first.json()["product"]["title"] == info["products"][0]["title"]
        assert first.headers["content-length"] == str(len(first.content))
        after = client.get("/demo/info").json()
        assert after["dataset_sha256"] == info["dataset_sha256"]
        assert [entry["generation_source"] for entry in after["recent_results"]] == ["fallback"] * 3
        assert all(entry["model"]["provider"] == "not_used" for entry in after["recent_results"])
    datasets = list(tmp_path.glob("*/dataset.json"))
    assert len(datasets) == 1
    assert json.loads(datasets[0].read_text(encoding="utf-8"))["products"][0]["id"] == first_id


def test_demo_missing_id_is_encoded_before_authoritative_404_echo(tmp_path):
    """404 綁定當次商品 ID，但將攻擊樣式輸入 URL encode，避免回應內容成為可執行回顯。"""
    product_id = "1' OR '1'='1"
    with TestClient(create_app(DemoConfig(), output_root=tmp_path), base_url="http://127.0.0.1:8000") as client:
        response = client.get("/api/products/" + quote(product_id, safe=""),
                              headers={"X-Request-ID": "demo-encoded-missing"})
    assert response.status_code == 404
    assert response.json()["type"] == "not_found"
    assert quote(product_id, safe="") in response.json()["message"]
    assert product_id not in response.text


def test_demo_seed_and_scope_reproduce_product_identity_after_restart(tmp_path):
    """相同設定重啟使用同一虛構實體；實體身份不依輸出資料夾的隨機名稱改變。"""
    identities = []
    for _ in range(2):
        with TestClient(create_app(DemoConfig(), output_root=tmp_path), base_url="http://127.0.0.1:8000") as client:
            info = client.get("/demo/info").json()
            identities.append((info["product_ids"], info["products"], info["dataset_sha256"]))
    assert identities[0] == identities[1]


@pytest.mark.parametrize("origin", ["http://127.0.0.1:8000/path", "http://127.0.0.1:8000?x=1",
                                    "http://user:password@localhost:8000", "ftp://127.0.0.1:8000",
                                    "http://127.0.0.1:8000#fragment"])
def test_demo_rejects_ambiguous_or_credential_bearing_origin(origin):
    """管理者 origin 必須完整且無歧義，不能藏入憑證、路徑或查詢條件。"""
    with pytest.raises((ValueError, ValidationError)):
        DemoConfig(origin=origin)


def test_demo_loads_only_explicit_environment_overrides(tmp_path, monkeypatch):
    """展示設定只接受管理者環境覆寫；未知欄位與其他業務領域不自動啟用。"""
    path = tmp_path / "demo.yaml"
    path.write_text("schema_version: 1\ndomain: ecommerce\nmode: fallback\n", encoding="utf-8")
    monkeypatch.setenv("MIRAGE_DEMO_ORIGIN", "http://localhost:8900")
    checked = load_demo_config(path)
    assert checked.origin == "http://localhost:8900" and checked.mode == "fallback"
    path.write_text("domain: ecommerce\nunknown: true\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_demo_config(path)
    with pytest.raises(ValidationError):
        DemoConfig(domain="unimplemented-domain")


def test_demo_rejects_unknown_writes_without_creating_transaction_state(tmp_path):
    """購買與扣款尚未提供，因此寫入明確失敗，前後商品資料保持一致。"""
    with TestClient(create_app(DemoConfig(), output_root=tmp_path), base_url="http://127.0.0.1:8000") as client:
        before = client.get("/demo/info").json()
        for path in ("/api/orders", "/api/wallet/withdraw", "/api/products/" + before["product_ids"][0]):
            response = client.post(path, json={"amount": -100, "price": 0, "admin": True})
            assert response.status_code == 503 and response.json()["code"] == "pipeline_unavailable"
        assert before["dataset_sha256"] == client.get("/demo/info").json()["dataset_sha256"]
