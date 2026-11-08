"""HTTP 驗證工具的目標限制與完整案例報告，透過真實應用程式驗證而非固定答案。"""

import pytest
from fastapi.testclient import TestClient

from deception.api.demo import DemoConfig, create_app
from tools import verify_ecommerce_api as verification


@pytest.mark.parametrize("target", ["https://127.0.0.1:8000", "http://shop.example", "http://0.0.0.0:8000",
                                    "http://user:password@localhost:8000", "http://localhost:8000/path",
                                    "http://localhost:8000?url=http://external.invalid", "http://localhost:8000#fragment"])
def test_verification_refuses_external_or_ambiguous_targets(target):
    """攻擊特徵請求只能送往明確 loopback 展示，不因設定錯誤打到外部商店。"""
    with pytest.raises(ValueError):
        verification.checked_origin(target)


@pytest.mark.parametrize("published_port", [8000, 8001])
def test_verification_report_checks_all_cases_against_real_application(tmp_path, monkeypatch, published_port):
    """完整測試矩陣跑真實應用程式，並驗證容器內連線埠與綁定 Host 不同的情況。"""
    config = DemoConfig(origin=f"http://127.0.0.1:{published_port}")
    with TestClient(create_app(config, output_root=tmp_path), base_url="http://127.0.0.1:8000") as client:
        def through_application(opener, base_url, path, *, method="GET", headers=None, body=None, timeout=60):
            """將 HTTP 封套交給真正 ASGI app，保留狀態、bytes、headers 與 JSON。"""
            response = client.request(method, path, headers=headers, content=body)
            return {"status": response.status_code, "headers": dict(response.headers),
                    "body": response.content, "json": response.json()}

        monkeypatch.setattr(verification, "request_json", through_application)
        report = verification.verify("http://127.0.0.1:8000", host_header=f"127.0.0.1:{published_port}")
    assert report["success"] is True, report
    assert report["request_count"] == 16
    assert all(item["passed"] for item in report["cases"])
    assert all(report["logical_consistency"].values())
    assert report["real_model_requests"] == 0
    assert report["configured_mode"] == "fallback"
    assert any(item["generation_source"] == "fallback" for item in report["observations"])


def test_verification_refuses_unmarked_services_before_attack_cases(monkeypatch):
    """沒有明示 test_only 的本機服務也不能被當成隔離商店測試目標。"""
    paths = []

    def production_info(opener, base_url, path, **kwargs):
        """模擬一般本機服務，確認工具只做前提讀取而不送攻擊案例。"""
        paths.append(path)
        return {"status": 200, "json": {"domain": "ecommerce", "test_only": False}}

    monkeypatch.setattr(verification, "request_json", production_info)
    with pytest.raises(ValueError, match="isolated"):
        verification.verify("http://127.0.0.1:8000")
    assert paths == ["/demo/info"]
