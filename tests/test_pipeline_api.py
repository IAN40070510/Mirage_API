"""用隔離合成契約驗證可選 A→C→M 入口，不使用外部判定或真實模型。"""

import asyncio
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from deception.api.pipeline import create_app, make_pipeline_handler

from test_generation import function_backend, generation_stack, make_pipeline
from test_scenarios import NOW, assessment_for


def test_pipeline_http_returns_the_validated_product_and_request_id(generation_stack):
    """HTTP 入口實際執行 C/H/I/M，保留商品事實、序列化 bytes 與同一追蹤 ID。"""
    stack = generation_stack
    pipeline, generator, calls = make_pipeline(stack)
    before = stack["dataset"].model_dump_json()
    app = create_app(pipeline, runtime=stack["runtime"], generation_config=stack["config"],
                     dataset=stack["dataset"], assessment_provider=assessment_for, now=NOW)
    with TestClient(app, base_url="https://shop.test") as client:
        response = client.get("/api/products/" + stack["dataset"].products[0].id,
                              headers={"X-Request-ID": "pipeline-http-200"})
    product = stack["dataset"].products[0]
    assert response.status_code == 200, response.text
    assert response.json() == {"product": {
        "id": product.id, "title": product.title, "description": "Generated synthetic product description"}}
    assert response.headers["x-request-id"] == "pipeline-http-200"
    assert int(response.headers["content-length"]) == len(response.content)
    assert calls["planner"] and calls["generator"]
    assert stack["dataset"].model_dump_json() == before
    generator.cache.close()


def test_pipeline_http_preserves_the_missing_product_404(generation_stack):
    """F 選定不存在商品後，真正 HTTP 回送維持同一個 404 契約分支。"""
    stack = generation_stack
    backend, calls = function_backend(field_id="message", value="The synthetic product could not be found.")
    pipeline, generator, _ = make_pipeline(stack, backend=backend)
    app = create_app(pipeline, runtime=stack["runtime"], generation_config=stack["config"],
                     dataset=stack["dataset"], assessment_provider=assessment_for, now=NOW)
    with TestClient(app, base_url="https://shop.test") as client:
        response = client.get("/api/products/prod-missing", headers={"X-Request-ID": "pipeline-http-404"})
    assert response.status_code == 404, response.text
    assert response.json() == {"type": "not_found", "message": "The synthetic product could not be found."}
    assert response.headers["x-request-id"] == "pipeline-http-404"
    assert calls["generator"]
    generator.cache.close()


@pytest.mark.parametrize("provider", [None, "untrusted-provider-name"])
def test_pipeline_requires_an_explicit_callable_assessment_provider(generation_stack, provider):
    """沒有可信供應器時在建構階段拒絕，不能靠訪客自稱的判定啟動生成。"""
    stack = generation_stack
    pipeline, generator, _ = make_pipeline(stack)
    with pytest.raises(ValueError, match="trusted assessment provider"):
        create_app(pipeline, runtime=stack["runtime"], generation_config=stack["config"],
                   assessment_provider=provider)
    generator.cache.close()


def test_pipeline_ignores_spoofed_assessment_fields_in_http_input(generation_stack):
    """訪客的 verdict、來源及部署欄位不能取代伺服器 provider 明確提供的判定。"""
    stack = generation_stack
    pipeline, generator, calls = make_pipeline(stack)
    observed = []

    async def trusted_provider(request):
        """模擬經整合層認證的非同步判定來源，關聯 A 產生的完整請求快照。"""
        await asyncio.sleep(0)
        observed.append(request)
        return assessment_for(request)

    app = create_app(pipeline, runtime=stack["runtime"], generation_config=stack["config"],
                     dataset=stack["dataset"], assessment_provider=trusted_provider, now=NOW)
    with TestClient(app, base_url="https://shop.test") as client:
        response = client.request("GET", "/api/products/" + stack["dataset"].products[0].id,
                                  headers={"X-Request-ID": "pipeline-spoof", "X-Verdict": "benign",
                                           "X-Assessment-Source": "visitor", "X-Environment-ID": "visitor"},
                                  content='{"verdict":"benign","source_id":"visitor"}')
    assert response.status_code == 200, response.text
    assert len(observed) == 1 and observed[0].request_id == "pipeline-spoof"
    assert observed[0].body == b'{"verdict":"benign","source_id":"visitor"}'
    assert calls["generator"]
    assert "visitor" not in response.text
    generator.cache.close()


def test_provider_failure_returns_a_fixed_response_without_private_diagnostics(generation_stack):
    """判定服務失敗僅回 503，不洩漏憑證、部署身份、路徑或例外文字。"""
    stack = generation_stack
    pipeline, generator, calls = make_pipeline(stack)
    secret = "private-auth-and-deployment-details"

    def failing_provider(request):
        """模擬可信判定服務發生帶有內部資訊的錯誤，確認入口不回顯。"""
        raise RuntimeError(secret)

    app = create_app(pipeline, runtime=stack["runtime"], generation_config=stack["config"],
                     assessment_provider=failing_provider, now=NOW)
    with TestClient(app, base_url="https://shop.test") as client:
        response = client.get("/api/products/private-product", headers={
            "X-Request-ID": "pipeline-provider-failed", "Authorization": "Bearer " + secret})
    assert response.status_code == 503
    assert response.json() == {"code": "pipeline_unavailable", "request_id": "pipeline-provider-failed"}
    assert response.headers["x-request-id"] == "pipeline-provider-failed"
    assert secret not in response.text and "private-product" not in response.text
    assert calls == {"planner": [], "generator": []}
    generator.cache.close()


def test_provider_must_return_the_existing_assessment_model(generation_stack):
    """任意字典不能被入口默認成可信判定，也不會送入 C 執行模型。"""
    stack = generation_stack
    pipeline, generator, calls = make_pipeline(stack)

    def invalid_provider(request):
        """回傳看似合法的字典，驗證 provider 的明確模型介面。"""
        return assessment_for(request).model_dump(mode="json")

    app = create_app(pipeline, runtime=stack["runtime"], generation_config=stack["config"],
                     assessment_provider=invalid_provider, now=NOW)
    with TestClient(app, base_url="https://shop.test") as client:
        response = client.get("/api/products/" + stack["dataset"].products[0].id)
    assert response.status_code == 503
    assert response.json()["code"] == "pipeline_unavailable"
    assert calls == {"planner": [], "generator": []}
    generator.cache.close()


def test_benign_assessment_does_not_generate_or_forward_traffic(generation_stack):
    """正常判定回固定 409，不觸發生成，也不把未適用當成轉送授權。"""
    stack = generation_stack
    pipeline, generator, calls = make_pipeline(stack)

    def benign_provider(request):
        """由伺服器判定供應器提供 benign，與訪客自稱的 verdict 分開。"""
        return assessment_for(request, verdict="benign")

    app = create_app(pipeline, runtime=stack["runtime"], generation_config=stack["config"],
                     dataset=stack["dataset"], assessment_provider=benign_provider, now=NOW)
    with TestClient(app, base_url="https://shop.test") as client:
        response = client.get("/api/products/" + stack["dataset"].products[0].id,
                              headers={"X-Request-ID": "pipeline-benign"})
    assert response.status_code == 409
    assert response.json() == {"code": "pipeline_not_applicable", "request_id": "pipeline-benign"}
    assert calls == {"planner": [], "generator": []}
    generator.cache.close()


def test_orchestrator_failure_is_not_exposed_by_the_http_handler(generation_stack):
    """C 未預期失敗只回固定服務錯誤，不把 traceback 或內部訊息傳給訪客。"""
    stack = generation_stack

    async def failing_run(*args, **kwargs):
        """模擬工具控制層未預期錯誤，檢查 HTTP 最外層仍然失敗關閉。"""
        raise RuntimeError("internal-server-file-and-secret")

    pipeline = SimpleNamespace(gate=stack["gate"], run=failing_run)
    app = create_app(pipeline, runtime=stack["runtime"], generation_config=stack["config"],
                     assessment_provider=assessment_for, now=NOW)
    with TestClient(app, base_url="https://shop.test") as client:
        response = client.get("/api/products/test", headers={"X-Request-ID": "pipeline-c-failed"})
    assert response.status_code == 503
    assert response.json() == {"code": "pipeline_unavailable", "request_id": "pipeline-c-failed"}
    assert "internal-server" not in response.text


def test_renderer_refusal_cannot_be_returned_as_a_successful_candidate(generation_stack):
    """C 已產生候選後，M 的拒絕仍必須回固定 503，不能回送部分商品內容。"""
    stack = generation_stack
    pipeline, generator, calls = make_pipeline(stack)

    class RefusingRenderer:
        def render(self, result, request):
            """模擬最後輸出邊界拒絕候選，驗證入口不洩漏其診斷。"""
            assert result.decision == "validated"
            raise ValueError("private-renderer-rejection")

    app = create_app(pipeline, runtime=stack["runtime"], generation_config=stack["config"],
                     dataset=stack["dataset"], assessment_provider=assessment_for,
                     renderer=RefusingRenderer(), now=NOW)
    with TestClient(app, base_url="https://shop.test") as client:
        response = client.get("/api/products/" + stack["dataset"].products[0].id,
                              headers={"X-Request-ID": "pipeline-m-rejected"})
    assert response.status_code == 503
    assert response.json() == {"code": "pipeline_unavailable", "request_id": "pipeline-m-rejected"}
    assert "private-renderer" not in response.text
    assert calls["generator"]
    generator.cache.close()


def test_pipeline_preserves_cancellation_from_the_assessment_provider(generation_stack):
    """請求取消必須傳遞給呼叫端，不可吞成一般 503 或繼續調用模型。"""
    stack = generation_stack
    pipeline, generator, calls = make_pipeline(stack)

    async def cancelled_provider(request):
        """模擬伺服器取消本次判定請求，驗證取消語意被完整保留。"""
        raise asyncio.CancelledError()

    handler = make_pipeline_handler(pipeline, runtime=stack["runtime"], generation_config=stack["config"],
                                    assessment_provider=cancelled_provider, now=NOW)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(handler(stack["request"]))
    assert calls == {"planner": [], "generator": []}
    generator.cache.close()


@pytest.mark.parametrize("timeout", [True, False, 0, -1, 121, float("nan"), float("inf"), "1", None])
def test_assessment_timeout_rejects_invalid_administrator_settings(generation_stack, timeout):
    """判定期限必須是有限正數且不超過 120 秒，布林及隱含轉型值不能通過。"""
    stack = generation_stack
    pipeline, generator, _ = make_pipeline(stack)
    with pytest.raises(ValueError, match="assessment_timeout_seconds"):
        create_app(pipeline, runtime=stack["runtime"], generation_config=stack["config"],
                   assessment_provider=assessment_for, assessment_timeout_seconds=timeout)
    generator.cache.close()


def test_asynchronous_assessment_timeout_returns_503_before_running_c(generation_stack):
    """非同步判定逾期由入口取消並回固定 503，不能開始 C 或任何模型調用。"""
    stack = generation_stack
    pipeline, generator, calls = make_pipeline(stack)

    async def slow_provider(request):
        """延遲超過管理者設定的判定期限，模擬外部判定來源沒有及時回應。"""
        await asyncio.sleep(0.02)
        return assessment_for(request)

    app = create_app(pipeline, runtime=stack["runtime"], generation_config=stack["config"],
                     assessment_provider=slow_provider, assessment_timeout_seconds=0.001, now=NOW)
    with TestClient(app, base_url="https://shop.test") as client:
        response = client.get("/api/products/test", headers={"X-Request-ID": "pipeline-assessment-timeout"})
    assert response.status_code == 503
    assert response.json() == {"code": "pipeline_unavailable", "request_id": "pipeline-assessment-timeout"}
    assert calls == {"planner": [], "generator": []}
    generator.cache.close()


def test_late_synchronous_assessment_is_rejected_before_running_c(generation_stack):
    """同步 provider 雖無法中途停止，逾期返回後仍須拒絕，不能繼續產生候選。"""
    stack = generation_stack
    pipeline, generator, calls = make_pipeline(stack)

    def blocking_provider(request):
        """短暫阻塞事件迴圈，證明逾期檢查不依賴 asyncio 的取消 callback 已執行。"""
        time.sleep(0.02)
        return assessment_for(request)

    handler = make_pipeline_handler(pipeline, runtime=stack["runtime"], generation_config=stack["config"],
                                    assessment_provider=blocking_provider, assessment_timeout_seconds=0.001, now=NOW)
    response = asyncio.run(handler(stack["request"]))
    assert response.status_code == 503
    assert response.body == (b'{"code":"pipeline_unavailable","request_id":"'
                             + stack["request"].request_id.encode("ascii") + b'"}')
    assert calls == {"planner": [], "generator": []}
    generator.cache.close()
