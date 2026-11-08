"""M 的傳輸封套測試：最終 headers、bytes 及原請求必須重新通過真實 I。"""

import asyncio
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from starlette.background import BackgroundTask

from deception.api.app import create_app
from deception.api.ingress import NormalizedRequest
from deception.core.handoff import verify_candidate
from deception.core.orchestrator import PipelineResult
from deception.core.renderer import RenderingError, ResponseRenderer
import deception.core.renderer as renderer_module
from deception.generation.models import digest
from deception.scenarios import fingerprint_request

from test_candidate_handoff import candidate_and_gate


def render_request(**changes):
    """建立與測試契約同站點的請求快照，可替換單一欄位驗證隔離。"""
    path = "/products/synthetic-product"
    request = NormalizedRequest(request_id="renderer-test", method="GET", raw_url="https://shop.test" + path,
                                path=path, raw_path=path.encode("ascii"), query_string=b"", query=(),
                                headers=(("host", "shop.test"),), body=b"")
    return replace(request, **changes)


def pipeline_result(candidate, gate, request):
    """以真實 I 建立 C 格式結果，記錄原請求指紋與候選完整摘要。"""
    return PipelineResult(decision="validated", candidate=candidate,
                          gate_result=verify_candidate(candidate, gate, request.raw_url),
                          trace={"request_id": request.request_id, "request_fingerprint": fingerprint_request(request),
                                 "candidate_sha256": digest(candidate.to_dict()),
                                 "release_deadline_monotonic": time.monotonic() + 60})


def emit_response(response, request, **scope_changes):
    """收集 Response 的真實 ASGI 訊息，失敗時保留空訊息以確認尚未開始回應。"""
    messages = []
    scope = {"type": "http", "method": request.method, "scheme": "https", "path": request.path,
             "raw_path": request.raw_path, "query_string": request.query_string,
             "headers": [(key.encode("latin-1"), value.encode("latin-1")) for key, value in request.headers],
             "server": ("shop.test", 443)}
    scope.update(scope_changes)

    async def receive():
        """提供已收完的空請求訊息，renderer 不需再讀取 body。"""
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        """保存渲染器原樣發出的 ASGI start 或 body 訊息。"""
        messages.append(message)

    asyncio.run(response(scope, receive, send))
    return messages


def test_final_transport_headers_and_utf8_bytes_are_revalidated(candidate_and_gate):
    """中文 bytes 長度與追蹤 ID 必須先加入最終封套，再經真正 I 通過。"""
    candidate, gate = candidate_and_gate
    candidate = replace(candidate, body='{"id":"中文測試商品"}')
    request = render_request()
    result = pipeline_result(candidate, gate, request)

    class RecordingGate:
        """保留最後收到的 GateRequest，以比對實際傳輸內容。"""

        def validate(self, value):
            """記錄最終封套並委派真實 OpenAPI gate，不改變判定。"""
            self.last = value
            return gate.validate(value)

    recording = RecordingGate()
    response = ResponseRenderer(recording).render(result, request)
    messages = emit_response(response, request)
    assert messages[0]["status"] == candidate.status_code
    assert messages[1]["body"] == candidate.body_bytes
    sent_headers = {key.decode("latin-1"): value.decode("latin-1") for key, value in messages[0]["headers"]}
    assert sent_headers == recording.last.headers
    assert sent_headers["content-length"] == str(len(candidate.body_bytes))
    assert int(sent_headers["content-length"]) > len(candidate.body)
    assert sent_headers["x-request-id"] == request.request_id
    assert recording.last.body == candidate.body
    assert response.gate_result.valid is True
    assert candidate.headers == result.candidate.headers


@pytest.mark.parametrize("decision", ["not_applicable", "unverifiable", "reject"])
def test_unvalidated_pipeline_results_cannot_be_rendered(candidate_and_gate, decision):
    """即使殘留候選與舊 gate pass，非 validated 的 C 結果也不得送出。"""
    candidate, gate = candidate_and_gate
    request = render_request()
    result = pipeline_result(candidate, gate, request).model_copy(update={"decision": decision})
    with pytest.raises(RenderingError, match="pipeline_not_validated"):
        ResponseRenderer(gate).render(result, request)


@pytest.mark.parametrize("changes", [{"request_id": "another-request"}, {"body": b"different"},
                                      {"raw_url": "https://unknown.test/products/synthetic-product"}])
def test_pipeline_result_is_bound_to_entire_request(candidate_and_gate, changes):
    """相同商品的其他請求、body 或 URL 不可借用先前結果取得 M 回應。"""
    candidate, gate = candidate_and_gate
    request = render_request()
    result = pipeline_result(candidate, gate, request)
    with pytest.raises(RenderingError, match="render_request_mismatch"):
        ResponseRenderer(gate).render(result, replace(request, **changes))


def test_candidate_cannot_change_after_pipeline_validation(candidate_and_gate):
    """候選被換成另一合法 body 時，原 C 摘要也必須失效。"""
    candidate, gate = candidate_and_gate
    request = render_request()
    result = pipeline_result(candidate, gate, request)
    result.candidate = replace(candidate, body='{"id":"another-product"}')
    with pytest.raises(RenderingError, match="render_request_mismatch"):
        ResponseRenderer(gate).render(result, request)


def test_gate_is_called_again_instead_of_trusting_old_pass(candidate_and_gate):
    """I 的最終拒絕不能由 C 保存的舊 pass 取代。"""
    candidate, gate = candidate_and_gate
    request = render_request()
    result = pipeline_result(candidate, gate, request)

    class RejectingGate:
        """模擬候選之後無法通過最終部署核對的 gate。"""

        def validate(self, value):
            """保留同契約身份，明確拒絕此次最終傳輸封套。"""
            return gate.validate(value).model_copy(update={"valid": False, "decision": "reject"})

    with pytest.raises(RenderingError, match="final_gate_not_passed"):
        ResponseRenderer(RejectingGate()).render(result, request)


def test_final_gate_identity_must_match_candidate(candidate_and_gate):
    """即使 gate 回 pass，也不可使用其他操作的回應驗證結果。"""
    candidate, gate = candidate_and_gate
    request = render_request()
    result = pipeline_result(candidate, gate, request)

    class WrongIdentityGate:
        """模擬回傳不同 operation 的表面成功結果。"""

        def validate(self, value):
            """替換操作身份，確認 M 仍透過 verify_candidate 拒絕。"""
            return gate.validate(value).model_copy(update={"operation_id": "otherOperation"})

    with pytest.raises(RenderingError, match="final_gate_not_passed"):
        ResponseRenderer(WrongIdentityGate()).render(result, request)


@pytest.mark.parametrize("extra", [
    (("Connection", "close"),), (("Transfer-Encoding", "chunked"),), (("Content-Encoding", "gzip"),),
    (("Content-Type", "application/json"),), (("Bad Header", "value"),), (("x-demo", "bad\r\nvalue"),),
    (("x-demo", "中文"),), (("Content-Length", "1"),), (("X-Request-ID", "different-request"),),
])
def test_unsupported_or_inconsistent_headers_cannot_be_sent(candidate_and_gate, extra):
    """拒絕重複、注入、編碼、hop-by-hop、長度或追蹤 ID 不一致的標頭。"""
    candidate, gate = candidate_and_gate
    request = render_request()
    result = pipeline_result(candidate, gate, request)
    result.candidate = replace(candidate, headers=candidate.headers + extra)
    result.trace["candidate_sha256"] = digest(result.candidate.to_dict())
    with pytest.raises(RenderingError):
        ResponseRenderer(gate).render(result, request)


@pytest.mark.parametrize("mutation", ["body", "headers", "status", "background"])
def test_response_mutation_is_rejected_before_asgi_start(candidate_and_gate, mutation):
    """框架內任何傳輸欄位改動或背景工作，都在發出 start 之前停止。"""
    candidate, gate = candidate_and_gate
    request = render_request()
    response = ResponseRenderer(gate).render(pipeline_result(candidate, gate, request), request)
    if mutation == "body":
        response.body = b"changed"
    elif mutation == "headers":
        response.headers["x-changed"] = "changed"
    elif mutation == "status":
        response.status_code = 201
    else:
        response.background = BackgroundTask(print, "must not run")
    with pytest.raises(RenderingError, match="validated_response_changed"):
        emit_response(response, request)


@pytest.mark.parametrize("changes", [{"scheme": "http"}, {"path": "/other/synthetic-product"},
                                      {"method": "HEAD"}])
def test_asgi_scope_must_match_bound_request(candidate_and_gate, changes):
    """即使外層誤用同一 Response，其他路徑、協定或方法也不能取得封套。"""
    candidate, gate = candidate_and_gate
    request = render_request()
    response = ResponseRenderer(gate).render(pipeline_result(candidate, gate, request), request)
    with pytest.raises(RenderingError, match="render_request_mismatch"):
        emit_response(response, request, **changes)


@pytest.mark.parametrize("method,status", [("HEAD", 200), ("GET", 204), ("GET", 205), ("GET", 304)])
def test_unimplemented_bodyless_semantics_are_rejected(candidate_and_gate, method, status):
    """尚未支援的 HEAD 與無 body 狀態不可透過一般 JSON renderer 送出。"""
    candidate, gate = candidate_and_gate
    request = render_request(method=method)
    base = pipeline_result(candidate, gate, render_request())
    candidate = replace(candidate, identity=replace(candidate.identity, method=method), status_code=status)
    base.candidate = candidate
    base.trace = {"request_id": request.request_id, "request_fingerprint": fingerprint_request(request),
                  "candidate_sha256": digest(candidate.to_dict()),
                  "release_deadline_monotonic": time.monotonic() + 60}
    with pytest.raises(RenderingError, match="unsupported_http_response"):
        ResponseRenderer(gate).render(base, request)


def test_fastapi_ingress_sends_exact_final_candidate(candidate_and_gate):
    """真實 FastAPI／TestClient 串接 A/M，最終 body 與 headers 對齊 M 驗證封套。"""
    candidate, gate = candidate_and_gate
    renderer = ResponseRenderer(gate)
    emitted = []

    async def handler(request):
        """依 A 的實際快照建置受信任結果，交由 M 完成最後驗證。"""
        response = renderer.render(pipeline_result(candidate, gate, request), request)
        emitted.append(response)
        return response

    with TestClient(create_app(handler), base_url="https://shop.test") as client:
        response = client.get("/products/synthetic-product", headers={"X-Request-ID": "renderer-http"})
    assert response.status_code == 200
    assert response.content == emitted[0].candidate.body_bytes
    assert tuple(response.headers.multi_items()) == emitted[0].candidate.headers
    assert response.headers["x-request-id"] == "renderer-http"


def test_ingress_cannot_reuse_sealed_response_for_another_request(candidate_and_gate):
    """A 在 handler 返回時再次核對指紋，阻止同一 Response 物件跨請求重用。"""
    candidate, gate = candidate_and_gate
    stored = []

    async def handler(request):
        """故意快取整個 Response，確認第二個請求會被 A/M 阻擋。"""
        if not stored:
            stored.append(ResponseRenderer(gate).render(pipeline_result(candidate, gate, request), request))
        return stored[0]

    with TestClient(create_app(handler), base_url="https://shop.test") as client:
        assert client.get("/products/synthetic-product", headers={"X-Request-ID": "first-request"}).status_code == 200
        with pytest.raises(RenderingError, match="render_request_mismatch"):
            client.get("/products/synthetic-product", headers={"X-Request-ID": "second-request"})


@pytest.mark.parametrize("deadline", [None, True, "future", -1, 0, float("nan"), float("inf"), float("-inf")])
def test_invalid_or_missing_release_deadline_is_rejected(candidate_and_gate, deadline):
    """缺漏、布林、非數值或非有限同程序期限不得繞過 C/F 的時效限制。"""
    candidate, gate = candidate_and_gate
    request = render_request()
    result = pipeline_result(candidate, gate, request)
    result.trace["release_deadline_monotonic"] = deadline
    with pytest.raises(RenderingError, match="render_deadline_exceeded"):
        ResponseRenderer(gate).render(result, request)


def test_expired_release_deadline_is_rejected_before_final_gate(candidate_and_gate):
    """C/F 已逾期的內部候選不能因 M 重新驗證契約而恢復有效。"""
    candidate, gate = candidate_and_gate
    request = render_request()
    result = pipeline_result(candidate, gate, request)
    result.trace["release_deadline_monotonic"] = time.monotonic() - 1
    with pytest.raises(RenderingError, match="render_deadline_exceeded"):
        ResponseRenderer(gate).render(result, request)


def test_final_gate_cannot_outlive_release_deadline(candidate_and_gate, monkeypatch):
    """I 在 M 最終核對時超過期限，即使回 pass 也不能建立可送出回應。"""
    candidate, gate = candidate_and_gate
    request = render_request()
    result = pipeline_result(candidate, gate, request)
    deadline = result.trace["release_deadline_monotonic"]
    clock = {"now": deadline - 1}

    def current_time():
        """提供只影響 renderer 的可控單調時鐘，不修改 asyncio 的時鐘。"""
        return clock["now"]

    class ExpiringGate:
        """模擬契約驗證工作耗盡剩餘釋出期限。"""

        def validate(self, value):
            """執行真正驗證後推進時鐘，重現 gate pass 返回時已逾期。"""
            checked = gate.validate(value)
            clock["now"] = deadline + 1
            return checked

    monkeypatch.setattr(renderer_module, "time", SimpleNamespace(monotonic=current_time))
    with pytest.raises(RenderingError, match="render_deadline_exceeded"):
        ResponseRenderer(ExpiringGate()).render(result, request)


def test_waiting_response_cannot_be_sent_after_release_deadline(candidate_and_gate, monkeypatch):
    """M 建好回應後若等待到 C/F 期限外，必須在 ASGI start 前停止。"""
    candidate, gate = candidate_and_gate
    request = render_request()
    result = pipeline_result(candidate, gate, request)
    response = ResponseRenderer(gate).render(result, request)

    def expired_time():
        """模擬回應排程延遲已超過原本的同程序釋出期限。"""
        return result.trace["release_deadline_monotonic"] + 1

    monkeypatch.setattr(renderer_module, "time", SimpleNamespace(monotonic=expired_time))
    with pytest.raises(RenderingError, match="render_deadline_exceeded"):
        emit_response(response, request)
