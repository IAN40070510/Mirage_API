"""固定安全錯誤的獨立模板、精確 ASGI 封套與請求綁定驗收。"""

import asyncio
from dataclasses import replace
import json
from pathlib import Path
import time

import pytest
from fastapi.testclient import TestClient
from starlette.background import BackgroundTask
from starlette.responses import JSONResponse

from deception.api.app import create_app
from deception.api.ingress import NormalizedRequest
from deception.api.pipeline import _unavailable
from deception.core.security_error import SecurityErrorRenderer, SecurityErrorResponse, SecurityErrorRenderingError
import deception.core.security_error as security_module
from deception.world.models import SecurityErrorSource


def request(**changes):
    """建立含原始 query 與標頭的不可變請求，個別案例可只改一個安全相關維度。"""
    return replace(NormalizedRequest(request_id="fixed-error-test", method="GET",
        raw_url="https://shop.test/private/test?x=1", path="/private/test", raw_path=b"/private/test",
        query_string=b"x=1", query=(("x", "1"),), headers=(("host", "shop.test"),), body=b""), **changes)


def emit(response, original, messages, **changes):
    """送入真實 ASGI scope 並保存送出訊息，讓送出前拒絕可核對零訊息。"""
    scope = dict(type="http", method=original.method, scheme="https", path=original.path,
        raw_path=original.raw_path, query_string=original.query_string,
        headers=[(name.encode("latin-1"), value.encode("latin-1")) for name, value in original.headers],
        server=("shop.test", 443))
    scope.update(changes)

    async def receive():
        """提供已讀完的請求；安全錯誤 Renderer 不再從網路讀取私有本文。"""
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        """保存封存回應的兩個原始 ASGI 訊息，不替 Renderer 改寫。"""
        messages.append(message)

    asyncio.run(response(scope, receive, send))


@pytest.mark.parametrize("not_applicable", [False, True])
def test_fixed_security_error_preserves_exact_legacy_envelope_without_database(monkeypatch, not_applicable):
    """原固定 503／409 bytes 與 headers 完全相同，且可在資料庫全部不可用時獨立驗證發送。"""
    import psycopg

    def refuse_connection(*args, **kwargs):
        """確保模板、來源、關聯驗證及 ASGI 送出不會嘗試任何 SQL 連線。"""
        raise AssertionError("fixed security error must not connect database")

    monkeypatch.setattr(psycopg, "connect", refuse_connection)
    original = request()
    response = _unavailable(original, not_applicable=not_applicable)
    expected = JSONResponse(status_code=409 if not_applicable else 503,
        content={"code": "pipeline_not_applicable" if not_applicable else "pipeline_unavailable",
                 "request_id": original.request_id}, headers={"X-Request-ID": original.request_id})
    assert isinstance(response, SecurityErrorResponse)
    assert (response.status_code, response.raw_headers, response.body) == (expected.status_code, expected.raw_headers, expected.body)
    assert response.source.kind == "security_error" and response.source.contract_revision == "1"
    messages = []
    emit(response, original, messages)
    assert messages == [{"type": "http.response.start", "status": expected.status_code, "headers": expected.raw_headers},
                        {"type": "http.response.body", "body": expected.body}]


@pytest.mark.parametrize("change", ["status", "body", "header", "extra_header", "source", "background", "sealed_body", "deadline"])
def test_security_error_tampering_emits_nothing(change):
    """封存後任一輸出或來源遭改寫都在 ASGI start 前拒絕，不送惡意替代內容。"""
    original, response = request(), _unavailable(request())
    if change == "status":
        response.status_code = 404
    elif change == "body":
        response.body = b"private-world-canary"
    elif change == "header":
        response.headers["x-request-id"] = "other-request"
    elif change == "extra_header":
        response.headers["set-cookie"] = "secret-canary"
    elif change == "source":
        response.source = SecurityErrorSource(template_id="fake-medusa", contract_revision="1")
    elif change == "background":
        response.background = BackgroundTask(print, "must-not-run")
    elif change == "sealed_body":
        response._sealed_body = b"private-world-canary"
    else:
        response._deadline = response._deadline + 10
    messages = []
    with pytest.raises(SecurityErrorRenderingError):
        emit(response, original, messages)
    assert messages == []


@pytest.mark.parametrize("changes", [{"request_id": "other"}, {"body": b"changed"},
    {"method": "POST"}, {"raw_url": "https://other.test/private/test?x=1"},
    {"path": "/changed"}, {"raw_path": b"/private/%74est"}, {"query_string": b"x=2"},
    {"query": (("x", "2"),)}, {"headers": (("host", "shop.test"), ("authorization", "secret"))}])
def test_error_response_cannot_be_reused_for_another_normalized_request(changes):
    """改變完整請求中任一關聯資料皆無法重用既有拒絕封套，包含未列入一般指紋的資料。"""
    original = request()
    response = _unavailable(original)
    with pytest.raises(SecurityErrorRenderingError, match="request_mismatch"):
        response.assert_request(replace(original, **changes))


@pytest.mark.parametrize("changes", [{"method": "POST"}, {"scheme": "http"}, {"path": "/changed"},
    {"raw_path": b"/private/%74est"}, {"query_string": b"x=2"}, {"headers": [(b"host", b"other.test")]}])
def test_error_response_checks_actual_asgi_scope(changes):
    """即使入口後的 scope 才被替換，實際送出前仍拒絕不同來源、路徑或標頭。"""
    original, messages = request(), []
    response = _unavailable(original)
    with pytest.raises(SecurityErrorRenderingError, match="request_mismatch"):
        emit(response, original, messages, **changes)
    assert messages == []


def test_duplicate_credential_headers_still_have_safe_bound_error():
    """重複 Authorization 使一般 fingerprint 無法計算時，固定拒絕仍可綁住完整原始標頭。"""
    original = request(headers=(("host", "shop.test"), ("authorization", "first-secret"), ("authorization", "second-secret")))
    response, messages = _unavailable(original), []
    emit(response, original, messages)
    assert json.loads(messages[1]["body"]) == {"code": "pipeline_unavailable", "request_id": original.request_id}
    assert b"secret" not in response.body


@pytest.mark.parametrize("method", ["HEAD", "TRACE", "OPTIONS"])
def test_security_error_handles_supported_ingress_methods(method):
    """錯誤模板不反射 TRACE 內容，HEAD 不送本文且保留對應 GET 表示的 Content-Length。"""
    original, messages = request(method=method, body=b"secret-canary"), []
    response = _unavailable(original)
    emit(response, original, messages)
    assert messages[0]["status"] == 503
    if method == "HEAD":
        assert messages[1]["body"] == b"" and int(response.headers["content-length"]) > 0
    else:
        assert json.loads(messages[1]["body"])["code"] == "pipeline_unavailable"
        assert b"secret" not in messages[1]["body"]


def test_error_deadline_equality_prevents_start(monkeypatch):
    """發送期限相等即拒絕，不能因模板固定而無期限重用回應。"""
    original, messages = request(), []
    response = _unavailable(original)
    monkeypatch.setattr(security_module.time, "monotonic", lambda: response._deadline)
    # lambda 只把同程序時鐘固定在既有期限邊界，不參與模板選擇。
    with pytest.raises(SecurityErrorRenderingError, match="deadline"):
        emit(response, original, messages)
    assert messages == []


@pytest.mark.parametrize("not_applicable", [False, True])
def test_real_ingress_preserves_security_renderer_seal(not_applicable):
    """正常 API 入口直接接受已封存的安全錯誤，不在驗證後再補改 headers。"""
    async def handler(value):
        """以真實正規化請求產生安全錯誤，供入口驗證及 ASGI 傳輸。"""
        return _unavailable(value, not_applicable=not_applicable)

    with TestClient(create_app(handler), base_url="https://shop.test") as client:
        response = client.get("/private/test?x=1", headers={"x-request-id": "fixed-error-test"})
    assert response.status_code == (409 if not_applicable else 503)
    assert response.headers["x-request-id"] == "fixed-error-test"
    assert response.json()["request_id"] == "fixed-error-test"


def test_renderer_import_matches_current_test_workspace():
    """載入的 Renderer 必須與本次測試屬於同一專案根目錄，避免跨副本的虛假通過。"""
    assert Path(security_module.__file__).resolve().is_relative_to(Path(__file__).resolve().parents[1])


@pytest.mark.parametrize("changes,option", [({"request_id": "bad\r\nheader"}, False),
    ({"request_id": ""}, False), ({"method": "CONNECT"}, False), ({}, 1), ({}, "false")])
def test_renderer_refuses_unapproved_template_inputs(changes, option):
    """不可信追蹤 ID、未支援方法與非 bool 模板選項不能構造可送出的錯誤封套。"""
    with pytest.raises(SecurityErrorRenderingError, match="invalid_security_error_input"):
        SecurityErrorRenderer().render(request(**changes), not_applicable=option)


@pytest.mark.parametrize("failure", ["blocked", "cancelled", "changed_after_start"])
def test_send_failure_never_starts_another_error_response(failure):
    """實際 send 阻塞、取消或起送後改寫都停止原傳輸，不發第二份 start 或替代本文。"""
    original, response, messages = request(), _unavailable(request()), []
    scope = dict(type="http", method="GET", scheme="https", path=original.path,
        raw_path=original.raw_path, query_string=original.query_string,
        headers=[(name.encode(), value.encode()) for name, value in original.headers], server=("shop.test", 443))
    if failure == "blocked":
        # 只縮短測試的同程序期限；正式建構子仍固定五秒，測試不等待整個生產上限。
        response._deadline = time.monotonic() + 0.02
        response._sealed_deadline = response._deadline

    async def receive():
        """提供已讀完請求，故障只發生在傳輸 callback。"""
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        """在第一次 start 嘗試模擬三種故障，記錄已發生事實而不重送。"""
        messages.append(message)
        if failure == "blocked":
            await asyncio.Event().wait()
        elif failure == "cancelled":
            raise asyncio.CancelledError
        else:
            response.body = b"private-body-canary"

    expected = {"blocked": TimeoutError, "cancelled": asyncio.CancelledError,
                "changed_after_start": SecurityErrorRenderingError}[failure]
    with pytest.raises(expected):
        asyncio.run(response(scope, receive, send))
    assert len(messages) == 1 and messages[0]["type"] == "http.response.start"
