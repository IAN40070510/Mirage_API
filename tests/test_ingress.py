"""Stage A captures HTTP input; it does not certify or generate platform responses."""

from uuid import UUID

import pytest
from fastapi.responses import Response
from fastapi.testclient import TestClient

from deception.api.app import create_app


def capture_app(**kwargs):
    """建立可記錄標準化請求的測試入口，回傳 client 與獨立擷取清單。"""
    captured = []

    async def handler(request):
        """保存本次標準化請求，並回傳不含 body 的 204 測試回應。"""
        captured.append(request)
        return Response(status_code=204)

    return TestClient(create_app(handler, **kwargs)), captured


def test_preserves_raw_url_query_headers_and_body():
    """入口須保留原始 URL 編碼、重複 query/header 及未解析的 body bytes。"""
    client, captured = capture_app()
    body = b' {"price":1.00, "id":1,"id":2} \n\xff'
    response = client.post(
        "https://shop.test:8443/store/products/prod%2F1?fields=id&fields=title&empty=&q=a+b&q=a%20b",
        headers=[("X-Request-ID", "demo-001"), ("X-Tag", "first"), ("X-Tag", "second"),
                 ("Content-Type", "application/octet-stream")],
        content=body,
    )
    assert response.status_code == 204
    assert response.headers["x-request-id"] == "demo-001"
    request = captured[0]
    assert request.method == "POST"
    assert request.request_id == "demo-001"
    assert request.raw_url == (
        "https://shop.test:8443/store/products/prod%2F1?fields=id&fields=title&empty=&q=a+b&q=a%20b"
    )
    assert request.path == "/store/products/prod/1"
    assert request.raw_path == b"/store/products/prod%2F1"
    assert request.query_string == b"fields=id&fields=title&empty=&q=a+b&q=a%20b"
    assert request.query == (("fields", "id"), ("fields", "title"), ("empty", ""),
                             ("q", "a b"), ("q", "a b"))
    assert [v for k, v in request.headers if k == "x-tag"] == ["first", "second"]
    assert request.body == body


@pytest.mark.parametrize("method", ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"])
@pytest.mark.parametrize("path", ["/", "/store/products/", "/docs", "/openapi.json"])
def test_methods_and_paths_reach_handler_without_redirect(method, path):
    """所有受支援方法與任意路徑直接交給 handler，不保留文件端點或自動轉址。"""
    client, captured = capture_app()
    response = client.request(method, path, follow_redirects=False)
    assert response.status_code == 204
    assert captured[0].method == method
    assert captured[0].raw_path.decode() == path
    assert captured[0].body == b""
    assert str(UUID(captured[0].request_id)) == response.headers["x-request-id"]


def test_unconnected_pipeline_fails_explicitly_without_echoing_input():
    """未接生成流程時回明確 501，並避免回顯 query、body 或憑證內容。"""
    client = TestClient(create_app())
    response = client.post("/store/products?token=secret", content=b"private body",
                           headers={"Authorization": "Bearer secret"})
    assert response.status_code == 501
    assert response.json()["code"] == "pipeline_not_implemented"
    assert response.json()["request_id"] == response.headers["x-request-id"]
    assert "secret" not in response.text
    assert "private body" not in response.text


@pytest.mark.parametrize("headers", [
    {"X-Request-ID": ""}, {"X-Request-ID": "contains spaces"}, {"X-Request-ID": "a" * 129},
    [("X-Request-ID", "first"), ("X-Request-ID", "second")],
])
def test_invalid_or_duplicate_request_id_is_rejected(headers):
    """無效或重複追蹤 ID 必須在 handler 前拒絕，錯誤回應另產生有效 ID。"""
    client, captured = capture_app()
    response = client.get("/store/products", headers=headers)
    assert response.status_code == 400
    assert response.json()["code"] == "invalid_request_id"
    UUID(response.headers["x-request-id"])
    assert not captured


def test_body_limit_checks_stream_without_content_length():
    """實際串流 bytes 超過限制時須回 413，不能只依賴 Content-Length。"""
    client, captured = capture_app(max_body_bytes=4)
    assert client.post("/", content=b"1234").status_code == 204

    def chunks():
        """分段送出總長超限的內容，模擬沒有 Content-Length 的 body 串流。"""
        yield b"123"
        yield b"45"

    response = client.post("/", content=chunks(), headers={"X-Request-ID": "large-1"})
    assert response.status_code == 413
    assert response.json()["code"] == "request_body_too_large"
    assert response.headers["x-request-id"] == "large-1"
    assert len(captured) == 1


def test_request_ids_and_bodies_do_not_leak_between_requests():
    """不同請求應有獨立追蹤 ID 與 body，空 body 不得沿用上一筆內容。"""
    client, captured = capture_app()
    client.post("/one", content=b"first")
    client.get("/two")
    assert captured[0].request_id != captured[1].request_id
    assert captured[0].body == b"first"
    assert captured[1].body == b""
