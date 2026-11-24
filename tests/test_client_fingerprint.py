"""獨立 HTTPX 客戶端與固定跨邊界請求摘要的互通驗證。"""

import json
from pathlib import Path

import httpx
import pytest

from deception.api.fingerprint import fingerprint_httpx_request

VECTORS = json.loads((Path(__file__).parent / "fixtures/golden_vectors/request_fingerprint.json").read_text(encoding="utf-8"))["cases"]


@pytest.mark.parametrize("vector", VECTORS, ids=[case["name"] for case in VECTORS])
def test_independent_client_matches_fixed_wire_vectors(vector):
    """不載入外部判定程式，以公開 wire 向量確認摘要及重複核准標頭拒絕。"""
    values = vector["request"]
    request = httpx.Request(values["method"], values["raw_url"], content=bytes.fromhex(values["body"]))
    request.headers = httpx.Headers([(name.encode("ascii"), value.encode("latin-1")) for name, value in values["headers"]])
    if "error" in vector:
        with pytest.raises(ValueError):
            fingerprint_httpx_request(request, values["request_id"])
    else:
        assert fingerprint_httpx_request(request, values["request_id"]) == vector["fingerprint"]


def test_streaming_body_is_not_read_to_prepare_a_signature():
    """未緩衝的 body 直接拒絕，不能消費串流後簽出與真正傳輸不同的內容。"""
    consumed = []

    def body():
        """記錄是否讀取測試串流，內容僅為無敏感資料的固定 bytes。"""
        consumed.append(True)
        yield b"synthetic"

    request = httpx.Request("POST", "https://example.test/items", content=body())
    with pytest.raises(ValueError, match="not_buffered"):
        fingerprint_httpx_request(request, "request-1")
    assert consumed == []


def test_preparing_fingerprint_keeps_original_wire_request_unchanged():
    """摘要計算不得添加簽章、改寫標頭或重新序列化已固定的業務 body。"""
    request = httpx.Request("POST", "https://example.test/items?a=1&a=2", content=b'{"quantity": 2}', headers={"x-request-id": "request-1"})
    before = (str(request.url), request.headers.raw, request.content)
    assert len(fingerprint_httpx_request(request, "request-1")) == 64
    assert (str(request.url), request.headers.raw, request.content) == before


def test_httpx2_test_client_request_uses_the_same_wire_contract():
    """新版 Starlette 使用相容的 httpx2 Request 時，仍依實際 bytes 計算同一摘要。"""
    httpx2 = pytest.importorskip("httpx2")
    values = dict(content=b'{"quantity": 2}', headers={"x-request-id": "request-1"})
    original = httpx.Request("POST", "https://example.test/items?a=1&a=2", **values)
    compatible = httpx2.Request("POST", "https://example.test/items?a=1&a=2", **values)
    assert fingerprint_httpx_request(compatible, "request-1") == fingerprint_httpx_request(original, "request-1")


def test_httpx2_streaming_request_is_rejected_without_consumption():
    """兩種相容客戶端都必須先緩衝 body，不能以放寬類別檢查繞過串流限制。"""
    httpx2 = pytest.importorskip("httpx2")
    request = httpx2.Request("POST", "https://example.test/items", content=iter([b"synthetic"]))
    with pytest.raises(ValueError, match="not_buffered"):
        fingerprint_httpx_request(request, "request-1")


def test_non_request_object_is_rejected_by_required_wire_fields():
    """移除具體類別檢查後，缺少請求介面的物件仍須明確拒絕。"""
    with pytest.raises(ValueError, match="invalid_fingerprint_request"):
        fingerprint_httpx_request(object(), "request-1")
