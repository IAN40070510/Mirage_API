"""HTTP 請求 fingerprint v1 的輕量、跨邊界實作。"""

import hashlib
import json

from .ingress import NormalizedRequest

FINGERPRINT_HEADERS = frozenset({
    "host", "content-type", "content-length", "x-request-id", "authorization",
    "idempotency-key", "x-publishable-api-key",
})


def fingerprint_httpx_request(outgoing, request_id: str) -> str:
    """將已完成建構的 HTTPX 請求轉為 Mirage v1 摘要，不依賴外部 Gateway。

    接受 HTTPX／httpx2 相容的已緩衝請求介面，不依套件的 Request 類別身份判定。
    必須先固定 URL、標頭及 body bytes，再將相同請求送出。此函式不讀取串流、
    不改寫請求、不簽發授權；空識別、未緩衝 body 或重複核准標頭會 ValueError。
    傳入的 request_id 仍須與服務端解析的識別一致，否則服務端驗章拒絕。
    """
    if not isinstance(request_id, str) or not request_id:
        raise ValueError("invalid_fingerprint_request")
    try:
        body = outgoing.content
        if not isinstance(body, bytes):
            raise ValueError("invalid_fingerprint_request")
        request = NormalizedRequest(
            request_id=request_id, method=outgoing.method, raw_url=str(outgoing.url),
            path=outgoing.url.path, raw_path=outgoing.url.raw_path.partition(b"?")[0],
            query_string=outgoing.url.query, query=tuple(outgoing.url.params.multi_items()),
            headers=tuple((name.decode("latin-1"), value.decode("latin-1")) for name, value in outgoing.headers.raw),
            body=body,
        )
    except AttributeError as error:
        raise ValueError("invalid_fingerprint_request") from error
    except RuntimeError as error:
        # 兩個相容套件的 RequestNotRead 均繼承 RuntimeError；不讀取或修補串流。
        raise ValueError("request_body_not_buffered") from error
    return fingerprint_request(request)


def fingerprint_request(request: NormalizedRequest) -> str:
    """以原始請求快照建立摘要，只納入核准 headers 並排除 JWS 本身。"""
    headers = []
    seen = set()
    for name, value in request.headers:
        normalized_name = name.lower()
        if normalized_name == "x-trusted-session":
            continue
        if normalized_name not in FINGERPRINT_HEADERS:
            continue
        if normalized_name in seen:
            raise ValueError("ambiguous_request_fingerprint_header")
        seen.add(normalized_name)
        if normalized_name == "authorization":
            value = hashlib.sha256(value.encode("latin-1")).hexdigest()
        headers.append((normalized_name, value))
    value = {
        "request_id": request.request_id,
        "method": request.method,
        "raw_url": request.raw_url,
        "path": request.path,
        "raw_path": request.raw_path.hex(),
        "query_string": request.query_string.hex(),
        "query": request.query,
        "headers": tuple(headers),
        "body_sha256": hashlib.sha256(request.body).hexdigest(),
    }
    return hashlib.sha256(json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")).hexdigest()
