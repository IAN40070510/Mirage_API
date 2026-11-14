"""HTTP 請求 fingerprint v1 的輕量、跨邊界實作。"""

import hashlib
import json

from .ingress import NormalizedRequest

FINGERPRINT_HEADERS = frozenset({
    "host", "content-type", "content-length", "x-request-id", "authorization",
})


def fingerprint_request(request: NormalizedRequest) -> str:
    """以原始請求快照建立摘要，只納入核准 headers 並排除 JWS 本身。"""
    headers = []
    for name, value in request.headers:
        normalized_name = name.lower()
        if normalized_name == "x-trusted-session":
            continue
        if normalized_name not in FINGERPRINT_HEADERS:
            continue
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
