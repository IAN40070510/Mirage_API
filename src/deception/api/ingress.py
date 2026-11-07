"""A 階段標準化：保留原始 HTTP 資料，供平台識別與生成使用。"""

import re
from dataclasses import dataclass
from uuid import uuid4

from fastapi import HTTPException, Request

MAX_BODY_BYTES = 1024 * 1024
REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", re.ASCII)


@dataclass(frozen=True)
class NormalizedRequest:
    """不可變的請求快照；原始 bytes 與解碼後欄位並存。"""

    request_id: str
    method: str
    raw_url: str
    path: str
    raw_path: bytes
    query_string: bytes
    query: tuple[tuple[str, str], ...]
    headers: tuple[tuple[str, str], ...]
    body: bytes


def resolve_request_id(request: Request) -> str:
    """接受單一合法 X-Request-ID；缺少時產生 UUID，拒絕重複或無效值。"""
    values = request.headers.getlist("x-request-id")
    if not values:
        return str(uuid4())
    if len(values) != 1 or not REQUEST_ID.fullmatch(values[0]):
        raise HTTPException(400, "invalid_request_id")
    return values[0]


async def normalize_request(
    request: Request, request_id: str, *, max_body_bytes: int = MAX_BODY_BYTES
) -> NormalizedRequest:
    """讀取並限制 body，保留 URL、query 與 headers 的原始資訊。"""

    # 依實際收到的位元組計數，不能只信任可能缺少或錯誤的 Content-Length。
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > max_body_bytes:
            raise HTTPException(413, "request_body_too_large")
        body.extend(chunk)

    raw_path = request.scope.get("raw_path", request.url.path.encode("utf-8"))
    query_string = request.scope.get("query_string", b"")
    # Request.url 的 path 已解碼；重新放入原始 path/query 以保留 percent encoding。
    raw_url = str(request.url.replace(
        path=raw_path.decode("latin-1"), query=query_string.decode("latin-1")
    ))
    return NormalizedRequest(
        request_id=request_id,
        method=request.method,
        raw_url=raw_url,
        path=request.scope["path"],
        raw_path=raw_path,
        query_string=query_string,
        # 有序配對保留重複參數，避免轉成 dict 後遺失資訊。
        query=tuple(request.query_params.multi_items()),
        headers=tuple((key.decode("latin-1"), value.decode("latin-1"))
                      for key, value in request.scope["headers"]),
        body=bytes(body),
    )
