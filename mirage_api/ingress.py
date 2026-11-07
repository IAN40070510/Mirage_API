"""Stage A: lossless request capture without platform inference or JSON coercion."""

import re
from dataclasses import dataclass
from uuid import uuid4

from fastapi import HTTPException, Request

MAX_BODY_BYTES = 1024 * 1024
REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", re.ASCII)


@dataclass(frozen=True)
class NormalizedRequest:
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
    values = request.headers.getlist("x-request-id")
    if not values:
        return str(uuid4())
    if len(values) != 1 or not REQUEST_ID.fullmatch(values[0]):
        raise HTTPException(400, "invalid_request_id")
    return values[0]


async def normalize_request(
    request: Request, request_id: str, *, max_body_bytes: int = MAX_BODY_BYTES
) -> NormalizedRequest:
    # Count streamed bytes even when Content-Length is missing or inaccurate.
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > max_body_bytes:
            raise HTTPException(413, "request_body_too_large")
        body.extend(chunk)

    raw_path = request.scope.get("raw_path", request.url.path.encode("utf-8"))
    query_string = request.scope.get("query_string", b"")
    # Request.url uses the decoded ASGI path. Reinsert the wire representation.
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
        query=tuple(request.query_params.multi_items()),
        headers=tuple((key.decode("latin-1"), value.decode("latin-1"))
                      for key, value in request.scope["headers"]),
        body=bytes(body),
    )
