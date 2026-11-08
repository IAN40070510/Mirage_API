"""A 階段入口：接收原生 HTTP 請求，交給後續處理器。"""

from collections.abc import Awaitable, Callable
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from .ingress import MAX_BODY_BYTES, NormalizedRequest, normalize_request, resolve_request_id

RequestHandler = Callable[[NormalizedRequest], Awaitable[Response]]


async def pipeline_not_implemented(request: NormalizedRequest) -> Response:
    """後續生成流程未接上時，明確回報 501 與本次追蹤 ID。"""
    return JSONResponse(status_code=501, content={
        "code": "pipeline_not_implemented",
        "message": "HTTP request captured; platform identification and generation are not implemented.",
        "request_id": request.request_id,
    })


def create_app(
    handler: RequestHandler = pipeline_not_implemented, *, max_body_bytes: int = MAX_BODY_BYTES
) -> FastAPI:
    """建立 HTTP 入口；handler 只會收到已通過入口檢查的標準化請求。"""
    if max_body_bytes < 0:
        raise ValueError("max_body_bytes must be nonnegative")
    # 所有路徑都是待模擬 API 的路徑，因此不保留 /docs 或 /openapi.json。
    app = FastAPI(title="Mirage HTTP Request Ingress", version="0.1.0",
                  docs_url=None, redoc_url=None, openapi_url=None,
                  redirect_slashes=False)

    @app.api_route("/{path:path}", methods=[
        "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"
    ], include_in_schema=False)
    async def receive_request(request: Request) -> Response:
        """先檢查追蹤 ID 與 body，再把完整請求交給後續處理器。"""
        try:
            request_id = resolve_request_id(request)
        except HTTPException as exc:
            # 原追蹤 ID 不可信；產生新 ID，讓錯誤回應仍可被追蹤。
            request_id = str(uuid4())
            return JSONResponse(status_code=exc.status_code,
                                content={"code": exc.detail, "request_id": request_id},
                                headers={"X-Request-ID": request_id})
        try:
            normalized = await normalize_request(request, request_id, max_body_bytes=max_body_bytes)
        except HTTPException as exc:
            # 大小限制等入口錯誤不會進入平台識別或生成流程。
            return JSONResponse(status_code=exc.status_code,
                                content={"code": exc.detail, "request_id": request_id},
                                headers={"X-Request-ID": request_id})
        response = await handler(normalized)
        # M 已把追蹤 ID 納入 I 的最終驗證，A 不可在這裡再修改其封套。
        from deception.core.renderer import ValidatedHTTPResponse
        if isinstance(response, ValidatedHTTPResponse):
            response.assert_request(normalized)
            return response
        # 讓後續 handler 的回應也帶有本次請求的追蹤 ID。
        response.headers["X-Request-ID"] = request_id
        return response

    return app


app = create_app()
