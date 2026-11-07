"""Native FastAPI ingress; the response validator remains a separate service."""

from collections.abc import Awaitable, Callable
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from .ingress import MAX_BODY_BYTES, NormalizedRequest, normalize_request, resolve_request_id

RequestHandler = Callable[[NormalizedRequest], Awaitable[Response]]


async def pipeline_not_implemented(request: NormalizedRequest) -> Response:
    return JSONResponse(status_code=501, content={
        "code": "pipeline_not_implemented",
        "message": "HTTP request captured; platform identification and generation are not implemented.",
        "request_id": request.request_id,
    })


def create_app(
    handler: RequestHandler = pipeline_not_implemented, *, max_body_bytes: int = MAX_BODY_BYTES
) -> FastAPI:
    if max_body_bytes < 0:
        raise ValueError("max_body_bytes must be nonnegative")
    # No reserved /docs or /openapi.json paths: all target paths reach stage A.
    app = FastAPI(title="Mirage HTTP Request Ingress", version="0.1.0",
                  docs_url=None, redoc_url=None, openapi_url=None,
                  redirect_slashes=False)

    @app.api_route("/{path:path}", methods=[
        "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"
    ], include_in_schema=False)
    async def receive_request(request: Request) -> Response:
        try:
            request_id = resolve_request_id(request)
        except HTTPException as exc:
            request_id = str(uuid4())
            return JSONResponse(status_code=exc.status_code,
                                content={"code": exc.detail, "request_id": request_id},
                                headers={"X-Request-ID": request_id})
        try:
            normalized = await normalize_request(request, request_id, max_body_bytes=max_body_bytes)
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code,
                                content={"code": exc.detail, "request_id": request_id},
                                headers={"X-Request-ID": request_id})
        response = await handler(normalized)
        response.headers["X-Request-ID"] = request_id
        return response

    return app


app = create_app()
