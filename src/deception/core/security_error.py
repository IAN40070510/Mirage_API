"""不依賴 World／DB 的固定安全錯誤 Renderer，封存最終傳輸並綁定原請求。"""

import asyncio
import hashlib
import hmac
import json
import time

from starlette.requests import Request
from starlette.responses import Response

from deception.api.ingress import NormalizedRequest, REQUEST_ID
from deception.world.models import SecurityErrorSource


class SecurityErrorRenderingError(RuntimeError):
    """表示固定安全錯誤封套或請求關聯無法驗證，只保存固定診斷碼。"""


def _request_binding(request: NormalizedRequest) -> str:
    """摘要完整原始請求，保留重複標頭以處理無法產生一般指紋的拒絕情境；不輸出摘要內容。"""
    values = dict(request_id=request.request_id, method=request.method, raw_url=request.raw_url,
        path=request.path, raw_path=request.raw_path.hex(), query_string=request.query_string.hex(),
        query=request.query, headers=request.headers, body_sha256=hashlib.sha256(request.body).hexdigest())
    encoded = json.dumps(values, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _template(request: NormalizedRequest, not_applicable: bool):
    """只建立兩個核准固定模板；HEAD 保留表示長度但不發本文，不允許自訂欄位或狀態。"""
    if (type(not_applicable) is not bool or not isinstance(request.request_id, str)
            or not REQUEST_ID.fullmatch(request.request_id)
            or request.method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}):
        raise SecurityErrorRenderingError("invalid_security_error_input")
    code = "pipeline_not_applicable" if not_applicable else "pipeline_unavailable"
    representation = json.dumps({"code": code, "request_id": request.request_id},
        ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    headers = ((b"x-request-id", request.request_id.encode("ascii")),
               (b"content-length", str(len(representation)).encode("ascii")),
               (b"content-type", b"application/json"))
    source = SecurityErrorSource(template_id="safe-not-applicable" if not_applicable else "safe-unavailable",
                                 contract_revision="1")
    return (409 if not_applicable else 503), headers, b"" if request.method == "HEAD" else representation, source


class SecurityErrorResponse(Response):
    """以獨立固定模板核對 status／headers／bytes／來源，ASGI 起送前重新驗證關聯。"""

    def __init__(self, request: NormalizedRequest, *, not_applicable: bool = False):
        """封存核准錯誤模板與完整請求摘要，建立五秒本機發送期限，不讀 World 或授權 DB。"""
        status, headers, body, source = _template(request, not_applicable)
        super().__init__(body, status_code=status, headers={name.decode("ascii"): value.decode("ascii")
                         for name, value in headers}, media_type=None)
        self.source = source
        self._request = request
        self._not_applicable = not_applicable
        self._bound_digest = _request_binding(request)
        self._sealed_status, self._sealed_headers, self._sealed_body = status, headers, body
        self._source_identity = (source.kind, source.template_id, source.contract_revision)
        self._deadline = time.monotonic() + 5
        self._sealed_deadline = self._deadline
        self._assert_unchanged()

    def _assert_unchanged(self) -> None:
        """重建固定模板並核對精確封套、來源、期限與請求，拒絕背景工作及中途改寫。"""
        expected = _template(self._request, self._not_applicable)
        if (self._deadline != self._sealed_deadline or time.monotonic() >= self._deadline):
            raise SecurityErrorRenderingError("security_error_deadline_exceeded")
        if (not isinstance(self.source, SecurityErrorSource)
                or (self.source.kind, self.source.template_id, self.source.contract_revision) != self._source_identity
                or self.source != expected[3]
                or (self.status_code, tuple(self.raw_headers), self.body) != expected[:3]
                or (self._sealed_status, self._sealed_headers, self._sealed_body) != expected[:3]
                or self.background is not None
                or not hmac.compare_digest(_request_binding(self._request), self._bound_digest)):
            raise SecurityErrorRenderingError("security_error_response_changed")

    def assert_request(self, request: NormalizedRequest) -> None:
        """供入口核對此回應只屬於原本完整請求，不使用一般 fingerprint 的重複標頭拒絕規則。"""
        if not hmac.compare_digest(_request_binding(request), self._bound_digest):
            raise SecurityErrorRenderingError("security_error_request_mismatch")
        self._assert_unchanged()

    async def __call__(self, scope, receive, send) -> None:
        """核對實際 ASGI request 後只發送封存訊息，錯配或逾期不發候選、不重新生成。"""
        self._assert_unchanged()
        request = self._request
        headers = tuple((name.decode("latin-1"), value.decode("latin-1")) for name, value in scope.get("headers", ()))
        if (scope.get("type") != "http" or scope.get("method") != request.method
                or scope.get("path") != request.path or scope.get("raw_path", request.raw_path) != request.raw_path
                or scope.get("query_string", b"") != request.query_string or headers != request.headers):
            raise SecurityErrorRenderingError("security_error_request_mismatch")
        actual_url = str(Request(scope).url.replace(path=request.raw_path.decode("latin-1"),
                                                  query=request.query_string.decode("latin-1")))
        if actual_url != request.raw_url:
            raise SecurityErrorRenderingError("security_error_request_mismatch")
        for message in ({"type": "http.response.start", "status": self._sealed_status,
                         "headers": list(self._sealed_headers)},
                        {"type": "http.response.body", "body": self._sealed_body}):
            self._assert_unchanged()
            async with asyncio.timeout(self._deadline - time.monotonic()):
                await send(message)


class SecurityErrorRenderer:
    """以固定 SecurityErrorSource 產生拒絕回應，不提供一般候選或私有世界輸出能力。"""

    def render(self, request: NormalizedRequest, *, not_applicable: bool = False) -> SecurityErrorResponse:
        """回傳已核對固定模板及原請求的封存 Response，無法驗證時拋錯而不回退其他模板。"""
        return SecurityErrorResponse(request, not_applicable=not_applicable)
