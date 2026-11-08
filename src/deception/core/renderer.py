"""M：把同一請求的已驗證候選轉為精確 HTTP 回應，再驗最終傳輸欄位。"""

import math
import re
import time
from dataclasses import replace

from starlette.requests import Request
from starlette.responses import Response

from deception.api.ingress import REQUEST_ID, NormalizedRequest
from deception.generation.models import digest
from deception.scenarios import fingerprint_request

from .handoff import verify_candidate
from .models import CandidateResponse

HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", re.ASCII)
HOP_HEADERS = frozenset({"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
                         "te", "trailer", "transfer-encoding", "upgrade", "content-encoding"})


class RenderingError(ValueError):
    """固定錯誤碼，表示回應無法原樣驗證或已在驗證後遭修改。"""

    def __init__(self, code: str):
        """保存不含請求、憑證、body 或底層例外文字的渲染診斷碼。"""
        self.code = code
        super().__init__(code)


def _check_release_deadline(value) -> float:
    """核對同程序單調時鐘期限；缺漏、無限值或逾期都禁止送出候選。"""
    if type(value) not in (int, float):
        raise RenderingError("render_deadline_exceeded")
    try:
        deadline = float(value)
    except (OverflowError, ValueError):
        raise RenderingError("render_deadline_exceeded") from None
    if not math.isfinite(deadline) or deadline <= 0 or time.monotonic() >= deadline:
        raise RenderingError("render_deadline_exceeded")
    return deadline


class ValidatedHTTPResponse(Response):
    """保留 M 最後驗證的 bytes 與 headers，送出前阻擋框架內的事後修改。"""

    def __init__(self, candidate: CandidateResponse, gate_result, request: NormalizedRequest,
                 *, release_deadline_monotonic: float):
        """保存已由 renderer 重新驗證的封套；此類別本身不是外部來源認證。"""
        super().__init__(content=candidate.body_bytes, status_code=candidate.status_code,
                         headers=dict(candidate.headers), media_type=None)
        self.candidate = candidate
        self.gate_result = gate_result.model_copy(deep=True)
        self._release_deadline_monotonic = _check_release_deadline(release_deadline_monotonic)
        self._bound_fingerprint = fingerprint_request(request)
        self._bound_url = request.raw_url
        self._bound_method = request.method
        self._bound_path = request.path
        self._bound_raw_path = request.raw_path
        self._bound_query = request.query_string
        self._bound_headers = request.headers
        self._sealed_status = self.status_code
        self._sealed_body = self.body
        self._sealed_headers = tuple(self.raw_headers)

    def assert_request(self, request: NormalizedRequest) -> None:
        """A 回傳前核對完整請求指紋，禁止把另一請求的回應或 gate pass 重用。"""
        if fingerprint_request(request) != self._bound_fingerprint:
            raise RenderingError("render_request_mismatch")
        self._assert_unchanged()

    def _assert_unchanged(self) -> None:
        """在任何 ASGI start 發出前確認 status、bytes、headers 與背景工作未變。"""
        _check_release_deadline(self._release_deadline_monotonic)
        if (self.status_code != self._sealed_status or self.body != self._sealed_body or
                tuple(self.raw_headers) != self._sealed_headers or self.background is not None):
            raise RenderingError("validated_response_changed")

    async def __call__(self, scope, receive, send) -> None:
        """只發出封存的兩個 ASGI 訊息；不重新序列化、不執行背景工作。"""
        self._assert_unchanged()
        headers = tuple((key.decode("latin-1"), value.decode("latin-1"))
                        for key, value in scope.get("headers", ()))
        if (scope.get("type") != "http" or scope.get("method") != self._bound_method or
                scope.get("path") != self._bound_path or
                scope.get("raw_path", self._bound_raw_path) != self._bound_raw_path or
                scope.get("query_string", b"") != self._bound_query or headers != self._bound_headers):
            raise RenderingError("render_request_mismatch")
        actual_url = str(Request(scope).url.replace(
            path=self._bound_raw_path.decode("latin-1"), query=self._bound_query.decode("latin-1")))
        if actual_url != self._bound_url:
            raise RenderingError("render_request_mismatch")
        _check_release_deadline(self._release_deadline_monotonic)
        await send({"type": "http.response.start", "status": self._sealed_status,
                    "headers": list(self._sealed_headers)})
        await send({"type": "http.response.body", "body": self._sealed_body})


class ResponseRenderer:
    """由受信任整合層注入 I，對實際 URL 與最終傳輸封套重新驗證。"""

    def __init__(self, gate):
        """保留本部署的 gate，不從候選或訪客輸入選擇驗證器。"""
        self.gate = gate

    def render(self, result, request: NormalizedRequest) -> ValidatedHTTPResponse:
        """核對 C 結果與請求後加入傳輸欄位，重驗 I；失敗拋 RenderingError。"""
        candidate = result.candidate
        if (result.decision != "validated" or not isinstance(candidate, CandidateResponse) or
                result.gate_result is None or result.gate_result.decision != "pass" or
                result.gate_result.valid is not True):
            raise RenderingError("pipeline_not_validated")
        deadline = _check_release_deadline(result.trace.get("release_deadline_monotonic"))
        if (result.trace.get("request_id") != request.request_id or
                result.trace.get("request_fingerprint") != fingerprint_request(request) or
                result.trace.get("candidate_sha256") != digest(candidate.to_dict()) or
                candidate.identity.method != request.method):
            raise RenderingError("render_request_mismatch")
        if (request.method == "HEAD" or type(candidate.status_code) is not int or
                not 200 <= candidate.status_code <= 599 or candidate.status_code in (204, 205, 304)):
            raise RenderingError("unsupported_http_response")
        if not REQUEST_ID.fullmatch(request.request_id):
            raise RenderingError("invalid_request_id")
        headers = self._final_headers(candidate, request.request_id)
        final = replace(candidate, headers=headers)
        _check_release_deadline(deadline)
        try:
            checked = verify_candidate(final, self.gate, request.raw_url)
        except Exception:
            raise RenderingError("final_gate_unverifiable") from None
        _check_release_deadline(deadline)
        if checked.decision != "pass" or checked.valid is not True:
            raise RenderingError("final_gate_not_passed")
        return ValidatedHTTPResponse(final, checked, request, release_deadline_monotonic=deadline)

    def _final_headers(self, candidate: CandidateResponse, request_id: str) -> tuple[tuple[str, str], ...]:
        """拒絕多值、非法或未支援的傳輸標頭，固定 UTF-8 長度與本次追蹤 ID。"""
        headers = {}
        try:
            size = len(candidate.body_bytes)
            for name, value in candidate.headers:
                if (not isinstance(name, str) or not HEADER_NAME.fullmatch(name) or
                        not isinstance(value, str) or any(ord(char) < 32 or ord(char) == 127 for char in value)):
                    raise RenderingError("invalid_response_headers")
                name.encode("ascii")
                value.encode("latin-1")
                lowered = name.lower()
                if lowered in headers or lowered in HOP_HEADERS:
                    raise RenderingError("unsupported_response_headers")
                headers[lowered] = value
        except (UnicodeError, TypeError, ValueError) as exc:
            if isinstance(exc, RenderingError):
                raise
            raise RenderingError("invalid_response_headers") from None
        if not headers.get("content-type"):
            raise RenderingError("missing_content_type")
        if "content-length" in headers and headers["content-length"] != str(size):
            raise RenderingError("content_length_mismatch")
        if "x-request-id" in headers and headers["x-request-id"] != request_id:
            raise RenderingError("response_request_id_mismatch")
        headers["content-length"] = str(size)
        headers["x-request-id"] = request_id
        return tuple(headers.items())
