"""G4 隔離候選：可信 Gateway 以雙重 mTLS 消費 Receipt 並轉送原生 HTTP。"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import ssl
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
import httpx
import uvicorn

from deception.api.fingerprint import fingerprint_request, FINGERPRINT_HEADERS
from deception.api.ingress import NormalizedRequest, normalize_request, resolve_request_id
from deception.world.transmission import response_envelope
from mirage_validator.json_utils import reject_constant, unique_object

from .protected_rpc import ProtectedRpcConfigurationError, require_mtls_files


class GatewayNativeProxyUnverifiable(RuntimeError):
    """驗證、授權或傳輸結果不明；同 Receipt 不可由 Gateway 再次起送。"""


@dataclass(frozen=True)
class GatewayAuthorizedReceipt:
    """只能由受信任 Verifier mTLS 回應與原始 Client 指紋共同形成的內部憑據。"""

    receipt_id: UUID
    candidate_hash: str


@dataclass(frozen=True)
class GatewayNativeHTTP:
    """Gateway 已用原 Authorizer Hash 驗證的 Sender 原生 status／ordered headers／bytes。"""

    status_code: int
    raw_headers: tuple[tuple[bytes, bytes], ...]
    body: bytes


def _fixed_mtls_origin(*, origin: str, client_cert: Path, client_key: Path,
                       server_ca: Path) -> tuple[str, ssl.SSLContext]:
    """拒絕可注入路由的 URL，且憑證與根 CA 必須是三個不同實體檔案。"""
    parsed = urlsplit(origin) if isinstance(origin, str) else None
    if (parsed is None or parsed.scheme != "https" or not parsed.hostname
            or parsed.port is None or parsed.path not in {"", "/"}
            or parsed.query or parsed.fragment
            or parsed.username is not None or parsed.password is not None):
        raise ProtectedRpcConfigurationError("gateway_fixed_mtls_origin_invalid")
    require_mtls_files(server_cert=client_cert, server_key=client_key, client_ca=server_ca)
    context = ssl.create_default_context(cafile=str(server_ca))
    context.load_cert_chain(str(client_cert), str(client_key))
    if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
        raise ProtectedRpcConfigurationError("gateway_fixed_mtls_verification_required")
    return origin.rstrip("/"), context


class FixedGatewayVerifierMTLSClient:
    """Gateway 將 Client 原始 HTTP 直送獨立 Verifier，驗證完整 Receipt 授權鏈。"""

    def __init__(self, *, origin: str, client_cert: Path, client_key: Path,
                 server_ca: Path) -> None:
        """固定 Verifier 伺服器身分與專用 Client CA，不接受 Runtime 代理標頭。"""
        self._origin, self._tls = _fixed_mtls_origin(
            origin=origin, client_cert=client_cert, client_key=client_key,
            server_ca=server_ca,
        )

    async def verify_original(self, request: NormalizedRequest) -> GatewayAuthorizedReceipt:
        """逐 byte 轉送原請求並要求 Receipt→Promotion→Authorizer 與原指紋一致。"""
        if (not isinstance(request, NormalizedRequest)
                or request.method not in {"GET", "POST", "DELETE"}
                or not request.raw_path.startswith(b"/")
                or len(request.raw_path) > 4096
                or any(value > 127 for value in request.raw_path)
                or b"?" in request.raw_path or b"#" in request.raw_path
                or any(value > 127 for value in request.query_string)
                or len(request.query_string) > 4096):
            raise GatewayNativeProxyUnverifiable("gateway_original_request_invalid")
        relevant = [(name.lower(), value) for name, value in request.headers
                    if name.lower() in FINGERPRINT_HEADERS]
        if sum(name == "host" for name, _ in relevant) != 1:
            raise GatewayNativeProxyUnverifiable("gateway_original_host_ambiguous")
        try:
            expected_fingerprint = fingerprint_request(request)
            path = request.raw_path.decode("ascii")
            query = ("?" + request.query_string.decode("ascii")) if request.query_string else ""
            url = self._origin + path + query
            # 不讓 HTTPX 為沒有 Body 的 GET／DELETE 自動新增 Content-Length: 0。
            kwargs = ({"content": request.body}
                      if request.method == "POST" or request.body else {})
            async with httpx.AsyncClient(verify=self._tls, trust_env=False,
                                         timeout=8.0, follow_redirects=False) as client:
                outbound = client.build_request(
                    request.method, url, headers=list(request.headers), **kwargs)
                forwarded = [(name.decode("latin-1").lower(), value.decode("latin-1"))
                             for name, value in outbound.headers.raw
                             if name.decode("latin-1").lower() in FINGERPRINT_HEADERS]
                if (forwarded != relevant
                        or outbound.url.raw_path.partition(b"?")[0] != request.raw_path):
                    raise GatewayNativeProxyUnverifiable("gateway_original_http_rewritten")
                response = await client.send(outbound)
        except (ValueError, UnicodeError, httpx.HTTPError) as exc:
            raise GatewayNativeProxyUnverifiable("gateway_verifier_transport_unverifiable") from exc
        if response.status_code != 200 or len(response.content) > 65536:
            raise GatewayNativeProxyUnverifiable("gateway_verifier_unverifiable")
        try:
            data = json.loads(response.content, object_pairs_hook=unique_object,
                              parse_constant=reject_constant)
            if (not isinstance(data, dict) or not isinstance(data.get("receipt_id"), str)
                    or not isinstance(data.get("candidate_promotion"), dict)
                    or not isinstance(data.get("receipt_authorization"), dict)):
                raise ValueError("gateway_receipt_chain_invalid")
            receipt = UUID(data["receipt_id"])
            promotion = data["candidate_promotion"]
            authorization = data["receipt_authorization"]
            candidate_hash = promotion.get("candidate_hash")
            if (receipt.version != 4
                    or authorization.get("receipt_id") != str(receipt)
                    or promotion.get("receipt_id") != str(receipt)
                    or authorization.get("request_fingerprint") != expected_fingerprint
                    or authorization.get("candidate_hash") != candidate_hash
                    or authorization.get("send_owner") != "protected-sender-" + receipt.hex
                    or authorization.get("trusted_send") != "disabled"
                    or not isinstance(candidate_hash, str)
                    or re.fullmatch(r"[0-9a-f]{64}", candidate_hash) is None):
                raise ValueError("gateway_receipt_chain_mismatch")
        except (ValueError, TypeError, KeyError) as exc:
            raise GatewayNativeProxyUnverifiable("gateway_receipt_chain_unverifiable") from exc
        return GatewayAuthorizedReceipt(receipt, candidate_hash)


class FixedGatewaySenderMTLSClient:
    """可信 Gateway 只傳 Receipt ID，驗證 Sender 的原生 HTTP Hash 後才給 Client。"""

    def __init__(self, *, origin: str, client_cert: Path, client_key: Path,
                 server_ca: Path) -> None:
        """固定 Sender 的另一組 mTLS 憑證，不允許 Runtime 選擇 URL 或 Payload。"""
        self._origin, self._tls = _fixed_mtls_origin(
            origin=origin, client_cert=client_cert, client_key=client_key,
            server_ca=server_ca,
        )

    async def emit_receipt_once(self, pin: GatewayAuthorizedReceipt) -> GatewayNativeHTTP:
        """一次 POST 後比對 immutable envelope；任何網路未知都不得重送。

        只刪除 Uvicorn/H11 注入的 transport-only headers。若原生回應本身
        含有同名 Header，Hash 比對會失敗並保持不可重送，不會默默改寫。
        """
        if (not isinstance(pin, GatewayAuthorizedReceipt)
                or not isinstance(pin.receipt_id, UUID) or pin.receipt_id.version != 4
                or not isinstance(pin.candidate_hash, str)
                or re.fullmatch(r"[0-9a-f]{64}", pin.candidate_hash) is None):
            raise GatewayNativeProxyUnverifiable("gateway_sender_pin_invalid")
        try:
            async with httpx.AsyncClient(verify=self._tls, trust_env=False,
                                         timeout=8.0, follow_redirects=False) as client:
                async with client.stream(
                    "POST", self._origin + "/internal/v1/emit-receipt",
                    json={"receipt_id": str(pin.receipt_id)},
                    headers={"accept-encoding": "identity"},
                ) as response:
                    body = bytearray()
                    async for chunk in response.aiter_raw():
                        if len(body) + len(chunk) > 8 * 1024 * 1024:
                            raise GatewayNativeProxyUnverifiable("gateway_sender_body_exceeds_limit")
                        body.extend(chunk)
                    # H11 會加 date/server/transfer-encoding；這些不在 Sender
                    # 的不可變業務 Envelope 內。其餘 headers 保留原始順序。
                    headers = tuple((name, value) for name, value in response.headers.raw
                                    if name.lower() not in {
                                        b"date", b"server", b"transfer-encoding",
                                        b"connection", b"keep-alive",
                                    })
                    expected = response_envelope(
                        response.status_code,
                        [(name.decode("ascii"), value.decode("latin-1"))
                         for name, value in headers], bytes(body),
                    )
                    if hashlib.sha256(expected).hexdigest() != pin.candidate_hash:
                        raise GatewayNativeProxyUnverifiable("gateway_sender_hash_mismatch")
                    return GatewayNativeHTTP(response.status_code, headers, bytes(body))
        except (httpx.HTTPError, UnicodeError, ValueError) as exc:
            raise GatewayNativeProxyUnverifiable("gateway_sender_transport_unverifiable") from exc


def create_gateway_native_proxy_candidate_app(*, verifier_client, sender_client) -> FastAPI:
    """隔離候選；正式 CLI 仍不裝載此 Gateway，未經 Gate 不可對公網監聽。"""
    if (not isinstance(verifier_client, FixedGatewayVerifierMTLSClient)
            or not isinstance(sender_client, FixedGatewaySenderMTLSClient)):
        raise ProtectedRpcConfigurationError("gateway_native_proxy_clients_required")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/internal/ready")
    async def ready() -> dict[str, str]:
        """只標示候選 App 的隔離存活，不宣布 DECEIVE 或 Trusted Send 啟用。"""
        return {"control_plane": "gateway-native-proxy-candidate", "trusted_send": "disabled"}

    @app.api_route("/{original_path:path}", methods=["GET", "POST", "DELETE"])
    async def relay(request: Request, original_path: str) -> Response:
        """只由 Verifier 授權 Receipt 驅動 Sender，Gateway 不產生業務 HTTP bytes。"""
        if request.scope.get("scheme") != "https":
            raise HTTPException(503, "gateway_client_tls_required")
        if request.url.path.startswith("/internal/"):
            raise HTTPException(404, "gateway_internal_route_denied")
        if len(request.headers.getlist("x-request-id")) != 1:
            raise HTTPException(403, "gateway_request_id_required")
        if len(request.headers.getlist("x-trusted-session")) != 1:
            raise HTTPException(403, "gateway_signed_session_required")
        normalized = await normalize_request(request, resolve_request_id(request))
        try:
            pinned = await verifier_client.verify_original(normalized)
            native = await sender_client.emit_receipt_once(pinned)
        except GatewayNativeProxyUnverifiable:
            # 不能知道 Sender 是否已消費唯一 Lease；不重試、不輸出 Sender
            # 的錯誤本文，也不把內部 503 誤當成核准的業務 503。
            return JSONResponse(status_code=503, content={"detail": "gateway_delivery_unverifiable"})
        response = Response(content=native.body, status_code=native.status_code)
        response.raw_headers = list(native.raw_headers)
        return response

    return app


def serve_gateway_native_proxy_loopback_tls(*, app: FastAPI, host: str, port: int,
                                            server_cert: Path, server_key: Path) -> None:
    """僅供隔離實驗的真 Client TLS 入口，絕不允許公網 bind 或正式 CLI 載入。"""
    if (not isinstance(app, FastAPI) or host not in {"127.0.0.1", "::1"}
            or type(port) is not int or not 1 <= port <= 65535
            or not isinstance(server_cert, Path) or not server_cert.is_file()
            or not isinstance(server_key, Path) or not server_key.is_file()
            or server_cert.resolve() == server_key.resolve()):
        raise ProtectedRpcConfigurationError("gateway_candidate_loopback_tls_required")
    config = uvicorn.Config(
        app, host=host, port=port, ssl_certfile=str(server_cert),
        ssl_keyfile=str(server_key), ssl_cert_reqs=ssl.CERT_NONE,
        ssl_version=ssl.PROTOCOL_TLS_SERVER, http="h11", log_level="warning",
        proxy_headers=False, access_log=False,
    )
    uvicorn.Server(config).run()
