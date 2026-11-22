"""受保護業務服務的獨立 mTLS 傳輸入口；業務 RPC 未驗收前一律 sealed。"""

from __future__ import annotations

import base64
import binascii
import json
import os
from pathlib import Path
import ssl
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request
import httpx
from pydantic import Field, UUID4
import uvicorn

from deception.common.models import SyntheticModel
from deception.api.fingerprint import FINGERPRINT_HEADERS
from deception.api.ingress import NormalizedRequest
from mirage_validator.json_utils import reject_constant, unique_object


class ProtectedRpcConfigurationError(ValueError):
    """mTLS 憑證、受信任 Client CA 或隔離設定不完整時拒絕啟動。"""


class FixedOriginalHTTP(SyntheticModel):
    """轉送只影響已驗證 Fingerprint 的原始 HTTP 欄位，不包含 Trusted JWS。"""

    request_id: str = Field(min_length=1, max_length=128)
    raw_url: str = Field(min_length=1, max_length=4096)
    headers: tuple[tuple[str, str], ...] = Field(max_length=32)


class FixedExecutorCall(SyntheticModel):
    """只接收 Receipt 身份與原始 HTTP bytes，不接受操作／Scope／權限欄位。"""

    receipt_id: UUID4
    raw_path_b64: str = Field(min_length=4, max_length=4096)
    raw_body_b64: str = Field(max_length=1398108)
    original_http: FixedOriginalHTTP | None = None


class FixedNativeProjectionCall(SyntheticModel):
    """獨立 Validator 僅允許查不可變 Receipt，不接受 Runtime 候選 Status 或 Body。"""

    receipt_id: UUID4


class FixedExecutorMTLSClient:
    """獨立 Verifier 用專屬 Client Cert 對已固定 Receipt 單次呼叫 Executor。"""

    def __init__(self, *, origin: str, client_cert: Path, client_key: Path,
                 server_ca: Path) -> None:
        """固定 HTTPS Server 身份與專屬 Verifier 私鑰，拒絕明文／URL 注入。

        不共用 HTTP Runtime Secret，不提供重試或可變 Handler 參數；
        如果 Executor COMMIT ACK 遺失，上游只能進入 UNVERIFIABLE 對帳。
        """
        if not isinstance(origin, str):
            raise ProtectedRpcConfigurationError("fixed_executor_origin_invalid")
        url = urlsplit(origin)
        if (url.scheme != "https" or not url.hostname or url.port is None
                or url.path not in {"", "/"} or url.query or url.fragment
                or url.username is not None or url.password is not None):
            raise ProtectedRpcConfigurationError("fixed_executor_origin_invalid")
        require_mtls_files(server_cert=client_cert, server_key=client_key, client_ca=server_ca)
        context = ssl.create_default_context(cafile=str(server_ca))
        context.load_cert_chain(str(client_cert), str(client_key))
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise ProtectedRpcConfigurationError("fixed_executor_server_verification_required")
        self._origin = origin.rstrip("/")
        self._tls = context

    async def execute_receipt(self, *, receipt_id: UUID, operation_id: str,
                              raw_path: bytes, raw_body: bytes,
                              original_request: NormalizedRequest | None = None) -> dict[str, object]:
        """只傳不可變 Receipt／原始 Bytes，單次 mTLS 呼叫且拒絕回應操作錯綁。"""
        payload = {"receipt_id": str(receipt_id),
                   "raw_path_b64": base64.b64encode(raw_path).decode("ascii"),
                   "raw_body_b64": base64.b64encode(raw_body).decode("ascii")}
        if original_request is not None:
            payload["original_http"] = {
                "request_id": original_request.request_id,
                "raw_url": original_request.raw_url,
                "headers": [(name, value) for name, value in original_request.headers
                            if name.lower() in FINGERPRINT_HEADERS],
            }
        async with httpx.AsyncClient(verify=self._tls, trust_env=False, timeout=8.0) as client:
            response = await client.post(self._origin + "/internal/v1/execute", json=payload)
        if response.status_code != 200:
            raise ProtectedRpcConfigurationError("fixed_executor_result_unverifiable")
        try:
            result = response.json()
        except ValueError as exc:
            raise ProtectedRpcConfigurationError("fixed_executor_result_invalid") from exc
        fields = {
            "world_mutation": {"kind", "operation", "commit_attempt_id", "status",
                               "state_version", "state_hash", "result_digest"},
            "cart_created": {"kind", "operation", "resource_id", "commit_attempt_id", "status"},
            "cart_read_admitted": {"kind", "operation", "resource_id", "attempt_id",
                                   "world_generation_id", "state_version", "state_hash"},
            "medusa_rejection": {"kind", "operation", "status_code", "template_id",
                                 "contract_revision", "envelope_hash"},
        }
        if (not isinstance(result, dict) or result.get("operation") != operation_id
                or result.get("kind") not in fields
                or set(result) != fields[result["kind"]]
                or (result["kind"] == "world_mutation" and result.get("status") not in {
                    "committed", "already_committed", "rejected"})
                or (result["kind"] == "medusa_rejection" and
                    (result.get("status_code") not in {400, 404}
                     or result.get("template_id") not in {"native-cart-invalid", "native-cart-rejected"}
                     or result.get("contract_revision") != "medusa-cart-1"))
                or (result["kind"] == "cart_created" and result.get("status") != "committed")):
            raise ProtectedRpcConfigurationError("fixed_executor_result_binding_mismatch")
        return result


class FixedNativeValidatorMTLSClient:
    """Verifier 以第三條專用 mTLS 邊驗證受保護 Medusa 原生候選封套。"""

    def __init__(self, *, origin: str, client_cert: Path, client_key: Path,
                 server_ca: Path) -> None:
        """固定 HTTPS Validator 身份與憑證，禁止 URL 帶路徑／Userinfo／明文。"""
        parsed = urlsplit(origin) if isinstance(origin, str) else None
        if (parsed is None or parsed.scheme != "https" or not parsed.hostname
                or parsed.port is None or parsed.path not in {"", "/"}
                or parsed.query or parsed.fragment or parsed.username or parsed.password):
            raise ProtectedRpcConfigurationError("native_validator_origin_invalid")
        require_mtls_files(server_cert=client_cert, server_key=client_key, client_ca=server_ca)
        context = ssl.create_default_context(cafile=str(server_ca))
        context.load_cert_chain(str(client_cert), str(client_key))
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise ProtectedRpcConfigurationError("native_validator_server_verification_required")
        self._origin = origin.rstrip("/")
        self._tls = context

    async def project_receipt(self, *, receipt_id: UUID, operation_id: str,
                              request_fingerprint: str, expected_status: int,
                              expected_envelope_hash: str) -> dict[str, object]:
        """只用受保護 Executor 結果綁定獨立投影，拒絕任何封套替換或非正規 Base64。"""
        from deception.world.transmission import response_hashes

        async with httpx.AsyncClient(verify=self._tls, trust_env=False, timeout=8.0) as client:
            response = await client.post(
                self._origin + "/internal/v1/project-medusa-rejection",
                json={"receipt_id": str(receipt_id)},
            )
        if response.status_code != 200:
            raise ProtectedRpcConfigurationError("native_validator_projection_unverifiable")
        try:
            result = json.loads(response.content, object_pairs_hook=unique_object,
                                parse_constant=reject_constant)
            if not isinstance(result, dict) or set(result) != {
                    "receipt_id", "operation_id", "scope", "request_fingerprint",
                    "status_code", "headers", "body_b64", "envelope_hash", "source",
                    "trusted_send"}:
                raise ValueError("native_validator_response_shape_invalid")
            body = _canonical_base64(result["body_b64"], max_bytes=4096)
            headers = result["headers"]
            if (headers != [["content-type", "application/json"]]
                    or result["receipt_id"] != str(receipt_id)
                    or result["operation_id"] != operation_id
                    or result["request_fingerprint"] != request_fingerprint
                    or type(result["status_code"]) is not int
                    or result["status_code"] != expected_status
                    or expected_status not in {400, 404}
                    or result["envelope_hash"] != expected_envelope_hash
                    or result["trusted_send"] != "disabled"
                    or result["source"] != {
                        "kind": "security_error",
                        "template_id": "native-cart-invalid" if expected_status == 400 else "native-cart-rejected",
                        "contract_revision": "medusa-cart-1",
                    }
                    or not isinstance(result["scope"], dict)
                    or set(result["scope"]) != {
                        "environment_id", "deployment_id", "session_id", "world_generation_id"}
                    or any(not isinstance(value, str) or not value for value in result["scope"].values())
                    or response_hashes(expected_status, (("content-type", "application/json"),), body)[0]
                    != expected_envelope_hash):
                raise ValueError("native_validator_projection_binding_mismatch")
        except (ValueError, KeyError, TypeError) as exc:
            raise ProtectedRpcConfigurationError("native_validator_projection_binding_mismatch") from exc
        return {"status_code": expected_status,
                "envelope_hash": expected_envelope_hash,
                "body_sha256": response_hashes(expected_status, (("content-type", "application/json"),), body)[1]}


def _canonical_base64(raw: str, *, max_bytes: int) -> bytes:
    """嚴格拒絕替代編碼與超大資料，避免 RPC 與 Verifier 解析分歧。"""
    if not isinstance(raw, str) or not raw.isascii():
        raise ValueError("invalid_base64_rpc_field")
    try:
        decoded = base64.b64decode(raw, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid_base64_rpc_field") from exc
    if len(decoded) > max_bytes or base64.b64encode(decoded).decode("ascii") != raw:
        raise ValueError("invalid_base64_rpc_field")
    return decoded


def create_fixed_executor_app(*, executor) -> FastAPI:
    """隔離 Executor mTLS 專用 HTTP 入口，所有 Handler／Scope 由 DB Receipt 決定。

    不接受 Runtime 自選 operation、binding、expected version 或初始世界。
    這個 App 僅准在專用 mTLS Listener 與實體 Executor SCRAM Role 執行；
    正式 Send Release Fuse 仍維持封閉，Medusa 未具 400/404 來源時禁止執行。
    """
    from deception.world.protected_world import PostgresProtectedWorldExecutor

    if not isinstance(executor, PostgresProtectedWorldExecutor):
        raise ProtectedRpcConfigurationError("fixed_executor_requires_protected_world")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/internal/ready")
    async def ready() -> dict[str, str]:
        """表明隔離固定 Handler RPC 已掛載，正式傳輸依舊關閉。"""
        return {"control_plane": "executor-lab-only", "trusted_send": "disabled"}

    @app.post("/internal/v1/execute")
    async def execute(request: Request) -> dict[str, object]:
        """從唯一 Receipt 與原始 bytes 在獨立 Executor 取回受保護業務結果。

        RPC 內容重複 JSON 欄位、替代 base64、超大封包或平台／操作不一致，
        在操作前拒絕；任何不明 COMMIT 只回固定 503，不重新起送。
        回傳只供獨立服務對帳，不得直接當成已授權 Client HTTP Response。
        """
        from deception.api.ingress import MAX_BODY_BYTES

        if request.scope.get("scheme") != "https":
            raise HTTPException(status_code=503, detail="fixed_executor_tls_required")
        received = bytearray()
        async for chunk in request.stream():
            if len(received) + len(chunk) > MAX_BODY_BYTES * 2:
                raise HTTPException(status_code=413, detail="fixed_executor_rpc_too_large")
            received.extend(chunk)
        try:
            parsed = json.loads(received, object_pairs_hook=unique_object,
                                parse_constant=reject_constant)
            if not isinstance(parsed, dict):
                raise ValueError("fixed_executor_rpc_object_required")
            # strict UUID4 模型允許 JSON 字串 UUID，但不接受 Python 字串隱式轉型。
            call = FixedExecutorCall.model_validate_json(bytes(received))
            path = _canonical_base64(call.raw_path_b64, max_bytes=2048)
            body = _canonical_base64(call.raw_body_b64, max_bytes=MAX_BODY_BYTES)
            original = None
            if call.original_http is not None:
                if any(name.lower() not in FINGERPRINT_HEADERS
                       or not name.isascii() or "\r" in value or "\n" in value
                       for name, value in call.original_http.headers):
                    raise ValueError("fixed_executor_original_headers_denied")
                original = NormalizedRequest(
                    request_id=call.original_http.request_id,
                    method="", raw_url=call.original_http.raw_url,
                    path="", raw_path=path, query_string=b"", query=(),
                    headers=call.original_http.headers, body=body,
                )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="fixed_executor_rpc_invalid") from exc
        try:
            return executor.execute_verified_http(
                receipt_id=UUID(str(call.receipt_id)), raw_path=path, raw_body=body,
                original_http=original,
            )
        except Exception as exc:
            # 不泄露受保護 DB／業務／重試細節；不可把未知 COMMIT 當安全重試。
            raise HTTPException(status_code=503, detail="fixed_executor_unverifiable") from exc

    return app


def create_native_validator_app(*, projector) -> FastAPI:
    """在專用 Validator mTLS 入口重建受保護的 Medusa 原生拒絕候選。

    只接受 Receipt，不接受 Caller 指定模板、Scope、Status 或 Payload。
    回傳的是內部候選交接資料，**不能**作為已授權的客戶端 HTTP 回應。
    """
    from deception.world.protected_native_http import PostgresProtectedNativeProjector

    if not isinstance(projector, PostgresProtectedNativeProjector):
        raise ProtectedRpcConfigurationError("native_validator_requires_protected_projector")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/internal/ready")
    async def ready() -> dict[str, str]:
        """只回報 Validator 已掛載且 Sender 關閉，不承諾來源或 Profile 已核准。"""
        return {"control_plane": "native-validator-candidate-only", "trusted_send": "disabled"}

    @app.post("/internal/v1/project-medusa-rejection")
    async def project(request: Request) -> dict[str, object]:
        """將精確 Receipt 的受保護 Read／Rejection 轉成不可直接發送的 JSON 封套。"""
        if request.scope.get("scheme") != "https":
            raise HTTPException(status_code=503, detail="native_validator_tls_required")
        received = bytearray()
        async for chunk in request.stream():
            if len(received) + len(chunk) > 1024:
                raise HTTPException(status_code=413, detail="native_validator_request_too_large")
            received.extend(chunk)
        try:
            parsed = json.loads(received, object_pairs_hook=unique_object,
                                parse_constant=reject_constant)
            if not isinstance(parsed, dict):
                raise ValueError("native_validator_object_required")
            call = FixedNativeProjectionCall.model_validate_json(received)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="native_validator_request_invalid") from exc
        try:
            projected = projector.project_medusa_rejection(UUID(str(call.receipt_id)))
        except Exception as exc:
            raise HTTPException(status_code=503, detail="native_validator_source_unverifiable") from exc
        return {
            "receipt_id": str(projected.receipt_id), "operation_id": projected.operation_id,
            "scope": projected.scope.model_dump(),
            "request_fingerprint": projected.request_fingerprint,
            "status_code": projected.status_code,
            "headers": list(projected.headers),
            "body_b64": base64.b64encode(projected.body_bytes).decode("ascii"),
            "envelope_hash": projected.envelope_hash,
            "source": projected.source.model_dump(),
            "trusted_send": "disabled",
        }

    return app


def create_direct_verifier_app(
    *, verifier, postgres_dsn: str, environment_id: str, deployment_id: str,
    expected_issuer: str, expected_audience: str,
    executor_client: FixedExecutorMTLSClient | None = None,
    executor_clients: Mapping[str, FixedExecutorMTLSClient] | None = None,
    native_validator_client: FixedNativeValidatorMTLSClient | None = None,
) -> FastAPI:
    """在獨立 Gateway mTLS 入口由實際 HTTP 訊息建立受保護 Operation Receipt。

    直接使用 ASGI 原始 path/header/body；不接受 Runtime 送入的 claims、
    已驗證旗標、Handler 名稱或用 JSON 重建的 Request。只提供內部 Receipt
    身份，不建立候選、不執行業務且絕不核發正式 HTTP Send 權。
    專用 Client CA 必須只簽發給原始 HTTP Gateway，不能供 Runtime 使用。
    """
    from deception.security.trusted_session import TrustedSessionVerifier

    if not isinstance(verifier, TrustedSessionVerifier):
        raise ProtectedRpcConfigurationError("direct_verifier_requires_trusted_verifier")
    if executor_client is not None and not isinstance(executor_client, FixedExecutorMTLSClient):
        raise ProtectedRpcConfigurationError("direct_verifier_executor_client_invalid")
    if executor_client is not None and executor_clients is not None:
        raise ProtectedRpcConfigurationError("direct_verifier_executor_routes_ambiguous")
    if native_validator_client is not None and not isinstance(native_validator_client, FixedNativeValidatorMTLSClient):
        raise ProtectedRpcConfigurationError("direct_verifier_native_validator_invalid")
    if executor_clients is not None and (
            not isinstance(executor_clients, Mapping) or not executor_clients
            or any(platform not in {"synthetic-inventory", "synthetic-carts", "medusa-native-cart"}
                   or not isinstance(client, FixedExecutorMTLSClient)
                   for platform, client in executor_clients.items())):
        raise ProtectedRpcConfigurationError("direct_verifier_executor_routes_invalid")
    fixed_clients = MappingProxyType(dict(executor_clients or {}))
    if not isinstance(postgres_dsn, str) or not postgres_dsn.strip():
        raise ProtectedRpcConfigurationError("direct_verifier_requires_db")
    if any(not isinstance(value, str) or not 1 <= len(value) <= 128 for value in (
            environment_id, deployment_id, expected_issuer, expected_audience)):
        raise ProtectedRpcConfigurationError("direct_verifier_identity_invalid")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/internal/ready")
    async def ready() -> dict[str, str]:
        """只證明內部 Verifier HTTP Listener 存活，正式發送仍封閉。"""
        return {"control_plane": "verifier-dispatch" if executor_client or fixed_clients else "verifier-only",
                "trusted_send": "disabled"}

    @app.post("/internal/v1/execute")
    async def execute_disabled() -> dict[str, str]:
        """阻擋將 Verifier 誤作可由 Runtime 指定 Handler 的業務 RPC。"""
        raise HTTPException(status_code=503, detail="direct_verifier_execution_not_available")

    @app.api_route("/{original_path:path}", methods=["GET", "POST", "DELETE"])
    async def verify_original(request: Request, original_path: str) -> dict[str, object]:
        """先從 ASGI 取得可信原始快照，再驗簽並原子記錄 Replay／Receipt／Operation。

        不接受 http／proxy header 模擬 TLS；只有 mTLS Listener 的真實 HTTPS
        Scope 可以進入。結果供專用 Gateway 對帳及日後獨立 Executor 使用；
        這裡不返回業務 200／400／404 或任何可被當成已授權的 Payload。
        """
        from deception.api.fingerprint import fingerprint_request
        from deception.api.ingress import normalize_request, resolve_request_id
        from deception.security.ingress_receipt import PostgresIngressReceiptWriter
        from deception.security.operation_binding import derive_verified_operation

        if request.scope.get("scheme") != "https":
            raise HTTPException(status_code=503, detail="direct_verifier_tls_required")
        normalized = await normalize_request(request, resolve_request_id(request))
        try:
            operation = derive_verified_operation(normalized)
            if fixed_clients and operation.platform not in fixed_clients:
                raise HTTPException(status_code=503,
                                    detail="direct_verifier_executor_platform_unavailable")
            tokens = [value for name, value in normalized.headers
                      if name.lower() == "x-trusted-session"]
            if len(tokens) != 1 or not tokens[0]:
                raise ValueError("trusted_session_header_missing_or_duplicate")
            writer = PostgresIngressReceiptWriter(
                postgres_dsn, environment_id=environment_id,
                deployment_id=deployment_id, verified_request=normalized,
            )
            _, receipt_id = verifier.verify_with_receipt(
                tokens[0], expected_issuer=expected_issuer,
                expected_audience=expected_audience,
                request_fingerprint=fingerprint_request(normalized),
                environment_id=environment_id, deployment_id=deployment_id,
                receipt_writer=writer,
            )
        except ValueError as exc:
            raise HTTPException(status_code=403, detail="direct_verifier_request_denied") from exc
        # 已建立 Receipt 後的 RPC 結果不明，不能重新消費 JTI 或盲目重執行。
        outcome = None
        selected_client = (fixed_clients.get(operation.platform) if fixed_clients else executor_client)
        if selected_client is not None:
            try:
                outcome = await selected_client.execute_receipt(
                    receipt_id=receipt_id, operation_id=operation.operation_id,
                    raw_path=normalized.raw_path, raw_body=normalized.body,
                    original_request=normalized,
                )
            except Exception as exc:
                raise HTTPException(status_code=503,
                                    detail="direct_verifier_executor_unverifiable") from exc
        projection = None
        if isinstance(outcome, dict) and outcome.get("kind") == "medusa_rejection":
            if native_validator_client is None:
                raise HTTPException(status_code=503,
                                    detail="direct_verifier_native_validator_not_wired")
            try:
                projection = await native_validator_client.project_receipt(
                    receipt_id=receipt_id, operation_id=operation.operation_id,
                    request_fingerprint=fingerprint_request(normalized),
                    expected_status=outcome["status_code"],
                    expected_envelope_hash=outcome["envelope_hash"],
                )
            except Exception as exc:
                raise HTTPException(status_code=503,
                                    detail="direct_verifier_native_projection_unverifiable") from exc
        # 不能在 HTTP 回應暴露已驗證 claims 或受保護 DB Secret；此結果非 Sender。
        result: dict[str, object] = {"receipt_id": str(receipt_id),
                                     "operation_id": operation.operation_id}
        if outcome is not None:
            result["executor_result"] = outcome
        if projection is not None:
            result["native_projection"] = projection
        return result

    return app


def require_mtls_files(*, server_cert: Path, server_key: Path, client_ca: Path) -> None:
    """確認三種不同用途的 TLS 檔案都已存在且不是同一個實體檔案。

    憑證與 key 必須由部署管理者透過唯讀 Secret Mount 提供；不建立預設
    自簽憑證，也不接受以 request headers 模擬 client identity。
    """
    paths = (server_cert, server_key, client_ca)
    if any(not isinstance(path, Path) or not path.is_file() for path in paths):
        raise ProtectedRpcConfigurationError("protected_rpc_mtls_files_required")
    if len({path.resolve() for path in paths}) != 3:
        raise ProtectedRpcConfigurationError("protected_rpc_mtls_file_reuse_denied")
    for path in paths:
        if path.stat().st_size == 0:
            raise ProtectedRpcConfigurationError("protected_rpc_empty_mtls_file")


def create_sealed_app() -> FastAPI:
    """提供不含敏感資料的控制面健康檢查；禁止一切尚未核准的業務呼叫。"""
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/internal/ready")
    async def ready() -> dict[str, str]:
        """表明 mTLS 傳輸已啟動，但執行與發送權仍然關閉。"""
        return {"control_plane": "sealed", "trusted_send": "disabled"}

    @app.post("/internal/v1/execute")
    async def execute_disabled() -> dict[str, str]:
        """拒絕未完成 Receipt/Operation 綁定的任意 RPC，不處理請求副作用。"""
        from fastapi import HTTPException

        raise HTTPException(status_code=503, detail="protected_rpc_operation_binding_not_ready")

    return app


def serve_sealed_mtls(*, host: str, port: int, server_cert: Path,
                      server_key: Path, client_ca: Path) -> None:
    """以 TLS Client Certificate Required 啟動專屬服務，拒絕普通 HTTPS 客戶端。

    服務只提供 sealed endpoint；獨立 Executor 憑證及其資料庫連線不得在
    HTTP Runtime 程序環境中配置。不能把此函式當作 G3b 業務接線成功。
    """
    require_mtls_files(server_cert=server_cert, server_key=server_key, client_ca=client_ca)
    if not isinstance(host, str) or not host or type(port) is not int or not 1 <= port <= 65535:
        raise ProtectedRpcConfigurationError("protected_rpc_bind_invalid")
    config = uvicorn.Config(
        create_sealed_app(), host=host, port=port,
        ssl_certfile=str(server_cert), ssl_keyfile=str(server_key),
        ssl_ca_certs=str(client_ca), ssl_cert_reqs=ssl.CERT_REQUIRED,
        ssl_version=ssl.PROTOCOL_TLS_SERVER, http="h11", log_level="warning",
        proxy_headers=False,
    )
    if config.ssl_cert_reqs is not ssl.CERT_REQUIRED:
        raise ProtectedRpcConfigurationError("protected_rpc_mtls_not_required")
    uvicorn.Server(config).run()


def serve_direct_verifier_mtls(
    *, app: FastAPI, host: str, port: int, server_cert: Path,
    server_key: Path, client_ca: Path,
) -> None:
    """以獨立 Gateway 專用 Client CA 啟動直接 HTTP Verifier，拒絕非 mTLS 流量。

    呼叫者只能傳入同一專屬 Verifier 程序建立的 App；沒有環境變數可
    自行關閉 Client Cert 驗證，也沒有 generic execute／Sender 後門。
    """
    if not isinstance(app, FastAPI):
        raise ProtectedRpcConfigurationError("direct_verifier_app_required")
    require_mtls_files(server_cert=server_cert, server_key=server_key, client_ca=client_ca)
    if not isinstance(host, str) or not host or type(port) is not int or not 1 <= port <= 65535:
        raise ProtectedRpcConfigurationError("direct_verifier_bind_invalid")
    config = uvicorn.Config(
        app, host=host, port=port,
        ssl_certfile=str(server_cert), ssl_keyfile=str(server_key),
        ssl_ca_certs=str(client_ca), ssl_cert_reqs=ssl.CERT_REQUIRED,
        ssl_version=ssl.PROTOCOL_TLS_SERVER, http="h11", log_level="warning",
        proxy_headers=False, access_log=False,
    )
    if config.ssl_cert_reqs is not ssl.CERT_REQUIRED:
        raise ProtectedRpcConfigurationError("direct_verifier_mtls_not_required")
    uvicorn.Server(config).run()


def serve_fixed_executor_mtls(
    *, app: FastAPI, host: str, port: int, server_cert: Path,
    server_key: Path, verifier_client_ca: Path,
) -> None:
    """使用只信任獨立 Verifier 的 Client CA 啟動 Executor，禁止明文回退。

    此入口目前只供隔離 Lab：執行業務不代表核發候選發送權，Medusa
    400／404 及完整 Gateway→Verifier→Executor 實體拓樸仍須逐項驗收。
    """
    if not isinstance(app, FastAPI):
        raise ProtectedRpcConfigurationError("fixed_executor_app_required")
    require_mtls_files(server_cert=server_cert, server_key=server_key,
                       client_ca=verifier_client_ca)
    if not isinstance(host, str) or not host or type(port) is not int or not 1 <= port <= 65535:
        raise ProtectedRpcConfigurationError("fixed_executor_bind_invalid")
    config = uvicorn.Config(
        app, host=host, port=port,
        ssl_certfile=str(server_cert), ssl_keyfile=str(server_key),
        ssl_ca_certs=str(verifier_client_ca), ssl_cert_reqs=ssl.CERT_REQUIRED,
        ssl_version=ssl.PROTOCOL_TLS_SERVER, http="h11", log_level="warning",
        proxy_headers=False, access_log=False,
    )
    if config.ssl_cert_reqs is not ssl.CERT_REQUIRED:
        raise ProtectedRpcConfigurationError("fixed_executor_mtls_not_required")
    uvicorn.Server(config).run()


def serve_native_validator_mtls(
    *, app: FastAPI, host: str, port: int, server_cert: Path,
    server_key: Path, verifier_client_ca: Path,
) -> None:
    """以獨立 Validator Server TLS 與專屬 Verifier Client CA 啟動只讀候選入口。"""
    if not isinstance(app, FastAPI):
        raise ProtectedRpcConfigurationError("native_validator_app_required")
    require_mtls_files(server_cert=server_cert, server_key=server_key,
                       client_ca=verifier_client_ca)
    if not isinstance(host, str) or not host or type(port) is not int or not 1 <= port <= 65535:
        raise ProtectedRpcConfigurationError("native_validator_bind_invalid")
    config = uvicorn.Config(
        app, host=host, port=port,
        ssl_certfile=str(server_cert), ssl_keyfile=str(server_key),
        ssl_ca_certs=str(verifier_client_ca), ssl_cert_reqs=ssl.CERT_REQUIRED,
        ssl_version=ssl.PROTOCOL_TLS_SERVER, http="h11", log_level="warning",
        proxy_headers=False, access_log=False,
    )
    if config.ssl_cert_reqs is not ssl.CERT_REQUIRED:
        raise ProtectedRpcConfigurationError("native_validator_mtls_not_required")
    uvicorn.Server(config).run()


def from_environment() -> None:
    """只接收專屬 mTLS Secret Mount，預設綁 loopback 且永遠封閉業務執行。"""
    names = ("MIRAGE_PROTECTED_RPC_CERT_FILE", "MIRAGE_PROTECTED_RPC_KEY_FILE",
             "MIRAGE_PROTECTED_RPC_CLIENT_CA_FILE")
    if any(not os.environ.get(name) for name in names):
        raise ProtectedRpcConfigurationError("protected_rpc_mtls_environment_required")
    raw_port = os.environ.get("MIRAGE_PROTECTED_RPC_PORT", "8444")
    if not raw_port.isascii() or not raw_port.isdecimal():
        raise ProtectedRpcConfigurationError("protected_rpc_port_invalid")
    serve_sealed_mtls(
        host=os.environ.get("MIRAGE_PROTECTED_RPC_HOST", "127.0.0.1"),
        port=int(raw_port), server_cert=Path(os.environ[names[0]]),
        server_key=Path(os.environ[names[1]]), client_ca=Path(os.environ[names[2]]),
    )


if __name__ == "__main__":
    from_environment()
