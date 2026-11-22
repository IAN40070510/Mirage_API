"""受保護業務服務的獨立 mTLS 傳輸入口；業務 RPC 未驗收前一律 sealed。"""

from __future__ import annotations

import os
from pathlib import Path
import ssl

from fastapi import FastAPI, HTTPException, Request
import uvicorn


class ProtectedRpcConfigurationError(ValueError):
    """mTLS 憑證、受信任 Client CA 或隔離設定不完整時拒絕啟動。"""


def create_direct_verifier_app(
    *, verifier, postgres_dsn: str, environment_id: str, deployment_id: str,
    expected_issuer: str, expected_audience: str,
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
    if not isinstance(postgres_dsn, str) or not postgres_dsn.strip():
        raise ProtectedRpcConfigurationError("direct_verifier_requires_db")
    if any(not isinstance(value, str) or not 1 <= len(value) <= 128 for value in (
            environment_id, deployment_id, expected_issuer, expected_audience)):
        raise ProtectedRpcConfigurationError("direct_verifier_identity_invalid")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/internal/ready")
    async def ready() -> dict[str, str]:
        """只證明內部 Verifier HTTP Listener 存活，正式發送仍封閉。"""
        return {"control_plane": "verifier-only", "trusted_send": "disabled"}

    @app.post("/internal/v1/execute")
    async def execute_disabled() -> dict[str, str]:
        """阻擋將 Verifier 誤作可由 Runtime 指定 Handler 的業務 RPC。"""
        raise HTTPException(status_code=503, detail="direct_verifier_execution_not_available")

    @app.api_route("/{original_path:path}", methods=["GET", "POST", "DELETE"])
    async def verify_original(request: Request, original_path: str) -> dict[str, str]:
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
        # 不能在 HTTP 回應暴露驗證後 claims 或受保護 DB Secret。
        return {"receipt_id": str(receipt_id), "operation_id": operation.operation_id}

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
