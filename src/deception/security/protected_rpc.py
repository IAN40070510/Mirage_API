"""受保護業務服務的獨立 mTLS 傳輸入口；業務 RPC 未驗收前一律 sealed。"""

from __future__ import annotations

import os
from pathlib import Path
import ssl

from fastapi import FastAPI
import uvicorn


class ProtectedRpcConfigurationError(ValueError):
    """mTLS 憑證、受信任 Client CA 或隔離設定不完整時拒絕啟動。"""


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
    )
    if config.ssl_cert_reqs is not ssl.CERT_REQUIRED:
        raise ProtectedRpcConfigurationError("protected_rpc_mtls_not_required")
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
