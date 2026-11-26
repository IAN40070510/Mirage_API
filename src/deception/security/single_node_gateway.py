"""標準單機隔離 Gateway：只允許明確封閉候選的 Compose TLS Listener。"""

from __future__ import annotations

import os
from pathlib import Path
import stat
from typing import Mapping

from fastapi import FastAPI
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import uvicorn

from deception.security.protected_gateway import (
    FixedGatewaySenderMTLSClient, FixedGatewayVerifierMTLSClient,
    create_gateway_native_proxy_candidate_app,
)
from deception.security.protected_rpc import (
    ProtectedRpcConfigurationError, require_distinct_mtls_ca_public_keys,
    require_mtls_files,
)
from deception.security.restore_profile import (
    RestoreProfileConfigurationError, load_restore_profile,
)


def _required(config: Mapping[str, str], name: str) -> str:
    """取得明確的非空設定，錯誤只輸出欄位名稱而不列印敏感內容。"""
    value = config.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ProtectedRpcConfigurationError("single_node_gateway_config_required:" + name)
    return value


def _certificate_key_identity(path: Path) -> bytes:
    """取出真 X.509 公鑰來阻止 Gateway 出入口使用複製後的同一身分。"""
    try:
        certificate = x509.load_pem_x509_certificate(path.read_bytes())
        return certificate.public_key().public_bytes(Encoding.DER,
                                                     PublicFormat.SubjectPublicKeyInfo)
    except (OSError, ValueError, TypeError):
        raise ProtectedRpcConfigurationError("single_node_gateway_certificate_invalid") from None


def create_sealed_compose_gateway(config: Mapping[str, str]) -> FastAPI:
    """在禁止 Trusted Send 且標準單機宣告完整時組裝候選 Gateway。

    唯有顯式 candidate-only 控制面可建立；這並不是正式 Release Fuse，
    將由 Compose **僅在 host loopback** 發布 8443 埠，不能自行暴露公網。
    """
    if (config.get("MIRAGE_TRUSTED_SEND_ENABLE") != "false"
            or config.get("MIRAGE_SINGLE_NODE_GATEWAY_MODE") != "sealed_candidate_only"):
        raise ProtectedRpcConfigurationError("single_node_gateway_release_not_approved")
    try:
        deployment = load_restore_profile(config)
    except RestoreProfileConfigurationError:
        raise ProtectedRpcConfigurationError("single_node_gateway_restore_profile_invalid") from None
    if deployment.name != "standard_single_node":
        raise ProtectedRpcConfigurationError("single_node_gateway_standard_profile_required")
    if any(config.get(name) for name in (
            "MIRAGE_POSTGRES_DSN", "MIRAGE_G3B_VERIFIER_DSN_FILE",
            "MIRAGE_G3B_EXECUTOR_DSN_FILE", "MIRAGE_G4_SENDER_DSN_FILE")):
        raise ProtectedRpcConfigurationError("single_node_gateway_cross_role_secret_denied")

    prefix = "MIRAGE_G4_GATEWAY_"
    verifier_cert = Path(_required(config, prefix + "VERIFIER_CLIENT_CERT_FILE"))
    verifier_key = Path(_required(config, prefix + "VERIFIER_CLIENT_KEY_FILE"))
    sender_cert = Path(_required(config, prefix + "SENDER_CLIENT_CERT_FILE"))
    sender_key = Path(_required(config, prefix + "SENDER_CLIENT_KEY_FILE"))
    public_cert = Path(_required(config, prefix + "SERVER_CERT_FILE"))
    public_key = Path(_required(config, prefix + "SERVER_KEY_FILE"))
    identities = (verifier_cert, sender_cert, public_cert)
    key_paths = (verifier_key, sender_key, public_key)
    if (len({path.resolve() for path in (*identities, *key_paths)}) != 6
            or any(not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o007
                   for path in key_paths)
            or len({_certificate_key_identity(cert) for cert in identities}) != 3):
        raise ProtectedRpcConfigurationError("single_node_gateway_tls_identity_reuse_denied")
    # Gateway→Verifier 和 Gateway→Sender 的兩條信任鏈不容共享 CA 私鑰；
    # 即使管理者把同一 PEM 複製到不同 Secret 名稱，也必須在綁定 Socket 前拒絕。
    require_distinct_mtls_ca_public_keys(
        Path(_required(config, prefix + "VERIFIER_SERVER_CA_FILE")),
        Path(_required(config, prefix + "SENDER_SERVER_CA_FILE")),
    )
    verifier = FixedGatewayVerifierMTLSClient(
        origin=_required(config, prefix + "VERIFIER_ORIGIN"),
        client_cert=verifier_cert,
        client_key=verifier_key,
        server_ca=Path(_required(config, prefix + "VERIFIER_SERVER_CA_FILE")),
    )
    sender = FixedGatewaySenderMTLSClient(
        origin=_required(config, prefix + "SENDER_ORIGIN"),
        client_cert=sender_cert,
        client_key=sender_key,
        server_ca=Path(_required(config, prefix + "SENDER_SERVER_CA_FILE")),
    )
    # Gateway 對外的是 JWS over HTTPS；內部呼叫使用分開的兩組 mTLS 身分。
    require_mtls_files(
        server_cert=public_cert, server_key=public_key,
        client_ca=Path(_required(config, prefix + "VERIFIER_SERVER_CA_FILE")),
    )
    return create_gateway_native_proxy_candidate_app(
        verifier_client=verifier, sender_client=sender,
    )


def from_environment() -> None:
    """僅在 Compose 內執行隔離 HTTPS 候選；沒有業務解封與外部綁定選項。"""
    config = os.environ
    app = create_sealed_compose_gateway(config)
    if (config.get("MIRAGE_SINGLE_NODE_GATEWAY_BIND_HOST") != "0.0.0.0"
            or config.get("MIRAGE_SINGLE_NODE_GATEWAY_BIND_PORT") != "8443"):
        raise ProtectedRpcConfigurationError("single_node_gateway_fixed_container_bind_required")
    uvicorn.Server(uvicorn.Config(
        app, host="0.0.0.0", port=8443,
        ssl_certfile=_required(config, "MIRAGE_G4_GATEWAY_SERVER_CERT_FILE"),
        ssl_keyfile=_required(config, "MIRAGE_G4_GATEWAY_SERVER_KEY_FILE"),
        ssl_cert_reqs=0, http="h11", log_level="warning", proxy_headers=False,
        access_log=False, server_header=False, date_header=False,
    )).run()


if __name__ == "__main__":
    from_environment()
