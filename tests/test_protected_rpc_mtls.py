"""獨立 G3b mTLS 服務入口的真實 TLS 握手與 sealed RPC 測試。"""

import multiprocessing
from pathlib import Path
import socket
import ssl
import subprocess
import time

import httpx
import pytest

from deception.security.protected_rpc import (
    ProtectedRpcConfigurationError, create_direct_verifier_app, create_sealed_app,
    require_mtls_files, serve_direct_verifier_mtls, serve_sealed_mtls,
)


def _issue_mtls_certificates(root: Path) -> tuple[Path, Path, Path, Path, Path]:
    """由測試專用 CA 簽發短期 Server 與 Client EKU 憑證，不共用任何正式秘密。"""
    ca, ca_key = root / "ca.pem", root / "ca.key"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=Mirage isolated control CA", "-addext", "basicConstraints=critical,CA:TRUE",
        "-out", str(ca), "-keyout", str(ca_key),
    ], check=True, capture_output=True)
    output = []
    for name, extension in (("server", "serverAuth"), ("client", "clientAuth")):
        cert, key, csr, ext = (root / f"{name}.pem", root / f"{name}.key",
                               root / f"{name}.csr", root / f"{name}.ext")
        ext.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            + ("subjectAltName=IP:127.0.0.1\n" if name == "server" else "")
            + f"extendedKeyUsage={extension}\n", encoding="ascii",
        )
        subprocess.run([
            "openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={name}",
            "-keyout", str(key), "-out", str(csr),
        ], check=True, capture_output=True)
        subprocess.run([
            "openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca),
            "-CAkey", str(ca_key), "-CAcreateserial", "-days", "1",
            "-extfile", str(ext), "-out", str(cert),
        ], check=True, capture_output=True)
        key.chmod(0o600)
        output.append((cert, key))
    return ca, *output[0], *output[1]


def _unused_local_port() -> int:
    """先取得隔離本機的隨機 TCP port，供子程序的 mTLS server 使用。"""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def test_protected_rpc_requires_distinct_nonempty_mtls_material(tmp_path):
    """缺少憑證、重用 CA 當 key 或空檔案時不能啟動服務。"""
    cert = tmp_path / "server.pem"
    with pytest.raises(ProtectedRpcConfigurationError, match="files_required"):
        require_mtls_files(server_cert=cert, server_key=cert, client_ca=cert)
    cert.write_bytes(b"example")
    with pytest.raises(ProtectedRpcConfigurationError, match="file_reuse_denied"):
        require_mtls_files(server_cert=cert, server_key=cert, client_ca=cert)
    assert create_sealed_app().openapi_url is None


def test_protected_rpc_real_mtls_rejects_missing_client_identity(tmp_path):
    """真實 TLS Server 拒絕無 Client Cert，持證方也不能執行封閉的業務 RPC。"""
    ca, server_cert, server_key, client_cert, client_key = _issue_mtls_certificates(tmp_path)
    port = _unused_local_port()
    worker = multiprocessing.Process(target=serve_sealed_mtls, kwargs={
        "host": "127.0.0.1", "port": port, "server_cert": server_cert,
        "server_key": server_key, "client_ca": ca,
    })
    worker.start()
    try:
        context = ssl.create_default_context(cafile=str(ca))
        context.load_cert_chain(str(client_cert), str(client_key))
        with httpx.Client(verify=context, trust_env=False, timeout=1.0) as trusted:
            for _ in range(50):
                try:
                    result = trusted.get(f"https://127.0.0.1:{port}/internal/ready")
                    break
                except httpx.ConnectError:
                    if not worker.is_alive():
                        pytest.fail("sealed mTLS server terminated during startup")
                    time.sleep(0.1)
            else:
                pytest.fail("sealed mTLS server failed to start")
            assert result.status_code == 200
            assert result.json() == {"control_plane": "sealed", "trusted_send": "disabled"}
            denied = trusted.post(f"https://127.0.0.1:{port}/internal/v1/execute", json={"operation": "any"})
            assert denied.status_code == 503
        anonymous_context = ssl.create_default_context(cafile=str(ca))
        with httpx.Client(verify=anonymous_context, trust_env=False, timeout=2.0) as anonymous:
            with pytest.raises(httpx.TransportError):
                anonymous.get(f"https://127.0.0.1:{port}/internal/ready")
    finally:
        worker.terminate()
        worker.join(timeout=5)
        if worker.is_alive():
            worker.kill()
            worker.join(timeout=5)


def test_direct_verifier_uses_distinct_mtls_listener_and_keeps_executor_sealed(tmp_path):
    """真 TLS：只有持 Gateway clientAuth 憑證可接觸 Verifier，且沒有自由執行入口。"""
    from deception.security.key_revocation import PostgresTrustedKeyRevocations
    from deception.security.trusted_session import TrustedKeyRegistry, TrustedSessionVerifier
    from deception.world.postgres_replay import PostgresReplayStore

    ca, server_cert, server_key, client_cert, client_key = _issue_mtls_certificates(tmp_path)
    dsn = "postgresql://unused.invalid/direct-verifier"
    app = create_direct_verifier_app(
        verifier=TrustedSessionVerifier(
            keys=TrustedKeyRegistry({}), replay_store=PostgresReplayStore(dsn),
            key_revocations=PostgresTrustedKeyRevocations(
                dsn, environment_id="env", deployment_id="deploy"),
        ),
        postgres_dsn=dsn, environment_id="env", deployment_id="deploy",
        expected_issuer="gateway", expected_audience="mirage",
    )
    port = _unused_local_port()
    worker = multiprocessing.Process(target=serve_direct_verifier_mtls, kwargs={
        "app": app, "host": "127.0.0.1", "port": port,
        "server_cert": server_cert, "server_key": server_key, "client_ca": ca,
    })
    worker.start()
    try:
        context = ssl.create_default_context(cafile=str(ca))
        context.load_cert_chain(str(client_cert), str(client_key))
        with httpx.Client(verify=context, trust_env=False, timeout=1.0) as trusted:
            for _ in range(50):
                try:
                    response = trusted.get(f"https://127.0.0.1:{port}/internal/ready")
                    break
                except httpx.ConnectError:
                    if not worker.is_alive():
                        pytest.fail("direct verifier TLS listener terminated during startup")
                    time.sleep(0.1)
            else:
                pytest.fail("direct verifier TLS listener did not start")
            assert response.status_code == 200
            assert response.json() == {"control_plane": "verifier-only", "trusted_send": "disabled"}
            blocked = trusted.post(f"https://127.0.0.1:{port}/internal/v1/execute",
                                   json={"operation": "cart.complete"})
            assert blocked.status_code == 503
        with httpx.Client(verify=ssl.create_default_context(cafile=str(ca)),
                          trust_env=False, timeout=2.0) as anonymous:
            with pytest.raises(httpx.TransportError):
                anonymous.get(f"https://127.0.0.1:{port}/internal/ready")
    finally:
        worker.terminate()
        worker.join(timeout=5)
        if worker.is_alive():
            worker.kill()
            worker.join(timeout=5)
