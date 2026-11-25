"""獨立 G3b mTLS 服務入口的真實 TLS 握手與 sealed RPC 測試。"""

import multiprocessing
from pathlib import Path
import socket
import ssl
import subprocess
import time
from uuid import uuid4

import httpx
import pytest

from deception.security.protected_rpc import (
    FixedAuthorizerMTLSClient, FixedCandidatePublisherMTLSClient,
    ProtectedRpcConfigurationError,
    create_direct_verifier_app, create_fixed_authorizer_app, create_fixed_executor_app,
    create_fixed_candidate_publisher_app, create_fixed_sender_app,
    create_sealed_app, require_mtls_files,
    serve_direct_verifier_mtls, serve_fixed_authorizer_mtls,
    serve_fixed_candidate_publisher_mtls, serve_fixed_executor_mtls, serve_fixed_sender_mtls,
    serve_sealed_mtls,
)


def _issue_mtls_certificates(root: Path) -> tuple[Path, Path, Path, Path, Path]:
    """由測試專用 CA 簽發短期 Server 與 Client EKU 憑證，不共用任何正式秘密。"""
    ca, ca_key = root / "ca.pem", root / "ca.key"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=Mirage isolated control CA", "-addext", "basicConstraints=critical,CA:TRUE",
        # OpenSSL 3.5+ 對 CA TLS 驗證會檢查 keyUsage；測試 CA 也須是完整 X.509 CA。
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
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


def test_isolated_mtls_ca_declares_required_key_usage(tmp_path):
    """測試 CA 同時具有 CA basicConstraints 與簽章用途，兼容嚴格 OpenSSL。"""
    from cryptography import x509

    ca, *_ = _issue_mtls_certificates(tmp_path)
    certificate = x509.load_pem_x509_certificate(ca.read_bytes())
    constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    assert constraints.ca and usage.key_cert_sign and usage.crl_sign


def test_protected_rpc_requires_distinct_nonempty_mtls_material(tmp_path):
    """缺少憑證、重用 CA 當 key 或空檔案時不能啟動服務。"""
    cert = tmp_path / "server.pem"
    with pytest.raises(ProtectedRpcConfigurationError, match="files_required"):
        require_mtls_files(server_cert=cert, server_key=cert, client_ca=cert)
    cert.write_bytes(b"example")
    with pytest.raises(ProtectedRpcConfigurationError, match="file_reuse_denied"):
        require_mtls_files(server_cert=cert, server_key=cert, client_ca=cert)
    assert create_sealed_app().openapi_url is None


def test_verifier_authorizer_and_publisher_deny_copied_tls_client_identity(tmp_path):
    """兩種持久寫入角色即使把相同憑證複製到不同檔名，也不能共用簽章身分。"""
    from deception.security.protected_services import _require_separate_authorizer_publisher_identity

    publisher_root, authorizer_root = tmp_path / "publisher", tmp_path / "authorizer"
    publisher_root.mkdir()
    authorizer_root.mkdir()
    _, _, _, publisher_cert, publisher_key = _issue_mtls_certificates(publisher_root)
    _, _, _, authorizer_cert, authorizer_key = _issue_mtls_certificates(authorizer_root)
    config = {
        "MIRAGE_G4_VERIFIER_PUBLISHER_CERT_FILE": str(publisher_cert),
        "MIRAGE_G4_VERIFIER_PUBLISHER_KEY_FILE": str(publisher_key),
        "MIRAGE_G4_VERIFIER_AUTHORIZER_CERT_FILE": str(authorizer_cert),
        "MIRAGE_G4_VERIFIER_AUTHORIZER_KEY_FILE": str(authorizer_key),
    }
    assert _require_separate_authorizer_publisher_identity(config) is None
    copied_cert = authorizer_root / "copied-client.pem"
    copied_cert.write_bytes(publisher_cert.read_bytes())
    with pytest.raises(ProtectedRpcConfigurationError, match="identity_reuse_denied"):
        _require_separate_authorizer_publisher_identity({
            **config, "MIRAGE_G4_VERIFIER_AUTHORIZER_CERT_FILE": str(copied_cert),
        })
    with pytest.raises(ProtectedRpcConfigurationError, match="identity_reuse_denied"):
        _require_separate_authorizer_publisher_identity({
            **config, "MIRAGE_G4_VERIFIER_AUTHORIZER_KEY_FILE": str(publisher_key),
        })


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


def test_g4_sender_real_mtls_is_credential_isolated_and_never_starts_send(tmp_path):
    """真 TLS Client Auth 拒絕無證書連線；即使持證亦固定 503 且無起送動作。"""
    from deception.world.protected_send import PostgresProtectedSender

    ca, server_cert, server_key, client_cert, client_key = _issue_mtls_certificates(tmp_path)
    app = create_fixed_sender_app(sender=PostgresProtectedSender(
        "postgresql://unused.invalid/g4", expected_login="sender_only"))
    port = _unused_local_port()
    worker = multiprocessing.Process(target=serve_fixed_sender_mtls, kwargs={
        "app": app, "host": "127.0.0.1", "port": port,
        "server_cert": server_cert, "server_key": server_key,
        "sender_client_ca": ca,
    })
    worker.start()
    try:
        context = ssl.create_default_context(cafile=str(ca))
        context.load_cert_chain(str(client_cert), str(client_key))
        with httpx.Client(verify=context, trust_env=False, timeout=2.0) as trusted:
            for _ in range(50):
                try:
                    result = trusted.get(f"https://127.0.0.1:{port}/internal/ready")
                    break
                except httpx.ConnectError:
                    if not worker.is_alive():
                        pytest.fail("Sender mTLS server terminated during startup")
                    time.sleep(0.1)
            else:
                pytest.fail("Sender mTLS listener failed to start")
            assert result.json() == {
                "control_plane": "sender-sealed-pending-security-acceptance", "trusted_send": "disabled"}
            for json_body in ({}, {"lease_id": "forged", "send": True}):
                result = trusted.post(f"https://127.0.0.1:{port}/internal/v1/send",
                                      json=json_body)
                assert result.status_code == 503
                assert result.json() == {"detail": "fixed_sender_release_gates_not_met"}
        anonymous_context = ssl.create_default_context(cafile=str(ca))
        with httpx.Client(verify=anonymous_context, trust_env=False, timeout=2.0) as anonymous:
            with pytest.raises(httpx.TransportError):
                anonymous.post(f"https://127.0.0.1:{port}/internal/v1/send", json={})
        unrelated_dir = tmp_path / "unrelated-ca"
        unrelated_dir.mkdir()
        _, _, _, unrelated_cert, unrelated_key = _issue_mtls_certificates(unrelated_dir)
        wrong_identity = ssl.create_default_context(cafile=str(ca))
        wrong_identity.load_cert_chain(str(unrelated_cert), str(unrelated_key))
        with httpx.Client(verify=wrong_identity, trust_env=False, timeout=2.0) as stranger:
            with pytest.raises(httpx.TransportError):
                stranger.post(f"https://127.0.0.1:{port}/internal/v1/send", json={})
    finally:
        worker.terminate()
        worker.join(timeout=5)
        if worker.is_alive():
            worker.kill()
            worker.join(timeout=5)


def test_g4_authorizer_real_mtls_rejects_anonymous_and_client_forgery(tmp_path):
    """真正 TLS Client Cert 必要；Receipt-only Authorizer 不接受候選欄位或不存在的 DB。"""
    import asyncio
    from deception.world.protected_grant import PostgresProtectedAuthorizer

    ca, server_cert, server_key, client_cert, client_key = _issue_mtls_certificates(tmp_path)
    app = create_fixed_authorizer_app(authorizer=PostgresProtectedAuthorizer(
        "postgresql://unused.invalid/g4", expected_login="authorizer_only"))
    port = _unused_local_port()
    worker = multiprocessing.Process(target=serve_fixed_authorizer_mtls, kwargs={
        "app": app, "host": "127.0.0.1", "port": port,
        "server_cert": server_cert, "server_key": server_key,
        "verifier_client_ca": ca,
    })
    worker.start()
    try:
        context = ssl.create_default_context(cafile=str(ca))
        context.load_cert_chain(str(client_cert), str(client_key))
        with httpx.Client(verify=context, trust_env=False, timeout=2.0) as trusted:
            for _ in range(50):
                try:
                    ready = trusted.get(f"https://127.0.0.1:{port}/internal/ready")
                    break
                except httpx.ConnectError:
                    if not worker.is_alive():
                        pytest.fail("Authorizer mTLS listener stopped during startup")
                    time.sleep(0.1)
            else:
                pytest.fail("Authorizer mTLS listener failed to start")
            assert ready.json() == {"control_plane": "authorizer-receipt-only",
                                    "trusted_send": "disabled"}
            receipt = uuid4()
            for body in ({"receipt_id": str(receipt), "candidate_ref": "forged"},
                         {"receipt_id": str(receipt), "deadline": 9999999999},
                         {"receipt_id": "invalid"}):
                response = trusted.post(f"https://127.0.0.1:{port}/internal/v1/authorize-receipt",
                                        json=body)
                assert response.status_code == 400
            # 只有真正 DB/Grant 可核准；此 mTLS 身分存在不等於能自創 Admission。
            assert trusted.post(f"https://127.0.0.1:{port}/internal/v1/authorize-receipt",
                                json={"receipt_id": str(receipt)}).status_code == 503
        with httpx.Client(verify=ssl.create_default_context(cafile=str(ca)),
                          trust_env=False, timeout=2.0) as anonymous:
            with pytest.raises(httpx.TransportError):
                anonymous.get(f"https://127.0.0.1:{port}/internal/ready")
        foreign_dir = tmp_path / "foreign-authorizer"
        foreign_dir.mkdir()
        _, _, _, foreign_cert, foreign_key = _issue_mtls_certificates(foreign_dir)
        wrong_context = ssl.create_default_context(cafile=str(ca))
        wrong_context.load_cert_chain(str(foreign_cert), str(foreign_key))
        with httpx.Client(verify=wrong_context, trust_env=False, timeout=2.0) as foreign:
            with pytest.raises(httpx.TransportError):
                foreign.get(f"https://127.0.0.1:{port}/internal/ready")
        client = FixedAuthorizerMTLSClient(
            origin=f"https://127.0.0.1:{port}", client_cert=client_cert,
            client_key=client_key, server_ca=ca,
        )
        with pytest.raises(ProtectedRpcConfigurationError, match="result_unverifiable"):
            asyncio.run(client.authorize_receipt(uuid4()))
    finally:
        worker.terminate()
        worker.join(timeout=5)
        if worker.is_alive():
            worker.kill()
            worker.join(timeout=5)


def test_g4_candidate_publisher_real_mtls_rejects_non_receipt_and_anonymous(tmp_path, monkeypatch):
    """真 mTLS：Publisher 專用憑證、僅 Receipt、Hash pin，不提供 Sender 通道。"""
    import asyncio
    from deception.world.protected_grant import (
        PostgresVerifiedReceiptPublisher, ProtectedPublishedCandidate,
    )

    ca, server_cert, server_key, client_cert, client_key = _issue_mtls_certificates(tmp_path)
    receipt = uuid4()
    expected_hash = "a" * 64

    def publish_without_database(self, receipt_id):
        """此測試只評估 TLS／HTTP 邊界；真實 SQL 由 PG17 隔離套件檢查。"""
        if receipt_id != receipt:
            raise ValueError("unexpected_unpinned_receipt")
        return ProtectedPublishedCandidate(
            receipt, "verified-native-" + receipt.hex, expected_hash, 1,
            int(time.time()) + 60,
        )

    monkeypatch.setattr(PostgresVerifiedReceiptPublisher, "publish_receipt_once",
                        publish_without_database)
    publisher = object.__new__(PostgresVerifiedReceiptPublisher)
    port = _unused_local_port()
    worker = multiprocessing.Process(target=serve_fixed_candidate_publisher_mtls, kwargs={
        "app": create_fixed_candidate_publisher_app(publisher=publisher),
        "host": "127.0.0.1", "port": port, "server_cert": server_cert,
        "server_key": server_key, "verifier_client_ca": ca,
    })
    worker.start()
    try:
        context = ssl.create_default_context(cafile=str(ca))
        context.load_cert_chain(str(client_cert), str(client_key))
        with httpx.Client(verify=context, trust_env=False, timeout=2.0) as trusted:
            for _ in range(50):
                try:
                    ready = trusted.get(f"https://127.0.0.1:{port}/internal/ready")
                    break
                except httpx.ConnectError:
                    if not worker.is_alive():
                        pytest.fail("candidate publisher terminated before mTLS readiness")
                    time.sleep(0.1)
            else:
                pytest.fail("candidate publisher failed to start")
            assert ready.status_code == 200
            assert ready.json()["trusted_send"] == "disabled"
            assert trusted.post(
                f"https://127.0.0.1:{port}/internal/v1/publish-receipt",
                json={"receipt_id": str(receipt), "candidate_hash": expected_hash},
            ).status_code == 400
        with httpx.Client(verify=ssl.create_default_context(cafile=str(ca)),
                          trust_env=False, timeout=2.0) as anonymous:
            with pytest.raises(httpx.TransportError):
                anonymous.get(f"https://127.0.0.1:{port}/internal/ready")
        client = FixedCandidatePublisherMTLSClient(
            origin=f"https://127.0.0.1:{port}", client_cert=client_cert,
            client_key=client_key, server_ca=ca,
        )
        good = asyncio.run(client.publish_receipt(receipt,
                                                 expected_candidate_hash=expected_hash))
        assert good["candidate_ref"] == "verified-native-" + receipt.hex
        assert good["trusted_send"] == "disabled"
        with pytest.raises(ProtectedRpcConfigurationError, match="binding_mismatch"):
            asyncio.run(client.publish_receipt(receipt,
                                               expected_candidate_hash="b" * 64))
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
        foreign_root = tmp_path / "foreign"
        foreign_root.mkdir()
        _, _, _, foreign_cert, foreign_key = _issue_mtls_certificates(foreign_root)
        foreign_context = ssl.create_default_context(cafile=str(ca))
        foreign_context.load_cert_chain(str(foreign_cert), str(foreign_key))
        with httpx.Client(verify=foreign_context, trust_env=False, timeout=2.0) as foreign:
            with pytest.raises(httpx.TransportError):
                foreign.get(f"https://127.0.0.1:{port}/internal/ready")
    finally:
        worker.terminate()
        worker.join(timeout=5)
        if worker.is_alive():
            worker.kill()
            worker.join(timeout=5)


def test_fixed_executor_real_mtls_rejects_anonymous_and_caller_chosen_handler(tmp_path):
    """真實 mTLS Executor 只接受原始 Receipt 形狀；自填 action 無法碰 World。"""
    from deception.domains.ecommerce.inventory import SyntheticInventory
    from deception.world.protected_world import PostgresProtectedWorldExecutor

    ca, server_cert, server_key, client_cert, client_key = _issue_mtls_certificates(tmp_path)
    dsn = "postgresql://unused.invalid/fixed-executor"
    app = create_fixed_executor_app(executor=PostgresProtectedWorldExecutor(
        dsn, expected_login="not-a-real-login", world_store=SyntheticInventory(dsn),
    ))
    port = _unused_local_port()
    worker = multiprocessing.Process(target=serve_fixed_executor_mtls, kwargs={
        "app": app, "host": "127.0.0.1", "port": port,
        "server_cert": server_cert, "server_key": server_key,
        "verifier_client_ca": ca,
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
                        pytest.fail("fixed Executor mTLS listener terminated")
                    time.sleep(0.1)
            else:
                pytest.fail("fixed Executor mTLS listener did not start")
            assert response.json() == {"control_plane": "executor-lab-only",
                                       "trusted_send": "disabled"}
            refused = trusted.post(f"https://127.0.0.1:{port}/internal/v1/execute",
                                   json={"operation": "cart.complete", "binding": {}})
            assert refused.status_code == 400
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
