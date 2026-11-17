"""AUTH-10：同一合法 JWS 透過 TLS 並行送入兩個真正獨立的 Mirage 驗章入口。"""

from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPSConnection
import json
import multiprocessing
import shutil
import socket
import ssl
import subprocess
import time
from threading import Barrier

import pytest

from test_postgres_conformance import isolated_test_dsn
from test_trusted_ingress import VECTOR, token, vector_request


def shared_provider(dsn):
    """使用固定公開測試向量與共享 PostgreSQL；固定時鐘只服務離線向量驗收。"""
    from deception.security.trusted_deployment import TrustedDeploymentSettings

    settings = TrustedDeploymentSettings(issuer="gateway", audience="mirage", environment_id="env-1",
        deployment_id="deploy-1", source_id="reviewed-detector", service_id="store", site_id="shop",
        public_keys={"gateway-1": VECTOR["public_key_hex"]})
    provider = settings.build_provider(postgres_dsn=dsn)
    provider._now = VECTOR["now"]
    return provider


def serve_shared_ingress(listener, cert, key, dsn):
    """在獨立程序啟動真正 ingress 正規化、JWS 驗證與共用 Replay；不執行業務或模型。"""
    import uvicorn
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    from deception.api.ingress import normalize_request, resolve_request_id
    from deception.api.pipeline import _unavailable
    from deception.security import TrustedSessionError

    app, provider = FastAPI(), shared_provider(dsn)

    @app.get("/healthz")
    async def health():
        """讓父程序確認 TLS 與事件迴圈已啟動；不讀取或消費授權。"""
        return {"ready": True}

    @app.get("/{path:path}")
    async def verify(request: Request):
        """以網路實收 bytes 驗證同一固定授權，公開拒絕不洩漏 Replay 內部原因。"""
        normalized = await normalize_request(request, resolve_request_id(request))
        try:
            assessment = provider(normalized)
        except TrustedSessionError:
            return _unavailable(normalized)
        return JSONResponse({"verdict": assessment.verdict})

    uvicorn.Server(uvicorn.Config(app, ssl_certfile=str(cert), ssl_keyfile=str(key), http="h11",
        log_level="error", access_log=False)).run(sockets=[listener])


def test_same_jws_reaches_two_independent_tls_ingresses_once(isolated_test_dsn, tmp_path):
    """同一簽章經兩個 TLS 程序最多成功一次；重送皆拒絕，退出後另一 provider 仍見 Replay。"""
    from deception.security import TrustedSessionError
    import psycopg

    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("requires openssl for independent TLS ingress processes")
    cert, key, config = tmp_path / "cert.pem", tmp_path / "key.pem", tmp_path / "openssl.cnf"
    config.write_text("[req]\ndistinguished_name=dn\n[dn]\n", encoding="ascii")
    subprocess.run([openssl, "req", "-config", str(config), "-x509", "-newkey", "rsa:2048", "-nodes",
        "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
        "-out", str(cert), "-keyout", str(key)], check=True, capture_output=True, timeout=20)
    context = multiprocessing.get_context("spawn")
    listeners, workers, ports = [], [], []
    trust = ssl.create_default_context(cafile=str(cert))

    def send(port, *, health=False, barrier=None):
        """僅改變網路目的 socket，保留同一 HTTPS authority、原始 path／query、headers 與 JWS。"""
        connection = HTTPSConnection("127.0.0.1", port, context=trust, timeout=15)
        try:
            if barrier is not None:
                barrier.wait(timeout=20)
            path = "/healthz" if health else VECTOR["request"]["raw_url"].split("shop.test", 1)[1]
            headers = {} if health else dict(VECTOR["request"]["headers"], **{"x-trusted-session": token()})
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    try:
        for _ in range(2):
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listeners.append(listener)
            ports.append(listener.getsockname()[1])
            worker = context.Process(target=serve_shared_ingress, args=(listener, cert, key, isolated_test_dsn))
            workers.append(worker)
            worker.start()
        assert len({worker.pid for worker in workers}) == 2
        for port, worker in zip(ports, workers):
            deadline = time.monotonic() + 30
            while True:
                try:
                    if send(port, health=True) == (200, {"ready": True}):
                        break
                except (OSError, TimeoutError):
                    pass
                assert worker.is_alive() and time.monotonic() < deadline, "independent TLS ingress did not become ready"
                time.sleep(0.05)
        barrier = Barrier(3)
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(send, port, barrier=barrier) for port in ports]
            barrier.wait(timeout=20)
            outcomes = [future.result(timeout=30) for future in futures]
        assert sorted(status for status, _ in outcomes) == [200, 503]
        assert [body for status, body in outcomes if status == 200] == [{"verdict": "malicious"}]
        for port in ports:
            assert send(port) == (503, {"code": "pipeline_unavailable", "request_id": VECTOR["request"]["request_id"]})
        with psycopg.connect(isolated_test_dsn) as observer:
            assert observer.execute("SELECT count(*) FROM replay_entries").fetchone() == (1,)
    finally:
        for worker in workers:
            if worker.pid is not None:
                if worker.is_alive():
                    worker.terminate()
                worker.join(5)
                worker.close()
        for listener in listeners:
            listener.close()
    with pytest.raises(TrustedSessionError, match="trusted_session_replay"):
        shared_provider(isolated_test_dsn)(vector_request())
