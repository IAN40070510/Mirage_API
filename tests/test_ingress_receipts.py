"""真實 PostgreSQL Key Guard／Replay／Ingress Receipt 單交易驗收。"""

import base64
import hashlib
import time
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deception.security import TrustedSessionError
from deception.security.ingress_receipt import IngressReceiptError, PostgresIngressReceiptWriter
from deception.api.fingerprint import fingerprint_request
from deception.api.fingerprint import fingerprint_httpx_request
from deception.security.protected_rpc import create_direct_verifier_app
from test_operation_binding import original_request
from deception.world import PostgresReplayStore
from deception.world.replay import ReplayConsumeResult
from test_key_revocation import verifier
from test_postgres_conformance import isolated_test_dsn
from test_trusted_session import encode


def signed(key, *, jti: str, reference_time: int | None = None,
           fingerprint: str = "a" * 64, access_mode: str = "read_only",
           session_id: str = "session", resource_id: str | None = None) -> str:
    """依目前時間簽發有效 JWS，讓 DB lock 後的權威時鐘檢查能實測。"""
    now = int(time.time()) if reference_time is None else reference_time
    claims = dict(
        iss="gateway", aud="mirage", iat=now - 5, nbf=now - 5, exp=now + 45,
        jti=jti, environment_id="env", deployment_id="deploy", session_id=session_id,
        session_epoch=1, access_mode=access_mode, request_fingerprint=fingerprint, assessment_id="assessment",
        assessment_digest="b" * 64)
    if resource_id is not None:
        claims["resource_id"] = resource_id
    prefix = encode(dict(alg="Ed25519", kid="old", protocol_version="1.1",
                         typ="mirage-trusted-session+jwt")) + "." + encode(claims)
    return prefix + "." + base64.urlsafe_b64encode(key.sign(prefix.encode())).decode().rstrip("=")


def verify_with_receipt(checker, token, writer, *, now: int | None = None,
                        fingerprint: str = "a" * 64):
    """以固定測試環境對完整 JWS 驗章並產生同交易 Receipt。"""
    return checker.verify_with_receipt(token, expected_issuer="gateway", expected_audience="mirage",
                                       request_fingerprint=fingerprint, environment_id="env",
                                       deployment_id="deploy", receipt_writer=writer,
                                       now=int(time.time()) if now is None else now)


def test_ingress_receipt_is_atomic_with_replay_and_single_use(isolated_test_dsn):
    """有效 JWS 同時持久化 Replay 與 Receipt，重放不能建立第二份 Receipt。"""
    import psycopg

    private_key = Ed25519PrivateKey.generate()
    checker = verifier(isolated_test_dsn, {"old": private_key})
    writer = PostgresIngressReceiptWriter(isolated_test_dsn, environment_id="env", deployment_id="deploy")
    jti = uuid4().hex
    token = signed(private_key, jti=jti)
    claims, receipt_id = verify_with_receipt(checker, token, writer)
    assert claims.jti == jti
    with psycopg.connect(isolated_test_dsn) as connection:
        rows = connection.execute(
            """SELECT r.receipt_id, r.key_id, r.session_id, r.request_fingerprint,
                      e.jti FROM ingress_receipts r JOIN replay_entries e
                        ON (r.issuer, r.audience, r.jti) = (e.issuer, e.audience, e.jti)
               WHERE r.jti=%s""", (jti,)).fetchall()
    assert rows == [(receipt_id, "old", "session", "a" * 64, jti)]
    with pytest.raises(TrustedSessionError, match="replay"):
        verify_with_receipt(checker, token, writer)
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM ingress_receipts WHERE jti=%s", (jti,)).fetchone()[0] == 1


def test_verified_http_operation_is_atomic_with_ingress_receipt(isolated_test_dsn):
    """原始 HTTP Operation 與 JTI／Receipt 同交易提交；不匹配則一起回滾。"""
    import psycopg

    key = Ed25519PrivateKey.generate()
    checker = verifier(isolated_test_dsn, {"old": key})
    request = original_request()
    fingerprint = fingerprint_request(request)
    writer = PostgresIngressReceiptWriter(
        isolated_test_dsn, environment_id="env", deployment_id="deploy",
        verified_request=request,
    )
    jti = uuid4().hex
    _, receipt = verify_with_receipt(
        checker, signed(key, jti=jti, fingerprint=fingerprint), writer,
        fingerprint=fingerprint,
    )
    with psycopg.connect(isolated_test_dsn) as connection:
        row = connection.execute(
            """SELECT operation_id,method,path_template,request_fingerprint,
                      request_path,request_content_type
               FROM protected_http_operation_bindings WHERE receipt_id=%s""", (receipt,),
        ).fetchone()
        assert row == ("reserveSyntheticInventory", "POST", "/synthetic/inventory/reservations",
                       fingerprint, request.path, "application/json")
    wrong_jti = uuid4().hex
    with pytest.raises(IngressReceiptError, match="fingerprint_mismatch"):
        verify_with_receipt(
            checker, signed(key, jti=wrong_jti, fingerprint="a" * 64), writer,
            fingerprint="a" * 64,
        )
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM replay_entries WHERE jti=%s",
                                  (wrong_jti,)).fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM ingress_receipts WHERE jti=%s",
                                  (wrong_jti,)).fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM protected_http_operation_bindings").fetchone()[0] == 1


def test_direct_https_verifier_captures_actual_request_and_mints_atomic_proof(isolated_test_dsn):
    """真 PostgreSQL：ASGI 原始 HTTP 進入獨立 Verifier 才能原子寫 Replay／Proof。"""
    import psycopg
    from fastapi.testclient import TestClient

    key = Ed25519PrivateKey.generate()
    app = create_direct_verifier_app(
        verifier=verifier(isolated_test_dsn, {"old": key}),
        postgres_dsn=isolated_test_dsn, environment_id="env", deployment_id="deploy",
        expected_issuer="gateway", expected_audience="mirage",
    )
    headers = {"x-request-id": "direct-original-1", "content-type": "application/json"}
    with TestClient(app, base_url="https://mirage.test") as client:
        unsigned = client.build_request("POST", "/synthetic/inventory/reservations",
                                        content=b"{}", headers=headers)
        fingerprint = fingerprint_httpx_request(unsigned, "direct-original-1")
        jti = uuid4().hex
        token = signed(key, jti=jti, fingerprint=fingerprint)
        unsigned.headers["x-trusted-session"] = token
        accepted = client.send(unsigned)
        assert accepted.status_code == 200
        receipt_id = accepted.json()["receipt_id"]
        assert accepted.json()["operation_id"] == "reserveSyntheticInventory"
        again = client.send(unsigned)
        assert again.status_code == 403
        forged = client.build_request("POST", "/synthetic/inventory/reservations",
                                      content=b'{"body":"substituted"}', headers=headers)
        forged.headers["x-trusted-session"] = signed(
            key, jti=uuid4().hex, fingerprint=fingerprint,
        )
        assert client.send(forged).status_code == 403
        unknown = client.build_request("POST", "/synthetic/unapproved", content=b"{}", headers=headers)
        unknown.headers["x-trusted-session"] = signed(
            key, jti=uuid4().hex,
            fingerprint=fingerprint_httpx_request(unknown, "direct-original-1"),
        )
        assert client.send(unknown).status_code == 403
        with TestClient(app, base_url="http://mirage.test") as plaintext:
            request = plaintext.build_request("POST", "/synthetic/inventory/reservations",
                                               content=b"{}", headers=headers)
            request.headers["x-trusted-session"] = signed(key, jti=uuid4().hex,
                fingerprint=fingerprint_httpx_request(request, "direct-original-1"))
            assert plaintext.send(request).status_code == 503
    with psycopg.connect(isolated_test_dsn) as connection:
        rows = connection.execute(
            """SELECT i.receipt_id,i.request_fingerprint,p.operation_id,p.request_path,
                      p.request_body_sha256 FROM ingress_receipts i
               JOIN protected_http_operation_bindings p ON p.receipt_id=i.receipt_id""",
        ).fetchall()
        assert len(rows) == 1
        assert str(rows[0][0]) == receipt_id
        assert rows[0][1:4] == (fingerprint, "reserveSyntheticInventory",
                                 "/synthetic/inventory/reservations")
        assert rows[0][4] == hashlib.sha256(b"{}").hexdigest()
        assert connection.execute("SELECT count(*) FROM replay_entries").fetchone()[0] == 1


def test_direct_verifier_dispatches_inventory_over_real_executor_mtls_once(isolated_test_dsn, tmp_path):
    """兩個真程序與實體 TLS：原始 JWS HTTP → Verifier Proof → Executor 固定庫存提交。"""
    import json
    import multiprocessing
    import ssl
    import time as clock

    import httpx
    import psycopg
    from fastapi.testclient import TestClient

    from deception.domains.ecommerce.inventory import SyntheticInventory
    from deception.security.protected_rpc import (
        FixedExecutorMTLSClient, create_fixed_executor_app, serve_fixed_executor_mtls,
    )
    from deception.world.protected_world import PostgresProtectedWorldExecutor
    from deception.world.session import SessionBinding
    from test_protected_rpc_mtls import _issue_mtls_certificates, _unused_local_port

    dsn = isolated_test_dsn
    now = int(clock.time())
    binding = SessionBinding(environment_id="env", deployment_id="deploy",
                             session_id="session", session_epoch=1, access_mode="inventory")
    world = SyntheticInventory(dsn)
    snapshot = world.resolve(binding, {"inventory": {"sku-1": 4}, "reservations": {}},
                             now=now, ttl=120)
    with psycopg.connect(dsn) as connection:
        login = connection.execute("SELECT session_user").fetchone()[0]
    executor = PostgresProtectedWorldExecutor(dsn, expected_login=login, world_store=world)
    ca, server_cert, server_key, client_cert, client_key = _issue_mtls_certificates(tmp_path)
    port = _unused_local_port()
    worker = multiprocessing.Process(target=serve_fixed_executor_mtls, kwargs={
        "app": create_fixed_executor_app(executor=executor), "host": "127.0.0.1", "port": port,
        "server_cert": server_cert, "server_key": server_key, "verifier_client_ca": ca,
    })
    worker.start()
    try:
        context = ssl.create_default_context(cafile=str(ca))
        context.load_cert_chain(str(client_cert), str(client_key))
        with httpx.Client(verify=context, trust_env=False, timeout=1.0) as mtls:
            for _ in range(50):
                try:
                    ready = mtls.get(f"https://127.0.0.1:{port}/internal/ready")
                    assert ready.status_code == 200
                    break
                except httpx.ConnectError:
                    if not worker.is_alive():
                        pytest.fail("Executor server crashed before readiness")
                    clock.sleep(0.1)
            else:
                pytest.fail("Executor server did not become ready")
        key = Ed25519PrivateKey.generate()
        executor_client = FixedExecutorMTLSClient(
            origin=f"https://127.0.0.1:{port}", client_cert=client_cert,
            client_key=client_key, server_ca=ca,
        )
        verifier_app = create_direct_verifier_app(
            verifier=verifier(dsn, {"old": key}), postgres_dsn=dsn,
            environment_id="env", deployment_id="deploy",
            expected_issuer="gateway", expected_audience="mirage",
            executor_client=executor_client,
        )
        body = json.dumps({"sku": "sku-1", "quantity": 2, "expected_version": 1,
                           "idempotency_key": "real-mtls-once",
                           "commit_attempt_id": str(uuid4())}).encode()
        with TestClient(verifier_app, base_url="https://mirage.test") as gateway:
            request = gateway.build_request("POST", "/synthetic/inventory/reservations",
                                           content=body, headers={"x-request-id": "two-process-1",
                                                                  "content-type": "application/json"})
            fingerprint = fingerprint_httpx_request(request, "two-process-1")
            request.headers["x-trusted-session"] = signed(
                key, jti=uuid4().hex, fingerprint=fingerprint, access_mode="inventory",
            )
            accepted = gateway.send(request)
            assert accepted.status_code == 200, accepted.text
            assert accepted.json()["executor_result"]["status"] == "committed"
            assert accepted.json()["executor_result"]["operation"] == "reserveSyntheticInventory"
            assert gateway.send(request).status_code == 403
        with psycopg.connect(dsn) as connection:
            assert connection.execute(
                "SELECT state->'inventory'->>'sku-1' FROM world_snapshots WHERE world_generation_id=%s",
                (snapshot.scope.world_generation_id,),
            ).fetchone()[0] == "2"
            assert connection.execute("SELECT count(*) FROM protected_world_commit_sources").fetchone()[0] == 1
            assert connection.execute("SELECT count(*) FROM protected_world_read_sources").fetchone()[0] == 1
            assert connection.execute("SELECT count(*) FROM ingress_receipts").fetchone()[0] == 1
    finally:
        worker.terminate()
        worker.join(timeout=5)
        if worker.is_alive():
            worker.kill()
            worker.join(timeout=5)


def test_direct_verifier_medusa_400_over_real_executor_mtls(isolated_test_dsn, tmp_path):
    """真雙程序：Medusa 原始金鑰與錯誤 Body 經 Fingerprint 鎖定後才建立可信 400。"""
    import multiprocessing
    import ssl
    import time as clock

    import httpx
    import psycopg
    from fastapi.testclient import TestClient

    from deception.domains.ecommerce.carts import SyntheticCarts
    from deception.security.protected_rpc import (
        FixedExecutorMTLSClient, create_fixed_executor_app, serve_fixed_executor_mtls,
    )
    from deception.world.protected_world import PostgresProtectedWorldExecutor
    from deception.world.session import SessionBinding
    from test_protected_rpc_mtls import _issue_mtls_certificates, _unused_local_port

    dsn = isolated_test_dsn
    now = int(clock.time())
    creator = SessionBinding(environment_id="env", deployment_id="deploy",
                             session_id="medusa-creator", session_epoch=1, access_mode="cart")
    world = SyntheticCarts(dsn)
    catalog = {"known": {"sku": "sku-1", "unit_price": 100}}
    inventory = {"sku-1": 5}
    world.resolve(creator, {"catalog": catalog, "inventory": inventory,
                            "reservations": {}}, now=now, ttl=120)
    creator_receipt, creator_jti = uuid4(), uuid4().hex
    with psycopg.connect(dsn) as connection:
        login = connection.execute("SELECT session_user").fetchone()[0]
        connection.execute("INSERT INTO replay_entries VALUES ('gateway','mirage',%s,%s)",
                           (creator_jti, now + 120))
        connection.execute(
            """INSERT INTO ingress_receipts (
                   receipt_id,issuer,audience,jti,key_id,environment_id,deployment_id,
                   session_id,session_epoch,request_fingerprint,assessment_digest,
                   claims_digest,verification_policy_version,token_issued_at,
                   token_not_before,token_expires_at,access_mode)
               VALUES (%s,'gateway','mirage',%s,'old','env','deploy',%s,1,%s,%s,%s,
                       'trusted-session-v1.1',%s,%s,%s,'cart')""",
            (creator_receipt, creator_jti, creator.session_id, "a" * 64,
             "b" * 64, "c" * 64, now - 5, now - 5, now + 90),
        )
    executor = PostgresProtectedWorldExecutor(
        dsn, expected_login=login, world_store=world,
        cart_initial_state={"catalog": catalog, "inventory": inventory,
                            "native_context": {"region_id": "reg_mirage_usd",
                                               "sales_channel_id": "sc_mirage",
                                               "email": "guest@example.invalid", "metadata": {}}},
        medusa_publishable_key="pk_trusted_only",
    )
    created = executor.create_cart(
        receipt_id=creator_receipt, creator=creator, request_fingerprint="a" * 64,
        idempotency_key=uuid4(), commit_attempt_id=uuid4(),
        creation_digest="d" * 64, ttl=120,
    )
    ca, server_cert, server_key, client_cert, client_key = _issue_mtls_certificates(tmp_path)
    port = _unused_local_port()
    worker = multiprocessing.Process(target=serve_fixed_executor_mtls, kwargs={
        "app": create_fixed_executor_app(executor=executor), "host": "127.0.0.1", "port": port,
        "server_cert": server_cert, "server_key": server_key, "verifier_client_ca": ca,
    })
    worker.start()
    try:
        context = ssl.create_default_context(cafile=str(ca))
        context.load_cert_chain(str(client_cert), str(client_key))
        with httpx.Client(verify=context, trust_env=False, timeout=1.0) as mtls:
            for _ in range(50):
                try:
                    assert mtls.get(f"https://127.0.0.1:{port}/internal/ready").status_code == 200
                    break
                except httpx.ConnectError:
                    if not worker.is_alive():
                        pytest.fail("Medusa executor terminated before mTLS readiness")
                    clock.sleep(0.1)
            else:
                pytest.fail("Medusa executor did not become ready")
        signer = Ed25519PrivateKey.generate()
        client = FixedExecutorMTLSClient(
            origin=f"https://127.0.0.1:{port}", client_cert=client_cert,
            client_key=client_key, server_ca=ca,
        )
        app = create_direct_verifier_app(
            verifier=verifier(dsn, {"old": signer}), postgres_dsn=dsn,
            environment_id="env", deployment_id="deploy",
            expected_issuer="gateway", expected_audience="mirage", executor_client=client,
        )
        path = "/store/carts/" + created.binding.resource_id + "/line-items"
        with TestClient(app, base_url="https://mirage.test") as gateway:
            request = gateway.build_request(
                "POST", path, content=b'{"variant_id":"known","quantity":0}',
                headers={"x-request-id": "medusa-two-process-1",
                         "content-type": "application/json",
                         "x-publishable-api-key": "pk_trusted_only"},
            )
            fingerprint = fingerprint_httpx_request(request, "medusa-two-process-1")
            request.headers["x-trusted-session"] = signed(
                signer, jti=uuid4().hex, fingerprint=fingerprint,
                access_mode="cart", session_id=created.binding.session_id,
                resource_id=created.binding.resource_id,
            )
            tampered = gateway.build_request(
                "POST", path, content=request.content, headers=dict(request.headers),
            )
            tampered.headers["x-publishable-api-key"] = "forged"
            assert gateway.send(tampered).status_code == 403
            accepted = gateway.send(request)
            assert accepted.status_code == 200, accepted.text
            assert accepted.json()["executor_result"]["kind"] == "medusa_rejection"
            assert accepted.json()["executor_result"]["status_code"] == 400
            assert accepted.json()["executor_result"]["template_id"] == "native-cart-invalid"
            assert gateway.send(request).status_code == 403
        with psycopg.connect(dsn) as connection:
            assert connection.execute("SELECT status_code,reason_code FROM protected_medusa_rejection_sources"
                                      ).fetchall() == [(400, "native_bad_item_body")]
            assert connection.execute("SELECT count(*) FROM protected_http_operation_bindings"
                                      ).fetchone()[0] == 1
            assert connection.execute("SELECT count(*) FROM protected_world_read_sources"
                                      ).fetchone()[0] == 1
            assert connection.execute("SELECT count(*) FROM world_events").fetchone()[0] == 0
    finally:
        worker.terminate()
        worker.join(timeout=5)
        if worker.is_alive():
            worker.kill()
            worker.join(timeout=5)


def test_ingress_receipt_failure_rolls_back_consumed_replay(isolated_test_dsn):
    """Receipt 寫入失敗時，同一連線已 INSERT 的 Replay 必須一同回滾。"""
    import psycopg

    private_key = Ed25519PrivateKey.generate()
    checker = verifier(isolated_test_dsn, {"old": private_key})
    jti = uuid4().hex
    token = signed(private_key, jti=jti)

    class FailingWriter(PostgresIngressReceiptWriter):
        """於 Replay 寫入成功後、Receipt 寫入前注入明確交易失敗。"""

        def _write_on_cursor(self, cursor, *, claims, kid):
            """在共享交易內故意拋錯，要求 Coordinator 自動 rollback。"""
            raise IngressReceiptError("injected_receipt_write_failure")

    failing = FailingWriter(isolated_test_dsn, environment_id="env", deployment_id="deploy")
    with pytest.raises(IngressReceiptError, match="injected_receipt_write_failure"):
        verify_with_receipt(checker, token, failing)
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM replay_entries WHERE jti=%s", (jti,)).fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM ingress_receipts WHERE jti=%s", (jti,)).fetchone()[0] == 0


def test_ingress_receipt_rejects_cross_database_writer_before_consumption(isolated_test_dsn):
    """Writer 與 Replay/Key Guard 不同 DSN 時，拒絕且不消費合法 JTI。"""
    import psycopg
    from deception.security.key_revocation import KeyRevocationError

    private_key = Ed25519PrivateKey.generate()
    checker = verifier(isolated_test_dsn, {"old": private_key})
    jti = uuid4().hex
    writer = PostgresIngressReceiptWriter("postgresql://different.invalid/db",
                                          environment_id="env", deployment_id="deploy")
    with pytest.raises(KeyRevocationError, match="same_postgres_connection_domain"):
        verify_with_receipt(checker, signed(private_key, jti=jti), writer)
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM replay_entries WHERE jti=%s", (jti,)).fetchone()[0] == 0


def test_ingress_receipt_rejects_revoked_key_without_consuming_jti(isolated_test_dsn):
    """Key Revocation 在 IngressTx 前已提交時，不能得到 Receipt 或消費 Replay。"""
    import psycopg
    from deception.security.key_revocation import PostgresTrustedKeyRevocations

    private_key = Ed25519PrivateKey.generate()
    checker = verifier(isolated_test_dsn, {"old": private_key})
    writer = PostgresIngressReceiptWriter(isolated_test_dsn, environment_id="env", deployment_id="deploy")
    jti = uuid4().hex
    PostgresTrustedKeyRevocations(isolated_test_dsn, environment_id="env",
                                   deployment_id="deploy").revoke("gateway", "old", revision=1)
    with pytest.raises(TrustedSessionError, match="trusted_key_revoked"):
        verify_with_receipt(checker, signed(private_key, jti=jti), writer)
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM replay_entries WHERE jti=%s", (jti,)).fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM ingress_receipts WHERE jti=%s", (jti,)).fetchone()[0] == 0


def test_ingress_receipt_rechecks_db_clock_after_key_lock(isolated_test_dsn):
    """即使 Runtime 偽造舊 Python now，資料庫時間仍拒絕已過期的 Receipt。"""
    import psycopg
    from deception.security.key_revocation import KeyRevocationError

    key = Ed25519PrivateKey.generate()
    checker = verifier(isolated_test_dsn, {"old": key})
    writer = PostgresIngressReceiptWriter(isolated_test_dsn, environment_id="env", deployment_id="deploy")
    jti = uuid4().hex
    forged_now = int(time.time()) - 120
    with pytest.raises(KeyRevocationError, match="ingress_receipt_db_time_invalid"):
        verify_with_receipt(checker, signed(key, jti=jti, reference_time=forged_now), writer, now=forged_now)
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM replay_entries WHERE jti=%s", (jti,)).fetchone()[0] == 0


def test_replay_gc_preserves_ingress_receipt_evidence_and_cleans_unreferenced(isolated_test_dsn):
    """Replay GC 不被 Receipt FK 阻塞所有過期清理，也不得刪掉可信引用墓碑。"""
    import psycopg

    key = Ed25519PrivateKey.generate()
    checker = verifier(isolated_test_dsn, {"old": key})
    writer = PostgresIngressReceiptWriter(isolated_test_dsn, environment_id="env", deployment_id="deploy")
    retained_jti, unbound_jti = uuid4().hex, uuid4().hex
    verify_with_receipt(checker, signed(key, jti=retained_jti), writer)
    replay = PostgresReplayStore(isolated_test_dsn)
    now = int(time.time())
    assert replay.consume(issuer="gateway", audience="mirage", jti=unbound_jti,
                          expires_at=now + 20, now=now) is ReplayConsumeResult.ACCEPTED
    assert replay.gc(now=now + 100) == 1
    with psycopg.connect(isolated_test_dsn) as connection:
        jtis = {row[0] for row in connection.execute("SELECT jti FROM replay_entries WHERE jti=ANY(%s)",
                                                     ([retained_jti, unbound_jti],))}
    assert jtis == {retained_jti}
