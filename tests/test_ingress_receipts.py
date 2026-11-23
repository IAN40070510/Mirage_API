"""真實 PostgreSQL Key Guard／Replay／Ingress Receipt 單交易驗收。"""

import base64
import hashlib
import os
import secrets
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


def _isolated_three_process_service_logins(dsn: str, request):
    """只在拋棄式 CI PG 建立 Verifier／Executor／Runtime 真 SCRAM Login 與窄授權。

    Login 彼此不繼承，Verifier 僅能建 Replay／Receipt／Operation Proof；
    Executor 僅能查受保護來源及提交固定世界，Runtime 沒有敏感表 DML。
    以 pytest finalizer 確保失敗也會清除專用 Role，不碰現有正式帳號。
    """
    if os.environ.get("MIRAGE_WORLD_ROLE_TEST_ISOLATED") != "true":
        pytest.skip("requires explicitly disposable PostgreSQL cluster for real login roles")
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    schema = conninfo_to_dict(dsn)["options"].split("search_path=", 1)[1].split(" ", 1)[0]
    suffix = uuid4().hex[:12]
    users = {role: (f"mirage_g3b_{role}_{suffix}", secrets.token_urlsafe(32))
             for role in ("verifier", "executor", "runtime")}
    with psycopg.connect(dsn, autocommit=True) as admin:
        for name, password in users.values():
            admin.execute(sql.SQL(
                "CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOREPLICATION NOBYPASSRLS PASSWORD {}"
            ).format(sql.Identifier(name), sql.Literal(password)))
            admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                sql.Identifier(schema), sql.Identifier(name)))
        verifier_role = sql.Identifier(users["verifier"][0])
        executor_role = sql.Identifier(users["executor"][0])
        admin.execute(sql.SQL(
            "GRANT SELECT ON trusted_key_revocations,replay_entries,ingress_receipts "
            "TO {}"
        ).format(verifier_role))
        admin.execute(sql.SQL(
            "GRANT INSERT ON replay_entries,ingress_receipts,protected_http_operation_bindings "
            "TO {}"
        ).format(verifier_role))
        admin.execute(sql.SQL(
            "GRANT SELECT ON ingress_receipts,protected_http_operation_bindings,"
            "session_heads,session_world_bindings,generation_controls,trusted_key_revocations,"
            "world_snapshots,world_operations,read_admissions,protected_world_read_sources,"
            "protected_world_commit_sources TO {}"
        ).format(executor_role))
        admin.execute(sql.SQL(
            "GRANT UPDATE ON session_heads,session_world_bindings,generation_controls,"
            "world_snapshots TO {}"
        ).format(executor_role))
        admin.execute(sql.SQL(
            "GRANT INSERT ON read_admissions,protected_world_read_sources,world_operations,"
            "world_events,world_commit_receipts,protected_world_commit_sources TO {}"
        ).format(executor_role))
        admin.execute(sql.SQL(
            "GRANT EXECUTE ON FUNCTION protected_lock_reference(text,jsonb) TO {}"
        ).format(executor_role))
        for name, _ in users.values():
            row = admin.execute(
                "SELECT rolpassword LIKE %s FROM pg_authid WHERE rolname=%s",
                ("SCRAM-SHA-256$%", name),
            ).fetchone()
            assert row == (True,), "isolated service login must use SCRAM-SHA-256"

    def cleanup_roles():
        """使用同一拋棄式管理 DSN 僅撤銷並移除本測試創建的三個 Login。"""
        with psycopg.connect(dsn, autocommit=True) as admin:
            for name, _ in users.values():
                admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(name)))
                admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(name)))

    request.addfinalizer(cleanup_roles)
    return {role: (make_conninfo(dsn, user=name, password=password), name)
            for role, (name, password) in users.items()}


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
    """真三程序雙 CA：Verifier→Executor 固定 Inventory 提交及獨立 Validator 409。"""
    import json
    import multiprocessing
    import ssl
    import time as clock

    import httpx
    import psycopg
    from fastapi.testclient import TestClient

    from deception.domains.ecommerce.inventory import SyntheticInventory
    from deception.security.protected_rpc import (
        FixedExecutorMTLSClient, FixedNativeValidatorMTLSClient,
        create_fixed_executor_app, create_native_validator_app,
        serve_fixed_executor_mtls, serve_native_validator_mtls,
    )
    from deception.world.protected_world import PostgresProtectedWorldExecutor
    from deception.world.protected_native_http import (
        PostgresProtectedNativeProjector, fixed_synthetic_rejection_bytes,
    )
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
    executor = PostgresProtectedWorldExecutor(
        dsn, expected_login=login, world_store=world,
        rejection_templates={"unknown_synthetic_sku": "synthetic-inventory-1"},
    )
    ca, server_cert, server_key, client_cert, client_key = _issue_mtls_certificates(tmp_path)
    validator_root = tmp_path / "inventory-validator-ca"
    validator_root.mkdir()
    validator_ca, validator_cert, validator_key, validator_client_cert, validator_client_key = (
        _issue_mtls_certificates(validator_root))
    assert validator_ca.read_bytes() != ca.read_bytes()
    port, validator_port = _unused_local_port(), _unused_local_port()
    while port == validator_port:
        validator_port = _unused_local_port()
    worker = multiprocessing.Process(target=serve_fixed_executor_mtls, kwargs={
        "app": create_fixed_executor_app(executor=executor), "host": "127.0.0.1", "port": port,
        "server_cert": server_cert, "server_key": server_key, "verifier_client_ca": ca,
    })
    validator_worker = multiprocessing.Process(target=serve_native_validator_mtls, kwargs={
        "app": create_native_validator_app(projector=PostgresProtectedNativeProjector(
            dsn, expected_login=login)),
        "host": "127.0.0.1", "port": validator_port,
        "server_cert": validator_cert, "server_key": validator_key,
        "verifier_client_ca": validator_ca,
    })
    worker.start()
    validator_worker.start()
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
        validator_context = ssl.create_default_context(cafile=str(validator_ca))
        validator_context.load_cert_chain(str(validator_client_cert), str(validator_client_key))
        with httpx.Client(verify=validator_context, trust_env=False, timeout=1.0) as validator_mtls:
            for _ in range(50):
                try:
                    assert validator_mtls.get(
                        f"https://127.0.0.1:{validator_port}/internal/ready").status_code == 200
                    break
                except httpx.ConnectError:
                    if not validator_worker.is_alive():
                        pytest.fail("Inventory validator crashed before readiness")
                    clock.sleep(0.1)
            else:
                pytest.fail("Inventory validator did not become ready")
        key = Ed25519PrivateKey.generate()
        executor_client = FixedExecutorMTLSClient(
            origin=f"https://127.0.0.1:{port}", client_cert=client_cert,
            client_key=client_key, server_ca=ca,
        )
        native_client = FixedNativeValidatorMTLSClient(
            origin=f"https://127.0.0.1:{validator_port}",
            client_cert=validator_client_cert, client_key=validator_client_key,
            server_ca=validator_ca,
        )
        verifier_app = create_direct_verifier_app(
            verifier=verifier(dsn, {"old": key}), postgres_dsn=dsn,
            environment_id="env", deployment_id="deploy",
            expected_issuer="gateway", expected_audience="mirage",
            executor_client=executor_client, native_validator_client=native_client,
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
            # I-03／I-04 走同一真 Verifier→Executor mTLS，僅取得 ReadAdmission。
            for index, (read_path, operation) in enumerate((
                    ("/synthetic/inventory/sku-1", "getSyntheticInventory"),
                    ("/synthetic/operations/" + json.loads(body)["commit_attempt_id"],
                     "getSyntheticOperation")), start=1):
                request_id = f"two-process-read-{index}"
                original = gateway.build_request("GET", read_path,
                                                 headers={"x-request-id": request_id})
                read_fingerprint = fingerprint_httpx_request(original, request_id)
                original.headers["x-trusted-session"] = signed(
                    key, jti=uuid4().hex, fingerprint=read_fingerprint,
                    access_mode="inventory",
                )
                read_http = gateway.send(original)
                assert read_http.status_code == 200, read_http.text  # 僅內部對帳 HTTP。
                internal = read_http.json()["executor_result"]
                assert internal["kind"] == "inventory_read_admitted"
                assert internal["operation"] == operation
                assert internal["state_version"] == 2
                assert "status_code" not in internal and "body_b64" not in internal
                assert gateway.send(original).status_code == 403
            # 真實拒絕來源只有被固定 Handler 拒絕後才能由另一程序投影。
            failed_body = json.dumps({"sku": "missing", "quantity": 1,
                                      "expected_version": 2, "idempotency_key": "real-409",
                                      "commit_attempt_id": str(uuid4())}).encode()
            rejected = gateway.build_request(
                "POST", "/synthetic/inventory/reservations", content=failed_body,
                headers={"x-request-id": "three-process-409", "content-type": "application/json"},
            )
            refusal_fingerprint = fingerprint_httpx_request(rejected, "three-process-409")
            rejected.headers["x-trusted-session"] = signed(
                key, jti=uuid4().hex, fingerprint=refusal_fingerprint, access_mode="inventory",
            )
            refused = gateway.send(rejected)
            assert refused.status_code == 200, refused.text  # 僅內部對帳，非 Client 原生 409。
            assert refused.json()["executor_result"]["status"] == "rejected"
            candidate = refused.json()["native_projection"]
            headers, expected_body = fixed_synthetic_rejection_bytes(
                "synthetic-inventory", "unknown_synthetic_sku")
            assert candidate["status_code"] == 409
            assert candidate["headers"] == [list(header) for header in headers]
            assert base64.b64decode(candidate["body_b64"], validate=True) == expected_body
            assert candidate["scope"]["session_id"] == binding.session_id
            assert candidate["delivery"] == "candidate_only_no_send_authorization"
            assert gateway.send(rejected).status_code == 403
        with psycopg.connect(dsn) as connection:
            assert connection.execute(
                "SELECT state->'inventory'->>'sku-1' FROM world_snapshots WHERE world_generation_id=%s",
                (snapshot.scope.world_generation_id,),
            ).fetchone()[0] == "2"
            assert connection.execute("SELECT count(*) FROM protected_world_commit_sources").fetchone()[0] == 1
            assert connection.execute("SELECT count(*) FROM protected_world_read_sources").fetchone()[0] == 4
            assert connection.execute("SELECT count(*) FROM ingress_receipts").fetchone()[0] == 4
            assert connection.execute("SELECT count(*) FROM protected_world_rejection_sources").fetchone()[0] == 1
    finally:
        for process in (worker, validator_worker):
            process.terminate()
            process.join(timeout=5)
            if process.is_alive():
                process.kill()
                process.join(timeout=5)


def test_direct_verifier_medusa_400_over_real_executor_mtls(isolated_test_dsn, tmp_path):
    """真三程序：Medusa 400 必須先有 Executor 來源再走另一 CA 的 Validator mTLS。"""
    import multiprocessing
    import ssl
    import time as clock

    import httpx
    import psycopg
    from fastapi.testclient import TestClient

    from deception.domains.ecommerce.carts import SyntheticCarts
    from deception.security.protected_rpc import (
        FixedExecutorMTLSClient, FixedNativeValidatorMTLSClient,
        create_fixed_executor_app, create_native_validator_app,
        serve_fixed_executor_mtls, serve_native_validator_mtls,
    )
    from deception.world.protected_world import PostgresProtectedWorldExecutor
    from deception.world.protected_native_http import PostgresProtectedNativeProjector
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
    validator_root = tmp_path / "validator-ca"
    validator_root.mkdir()
    validator_ca, validator_cert, validator_key, validator_client_cert, validator_client_key = (
        _issue_mtls_certificates(validator_root))
    assert validator_ca.read_bytes() != ca.read_bytes()
    port, validator_port = _unused_local_port(), _unused_local_port()
    while port == validator_port:
        validator_port = _unused_local_port()
    worker = multiprocessing.Process(target=serve_fixed_executor_mtls, kwargs={
        "app": create_fixed_executor_app(executor=executor), "host": "127.0.0.1", "port": port,
        "server_cert": server_cert, "server_key": server_key, "verifier_client_ca": ca,
    })
    validator_worker = multiprocessing.Process(target=serve_native_validator_mtls, kwargs={
        "app": create_native_validator_app(projector=PostgresProtectedNativeProjector(
            dsn, expected_login=login)),
        "host": "127.0.0.1", "port": validator_port,
        "server_cert": validator_cert, "server_key": validator_key,
        "verifier_client_ca": validator_ca,
    })
    worker.start()
    validator_worker.start()
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
        validator_context = ssl.create_default_context(cafile=str(validator_ca))
        validator_context.load_cert_chain(str(validator_client_cert), str(validator_client_key))
        with httpx.Client(verify=validator_context, trust_env=False, timeout=1.0) as validator_mtls:
            for _ in range(50):
                try:
                    assert validator_mtls.get(
                        f"https://127.0.0.1:{validator_port}/internal/ready"
                    ).status_code == 200
                    break
                except httpx.ConnectError:
                    if not validator_worker.is_alive():
                        pytest.fail("Medusa native validator terminated before readiness")
                    clock.sleep(0.1)
            else:
                pytest.fail("Medusa native validator did not become ready")
        with httpx.Client(verify=ssl.create_default_context(cafile=str(validator_ca)),
                          trust_env=False, timeout=2.0) as anonymous_validator:
            with pytest.raises(httpx.TransportError):
                anonymous_validator.get(f"https://127.0.0.1:{validator_port}/internal/ready")
        wrong_validator_client = ssl.create_default_context(cafile=str(validator_ca))
        wrong_validator_client.load_cert_chain(str(client_cert), str(client_key))
        with httpx.Client(verify=wrong_validator_client, trust_env=False,
                          timeout=2.0) as other_role:
            with pytest.raises(httpx.TransportError):
                other_role.get(f"https://127.0.0.1:{validator_port}/internal/ready")
        signer = Ed25519PrivateKey.generate()
        client = FixedExecutorMTLSClient(
            origin=f"https://127.0.0.1:{port}", client_cert=client_cert,
            client_key=client_key, server_ca=ca,
        )
        native_client = FixedNativeValidatorMTLSClient(
            origin=f"https://127.0.0.1:{validator_port}",
            client_cert=validator_client_cert, client_key=validator_client_key,
            server_ca=validator_ca,
        )
        app = create_direct_verifier_app(
            verifier=verifier(dsn, {"old": signer}), postgres_dsn=dsn,
            environment_id="env", deployment_id="deploy",
            expected_issuer="gateway", expected_audience="mirage", executor_client=client,
            native_validator_client=native_client,
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
            assert accepted.json()["native_projection"]["status_code"] == 400
            assert (accepted.json()["native_projection"]["envelope_hash"]
                    == accepted.json()["executor_result"]["envelope_hash"])
            from deception.world.protected_native_http import fixed_medusa_rejection_bytes

            headers, expected_body = fixed_medusa_rejection_bytes(400, "native-cart-invalid")
            projected = accepted.json()["native_projection"]
            assert projected["headers"] == [list(header) for header in headers]
            assert base64.b64decode(projected["body_b64"], validate=True) == expected_body
            assert projected["scope"]["session_id"] == created.binding.session_id
            assert projected["source"] == {
                "kind": "security_error", "template_id": "native-cart-invalid",
                "contract_revision": "medusa-cart-1",
            }
            assert projected["delivery"] == "candidate_only_no_send_authorization"
            # 目前仍是內部對帳 200，不能以本測試冒稱客戶端原生 400。
            assert accepted.headers["content-type"] == "application/json"
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
        for process in (worker, validator_worker):
            process.terminate()
            process.join(timeout=5)
            if process.is_alive():
                process.kill()
                process.join(timeout=5)


def test_three_process_gateway_verifier_executor_distinct_mtls_roots(isolated_test_dsn, tmp_path, request):
    """真三程序／CA／SCRAM：Gateway 原始 HTTP 不經 Runtime 建 Proof 並執行一次。"""
    import json
    import multiprocessing
    import ssl
    import time as clock

    import httpx
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict

    from deception.domains.ecommerce.inventory import SyntheticInventory
    from deception.security.protected_rpc import (
        FixedExecutorMTLSClient, create_fixed_executor_app, serve_direct_verifier_mtls,
        serve_fixed_executor_mtls,
    )
    from deception.security.protected_services import create_executor_service, create_verifier_service
    from deception.security.protected_rpc import ProtectedRpcConfigurationError
    from deception.world.protected_world import PostgresProtectedWorldExecutor
    from deception.world.session import SessionBinding
    from test_protected_rpc_mtls import _issue_mtls_certificates, _unused_local_port

    dsn, now = isolated_test_dsn, int(clock.time())
    binding = SessionBinding(environment_id="env", deployment_id="deploy",
                             session_id="session", session_epoch=1, access_mode="inventory")
    world = SyntheticInventory(dsn)
    snapshot = world.resolve(binding, {"inventory": {"sku-1": 5}, "reservations": {}},
                             now=now, ttl=120)
    logins = _isolated_three_process_service_logins(dsn, request)
    executor_dsn, executor_login = logins["executor"]
    verifier_dsn, _ = logins["verifier"]
    with psycopg.connect(verifier_dsn) as verifier_connection:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            verifier_connection.execute("SELECT * FROM protected_world_commit_sources LIMIT 0")
    with psycopg.connect(executor_dsn) as executor_connection:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            executor_connection.execute("INSERT INTO ingress_receipts DEFAULT VALUES")
    trusted_executor = PostgresProtectedWorldExecutor(
        executor_dsn, expected_login=executor_login,
        world_store=SyntheticInventory(executor_dsn),
    )
    gateway_ca_root, executor_ca_root = tmp_path / "gateway-root", tmp_path / "executor-root"
    gateway_ca_root.mkdir()
    executor_ca_root.mkdir()
    validator_ca_root = tmp_path / "validator-root"
    validator_ca_root.mkdir()
    gateway_ca, verifier_cert, verifier_key, gateway_cert, gateway_key = _issue_mtls_certificates(
        gateway_ca_root)
    executor_ca, executor_cert, executor_key, verifier_client_cert, verifier_client_key = (
        _issue_mtls_certificates(executor_ca_root))
    validator_ca, _, _, validator_client_cert, validator_client_key = (
        _issue_mtls_certificates(validator_ca_root))
    assert gateway_ca.read_bytes() != executor_ca.read_bytes()
    verifier_port, executor_port = _unused_local_port(), _unused_local_port()
    while verifier_port == executor_port:
        executor_port = _unused_local_port()
    signer = Ed25519PrivateKey.generate()
    verifier_dsn_file, executor_dsn_file = tmp_path / "verifier.dsn", tmp_path / "executor.dsn"
    verifier_dsn_file.write_text(verifier_dsn, encoding="utf-8")
    executor_dsn_file.write_text(executor_dsn, encoding="utf-8")
    keys_file = tmp_path / "verifier-keys.json"
    keys_file.write_text(json.dumps({"old": base64.b64encode(
        signer.public_key().public_bytes_raw()).decode("ascii")}), encoding="utf-8")
    verifier_config = {
        "MIRAGE_G3B_VERIFIER_DSN_FILE": str(verifier_dsn_file),
        "MIRAGE_G3B_VERIFIER_LOGIN": logins["verifier"][1],
        "MIRAGE_G3B_ENVIRONMENT_ID": "env", "MIRAGE_G3B_DEPLOYMENT_ID": "deploy",
        "MIRAGE_G3B_WORLD_SCHEMA": conninfo_to_dict(dsn)["options"].split("search_path=", 1)[1].split(" ", 1)[0],
        "MIRAGE_G3B_EXPECTED_ISSUER": "gateway", "MIRAGE_G3B_EXPECTED_AUDIENCE": "mirage",
        "MIRAGE_G3B_VERIFIER_KEYS_FILE": str(keys_file),
        "MIRAGE_G3B_INVENTORY_EXECUTOR_ORIGIN": f"https://127.0.0.1:{executor_port}",
        "MIRAGE_G3B_CART_EXECUTOR_ORIGIN": f"https://127.0.0.1:{executor_port}",
        "MIRAGE_G3B_VERIFIER_CLIENT_CERT_FILE": str(verifier_client_cert),
        "MIRAGE_G3B_VERIFIER_CLIENT_KEY_FILE": str(verifier_client_key),
        "MIRAGE_G3B_EXECUTOR_SERVER_CA_FILE": str(executor_ca),
        "MIRAGE_G3B_NATIVE_VALIDATOR_ORIGIN": "https://127.0.0.1:18445",
        "MIRAGE_G3B_VERIFIER_VALIDATOR_CERT_FILE": str(validator_client_cert),
        "MIRAGE_G3B_VERIFIER_VALIDATOR_KEY_FILE": str(validator_client_key),
        "MIRAGE_G3B_NATIVE_VALIDATOR_SERVER_CA_FILE": str(validator_ca),
    }
    executor_config = {
        "MIRAGE_G3B_EXECUTOR_DSN_FILE": str(executor_dsn_file),
        "MIRAGE_G3B_EXECUTOR_LOGIN": executor_login,
        "MIRAGE_G3B_EXECUTOR_PLATFORM": "synthetic-inventory",
        "MIRAGE_G3B_WORLD_SCHEMA": verifier_config["MIRAGE_G3B_WORLD_SCHEMA"],
    }
    assert create_verifier_service(verifier_config).state is not None
    assert create_executor_service(executor_config).state is not None
    with pytest.raises(ProtectedRpcConfigurationError, match="physical_login_denied"):
        create_executor_service({**executor_config, "MIRAGE_G3B_EXECUTOR_LOGIN": logins["runtime"][1]})
    with pytest.raises(ProtectedRpcConfigurationError, match="required_acl_missing"):
        create_executor_service({**executor_config, "MIRAGE_G3B_EXECUTOR_PLATFORM": "synthetic-carts"})
    executor_client = FixedExecutorMTLSClient(
        origin=f"https://127.0.0.1:{executor_port}", client_cert=verifier_client_cert,
        client_key=verifier_client_key, server_ca=executor_ca,
    )
    verifier_app = create_direct_verifier_app(
        verifier=verifier(verifier_dsn, {"old": signer}), postgres_dsn=verifier_dsn,
        environment_id="env", deployment_id="deploy",
        expected_issuer="gateway", expected_audience="mirage",
        executor_clients={"synthetic-inventory": executor_client},
    )
    executor_worker = multiprocessing.Process(target=serve_fixed_executor_mtls, kwargs={
        "app": create_fixed_executor_app(executor=trusted_executor),
        "host": "127.0.0.1", "port": executor_port,
        "server_cert": executor_cert, "server_key": executor_key,
        "verifier_client_ca": executor_ca,
    })
    verifier_worker = multiprocessing.Process(target=serve_direct_verifier_mtls, kwargs={
        "app": verifier_app, "host": "127.0.0.1", "port": verifier_port,
        "server_cert": verifier_cert, "server_key": verifier_key, "client_ca": gateway_ca,
    })
    executor_worker.start()
    verifier_worker.start()
    try:
        executor_context = ssl.create_default_context(cafile=str(executor_ca))
        executor_context.load_cert_chain(str(verifier_client_cert), str(verifier_client_key))
        with httpx.Client(verify=executor_context, trust_env=False, timeout=2.0) as internal:
            for _ in range(70):
                try:
                    assert internal.get(f"https://127.0.0.1:{executor_port}/internal/ready").status_code == 200
                    break
                except httpx.ConnectError:
                    if not executor_worker.is_alive():
                        pytest.fail("fixed executor terminated before readiness")
                    clock.sleep(0.1)
            else:
                pytest.fail("three-process executor did not become ready")
        gateway_context = ssl.create_default_context(cafile=str(gateway_ca))
        gateway_context.load_cert_chain(str(gateway_cert), str(gateway_key))
        with httpx.Client(verify=gateway_context, trust_env=False, timeout=8.0) as gateway:
            url = f"https://127.0.0.1:{verifier_port}/synthetic/inventory/reservations"
            for _ in range(70):
                try:
                    ready = gateway.get(f"https://127.0.0.1:{verifier_port}/internal/ready")
                    assert ready.status_code == 200
                    break
                except httpx.ConnectError:
                    if not verifier_worker.is_alive() or not executor_worker.is_alive():
                        pytest.fail("independent mTLS service terminated before readiness")
                    clock.sleep(0.1)
            else:
                pytest.fail("three-process verifier did not become ready")
            assert gateway.post(f"https://127.0.0.1:{verifier_port}/synthetic/carts",
                                json={}, headers={"x-request-id": "unwired-cart"}).status_code == 503
            body = json.dumps({"sku": "sku-1", "quantity": 2, "expected_version": 1,
                               "idempotency_key": "three-process-once",
                               "commit_attempt_id": str(uuid4())}).encode()
            outbound = gateway.build_request(
                "POST", url, content=body,
                headers={"x-request-id": "gateway-three-process-1",
                         "content-type": "application/json"},
            )
            fingerprint = fingerprint_httpx_request(outbound, "gateway-three-process-1")
            assert gateway.send(outbound).status_code == 403
            outbound.headers["x-trusted-session"] = signed(
                signer, jti=uuid4().hex, fingerprint=fingerprint, access_mode="inventory",
            )
            tampered = gateway.build_request(
                "POST", url, content=body.replace(b'"sku-1"', b'"sku-2"'),
                headers=dict(outbound.headers),
            )
            assert gateway.send(tampered).status_code == 403
            accepted = gateway.send(outbound)
            assert accepted.status_code == 200, accepted.text
            result = accepted.json()
            assert result["operation_id"] == "reserveSyntheticInventory"
            assert result["executor_result"]["status"] == "committed"
            assert result["executor_result"]["operation"] == result["operation_id"]
            assert gateway.send(outbound).status_code == 403
        with httpx.Client(verify=ssl.create_default_context(cafile=str(gateway_ca)),
                          trust_env=False, timeout=2.0) as anonymous:
            with pytest.raises(httpx.TransportError):
                anonymous.get(f"https://127.0.0.1:{verifier_port}/internal/ready")
        wrong_ca = ssl.create_default_context(cafile=str(gateway_ca))
        wrong_ca.load_cert_chain(str(verifier_client_cert), str(verifier_client_key))
        with httpx.Client(verify=wrong_ca, trust_env=False, timeout=2.0) as wrong_role:
            with pytest.raises(httpx.TransportError):
                wrong_role.get(f"https://127.0.0.1:{verifier_port}/internal/ready")
        with psycopg.connect(dsn) as connection:
            assert connection.execute(
                "SELECT state->'inventory'->>'sku-1' FROM world_snapshots WHERE world_generation_id=%s",
                (snapshot.scope.world_generation_id,),
            ).fetchone()[0] == "3"
            assert connection.execute("SELECT count(*) FROM protected_http_operation_bindings"
                                      ).fetchone()[0] == 1
            assert connection.execute("SELECT count(*) FROM protected_world_commit_sources"
                                      ).fetchone()[0] == 1
        with psycopg.connect(logins["runtime"][0]) as runtime:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                runtime.execute("INSERT INTO protected_http_operation_bindings(receipt_id) VALUES (%s)",
                                (uuid4(),))
        with psycopg.connect(logins["runtime"][0]) as runtime:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                runtime.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(executor_login)))
    finally:
        for worker in (verifier_worker, executor_worker):
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
