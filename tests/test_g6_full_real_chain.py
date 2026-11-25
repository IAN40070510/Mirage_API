"""G3b～G6 隔離真鏈：Client TLS→Gateway→六段 mTLS→PG 原生 HTTP。"""

import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import secrets
import ssl
import time
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import httpx
import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
import pytest

from deception.api.fingerprint import fingerprint_httpx_request
from deception.domains.ecommerce.inventory import SyntheticInventory
from deception.security.protected_gateway import (
    FixedGatewaySenderMTLSClient, FixedGatewayVerifierMTLSClient,
    create_gateway_native_proxy_candidate_app, serve_gateway_native_proxy_loopback_tls,
)
from deception.security.protected_rpc import (
    FixedAuthorizerMTLSClient, FixedCandidatePublisherMTLSClient,
    FixedExecutorMTLSClient, FixedNativeValidatorMTLSClient,
    create_direct_verifier_app, create_fixed_authorizer_app,
    create_fixed_candidate_publisher_app, create_fixed_executor_app,
    create_native_validator_app, create_receipt_proxy_sender_candidate_app,
    serve_direct_verifier_mtls, serve_fixed_authorizer_mtls,
    serve_fixed_candidate_publisher_mtls, serve_fixed_executor_mtls,
    serve_fixed_sender_mtls, serve_native_validator_mtls,
)
from deception.world import (
    PostgresCandidatePromoter, PostgresCandidateStore, PostgresProjectionRegistry,
    PostgresProtectedAuthorizer, PostgresProtectedSender, PostgresProtectedWorldExecutor,
    PostgresVerifiedReceiptPublisher, ProjectionCompatibilityProfile, ProjectionEvidence,
)
from deception.world.protected_native_http import PostgresProtectedNativeProjector
from deception.world.session import SessionBinding
from test_ingress_receipts import signed
from test_key_revocation import verifier as trusted_verifier
from test_postgres_conformance import isolated_test_dsn
from test_protected_grant import _login
from test_protected_rpc_mtls import _issue_mtls_certificates, _unused_local_port


def _g6_projection_profiles():
    """以三種固定平台 Evidence 建立可核對的隔離 Publisher 契約。"""
    profiles = {}
    for platform in ("synthetic-inventory", "synthetic-carts", "medusa-native-cart"):
        source_hash = hashlib.sha256(("g6-source-" + platform).encode()).hexdigest()
        profiles[platform] = ProjectionEvidence(
            source_spec_sha256=source_hash,
            compatibility_profile=ProjectionCompatibilityProfile(
                profile_id="g6-isolated", profile_version="1",
                profile_sha256=hashlib.sha256(("g6-profile-" + platform).encode()).hexdigest(),
                platform_id=platform, platform_version="1",
                source_spec_sha256=source_hash, world_schema_version="1",
                domain_adapter_version="1",
            ),
            projection_contract_hash=hashlib.sha256(
                ("g6-contract-" + platform).encode()).hexdigest(),
            official_schema_valid=True, effective_projection_valid=True,
        )
    return profiles


def _g6_create_promoter_login(dsn, request):
    """僅在明示拋棄式 PG 建立一個最小權限的 Promoter Role 並註冊清理。"""
    if os.environ.get("MIRAGE_WORLD_ROLE_TEST_ISOLATED") != "true":
        pytest.skip("requires explicitly disposable isolated PostgreSQL role lab")
    schema = conninfo_to_dict(dsn)["options"].split("search_path=", 1)[1].split(" ", 1)[0]
    name = "mirage_g6_promoter_" + uuid4().hex[:12]
    password = secrets.token_urlsafe(32)
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(sql.SQL(
            "CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "NOREPLICATION NOBYPASSRLS PASSWORD {}"
        ).format(sql.Identifier(name), sql.Literal(password)))

    def cleanup():
        """只撤銷此測試單一 Role 的 grants 與 LOGIN，保留所有共享實例。"""
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(name)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(name)))

    request.addfinalizer(cleanup)
    with psycopg.connect(dsn, autocommit=True) as admin:
        promoter = sql.Identifier(name)
        admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
            sql.Identifier(schema), promoter))
        admin.execute(sql.SQL(
            "GRANT SELECT ON candidate_records,read_admissions,world_operations,"
            "protected_world_read_sources,protected_world_commit_sources,"
            "projection_registry,projection_profile_revocations,ingress_receipts,"
            "protected_http_operation_bindings,protected_world_rejection_sources,"
            "protected_medusa_rejection_sources,protected_cart_creations,"
            "guest_cart_creations,synthetic_resources,session_heads,"
            "session_world_bindings,generation_controls,world_snapshots,"
            "world_commit_receipts,trusted_key_revocations TO {}"
        ).format(promoter))
        admin.execute(sql.SQL(
            "GRANT INSERT,SELECT ON protected_candidate_promotions TO {}"
        ).format(promoter))
        admin.execute(sql.SQL(
            "GRANT EXECUTE ON FUNCTION protected_lock_reference(text,jsonb) TO {}"
        ).format(promoter))
    return make_conninfo(dsn, user=name, password=password), name


def _g6_tls_endpoint(tmp_path: Path, name: str, app, serve, client_ca_arg):
    """建立用途分離的 CA，固定一個 loopback mTLS Listener 與握手客戶端。"""
    root = tmp_path / name
    root.mkdir()
    ca, server_cert, server_key, client_cert, client_key = _issue_mtls_certificates(root)
    port = _unused_local_port()
    worker = multiprocessing.Process(target=serve, kwargs={
        "app": app, "host": "127.0.0.1", "port": port,
        "server_cert": server_cert, "server_key": server_key,
        client_ca_arg: ca,
    })
    return {
        "name": name, "port": port, "ca": ca, "server_cert": server_cert,
        "server_key": server_key, "client_cert": client_cert,
        "client_key": client_key, "worker": worker,
    }


def _g6_client(endpoint, client_class):
    """固定 mTLS 出站 URL、Client Cert／Key 與 Server CA，不允許改路由。"""
    return client_class(
        origin=f"https://127.0.0.1:{endpoint['port']}",
        client_cert=endpoint["client_cert"], client_key=endpoint["client_key"],
        server_ca=endpoint["ca"],
    )


def _g6_wait_ready(endpoint):
    """以實際 CA+Client cert TLS 握手確認獨立服務，而非依賴固定 sleep。"""
    context = ssl.create_default_context(cafile=str(endpoint["ca"]))
    context.load_cert_chain(str(endpoint["client_cert"]), str(endpoint["client_key"]))
    with httpx.Client(verify=context, trust_env=False, timeout=1) as probe:
        for _ in range(50):
            try:
                ready = probe.get(f"https://127.0.0.1:{endpoint['port']}/internal/ready")
                assert ready.status_code == 200
                return
            except (httpx.ConnectError, httpx.ReadError):
                assert endpoint["worker"].is_alive(), endpoint["name"] + " worker died"
                time.sleep(0.1)
    pytest.fail(endpoint["name"] + " mTLS readiness timed out")


def _g6_signed_client_request(client, signer_key, gateway_port, *,
                              method, path, request_id, body=None,
                              access_mode="inventory", session_id="session",
                              resource_id=None):
    """在 Client 發送前依精確 HTTPX URL／Headers／Body 簽 Ed25519 JWS。"""
    headers = {"x-request-id": request_id}
    kwargs = {}
    if body is not None:
        headers["content-type"] = "application/json"
        kwargs["content"] = json.dumps(body, separators=(",", ":")).encode("utf-8")
    outbound = client.build_request(
        method, f"https://127.0.0.1:{gateway_port}{path}",
        headers=headers, **kwargs,
    )
    jti = uuid4().hex
    outbound.headers["x-trusted-session"] = signed(
        signer_key, jti=jti,
        fingerprint=fingerprint_httpx_request(outbound, request_id),
        access_mode=access_mode, session_id=session_id, resource_id=resource_id,
    )
    return outbound, jti


def test_g6_full_real_jws_seven_tls_hops_native_http_and_replay(
        tmp_path, request, isolated_test_dsn):
    """I-01～I-04 八種真 Client 2xx／4xx 經七 TLS／PG Grant/Lease，JWS 重放禁止。"""
    dsn = isolated_test_dsn
    login = _login(dsn)
    now = int(time.time())
    binding = SessionBinding(
        environment_id="env", deployment_id="deploy", session_id="session",
        session_epoch=1, access_mode="inventory",
    )
    world = SyntheticInventory(dsn)
    world.resolve(binding, {"inventory": {"sku-1": 4}, "reservations": {}},
                  now=now, ttl=150)
    profiles = _g6_projection_profiles()
    PostgresProjectionRegistry(dsn).ensure_registered_batch((profiles["synthetic-inventory"],))
    promoter_dsn, promoter_login = _g6_create_promoter_login(dsn, request)
    projector = PostgresProtectedNativeProjector(dsn, expected_login=login)
    publisher = PostgresVerifiedReceiptPublisher(
        projector=projector, candidate_store=PostgresCandidateStore(dsn),
        promoter=PostgresCandidatePromoter(promoter_dsn, expected_login=promoter_login),
        evidence_by_platform=profiles,
    )
    signer_key = Ed25519PrivateKey.generate()
    endpoint_specs = (
        ("executor", create_fixed_executor_app(executor=PostgresProtectedWorldExecutor(
            dsn, expected_login=login, world_store=world,
            rejection_templates={
                "unknown_synthetic_sku": "synthetic-inventory-1",
                "reservation_not_active": "synthetic-inventory-1",
            })),
         serve_fixed_executor_mtls, "verifier_client_ca"),
        ("validator", create_native_validator_app(projector=projector),
         serve_native_validator_mtls, "verifier_client_ca"),
        ("publisher", create_fixed_candidate_publisher_app(publisher=publisher),
         serve_fixed_candidate_publisher_mtls, "verifier_client_ca"),
        ("authorizer", create_fixed_authorizer_app(authorizer=PostgresProtectedAuthorizer(
            dsn, expected_login=login)),
         serve_fixed_authorizer_mtls, "verifier_client_ca"),
        ("sender", create_receipt_proxy_sender_candidate_app(sender=PostgresProtectedSender(
            dsn, expected_login=login)),
         serve_fixed_sender_mtls, "sender_client_ca"),
    )
    endpoints = {name: _g6_tls_endpoint(tmp_path, name, app, serve, ca_arg)
                 for name, app, serve, ca_arg in endpoint_specs}
    # 真 Verifier 必須先接上固定五個內部 Client，才有資格核發 Receipt 授權鏈。
    verifier_app = create_direct_verifier_app(
        verifier=trusted_verifier(dsn, {"old": signer_key}), postgres_dsn=dsn,
        environment_id="env", deployment_id="deploy",
        expected_issuer="gateway", expected_audience="mirage",
        executor_client=_g6_client(endpoints["executor"], FixedExecutorMTLSClient),
        native_validator_client=_g6_client(endpoints["validator"], FixedNativeValidatorMTLSClient),
        candidate_publisher_client=_g6_client(
            endpoints["publisher"], FixedCandidatePublisherMTLSClient),
        authorizer_client=_g6_client(endpoints["authorizer"], FixedAuthorizerMTLSClient),
    )
    endpoints["verifier"] = _g6_tls_endpoint(
        tmp_path, "verifier", verifier_app, serve_direct_verifier_mtls, "client_ca")
    gateway_app = create_gateway_native_proxy_candidate_app(
        verifier_client=_g6_client(endpoints["verifier"], FixedGatewayVerifierMTLSClient),
        sender_client=_g6_client(endpoints["sender"], FixedGatewaySenderMTLSClient),
    )
    client_root = tmp_path / "client-https"
    client_root.mkdir()
    client_ca, client_cert, client_key, _, _ = _issue_mtls_certificates(client_root)
    gateway_port = _unused_local_port()
    gateway_worker = multiprocessing.Process(target=serve_gateway_native_proxy_loopback_tls,
        kwargs={"app": gateway_app, "host": "127.0.0.1", "port": gateway_port,
                "server_cert": client_cert, "server_key": client_key})
    workers = [endpoint["worker"] for endpoint in endpoints.values()] + [gateway_worker]
    try:
        for endpoint in endpoints.values():
            endpoint["worker"].start()
        for endpoint in endpoints.values():
            _g6_wait_ready(endpoint)
        gateway_worker.start()
        context = ssl.create_default_context(cafile=str(client_ca))
        with httpx.Client(verify=context, trust_env=False, timeout=30) as client:
            for _ in range(50):
                try:
                    ready = client.get(f"https://127.0.0.1:{gateway_port}/internal/ready")
                    assert ready.status_code == 200
                    break
                except httpx.ConnectError:
                    assert gateway_worker.is_alive()
                    time.sleep(0.1)
            else:
                pytest.fail("G6 true Client HTTPS listener did not become ready")
            original, jti = _g6_signed_client_request(
                client, signer_key, gateway_port, method="GET",
                path="/synthetic/inventory/sku-1", request_id="g6-real-jws-1")
            native = client.send(original)
            if native.status_code != 200:
                with psycopg.connect(dsn) as debug_connection:
                    counts = {name: debug_connection.execute(
                        "SELECT count(*) FROM " + name).fetchone()[0] for name in (
                            "replay_entries", "ingress_receipts", "read_admissions",
                            "protected_candidate_promotions", "response_admissions",
                            "protected_send_leases",
                        )}
                pytest.fail(f"native {native.status_code}: {native.text}; stages={counts}")
            assert native.json() == {"sku": "sku-1", "available": 4, "state_version": 1}
            duplicate = client.send(original)
            assert duplicate.status_code == 503
            assert duplicate.json() == {"detail": "gateway_delivery_unverifiable"}
            assert b"available" not in duplicate.content
            # I-04 真業務 409 必須走同一條獨立投影→Grant→Sender，不能由 Gateway 造錯誤。
            missing, missing_jti = _g6_signed_client_request(
                client, signer_key, gateway_port, method="GET",
                path="/synthetic/inventory/not-in-world",
                request_id="g6-real-jws-native-409")
            missing_native = client.send(missing)
            assert missing_native.status_code == 409, missing_native.text
            assert missing_native.content == b'{"code":"unknown_synthetic_sku"}'
            assert missing_native.headers["content-type"] == "application/json"
            missing_replay = client.send(missing)
            assert missing_replay.status_code == 503
            assert missing_replay.json() == {"detail": "gateway_delivery_unverifiable"}
            # I-01：真世界預留 Commit → 獨立 Validator 的原生 200，不是 RPC 元資料。
            reservation_attempt = str(uuid4())
            reserve, reserve_jti = _g6_signed_client_request(
                client, signer_key, gateway_port, method="POST",
                path="/synthetic/inventory/reservations", request_id="g6-inventory-reserve",
                body={"sku": "sku-1", "quantity": 2, "expected_version": 1,
                      "idempotency_key": "g6-reserve-once",
                      "commit_attempt_id": reservation_attempt},
            )
            reserved = client.send(reserve)
            assert reserved.status_code == 200, reserved.text
            reservation = reserved.json()
            assert reservation["commit_attempt_id"] == reservation_attempt
            assert reservation["state_version"] == 2
            reservation_id = reservation["reservation"]["reservation_id"]
            assert reservation["reservation"]["sku"] == "sku-1"
            assert client.send(reserve).json() == {"detail": "gateway_delivery_unverifiable"}
            # I-03：歷史 operation 真 200；缺少另一個 UUID4 的真業務 409。
            history, history_jti = _g6_signed_client_request(
                client, signer_key, gateway_port, method="GET",
                path="/synthetic/operations/" + reservation_attempt,
                request_id="g6-inventory-history-200",
            )
            history_response = client.send(history)
            assert history_response.status_code == 200, history_response.text
            assert history_response.json()["commit_attempt_id"] == reservation_attempt
            absent_operation, absent_operation_jti = _g6_signed_client_request(
                client, signer_key, gateway_port, method="GET",
                path="/synthetic/operations/" + str(uuid4()),
                request_id="g6-inventory-history-409",
            )
            absent_history = client.send(absent_operation)
            assert absent_history.status_code == 409, absent_history.text
            assert absent_history.content == b'{"code":"operation_not_found"}'
            # I-02：真取消 200，另一個新 Receipt 的重複取消 409，不得生成假成功。
            cancel_path = "/synthetic/inventory/reservations/" + reservation_id + "/cancel"
            cancel, cancel_jti = _g6_signed_client_request(
                client, signer_key, gateway_port, method="POST", path=cancel_path,
                request_id="g6-inventory-cancel-200",
                body={"expected_version": 2, "idempotency_key": "g6-cancel-once",
                      "commit_attempt_id": str(uuid4())},
            )
            cancelled = client.send(cancel)
            assert cancelled.status_code == 200, cancelled.text
            assert cancelled.json()["state_version"] == 3
            assert cancelled.json()["reservation"]["reservation_id"] == reservation_id
            assert cancelled.json()["reservation"]["status"] == "cancelled"
            cancel_again, cancel_again_jti = _g6_signed_client_request(
                client, signer_key, gateway_port, method="POST", path=cancel_path,
                request_id="g6-inventory-cancel-409",
                body={"expected_version": 3, "idempotency_key": "g6-cancel-again",
                      "commit_attempt_id": str(uuid4())},
            )
            already_cancelled = client.send(cancel_again)
            assert already_cancelled.status_code == 409, already_cancelled.text
            assert already_cancelled.content == b'{"code":"reservation_not_active"}'
            # I-01 負面：未知 SKU 必須由受保護 Handler 拒絕、原生 409。
            unknown_sku, unknown_sku_jti = _g6_signed_client_request(
                client, signer_key, gateway_port, method="POST",
                path="/synthetic/inventory/reservations", request_id="g6-reserve-unknown-409",
                body={"sku": "not-in-world", "quantity": 1, "expected_version": 3,
                      "idempotency_key": "g6-reserve-unknown",
                      "commit_attempt_id": str(uuid4())},
            )
            unknown_result = client.send(unknown_sku)
            assert unknown_result.status_code == 409, unknown_result.text
            assert unknown_result.content == b'{"code":"unknown_synthetic_sku"}'
            for used in (history, absent_operation, cancel, cancel_again, unknown_sku):
                replay = client.send(used)
                assert replay.status_code == 503
                assert replay.json() == {"detail": "gateway_delivery_unverifiable"}
        with psycopg.connect(dsn) as connection:
            all_jtis = (jti, missing_jti, reserve_jti, history_jti,
                        absent_operation_jti, cancel_jti, cancel_again_jti, unknown_sku_jti)
            assert connection.execute(
                "SELECT count(*) FROM replay_entries WHERE jti=ANY(%s)",
                (list(all_jtis),),
            ).fetchone() == (8,)
            assert connection.execute(
                "SELECT count(*) FROM ingress_receipts WHERE jti=ANY(%s)",
                (list(all_jtis),),
            ).fetchone() == (8,)
            assert connection.execute(
                "SELECT count(*) FROM protected_candidate_promotions"
            ).fetchone() == (8,)
            assert connection.execute(
                "SELECT count(*) FROM protected_send_leases"
            ).fetchone() == (8,)
    finally:
        for worker in workers:
            if worker.pid is not None:
                worker.terminate()
                worker.join(timeout=5)
                if worker.is_alive():
                    worker.kill()
                    worker.join(timeout=5)
