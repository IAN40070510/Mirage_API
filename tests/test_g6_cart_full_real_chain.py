"""G3b～G6 Cart→Order 全路由：真 Client HTTPS、七 TLS、真 PostgreSQL Lease。"""

import json
import multiprocessing
import ssl
import time
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import httpx
import psycopg
import pytest

from deception.domains.ecommerce.carts import SyntheticCarts
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
    PostgresVerifiedReceiptPublisher,
)
from deception.world.protected_native_http import PostgresProtectedNativeProjector
from deception.world.session import SessionBinding
from test_g6_full_real_chain import (
    _g6_client, _g6_create_promoter_login, _g6_create_service_logins,
    _g6_projection_profiles,
    _g6_signed_client_request, _g6_stage_counts, _g6_tls_endpoint, _g6_wait_ready,
)
from test_key_revocation import verifier as trusted_verifier
from test_postgres_conformance import isolated_test_dsn
from test_protected_rpc_mtls import _issue_mtls_certificates, _unused_local_port


def test_g6_cart_order_nine_native_routes_seven_tls_and_replay(
        tmp_path, request, isolated_test_dsn):
    """C-01～C-09 真 Client 200／業務 409、逐筆 Replay 拒絕及不可重複 Lease。"""
    dsn = isolated_test_dsn
    now = int(time.time())
    initial = {
        "catalog": {"v1": {"sku": "sku-1", "unit_price": 100}},
        "inventory": {"sku-1": 5},
    }
    creator = SessionBinding(
        environment_id="env", deployment_id="deploy", session_id="session",
        session_epoch=1, access_mode="cart",
    )
    world = SyntheticCarts(dsn)
    world.resolve(creator, {**initial, "reservations": {}}, now=now, ttl=240)
    profiles = _g6_projection_profiles()
    PostgresProjectionRegistry(dsn).ensure_registered_batch((profiles["synthetic-carts"],))
    logins = _g6_create_service_logins(dsn, request, platform="synthetic-carts")
    promoter_dsn, promoter_login = _g6_create_promoter_login(dsn, request)
    projector = PostgresProtectedNativeProjector(
        logins["validator"][0], expected_login=logins["validator"][1],
    )
    publisher = PostgresVerifiedReceiptPublisher(
        projector=projector, candidate_store=PostgresCandidateStore(logins["candidate_writer"][0]),
        promoter=PostgresCandidatePromoter(promoter_dsn, expected_login=promoter_login),
        evidence_by_platform=profiles,
    )
    signer = Ed25519PrivateKey.generate()
    executor = PostgresProtectedWorldExecutor(
        logins["executor"][0], expected_login=logins["executor"][1],
        world_store=SyntheticCarts(logins["executor"][0]), cart_initial_state=initial,
        rejection_templates={code: "synthetic-carts-1" for code in (
            "cart_item_not_found", "unknown_synthetic_variant",
            "insufficient_synthetic_inventory", "empty_synthetic_cart",
            "cart_not_active", "order_not_cancellable",
        )},
    )
    endpoint_specs = (
        ("executor", create_fixed_executor_app(executor=executor),
         serve_fixed_executor_mtls, "verifier_client_ca"),
        ("validator", create_native_validator_app(projector=projector),
         serve_native_validator_mtls, "verifier_client_ca"),
        ("publisher", create_fixed_candidate_publisher_app(publisher=publisher),
         serve_fixed_candidate_publisher_mtls, "verifier_client_ca"),
        ("authorizer", create_fixed_authorizer_app(
            authorizer=PostgresProtectedAuthorizer(
                logins["authorizer"][0], expected_login=logins["authorizer"][1])),
         serve_fixed_authorizer_mtls, "verifier_client_ca"),
        ("sender", create_receipt_proxy_sender_candidate_app(
            sender=PostgresProtectedSender(
                logins["sender"][0], expected_login=logins["sender"][1])),
         serve_fixed_sender_mtls, "sender_client_ca"),
    )
    endpoints = {name: _g6_tls_endpoint(tmp_path, name, app, serve, ca_arg)
                 for name, app, serve, ca_arg in endpoint_specs}
    verifier_app = create_direct_verifier_app(
        verifier=trusted_verifier(logins["verifier"][0], {"old": signer}),
        postgres_dsn=logins["verifier"][0],
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
    ca, certificate, private_key, _, _ = _issue_mtls_certificates(client_root)
    gateway_port = _unused_local_port()
    gateway_worker = multiprocessing.Process(
        target=serve_gateway_native_proxy_loopback_tls,
        kwargs={"app": gateway_app, "host": "127.0.0.1", "port": gateway_port,
                "server_cert": certificate, "server_key": private_key},
    )
    workers = [endpoint["worker"] for endpoint in endpoints.values()] + [gateway_worker]
    jtids = []
    try:
        for endpoint in endpoints.values():
            endpoint["worker"].start()
        for endpoint in endpoints.values():
            _g6_wait_ready(endpoint)
        gateway_worker.start()
        context = ssl.create_default_context(cafile=str(ca))
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
                pytest.fail("Cart true Client HTTPS listener did not become ready")

            def native(method, path, *, body=None, binding=creator,
                       expected=200, code=None):
                """逐筆提交受信 JWS、核對真業務 Envelope、立即拒絕同 JTI 重播。"""
                original, jti = _g6_signed_client_request(
                    client, signer, gateway_port, method=method, path=path,
                    request_id="g6-cart-" + uuid4().hex, body=body,
                    access_mode="cart", session_id=binding.session_id,
                    resource_id=binding.resource_id,
                )
                response = client.send(original)
                assert response.status_code == expected, (
                    f"{method} {path}: expected {expected}, got "
                    f"{response.status_code}: {response.text}; "
                    f"stages={_g6_stage_counts(dsn)}"
                )
                if code:
                    assert response.content == json.dumps(
                        {"code": code}, separators=(",", ":")).encode()
                else:
                    assert response.headers["content-type"] == "application/json"
                replay = client.send(original)
                assert replay.status_code == 503, (method, path, replay.text)
                assert replay.json() == {"detail": "gateway_delivery_unverifiable"}
                jtids.append(jti)
                return response.json()

            def mutation(version, name, **fields):
                """生成真實 UUID4 Attempt 與固定版本的 Cart／Order 命令。"""
                return {
                    **fields, "expected_version": version,
                    "idempotency_key": name, "commit_attempt_id": str(uuid4()),
                }

            def fail_closed(method, path, *, body=None, binding=creator):
                """越權或舊 CAS 僅得固定 503，不得冒充可送達的業務回應。"""
                attempted, _ = _g6_signed_client_request(
                    client, signer, gateway_port, method=method, path=path,
                    request_id="g6-cart-denied-" + uuid4().hex, body=body,
                    access_mode="cart", session_id=binding.session_id,
                    resource_id=binding.resource_id,
                )
                denied = client.send(attempted)
                assert denied.status_code == 503, (method, path, denied.text)
                assert denied.json() == {"detail": "gateway_delivery_unverifiable"}

            # Creator 的能力不能被當成 Derived Cart 能力；Test 控制面
            # 從受保護 Resource Mapping 取得 Derived Session 供簽發新的有效 JWS。
            created = native("POST", "/synthetic/carts", body={})
            cart_id = created["cart"]["id"]
            assert cart_id.startswith("cart_")
            assert created["state_version"] == 1
            cart = world.resource_binding(
                cart_id, environment_id="env", deployment_id="deploy", now=int(time.time()),
            )
            cart_path = "/synthetic/carts/" + cart_id
            fetched = native("GET", cart_path, binding=cart)
            assert fetched["cart"] == created["cart"]
            assert fetched["state_version"] == 1
            # 原 Creator 即使知道 ID，也不能跨到 Derived Session 讀 Cart。
            fail_closed("GET", cart_path)

            unknown = native(
                "POST", cart_path + "/line-items", binding=cart, expected=409,
                code="unknown_synthetic_variant",
                body=mutation(1, "cart-unknown-variant", variant_id="absent", quantity=1),
            )
            assert unknown == {"code": "unknown_synthetic_variant"}
            add_attempt = str(uuid4())
            added = native(
                "POST", cart_path + "/line-items", binding=cart,
                body={**mutation(1, "cart-add", variant_id="v1", quantity=2),
                      "commit_attempt_id": add_attempt},
            )
            assert added["state_version"] == 2
            item = added["cart"]["items"][0]
            assert item["quantity"] == 2
            # CAS 舊版本不具真實 Handler 409 Source，必須阻斷發送。
            fail_closed(
                "POST", cart_path + "/line-items", binding=cart,
                body=mutation(1, "cart-stale-cas", variant_id="v1", quantity=1),
            )
            assert native(
                "GET", cart_path + "/operations/" + add_attempt, binding=cart,
            )["commit_attempt_id"] == add_attempt
            assert native(
                "GET", cart_path + "/operations/" + str(uuid4()), binding=cart,
                expected=409, code="operation_not_found",
            ) == {"code": "operation_not_found"}

            item_path = cart_path + "/line-items/" + item["id"]
            updated = native(
                "POST", item_path, binding=cart,
                body=mutation(2, "cart-update", quantity=3),
            )
            assert updated["state_version"] == 3
            assert updated["cart"]["items"][0]["quantity"] == 3
            assert native(
                "POST", cart_path + "/line-items/item_" + "f" * 32,
                binding=cart, expected=409, code="cart_item_not_found",
                body=mutation(3, "cart-update-absent", quantity=1),
            ) == {"code": "cart_item_not_found"}
            removed = native(
                "DELETE", item_path, binding=cart,
                body=mutation(3, "cart-remove"),
            )
            assert removed["state_version"] == 4
            assert removed["cart"]["items"] == []
            assert native(
                "DELETE", item_path, binding=cart, expected=409,
                code="cart_item_not_found", body=mutation(4, "cart-remove-again"),
            ) == {"code": "cart_item_not_found"}
            assert native(
                "POST", cart_path + "/complete", binding=cart, expected=409,
                code="empty_synthetic_cart", body=mutation(4, "cart-empty-complete"),
            ) == {"code": "empty_synthetic_cart"}
            assert native(
                "POST", cart_path + "/line-items", binding=cart,
                body=mutation(4, "cart-refill", variant_id="v1", quantity=1),
            )["state_version"] == 5
            completed = native(
                "POST", cart_path + "/complete", binding=cart,
                body=mutation(5, "cart-complete"),
            )
            assert completed["state_version"] == 6
            order_id = completed["order"]["id"]
            assert completed["order"]["cart_id"] == cart_id
            order = world.resource_binding(
                order_id, environment_id="env", deployment_id="deploy", now=int(time.time()),
            )
            order_path = "/synthetic/orders/" + order_id
            assert native("GET", order_path, binding=order)["order"] == completed["order"]
            # Cart capability 不能借用來讀取 Order，須換成派生 Order binding。
            fail_closed("GET", order_path, binding=cart)
            cancelled = native(
                "POST", order_path + "/cancel", binding=order,
                body=mutation(6, "order-cancel"),
            )
            assert cancelled["state_version"] == 7
            assert cancelled["order"]["status"] == "cancelled"
            assert native(
                "POST", order_path + "/cancel", binding=order, expected=409,
                code="order_not_cancellable", body=mutation(7, "order-cancel-again"),
            ) == {"code": "order_not_cancellable"}

        assert len(jtids) == 16
        with psycopg.connect(dsn) as connection:
            assert connection.execute(
                "SELECT count(*) FROM replay_entries WHERE jti=ANY(%s)",
                (jtids,),
            ).fetchone() == (16,)
            assert connection.execute(
                "SELECT count(*) FROM ingress_receipts WHERE jti=ANY(%s)",
                (jtids,),
            ).fetchone() == (16,)
            assert connection.execute(
                "SELECT count(*) FROM protected_candidate_promotions",
            ).fetchone() == (16,)
            assert connection.execute(
                "SELECT count(*) FROM protected_send_leases",
            ).fetchone() == (16,)
    finally:
        for worker in workers:
            if worker.pid is not None:
                worker.terminate()
                worker.join(timeout=5)
                if worker.is_alive():
                    worker.kill()
                    worker.join(timeout=5)
