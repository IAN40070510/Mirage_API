"""G3b～G6 Medusa Store Cart：真 Client HTTP 經七 TLS、受保護 PG 及唯一 Sender。"""

import multiprocessing
from pathlib import Path
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


def test_g6_medusa_store_all_seven_native_routes_and_business_errors(
        tmp_path, request, isolated_test_dsn):
    """M-01～M-07 真 HTTP 200/400/404、Read/Commit 來源、JWS Replay 與 PG Lease。"""
    dsn, now = isolated_test_dsn, int(time.time())
    native_context = {
        "region_id": "reg_mirage_usd", "sales_channel_id": "sc_mirage",
        "email": "ci@example.invalid", "metadata": {},
    }
    initial = {
        "catalog": {"known": {"sku": "sku-1", "unit_price": 100}},
        "inventory": {"sku-1": 7}, "native_context": native_context,
    }
    creator = SessionBinding(
        environment_id="env", deployment_id="deploy", session_id="session",
        session_epoch=1, access_mode="cart",
    )
    world = SyntheticCarts(dsn)
    world.resolve(
        creator, {"catalog": initial["catalog"], "inventory": initial["inventory"],
                  "reservations": {}}, now=now, ttl=240,
    )
    profiles = _g6_projection_profiles()
    PostgresProjectionRegistry(dsn).ensure_registered_batch((profiles["medusa-native-cart"],))
    logins = _g6_create_service_logins(dsn, request, platform="synthetic-carts")
    promoter_dsn, promoter_login = _g6_create_promoter_login(dsn, request)
    source = (Path(__file__).resolve().parents[1]
              / "domains/ecommerce/inputs/sources/medusa/openapi.yaml")
    projector = PostgresProtectedNativeProjector(
        logins["validator"][0], expected_login=logins["validator"][1],
        medusa_source=source,
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
        medusa_publishable_key="pk_only_executor",
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
                pytest.fail("Medusa true Client HTTPS listener did not become ready")

            def request_native(method, path, *, body=None, binding=creator,
                               expected=200, publishable_key="pk_only_executor"):
                """原始 Host／Publishable Key 納入 JWS Fingerprint，核對完整原生回應。"""
                outbound, jti = _g6_signed_client_request(
                    client, signer, gateway_port, method=method, path=path,
                    request_id="g6-medusa-" + uuid4().hex, body=body,
                    access_mode="cart", session_id=binding.session_id,
                    resource_id=binding.resource_id,
                    extra_headers={
                        "content-type": "application/json",
                        "x-publishable-api-key": publishable_key,
                    },
                )
                response = client.send(outbound)
                assert response.status_code == expected, (
                    f"{method} {path}: expected {expected}, got "
                    f"{response.status_code}: {response.text}; "
                    f"stages={_g6_stage_counts(dsn)}"
                )
                assert response.headers["content-type"] == "application/json"
                payload = response.json()
                replay = client.send(outbound)
                assert replay.status_code == 503, (method, path, replay.text)
                assert replay.json() == {"detail": "gateway_delivery_unverifiable"}
                jtids.append(jti)
                return payload

            def fail_closed(method, path, *, body=None, binding=creator, key="pk_only_executor"):
                """無受保護 Error Source 或錯 Publishable Key 必須固定 503。"""
                outbound, _ = _g6_signed_client_request(
                    client, signer, gateway_port, method=method, path=path,
                    request_id="g6-medusa-denied-" + uuid4().hex, body=body,
                    access_mode="cart", session_id=binding.session_id,
                    resource_id=binding.resource_id,
                    extra_headers={
                        "content-type": "application/json",
                        "x-publishable-api-key": key,
                    },
                )
                response = client.send(outbound)
                assert response.status_code == 503, (method, path, response.text)
                assert response.json() == {"detail": "gateway_delivery_unverifiable"}

            created = request_native(
                "POST", "/store/carts",
                body={"email": "ci@example.invalid", "items": []},
            )
            assert set(created) == {"cart"}
            cart_id = created["cart"]["id"]
            assert created["cart"]["items"] == []
            cart = world.resource_binding(
                cart_id, environment_id="env", deployment_id="deploy", now=int(time.time()),
            )
            cart_path = "/store/carts/" + cart_id
            fetched = request_native("GET", cart_path, binding=cart)
            assert fetched["cart"]["id"] == cart_id
            fail_closed("GET", cart_path, binding=cart, key="incorrect_public_key")
            fail_closed("GET", cart_path)

            line_path = cart_path + "/line-items"
            invalid = request_native(
                "POST", line_path, binding=cart, expected=400,
                body={"variant_id": "known", "quantity": 0},
            )
            assert invalid == {
                "message": "The requested cart operation is not supported.",
                "type": "invalid_data",
            }
            missing = request_native(
                "POST", line_path, binding=cart, expected=404,
                body={"variant_id": "missing", "quantity": 1},
            )
            assert missing == {
                "message": "The requested cart operation could not be completed.",
                "type": "not_found",
            }
            added = request_native(
                "POST", line_path, binding=cart,
                body={"variant_id": "known", "quantity": 2},
            )
            assert added["cart"]["id"] == cart_id
            item = added["cart"]["items"][0]
            assert item["quantity"] == 2
            item_path = line_path + "/" + item["id"]
            updated = request_native(
                "POST", item_path, binding=cart, body={"quantity": 3},
            )
            assert updated["cart"]["items"][0]["quantity"] == 3
            deleted = request_native("DELETE", item_path, binding=cart)
            assert set(deleted) == {"id", "object", "deleted", "parent"}
            assert deleted["id"] == item["id"]
            assert deleted["deleted"] is True
            assert deleted["parent"]["items"] == []
            fail_closed("DELETE", item_path, binding=cart)
            fail_closed("POST", cart_path + "/complete", binding=cart)

            refilled = request_native(
                "POST", line_path, binding=cart,
                body={"variant_id": "known", "quantity": 1},
            )
            assert refilled["cart"]["items"][0]["quantity"] == 1
            completed = request_native(
                "POST", cart_path + "/complete", binding=cart,
            )
            assert completed["type"] == "order"
            order_id = completed["order"]["id"]
            assert completed["order"]["payment_status"] == "not_paid"
            assert completed["order"]["fulfillment_status"] == "not_fulfilled"
            order = world.resource_binding(
                order_id, environment_id="env", deployment_id="deploy", now=int(time.time()),
            )
            order_read = request_native(
                "GET", "/store/orders/" + order_id, binding=order,
            )
            assert order_read["order"]["id"] == order_id
            assert order_read["order"]["customer_id"] is None
            fail_closed("GET", "/store/orders/" + order_id, binding=cart)

        assert len(jtids) == 10
        with psycopg.connect(dsn) as connection:
            assert connection.execute(
                "SELECT count(*) FROM replay_entries WHERE jti=ANY(%s)",
                (jtids,),
            ).fetchone() == (10,)
            assert connection.execute(
                "SELECT count(*) FROM ingress_receipts WHERE jti=ANY(%s)",
                (jtids,),
            ).fetchone() == (10,)
            assert connection.execute(
                "SELECT count(*) FROM protected_candidate_promotions",
            ).fetchone() == (10,)
            assert connection.execute(
                "SELECT count(*) FROM protected_send_leases",
            ).fetchone() == (10,)
    finally:
        for worker in workers:
            if worker.pid is not None:
                worker.terminate()
                worker.join(timeout=5)
                if worker.is_alive():
                    worker.kill()
                    worker.join(timeout=5)
