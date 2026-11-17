"""原生 Store 請求經 JWS、共用世界、有效投影與 Admission 的端到端驗收。"""

import asyncio
import base64
import time
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from starlette.requests import Request

from deception.domains.ecommerce.carts import SyntheticCarts
from deception.domains.ecommerce.http_demo import DemoConfig
from deception.domains.ecommerce.trusted_http import create_app
from deception.security.anonymous_identity import AnonymousGroups, AnonymousIdentityProvider
from deception.security.resource_identity import ResourceIdentityProvider
from deception.security.trusted_deployment import TrustedDeploymentSettings
from test_postgres_conformance import isolated_test_dsn
from test_trusted_session import encode


def test_native_medusa_guest_cart_to_order_and_internal_cancellation(isolated_test_dsn, tmp_path):
    """原生建立／增刪改／下單不要求控制欄位，使用同一合成引擎並保留冪等投影。"""
    import psycopg

    from deception.api.fingerprint import fingerprint_httpx_request as wire_fingerprint

    signing = Ed25519PrivateKey.generate()
    settings = TrustedDeploymentSettings(issuer="gateway", audience="mirage", environment_id="isolated-demo",
        deployment_id="isolated-demo", source_id="local-demo-detector", service_id="synthetic-store",
        site_id="demo-store", public_keys={"key": signing.public_key().public_bytes_raw().hex()})
    app = create_app(settings=settings, postgres_dsn=isolated_test_dsn, config=DemoConfig(origin="https://shop.test"),
        output_root=tmp_path, enable_business=True, enable_medusa_store=True, medusa_publishable_key="pk_synthetic_native")
    now = int(time.time())
    # 固定匿名窗口僅為測試建立重試；資源路徑之後不依賴 IP／UA 分組。
    anonymous = AnonymousIdentityProvider(key=b"n" * 32, groups=AnonymousGroups(isolated_test_dsn),
        environment_id="isolated-demo", deployment_id="isolated-demo", clock=lambda: now)
    carts = SyntheticCarts(isolated_test_dsn)
    scope = dict(environment_id="isolated-demo", deployment_id="isolated-demo")
    synthetic = ResourceIdentityProvider(fallback=anonymous, resources=carts, **scope)
    identities = ResourceIdentityProvider(fallback=synthetic, resources=carts, prefix="/store", **scope)

    with TestClient(app, base_url="https://shop.test") as client:
        def send(method, path, body=None, *, key=None, peer="192.0.2.1", expected=200, tamper_key=False):
            """由實際 Gateway fingerprint 簽發最終請求；可改變來源或注入簽後竄改負例。"""
            request_id = uuid4().hex
            headers = {"x-request-id": request_id, "x-publishable-api-key": "pk_synthetic_native"}
            if key is not None:
                headers["idempotency-key"] = key
            outgoing = client.build_request(method, path, json=body, headers=headers)
            incoming = Request({"type": "http", "method": method, "path": path, "raw_path": path.encode(),
                "query_string": b"", "scheme": "https", "server": ("shop.test", 443), "client": (peer, 1234),
                "headers": [(name.lower(), value) for name, value in outgoing.headers.raw]})
            binding = asyncio.run(identities(incoming))
            clock = int(time.time())
            header = dict(alg="Ed25519", typ="mirage-trusted-session+jwt", protocol_version="1.1", kid="key")
            claims = dict(iss="gateway", aud="mirage", iat=clock, nbf=clock, exp=clock+60, jti=uuid4().hex,
                environment_id=binding.environment_id, deployment_id=binding.deployment_id,
                session_id=binding.session_id, session_epoch=binding.session_epoch, access_mode=binding.access_mode,
                resource_id=binding.resource_id, request_fingerprint=wire_fingerprint(outgoing, request_id),
                assessment_id=uuid4().hex, assessment_digest="a"*64)
            value = encode(header) + "." + encode(claims)
            outgoing.headers["x-trusted-session"] = value + "." + base64.urlsafe_b64encode(
                signing.sign(value.encode())).decode().rstrip("=")
            if tamper_key:
                outgoing.headers["idempotency-key"] = "changed-after-signature"
            response = client.send(outgoing)
            assert response.status_code == expected, response.text
            assert "set-cookie" not in response.headers
            return response.json()

        info = client.get("/demo/info").json()
        assert info["transactions_supported"] is True and info["medusa_store_enabled"] is True
        variant = info["variants"][0]
        created = send("POST", "/store/carts", {}, key="create")
        assert set(created) == {"cart"} and created["cart"]["items"] == []
        cart_id = created["cart"]["id"]
        base = "/store/carts/" + cart_id
        added = send("POST", base + "/line-items", {"variant_id": variant["id"], "quantity": 1}, key="add")
        assert added["cart"]["total"] == variant["unit_price"] / 100
        assert send("POST", base + "/line-items", {"variant_id": variant["id"], "quantity": 1}, key="add") == added
        assert send("POST", "/store/carts", {}, key="create") == created
        send("POST", base + "/line-items", {"variant_id": variant["id"], "quantity": 2}, key="add", expected=409)
        send("POST", base + "/line-items", {"variant_id": variant["id"], "quantity": 1}, key="tamper",
             expected=503, tamper_key=True)
        item = added["cart"]["items"][0]["id"]
        removed = send("DELETE", base + "/line-items/" + item)
        assert removed["deleted"] is True and removed["parent"]["items"] == []
        added = send("POST", base + "/line-items", {"variant_id": variant["id"], "quantity": 1}, key="add-again")
        item = added["cart"]["items"][0]["id"]
        updated = send("POST", base + "/line-items/" + item, {"quantity": 2}, key="update", peer="198.51.100.2")
        assert updated["cart"]["items"][0]["quantity"] == 2
        assert send("GET", base)["cart"] == updated["cart"]
        complete = send("POST", base + "/complete")
        assert complete["type"] == "order" and complete["order"]["payment_status"] == "not_paid"
        assert complete["order"]["customer_id"] is None
        assert send("POST", base + "/complete") == complete
        order_id = complete["order"]["id"]
        assert send("GET", "/store/orders/" + order_id)["order"] == complete["order"]
        send("POST", "/store/orders/" + order_id + "/cancel", expected=503)
        binding = carts.resource_binding(order_id, now=int(time.time()), **scope)
        snapshot = carts.inspect_binding(binding, now=int(time.time()))
        send("POST", "/synthetic/orders/" + order_id + "/cancel", {"expected_version": snapshot.version,
             "idempotency_key": "internal-cancel", "commit_attempt_id": str(uuid4())})
        assert send("GET", "/store/orders/" + order_id)["order"]["status"] == "canceled"
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM world_events").fetchone() == (6,)
        assert connection.execute("SELECT count(*) FROM response_admissions WHERE state!='SEND_COMPLETED'").fetchone() == (0,)
