"""透過 JWS HTTP 正常入口驗證匿名 cart.id 到合成訂單的完整流程。"""

import asyncio
import base64
import json
import time
from uuid import uuid4

import httpx
import pytest
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


def test_anonymous_cart_http_to_order_and_cancellation(isolated_test_dsn, tmp_path):
    """無登入或 Cookie，依回傳 cart／order ID 增刪商品、下單及取消，回應均經 Gate 與 Admission。"""
    from deception.api.fingerprint import fingerprint_httpx_request as wire_fingerprint

    signing = Ed25519PrivateKey.generate()
    settings = TrustedDeploymentSettings(issuer="gateway", audience="mirage", environment_id="isolated-demo",
        deployment_id="isolated-demo", source_id="local-demo-detector", service_id="synthetic-store",
        site_id="demo-store", public_keys={"key": signing.public_key().public_bytes_raw().hex()})
    app = create_app(settings=settings, postgres_dsn=isolated_test_dsn, config=DemoConfig(origin="https://shop.test"),
                      output_root=tmp_path, enable_business=True)
    frozen_time = int(time.time())
    anonymous = AnonymousIdentityProvider(key=b"z" * 32, groups=AnonymousGroups(isolated_test_dsn),
        environment_id="isolated-demo", deployment_id="isolated-demo", clock=lambda: frozen_time)
    # 固定分組時鐘避免本測試跨過短期窗口；授權期限仍採實際時間。
    identities = ResourceIdentityProvider(fallback=anonymous, resources=SyntheticCarts(isolated_test_dsn),
        environment_id="isolated-demo", deployment_id="isolated-demo")

    with TestClient(app, base_url="https://shop.test") as client:
        def send(method, path, payload=None):
            """模擬可信 Gateway 對最終 HTTP bytes 驗證資源身份並簽發一個新 JTI。"""
            request_id = str(uuid4())
            outgoing = client.build_request(method, "https://shop.test" + path,
                headers={"x-request-id": request_id, "user-agent": "anonymous-integration"}, json=payload)
            incoming = Request({"type": "http", "method": method, "path": path, "raw_path": path.encode(),
                "query_string": b"", "scheme": "https", "server": ("shop.test", 443),
                "client": ("192.0.2.1", 1234), "headers": [(name.lower(), value) for name, value in outgoing.headers.raw]})
            binding = asyncio.run(identities(incoming))
            now = int(time.time())
            header = dict(alg="Ed25519", typ="mirage-trusted-session+jwt", protocol_version="1.1", kid="key")
            claims = dict(iss="gateway", aud="mirage", iat=now, nbf=now, exp=now+60, jti=uuid4().hex,
                environment_id=binding.environment_id, deployment_id=binding.deployment_id,
                session_id=binding.session_id, session_epoch=binding.session_epoch, access_mode=binding.access_mode,
                resource_id=binding.resource_id, request_fingerprint=wire_fingerprint(outgoing, request_id),
                assessment_id=uuid4().hex, assessment_digest="a"*64)
            content = encode(header) + "." + encode(claims)
            outgoing.headers["x-trusted-session"] = content + "." + base64.urlsafe_b64encode(
                signing.sign(content.encode())).decode().rstrip("=")
            response = client.send(outgoing)
            assert response.status_code in (200, 409), response.text
            assert "set-cookie" not in response.headers
            return response

        info = client.get("/demo/info").json()
        variant = info["variants"][0]
        rejected = send("POST", "/synthetic/inventory/reservations", {
            "sku": variant["sku"], "quantity": 1, "expected_version": 1,
            "idempotency_key": "anonymous-direct-stock", "commit_attempt_id": str(uuid4())})
        assert rejected.status_code == 409
        assert rejected.json() == {"code": "inventory_write_not_authorized"}
        creation = {"idempotency_key": str(uuid4()), "commit_attempt_id": str(uuid4())}
        created = send("POST", "/synthetic/carts", creation).json()
        cart_id = created["cart"]["id"]
        assert send("POST", "/synthetic/carts", creation).json() == created
        assert send("GET", "/synthetic/carts/" + cart_id).json()["cart"]["items"] == []

        def metadata(version, key):
            """為每個業務動作產生可重試且不等同 JTI 的操作鍵。"""
            return dict(expected_version=version, idempotency_key=key, commit_attempt_id=str(uuid4()))

        added = send("POST", f"/synthetic/carts/{cart_id}/line-items",
                     {**metadata(1, "add"), "variant_id": variant["id"], "quantity": 1}).json()
        item_id = added["cart"]["items"][0]["id"]
        assert added["cart"]["total"] == variant["unit_price"]
        removed = send("DELETE", f"/synthetic/carts/{cart_id}/line-items/{item_id}", metadata(2, "remove")).json()
        assert removed["cart"]["items"] == []
        send("POST", f"/synthetic/carts/{cart_id}/line-items",
             {**metadata(3, "add-again"), "variant_id": variant["id"], "quantity": 1})
        complete = metadata(4, "complete")
        placed = send("POST", f"/synthetic/carts/{cart_id}/complete", complete).json()
        assert placed["order"]["status"] == "placed"
        assert send("POST", f"/synthetic/carts/{cart_id}/complete", complete).json() == placed
        order_id = placed["order"]["id"]
        lookup = send("GET", f"/synthetic/carts/{cart_id}/operations/{complete['commit_attempt_id']}").json()
        assert lookup == placed
        cancelled = send("POST", f"/synthetic/orders/{order_id}/cancel", metadata(5, "cancel")).json()
        assert cancelled["order"]["status"] == "cancelled"

    import psycopg
    with psycopg.connect(isolated_test_dsn) as observer:
        assert observer.execute("SELECT count(*) FROM response_admissions WHERE state!='SEND_COMPLETED'").fetchone() == (0,)
        assert observer.execute("SELECT count(*) FROM world_events").fetchone() == (5,)
        assert observer.execute("SELECT count(*) FROM world_initializations").fetchone() == (2,)
        assert observer.execute("SELECT count(*) FROM read_admissions").fetchone()[0] > 0
        assert observer.execute(
            "SELECT count(*) FROM response_audit WHERE event_name='response_send_attempted'").fetchone()[0] > 0
