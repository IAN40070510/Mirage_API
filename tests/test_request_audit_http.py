"""可信 JWS 經真實 ASGI 的請求關聯、跨世界初始化與 Audit 故障驗收。"""

import base64
import hashlib
import json
import time
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
import pytest

from deception.domains.ecommerce.carts import SyntheticCarts
from deception.domains.ecommerce.http_demo import DemoConfig
from deception.domains.ecommerce.trusted_http import create_app
from deception.security.trusted_deployment import TrustedDeploymentSettings
from deception.world.session import SessionBinding
from test_postgres_conformance import isolated_test_dsn
from test_trusted_session import encode


@pytest.fixture
def audit_http(isolated_test_dsn, tmp_path):
    """啟動真實可信 ASGI app，只讓本機測試簽章器產生授權，使用 Mirage 獨立 HTTPX wire 摘要。"""
    from deception.api.fingerprint import fingerprint_httpx_request as wire_fingerprint

    signing = Ed25519PrivateKey.generate()
    settings = TrustedDeploymentSettings(issuer="gateway", audience="mirage", environment_id="isolated-demo",
        deployment_id="isolated-demo", source_id="local-demo-detector", service_id="synthetic-store",
        site_id="demo-store", public_keys={"test": signing.public_key().public_bytes_raw().hex()})
    app = create_app(settings=settings, postgres_dsn=isolated_test_dsn,
        config=DemoConfig(origin="https://shop.test"), output_root=tmp_path, enable_business=True)
    requests = []
    creator = SessionBinding(environment_id="isolated-demo", deployment_id="isolated-demo", session_id=uuid4().hex,
                             session_epoch=1, access_mode="read_only")
    with TestClient(app, base_url="https://shop.test") as client:
        def send(method, path, binding, body=None, *, issued_offset=0):
            """簽發綁定 bytes 的新 JTI 並保留預期摘要；issued_offset 僅模擬發送端時差，不改 Receiver 政策。"""
            request_id = "audit-request-canary-" + uuid4().hex
            outgoing = client.build_request(method, path, json=body,
                headers={"x-request-id": request_id, "authorization": "Bearer audit-credential-canary"})
            now = int(time.time()) + issued_offset
            claims = dict(iss="gateway", aud="mirage", iat=now, nbf=now, exp=now+60, jti=uuid4().hex,
                environment_id=binding.environment_id, deployment_id=binding.deployment_id, session_id=binding.session_id,
                session_epoch=binding.session_epoch, resource_id=binding.resource_id, access_mode=binding.access_mode,
                request_fingerprint=wire_fingerprint(outgoing, request_id), assessment_id="audit-assessment-canary",
                assessment_digest="a" * 64)
            material = encode(dict(alg="Ed25519", typ="mirage-trusted-session+jwt", protocol_version="1.1", kid="test")) + "." + encode(claims)
            outgoing.headers["x-trusted-session"] = material + "." + base64.urlsafe_b64encode(signing.sign(material.encode())).decode().rstrip("=")
            expected_context = hashlib.sha256(json.dumps(claims, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            requests.append((hashlib.sha256(request_id.encode()).hexdigest(), expected_context, claims["request_fingerprint"]))
            return client.send(outgoing)

        yield client, send, creator, requests, isolated_test_dsn


def test_http_audit_correlates_request_context_base_and_committed_world(audit_http):
    """建立 cart 可跨基底世界，寫入則連回同一世界；請求、驗證與傳輸只以摘要和 ID 關聯。"""
    import psycopg

    client, send, creator, requests, dsn = audit_http
    info = client.get("/demo/info").json()
    created = send("POST", "/synthetic/carts", creator, {})
    assert created.status_code == 200, created.text
    cart_id = created.json()["cart"]["id"]
    binding = SyntheticCarts(dsn).resource_binding(cart_id, environment_id="isolated-demo", deployment_id="isolated-demo", now=int(time.time()))
    added = send("POST", "/synthetic/carts/" + cart_id + "/line-items", binding,
        {"variant_id": info["variants"][0]["id"], "quantity": 1, "expected_version": 1,
         "idempotency_key": "audit-add", "commit_attempt_id": str(uuid4())})
    assert added.status_code == 200, added.text
    refused = send("POST", "/synthetic/carts/" + cart_id + "/line-items", binding,
        {"variant_id": info["variants"][0]["id"], "quantity": 2, "expected_version": 2,
         "idempotency_key": "audit-add", "commit_attempt_id": str(uuid4())})
    assert refused.status_code == 409, refused.text
    with psycopg.connect(dsn) as connection:
        for request_id, context, fingerprint in requests:
            row = connection.execute("SELECT o.base_session_id,o.base_state_version,r.target_session_id,r.committed_state_version,"
                "r.domain_validation,r.contract_validation,a.state FROM request_observations o "
                "JOIN request_observation_results r USING(observation_id) JOIN response_admissions a USING(admission_id) "
                "WHERE request_id_digest=%s AND trusted_context_digest=%s AND o.request_binding_digest=%s",
                (request_id, context, fingerprint)).fetchone()
            assert row is not None and row[-3:] == ("passed", "passed", "SEND_COMPLETED")
            if request_id == requests[0][0]:
                assert row[0] != row[2] and row[3] == 1
            elif request_id == requests[1][0]:
                assert row[0] == row[2] and row[1] == 1 and row[3] == 2
            else:
                assert row[0] == row[2] and row[1] == 2 and row[3] is None
        data = connection.execute("SELECT json_agg(row_to_json(o))::text FROM request_observations o").fetchone()[0]
        assert all(value not in data for value in ("audit-request-canary", "audit-credential-canary", "audit-assessment-canary"))
        assert connection.execute("SELECT count(*) FROM response_audit WHERE event_name='asgi_send_completed'").fetchone() == (3,)
        assert connection.execute("SELECT count(*) FROM world_events").fetchone() == (1,)


@pytest.mark.parametrize("failure", ["begin", "grant"])
def test_http_audit_failure_refuses_send_without_guessing_business_rollback(audit_http, failure):
    """觀察失敗時不進業務，Grant Audit 失敗時業務可能已提交；兩者均無新發送權且不盲目重試。"""
    import psycopg

    client, send, creator, _, dsn = audit_http
    created = send("POST", "/synthetic/carts", creator, {})
    assert created.status_code == 200, created.text
    cart_id = created.json()["cart"]["id"]
    carts = SyntheticCarts(dsn)
    binding = carts.resource_binding(cart_id, environment_id="isolated-demo", deployment_id="isolated-demo", now=int(time.time()))
    variant = client.get("/demo/info").json()["variants"][0]["id"]
    target = "request_observations" if failure == "begin" else "request_observation_results"
    with psycopg.connect(dsn) as connection:
        connection.execute("ALTER TABLE " + target + " ADD CONSTRAINT refuse_http_audit CHECK (false) NOT VALID")
        before = connection.execute("SELECT count(*) FROM response_admissions").fetchone()[0]
    attempt = uuid4()
    response = send("POST", "/synthetic/carts/" + cart_id + "/line-items", binding,
        {"variant_id": variant, "quantity": 1, "expected_version": 1,
         "idempotency_key": "audit-failure", "commit_attempt_id": str(attempt)})
    assert response.status_code == 503 and response.json()["code"] == "pipeline_unavailable"
    with psycopg.connect(dsn) as connection:
        assert connection.execute("SELECT count(*) FROM response_admissions").fetchone() == (before,)
        assert connection.execute("SELECT count(*) FROM world_events").fetchone() == (1 if failure == "grant" else 0,)
    recovered = carts.operation_result(binding, attempt, now=int(time.time()))
    assert (recovered is not None) == (failure == "grant")
    if recovered is not None:
        assert recovered.status == "committed" and recovered.state_version == 2
