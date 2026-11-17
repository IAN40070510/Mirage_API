"""明確指定隔離服務時，驗證已建置容器的可信入口與合成業務交易。"""

import base64
import json
import os
from pathlib import Path
import time
from uuid import uuid4

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deception.domains.ecommerce.carts import SyntheticCarts
from deception.world.session import SessionBinding


def test_packaged_trusted_service_guest_checkout():
    """對已啟動的隔離映像驗證無授權拒絕、訪客購物車、一次預留與取消回補。

    需要專用 origin、DB 與本機短期私鑰檔；不建立容器、不接觸正式身份。
    所有寫入均使用隨機合成 Session，環境銷毀由建立該服務的驗收流程負責。
    """
    origin = os.environ.get("MIRAGE_CONTAINER_TEST_ORIGIN")
    key_path = os.environ.get("MIRAGE_CONTAINER_TEST_KEY_FILE")
    dsn = os.environ.get("MIRAGE_POSTGRES_TEST_DSN")
    if not all((origin, key_path, dsn)):
        pytest.skip("requires isolated container origin, local signing key and test DSN")
    from deception.api.fingerprint import fingerprint_httpx_request as wire_fingerprint

    key = Ed25519PrivateKey.from_private_bytes(Path(key_path).read_bytes())
    worlds = SyntheticCarts(dsn)
    creator = SessionBinding(environment_id="isolated-demo", deployment_id="isolated-demo",
                             session_id="container-" + uuid4().hex, session_epoch=1)

    def encode(value):
        """將合成授權欄位編成不含 padding 的 Compact JWS 元件。"""
        return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")

    with httpx.Client(base_url=origin, timeout=60, trust_env=False) as client:
        info = client.get("/demo/info")
        assert info.status_code == 200
        assert client.post("/synthetic/carts", json={}).status_code == 503
        variant = info.json()["variants"][0]

        def send(method, path, binding, payload=None):
            """在本機對最終 wire bytes 簽發新授權，只重用業務鍵而不重用 JTI。"""
            request_id, now = uuid4().hex, int(time.time())
            request = client.build_request(method, path, json=payload, headers={"x-request-id": request_id})
            header = dict(alg="Ed25519", typ="mirage-trusted-session+jwt", protocol_version="1.1", kid="acceptance")
            claims = dict(iss="gateway", aud="mirage", iat=now, nbf=now, exp=now + 60, jti=uuid4().hex,
                environment_id=binding.environment_id, deployment_id=binding.deployment_id,
                session_id=binding.session_id, session_epoch=binding.session_epoch,
                access_mode=binding.access_mode, resource_id=binding.resource_id,
                request_fingerprint=wire_fingerprint(request, request_id),
                assessment_id=uuid4().hex, assessment_digest="a" * 64)
            content = encode(header) + "." + encode(claims)
            request.headers["x-trusted-session"] = content + "." + base64.urlsafe_b64encode(
                key.sign(content.encode())).decode().rstrip("=")
            response = client.send(request)
            assert response.status_code == 200, response.text
            assert "set-cookie" not in response.headers
            return response.json()

        creation = dict(idempotency_key=str(uuid4()), commit_attempt_id=str(uuid4()))
        created = send("POST", "/synthetic/carts", creator, creation)
        assert send("POST", "/synthetic/carts", creator, creation) == created
        cart_id = created["cart"]["id"]
        binding = worlds.resource_binding(cart_id, environment_id="isolated-demo",
                                           deployment_id="isolated-demo", now=int(time.time()))
        before = worlds.inspect_binding(binding, now=int(time.time())).state["inventory"]

        def metadata(version):
            """產生事先保存的業務冪等鍵、CAS 版本與提交查詢識別。"""
            return dict(expected_version=version, idempotency_key=uuid4().hex, commit_attempt_id=str(uuid4()))

        send("POST", f"/synthetic/carts/{cart_id}/line-items", binding,
             {**metadata(1), "variant_id": variant["id"], "quantity": 1})
        assert worlds.inspect_binding(binding, now=int(time.time())).state["inventory"] == before


        complete = metadata(2)
        order = send("POST", f"/synthetic/carts/{cart_id}/complete", binding, complete)
        assert order["order"]["status"] == "placed"
        assert send("POST", f"/synthetic/carts/{cart_id}/complete", binding, complete) == order
        order_id = order["order"]["id"]
        order_binding = worlds.resource_binding(order_id, environment_id="isolated-demo",
            deployment_id="isolated-demo", now=int(time.time()))
        cancelled = send("POST", f"/synthetic/orders/{order_id}/cancel", order_binding, metadata(3))
        assert cancelled["order"]["status"] == "cancelled"
        assert worlds.inspect_binding(binding, now=int(time.time())).state["inventory"] == before


def test_packaged_native_store_mapping():
    """更新映像的原生建立／加品項／下單／查單保留合成商品關聯及差異核准證據。"""
    origin = os.environ.get("MIRAGE_CONTAINER_TEST_ORIGIN")
    key_path = os.environ.get("MIRAGE_CONTAINER_TEST_KEY_FILE")
    dsn = os.environ.get("MIRAGE_POSTGRES_TEST_DSN")
    publishable = os.environ.get("MIRAGE_CONTAINER_NATIVE_PUBLISHABLE_KEY")
    if not all((origin, key_path, dsn, publishable)):
        pytest.skip("requires isolated native container, local signing key, publishable key and test DSN")
    from deception.api.fingerprint import fingerprint_httpx_request as wire_fingerprint
    from test_trusted_session import encode
    import psycopg

    key = Ed25519PrivateKey.from_private_bytes(Path(key_path).read_bytes())
    worlds = SyntheticCarts(dsn)
    creator = SessionBinding(environment_id="isolated-demo", deployment_id="isolated-demo",
                             session_id="native-image-" + uuid4().hex, session_epoch=1)
    with httpx.Client(base_url=origin, timeout=60, trust_env=False) as client:
        def send(method, path, binding, payload=None, *, idempotency=None, changes=None, expected=200):
            """在本機簽發精確原生請求及錯配負例；私鑰不傳入容器，也不重用 JTI。"""
            request_id, now = uuid4().hex, int(time.time())
            headers = {"x-request-id": request_id, "x-publishable-api-key": publishable}
            if idempotency is not None:
                headers["idempotency-key"] = idempotency
            request = client.build_request(method, path, json=payload, headers=headers)
            header = dict(alg="Ed25519", typ="mirage-trusted-session+jwt", protocol_version="1.1", kid="acceptance")
            claims = dict(iss="gateway", aud="mirage", iat=now, nbf=now, exp=now+60, jti=uuid4().hex,
                environment_id=binding.environment_id, deployment_id=binding.deployment_id,
                session_id=binding.session_id, session_epoch=binding.session_epoch,
                resource_id=binding.resource_id, access_mode=binding.access_mode,
                request_fingerprint=wire_fingerprint(request, request_id), assessment_id=uuid4().hex,
                assessment_digest="a"*64)
            claims.update(changes or {})
            value = encode(header) + "." + encode(claims)
            request.headers["x-trusted-session"] = value + "." + base64.urlsafe_b64encode(
                key.sign(value.encode())).decode().rstrip("=")
            response = client.send(request)
            assert response.status_code == expected, response.text
            assert "set-cookie" not in response.headers
            return response.json()

        info = client.get("/demo/info").json()
        assert info["medusa_store_enabled"] is True and info["transactions_supported"] is True
        variant = info["variants"][0]
        created = send("POST", "/store/carts", creator, {}, idempotency="native-image-create")
        cart_id = created["cart"]["id"]
        assert send("POST", "/store/carts", creator, {}, idempotency="native-image-create") == created
        binding = worlds.resource_binding(cart_id, environment_id="isolated-demo",
                                          deployment_id="isolated-demo", now=int(time.time()))
        base = "/store/carts/" + cart_id
        added = send("POST", base + "/line-items", binding,
                     {"variant_id": variant["id"], "quantity": 1}, idempotency="native-image-add")
        assert added["cart"]["total"] == variant["unit_price"] / 100
        assert added["cart"]["items"][0]["product_id"] in info["product_ids"]
        assert "state_version" not in added["cart"]
        before_conflict = worlds.inspect_binding(binding, now=int(time.time()))
        send("POST", base + "/line-items", binding,
             {"variant_id": variant["id"], "quantity": 2}, idempotency="native-image-add", expected=409)
        assert worlds.inspect_binding(binding, now=int(time.time())) == before_conflict
        completed = send("POST", base + "/complete", binding)
        assert completed["type"] == "order" and completed["order"]["customer_id"] is None
        assert send("POST", base + "/complete", binding) == completed
        assert completed["order"]["items"][0]["product_id"] == added["cart"]["items"][0]["product_id"]
        order_binding = worlds.resource_binding(completed["order"]["id"], environment_id="isolated-demo",
            deployment_id="isolated-demo", now=int(time.time()))
        assert send("GET", "/store/orders/" + completed["order"]["id"], order_binding)["order"] == completed["order"]
        snapshot = worlds.inspect_binding(binding, now=int(time.time()))
        generation = snapshot.scope.world_generation_id
        assert snapshot.compatibility is not None
        assert "_mirage_world_compatibility" not in json.dumps(completed)
        other = send("POST", "/store/carts", creator, {}, idempotency="native-image-other")["cart"]["id"]
        other_binding = worlds.resource_binding(other, environment_id="isolated-demo",
            deployment_id="isolated-demo", now=int(time.time()))
        other_snapshot = worlds.inspect_binding(other_binding, now=int(time.time()))
        rejected = send("GET", base, binding, changes={"session_id": other_binding.session_id}, expected=503)
        assert rejected["code"] == "pipeline_unavailable"
        assert worlds.inspect_binding(binding, now=int(time.time())) == snapshot
        assert worlds.inspect_binding(other_binding, now=int(time.time())) == other_snapshot
    with psycopg.connect(dsn) as connection:
        rows = connection.execute("SELECT admission FROM response_admissions WHERE world_generation_id=%s",
                                  (generation,)).fetchall()
        refusals = connection.execute("SELECT r.source_kind,r.committed_state_version,r.committed_state_hash "
            "FROM request_observation_results r JOIN response_admissions a USING(admission_id) "
            "WHERE a.world_generation_id=%s AND a.admission->'source'->>'kind'='security_error'", (generation,)).fetchall()
        assert refusals and all(row == ("security_error", None, None) for row in refusals)
    evidence = [row[0]["projection_evidence"] for row in rows]
    assert evidence and any(not item["official_schema_valid"] for item in evidence)
    assert all(item["effective_projection_valid"] for item in evidence)
    assert all(item["deviation_approval"] is not None for item in evidence if not item["official_schema_valid"])
    from deception.world import ProjectionEvidence
    assert all(snapshot.compatibility.permits(ProjectionEvidence.model_validate(item)) for item in evidence)


def test_packaged_profile_revocation_requires_explicit_isolated_opt_in():
    """只有明確指定可丟棄資料庫時，永久撤銷映像的原生 Profile 並確認安全投影仍可用。"""
    if os.environ.get("MIRAGE_CONTAINER_PROFILE_REVOCATION_TEST") != "true":
        pytest.skip("requires explicit isolated Profile revocation opt-in")
    origin, key_file, dsn, publishable = [os.environ.get(name) for name in (
        "MIRAGE_CONTAINER_TEST_ORIGIN", "MIRAGE_CONTAINER_TEST_KEY_FILE", "MIRAGE_POSTGRES_TEST_DSN",
        "MIRAGE_CONTAINER_NATIVE_PUBLISHABLE_KEY")]
    if not all((origin, key_file, dsn, publishable)):
        pytest.skip("requires disposable container, local signing key, publishable key and database")
    from deception.api.fingerprint import fingerprint_httpx_request as wire_fingerprint
    from deception.world import PostgresProjectionRegistry
    from test_trusted_session import encode
    import psycopg

    key = Ed25519PrivateKey.from_private_bytes(Path(key_file).read_bytes())
    carts = SyntheticCarts(dsn)
    creator = SessionBinding(environment_id="isolated-demo", deployment_id="isolated-demo",
                             session_id="profile-container-" + uuid4().hex, session_epoch=1)
    with httpx.Client(base_url=origin, trust_env=False, timeout=30) as client:
        def send(method, path, binding, payload=None):
            """對該隔離服務簽發新 JTI，讓拒絕確實來自 Profile 墓碑而不是舊授權重放。"""
            now, request_id = int(time.time()), uuid4().hex
            request = client.build_request(method, path, json=payload,
                headers={"x-request-id": request_id, "x-publishable-api-key": publishable})
            claims = dict(iss="gateway", aud="mirage", iat=now, nbf=now, exp=now+60, jti=uuid4().hex,
                environment_id=binding.environment_id, deployment_id=binding.deployment_id,
                session_id=binding.session_id, session_epoch=binding.session_epoch,
                resource_id=binding.resource_id, access_mode=binding.access_mode,
                request_fingerprint=wire_fingerprint(request, request_id), assessment_id=uuid4().hex,
                assessment_digest="a" * 64)
            content = encode(dict(alg="Ed25519", typ="mirage-trusted-session+jwt", protocol_version="1.1", kid="acceptance")) + "." + encode(claims)
            request.headers["x-trusted-session"] = content + "." + base64.urlsafe_b64encode(
                key.sign(content.encode())).decode().rstrip("=")
            return client.send(request)

        created = send("POST", "/store/carts", creator, {})
        assert created.status_code == 200, created.text
        cart_id = created.json()["cart"]["id"]
        binding = carts.resource_binding(cart_id, environment_id="isolated-demo",
            deployment_id="isolated-demo", now=int(time.time()))
        before = carts.inspect_binding(binding, now=int(time.time()))
        with psycopg.connect(dsn) as connection:
            profile, = connection.execute("SELECT admission#>>'{projection_evidence,compatibility_profile,profile_sha256}' "
                "FROM response_admissions WHERE world_generation_id=%s LIMIT 1",
                (before.scope.world_generation_id,)).fetchone()
        registry = PostgresProjectionRegistry(dsn)
        revoked = registry.revoke_profile(profile, registry_revision=1)
        refused = send("GET", "/store/carts/" + cart_id, binding)
        assert refused.status_code == 503 and refused.json()["code"] == "pipeline_unavailable"
        safe = send("GET", "/synthetic/carts/" + cart_id, binding)
        assert safe.status_code == 200 and safe.json()["cart"]["id"] == cart_id
        assert carts.inspect_binding(binding, now=int(time.time())) == before
        assert registry.profile_revocation(profile) == revoked


def test_packaged_key_revocation_requires_explicit_isolated_opt_in():
    """最後才永久撤銷隔離映像的簽發 kid，確認有效舊簽章不能新增世界、Replay 或准入。"""
    if os.environ.get("MIRAGE_CONTAINER_KEY_REVOCATION_TEST") != "true":
        pytest.skip("requires explicit disposable signing key revocation opt-in")
    origin, key_file, dsn = [os.environ.get(name) for name in (
        "MIRAGE_CONTAINER_TEST_ORIGIN", "MIRAGE_CONTAINER_TEST_KEY_FILE", "MIRAGE_POSTGRES_TEST_DSN")]
    if not all((origin, key_file, dsn)):
        pytest.skip("requires disposable container, local signing key and database")
    from deception.api.fingerprint import fingerprint_httpx_request as wire_fingerprint
    from deception.security.key_revocation import PostgresTrustedKeyRevocations
    from test_trusted_session import encode
    import psycopg
    from psycopg import sql

    key, session = Ed25519PrivateKey.from_private_bytes(Path(key_file).read_bytes()), uuid4().hex
    with httpx.Client(base_url=origin, trust_env=False, timeout=30) as client:
        info = client.get("/demo/info").json()
        product_path = info["product_path_template"].replace("{id}", info["product_ids"][0])

        def send():
            """每次以新 JTI 簽同一合法查詢，讓拒絕原因確實來自撤銷而不是 Replay。"""
            now, request_id = int(time.time()), uuid4().hex
            request = client.build_request("GET", product_path, headers={"x-request-id": request_id})
            claims = dict(iss="gateway", aud="mirage", iat=now, nbf=now, exp=now+60, jti=uuid4().hex,
                environment_id="isolated-demo", deployment_id="isolated-demo", session_id=session,
                session_epoch=1, access_mode="read_only", resource_id=None,
                request_fingerprint=wire_fingerprint(request, request_id), assessment_id=uuid4().hex, assessment_digest="a" * 64)
            content = encode(dict(alg="Ed25519", typ="mirage-trusted-session+jwt", protocol_version="1.1", kid="acceptance")) + "." + encode(claims)
            request.headers["x-trusted-session"] = content + "." + base64.urlsafe_b64encode(
                key.sign(content.encode())).decode().rstrip("=")
            return client.send(request)

        def counts():
            """從新連線比對世界與控制表，拒絕稽核另計，不讓拒絕產生新准入。"""
            with psycopg.connect(dsn) as connection:
                return {table: connection.execute(sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(table))).fetchone()[0]
                    for table in ("world_snapshots", "replay_entries", "read_admissions", "response_admissions")}

        assert send().status_code == 200
        before = counts()
        manager = PostgresTrustedKeyRevocations(dsn, environment_id="isolated-demo", deployment_id="isolated-demo")
        manager.revoke("gateway", "acceptance", revision=1)
        for _ in range(2):
            refused = send()
            assert refused.status_code == 503 and refused.json()["code"] == "pipeline_unavailable"
        assert counts() == before
        with psycopg.connect(dsn) as connection:
            assert connection.execute("SELECT count(*) FROM ingress_refusal_audit WHERE stage='trusted_ingress'").fetchone()[0] >= 2
