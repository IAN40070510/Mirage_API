"""入口拒絕的持久化、固定分類、資料最小化及稽核故障拒絕驗收。"""

import logging
from uuid import UUID

import pytest

from deception.security.ingress_audit import PostgresIngressAudit
from test_postgres_conformance import isolated_test_dsn
from test_http_world_isolation import http_worlds


@pytest.mark.parametrize("stage,reason", [("visitor-input", "unavailable"),
    ("trusted_ingress", "secret-token"), ("", ""), ("TRUSTED_INGRESS", "unavailable")])
def test_unknown_audit_classification_rejected_before_connect(stage, reason):
    """外部文字不能成為可保存的分類，無效分類在任何資料庫連線前拒絕。"""
    audit = PostgresIngressAudit("postgresql://unused.invalid/db", environment_id="env", deployment_id="deploy")
    with pytest.raises(ValueError, match="classification"):
        audit.record_refusal(stage=stage, reason=reason)


def test_audit_records_are_shared_and_have_only_fixed_fields(isolated_test_dsn):
    """獨立實例提交不同 UUID，使用新連線確認內容只有伺服器分類與固定部署設定。"""
    import psycopg

    ids = [PostgresIngressAudit(isolated_test_dsn, environment_id="env", deployment_id="deploy").record_refusal(
        stage="trusted_ingress", reason="unavailable") for _ in range(2)]
    assert ids[0] != ids[1] and all(UUID(value).version == 4 for value in ids)
    with psycopg.connect(isolated_test_dsn) as connection:
        rows = connection.execute("SELECT row_to_json(record) FROM ingress_refusal_audit AS record").fetchall()
    assert len(rows) == 2
    for row, in rows:
        assert set(row) == {"event_id", "environment_id", "deployment_id", "stage", "reason", "recorded_at"}
        assert row["event_id"] in ids and row["environment_id"] == "env" and row["deployment_id"] == "deploy"
        assert row["stage"] == "trusted_ingress" and row["reason"] == "unavailable"


def test_two_services_record_refusals_without_world_or_secret_leak(http_worlds):
    """雙 TLS 程序保存驗章及資源錯配拒絕，不保存 Token／ID／路徑，也不建立替代世界。"""
    import httpx
    import psycopg

    lab = http_worlds
    binding = lab.create(0, "audit-only-creator-canary")
    before = lab.counts()
    with psycopg.connect(lab.dsn) as connection:
        assert connection.execute("SELECT count(*) FROM ingress_refusal_audit").fetchone() == (0,)
    request_id = "audit-fixed-request-id"
    unsigned = httpx.Request("GET", "https://shop.test/store/carts/secret-resource-canary",
        headers={"x-request-id": request_id, "x-trusted-session": "secret-token-canary",
                 "cookie": "secret-cookie-canary", "user-agent": "secret-agent-canary"})
    first = lab.exchange(0, unsigned)
    second = lab.send(1, binding, "GET", "/store/carts/secret-resource-canary", request_id=request_id)
    assert first.status_code == second.status_code == 503 and first.content == second.content
    assert list(first.headers.multi_items()) == list(second.headers.multi_items())
    assert lab.counts() == before
    with psycopg.connect(lab.dsn) as connection:
        rows = connection.execute("SELECT row_to_json(record) FROM ingress_refusal_audit AS record").fetchall()
    assert len(rows) == 2
    assert {(row["stage"], row["reason"]) for row, in rows} == {
        ("trusted_ingress", "unavailable"), ("resource_binding", "resource_scope_mismatch")}
    import json
    serialized = json.dumps(rows)
    for value in ("secret-", binding.resource_id, binding.session_id, request_id, "/store/", "x-trusted-session"):
        assert value not in serialized


def test_audit_storage_failure_keeps_refusal_and_sanitized_alarm(isolated_test_dsn, tmp_path, monkeypatch, caplog):
    """稽核寫入故障不放行、無重試，告警不包含底層例外、DSN 或訪客憑證。"""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from fastapi.testclient import TestClient
    from deception.domains.ecommerce.http_demo import DemoConfig
    from deception.domains.ecommerce.trusted_http import create_app
    from deception.security.trusted_deployment import TrustedDeploymentSettings

    settings = TrustedDeploymentSettings(issuer="gateway", audience="mirage", environment_id="isolated-demo",
        deployment_id="isolated-demo", source_id="local-demo-detector", service_id="synthetic-store",
        site_id="demo-store", public_keys={"test": Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()})
    app = create_app(settings=settings, postgres_dsn=isolated_test_dsn,
        config=DemoConfig(origin="https://shop.test"), output_root=tmp_path)
    attempts = []

    def broken_audit(self, **values):
        """模擬含機密的 DB 例外，確認入口只輸出固定告警且不重新寫入。"""
        attempts.append(values)
        raise RuntimeError("secret-database-password-canary")

    monkeypatch.setattr(PostgresIngressAudit, "record_refusal", broken_audit)
    with caplog.at_level(logging.ERROR), TestClient(app, base_url="https://shop.test") as client:
        response = client.get("/products/secret-product", headers={"x-trusted-session": "secret-token-canary"})
    assert response.status_code == 503 and response.json()["code"] == "pipeline_unavailable"
    assert attempts == [{"stage": "trusted_ingress", "reason": "unavailable"}]
    assert "mirage_ingress_audit_unavailable" in caplog.text and "secret-" not in caplog.text
    assert isolated_test_dsn not in caplog.text


@pytest.mark.parametrize("boundary", ["world_resolve", "read_admission", "response_pipeline"])
def test_verified_request_failure_records_actual_boundary(isolated_test_dsn, tmp_path, monkeypatch, boundary):
    """真正驗章通過後，在世界、讀取或 pipeline 回固定錯誤的邊界故障仍保存正確階段。"""
    import base64
    import time
    from uuid import uuid4
    import psycopg
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from fastapi.testclient import TestClient
    from deception.api.fingerprint import fingerprint_request
    from deception.api.ingress import NormalizedRequest
    from deception.api.pipeline import _unavailable
    from deception.domains.ecommerce import trusted_http
    from deception.domains.ecommerce.http_demo import DemoConfig
    from deception.security.trusted_deployment import TrustedDeploymentSettings
    from test_trusted_session import encode

    signing = Ed25519PrivateKey.generate()
    settings = TrustedDeploymentSettings(issuer="gateway", audience="mirage", environment_id="isolated-demo",
        deployment_id="isolated-demo", source_id="local-demo-detector", service_id="synthetic-store",
        site_id="demo-store", public_keys={"test": signing.public_key().public_bytes_raw().hex()})
    app = trusted_http.create_app(settings=settings, postgres_dsn=isolated_test_dsn,
        config=DemoConfig(origin="https://shop.test"), output_root=tmp_path)

    def broken_boundary(self, *args, **kwargs):
        """在指定儲存邊界模擬故障，例外內容不得進入稽核。"""
        raise RuntimeError("secret-boundary-canary")

    async def unavailable_pipeline(request):
        """模擬內層 pipeline 自行捕捉失敗後回 503，而非向外拋錯。"""
        return _unavailable(request)

    def pipeline_factory(*args, **kwargs):
        """只替換測試的內層 pipeline，保留外層驗章與世界讀取。"""
        return unavailable_pipeline

    if boundary == "response_pipeline":
        monkeypatch.setattr(trusted_http, "make_pipeline_handler", pipeline_factory)
    else:
        method = "resolve" if boundary == "world_resolve" else "admit_read"
        monkeypatch.setattr(trusted_http.PostgresSessionWorlds, method, broken_boundary)
    with TestClient(app, base_url="https://shop.test") as client:
        request_id = uuid4().hex
        outgoing = client.build_request("GET", "/products/secret-product", headers={"x-request-id": request_id})
        normalized = NormalizedRequest(request_id=request_id, method="GET", raw_url=str(outgoing.url),
            path="/products/secret-product", raw_path=b"/products/secret-product", query_string=b"", query=(),
            headers=tuple(outgoing.headers.multi_items()), body=b"")
        now = int(time.time())
        claims = dict(iss="gateway", aud="mirage", iat=now, nbf=now, exp=now+60, jti=uuid4().hex,
            environment_id="isolated-demo", deployment_id="isolated-demo", session_id=uuid4().hex,
            session_epoch=1, resource_id=None, access_mode="read_only", request_fingerprint=fingerprint_request(normalized),
            assessment_id=uuid4().hex, assessment_digest="a" * 64)
        content = encode(dict(alg="Ed25519", typ="mirage-trusted-session+jwt", protocol_version="1.1", kid="test")) + "." + encode(claims)
        outgoing.headers["x-trusted-session"] = content + "." + base64.urlsafe_b64encode(
            signing.sign(content.encode())).decode().rstrip("=")
        response = client.send(outgoing)
    assert response.status_code == 503
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT stage,reason FROM ingress_refusal_audit").fetchall() == [(boundary, "unavailable")]
        assert connection.execute("SELECT count(*) FROM replay_entries").fetchone() == (1,)
