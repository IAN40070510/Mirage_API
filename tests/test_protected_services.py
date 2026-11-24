"""G3b 正式角色組裝只接受專用 Secret／固定路由，不允許共用 Runtime 權限。"""

import asyncio
import base64
from copy import deepcopy
import json
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deception.security.protected_rpc import (
    FixedExecutorMTLSClient, FixedNativeValidatorMTLSClient,
    ProtectedRpcConfigurationError, create_fixed_sender_app, create_native_validator_app,
)
from deception.security.protected_services import (
    _json_secret, _login_preflight, _verifier_key_registry, create_executor_service,
    create_native_validator_service, create_sender_service,
    create_verifier_service, from_environment,
)
from deception.world.protected_grant import ProtectedGrantError
from deception.world.protected_native_http import (
    PostgresProtectedNativeProjector, fixed_medusa_rejection_bytes,
    fixed_synthetic_rejection_bytes,
)
from deception.world.transmission import response_hashes


def test_g3b_cart_creation_validator_rejects_cross_scope_and_forged_projection(monkeypatch):
    """C-01 只從 Creator Receipt 取派生建置，重算合法 Hash 也不能換掉 Scope。"""
    from deception.security import protected_rpc

    receipt, attempt = uuid4(), uuid4()
    resource = "cart_" + uuid4().hex
    projection = {}

    class MockCartCreationValidator:
        """傳輸只接受 Receipt；客戶端必須自行檢查每個 Source 欄位。"""

        def __init__(self, **kwargs):
            """所有請求不繼承環境代理伺服器。"""
            assert kwargs["trust_env"] is False

        async def __aenter__(self):
            """提供模擬的單次 mTLS 連線。"""
            return self

        async def __aexit__(self, *_):
            """不隱藏 Validator 失敗。"""
            return False

        async def post(self, url, *, json):
            """Caller 不得選擇 Response Body 或源 Scope。"""
            assert url == "https://validator.invalid:8445/internal/v1/project-cart-creation"
            assert json == {"receipt_id": str(receipt)}
            return httpx.Response(200, json=projection)

    monkeypatch.setattr(protected_rpc.httpx, "AsyncClient", MockCartCreationValidator)
    client = object.__new__(FixedNativeValidatorMTLSClient)
    client._origin, client._tls = "https://validator.invalid:8445", object()
    payload = {"cart": {"id": resource, "items": [], "currency_code": "usd",
                        "total": 0, "status": "active"}, "state_version": 1,
               "state_hash": "b" * 64, "commit_attempt_id": str(attempt)}
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    headers = (("content-type", "application/json"),)
    baseline = {
        "receipt_id": str(receipt), "operation_id": "createGuestCart",
        "scope": {"environment_id": "env", "deployment_id": "deploy",
                  "session_id": "creator", "world_generation_id": "creator-world"},
        "request_fingerprint": "a" * 64, "status_code": 200,
        "headers": [["content-type", "application/json"]],
        "body_b64": base64.b64encode(body).decode(),
        "envelope_hash": response_hashes(200, headers, body)[0],
        "source": {"kind": "cart_creation", "derived_session_id": "derived",
                   "derived_world_generation_id": "derived-world", "resource_id": resource,
                   "commit_attempt_id": str(attempt), "state_version": 1,
                   "state_hash": "b" * 64}, "trusted_send": "disabled",
    }
    args = dict(receipt_id=receipt, operation_id="createGuestCart", resource_id=resource,
                commit_attempt_id=str(attempt), request_fingerprint="a" * 64,
                expected_environment_id="env", expected_deployment_id="deploy",
                expected_session_id="creator")
    projection.update(deepcopy(baseline))
    accepted = asyncio.run(client.project_cart_creation(**args))
    assert accepted["body_sha256"] == response_hashes(200, headers, body)[1]
    assert accepted["delivery"] == "candidate_only_no_send_authorization"
    for change in (
            {"status_code": 409}, {"receipt_id": str(uuid4())},
            {"trusted_send": "enabled"}, {"envelope_hash": "f" * 64},
            {"headers": [["x-forged", "true"]]},
            {"scope": {**baseline["scope"], "session_id": "derived"}},
            {"source": {**baseline["source"], "derived_session_id": "creator"}},
            {"source": {**baseline["source"], "resource_id": "cart_" + uuid4().hex}},
            {"source": {**baseline["source"], "state_hash": "c" * 64}},
            {"body_b64": base64.b64encode(body + b" ").decode()},
            {"extra": "injected"},
    ):
        projection.clear()
        projection.update(deepcopy(baseline))
        projection.update(change)
        with pytest.raises(ProtectedRpcConfigurationError, match="cart_creation_binding_mismatch"):
            asyncio.run(client.project_cart_creation(**args))


def test_g3b_cart_executor_requires_medusa_insert_but_inventory_denies_it(monkeypatch):
    """模擬實體 ACL：Cart 可寫固定拒絕來源，Inventory 不得借用這項特權。"""
    import psycopg

    class FakeConnection:
        """僅模擬角色身分與 ACL 查詢，強制觀察是否錯判 Cart 權限。"""

        def __enter__(self):
            """模擬開啟單一實體角色的資料庫連線。"""
            return self

        def __exit__(self, *_):
            """模擬關閉唯讀的預檢交易。"""
            return False

        def execute(self, query, params=()):
            """對 ACL 探查回傳明確的允許／拒絕結果。"""
            statement = str(query)
            if "SELECT session_user,current_user" in statement:
                self.value = ("cart_login", "cart_login", False, False, False,
                              False, False, False)
            elif "SELECT current_schema()" in statement:
                self.value = ("public",)
            elif "has_schema_privilege" in statement:
                self.value = (False,)
            elif "FROM pg_auth_members" in statement:
                self.value = (0,)
            elif "has_table_privilege" in statement:
                table, privilege = params
                denied = {("ingress_receipts", "INSERT"),
                          ("protected_http_operation_bindings", "INSERT"),
                          ("protected_candidate_promotions", "INSERT")}
                self.value = ((table, privilege) not in denied,)
            elif "has_function_privilege" in statement:
                self.value = (True,)
            else:
                raise AssertionError("unexpected ACL query: " + statement)
            return self

        def fetchone(self):
            """回傳最近一次 ACL 或身分預檢結果。"""
            return self.value

    monkeypatch.setattr(psycopg, "connect", lambda *_args, **_kwargs: FakeConnection())
    _login_preflight("postgresql://unused", "cart_login", role="executor",
                     schema="public", platform="synthetic-carts")
    with pytest.raises(ProtectedRpcConfigurationError, match="forbidden_acl_detected"):
        _login_preflight("postgresql://unused", "cart_login", role="executor",
                         schema="public", platform="synthetic-inventory")


def test_g3b_service_bootstrap_rejects_missing_role_and_unsafe_sender(monkeypatch):
    """缺少服務角色、埠號或企圖開 Sender 時立即拒絕，不誤啟任何 listener。"""
    with pytest.raises(ProtectedRpcConfigurationError, match="configuration_incomplete"):
        from_environment()
    monkeypatch.setenv("MIRAGE_G3B_BIND_HOST", "127.0.0.1")
    monkeypatch.setenv("MIRAGE_G3B_BIND_PORT", "8444")
    monkeypatch.setenv("MIRAGE_G3B_SERVICE_ROLE", "runtime")
    with pytest.raises(ProtectedRpcConfigurationError, match="unapproved_role"):
        from_environment()
    monkeypatch.setenv("MIRAGE_TRUSTED_SEND_ENABLE", "true")
    with pytest.raises(ProtectedRpcConfigurationError, match="unsafe_runtime_configuration"):
        from_environment()


def test_g4_sender_dedicated_secret_and_lease_are_sealed(tmp_path, monkeypatch):
    """G4 專用 Sender 即使有 DB 身分也不能透過 HTTP 申請 Lease 或起送。"""
    from fastapi.testclient import TestClient
    from deception.world.protected_send import PostgresProtectedSender

    dsn = tmp_path / "sender.dsn"
    dsn.write_text("postgresql://sender-only.invalid/g4", encoding="ascii")
    seen = []

    def preflight(*args, **kwargs):
        """確認建置流程僅使用專用 Sender 實體 Login 預檢。"""
        seen.append((args, kwargs))

    monkeypatch.setattr("deception.security.protected_services._login_preflight", preflight)
    config = {"MIRAGE_G4_SENDER_DSN_FILE": str(dsn),
              "MIRAGE_G4_SENDER_LOGIN": "sender_only",
              "MIRAGE_G3B_WORLD_SCHEMA": "public"}
    app = create_sender_service(config)
    assert seen == [(('postgresql://sender-only.invalid/g4', 'sender_only'),
                     {'role': 'sender', 'schema': 'public'})]
    assert app.openapi_url is None

    def forbidden_send(*_args, **_kwargs):
        """若 HTTP 竟觸發 Sender 原始方法，測試必須直接失敗。"""
        raise AssertionError("sealed Sender must not touch the lease database")

    monkeypatch.setattr(PostgresProtectedSender, "start_send", forbidden_send)
    with TestClient(app, base_url="https://sender.test") as caller:
        assert caller.get("/internal/ready").json() == {
            "control_plane": "sender-sealed-until-restore-fence",
            "trusted_send": "disabled"}
        for payload in ({}, {"trusted_send": "enabled", "force": True},
                        {"receipt_id": str(uuid4()), "payload": "forged"}):
            reply = caller.post("/internal/v1/send", json=payload)
            assert reply.status_code == 503
            assert reply.json() == {"detail": "fixed_sender_restore_fence_required"}
        assert caller.post("/internal/v1/execute", json={}).status_code == 404
    with pytest.raises(ProtectedRpcConfigurationError, match="requires_protected_sender"):
        create_fixed_sender_app(sender=object())

    for key in ("MIRAGE_POSTGRES_DSN", "MIRAGE_G3B_VERIFIER_DSN_FILE",
                "MIRAGE_G3B_EXECUTOR_DSN_FILE", "MIRAGE_G3B_VALIDATOR_DSN_FILE"):
        with pytest.raises(ProtectedRpcConfigurationError, match="cross_role_secret_denied"):
            create_sender_service({**config, key: "not-a-sender-secret"})
    with pytest.raises(ProtectedRpcConfigurationError, match="unsafe_runtime_configuration"):
        create_sender_service({**config, "MIRAGE_TRUSTED_SEND_ENABLE": "true"})


def test_g4_sender_preflight_requires_column_only_state_update(monkeypatch):
    """Sender 無權修改 Admission 任意欄位，也不能寫 Proof、Snapshot 與業務表。"""
    import psycopg

    class FakeConnection:
        """模擬獨立物理 Login、唯狀態欄可更新的最小必要 ACL。"""

        def __enter__(self):
            """支援預檢 context。"""
            return self

        def __exit__(self, *_):
            """結束測試連線。"""
            return False

        def execute(self, query, params=()):
            """用明確 deny-by-default ACL 回應，避免任何隱藏的權限通過。"""
            statement = str(query)
            if "SELECT session_user,current_user" in statement:
                self.value = ("sender_login", "sender_login", False, False, False,
                              False, False, False)
            elif "SELECT current_schema()" in statement:
                self.value = ("public",)
            elif "has_schema_privilege" in statement:
                self.value = (False,)
            elif "FROM pg_auth_members" in statement:
                self.value = (0,)
            elif "has_table_privilege" in statement:
                allowed = {("response_admissions", "SELECT"),
                           ("protected_authorized_http_snapshots", "SELECT"),
                           ("protected_grant_bindings", "SELECT"),
                           ("protected_send_leases", "INSERT"),
                           ("protected_send_leases", "SELECT"),
                           ("response_audit", "INSERT")}
                self.value = (params in allowed,)
            elif "has_column_privilege" in statement:
                table, column = params
                self.value = (table == "response_admissions" and column == "state",)
            else:
                raise AssertionError("unexpected Sender ACL query: " + statement)
            return self

        def fetchone(self):
            """取得最後一次 PG ACL 檢查結果。"""
            return self.value

    fake = FakeConnection()
    monkeypatch.setattr(psycopg, "connect", lambda *_args, **_kwargs: fake)
    _login_preflight("postgresql://unused", "sender_login", role="sender", schema="public")
    original_execute = FakeConnection.execute

    def overly_privileged(self, query, params=()):
        """任意欄位被多授 UPDATE 權即刻要求啟動失敗。"""
        result = original_execute(self, query, params)
        if "has_column_privilege" in str(query) and params[1] == "admission":
            self.value = (True,)
        return result

    monkeypatch.setattr(FakeConnection, "execute", overly_privileged)
    with pytest.raises(ProtectedRpcConfigurationError, match="excessive_acl_detected"):
        _login_preflight("postgresql://unused", "sender_login", role="sender", schema="public")


def test_g3b_secret_parser_rejects_duplicates_and_unapproved_public_keys(tmp_path):
    """重複 JSON Key、超大 Secret、無法核對的 Ed25519 公鑰均不可進入 Verifier。"""
    path = tmp_path / "keys.json"
    config = {"MIRAGE_G3B_EXPECTED_ISSUER": "gateway", "MIRAGE_G3B_VERIFIER_KEYS_FILE": str(path)}
    path.write_text('{"old":"a","old":"b"}', encoding="utf-8")
    with pytest.raises(ProtectedRpcConfigurationError, match="secret_json_invalid"):
        _json_secret(config, "MIRAGE_G3B_VERIFIER_KEYS_FILE")
    path.write_bytes(b"x" * 65537)
    with pytest.raises(ProtectedRpcConfigurationError, match="secret_unavailable"):
        _json_secret(config, "MIRAGE_G3B_VERIFIER_KEYS_FILE")
    path.write_text(json.dumps({"old": "!!!"}), encoding="utf-8")
    with pytest.raises(ProtectedRpcConfigurationError, match="key_registry_invalid"):
        _verifier_key_registry(config)
    key = Ed25519PrivateKey.generate()
    path.write_text(json.dumps({"old": base64.b64encode(key.public_key().public_bytes_raw()).decode()}),
                    encoding="utf-8")
    assert _verifier_key_registry(config).get("gateway", "old") is not None


def test_g3b_cross_role_secret_is_denied_before_db_connection():
    """Verifier 與 Executor 不能把 Runtime 共用 DSN 或對方的角色秘密當作備援。"""
    for maker in (create_verifier_service, create_executor_service,
                  create_native_validator_service):
        for key in ("MIRAGE_POSTGRES_DSN", "MIRAGE_G3B_VERIFIER_DSN_FILE",
                    "MIRAGE_G3B_EXECUTOR_DSN_FILE", "MIRAGE_G3B_VALIDATOR_DSN_FILE"):
            owned = {
                create_verifier_service: "MIRAGE_G3B_VERIFIER_DSN_FILE",
                create_executor_service: "MIRAGE_G3B_EXECUTOR_DSN_FILE",
                create_native_validator_service: "MIRAGE_G3B_VALIDATOR_DSN_FILE",
            }[maker]
            if key == owned:
                continue
            with pytest.raises(ProtectedRpcConfigurationError, match="cross_role_secret_denied"):
                maker({key: "postgresql://leaked.invalid/db"})


def test_g3b_isolated_compose_does_not_publish_executor_or_share_dsn():
    """四服務、三層網路、獨立物理 DSN 與 mTLS Secret，不得公開埠。"""
    root = Path(__file__).resolve().parents[1]
    path = root / "deploy/security-lab/g3b-compose.yaml"
    compose = yaml.safe_load(path.read_text(encoding="utf-8"))
    services = compose["services"]
    assert set(services) == {"verifier", "inventory-executor", "cart-executor", "native-validator"}
    for name, service in services.items():
        assert "ports" not in service
        assert service["read_only"] is True
        assert service["profiles"] == ["g3b-isolated"]
        assert "ALL" in service["cap_drop"]
        assert "g3b_execution" in service["networks"]
        assert "g3b_database" in service["networks"]
        assert service["environment"]["MIRAGE_TRUSTED_SEND_ENABLE"] == "false"
        assert "MIRAGE_POSTGRES_DSN" not in service["environment"]
        assert "MIRAGE_POSTGRES_DSN" not in service["secrets"]
    assert services["verifier"]["networks"] == ["g3b_gateway", "g3b_execution", "g3b_database"]
    assert "g3b_gateway" not in services["inventory-executor"]["networks"]
    assert "g3b_gateway" not in services["cart-executor"]["networks"]
    assert "g3b_gateway" not in services["native-validator"]["networks"]
    assert "g3b_inventory_executor_dsn" not in services["verifier"]["secrets"]
    assert "g3b_cart_executor_dsn" not in services["verifier"]["secrets"]
    assert "g3b_verifier_dsn" not in services["inventory-executor"]["secrets"]
    assert "g3b_verifier_dsn" not in services["cart-executor"]["secrets"]
    assert "g3b_verifier_dsn" not in services["native-validator"]["secrets"]
    assert "g3b_native_validator_dsn" not in services["verifier"]["secrets"]
    assert "g3b_native_validator_dsn" not in services["inventory-executor"]["secrets"]
    assert "g3b_native_validator_dsn" not in services["cart-executor"]["secrets"]
    assert set(services["native-validator"]["secrets"]).isdisjoint(
        services["cart-executor"]["secrets"])
    assert services["verifier"]["environment"]["MIRAGE_G3B_NATIVE_VALIDATOR_ORIGIN"] == (
        "https://native-validator:8445")


def test_g4_sender_compose_is_separate_sealed_network_and_secret_boundary():
    """G4 Sender 的候選部署不進四服務 Gateway/Executor 網，無 Host 埠及跨角色秘密。"""
    root = Path(__file__).resolve().parents[1]
    compose = yaml.safe_load((root / "deploy/security-lab/g4-sender-sealed-compose.yaml")
                             .read_text(encoding="utf-8"))
    assert set(compose["services"]) == {"sender"}
    service = compose["services"]["sender"]
    assert service["profiles"] == ["g4-sender-sealed"]
    assert service["networks"] == ["g4_sender_delivery", "g3b_database"]
    assert "ports" not in service
    assert "ALL" in service["cap_drop"]
    assert service["read_only"] is True
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["environment"]["MIRAGE_G3B_SERVICE_ROLE"] == "sender"
    assert service["environment"]["MIRAGE_TRUSTED_SEND_ENABLE"] == "false"
    assert set(service["secrets"]) == {
        "g4_sender_dsn", "g4_sender_server_cert", "g4_sender_server_key",
        "g4_sender_client_ca"}
    assert "MIRAGE_POSTGRES_DSN" not in service["environment"]
    assert "MIRAGE_POSTGRES_DSN" not in service["secrets"]
    assert "g3b_gateway" not in compose["networks"]
    assert "g3b_execution" not in compose["networks"]
    assert compose["networks"]["g4_sender_delivery"]["name"] == (
        "mirage-g4-sender-delivery-net")


def test_g3b_ci_waits_for_final_postgres_tcp_listener_not_initdb_socket():
    """隔離四服務 CI 不得把 initdb 的暫時 Unix socket ready 誤當正式 DB 啟動。"""
    workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/"
                "g3b-four-service-isolated.yml").read_text(encoding="utf-8")
    assert "database_ready=false" in workflow
    assert "pg_isready -h 127.0.0.1 -U mirage_ci_owner -d mirage_g3b_ci" in workflow
    assert "G3B_POSTGRES_TCP_READINESS_TIMEOUT" in workflow


def test_medusa_native_rejection_bytes_are_fixed_and_never_caller_defined():
    """只有受保護 400／404 模板能產生固定原生 JSON，403／409／200 必須拒絕。"""
    for status, template, expected in (
        (400, "native-cart-invalid", "invalid_data"),
        (404, "native-cart-rejected", "not_found"),
    ):
        headers, body = fixed_medusa_rejection_bytes(status, template)
        assert headers == (("content-type", "application/json"),)
        assert json.loads(body)["type"] == expected
    for status, template in ((200, "native-cart-invalid"), (409, "native-cart-rejected"),
                             (400, "native-cart-rejected"), (404, "native-cart-invalid")):
        with pytest.raises(ProtectedGrantError, match="template_unapproved"):
            fixed_medusa_rejection_bytes(status, template)


def test_g3b_native_validator_only_accepts_https_receipt_uuid4():
    """獨立 Validator 入口只收 HTTPS／UUID4，拒絕 Client 補 Status、Body 或雙重 Key。"""
    from uuid import uuid4

    from fastapi.testclient import TestClient

    projector = PostgresProtectedNativeProjector(
        "postgresql://localhost/invalid-test", expected_login="validator",
    )
    app = create_native_validator_app(projector=projector)
    receipt = str(uuid4())
    with TestClient(app, base_url="http://validator.test") as insecure:
        assert insecure.post("/internal/v1/project-medusa-rejection",
                             json={"receipt_id": receipt}).status_code == 503
        assert insecure.post("/internal/v1/project-synthetic-rejection",
                             json={"receipt_id": receipt}).status_code == 503
        assert insecure.post("/internal/v1/project-inventory-operation",
                             json={"receipt_id": receipt}).status_code == 503
        assert insecure.post("/internal/v1/project-cart-read",
                             json={"receipt_id": receipt}).status_code == 503
    with TestClient(app, base_url="https://validator.test") as secure:
        assert secure.post("/internal/v1/project-medusa-rejection",
                           json={"receipt_id": receipt, "status_code": 200}).status_code == 400
        assert secure.post("/internal/v1/project-medusa-rejection", content=(
            '{"receipt_id":"' + receipt + '","receipt_id":"' + receipt + '"}'
        )).status_code == 400
        assert secure.post("/internal/v1/project-medusa-rejection",
                           json={"receipt_id": "not-uuid"}).status_code == 400
        assert secure.post("/internal/v1/project-medusa-rejection",
                           content=b"x" * 1025).status_code == 413
        assert secure.post("/internal/v1/project-medusa-rejection",
                           json={"receipt_id": receipt}).status_code == 503
        assert secure.post("/internal/v1/project-synthetic-rejection",
                           json={"receipt_id": receipt, "template_id": "version_conflict"}).status_code == 400
        assert secure.post("/internal/v1/project-synthetic-rejection",
                           json={"receipt_id": receipt}).status_code == 503
        assert secure.post("/internal/v1/project-inventory-snapshot",
                           json={"receipt_id": receipt, "sku": "caller-selected"}).status_code == 400
        assert secure.post("/internal/v1/project-inventory-snapshot",
                           json={"receipt_id": receipt}).status_code == 503
        assert secure.post("/internal/v1/project-inventory-operation",
                           json={"receipt_id": receipt, "status_code": 200}).status_code == 400
        assert secure.post("/internal/v1/project-inventory-operation",
                           json={"receipt_id": receipt}).status_code == 503
        assert secure.post("/internal/v1/project-cart-read",
                           json={"receipt_id": receipt, "status_code": 200}).status_code == 400
        assert secure.post("/internal/v1/project-cart-read",
                           json={"receipt_id": receipt}).status_code == 503


def test_g3b_cart_order_read_200_validator_rejects_forged_native_payloads(monkeypatch):
    """C-02／C-07 獨立 Validator 固定成功 JSON，不接受錯綁 Cart／Order 或任意 Header。"""
    from deception.security import protected_rpc

    receipt = uuid4()
    cart_id, order_id = "cart_" + uuid4().hex, "order_" + uuid4().hex
    headers = (("content-type", "application/json"),)
    projection = {}

    class MockCartValidator:
        """模擬隔離 Validator 傳輸，保留真實用戶端 JSON／Digest 驗證流程。"""

        def __init__(self, **kwargs):
            """禁止模擬過程降級 TLS 或環境 Proxy。"""
            assert kwargs["trust_env"] is False

        async def __aenter__(self):
            """提供有限範圍的測試 mTLS 實體。"""
            return self

        async def __aexit__(self, *_):
            """不吞掉驗證失敗。"""
            return False

        async def post(self, url, *, json):
            """唯讀 Validator 只接受受保護 Receipt，不接受狀態或 Body 選擇。"""
            assert url == "https://validator.invalid:8445/internal/v1/project-cart-read"
            assert json == {"receipt_id": str(receipt)}
            return httpx.Response(200, json=projection)

    monkeypatch.setattr(protected_rpc.httpx, "AsyncClient", MockCartValidator)
    client = object.__new__(FixedNativeValidatorMTLSClient)
    client._origin, client._tls = "https://validator.invalid:8445", object()
    for operation, resource, kind, entity in (
            ("getGuestCart", cart_id, "cart", {
                "id": cart_id, "items": [], "currency_code": "usd", "total": 0,
                "status": "active"}),
            ("getSyntheticOrder", order_id, "order", {
                "id": order_id, "cart_id": cart_id, "items": [], "currency_code": "usd",
                "total": 0, "status": "placed"}),
    ):
        payload = {kind: entity, "state_version": 2, "state_hash": "b" * 64,
                   "commit_attempt_id": None}
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        envelope, body_hash, _ = response_hashes(200, headers, body)
        baseline = {
            "receipt_id": str(receipt), "operation_id": operation,
            "scope": {"environment_id": "env", "deployment_id": "deploy",
                      "session_id": "session", "world_generation_id": "world"},
            "request_fingerprint": "a" * 64, "status_code": 200,
            "headers": [["content-type", "application/json"]],
            "body_b64": base64.b64encode(body).decode("ascii"),
            "envelope_hash": envelope,
            "source": {"kind": "snapshot", "read_admission_id": uuid4().hex,
                       "world_generation_id": "world", "state_version": 2,
                       "state_hash": "b" * 64},
            "trusted_send": "disabled",
        }
        kwargs = dict(receipt_id=receipt, operation_id=operation, resource_id=resource,
                      request_fingerprint="a" * 64,
                      expected_environment_id="env", expected_deployment_id="deploy",
                      expected_session_id="session",
                      expected_read_admission_id=baseline["source"]["read_admission_id"],
                      expected_world_generation_id="world", expected_state_version=2,
                      expected_state_hash="b" * 64)
        projection.clear()
        projection.update(deepcopy(baseline))
        accepted = asyncio.run(client.project_cart_read(**kwargs))
        assert accepted["body_sha256"] == body_hash
        assert accepted["status_code"] == 200
        assert accepted["delivery"] == "candidate_only_no_send_authorization"
        for change in (
                {"status_code": 409}, {"receipt_id": str(uuid4())},
                {"request_fingerprint": "f" * 64}, {"trusted_send": "enabled"},
                {"envelope_hash": "f" * 64},
                {"headers": [["x-runtime", "false"]]},
                {"source": {**baseline["source"], "read_admission_id": uuid4().hex}},
                {"scope": {**baseline["scope"], "session_id": "other"}},
                {"body_b64": base64.b64encode(body + b" ").decode()},
                {"body_b64": base64.b64encode(body.replace(resource.encode(),
                                                              ("cart_" + "0" * 32 if kind == "cart"
                                                               else "order_" + "0" * 32).encode())).decode()},
                {"body_b64": base64.b64encode(body.replace(b'"state_version":2',
                                                             b'"state_version":3')).decode()},
                {"extra": "forged"},
        ):
            projection.clear()
            projection.update(deepcopy(baseline))
            projection.update(change)
            with pytest.raises(ProtectedRpcConfigurationError, match="cart_validator_binding_mismatch"):
                asyncio.run(client.project_cart_read(**kwargs))
        with pytest.raises(ProtectedRpcConfigurationError, match="cart_validator_operation_unapproved"):
            asyncio.run(client.project_cart_read(**{**kwargs, "resource_id": "wrong"}))


@pytest.mark.parametrize("kind", ["cart", "order"])
def test_g3b_cart_operation_validator_binds_historical_entity_to_requested_cart(monkeypatch, kind):
    """C-09 歷史結果即使 Schema／Hash 合法，亦不得換成另一個 Cart 的實體。"""
    from deception.security import protected_rpc

    receipt, attempt = uuid4(), uuid4()
    cart_id = "cart_" + uuid4().hex
    entity = ({"id": cart_id, "items": [], "currency_code": "usd", "total": 0,
               "status": "active"} if kind == "cart" else
              {"id": "order_" + uuid4().hex, "cart_id": cart_id,
               "items": [], "currency_code": "usd", "total": 0, "status": "placed"})
    projected = {}

    class MockValidator:
        """只替換獨立 mTLS 結果，保留真實投影綁定驗證。"""

        def __init__(self, **kwargs):
            """檢查來源獨立於環境 Proxy。"""
            assert kwargs["trust_env"] is False

        async def __aenter__(self):
            """開啟單次模擬 mTLS 連線。"""
            return self

        async def __aexit__(self, *_):
            """結束連線且傳播驗證錯誤。"""
            return False

        async def post(self, url, *, json):
            """只允許以 Receipt 查核，不讓 Client 選擇歷史 Response。"""
            assert url == "https://validator.invalid:8445/internal/v1/project-cart-read"
            assert json == {"receipt_id": str(receipt)}
            return httpx.Response(200, json=projected)

    monkeypatch.setattr(protected_rpc.httpx, "AsyncClient", MockValidator)
    client = object.__new__(FixedNativeValidatorMTLSClient)
    client._origin, client._tls = "https://validator.invalid:8445", object()
    args = dict(receipt_id=receipt, operation_id="getCartOperation", resource_id=cart_id,
                request_fingerprint="a" * 64, expected_environment_id="env",
                expected_deployment_id="deploy", expected_session_id="session",
                expected_read_admission_id=uuid4().hex, expected_world_generation_id="world",
                expected_state_version=3, expected_state_hash="c" * 64,
                expected_attempt_id=str(attempt))

    def set_projection(result_entity):
        """依固定原生契約重算 Hash，避免單純雜湊錯誤掩蓋資源重綁。"""
        payload = {kind: result_entity, "state_version": 2, "state_hash": "b" * 64,
                   "commit_attempt_id": str(attempt)}
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        projected.clear()
        projected.update({
            "receipt_id": str(receipt), "operation_id": "getCartOperation",
            "scope": {"environment_id": "env", "deployment_id": "deploy",
                      "session_id": "session", "world_generation_id": "world"},
            "request_fingerprint": "a" * 64, "status_code": 200,
            "headers": [["content-type", "application/json"]],
            "body_b64": base64.b64encode(body).decode("ascii"),
            "envelope_hash": response_hashes(200, (("content-type", "application/json"),), body)[0],
            "source": {"kind": "snapshot", "read_admission_id": args["expected_read_admission_id"],
                       "world_generation_id": "world", "state_version": 3,
                       "state_hash": "c" * 64}, "trusted_send": "disabled",
        })

    set_projection(entity)
    assert asyncio.run(client.project_cart_read(**args))["status_code"] == 200
    altered = dict(entity)
    altered["id" if kind == "cart" else "cart_id"] = "cart_" + uuid4().hex
    set_projection(altered)
    with pytest.raises(ProtectedRpcConfigurationError, match="cart_validator_binding_mismatch"):
        asyncio.run(client.project_cart_read(**args))
    # 型別也不能互換：order.id 不是 cart.id，反之亦然。
    altered_type = dict(entity)
    altered_type["id"] = ("order_" if kind == "cart" else "cart_") + uuid4().hex
    set_projection(altered_type)
    with pytest.raises(ProtectedRpcConfigurationError, match="cart_validator_binding_mismatch"):
        asyncio.run(client.project_cart_read(**args))


def test_g3b_synthetic_rejection_has_fixed_native_409_contract():
    """合成庫存與 Cart 的 409 僅輸出精確 JSON，不允許 Runtime 自造模板碼。"""
    for platform, code in (("synthetic-inventory", "insufficient_synthetic_inventory"),
                           ("synthetic-carts", "cart_not_active")):
        headers, body = fixed_synthetic_rejection_bytes(platform, code)
        assert headers == (("content-type", "application/json"),)
        assert json.loads(body) == {"code": code}
        assert response_hashes(409, headers, body)[0] != response_hashes(200, headers, body)[0]
    for platform, code in (("medusa-native-cart", "version_conflict"),
                           ("synthetic-inventory", "runtime_defined"),
                           ("synthetic-carts", "unknown_synthetic_sku")):
        with pytest.raises(ProtectedGrantError, match="rejection_code_unapproved"):
            fixed_synthetic_rejection_bytes(platform, code)


def test_g3b_inventory_200_validator_handoff_rejects_modified_world_bytes(monkeypatch):
    """I-04 唯讀 Snapshot 的精確 JSON／來源／Scope 不得由 RPC 改寫。"""
    from deception.security import protected_rpc

    receipt = uuid4()
    payload = {"sku": "sku-1", "available": 4, "state_version": 2}
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    headers = (("content-type", "application/json"),)
    envelope, body_hash, _ = response_hashes(200, headers, body)
    baseline = {
        "receipt_id": str(receipt), "operation_id": "getSyntheticInventory",
        "scope": {"environment_id": "env", "deployment_id": "deploy",
                  "session_id": "session", "world_generation_id": "world"},
        "request_fingerprint": "a" * 64, "status_code": 200,
        "headers": [["content-type", "application/json"]],
        "body_b64": base64.b64encode(body).decode("ascii"),
        "envelope_hash": envelope,
        "source": {"kind": "snapshot", "read_admission_id": uuid4().hex,
                   "world_generation_id": "world", "state_version": 2,
                   "state_hash": "b" * 64}, "trusted_send": "disabled",
    }
    projected = deepcopy(baseline)

    class MockValidator:
        """保留真正 JSON 解析與核對邏輯，只模擬 mTLS Server 回傳。"""

        def __init__(self, **kwargs):
            """驗證 Client 不會使用 Proxy 或注入不可信 CA。"""
            assert kwargs["trust_env"] is False

        async def __aenter__(self):
            """提供單次驗證的 mTLS client 模擬。"""
            return self

        async def __aexit__(self, *_):
            """離開測試用 client 時不吞例外。"""
            return False

        async def post(self, url, *, json):
            """Validator 僅收 Receipt，禁止 Caller 自選 SKU 或 Response Body。"""
            assert url == "https://validator.invalid:8445/internal/v1/project-inventory-snapshot"
            assert json == {"receipt_id": str(receipt)}
            return httpx.Response(200, json=projected)

    monkeypatch.setattr(protected_rpc.httpx, "AsyncClient", MockValidator)
    client = object.__new__(FixedNativeValidatorMTLSClient)
    client._origin, client._tls = "https://validator.invalid:8445", object()
    kwargs = dict(receipt_id=receipt, operation_id="getSyntheticInventory",
                  resource_id="sku-1", request_fingerprint="a" * 64,
                  expected_environment_id="env", expected_deployment_id="deploy",
                  expected_session_id="session",
                  expected_read_admission_id=baseline["source"]["read_admission_id"],
                  expected_world_generation_id="world", expected_state_version=2,
                  expected_state_hash="b" * 64)
    accepted = asyncio.run(client.project_inventory_snapshot(**kwargs))
    assert accepted["body_sha256"] == body_hash
    assert accepted["delivery"] == "candidate_only_no_send_authorization"
    assert accepted["source"]["kind"] == "snapshot"
    for change in (
            {"status_code": 409}, {"receipt_id": str(uuid4())},
            {"request_fingerprint": "c" * 64}, {"trusted_send": "enabled"},
            {"envelope_hash": "0" * 64},
            {"body_b64": base64.b64encode(b'{"sku":"sku-1","available":true,"state_version":2}').decode()},
            {"body_b64": base64.b64encode(b'{"available":4,"sku":"other","state_version":2}').decode()},
            {"source": {**baseline["source"], "state_version": 3}},
            {"scope": {**baseline["scope"], "session_id": "another-session"}},
            {"headers": [["x-untrusted", "1"]]},
            {"extra_field": "forged"},
    ):
        projected.clear()
        projected.update(deepcopy(baseline))
        projected.update(change)
        with pytest.raises(ProtectedRpcConfigurationError,
                           match="inventory_validator_binding_mismatch"):
            asyncio.run(client.project_inventory_snapshot(**kwargs))
    with pytest.raises(ProtectedRpcConfigurationError, match="operation_unapproved"):
        asyncio.run(client.project_inventory_snapshot(**{**kwargs, "resource_id": "%73ku-1"}))
    for mismatch in ({"expected_read_admission_id": uuid4().hex},
                     {"expected_world_generation_id": "another-world"},
                     {"expected_state_version": 3}, {"expected_state_hash": "c" * 64}):
        projected.clear()
        projected.update(deepcopy(baseline))
        with pytest.raises(ProtectedRpcConfigurationError, match="inventory_validator_binding_mismatch"):
            asyncio.run(client.project_inventory_snapshot(**{**kwargs, **mismatch}))
    # 409 必須由同一 Snapshot 的「缺 SKU」形成固定 JSON，不能自選任意錯誤。
    denial_body = b'{"code":"unknown_synthetic_sku"}'
    denial = deepcopy(baseline)
    denial.update(status_code=409, body_b64=base64.b64encode(denial_body).decode("ascii"),
                  envelope_hash=response_hashes(409, headers, denial_body)[0])
    projected.clear()
    projected.update(deepcopy(denial))
    accepted_denial = asyncio.run(client.project_inventory_snapshot(**kwargs))
    assert accepted_denial["status_code"] == 409
    assert accepted_denial["delivery"] == "candidate_only_no_send_authorization"
    assert base64.b64decode(accepted_denial["body_b64"], validate=True) == denial_body
    for bad_body in (b'{"code":"version_conflict"}',
                     b'{"code":"unknown_synthetic_sku","extra":true}'):
        projected.clear()
        projected.update(deepcopy(denial))
        projected["body_b64"] = base64.b64encode(bad_body).decode("ascii")
        projected["envelope_hash"] = response_hashes(409, headers, bad_body)[0]
        with pytest.raises(ProtectedRpcConfigurationError, match="inventory_validator_binding_mismatch"):
            asyncio.run(client.project_inventory_snapshot(**kwargs))
    # I-04 原始 GET 允許未百分比編碼的 UTF-8 SKU；候選 mTLS 不得另設 ASCII 限制。
    unicode_sku = "品項+特別:版"
    unicode_body = json.dumps({"sku": unicode_sku, "available": 4, "state_version": 2},
                              ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    projected.clear()
    projected.update(deepcopy(baseline))
    projected["body_b64"] = base64.b64encode(unicode_body).decode("ascii")
    projected["envelope_hash"] = response_hashes(200, headers, unicode_body)[0]
    assert asyncio.run(client.project_inventory_snapshot(
        **{**kwargs, "resource_id": unicode_sku}))["status_code"] == 200


def test_g3b_inventory_operation_200_validator_rejects_forged_history(monkeypatch):
    """I-03 原生操作結果須具獨立的 Receipt／Commit／Read 證據，不能改寫歷史 Body。"""
    from deception.security import protected_rpc

    receipt, attempt = uuid4(), uuid4()
    reservation = {"reservation_id": uuid4().hex, "sku": "sku-1",
                   "quantity": 2, "status": "reserved"}
    payload = {"commit_attempt_id": str(attempt), "state_version": 2,
               "state_hash": "c" * 64, "reservation": reservation}
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    envelope, body_hash, _ = response_hashes(200, (("content-type", "application/json"),), body)
    baseline = {
        "receipt_id": str(receipt), "operation_id": "getSyntheticOperation",
        "scope": {"environment_id": "env", "deployment_id": "deploy",
                  "session_id": "session", "world_generation_id": "world"},
        "request_fingerprint": "a" * 64, "status_code": 200,
        "headers": [["content-type", "application/json"]],
        "body_b64": base64.b64encode(body).decode("ascii"),
        "envelope_hash": envelope,
        "source": {"kind": "snapshot", "read_admission_id": uuid4().hex,
                   "world_generation_id": "world", "state_version": 3,
                   "state_hash": "b" * 64}, "trusted_send": "disabled",
    }
    projected = deepcopy(baseline)

    class MockValidator:
        """替換 mTLS 傳輸結果，保留生產的獨立候選解析與逐欄驗證。"""

        def __init__(self, **kwargs):
            """禁止使用環境 Proxy 取代專屬 mTLS。"""
            assert kwargs["trust_env"] is False

        async def __aenter__(self):
            """開啟受控的 HTTPX 測試 context。"""
            return self

        async def __aexit__(self, *_):
            """離開測試 context。"""
            return False

        async def post(self, url, *, json):
            """驗證 RPC 僅傳 Receipt，絕不從 Verifier 帶入 Body／Status。"""
            assert url == "https://validator.invalid:8445/internal/v1/project-inventory-operation"
            assert json == {"receipt_id": str(receipt)}
            return httpx.Response(200, json=projected)

    monkeypatch.setattr(protected_rpc.httpx, "AsyncClient", MockValidator)
    client = object.__new__(FixedNativeValidatorMTLSClient)
    client._origin, client._tls = "https://validator.invalid:8445", object()
    kwargs = dict(receipt_id=receipt, operation_id="getSyntheticOperation",
                  resource_id=str(attempt), request_fingerprint="a" * 64,
                  expected_environment_id="env", expected_deployment_id="deploy",
                  expected_session_id="session",
                  expected_read_admission_id=baseline["source"]["read_admission_id"],
                  expected_world_generation_id="world", expected_state_version=3,
                  expected_state_hash="b" * 64)
    accepted = asyncio.run(client.project_inventory_operation(**kwargs))
    assert accepted["body_sha256"] == body_hash
    assert accepted["delivery"] == "candidate_only_no_send_authorization"
    for change in (
            {"receipt_id": str(uuid4())}, {"operation_id": "getSyntheticInventory"},
            {"status_code": 409}, {"headers": [["x-extra", "value"]]},
            {"trusted_send": "enabled"}, {"envelope_hash": "0" * 64},
            {"body_b64": base64.b64encode(body + b" ").decode("ascii")},
            {"body_b64": base64.b64encode(json.dumps({**payload,
                "reservation": {**reservation, "quantity": True}}, sort_keys=True,
                separators=(",", ":")).encode()).decode()},
            {"source": {**baseline["source"], "read_admission_id": uuid4().hex}},
            {"scope": {**baseline["scope"], "session_id": "another"}},
            {"unexpected": "untrusted"},
    ):
        projected.clear()
        projected.update(deepcopy(baseline))
        projected.update(change)
        with pytest.raises(ProtectedRpcConfigurationError, match="inventory_operation_binding_mismatch"):
            asyncio.run(client.project_inventory_operation(**kwargs))
    with pytest.raises(ProtectedRpcConfigurationError, match="operation_validator_unapproved"):
        asyncio.run(client.project_inventory_operation(**{**kwargs, "resource_id": "not-uuid4"}))


@pytest.mark.parametrize("platform,operation,code", [
    ("synthetic-inventory", "reserveSyntheticInventory", "insufficient_synthetic_inventory"),
    ("synthetic-carts", "addGuestCartItem", "unknown_synthetic_variant"),
])
def test_g3b_independent_synthetic_409_handoff_denies_candidate_rebinding(
        monkeypatch, platform, operation, code):
    """真實 HTTPX JSON 交接僅接受 Validator 的固定 Body/Scope，不能改送業務 200。"""
    from deception.security import protected_rpc

    receipt = uuid4()
    headers, body = fixed_synthetic_rejection_bytes(platform, code)
    envelope, body_hash, _ = response_hashes(409, headers, body)
    baseline = {
        "receipt_id": str(receipt), "operation_id": operation,
        "scope": {"environment_id": "env", "deployment_id": "deploy",
                  "session_id": "session", "world_generation_id": "world"},
        "request_fingerprint": "a" * 64, "status_code": 409,
        "headers": [["content-type", "application/json"]],
        "body_b64": base64.b64encode(body).decode("ascii"), "envelope_hash": envelope,
        "source": {"kind": "security_error", "template_id": code,
                   "contract_revision": platform + "-1"}, "trusted_send": "disabled",
    }
    projected = deepcopy(baseline)

    class StubAsyncClient:
        """模擬隔離 Validator 的精確 JSON，測試 Verifier 不信任結果中的欄位。"""

        def __init__(self, **kwargs):
            """強制核對獨立 mTLS 連線不得經環境 Proxy。"""
            assert kwargs["trust_env"] is False

        async def __aenter__(self):
            """提供可模擬篡改結果的 AsyncClient。"""
            return self

        async def __aexit__(self, *_):
            """關閉受控測試 HTTPX context。"""
            return False

        async def post(self, url, *, json):
            """驗證唯一 Receipt 輸入，不接受 Runtime 傳入偽造來源。"""
            assert url == "https://validator.invalid:8445/internal/v1/project-synthetic-rejection"
            assert json == {"receipt_id": str(receipt)}
            return httpx.Response(200, json=projected)

    monkeypatch.setattr(protected_rpc.httpx, "AsyncClient", StubAsyncClient)
    client = object.__new__(FixedNativeValidatorMTLSClient)
    client._origin, client._tls = "https://validator.invalid:8445", object()
    args = dict(receipt_id=receipt, operation_id=operation, platform=platform,
                request_fingerprint="a" * 64, expected_environment_id="env",
                expected_deployment_id="deploy", expected_session_id="session")
    admitted = asyncio.run(client.project_synthetic_rejection(**args))
    assert admitted["status_code"] == 409 and admitted["body_sha256"] == body_hash
    assert base64.b64decode(admitted["body_b64"], validate=True) == body
    assert admitted["delivery"] == "candidate_only_no_send_authorization"
    for mutation in ({"status_code": 200}, {"receipt_id": str(uuid4())},
                     {"request_fingerprint": "b" * 64}, {"trusted_send": "enabled"},
                     {"body_b64": base64.b64encode(body + b"x").decode("ascii")},
                     {"envelope_hash": "f" * 64}, {"headers": [["x-fake", "1"]]},
                     {"operation_id": "cancelSyntheticOrder"},
                     {"source": {"kind": "security_error", "template_id": "runtime_defined",
                                 "contract_revision": platform + "-1"}},
                     {"scope": {**baseline["scope"], "session_id": "cross-session"}},
                     {"handler": "caller-selected"}):
        projected.clear()
        projected.update(deepcopy(baseline))
        projected.update(mutation)
        with pytest.raises(ProtectedRpcConfigurationError,
                           match="synthetic_validator_projection_binding_mismatch"):
            asyncio.run(client.project_synthetic_rejection(**args))


@pytest.mark.parametrize("status,template", [
    (400, "native-cart-invalid"), (404, "native-cart-rejected"),
])
def test_g3b_validator_handoff_preserves_native_status_headers_and_body(
        monkeypatch, status, template):
    """驗證 Validator 的真實 bytes／Scope 後完整交給 Verifier，但不鑄造發送權。"""
    from deception.security import protected_rpc

    receipt = uuid4()
    headers, body = fixed_medusa_rejection_bytes(status, template)
    envelope = response_hashes(status, headers, body)[0]
    projected = {
        "receipt_id": str(receipt), "operation_id": "PostCartsIdLineItems",
        "scope": {"environment_id": "env", "deployment_id": "deploy",
                  "session_id": "session", "world_generation_id": "world"},
        "request_fingerprint": "a" * 64, "status_code": status,
        "headers": [["content-type", "application/json"]],
        "body_b64": base64.b64encode(body).decode("ascii"),
        "envelope_hash": envelope,
        "source": {"kind": "security_error", "template_id": template,
                   "contract_revision": "medusa-cart-1"},
        "trusted_send": "disabled",
    }

    class StubAsyncClient:
        """用已知 HTTPS 來源模擬回應，隔離測試完整 Validator RPC 解碼。"""

        def __init__(self, **kwargs):
            """保留已選的合法或遭竄改投影，不建立外部網路連線。"""
            assert kwargs["trust_env"] is False

        async def __aenter__(self):
            """模擬 HTTPX async context 進入。"""
            return self

        async def __aexit__(self, *_):
            """模擬 HTTPX async context 關閉。"""
            return False

        async def post(self, url, *, json):
            """核對 RPC 只傳 Receipt，不容許自選 Template 或 Scope。"""
            assert url == "https://validator.invalid:8445/internal/v1/project-medusa-rejection"
            assert json == {"receipt_id": str(receipt)}
            return httpx.Response(200, json=projected)

    monkeypatch.setattr(protected_rpc.httpx, "AsyncClient", StubAsyncClient)
    client = object.__new__(FixedNativeValidatorMTLSClient)
    client._origin, client._tls = "https://validator.invalid:8445", object()
    args = dict(receipt_id=receipt, operation_id="PostCartsIdLineItems",
                request_fingerprint="a" * 64, expected_status=status,
                expected_envelope_hash=envelope, expected_environment_id="env",
                expected_deployment_id="deploy", expected_session_id="session")
    candidate = asyncio.run(client.project_receipt(**args))
    assert candidate["status_code"] == status
    assert candidate["headers"] == [["content-type", "application/json"]]
    assert base64.b64decode(candidate["body_b64"], validate=True) == body
    assert candidate["body_sha256"] == response_hashes(status, headers, body)[1]
    assert candidate["scope"] == projected["scope"]
    assert candidate["source"] == projected["source"]
    assert candidate["delivery"] == "candidate_only_no_send_authorization"

    for mutation in ("session", "environment", "deployment", "fingerprint", "status", "body",
                     "source", "headers", "delivery", "extra", "base64"):
        negative = deepcopy(projected)
        if mutation == "session":
            negative["scope"]["session_id"] = "another-session"
        elif mutation == "environment":
            negative["scope"]["environment_id"] = "another-env"
        elif mutation == "deployment":
            negative["scope"]["deployment_id"] = "another-deploy"
        elif mutation == "fingerprint":
            negative["request_fingerprint"] = "b" * 64
        elif mutation == "status":
            negative["status_code"] = 200
        elif mutation == "body":
            negative["body_b64"] = base64.b64encode(body + b"forgery").decode("ascii")
        elif mutation == "source":
            negative["source"]["template_id"] = "runtime-custom-error"
        elif mutation == "headers":
            negative["headers"].append(["x-fake", "true"])
        elif mutation == "delivery":
            negative["trusted_send"] = "enabled"
        elif mutation == "extra":
            negative["handler"] = "arbitrary"
        elif mutation == "base64":
            negative["body_b64"] = negative["body_b64"].rstrip("=")
        projected.clear()
        projected.update(negative)
        with pytest.raises(ProtectedRpcConfigurationError,
                           match="native_validator_projection_binding_mismatch"):
            asyncio.run(client.project_receipt(**args))
        projected.clear()
        projected.update({
            "receipt_id": str(receipt), "operation_id": "PostCartsIdLineItems",
            "scope": {"environment_id": "env", "deployment_id": "deploy",
                      "session_id": "session", "world_generation_id": "world"},
            "request_fingerprint": "a" * 64, "status_code": status,
            "headers": [["content-type", "application/json"]],
            "body_b64": base64.b64encode(body).decode("ascii"),
            "envelope_hash": envelope,
            "source": {"kind": "security_error", "template_id": template,
                       "contract_revision": "medusa-cart-1"},
            "trusted_send": "disabled",
        })


def test_g3b_executor_rpc_refuses_ambiguous_result_json(monkeypatch):
    """Executor 的內部 200 不等於可信資料；重複 Key／NaN 不得傳給 Verifier。"""
    from deception.security import protected_rpc

    body = (b'{"kind":"world_mutation","operation":"reserveSyntheticInventory",'
            b'"commit_attempt_id":"attempt","status":"committed",'
            b'"state_version":1,"state_hash":"hash","result_digest":"digest"}')

    class StubAsyncClient:
        """注入真 HTTPX Response parser 邊界的重複欄位與非有限常數。"""

        def __init__(self, **kwargs):
            """確認 Proxy 不得由部署環境隱式啟用。"""
            assert kwargs["trust_env"] is False

        async def __aenter__(self):
            """建立內部測試用單次連線。"""
            return self

        async def __aexit__(self, *_):
            """關閉內部測試用單次連線。"""
            return False

        async def post(self, url, *, json):
            """固定 Receipt 與 Bytes，不讓 RPC 呼叫者選 Handler。"""
            assert url == "https://executor.invalid:8444/internal/v1/execute"
            assert set(json) == {"receipt_id", "raw_path_b64", "raw_body_b64"}
            return httpx.Response(200, content=body)

    monkeypatch.setattr(protected_rpc.httpx, "AsyncClient", StubAsyncClient)
    client = object.__new__(FixedExecutorMTLSClient)
    client._origin, client._tls = "https://executor.invalid:8444", object()
    args = dict(receipt_id=uuid4(), operation_id="reserveSyntheticInventory",
                raw_path=b"/synthetic/inventory/reservations", raw_body=b"{}")
    assert asyncio.run(client.execute_receipt(**args))["status"] == "committed"
    for forged in (body[:-1] + b',"status":"rejected"}',
                   body.replace(b'"state_version":1', b'"state_version":NaN')):
        body = forged
        with pytest.raises(ProtectedRpcConfigurationError, match="fixed_executor_result_invalid"):
            asyncio.run(client.execute_receipt(**args))


@pytest.mark.parametrize("operation,sku", [
    ("getSyntheticInventory", "sku-1"),
    ("getSyntheticInventory", "品項+特別:版"),
    ("getSyntheticOperation", None),
])
def test_g3b_executor_inventory_get_response_is_admission_metadata_only(monkeypatch, operation, sku):
    """驗證 Verifier 僅接受精確 I-03／I-04 來源欄位，拒絕混入偽造 HTTP 回應。"""
    from deception.security import protected_rpc
    from urllib.parse import quote

    resource = sku if sku is not None else str(uuid4())
    response = {"kind": "inventory_read_admitted", "operation": operation,
                "resource_id": resource, "read_admission_id": uuid4().hex,
                "world_generation_id": uuid4().hex, "state_version": 1, "state_hash": "a" * 64}

    class StubAsyncClient:
        """僅替換結果傳輸，保留真實 Executor Response Shape Parser。"""

        def __init__(self, **kwargs):
            """固定內部 TLS 設定，且禁止環境 Proxy 影響隔離測試。"""
            assert kwargs["trust_env"] is False

        async def __aenter__(self):
            """提供單次受控測試的 AsyncClient context。"""
            return self

        async def __aexit__(self, *_):
            """離開測試用 HTTP context。"""
            return False

        async def post(self, url, *, json):
            """回傳受控 Executor metadata，禁止從 Request 選擇其他操作。"""
            assert url == "https://executor.invalid:8444/internal/v1/execute"
            assert set(json) == {"receipt_id", "raw_path_b64", "raw_body_b64"}
            return httpx.Response(200, json=response)

    monkeypatch.setattr(protected_rpc.httpx, "AsyncClient", StubAsyncClient)
    client = object.__new__(FixedExecutorMTLSClient)
    client._origin, client._tls = "https://executor.invalid:8444", object()
    path = (("/synthetic/inventory/" + quote(resource, safe="!$&'()*+,-._~:;=@"))
            if sku is not None else "/synthetic/operations/" + resource)
    args = dict(receipt_id=uuid4(), operation_id=operation,
                raw_path=path.encode("ascii"), raw_body=b"")
    assert asyncio.run(client.execute_receipt(**args)) == response
    for invalid in ({"status_code": 200}, {"body_b64": "e30="}, {"trusted_send": "enabled"},
                    {"state_version": True}, {"state_version": 0},
                    {"state_hash": "short"}, {"operation": "reserveSyntheticInventory"},
                    {"resource_id": ""}, {"resource_id": "other-resource"},
                    {"read_admission_id": "forged"}, {"world_generation_id": "not-uuid"}):
        previous = dict(response)
        response.update(invalid)
        with pytest.raises(ProtectedRpcConfigurationError, match="fixed_executor_result_binding_mismatch"):
            asyncio.run(client.execute_receipt(**args))
        response.clear()
        response.update(previous)


def test_g3b_cart_read_executor_metadata_cannot_change_operation_or_source(monkeypatch):
    """Cart GET Executor RPC 必須保留完整固定路徑、ReadAdmission 及 Snapshot 身分。"""
    from deception.security import protected_rpc

    cart_id = "cart_" + uuid4().hex
    reply = {"kind": "cart_read_admitted", "operation": "getGuestCart",
             "resource_id": cart_id, "attempt_id": None,
             "read_admission_id": uuid4().hex,
             "world_generation_id": uuid4().hex,
             "state_version": 2, "state_hash": "a" * 64}

    class MockExecutor:
        """隔離 Executor HTTP 假資料，測試用戶端是否 fail closed。"""

        def __init__(self, **kwargs):
            """驗證測試客戶端禁用環境 Proxy。"""
            assert kwargs["trust_env"] is False

        async def __aenter__(self):
            """提供 AsyncClient Context。"""
            return self

        async def __aexit__(self, *_):
            """傳播驗證例外。"""
            return False

        async def post(self, url, *, json):
            """業務 Handler、Scope 不得從 Caller RPC JSON 自選。"""
            assert url == "https://executor.invalid:8444/internal/v1/execute"
            assert set(json) == {"receipt_id", "raw_path_b64", "raw_body_b64"}
            return httpx.Response(200, json=reply)

    monkeypatch.setattr(protected_rpc.httpx, "AsyncClient", MockExecutor)
    client = object.__new__(FixedExecutorMTLSClient)
    client._origin, client._tls = "https://executor.invalid:8444", object()
    kwargs = dict(receipt_id=uuid4(), operation_id="getGuestCart",
                  raw_path=("/synthetic/carts/" + cart_id).encode(), raw_body=b"")
    assert asyncio.run(client.execute_receipt(**kwargs)) == reply
    for change in ({"attempt_id": str(uuid4())}, {"read_admission_id": "untrusted"},
                   {"world_generation_id": "untrusted"}, {"state_version": True},
                   {"state_hash": "short"}, {"resource_id": "cart_" + uuid4().hex},
                   {"operation": "getSyntheticOrder"}, {"status_code": 200},
                   {"body_b64": "e30="}):
        previous = deepcopy(reply)
        reply.update(change)
        with pytest.raises(ProtectedRpcConfigurationError, match="fixed_executor_result_binding_mismatch"):
            asyncio.run(client.execute_receipt(**kwargs))
        reply.clear()
        reply.update(previous)
    with pytest.raises(ProtectedRpcConfigurationError, match="fixed_executor_result_binding_mismatch"):
        asyncio.run(client.execute_receipt(**{**kwargs, "raw_body": b"{}"}))


def test_g3b_real_container_ci_has_explicit_isolation_and_no_sender():
    """真正容器驗收需隔離 DB／三網／四服務，不能把範本靜態測試冒充部署證據。"""
    root = Path(__file__).resolve().parents[1]
    workflow = root / ".github/workflows/g3b-four-service-isolated.yml"
    code = workflow.read_text(encoding="utf-8")
    assert "MIRAGE_G3B_CI_EXPLICIT: ephemeral-four-services-only" in code
    assert "MIRAGE_TRUSTED_SEND_ENABLE: 'false'" in code
    for network in ("mirage-g3b-gateway-net", "mirage-g3b-execution-net",
                    "mirage-g3b-database-net"):
        assert "docker network create " + network in code
    for source in ("g3b_ci_prepare.py", "g3b_ci_probe.py", "g3b-compose.yaml",
                   "postgres:17.6-alpine"):
        assert source in code
    assert "--network mirage-g3b-gateway-net" in code
    assert "--mode audit" in code
    assert "--profile g3b-isolated up --detach" in code
    assert "staging" not in code and "production" not in code
    compose = yaml.safe_load((root / "deploy/security-lab/g3b-compose.yaml").read_text(
        encoding="utf-8"))
    assert all(service["healthcheck"]["disable"] is True
               for service in compose["services"].values())


def test_g3b_ci_signed_claims_are_pinned_and_short_lived():
    """真容器 Gateway Probe 的 JWS 不能選擇部署、issuer 或無期限有效期。"""
    import importlib.util

    root = Path(__file__).resolve().parents[1]
    path = root / "deploy/security-lab/g3b_ci_probe.py"
    spec = importlib.util.spec_from_file_location("g3b_ci_probe", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    signer = Ed25519PrivateKey.generate()
    signed = module._sign(signer, fingerprint="a" * 64, session="session", mode="inventory")
    header, claims, signature = signed.split(".")
    unpack = lambda value: json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))
    assert unpack(header) == {
        "alg": "Ed25519", "kid": "old", "protocol_version": "1.1",
        "typ": "mirage-trusted-session+jwt",
    }
    payload = unpack(claims)
    assert (payload["iss"], payload["aud"], payload["environment_id"],
            payload["deployment_id"], payload["access_mode"], payload["request_fingerprint"]) == (
        "gateway", "mirage", "env", "deploy", "inventory", "a" * 64,
    )
    assert payload["exp"] - payload["iat"] == 50
    assert len(base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))) == 64


def test_g3b_ci_twenty_unsigned_routes_have_distinct_live_probes():
    """二十條 HTTPS 拒絕探針均含固定 Handler ID，並明確排除原生業務回應簽收。"""
    import importlib.util

    root = Path(__file__).resolve().parents[1]
    path = root / "deploy/security-lab/g3b_ci_probe.py"
    spec = importlib.util.spec_from_file_location("g3b_ci_probe_routes", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    cases = module._twenty_native_routes()
    assert len(cases) == 20
    assert all("{" not in module._probe_path(template) for _, _, template, _ in cases)
    assert all(operation_id for _, _, _, operation_id in cases)
    assert {platform for platform, _, _, _ in cases} == {
        "synthetic-inventory", "synthetic-carts", "medusa-native-cart",
    }


def test_g3b_ci_validator_ca_key_stays_distinct_from_server_key(tmp_path):
    """真 OpenSSL 簽發第二張 Validator Client 憑證仍必須使用 CA key，不可誤用 Server key。"""
    import importlib.util
    import subprocess
    from cryptography import x509

    root = Path(__file__).resolve().parents[1]
    path = root / "deploy/security-lab/g3b_ci_prepare.py"
    spec = importlib.util.spec_from_file_location("g3b_ci_prepare", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    (tmp_path / "secrets").mkdir()
    (tmp_path / "probe").mkdir()
    module._identity_material(tmp_path, {role: "postgresql://role.invalid/db" for role in (
        "verifier", "inventory", "cart", "validator", "runtime")})
    for directory in ("gateway-ca", "executor-ca", "validator-ca"):
        ca_certificate = x509.load_pem_x509_certificate(
            (tmp_path / directory / "ca.pem").read_bytes())
        usage = ca_certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        assert usage.key_cert_sign and usage.crl_sign
    ca = tmp_path / "validator-ca/ca.pem"
    for name in ("native-validator", "verifier-validator"):
        cert = tmp_path / "validator-ca" / (name + ".pem")
        usage = x509.load_pem_x509_certificate(cert.read_bytes()).extensions.get_extension_for_class(
            x509.KeyUsage).value
        assert usage.digital_signature and not usage.key_cert_sign
        purpose = "sslserver" if name == "native-validator" else "sslclient"
        result = subprocess.run(["openssl", "verify", "-purpose", purpose,
                                 "-CAfile", str(ca), str(cert)],
                                capture_output=True, check=True, text=True)
        assert result.stdout.strip().endswith(": OK")
    assert (tmp_path / "secrets/g3b_native_validator_server_key").read_bytes() != (
        tmp_path / "validator-ca/ca.key").read_bytes()


@pytest.mark.parametrize("action", ["cart.complete", "cart.cancel_order"])
def test_g3b_order_success_binding_distinguishes_cart_and_order_resource(action):
    """C-06／C-08 不能互換路徑身分，錯 Cart、錯 Order 與孤兒訂單皆拒絕。"""
    from deception.world.protected_native_http import _verified_order_result_matches_snapshot

    cart_id = "cart_" + uuid4().hex
    order_id = "order_" + uuid4().hex
    order = {"id": order_id, "cart_id": cart_id, "items": [], "status": "placed"}
    state = {"cart": {"id": cart_id}, "orders": {order_id: order}}
    resource = cart_id if action == "cart.complete" else order_id
    valid = dict(action=action, resource=resource, result=order, snapshot_state=state)
    assert _verified_order_result_matches_snapshot(**valid)
    wrong_resource = order_id if action == "cart.complete" else cart_id
    assert not _verified_order_result_matches_snapshot(**{**valid, "resource": wrong_resource})
    assert not _verified_order_result_matches_snapshot(**{
        **valid, "result": {**order, "cart_id": "cart_" + uuid4().hex},
    })
    assert not _verified_order_result_matches_snapshot(**{
        **valid, "snapshot_state": {**state, "orders": {}},
    })
    assert not _verified_order_result_matches_snapshot(**{
        **valid, "result": {**order, "id": "order_" + uuid4().hex},
    })


def test_g3b_cart_success_matches_exact_hashed_snapshot_independent_of_item_order():
    """C-03～C-05 不能用合法 JSON/Result Digest 把別的數量、品項或 Cart 包成 200。"""
    from deception.world.protected_native_http import _verified_cart_result_matches_snapshot

    cart_id = "cart_" + uuid4().hex
    first = {"id": "item_" + uuid4().hex, "variant_id": "v1", "sku": "sku-1",
             "unit_price": 100, "quantity": 2}
    second = {"id": "item_" + uuid4().hex, "variant_id": "v2", "sku": "sku-2",
              "unit_price": 50, "quantity": 1}
    cart = {"id": cart_id, "items": {first["id"]: first, second["id"]: second},
            "currency_code": "usd", "total": 250, "status": "active"}
    result = {**cart, "items": [second, first]}
    valid = dict(resource=cart_id, result=result, snapshot_state={"cart": cart})
    assert _verified_cart_result_matches_snapshot(**valid)
    for altered in (
            {**result, "id": "cart_" + uuid4().hex},
            {**result, "total": 249},
            {**result, "items": [second, {**first, "quantity": 4}]},
            {**result, "items": [second, second]},
            {**result, "items": [second]},
            {**result, "items": [second, {**first, "id": "item_" + uuid4().hex}]},
            {**result, "items": {first["id"]: first}},
    ):
        assert not _verified_cart_result_matches_snapshot(**{**valid, "result": altered})
    assert not _verified_cart_result_matches_snapshot(**{
        **valid, "snapshot_state": {"cart": {**cart, "items": {}}},
    })
    assert not _verified_cart_result_matches_snapshot(**{
        **valid, "resource": "cart_" + uuid4().hex,
    })
