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
    ProtectedRpcConfigurationError, create_native_validator_app,
)
from deception.security.protected_services import (
    _json_secret, _login_preflight, _verifier_key_registry, create_executor_service,
    create_native_validator_service,
    create_verifier_service, from_environment,
)
from deception.world.protected_grant import ProtectedGrantError
from deception.world.protected_native_http import (
    PostgresProtectedNativeProjector, fixed_medusa_rejection_bytes,
)
from deception.world.transmission import response_hashes


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
