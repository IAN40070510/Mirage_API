"""G3b 正式角色組裝只接受專用 Secret／固定路由，不允許共用 Runtime 權限。"""

import base64
import json
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deception.security.protected_rpc import (
    ProtectedRpcConfigurationError, create_native_validator_app,
)
from deception.security.protected_services import (
    _json_secret, _verifier_key_registry, create_executor_service,
    create_native_validator_service,
    create_verifier_service, from_environment,
)
from deception.world.protected_grant import ProtectedGrantError
from deception.world.protected_native_http import (
    PostgresProtectedNativeProjector, fixed_medusa_rejection_bytes,
)


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
