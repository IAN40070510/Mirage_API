"""正式標準單機 Docker Compose 與隔離候選 Gateway 的失敗封閉配置測試。"""

from copy import deepcopy
from pathlib import Path

from fastapi.testclient import TestClient
import pytest
import yaml

from deception.security import single_node_gateway
from deception.security.protected_rpc import ProtectedRpcConfigurationError
from deception.security.single_node_gateway import create_sealed_compose_gateway
from tools.check_single_node_compose import (
    COMPOSE, SingleNodeComposeError, validate_single_node_compose,
)
from test_protected_rpc_mtls import _issue_mtls_certificates


def _compose() -> dict:
    """從待提交的真正 YAML 讀取完整原始拓樸供反向破壞測試。"""
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


def test_standard_single_node_compose_accepts_complete_sealed_topology():
    """八個角色與 PostgreSQL、全部 Secret、六網段的固定拓樸通過靜態核對。"""
    document = _compose()
    validate_single_node_compose(document)
    assert len(document["services"]) == 9
    assert set(document["services"]["gateway"]["networks"]) == {
        "edge", "ingress", "delivery",
    }
    assert "MIRAGE_FENCE_AUTHORITY_DSN" not in str(document)


@pytest.mark.parametrize("mutation", [
    "public_gateway", "sender_port", "db_port", "remove_gateway_profile",
    "trusted_send", "remove_sender_label", "sender_restart", "db_on_edge",
    "gateway_gets_sender_dsn", "verifier_wrong_dsn", "fence_config",
    "world_network_external", "role_uid_reused", "unmounted_secret",
    "publisher_missing", "gateway_unsealed", "missing_healthcheck",
    "gateway_wrong_verifier_origin", "verifier_wrong_executor_origin",
    "raw_db_admin_dsn", "privileged_sender", "host_network_gateway",
    "gateway_extra_volume", "sender_unapproved_entrypoint",
])
def test_single_node_compose_fails_closed_for_unsafe_mutations(mutation):
    """逐項篡改對外暴露、角色分權、停流標籤與 FUSE 皆不能通過檢查。"""
    document = deepcopy(_compose())
    services = document["services"]
    if mutation == "public_gateway":
        services["gateway"]["ports"] = ["0.0.0.0:443:8443"]
    elif mutation == "sender_port":
        services["sender"]["ports"] = ["8448:8448"]
    elif mutation == "db_port":
        services["postgres"]["ports"] = ["5432:5432"]
    elif mutation == "remove_gateway_profile":
        services["gateway"].pop("profiles")
    elif mutation == "trusted_send":
        services["sender"]["environment"]["MIRAGE_TRUSTED_SEND_ENABLE"] = "true"
    elif mutation == "remove_sender_label":
        services["sender"]["labels"].pop("mirage.restore.stop_eligible")
    elif mutation == "sender_restart":
        services["sender"]["restart"] = "unless-stopped"
    elif mutation == "db_on_edge":
        services["postgres"]["networks"].append("edge")
    elif mutation == "gateway_gets_sender_dsn":
        services["gateway"]["secrets"].append("sender_dsn")
        services["gateway"]["environment"]["MIRAGE_G4_SENDER_DSN_FILE"] = (
            "/run/secrets/sender_dsn")
    elif mutation == "verifier_wrong_dsn":
        services["verifier"]["environment"]["MIRAGE_G3B_VERIFIER_DSN_FILE"] = (
            "/run/secrets/sender_dsn")
    elif mutation == "fence_config":
        services["sender"]["environment"]["MIRAGE_FENCE_AUTHORITY_DSN"] = "bad"
    elif mutation == "world_network_external":
        document["networks"]["database"].pop("internal")
    elif mutation == "role_uid_reused":
        services["sender"]["user"] = services["verifier"]["user"]
    elif mutation == "unmounted_secret":
        services["sender"]["secrets"] = []
    elif mutation == "publisher_missing":
        services.pop("candidate-publisher")
    elif mutation == "gateway_unsealed":
        services["gateway"]["environment"]["MIRAGE_SINGLE_NODE_GATEWAY_MODE"] = "public"
    elif mutation == "missing_healthcheck":
        services["verifier"].pop("healthcheck")
    elif mutation == "gateway_wrong_verifier_origin":
        services["gateway"]["environment"]["MIRAGE_G4_GATEWAY_VERIFIER_ORIGIN"] = (
            "https://attacker.invalid:8443")
    elif mutation == "verifier_wrong_executor_origin":
        services["verifier"]["environment"]["MIRAGE_G3B_INVENTORY_EXECUTOR_ORIGIN"] = (
            "https://attacker.invalid:8444")
    elif mutation == "raw_db_admin_dsn":
        services["verifier"]["environment"]["MIRAGE_POSTGRES_DSN"] = "secret-placeholder"
    elif mutation == "privileged_sender":
        services["sender"]["privileged"] = True
    elif mutation == "host_network_gateway":
        services["gateway"]["network_mode"] = "host"
    elif mutation == "gateway_extra_volume":
        services["gateway"]["volumes"] = ["/var/run/docker.sock:/var/run/docker.sock"]
    elif mutation == "sender_unapproved_entrypoint":
        services["sender"]["entrypoint"] = ["sh"]
    with pytest.raises(SingleNodeComposeError):
        validate_single_node_compose(document)


def _gateway_config(tmp_path: Path) -> dict[str, str]:
    """各自生成短期真 X.509 身分和三組不同 CA，絕不存固定測試私鑰。"""
    material = {}
    for role in ("public", "verifier", "sender"):
        folder = tmp_path / role
        folder.mkdir()
        ca, server_cert, server_key, client_cert, client_key = _issue_mtls_certificates(folder)
        material[role] = (ca, server_cert, server_key, client_cert, client_key)
    return {
        "MIRAGE_TRUSTED_SEND_ENABLE": "false",
        "MIRAGE_RESTORE_PROFILE": "standard_single_node",
        "MIRAGE_RESTORE_PROFILE_VERSION": "1",
        "MIRAGE_SINGLE_NODE_GATEWAY_MODE": "sealed_candidate_only",
        "MIRAGE_SINGLE_NODE_GATEWAY_BIND_HOST": "0.0.0.0",
        "MIRAGE_SINGLE_NODE_GATEWAY_BIND_PORT": "8443",
        "MIRAGE_G4_GATEWAY_SERVER_CERT_FILE": str(material["public"][1]),
        "MIRAGE_G4_GATEWAY_SERVER_KEY_FILE": str(material["public"][2]),
        "MIRAGE_G4_GATEWAY_VERIFIER_ORIGIN": "https://verifier:8443",
        "MIRAGE_G4_GATEWAY_VERIFIER_CLIENT_CERT_FILE": str(material["verifier"][3]),
        "MIRAGE_G4_GATEWAY_VERIFIER_CLIENT_KEY_FILE": str(material["verifier"][4]),
        "MIRAGE_G4_GATEWAY_VERIFIER_SERVER_CA_FILE": str(material["verifier"][0]),
        "MIRAGE_G4_GATEWAY_SENDER_ORIGIN": "https://sender:8448",
        "MIRAGE_G4_GATEWAY_SENDER_CLIENT_CERT_FILE": str(material["sender"][3]),
        "MIRAGE_G4_GATEWAY_SENDER_CLIENT_KEY_FILE": str(material["sender"][4]),
        "MIRAGE_G4_GATEWAY_SENDER_SERVER_CA_FILE": str(material["sender"][0]),
    }


def test_single_node_gateway_requires_sealed_profile_and_owns_no_db_secret(tmp_path):
    """完整標準模式及隔離真憑證才能組裝且 readiness 不宣稱正式發送。"""
    config = _gateway_config(tmp_path)
    app = create_sealed_compose_gateway(config)
    with TestClient(app) as client:
        assert client.get("/internal/ready").json() == {
            "control_plane": "gateway-native-proxy-candidate", "trusted_send": "disabled",
        }
    for key, value in (
        ("MIRAGE_TRUSTED_SEND_ENABLE", "true"),
        ("MIRAGE_SINGLE_NODE_GATEWAY_MODE", "public"),
        ("MIRAGE_RESTORE_PROFILE", "external_fence"),
        ("MIRAGE_G4_SENDER_DSN_FILE", "/run/secrets/sender_dsn"),
    ):
        unsafe = {**config, key: value}
        with pytest.raises(ProtectedRpcConfigurationError):
            create_sealed_compose_gateway(unsafe)


def test_single_node_gateway_denies_copied_identity_and_world_readable_keys(tmp_path):
    """就算改名複製相同 X.509 公鑰或放寬私鑰權限都拒絕啟動。"""
    config = _gateway_config(tmp_path)
    verifier_cert = Path(config["MIRAGE_G4_GATEWAY_VERIFIER_CLIENT_CERT_FILE"])
    sender_cert = Path(config["MIRAGE_G4_GATEWAY_SENDER_CLIENT_CERT_FILE"])
    sender_cert.write_bytes(verifier_cert.read_bytes())
    with pytest.raises(ProtectedRpcConfigurationError, match="tls_identity_reuse_denied"):
        create_sealed_compose_gateway(config)
    # 使用全新材料重做世界可讀的密鑰測試；勿重用被修改的 X.509。
    second = tmp_path / "second"
    second.mkdir()
    safe = _gateway_config(second)
    key = Path(safe["MIRAGE_G4_GATEWAY_SENDER_CLIENT_KEY_FILE"])
    key.chmod(0o644)
    with pytest.raises(ProtectedRpcConfigurationError, match="tls_identity_reuse_denied"):
        create_sealed_compose_gateway(safe)


def test_single_node_gateway_denies_copied_mtls_trust_authority(tmp_path):
    """不同 Secret 名稱若裝入相同 CA 公鑰，Gateway 不能合併 Verifier／Sender 信任鏈。"""
    config = _gateway_config(tmp_path)
    sender_root = Path(config["MIRAGE_G4_GATEWAY_SENDER_SERVER_CA_FILE"])
    verifier_root = Path(config["MIRAGE_G4_GATEWAY_VERIFIER_SERVER_CA_FILE"])
    assert sender_root != verifier_root
    sender_root.write_bytes(verifier_root.read_bytes())
    with pytest.raises(ProtectedRpcConfigurationError,
                       match="protected_rpc_mtls_ca_identity_reuse_denied"):
        create_sealed_compose_gateway(config)


def test_gateway_container_start_checks_bind_before_any_server_run(tmp_path, monkeypatch):
    """限制容器固定 bind；憑證配置通過後才呼叫 Uvicorn，無實際開 socket。"""
    config = _gateway_config(tmp_path)
    for key, value in config.items():
        monkeypatch.setenv(key, value)
    started = []

    def fake_run(self):
        """擷取已驗證 Uvicorn 設定，不開啟任何實體 Listener。"""
        started.append(self.config)

    monkeypatch.setattr(single_node_gateway.uvicorn.Server, "run", fake_run)
    single_node_gateway.from_environment()
    assert len(started) == 1
    assert started[0].host == "0.0.0.0" and started[0].port == 8443
    monkeypatch.setenv("MIRAGE_SINGLE_NODE_GATEWAY_BIND_HOST", "192.0.2.1")
    with pytest.raises(ProtectedRpcConfigurationError, match="fixed_container_bind_required"):
        single_node_gateway.from_environment()
    assert len(started) == 1
