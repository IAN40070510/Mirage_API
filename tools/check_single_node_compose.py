"""標準單機 Compose 的固定角色、停流、網路與 Release Fuse 靜態安全核對。"""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy/single-node/compose.yaml"
ROLES = {
    "verifier": "verifier",
    "inventory-executor": "executor",
    "cart-executor": "executor",
    "native-validator": "validator",
    "candidate-publisher": "publisher",
    "authorizer": "authorizer",
    "sender": "sender",
}
NETWORKS = {
    "postgres": {"database"},
    "verifier": {"ingress", "execution", "promotion", "database"},
    "inventory-executor": {"execution", "database"},
    "cart-executor": {"execution", "database"},
    "native-validator": {"execution", "database"},
    "candidate-publisher": {"promotion", "database"},
    "authorizer": {"promotion", "database"},
    "sender": {"delivery", "database"},
    "gateway": {"edge", "ingress", "delivery"},
}
ORIGINS = {
    "verifier": {
        "MIRAGE_G3B_INVENTORY_EXECUTOR_ORIGIN": "https://inventory-executor:8444",
        "MIRAGE_G3B_CART_EXECUTOR_ORIGIN": "https://cart-executor:8444",
        "MIRAGE_G3B_NATIVE_VALIDATOR_ORIGIN": "https://native-validator:8445",
        "MIRAGE_G4_PUBLISHER_ORIGIN": "https://candidate-publisher:8446",
        "MIRAGE_G4_AUTHORIZER_ORIGIN": "https://authorizer:8447",
    },
    "gateway": {
        "MIRAGE_G4_GATEWAY_VERIFIER_ORIGIN": "https://verifier:8443",
        "MIRAGE_G4_GATEWAY_SENDER_ORIGIN": "https://sender:8448",
    },
}
DSN_SECRETS = {
    "verifier": ("verifier_dsn",),
    "inventory-executor": ("inventory_dsn",),
    "cart-executor": ("cart_dsn",),
    "native-validator": ("validator_dsn",),
    "candidate-publisher": ("publisher_reader_dsn", "publisher_writer_dsn",
                            "publisher_promoter_dsn"),
    "authorizer": ("authorizer_dsn",),
    "sender": ("sender_dsn",),
    "gateway": (),
}


class SingleNodeComposeError(ValueError):
    """表示單機部署拓樸有可使角色越權、漏停流或意外公開的設定。"""


def _require(condition: bool, error: str) -> None:
    """以固定錯誤碼拒絕錯誤配置，不輸出任何 DSN 或檔案內容。"""
    if not condition:
        raise SingleNodeComposeError("single_node_compose_" + error)


def validate_single_node_compose(document: dict[str, Any]) -> None:
    """靜態拒絕不安全的單機宣告；真正啟動／SCRAM／mTLS 需另行驗證。"""
    _require(isinstance(document, dict), "document_invalid")
    _require(document.get("name") == "mirage-standard-single-node", "project_invalid")
    services = document.get("services")
    _require(isinstance(services, dict)
             and set(services) == {"postgres", "gateway", *ROLES}, "service_set_invalid")
    networks = document.get("networks")
    _require(isinstance(networks, dict) and set(networks) == {
        "edge", "ingress", "execution", "promotion", "delivery", "database",
    }, "network_set_invalid")
    for name, config in networks.items():
        _require(isinstance(config, dict)
                 and (name == "edge" or config.get("internal") is True),
                 "internal_network_required")
    secrets = document.get("secrets")
    _require(isinstance(secrets, dict) and len(secrets) >= 30, "secrets_missing")
    for name, source in secrets.items():
        _require(isinstance(source, dict) and source.get("file") == (
            "${MIRAGE_SINGLE_NODE_SECRETS_DIR:?required}/" + name),
            "secret_file_boundary_invalid")

    names = set()
    dsn_names = set()
    for service, config in services.items():
        _require(isinstance(config, dict) and set(config.get("networks", ())) == NETWORKS[service],
                 "service_network_invalid")
        _require(not any(key in config for key in (
            "privileged", "network_mode", "pid", "ipc", "uts", "devices", "cap_add",
            "extra_hosts", "userns_mode", "cgroupns_mode", "entrypoint",
        )), "unsafe_container_override_denied")
        _require(service == "gateway" or not config.get("ports"), "public_port_denied")
        mounted = config.get("secrets")
        _require(isinstance(mounted, list) and len(mounted) == len(set(mounted))
                 and set(mounted).issubset(secrets), "secret_mount_invalid")
        if service == "postgres":
            _require(config.get("environment", {}).get("POSTGRES_PASSWORD_FILE") ==
                     "/run/secrets/postgres_password", "database_secret_required")
            _require(config.get("healthcheck") is not None, "database_healthcheck_required")
            continue
        _require(config.get("restart") == "no" and config.get("read_only") is True
                 and config.get("cap_drop") == ["ALL"]
                 and "no-new-privileges:true" in config.get("security_opt", ())
                 and config.get("healthcheck") is not None,
                 "service_hardening_required")
        _require(not config.get("volumes") and config.get("command") == (
            ["python", "-m", "deception.security.single_node_gateway"]
            if service == "gateway" else
            ["python", "-m", "deception.security.protected_services"]),
            "untrusted_entrypoint_or_volume_denied")
        uid = config.get("user")
        _require(isinstance(uid, str) and uid.count(":") == 1
                 and uid.split(":")[0] == uid.split(":")[1]
                 and uid not in names, "physical_user_separation_required")
        names.add(uid)
        environment = config.get("environment")
        _require(isinstance(environment, dict)
                 and environment.get("MIRAGE_TRUSTED_SEND_ENABLE") == "false"
                 and "MIRAGE_POSTGRES_DSN" not in environment
                 and not any(key.startswith("MIRAGE_FENCE_") for key in environment),
                 "release_fuse_or_fence_invalid")
        _require(all(environment.get(key) == value for key, value in
                     ORIGINS.get(service, {}).items()), "fixed_tls_origins_required")
        _require({path.removeprefix("/run/secrets/") for key, path in environment.items()
                  if key.endswith("_DSN_FILE") and isinstance(path, str)} ==
                 set(DSN_SECRETS[service]), "physical_dsn_role_manifest_required")
        if service != "gateway":
            _require(environment.get("MIRAGE_G3B_SERVICE_ROLE") == ROLES[service]
                     and environment.get("MIRAGE_G3B_BIND_HOST") == "0.0.0.0",
                     "service_role_invalid")
        for key, path in environment.items():
            if key.endswith("_DSN_FILE"):
                _require(isinstance(path, str)
                         and path.startswith("/run/secrets/")
                         and path.removeprefix("/run/secrets/") in mounted
                         and path not in dsn_names, "role_dsn_isolation_invalid")
                dsn_names.add(path)

    for service, role in (("verifier", "ingress"), ("sender", "sender"),
                          ("gateway", "ingress")):
        labels = services[service].get("labels", {})
        _require(labels.get("mirage.restore.stop_eligible") == "true"
                 and labels.get("mirage.restore.role") == role,
                 "restore_stop_labels_required")
    for service in ("sender", "gateway"):
        env = services[service]["environment"]
        _require(env.get("MIRAGE_RESTORE_PROFILE") == "standard_single_node"
                 and env.get("MIRAGE_RESTORE_PROFILE_VERSION") == "1",
                 "standard_profile_required")
    gateway = services["gateway"]
    _require(gateway.get("profiles") == ["isolated-gateway"]
             and gateway.get("ports") == [
                 "127.0.0.1:${MIRAGE_SINGLE_NODE_GATEWAY_LOCAL_PORT:-18443}:8443",
             ] and gateway["environment"].get("MIRAGE_SINGLE_NODE_GATEWAY_MODE") ==
             "sealed_candidate_only", "gateway_candidate_exposure_denied")
    _require(not services["sender"].get("ports")
             and not services["postgres"].get("ports"), "private_data_or_sender_port_required")


def main() -> int:
    """讀取版本庫固定 Compose，安全核對後才回報候選靜態 PASS。"""
    try:
        document = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
        validate_single_node_compose(document)
    except (OSError, yaml.YAMLError, SingleNodeComposeError):
        print("single_node_compose_status=DENIED")
        return 1
    print("single_node_compose_status=STATIC_PASS trusted_send=off gateway=loopback_profile")
    return 0


if __name__ == "__main__":
    sys.exit(main())
