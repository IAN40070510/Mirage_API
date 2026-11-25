"""G3b 獨立角色啟動配置與 G4 封閉 Sender mTLS；禁止正式起送。"""

from __future__ import annotations

import base64
import binascii
import json
import os
from pathlib import Path
import re
from typing import Mapping

from fastapi import FastAPI

from mirage_validator.json_utils import reject_constant, unique_object

from .protected_rpc import (
    FixedExecutorMTLSClient, FixedNativeValidatorMTLSClient, ProtectedRpcConfigurationError,
    create_direct_verifier_app, create_fixed_executor_app, create_fixed_sender_app,
    create_native_validator_app, serve_direct_verifier_mtls, serve_fixed_executor_mtls,
    serve_fixed_sender_mtls, serve_native_validator_mtls,
)


def _required_config(config: Mapping[str, str], name: str) -> str:
    """從部署控制面取得非空明確設定，拒絕缺值及含前後空白的別名。"""
    value = config.get(name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise ProtectedRpcConfigurationError("g3b_service_configuration_incomplete")
    return value


def _secret_file(config: Mapping[str, str], name: str, *, max_bytes: int) -> str:
    """僅由角色專用 Secret Mount 讀取有大小上限的設定，禁止空秘密與超長資料。"""
    path = Path(_required_config(config, name))
    try:
        if not path.is_file() or not 0 < path.stat().st_size <= max_bytes:
            raise ProtectedRpcConfigurationError("g3b_service_secret_unavailable")
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise ProtectedRpcConfigurationError("g3b_service_secret_unavailable") from exc
    if not value:
        raise ProtectedRpcConfigurationError("g3b_service_secret_unavailable")
    return value


def _json_secret(config: Mapping[str, str], name: str) -> dict:
    """用嚴格 JSON 解析專屬設定，重複 Key、NaN 或非物件一律拒絕。"""
    try:
        data = json.loads(_secret_file(config, name, max_bytes=65536),
                          object_pairs_hook=unique_object, parse_constant=reject_constant)
    except ProtectedRpcConfigurationError:
        raise
    except (ValueError, TypeError) as exc:
        raise ProtectedRpcConfigurationError("g3b_service_secret_json_invalid") from exc
    if not isinstance(data, dict):
        raise ProtectedRpcConfigurationError("g3b_service_secret_json_invalid")
    return data


def _login_preflight(dsn: str, login: str, *, role: str, schema: str,
                     platform: str | None = None) -> None:
    """核對實體 PG Login／NOINHERIT、最低必要權限與跨角色資料表拒絕。"""
    import psycopg

    if (not re.fullmatch(r"[a-z][a-z0-9_]{2,62}", login)
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", schema)):
        raise ProtectedRpcConfigurationError("g3b_service_login_invalid")
    if role not in {"verifier", "executor", "validator", "sender"}:
        raise ProtectedRpcConfigurationError("g3b_service_unapproved_role")
    required = (("ingress_receipts", "INSERT"), ("ingress_receipts", "SELECT"),
                ("replay_entries", "INSERT"), ("trusted_key_revocations", "SELECT"),
                ("protected_http_operation_bindings", "INSERT")) if role == "verifier" else ((
                ("ingress_receipts", "SELECT"), ("protected_http_operation_bindings", "SELECT"),
                ("session_heads", "SELECT"), ("session_world_bindings", "SELECT"),
                ("generation_controls", "SELECT"), ("trusted_key_revocations", "SELECT"),
                ("world_snapshots", "SELECT"), ("world_operations", "SELECT"),
                ("read_admissions", "SELECT"),
                ("protected_world_read_sources", "SELECT"),
                ("protected_world_commit_sources", "SELECT"),
                ("protected_world_rejection_sources", "SELECT"),
                ("read_admissions", "INSERT"), ("protected_world_read_sources", "INSERT"),
                ("protected_world_rejection_sources", "INSERT"),
                ("world_events", "INSERT"), ("world_operations", "INSERT"),
                ("world_commit_receipts", "INSERT"), ("protected_world_commit_sources", "INSERT"),
                ("session_heads", "UPDATE"), ("session_world_bindings", "UPDATE"),
                ("generation_controls", "UPDATE"), ("world_snapshots", "UPDATE"))
                if role == "executor" else (
                ("protected_medusa_rejection_sources", "SELECT"),
                ("protected_world_rejection_sources", "SELECT"),
                ("world_operations", "SELECT"),
                ("world_commit_receipts", "SELECT"),
                ("protected_world_commit_sources", "SELECT"),
                ("synthetic_resources", "SELECT"),
                ("world_snapshots", "SELECT"),
                ("ingress_receipts", "SELECT"), ("protected_http_operation_bindings", "SELECT"),
                ("protected_world_read_sources", "SELECT"), ("read_admissions", "SELECT"),
                ("session_heads", "SELECT"), ("session_world_bindings", "SELECT"),
                ("generation_controls", "SELECT"), ("trusted_key_revocations", "SELECT")))
    if role == "sender":
        required = (("response_admissions", "SELECT"),
                    ("protected_authorized_http_snapshots", "SELECT"),
                    ("protected_grant_bindings", "SELECT"),
                    ("protected_local_restore_events", "SELECT"),
                    ("protected_send_leases", "INSERT"),
                    ("protected_send_leases", "SELECT"),
                    ("response_audit", "INSERT"))
    if role == "validator":
        # C-01 必須可用獨立實體唯讀 Login 核對不可變 Creator→Derived Lineage，
        # M-03 還需唯讀比對原子保存的 Native Context，不得借用 Cart 寫入權。
        required += (("protected_cart_creations", "SELECT"),
                     ("guest_cart_creations", "SELECT"),
                     ("native_response_contexts", "SELECT"))
    forbidden = (("world_operations", "INSERT"), ("protected_world_commit_sources", "SELECT"),
                 ("protected_candidate_promotions", "INSERT")) if role == "verifier" else (
                 ("ingress_receipts", "INSERT"),
                 ("protected_http_operation_bindings", "INSERT"),
                 ("protected_candidate_promotions", "INSERT"),
                 ("protected_medusa_rejection_sources", "INSERT"))
    if role == "sender":
        forbidden = (("response_admissions", "UPDATE"),
                     ("response_admissions", "INSERT"),
                     ("response_admissions", "DELETE"),
                     ("protected_send_leases", "UPDATE"),
                     ("protected_send_leases", "DELETE"),
                     ("protected_authorized_http_snapshots", "UPDATE"),
                     ("protected_authorized_http_snapshots", "INSERT"),
                     ("protected_grant_bindings", "INSERT"),
                     ("protected_local_restore_events", "INSERT"),
                     ("protected_local_restore_events", "UPDATE"),
                     ("protected_local_restore_events", "DELETE"),
                     ("response_audit", "UPDATE"),
                     ("response_audit", "DELETE"),
                     ("ingress_receipts", "INSERT"),
                     ("protected_http_operation_bindings", "INSERT"),
                     ("protected_candidate_promotions", "INSERT"),
                     ("world_operations", "INSERT"),
                     ("world_snapshots", "UPDATE"),
                     ("session_heads", "UPDATE"),
                     ("generation_controls", "UPDATE"))
    if role == "executor" and platform == "synthetic-carts":
        required += (("protected_cart_creations", "INSERT"),
                     ("protected_cart_creations", "SELECT"),
                     ("synthetic_resources", "SELECT"),
                     ("synthetic_resources", "INSERT"),
                     ("guest_cart_creations", "SELECT"),
                     ("guest_cart_creations", "INSERT"),
                     ("native_response_contexts", "INSERT"),
                     ("world_initializations", "INSERT"),
                     ("protected_medusa_rejection_sources", "SELECT"),
                     ("protected_medusa_rejection_sources", "INSERT"),
                     ("session_heads", "INSERT"),
                     ("session_world_bindings", "INSERT"),
                     ("generation_controls", "INSERT"),
                     ("world_snapshots", "INSERT"))
        # Cart Executor 是唯一允許建立 Medusa 400/404 來源的執行身分；
        # Inventory Executor 仍必須拒絕同一資料表的 INSERT。
        forbidden = tuple((table, privilege) for table, privilege in forbidden
                          if (table, privilege) != ("protected_medusa_rejection_sources", "INSERT"))
    try:
        with psycopg.connect(dsn, connect_timeout=5) as connection:
            identity = connection.execute(
                """SELECT session_user,current_user,r.rolinherit,r.rolsuper,r.rolbypassrls,
                          r.rolcreaterole,r.rolcreatedb,r.rolreplication
                   FROM pg_roles r WHERE r.rolname=session_user"""
            ).fetchone()
            if identity != (login, login, False, False, False, False, False, False):
                raise ProtectedRpcConfigurationError("g3b_service_physical_login_denied")
            if connection.execute("SELECT current_schema()").fetchone() != (schema,):
                raise ProtectedRpcConfigurationError("g3b_service_schema_mismatch")
            if connection.execute("SELECT has_schema_privilege(%s,'CREATE')", (
                    schema,)).fetchone() != (False,):
                raise ProtectedRpcConfigurationError("g3b_service_schema_create_denied")
            memberships = connection.execute(
                """SELECT count(*) FROM pg_auth_members m
                   JOIN pg_roles r ON r.oid=m.member WHERE r.rolname=session_user"""
            ).fetchone()[0]
            if memberships:
                raise ProtectedRpcConfigurationError("g3b_service_role_membership_denied")
            for table, privilege in required:
                permitted = connection.execute("SELECT has_table_privilege(%s,%s)",
                                               (table, privilege)).fetchone()[0]
                if permitted is not True:
                    raise ProtectedRpcConfigurationError("g3b_service_required_acl_missing")
            # SELECT ... FOR SHARE OF resource needs one UPDATE column in PG17,
            # but never table-wide UPDATE of session/resource identity.
            if role == "executor" and platform == "synthetic-carts" and connection.execute(
                    "SELECT has_column_privilege('synthetic_resources','resource_kind','UPDATE'),"
                    "has_table_privilege('synthetic_resources','UPDATE')"
            ).fetchone() != (True, False):
                raise ProtectedRpcConfigurationError("g3b_service_resource_lock_acl_invalid")
            for table, privilege in forbidden:
                permitted = connection.execute("SELECT has_table_privilege(%s,%s)",
                                               (table, privilege)).fetchone()[0]
                if permitted is not False:
                    raise ProtectedRpcConfigurationError("g3b_service_forbidden_acl_detected")
            if role == "sender":
                if connection.execute(
                        "SELECT has_column_privilege(%s,%s,'UPDATE')",
                        ("response_admissions", "state"),
                ).fetchone() != (True,):
                    raise ProtectedRpcConfigurationError("g4_sender_state_acl_missing")
                for column in ("admission", "claim_owner", "transmission_deadline"):
                    if connection.execute(
                            "SELECT has_column_privilege(%s,%s,'UPDATE')",
                            ("response_admissions", column),
                    ).fetchone() != (False,):
                        raise ProtectedRpcConfigurationError("g4_sender_excessive_acl_detected")
            if role == "validator":
                for table in (
                        "protected_medusa_rejection_sources", "ingress_receipts",
                        "protected_world_rejection_sources", "world_operations",
                        "world_commit_receipts", "protected_world_commit_sources",
                        "world_snapshots", "world_initializations", "synthetic_resources",
                        "native_response_contexts",
                        "protected_cart_creations", "guest_cart_creations",
                        "protected_http_operation_bindings", "protected_world_read_sources",
                        "read_admissions", "session_heads", "session_world_bindings",
                        "generation_controls", "trusted_key_revocations", "world_operations",
                        "protected_candidate_promotions"):
                    if connection.execute(
                            "SELECT has_table_privilege(%s,%s)",
                            (table, "INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER"),
                    ).fetchone() != (False,):
                        raise ProtectedRpcConfigurationError("g3b_service_readonly_acl_violated")
            if role == "executor" and connection.execute(
                    "SELECT has_function_privilege(%s,'EXECUTE')",
                    (schema + ".protected_lock_reference(text,jsonb)",),
            ).fetchone() != (True,):
                raise ProtectedRpcConfigurationError("g3b_service_lock_acl_missing")
    except psycopg.Error as exc:
        raise ProtectedRpcConfigurationError("g3b_service_database_preflight_unverifiable") from exc


def _verifier_key_registry(config: Mapping[str, str]):
    """僅接受部署端固定 issuer 的 Ed25519 公鑰清單，不接受 Token 自選 key。"""
    from .trusted_session import TrustedKeyRegistry

    issuer = _required_config(config, "MIRAGE_G3B_EXPECTED_ISSUER")
    keys = _json_secret(config, "MIRAGE_G3B_VERIFIER_KEYS_FILE")
    if not 1 <= len(keys) <= 16:
        raise ProtectedRpcConfigurationError("g3b_service_key_registry_invalid")
    trusted = {}
    for kid, encoded in keys.items():
        if (not isinstance(kid, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", kid)
                or not isinstance(encoded, str) or not encoded.isascii()):
            raise ProtectedRpcConfigurationError("g3b_service_key_registry_invalid")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ProtectedRpcConfigurationError("g3b_service_key_registry_invalid") from exc
        if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != encoded:
            raise ProtectedRpcConfigurationError("g3b_service_key_registry_invalid")
        trusted[(issuer, kid)] = raw
    return TrustedKeyRegistry(trusted)


def _tls_path(config: Mapping[str, str], name: str) -> Path:
    """由角色明確的唯讀 Mount 取得憑證路徑，實際 TLS 會在啟動前驗證。"""
    return Path(_required_config(config, name))


def create_verifier_service(config: Mapping[str, str]) -> FastAPI:
    """使用唯一 Verifier Login 與兩個不共用的 TLS 身分組裝原始 HTTP 入口。

    Gateway 原始 HTTP 由 mTLS 直送此 App；只有 Receipt／Operation 與內部
    Executor 結果，不提供 Trusted Send 或公開成功封套。啟動失敗不得回退 Runtime。
    """
    from .key_revocation import PostgresTrustedKeyRevocations
    from .trusted_session import TrustedSessionVerifier
    from deception.world.postgres_replay import PostgresReplayStore

    if (config.get("MIRAGE_G3B_EXECUTOR_DSN_FILE")
            or config.get("MIRAGE_G3B_VALIDATOR_DSN_FILE")
            or config.get("MIRAGE_G4_SENDER_DSN_FILE")
            or config.get("MIRAGE_POSTGRES_DSN")):
        raise ProtectedRpcConfigurationError("g3b_service_cross_role_secret_denied")
    dsn = _secret_file(config, "MIRAGE_G3B_VERIFIER_DSN_FILE", max_bytes=4096)
    login = _required_config(config, "MIRAGE_G3B_VERIFIER_LOGIN")
    _login_preflight(dsn, login, role="verifier",
                     schema=_required_config(config, "MIRAGE_G3B_WORLD_SCHEMA"))
    environment = _required_config(config, "MIRAGE_G3B_ENVIRONMENT_ID")
    deployment = _required_config(config, "MIRAGE_G3B_DEPLOYMENT_ID")
    checker = TrustedSessionVerifier(
        keys=_verifier_key_registry(config), replay_store=PostgresReplayStore(dsn),
        key_revocations=PostgresTrustedKeyRevocations(
            dsn, environment_id=environment, deployment_id=deployment),
    )
    clients = {}
    for platform, key in (("synthetic-inventory", "MIRAGE_G3B_INVENTORY_EXECUTOR_ORIGIN"),
                          ("synthetic-carts", "MIRAGE_G3B_CART_EXECUTOR_ORIGIN"),
                          ("medusa-native-cart", "MIRAGE_G3B_CART_EXECUTOR_ORIGIN")):
        clients[platform] = FixedExecutorMTLSClient(
            origin=_required_config(config, key),
            client_cert=_tls_path(config, "MIRAGE_G3B_VERIFIER_CLIENT_CERT_FILE"),
            client_key=_tls_path(config, "MIRAGE_G3B_VERIFIER_CLIENT_KEY_FILE"),
            server_ca=_tls_path(config, "MIRAGE_G3B_EXECUTOR_SERVER_CA_FILE"),
        )
    validator_client = FixedNativeValidatorMTLSClient(
        origin=_required_config(config, "MIRAGE_G3B_NATIVE_VALIDATOR_ORIGIN"),
        client_cert=_tls_path(config, "MIRAGE_G3B_VERIFIER_VALIDATOR_CERT_FILE"),
        client_key=_tls_path(config, "MIRAGE_G3B_VERIFIER_VALIDATOR_KEY_FILE"),
        server_ca=_tls_path(config, "MIRAGE_G3B_NATIVE_VALIDATOR_SERVER_CA_FILE"),
    )
    return create_direct_verifier_app(
        verifier=checker, postgres_dsn=dsn,
        environment_id=environment, deployment_id=deployment,
        expected_issuer=_required_config(config, "MIRAGE_G3B_EXPECTED_ISSUER"),
        expected_audience=_required_config(config, "MIRAGE_G3B_EXPECTED_AUDIENCE"),
        executor_clients=clients, native_validator_client=validator_client,
    )


def create_executor_service(config: Mapping[str, str]) -> FastAPI:
    """以單一核准平台與專屬 Executor SCRAM 身分掛固定 Handler，不接 Runtime 指令。"""
    from deception.domains.ecommerce.carts import SyntheticCarts
    from deception.domains.ecommerce.cart_http import CART_ERRORS
    from deception.domains.ecommerce.inventory import SyntheticInventory
    from deception.domains.ecommerce.inventory_http import ERROR_CODES
    from deception.world.protected_world import PostgresProtectedWorldExecutor

    if (config.get("MIRAGE_G3B_VERIFIER_DSN_FILE")
            or config.get("MIRAGE_G3B_VALIDATOR_DSN_FILE")
            or config.get("MIRAGE_G4_SENDER_DSN_FILE")
            or config.get("MIRAGE_POSTGRES_DSN")):
        raise ProtectedRpcConfigurationError("g3b_service_cross_role_secret_denied")
    dsn = _secret_file(config, "MIRAGE_G3B_EXECUTOR_DSN_FILE", max_bytes=4096)
    login = _required_config(config, "MIRAGE_G3B_EXECUTOR_LOGIN")
    platform = _required_config(config, "MIRAGE_G3B_EXECUTOR_PLATFORM")
    if platform not in {"synthetic-inventory", "synthetic-carts"}:
        raise ProtectedRpcConfigurationError("g3b_service_unapproved_platform")
    _login_preflight(dsn, login, role="executor",
                     schema=_required_config(config, "MIRAGE_G3B_WORLD_SCHEMA"), platform=platform)
    state = None
    publishable = None
    if platform == "synthetic-carts":
        state = _json_secret(config, "MIRAGE_G3B_CART_STATE_FILE")
        if set(state) not in ({"catalog", "inventory"}, {"catalog", "inventory", "native_context"}):
            raise ProtectedRpcConfigurationError("g3b_service_cart_state_invalid")
        if not isinstance(state["catalog"], dict) or not isinstance(state["inventory"], dict):
            raise ProtectedRpcConfigurationError("g3b_service_cart_state_invalid")
        if config.get("MIRAGE_G3B_MEDUSA_PUBLISHABLE_KEY_FILE"):
            publishable = _secret_file(config, "MIRAGE_G3B_MEDUSA_PUBLISHABLE_KEY_FILE", max_bytes=256)
    elif config.get("MIRAGE_G3B_CART_STATE_FILE") or config.get("MIRAGE_G3B_MEDUSA_PUBLISHABLE_KEY_FILE"):
        raise ProtectedRpcConfigurationError("g3b_service_cross_platform_secret_denied")
    store = SyntheticInventory(dsn) if platform == "synthetic-inventory" else SyntheticCarts(dsn)
    executor = PostgresProtectedWorldExecutor(
        dsn, expected_login=login, world_store=store,
        cart_initial_state=state, medusa_publishable_key=publishable,
        rejection_templates={code: ("synthetic-inventory-1" if platform == "synthetic-inventory"
                                    else "synthetic-carts-1")
                             for code in (ERROR_CODES if platform == "synthetic-inventory" else CART_ERRORS)},
    )
    return create_fixed_executor_app(executor=executor)


def create_native_validator_service(config: Mapping[str, str]) -> FastAPI:
    """以只讀 Validator 物理 Login 啟動 Medusa 來源重建，不接受 Executor／Runtime DSN。"""
    from deception.world.protected_native_http import PostgresProtectedNativeProjector

    if (config.get("MIRAGE_POSTGRES_DSN") or config.get("MIRAGE_G3B_VERIFIER_DSN_FILE")
            or config.get("MIRAGE_G3B_EXECUTOR_DSN_FILE")
            or config.get("MIRAGE_G4_SENDER_DSN_FILE")):
        raise ProtectedRpcConfigurationError("g3b_service_cross_role_secret_denied")
    dsn = _secret_file(config, "MIRAGE_G3B_VALIDATOR_DSN_FILE", max_bytes=4096)
    login = _required_config(config, "MIRAGE_G3B_VALIDATOR_LOGIN")
    _login_preflight(dsn, login, role="validator",
                     schema=_required_config(config, "MIRAGE_G3B_WORLD_SCHEMA"))
    # 只使用部署者固定的來源路徑，實際載入時仍依官方固定 SHA-256 驗證。
    # 未掛來源的既存實驗服務不得自動宣稱可投影原生 Medusa 成功回應。
    domains = config.get("MIRAGE_DOMAINS_DIR")
    medusa_source = (Path(domains) / "ecommerce/inputs/sources/medusa/openapi.yaml"
                     if isinstance(domains, str) and domains else None)
    return create_native_validator_app(
        projector=PostgresProtectedNativeProjector(
            dsn, expected_login=login, medusa_source=medusa_source,
        ),
    )


def create_sender_service(config: Mapping[str, str]) -> FastAPI:
    """核對 D-74 部署 Profile，再以獨立 Sender Login 建立封閉的 G4 服務。"""
    from deception.world.protected_send import PostgresProtectedSender
    from deception.security.restore_profile import load_restore_profile

    if any(config.get(key) for key in (
            "MIRAGE_POSTGRES_DSN", "MIRAGE_G3B_VERIFIER_DSN_FILE",
            "MIRAGE_G3B_EXECUTOR_DSN_FILE", "MIRAGE_G3B_VALIDATOR_DSN_FILE")):
        raise ProtectedRpcConfigurationError("g3b_service_cross_role_secret_denied")
    if config.get("MIRAGE_TRUSTED_SEND_ENABLE") not in (None, "false"):
        raise ProtectedRpcConfigurationError("g3b_service_unsafe_runtime_configuration")
    # Profile 只標示部署契約，絕不能藉此取消 Sender 的安全 Release Fuse。
    load_restore_profile(config)
    dsn = _secret_file(config, "MIRAGE_G4_SENDER_DSN_FILE", max_bytes=4096)
    login = _required_config(config, "MIRAGE_G4_SENDER_LOGIN")
    _login_preflight(dsn, login, role="sender",
                     schema=_required_config(config, "MIRAGE_G3B_WORLD_SCHEMA"))
    return create_fixed_sender_app(
        sender=PostgresProtectedSender(dsn, expected_login=login),
    )


def from_environment() -> None:
    """專用 CLI 僅選一個固定角色，真 mTLS Listener 與資料庫前置檢查不能跳過。"""
    config = os.environ
    if (config.get("MIRAGE_TRUSTED_SEND_ENABLE") not in (None, "false")
            or sum(bool(config.get(name)) for name in (
                "MIRAGE_G3B_EXECUTOR_DSN_FILE", "MIRAGE_G3B_VERIFIER_DSN_FILE",
                "MIRAGE_G3B_VALIDATOR_DSN_FILE", "MIRAGE_G4_SENDER_DSN_FILE")) > 1):
        raise ProtectedRpcConfigurationError("g3b_service_unsafe_runtime_configuration")
    role = _required_config(config, "MIRAGE_G3B_SERVICE_ROLE")
    raw_port = _required_config(config, "MIRAGE_G3B_BIND_PORT")
    if not raw_port.isascii() or not raw_port.isdecimal() or not 1 <= int(raw_port) <= 65535:
        raise ProtectedRpcConfigurationError("g3b_service_port_invalid")
    host = _required_config(config, "MIRAGE_G3B_BIND_HOST")
    if role == "verifier":
        app = create_verifier_service(config)
        serve_direct_verifier_mtls(
            app=app, host=host, port=int(raw_port),
            server_cert=_tls_path(config, "MIRAGE_G3B_VERIFIER_SERVER_CERT_FILE"),
            server_key=_tls_path(config, "MIRAGE_G3B_VERIFIER_SERVER_KEY_FILE"),
            client_ca=_tls_path(config, "MIRAGE_G3B_GATEWAY_CLIENT_CA_FILE"),
        )
    elif role == "executor":
        app = create_executor_service(config)
        serve_fixed_executor_mtls(
            app=app, host=host, port=int(raw_port),
            server_cert=_tls_path(config, "MIRAGE_G3B_EXECUTOR_SERVER_CERT_FILE"),
            server_key=_tls_path(config, "MIRAGE_G3B_EXECUTOR_SERVER_KEY_FILE"),
            verifier_client_ca=_tls_path(config, "MIRAGE_G3B_VERIFIER_CLIENT_CA_FILE"),
        )
    elif role == "validator":
        app = create_native_validator_service(config)
        serve_native_validator_mtls(
            app=app, host=host, port=int(raw_port),
            server_cert=_tls_path(config, "MIRAGE_G3B_VALIDATOR_SERVER_CERT_FILE"),
            server_key=_tls_path(config, "MIRAGE_G3B_VALIDATOR_SERVER_KEY_FILE"),
            verifier_client_ca=_tls_path(config, "MIRAGE_G3B_VALIDATOR_CLIENT_CA_FILE"),
        )
    elif role == "sender":
        app = create_sender_service(config)
        serve_fixed_sender_mtls(
            app=app, host=host, port=int(raw_port),
            server_cert=_tls_path(config, "MIRAGE_G4_SENDER_SERVER_CERT_FILE"),
            server_key=_tls_path(config, "MIRAGE_G4_SENDER_SERVER_KEY_FILE"),
            sender_client_ca=_tls_path(config, "MIRAGE_G4_SENDER_CLIENT_CA_FILE"),
        )
    else:
        raise ProtectedRpcConfigurationError("g3b_service_unapproved_role")


if __name__ == "__main__":
    from_environment()
