"""只在一次性 Docker CI 資料庫建立四服務 SCRAM、mTLS 身分與 Compose Secret。"""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import time
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
import yaml

from deception.domains.ecommerce.carts import SyntheticCarts
from deception.domains.ecommerce.inventory import SyntheticInventory
from deception.world.migrations import apply_migrations
from deception.world.protected_world import PostgresProtectedWorldExecutor
from deception.world.session import SessionBinding


ROLES = {
    "verifier": "mirage_g3b_ci_verifier",
    "inventory": "mirage_g3b_ci_inventory",
    "cart": "mirage_g3b_ci_cart",
    "validator": "mirage_g3b_ci_validator",
    "runtime": "mirage_g3b_ci_runtime",
}


def _openssl(*args: str) -> None:
    """以不輸出私鑰的形式簽發 CI 短期 CA／End Entity 憑證，遇到錯誤立即停止。"""
    subprocess.run(["openssl", *args], check=True, capture_output=True)


def _ca(directory: Path, label: str) -> tuple[Path, Path]:
    """在單次 CI 專屬目錄產生獨立根 CA，不重用 Gateway／Executor／Validator 身份。"""
    directory.mkdir(mode=0o700)
    cert, key = directory / "ca.pem", directory / "ca.key"
    _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=Mirage CI " + label,
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-out", str(cert), "-keyout", str(key))
    return cert, key


def _leaf(directory: Path, ca_cert: Path, ca_key: Path, name: str, *,
          server: bool) -> tuple[Path, Path]:
    """對固定 Docker DNS SAN 簽 ServerAuth 或 ClientAuth，不允許互換用途。"""
    cert, key = directory / (name + ".pem"), directory / (name + ".key")
    csr, ext = directory / (name + ".csr"), directory / (name + ".ext")
    ext.write_text("basicConstraints=critical,CA:FALSE\n"
                   + ("subjectAltName=DNS:" + name + "\n" if server else "")
                   + ("keyUsage=critical,digitalSignature,keyEncipherment\n"
                      if server else "keyUsage=critical,digitalSignature\n")
                   + ("extendedKeyUsage=serverAuth\n" if server else "extendedKeyUsage=clientAuth\n"),
                   encoding="ascii")
    _openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + name,
             "-keyout", str(key), "-out", str(csr))
    _openssl("x509", "-req", "-in", str(csr), "-CA", str(ca_cert),
             "-CAkey", str(ca_key), "-CAcreateserial", "-days", "1",
             "-extfile", str(ext), "-out", str(cert))
    key.chmod(0o600)
    return cert, key


def _store(root: Path, name: str, content: str | Path) -> None:
    """只把指定用途的秘密放到單次 CI 的 Docker Compose file-secret 來源。"""
    destination = root / "secrets" / name
    if isinstance(content, Path):
        shutil.copyfile(content, destination)
    else:
        destination.write_text(content, encoding="utf-8")
    # Docker Compose 的 standalone file secret 是唯讀 bind；目錄 0700 防止
    # Host 非擁有者瀏覽來源，檔案 0444 讓容器的不同 non-root UID 可讀。
    destination.chmod(0o444)


def _provision_roles(admin_dsn: str) -> dict[str, str]:
    """在核對過的全新 CI DB 內建五個不可繼承 SCRAM 角色並逐表賦最小權限。"""
    passwords = {role: secrets.token_urlsafe(36) for role in ROLES}
    with psycopg.connect(admin_dsn, autocommit=True) as admin:
        if admin.execute("SELECT current_database(),session_user").fetchone() != (
                "mirage_g3b_ci", "mirage_ci_owner"):
            raise RuntimeError("g3b_ci_wrong_database_identity")
        if admin.execute("SELECT count(*) FROM pg_roles WHERE rolname=ANY(%s)",
                         (list(ROLES.values()),)).fetchone()[0]:
            raise RuntimeError("g3b_ci_roles_already_exist")
        admin.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        admin.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC")
        for role, name in ROLES.items():
            admin.execute(sql.SQL(
                "CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOREPLICATION NOBYPASSRLS PASSWORD {}"
            ).format(sql.Identifier(name), sql.Literal(passwords[role])))
            admin.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(
                sql.Identifier(name)))
        grants = (
            ("verifier", "SELECT", "trusted_key_revocations,ingress_receipts,replay_entries"),
            ("verifier", "INSERT", "replay_entries,ingress_receipts,protected_http_operation_bindings"),
            ("inventory", "SELECT", "ingress_receipts,protected_http_operation_bindings,"
             "session_heads,session_world_bindings,generation_controls,trusted_key_revocations,"
             "world_snapshots,world_operations,read_admissions,protected_world_read_sources,"
             "protected_world_commit_sources,protected_world_rejection_sources"),
            ("inventory", "INSERT", "read_admissions,protected_world_read_sources,"
             "world_operations,world_events,world_commit_receipts,protected_world_commit_sources"),
            ("inventory", "INSERT", "protected_world_rejection_sources"),
            ("inventory", "UPDATE", "session_heads,session_world_bindings,"
             "generation_controls,world_snapshots"),
            ("cart", "SELECT", "ingress_receipts,protected_http_operation_bindings,"
             "session_heads,session_world_bindings,generation_controls,trusted_key_revocations,"
             "world_snapshots,world_operations,read_admissions,protected_world_read_sources,"
             "protected_world_commit_sources,protected_world_rejection_sources,"
             "protected_cart_creations,synthetic_resources,"
             "guest_cart_creations,protected_medusa_rejection_sources"),
            ("cart", "INSERT", "read_admissions,protected_world_read_sources,world_operations,"
             "world_events,world_commit_receipts,protected_world_commit_sources,"
             "protected_cart_creations,synthetic_resources,guest_cart_creations,"
             "native_response_contexts,world_initializations,"
             "protected_medusa_rejection_sources,session_heads,session_world_bindings,"
             "generation_controls,world_snapshots,protected_world_rejection_sources"),
            ("cart", "UPDATE", "session_heads,session_world_bindings,"
             "generation_controls,world_snapshots"),
            ("validator", "SELECT", "protected_medusa_rejection_sources,ingress_receipts,"
             "protected_http_operation_bindings,protected_world_read_sources,read_admissions,"
             "session_heads,session_world_bindings,generation_controls,trusted_key_revocations,"
             "protected_world_rejection_sources,world_operations,world_commit_receipts,"
             "protected_world_commit_sources,world_snapshots,synthetic_resources,"
             "protected_cart_creations,guest_cart_creations,native_response_contexts"),
        )
        for role, privilege, names in grants:
            admin.execute(sql.SQL("GRANT {} ON {} TO {}").format(
                sql.SQL(privilege),
                sql.SQL(",").join(sql.Identifier(name) for name in names.split(",")),
                sql.Identifier(ROLES[role]),
            ))
        # FOR SHARE OF synthetic_resources demands UPDATE on >= one column in PG17.
        # Never give table-wide UPDATE of the resource identity: migration 028
        # makes the row immutable and this narrow privilege exists for locking only.
        admin.execute(sql.SQL(
            "GRANT UPDATE (resource_kind) ON synthetic_resources TO {}"
        ).format(sql.Identifier(ROLES["cart"])))
        for role in ("inventory", "cart"):
            admin.execute(sql.SQL(
                "GRANT EXECUTE ON FUNCTION protected_lock_reference(text,jsonb) TO {}"
            ).format(sql.Identifier(ROLES[role])))
        for name in ROLES.values():
            if admin.execute("SELECT rolpassword LIKE %s FROM pg_authid "
                             "WHERE rolname=%s", ("SCRAM-SHA-256$%", name)).fetchone() != (True,):
                raise RuntimeError("g3b_ci_scram_required")
    return {role: make_conninfo(host="g3b-postgres", dbname="mirage_g3b_ci",
                                user=name, password=password, connect_timeout=5,
                                options="-c search_path=public")
            for role, (name, password) in
            ((role, (ROLES[role], passwords[role])) for role in ROLES)}


def _seed_world(admin_dsn: str, root: Path) -> None:
    """以一次性 DB Owner 建立可信 Inventory 及衍生 Cart 的測試初始世界。"""
    now = int(time.time())
    inventory = SessionBinding(environment_id="env", deployment_id="deploy",
                               session_id="session", session_epoch=1, access_mode="inventory")
    SyntheticInventory(admin_dsn).resolve(
        inventory, {"inventory": {"sku-1": 5}, "reservations": {}}, now=now, ttl=420)
    creator = SessionBinding(environment_id="env", deployment_id="deploy",
                             session_id="g3b-ci-cart-creator", session_epoch=1, access_mode="cart")
    state = {"catalog": {"known": {"sku": "sku-1", "unit_price": 100}},
             "inventory": {"sku-1": 5},
             "native_context": {"region_id": "reg_mirage_usd", "sales_channel_id": "sc_mirage",
                                "email": "ci@example.invalid", "metadata": {}}}
    carts = SyntheticCarts(admin_dsn)
    carts.resolve(creator, {"catalog": state["catalog"], "inventory": state["inventory"],
                            "reservations": {}}, now=now, ttl=420)
    receipt_id, jti = uuid4(), uuid4().hex
    with psycopg.connect(admin_dsn) as connection:
        connection.execute("INSERT INTO replay_entries VALUES ('gateway','mirage',%s,%s)",
                           (jti, now + 420))
        connection.execute(
            """INSERT INTO ingress_receipts (
                 receipt_id,issuer,audience,jti,key_id,environment_id,deployment_id,
                 session_id,session_epoch,request_fingerprint,assessment_digest,
                 claims_digest,verification_policy_version,token_issued_at,
                 token_not_before,token_expires_at,access_mode)
               VALUES (%s,'gateway','mirage',%s,'old','env','deploy',%s,1,%s,%s,%s,
                       'trusted-session-v1.1',%s,%s,%s,'cart')""",
            (receipt_id, jti, creator.session_id, "a" * 64, "b" * 64, "c" * 64,
             now - 5, now - 5, now + 420),
        )
    executor = PostgresProtectedWorldExecutor(
        admin_dsn, expected_login="mirage_ci_owner", world_store=carts,
        cart_initial_state=state, medusa_publishable_key="pk_g3b_ci_only",
    )
    created = executor.create_cart(
        receipt_id=receipt_id, creator=creator, request_fingerprint="a" * 64,
        idempotency_key=uuid4(), commit_attempt_id=uuid4(),
        creation_digest="d" * 64, ttl=420,
    )
    with psycopg.connect(admin_dsn) as connection:
        generation = connection.execute(
            """SELECT world_generation_id FROM session_world_bindings
               WHERE environment_id=%s AND deployment_id=%s
                 AND session_id=%s AND session_epoch=%s""",
            (created.binding.environment_id, created.binding.deployment_id,
             created.binding.session_id, created.binding.session_epoch),
        ).fetchone()
    if generation is None:
        raise RuntimeError("g3b_ci_cart_generation_missing")
    _store(root, "g3b_cart_initial_state", json.dumps(state, separators=(",", ":")))
    _store(root, "g3b_medusa_publishable_key", "pk_g3b_ci_only")
    (root / "probe" / "world.json").write_text(json.dumps({
        "cart_id": created.binding.resource_id,
        "cart_session": created.binding.session_id,
        "cart_generation": generation[0],
    }), encoding="utf-8")


def _identity_material(root: Path, dsns: dict[str, str]) -> None:
    """隔開 Gateway、Executor、Validator 的 TLS 私鑰與角色 DSN，產生固定來源覆寫。"""
    gateway_root = root / "gateway-ca"
    executor_root = root / "executor-ca"
    validator_root = root / "validator-ca"
    gateway_ca, gateway_key = _ca(gateway_root, "Gateway")
    executor_ca, executor_key = _ca(executor_root, "Executor")
    validator_ca, validator_ca_key = _ca(validator_root, "Validator")
    verifier_cert, verifier_key = _leaf(gateway_root, gateway_ca, gateway_key, "verifier", server=True)
    gateway_cert, gateway_client_key = _leaf(gateway_root, gateway_ca, gateway_key,
                                              "gateway-probe", server=False)
    inventory_cert, inventory_key = _leaf(executor_root, executor_ca, executor_key,
                                           "inventory-executor", server=True)
    cart_cert, cart_key = _leaf(executor_root, executor_ca, executor_key,
                                 "cart-executor", server=True)
    verifier_client_cert, verifier_client_key = _leaf(executor_root, executor_ca, executor_key,
                                                       "verifier-executor", server=False)
    validator_cert, validator_server_key = _leaf(
        validator_root, validator_ca, validator_ca_key, "native-validator", server=True)
    validator_client_cert, validator_client_key = _leaf(validator_root, validator_ca,
                                                        validator_ca_key, "verifier-validator", server=False)
    material = {
        "g3b_verifier_dsn": dsns["verifier"],
        "g3b_inventory_executor_dsn": dsns["inventory"],
        "g3b_cart_executor_dsn": dsns["cart"],
        "g3b_native_validator_dsn": dsns["validator"],
        "g3b_verifier_server_cert": verifier_cert,
        "g3b_verifier_server_key": verifier_key,
        "g3b_gateway_client_ca": gateway_ca,
        "g3b_verifier_client_cert": verifier_client_cert,
        "g3b_verifier_client_key": verifier_client_key,
        "g3b_executor_server_ca": executor_ca,
        "g3b_inventory_server_cert": inventory_cert,
        "g3b_inventory_server_key": inventory_key,
        "g3b_cart_server_cert": cart_cert,
        "g3b_cart_server_key": cart_key,
        "g3b_verifier_client_ca": executor_ca,
        "g3b_verifier_validator_cert": validator_client_cert,
        "g3b_verifier_validator_key": validator_client_key,
        "g3b_native_validator_server_ca": validator_ca,
        "g3b_native_validator_server_cert": validator_cert,
        "g3b_native_validator_server_key": validator_server_key,
        "g3b_native_validator_client_ca": validator_ca,
    }
    for name, content in material.items():
        _store(root, name, content)
    signing_key = Ed25519PrivateKey.generate()
    _store(root, "g3b_verifier_keys", json.dumps({
        "old": base64.b64encode(signing_key.public_key().public_bytes_raw()).decode("ascii"),
    }))
    (root / "probe" / "signing.key").write_bytes(signing_key.private_bytes_raw())
    for name, path in (("gateway-ca.pem", gateway_ca), ("gateway-client.pem", gateway_cert),
                       ("gateway-client.key", gateway_client_key)):
        shutil.copyfile(path, root / "probe" / name)
    _store(root, "runtime-dsn-ci-probe", dsns["runtime"])
    host_runtime = conninfo_to_dict(dsns["runtime"])
    host_runtime.update(host="127.0.0.1", port="55433")
    (root / "probe" / "runtime-host.dsn").write_text(
        make_conninfo(**host_runtime), encoding="utf-8")
    override = {"secrets": {name: {"file": str(root / "secrets" / name), "external": False}
                            for name in material | {"g3b_verifier_keys": ""}}}
    # CI-only override: record an opaque failure class from the disposable Cart
    # Executor, not arbitrary SQL, candidate bodies or sensitive credentials.
    override["services"] = {"cart-executor": {"environment": {
        "MIRAGE_G3B_CI_DIAGNOSTIC": "opaque-failure-classes",
    }}}
    override["secrets"].update({
        "g3b_cart_initial_state": {"file": str(root / "secrets" / "g3b_cart_initial_state"),
                                   "external": False},
        "g3b_medusa_publishable_key": {"file": str(root / "secrets" / "g3b_medusa_publishable_key"),
                                       "external": False},
    })
    (root / "ci-override.yaml").write_text(yaml.safe_dump(override), encoding="utf-8")


def main() -> None:
    """核對 CI 明確標記與全新 DB 後建最小授權及 Secret，任何失敗禁止部署。"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--dsn", required=True)
    args = parser.parse_args()
    if os.environ.get("MIRAGE_G3B_CI_EXPLICIT") != "ephemeral-four-services-only":
        raise RuntimeError("g3b_ci_isolation_marker_required")
    root = args.root.resolve(strict=True)
    if not root.is_dir() or any(root.iterdir()):
        raise RuntimeError("g3b_ci_requires_empty_directory")
    (root / "secrets").mkdir(mode=0o700)
    (root / "probe").mkdir(mode=0o700)
    with psycopg.connect(args.dsn) as connection:
        if connection.execute("SELECT current_database(),session_user").fetchone() != (
                "mirage_g3b_ci", "mirage_ci_owner"):
            raise RuntimeError("g3b_ci_wrong_database_identity")
    apply_migrations(args.dsn, Path("migrations"))
    _seed_world(args.dsn, root)
    role_dsns = _provision_roles(args.dsn)
    _identity_material(root, role_dsns)
    print("G3B_CI_PREPARED roles=5 ca_roots=3 services=4 secrets=redacted trusted_send=off")


if __name__ == "__main__":
    main()
