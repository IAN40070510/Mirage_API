"""SINGLE-NODE-01／02：隔離 D-74 Compose 九容器、真 SCRAM 與 mTLS 啟動試驗。"""

from __future__ import annotations

import base64
import ctypes
import ctypes.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import stat
import struct
import subprocess
import time
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import httpx
import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
import pytest
import yaml

from deception.world.migrations import apply_migrations
from deception.security.protected_services import _login_preflight
from tools.check_single_node_compose import validate_single_node_compose


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy/single-node/compose.yaml"
DOCKER = "/usr/bin/docker"
COMPOSE_BIN = "/usr/local/bin/docker-compose"
ROLE_UID = {
    "verifier": 10021, "inventory-executor": 10022, "cart-executor": 10023,
    "native-validator": 10024, "candidate-publisher": 10026,
    "authorizer": 10027, "sender": 10025, "gateway": 10020,
}
LOGINS = {
    "verifier": "mirage_sn_ci_verifier",
    "inventory": "mirage_sn_ci_inventory",
    "cart": "mirage_sn_ci_cart",
    "validator": "mirage_sn_ci_validator",
    "publisher_reader": "mirage_sn_ci_pub_reader",
    "publisher_writer": "mirage_sn_ci_pub_writer",
    "publisher_promoter": "mirage_sn_ci_pub_promoter",
    "authorizer": "mirage_sn_ci_authorizer",
    "sender": "mirage_sn_ci_sender",
}
READ = {
    "verifier": "trusted_key_revocations,ingress_receipts,replay_entries",
    "inventory": "ingress_receipts,protected_http_operation_bindings,session_heads,"
    "session_world_bindings,generation_controls,trusted_key_revocations,world_snapshots,"
    "world_operations,read_admissions,protected_world_read_sources,"
    "protected_world_commit_sources,protected_world_rejection_sources",
    "cart": "ingress_receipts,protected_http_operation_bindings,session_heads,"
    "session_world_bindings,generation_controls,trusted_key_revocations,world_snapshots,"
    "world_operations,read_admissions,protected_world_read_sources,"
    "protected_world_commit_sources,protected_world_rejection_sources,"
    "protected_cart_creations,synthetic_resources,guest_cart_creations,"
    "protected_medusa_rejection_sources",
    "validator": "protected_medusa_rejection_sources,ingress_receipts,"
    "protected_http_operation_bindings,protected_world_read_sources,read_admissions,"
    "session_heads,session_world_bindings,generation_controls,trusted_key_revocations,"
    "protected_world_rejection_sources,world_operations,world_commit_receipts,"
    "protected_world_commit_sources,world_snapshots,synthetic_resources,"
    "protected_cart_creations,guest_cart_creations,native_response_contexts",
    "publisher_reader": "protected_medusa_rejection_sources,ingress_receipts,"
    "protected_http_operation_bindings,protected_world_read_sources,read_admissions,"
    "session_heads,session_world_bindings,generation_controls,trusted_key_revocations,"
    "protected_world_rejection_sources,world_operations,world_commit_receipts,"
    "protected_world_commit_sources,world_snapshots,synthetic_resources,"
    "protected_cart_creations,guest_cart_creations,native_response_contexts",
    "publisher_writer": "candidate_records",
    "publisher_promoter": "candidate_records,ingress_receipts,"
    "protected_http_operation_bindings,read_admissions,protected_world_read_sources,"
    "world_operations,protected_world_commit_sources,protected_world_rejection_sources,"
    "protected_medusa_rejection_sources,projection_registry,"
    "projection_profile_revocations,protected_cart_creations,guest_cart_creations,"
    "synthetic_resources,session_heads,session_world_bindings,generation_controls,"
    "world_snapshots,world_commit_receipts,trusted_key_revocations",
    "authorizer": "protected_candidate_promotions,ingress_receipts,projection_registry,"
    "session_heads,session_world_bindings,generation_controls,trusted_key_revocations,"
    "projection_profile_revocations,response_admissions,protected_grant_bindings,"
    "protected_http_operation_bindings,protected_cart_creations,guest_cart_creations,"
    "synthetic_resources,world_snapshots,world_commit_receipts",
    "sender": "response_admissions,protected_authorized_http_snapshots,"
    "protected_grant_bindings,protected_authorized_snapshot_purge_fences,"
    "protected_local_restore_events,protected_send_leases",
}
INSERT = {
    "verifier": "replay_entries,ingress_receipts,protected_http_operation_bindings",
    "inventory": "read_admissions,protected_world_read_sources,world_operations,"
    "world_events,world_commit_receipts,protected_world_commit_sources,"
    "protected_world_rejection_sources",
    "cart": "read_admissions,protected_world_read_sources,world_operations,"
    "world_events,world_commit_receipts,protected_world_commit_sources,"
    "protected_cart_creations,synthetic_resources,guest_cart_creations,"
    "native_response_contexts,world_initializations,protected_medusa_rejection_sources,"
    "session_heads,session_world_bindings,generation_controls,world_snapshots,"
    "protected_world_rejection_sources",
    "publisher_writer": "candidate_records",
    "publisher_promoter": "protected_candidate_promotions",
    "authorizer": "response_admissions,protected_grant_bindings,"
    "protected_authorized_http_snapshots",
    "sender": "protected_send_leases,response_audit",
}
UPDATE = {
    "inventory": "session_heads,session_world_bindings,generation_controls,world_snapshots",
    "cart": "session_heads,session_world_bindings,generation_controls,world_snapshots",
}


def _run(argv: list[str], *, env: dict[str, str] | None = None,
         timeout: int = 90) -> bytes:
    """只執行固定程序與 argv；任何錯誤均隱藏可能包含密碼的命令輸出。"""
    try:
        result = subprocess.run(
            argv, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise AssertionError("single_node_full_stack_command_unavailable") from None
    assert result.returncode == 0, "single_node_full_stack_command_failed"
    assert len(result.stdout) <= 512 * 1024, "single_node_full_stack_output_too_large"
    return result.stdout


def _openssl(*args: str) -> None:
    """靜默生成短期 CA／憑證；私鑰不可出現在測試或 SSH 日誌。"""
    _run(["/usr/bin/openssl", *args], timeout=40)


def _ca(root: Path, name: str) -> tuple[Path, Path]:
    """為每條服務信任鏈生成一次性根 CA，與其他角色和正式 PKI 分離。"""
    root.mkdir(mode=0o700)
    cert, key = root / "ca.pem", root / "ca.key"
    _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=Mirage single node CI " + name,
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-out", str(cert), "-keyout", str(key))
    return cert, key


def _leaf(root: Path, ca: tuple[Path, Path], name: str, *, server: bool) -> tuple[Path, Path]:
    """簽發 DNS SAN 正確且 ServerAuth／ClientAuth 分離的短期 TLS 葉憑證。"""
    cert, key = root / (name + ".pem"), root / (name + ".key")
    csr, ext = root / (name + ".csr"), root / (name + ".ext")
    ext.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        + ("subjectAltName=DNS:" + name + "\n" if server else "")
        + ("keyUsage=critical,digitalSignature,keyEncipherment\n"
           if server else "keyUsage=critical,digitalSignature\n")
        + ("extendedKeyUsage=serverAuth\n" if server else "extendedKeyUsage=clientAuth\n"),
        encoding="ascii",
    )
    _openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + name,
             "-keyout", str(key), "-out", str(csr))
    _openssl("x509", "-req", "-in", str(csr), "-CA", str(ca[0]),
             "-CAkey", str(ca[1]), "-CAcreateserial", "-days", "1",
             "-extfile", str(ext), "-out", str(cert))
    return cert, key


def _provision(admin_dsn: str, database: str, admin_login: str,
               container_host: str) -> dict[str, str]:
    """在全新 PG DB 建九個不同 SCRAM NOINHERIT Login，僅授予角色前置檢查所需 ACL。"""
    passwords = {name: secrets.token_urlsafe(36) for name in LOGINS}
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        assert conn.execute("SELECT current_database(),session_user").fetchone() == (
            database, admin_login,
        ), "single_node_full_stack_wrong_database"
        assert conn.execute(
            "SELECT count(*) FROM pg_roles WHERE rolname=ANY(%s)", (list(LOGINS.values()),)
        ).fetchone() == (0,), "single_node_full_stack_preexisting_role"
        conn.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        conn.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC")
        for kind, login in LOGINS.items():
            conn.execute(sql.SQL(
                "CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOREPLICATION NOBYPASSRLS PASSWORD {}"
            ).format(sql.Identifier(login), sql.Literal(passwords[kind])))
            conn.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(
                sql.Identifier(login)))
        for privilege, grants in (("SELECT", READ), ("INSERT", INSERT), ("UPDATE", UPDATE)):
            for kind, tables in grants.items():
                conn.execute(sql.SQL("GRANT {} ON {} TO {}").format(
                    sql.SQL(privilege),
                    sql.SQL(",").join(sql.Identifier(name) for name in tables.split(",")),
                    sql.Identifier(LOGINS[kind]),
                ))
        conn.execute(sql.SQL(
            "GRANT UPDATE (resource_kind) ON synthetic_resources TO {}"
        ).format(sql.Identifier(LOGINS["cart"])))
        conn.execute(sql.SQL(
            "GRANT UPDATE (state) ON response_admissions TO {}"
        ).format(sql.Identifier(LOGINS["sender"])))
        conn.execute(sql.SQL(
            "GRANT UPDATE (control_revision) ON generation_controls TO {}"
        ).format(sql.Identifier(LOGINS["authorizer"])))
        conn.execute(sql.SQL(
            "GRANT UPDATE (state,claim_owner,claim_revision,"
            "send_authorization_revision) ON response_admissions TO {}"
        ).format(sql.Identifier(LOGINS["authorizer"])))
        for kind in ("inventory", "cart", "publisher_promoter", "authorizer"):
            conn.execute(sql.SQL(
                "GRANT EXECUTE ON FUNCTION protected_lock_reference(text,jsonb) TO {}"
            ).format(sql.Identifier(LOGINS[kind])))
        for name in LOGINS.values():
            assert conn.execute(
                "SELECT rolpassword LIKE 'SCRAM-SHA-256$%%' FROM pg_authid WHERE rolname=%s",
                (name,),
            ).fetchone() == (True,), "single_node_full_stack_scram_required"
    dsns = {
        kind: make_conninfo(
            host=container_host, dbname=database, user=login,
            password=passwords[kind], connect_timeout=5,
            options="-c search_path=public",
        )
        for kind, login in LOGINS.items()
    }
    for kind, role, platform in (
            ("verifier", "verifier", None),
            ("inventory", "executor", "synthetic-inventory"),
            ("cart", "executor", "synthetic-carts"),
            ("validator", "validator", None),
            ("publisher_reader", "validator", None),
            ("publisher_writer", "candidate_writer", None),
            ("publisher_promoter", "promoter", None),
            ("authorizer", "authorizer", None),
            ("sender", "sender", None)):
        # 真實服務在啟動時會再次執行同一個 Preflight；主機預檢提前定位 ACL。
        # 由於 DSN 的 Docker hostname 只在容器可解析，改成固定 PG bridge IP。
        info = conninfo_to_dict(dsns[kind])
        info["host"] = conninfo_to_dict(admin_dsn)["host"]
        _login_preflight(make_conninfo(**info), LOGINS[kind],
                         role=role, schema="public", platform=platform)
    return dsns


def _material(root: Path, dsns: dict[str, str], pg_password: str) -> dict[str, str | Path]:
    """產生全部 Compose Secret；每條 Client→Server 都用獨立 CA 與葉私鑰。"""
    trust = {}
    for name in ("gateway_verifier", "gateway_sender", "executor", "validator",
                 "publisher", "authorizer", "gateway_public"):
        trust[name] = _ca(root / ("ca-" + name), name)
    material: dict[str, str | Path] = {
        "postgres_password": pg_password,
        "verifier_dsn": dsns["verifier"],
        "inventory_dsn": dsns["inventory"],
        "cart_dsn": dsns["cart"],
        "validator_dsn": dsns["validator"],
        "publisher_reader_dsn": dsns["publisher_reader"],
        "publisher_writer_dsn": dsns["publisher_writer"],
        "publisher_promoter_dsn": dsns["publisher_promoter"],
        "authorizer_dsn": dsns["authorizer"],
        "sender_dsn": dsns["sender"],
        "cart_initial_state": json.dumps({
            "catalog": {"known": {"sku": "sku-1", "unit_price": 100}},
            "inventory": {"sku-1": 5},
            "native_context": {"region_id": "reg_mirage_usd",
                               "sales_channel_id": "sc_mirage",
                               "email": "ci@example.invalid", "metadata": {}},
        }, separators=(",", ":")),
        "medusa_publishable_key": "pk_disposable_single_node_only",
    }
    key = Ed25519PrivateKey.generate()
    material["verifier_keys"] = json.dumps({
        "test": base64.b64encode(key.public_key().public_bytes_raw()).decode("ascii"),
    })
    material["publisher_evidence"] = json.dumps({
        name: {
            "source_spec_sha256": "1" * 64,
            "compatibility_profile": {
                "profile_id": "disposable", "profile_version": "1",
                "profile_sha256": "2" * 64, "platform_id": name,
                "platform_version": "1", "source_spec_sha256": "1" * 64,
                "world_schema_version": "1", "domain_adapter_version": "1",
            },
            "projection_contract_hash": "3" * 64,
            "official_schema_valid": True, "effective_projection_valid": True,
        }
        for name in ("synthetic-inventory", "synthetic-carts", "medusa-native-cart")
    }, separators=(",", ":"))
    server = (
        ("verifier", "gateway_verifier", "verifier_server"),
        ("sender", "gateway_sender", "sender_server"),
        ("inventory-executor", "executor", "inventory_server"),
        ("cart-executor", "executor", "cart_server"),
        ("native-validator", "validator", "validator_server"),
        ("candidate-publisher", "publisher", "publisher_server"),
        ("authorizer", "authorizer", "authorizer_server"),
        ("localhost", "gateway_public", "gateway_server"),
    )
    for dns, ca_name, prefix in server:
        cert, key_path = _leaf(root / ("ca-" + ca_name), trust[ca_name],
                               dns, server=True)
        material[prefix + "_cert"] = cert
        material[prefix + "_key"] = key_path
    clients = (
        ("gateway-verifier", "gateway_verifier", "gateway_verifier_client"),
        ("gateway-sender", "gateway_sender", "gateway_sender_client"),
        ("verifier-executor", "executor", "verifier_executor_client"),
        ("verifier-validator", "validator", "verifier_validator_client"),
        ("verifier-publisher", "publisher", "verifier_publisher_client"),
        ("verifier-authorizer", "authorizer", "verifier_authorizer_client"),
    )
    for dns, ca_name, prefix in clients:
        cert, key_path = _leaf(root / ("ca-" + ca_name), trust[ca_name],
                               dns, server=False)
        material[prefix + "_cert"] = cert
        material[prefix + "_key"] = key_path
    material.update({
        "gateway_client_ca": trust["gateway_verifier"][0],
        "gateway_sender_client_ca": trust["gateway_sender"][0],
        "gateway_verifier_server_ca": trust["gateway_verifier"][0],
        "gateway_sender_server_ca": trust["gateway_sender"][0],
        "executor_server_ca": trust["executor"][0],
        "inventory_verifier_client_ca": trust["executor"][0],
        "cart_verifier_client_ca": trust["executor"][0],
        "validator_server_ca": trust["validator"][0],
        "verifier_validator_client_ca": trust["validator"][0],
        "publisher_server_ca": trust["publisher"][0],
        "verifier_publisher_client_ca": trust["publisher"][0],
        "authorizer_server_ca": trust["authorizer"][0],
        "verifier_authorizer_client_ca": trust["authorizer"][0],
    })
    return material


def _install_role_owned_secrets(root: Path, material: dict[str, str | Path],
                                doc: dict) -> None:
    """由檔案擁有者以 POSIX ACL 只授權指定 Runtime UID，拒絕 world-readable。"""
    directory = root / "secrets"
    directory.mkdir(mode=0o700, exist_ok=True)
    assert set(material) == set(doc["secrets"]), "single_node_full_stack_secret_mismatch"
    ownership: dict[str, int] = {}
    for service, uid in ROLE_UID.items():
        for name in doc["services"][service]["secrets"]:
            assert name not in ownership, "single_node_full_stack_secret_shared_between_uids"
            ownership[name] = uid
    assert set(ownership) == set(material) - {"postgres_password"}
    for name, source in material.items():
        destination = directory / name
        if name == "postgres_password":
            assert isinstance(source, str) and destination.read_text(encoding="utf-8") == source
            assert destination.stat().st_mode & 0o777 == 0o400
            continue
        if isinstance(source, Path):
            shutil.copyfile(source, destination)
        else:
            destination.write_text(source, encoding="utf-8")
        destination.chmod(0o400)
    library = ctypes.util.find_library("acl")
    assert library, "single_node_full_stack_posix_acl_unavailable"
    acl_lib = ctypes.CDLL(library, use_errno=True)
    acl_lib.acl_from_text.argtypes = [ctypes.c_char_p]
    acl_lib.acl_from_text.restype = ctypes.c_void_p
    acl_lib.acl_set_file.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]
    acl_lib.acl_set_file.restype = ctypes.c_int
    acl_lib.acl_free.argtypes = [ctypes.c_void_p]
    acl_lib.acl_free.restype = ctypes.c_int
    for name, uid in ownership.items():
        assert re.fullmatch(r"[a-z][a-z0-9_]*", name)
        destination = directory / name
        check = destination.lstat()
        assert stat.S_ISREG(check.st_mode) and check.st_uid == os.geteuid()
        assert stat.S_IMODE(check.st_mode) == 0o400
        # ACL_MASK 只授權具名 UID；群組本身及其他使用者沒有讀權。
        acl_text = ("u::r--,u:" + str(uid) + ":r--,g::---,m::r--,o::---").encode("ascii")
        acl = acl_lib.acl_from_text(acl_text)
        assert acl, "single_node_full_stack_acl_compile_failed"
        try:
            assert acl_lib.acl_set_file(os.fsencode(destination), 0x8000, acl) == 0, (
                "single_node_full_stack_acl_set_failed"
            )
        finally:
            acl_lib.acl_free(acl)
    for name, uid in ownership.items():
        status = (directory / name).stat()
        assert status.st_uid == os.geteuid() and status.st_mode & 0o007 == 0
        assert os.getxattr(directory / name, "system.posix_acl_access")
    source = directory / "verifier_dsn"
    for uid, expected_readable in ((ROLE_UID["verifier"], True),
                                   (ROLE_UID["sender"], False)):
        prefix = [
            DOCKER, "run", "--rm", "--network", "none", "--read-only",
            "--user", str(uid) + ":" + str(uid), "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--mount", "type=bind,src=" + str(source) + ",dst=/probe,readonly",
            "postgres:17.6-alpine",
        ]
        metadata = _run([*prefix, "stat", "-c", "%u:%g:%a", "/probe"],
                        timeout=30).decode("ascii").strip()
        try:
            _run([*prefix, "sh", "-ec",
                  "head -c 1 /probe >/dev/null" if expected_readable
                  else "! head -c 1 /probe >/dev/null 2>&1"],
                 timeout=30)
        except AssertionError:
            encoded = os.getxattr(source, "system.posix_acl_access")
            entries = [struct.unpack_from("<HHI", encoded, offset)
                       for offset in range(4, len(encoded), 8)]
            raise AssertionError(
                "single_node_full_stack_posix_acl_container_mismatch "
                + metadata + " expected=" + str(expected_readable)
                + " acl_entries=" + repr(entries)
            ) from None


def _env(directory: Path, database: str, admin: str, port: int) -> dict[str, str]:
    """組合單次實測的非機密 Compose 變數，永遠不注入外部 Fence。"""
    env = os.environ.copy()
    image = env.get("MIRAGE_SINGLE_NODE_TEST_IMAGE", "")
    assert re.fullmatch(r"mirage-api:sn-[0-9a-f]{7,40}", image), (
        "single_node_full_stack_exact_image_required"
    )
    env.update({
        "MIRAGE_SINGLE_NODE_IMAGE": image,
        "MIRAGE_SINGLE_NODE_POSTGRES_IMAGE": "postgres:17.6-alpine",
        "MIRAGE_SINGLE_NODE_SECRETS_DIR": str(directory),
        "MIRAGE_SINGLE_NODE_DB_NAME": database,
        "MIRAGE_SINGLE_NODE_DB_ADMIN": admin,
        "MIRAGE_SINGLE_NODE_WORLD_SCHEMA": "public",
        "MIRAGE_SINGLE_NODE_ENVIRONMENT_ID": "disposable",
        "MIRAGE_SINGLE_NODE_DEPLOYMENT_ID": "isolated",
        "MIRAGE_SINGLE_NODE_ISSUER": "gateway",
        "MIRAGE_SINGLE_NODE_AUDIENCE": "mirage",
        "MIRAGE_SINGLE_NODE_GATEWAY_LOCAL_PORT": str(port),
    })
    for kind, login in LOGINS.items():
        env["MIRAGE_SINGLE_NODE_" + kind.upper() + "_LOGIN"] = login
    # Compose 使用 INVENTORY/CART/VALIDATOR/PUBLISHER_READER 等固定同名欄位。
    return env


def _no_project_resources(project: str) -> None:
    """檢查同一亂數專案沒有任何殘留容器、資料卷或網路。"""
    for resource, args in (
            ("container", [DOCKER, "ps", "-aq"]),
            ("volume", [DOCKER, "volume", "ls", "-q"]),
            ("network", [DOCKER, "network", "ls", "-q"])):
        output = _run([*args, "--filter", "label=com.docker.compose.project=" + project])
        assert not output.strip(), "single_node_full_stack_" + resource + "_residue"


def _safe_startup_error_codes(container_id: str) -> tuple[str, ...]:
    """只從短尾日誌擷取既定錯誤碼，不把 TLS、DSN、Header 或私鑰載入報告。"""
    try:
        result = subprocess.run(
            [DOCKER, "logs", "--tail", "50", container_id],
            capture_output=True, stdin=subprocess.DEVNULL,
            check=False, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ("logs_unavailable",)
    raw = (result.stdout + result.stderr).decode("utf-8", "ignore")
    codes = set(re.findall(
        r"(?:g3b|g4|g5|single_node|protected_rpc)_[a-z0-9_]{4,90}", raw,
    ))
    codes.update(re.findall(
        r"\b(?:PermissionError|FileNotFoundError|ValueError|AttributeError|"
        r"ProtectedRpcConfigurationError|RuntimeError|ImportError|"
        r"ModuleNotFoundError|OperationalError|SSLError|OSError)\b", raw,
    ))
    codes.update(re.findall(r"\[Errno (?:1|2|13|98|99|111)\]", raw))
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if lines:
        last = lines[-1]
        if not re.search(r"(?i)(password|private|secret|://|token|dsn|/run/)", last):
            codes.add("lastlog_" + re.sub(r"[^A-Za-z0-9_: .-]", "", last)[:130])
    return tuple(sorted(codes))[:16]


def test_true_nine_service_compose_sealed_stack_with_physical_scram_and_tls(tmp_path):
    """明確 opt-in 的可銷毀專案才建九容器，驗證真最小權限、TLS 與 Gateway 封閉。"""
    if (os.environ.get("MIRAGE_SINGLE_NODE_FULL_STACK_ISOLATED") != "true"
            or os.environ.get("MIRAGE_SINGLE_NODE_DISPOSABLE_COMPOSE_PROJECT") != "true"
            or os.environ.get("MIRAGE_G5_RESTORE_PG_TOOL_CONTAINER") != "mirage-g3b-ci-db"):
        pytest.skip("requires exact disposable ARM64 full-stack Docker opt-ins")
    doc = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    validate_single_node_compose(doc)
    project = "mirage-sn-full-" + uuid4().hex[:12]
    database = "mirage_sn_full_" + uuid4().hex[:10]
    admin, password = "mirage_sn_ci_admin", secrets.token_urlsafe(36)
    assert re.fullmatch(r"mirage-sn-full-[0-9a-f]{12}", project)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    secret_dir = tmp_path / "secrets"
    secret_dir.mkdir(mode=0o700)
    (secret_dir / "postgres_password").write_text(password, encoding="utf-8")
    (secret_dir / "postgres_password").chmod(0o400)
    env = _env(secret_dir, database, admin, port)
    base = [COMPOSE_BIN, "-p", project, "-f", str(COMPOSE)]
    _no_project_resources(project)
    created = False
    try:
        _run([*base, "config", "--quiet"], env=env)
        created = True
        _run([*base, "up", "-d", "--no-deps", "postgres"], env=env, timeout=120)
        for _ in range(90):
            status = subprocess.run(
                [*base, "exec", "-T", "postgres", "pg_isready", "-h", "127.0.0.1",
                 "-U", admin, "-d", database],
                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                check=False, timeout=15,
            )
            if status.returncode == 0:
                break
            time.sleep(0.5)
        else:
            pytest.fail("single_node_full_stack_pg_not_ready")
        container = _run([
            DOCKER, "ps", "-q", "--filter", "label=com.docker.compose.project=" + project,
            "--filter", "label=com.docker.compose.service=postgres",
        ]).decode("ascii").strip()
        assert re.fullmatch(r"[0-9a-f]{12,64}", container)
        ip = json.loads(_run([DOCKER, "inspect", container]))[0][
            "NetworkSettings"]["Networks"][project + "_database"]["IPAddress"]
        admin_dsn = make_conninfo(
            host=ip, port=5432, dbname=database, user=admin,
            password=password, connect_timeout=5,
        )
        apply_migrations(admin_dsn, ROOT / "migrations")
        dsns = _provision(admin_dsn, database, admin, "postgres")
        material = _material(tmp_path, dsns, password)
        _install_role_owned_secrets(tmp_path, material, doc)
        _run([*base, "--profile", "isolated-gateway", "up", "-d"],
             env=env, timeout=180)
        containers = _run([
            DOCKER, "ps", "-aq", "--filter", "label=com.docker.compose.project=" + project,
        ]).decode("ascii").strip().splitlines()
        assert len(containers) == 9, "single_node_full_stack_container_count"
        deadline = time.monotonic() + 80
        while True:
            startup_failures = []
            pending = []
            inspected = json.loads(_run([DOCKER, "inspect", *containers]))
            for data in inspected:
                role = data["Config"]["Labels"]["com.docker.compose.service"]
                cid = data["Id"]
                if data["State"]["Running"] is not True:
                    startup_failures.append(
                        role + ":exit=" + str(data["State"].get("ExitCode"))
                        + ":codes=" + ",".join(_safe_startup_error_codes(cid))
                    )
                elif data["State"]["Health"]["Status"] != "healthy":
                    pending.append(role + ":" + str(data["State"]["Health"]["Status"]))
                assert data["HostConfig"]["PortBindings"] in (None, {}) or role == "gateway"
                if role in ROLE_UID:
                    assert data["Config"]["User"] == str(ROLE_UID[role]) + ":" + str(
                        ROLE_UID[role])
            if startup_failures or not pending or time.monotonic() >= deadline:
                break
            time.sleep(1)
        assert not startup_failures and not pending, (
            "single_node_full_stack_startup:"
            + ";".join(sorted(startup_failures + pending))
        )
        ca = tmp_path / "ca-gateway_public" / "ca.pem"
        origin = "https://localhost:" + str(port)
        with httpx.Client(verify=ssl.create_default_context(cafile=str(ca)),
                          timeout=8, trust_env=False) as client:
            response = client.get(origin + "/internal/ready")
            assert response.status_code == 200
            assert response.json()["trusted_send"] == "disabled"
            missing_signature = client.get(
                origin + "/api/items", headers={"x-request-id": uuid4().hex},
            )
            assert missing_signature.status_code == 403
            assert missing_signature.json()["detail"] == "gateway_signed_session_required"
            # 非法 JWS 必須經真正的 Gateway→Verifier mTLS 而遭拒；不會轉 Sender。
            invalid_signed_request = client.get(
                origin + "/api/items",
                headers={"x-request-id": uuid4().hex, "x-trusted-session": "invalid-jws"},
            )
            assert invalid_signed_request.status_code == 503
            assert invalid_signed_request.json()["detail"] == "gateway_delivery_unverifiable"
        with psycopg.connect(admin_dsn) as conn:
            assert conn.execute("SELECT count(*) FROM ingress_receipts").fetchone() == (0,)
            assert conn.execute("SELECT count(*) FROM protected_send_leases").fetchone() == (0,)
    finally:
        try:
            if created:
                _run([*base, "--profile", "isolated-gateway", "down",
                      "--volumes", "--remove-orphans"], env=env, timeout=120)
                _no_project_resources(project)
        finally:
            # 只清理 pytest 本次生成的 Secret 和 CA；不可碰既有 G3b/G5 資源。
            shutil.rmtree(secret_dir, ignore_errors=False)
            for folder in tmp_path.glob("ca-*"):
                if folder.is_dir() and folder.parent == tmp_path:
                    shutil.rmtree(folder)
