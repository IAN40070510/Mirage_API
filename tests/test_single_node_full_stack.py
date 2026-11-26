"""SINGLE-NODE-01／02：隔離 D-74 Compose 九容器、真 SCRAM 與 mTLS 啟動試驗。"""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import ctypes
import ctypes.util
import hashlib
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
from threading import Barrier
import time
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from deception.api.fingerprint import fingerprint_httpx_request
from deception.domains.ecommerce.carts import SyntheticCarts
from deception.domains.ecommerce.inventory import SyntheticInventory
from deception.world import (
    PostgresProjectionRegistry, ProjectionCompatibilityProfile, ProjectionEvidence,
)
from deception.world.session import SessionBinding
from test_operation_binding import PINNED_HTTP_CASES
from test_trusted_session import encode
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
    "world_snapshots,world_commit_receipts,trusted_key_revocations,"
    "protected_candidate_promotions",
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


def _material(root: Path, dsns: dict[str, str], pg_password: str,
              signing_key: Ed25519PrivateKey) -> dict[str, str | Path]:
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
            "catalog": {"known": {"sku": "sku-1", "unit_price": 100},
                        "v1": {"sku": "sku-1", "unit_price": 100}},
            "inventory": {"sku-1": 5},
            "native_context": {"region_id": "reg_mirage_usd",
                               "sales_channel_id": "sc_mirage",
                               "email": "ci@example.invalid", "metadata": {}},
        }, separators=(",", ":")),
        "medusa_publishable_key": "pk_disposable_single_node_only",
    }
    material["verifier_keys"] = json.dumps({
        "test": base64.b64encode(signing_key.public_key().public_bytes_raw()).decode("ascii"),
    })
    material["publisher_evidence"] = json.dumps({
        name: {
            "source_spec_sha256": hashlib.sha256(
                ("single-node-source:" + name).encode("ascii")
            ).hexdigest(),
            "compatibility_profile": {
                "profile_id": "disposable", "profile_version": "1",
                "profile_sha256": hashlib.sha256(
                    ("single-node-profile:" + name).encode("ascii")
                ).hexdigest(), "platform_id": name,
                "platform_version": "1", "source_spec_sha256": hashlib.sha256(
                    ("single-node-source:" + name).encode("ascii")
                ).hexdigest(),
                "world_schema_version": "1", "domain_adapter_version": "1",
            },
            "projection_contract_hash": hashlib.sha256(
                ("single-node-contract:" + name).encode("ascii")
            ).hexdigest(),
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


def _seed_disposable_native_inventory(admin_dsn: str,
                                      material: dict[str, str | Path]) -> None:
    """僅對本次全新拋棄式 DB 建立真 World 與投影 Registry，不替正式 Profile 背書。"""
    contract = json.loads(str(material["publisher_evidence"]))["synthetic-inventory"]
    profile = ProjectionEvidence(
        source_spec_sha256=contract["source_spec_sha256"],
        compatibility_profile=ProjectionCompatibilityProfile(
            **contract["compatibility_profile"],
        ),
        projection_contract_hash=contract["projection_contract_hash"],
        official_schema_valid=contract["official_schema_valid"],
        effective_projection_valid=contract["effective_projection_valid"],
    )
    PostgresProjectionRegistry(admin_dsn).ensure_registered_batch((profile,))
    binding = SessionBinding(
        environment_id="disposable", deployment_id="isolated",
        session_id="session", session_epoch=1, access_mode="inventory",
    )
    SyntheticInventory(admin_dsn).resolve(
        binding, {"inventory": {"sku-1": 4}, "reservations": {}},
        now=int(time.time()), ttl=600,
    )


def _seed_disposable_native_cart(admin_dsn: str,
                                 material: dict[str, str | Path],
                                 *, medusa: bool = False) -> None:
    """建立短期 Creator Cart World；Medusa 模式再註冊獨立的原生來源 Profile。"""
    contracts = json.loads(str(material["publisher_evidence"]))
    platforms = ("synthetic-carts", "medusa-native-cart") if medusa else ("synthetic-carts",)
    profiles = tuple(ProjectionEvidence(
        source_spec_sha256=contracts[name]["source_spec_sha256"],
        compatibility_profile=ProjectionCompatibilityProfile(
            **contracts[name]["compatibility_profile"],
        ),
        projection_contract_hash=contracts[name]["projection_contract_hash"],
        official_schema_valid=contracts[name]["official_schema_valid"],
        effective_projection_valid=contracts[name]["effective_projection_valid"],
    ) for name in platforms)
    PostgresProjectionRegistry(admin_dsn).ensure_registered_batch(profiles)
    state = json.loads(str(material["cart_initial_state"]))
    binding = SessionBinding(
        environment_id="disposable", deployment_id="isolated",
        session_id="cart-creator", session_epoch=1, access_mode="cart",
    )
    SyntheticCarts(admin_dsn).resolve(
        binding, {"catalog": state["catalog"], "inventory": state["inventory"],
                  "reservations": {}}, now=int(time.time()), ttl=600,
    )


def _sign_disposable_native_request(
        client: httpx.Client, origin: str, signer: Ed25519PrivateKey,
        *, method: str = "GET", path: str = "/synthetic/inventory/sku-1",
        body: dict | None = None, access_mode: str = "inventory",
        session_id: str = "session", resource_id: str | None = None,
        extra_headers: dict[str, str] | None = None) -> httpx.Request:
    """依真正原生 Method／URL／JSON Body 簽一次 JWS，私鑰僅留測試記憶體。"""
    jti = uuid4().hex
    request_id = "sn-compose-valid-" + jti
    headers = {"x-request-id": request_id}
    if extra_headers is not None:
        headers.update(extra_headers)
    kwargs = {}
    if body is not None:
        headers["content-type"] = "application/json"
        kwargs["content"] = json.dumps(body, separators=(",", ":")).encode("utf-8")
    outgoing = client.build_request(
        method, origin + path, headers=headers, **kwargs,
    )
    now = int(time.time())
    claims = {
        "iss": "gateway", "aud": "mirage", "iat": now - 5, "nbf": now - 5,
        "exp": now + 45, "jti": jti, "environment_id": "disposable",
        "deployment_id": "isolated", "session_id": session_id, "session_epoch": 1,
        "access_mode": access_mode,
        "request_fingerprint": fingerprint_httpx_request(outgoing, request_id),
        "assessment_id": "isolated", "assessment_digest": "b" * 64,
    }
    if resource_id is not None:
        claims["resource_id"] = resource_id
    prefix = encode({
        "alg": "Ed25519", "kid": "test", "protocol_version": "1.1",
        "typ": "mirage-trusted-session+jwt",
    }) + "." + encode(claims)
    signature = base64.urlsafe_b64encode(
        signer.sign(prefix.encode("ascii")),
    ).decode("ascii").rstrip("=")
    outgoing.headers["x-trusted-session"] = prefix + "." + signature
    return outgoing


def _verify_required_headers_for_all_routes(client: httpx.Client, origin: str) -> None:
    """核對三平台固定路由缺任一必要 Header 時的 Gateway 原生拒絕。"""
    for case_id, _, method, path, _, _ in PINNED_HTTP_CASES:
        for headers, reason in (
                ({"x-request-id": uuid4().hex}, "gateway_signed_session_required"),
                ({"x-trusted-session": "disposable"}, "gateway_request_id_required")):
            response = client.request(method, origin + path, headers=headers)
            assert response.status_code == 403, (case_id, reason, response.status_code)
            assert response.json() == {"detail": reason}, (case_id, reason)


def _verify_client_reset_after_native_status(
        client: httpx.Client, origin: str, signer: Ed25519PrivateKey, ca: Path) -> None:
    """真 Client 讀到原生 200 後以 TCP RST 關閉，重送相同 JWS 必須遭拒。"""
    signed = _sign_disposable_native_request(client, origin, signer)
    context = ssl.create_default_context(cafile=str(ca))
    with socket.create_connection(("127.0.0.1", signed.url.port), timeout=30) as tcp:
        with context.wrap_socket(tcp, server_hostname="localhost") as tls:
            # 使用已簽請求的原始 Header 和 URL，保持 Verifier 核對的指紋。
            headers = b"".join(k + b": " + v + b"\r\n" for k, v in signed.headers.raw)
            tls.sendall(b"GET " + signed.url.raw_path + b" HTTP/1.1\r\n" + headers + b"\r\n")
            prefix = b"HTTP/1.1 200 "
            for expected in prefix:
                assert tls.recv(1) == bytes([expected]), "native status missing before reset"
            tls.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    replay = client.send(signed)
    assert replay.status_code == 503
    assert replay.json() == {"detail": "gateway_delivery_unverifiable"}


def _exercise_disposable_inventory_native_matrix(
        client: httpx.Client, origin: str, signer: Ed25519PrivateKey) -> int:
    """在真九容器驗證 I-01～I-04 的原生 200／409、World Commit 與重放拒絕。"""
    signed = []

    missing_sku = _sign_disposable_native_request(
        client, origin, signer, path="/synthetic/inventory/not-in-world",
    )
    unknown = client.send(missing_sku)
    assert unknown.status_code == 409, unknown.text
    assert unknown.content == b'{"code":"unknown_synthetic_sku"}'
    assert unknown.headers["content-type"] == "application/json"
    signed.append(missing_sku)

    attempt = str(uuid4())
    reserve = _sign_disposable_native_request(
        client, origin, signer, method="POST",
        path="/synthetic/inventory/reservations",
        body={"sku": "sku-1", "quantity": 2, "expected_version": 1,
              "idempotency_key": "single-node-reserve-" + uuid4().hex,
              "commit_attempt_id": attempt},
    )
    reserved = client.send(reserve)
    assert reserved.status_code == 200, reserved.text
    reservation = reserved.json()
    assert reservation["commit_attempt_id"] == attempt
    assert reservation["state_version"] == 2
    reservation_id = reservation["reservation"]["reservation_id"]
    assert reservation["reservation"]["sku"] == "sku-1"
    signed.append(reserve)

    history = _sign_disposable_native_request(
        client, origin, signer, path="/synthetic/operations/" + attempt,
    )
    historical = client.send(history)
    assert historical.status_code == 200, historical.text
    assert historical.json()["commit_attempt_id"] == attempt
    signed.append(history)

    absent = _sign_disposable_native_request(
        client, origin, signer, path="/synthetic/operations/" + str(uuid4()),
    )
    absent_history = client.send(absent)
    assert absent_history.status_code == 409, absent_history.text
    assert absent_history.content == b'{"code":"operation_not_found"}'
    signed.append(absent)

    cancel_path = "/synthetic/inventory/reservations/" + reservation_id + "/cancel"
    cancel = _sign_disposable_native_request(
        client, origin, signer, method="POST", path=cancel_path,
        body={"expected_version": 2,
              "idempotency_key": "single-node-cancel-" + uuid4().hex,
              "commit_attempt_id": str(uuid4())},
    )
    cancelled = client.send(cancel)
    assert cancelled.status_code == 200, cancelled.text
    assert cancelled.json()["state_version"] == 3
    assert cancelled.json()["reservation"]["reservation_id"] == reservation_id
    assert cancelled.json()["reservation"]["status"] == "cancelled"
    signed.append(cancel)

    cancel_again = _sign_disposable_native_request(
        client, origin, signer, method="POST", path=cancel_path,
        body={"expected_version": 3,
              "idempotency_key": "single-node-recancel-" + uuid4().hex,
              "commit_attempt_id": str(uuid4())},
    )
    cancelled_twice = client.send(cancel_again)
    assert cancelled_twice.status_code == 409, cancelled_twice.text
    assert cancelled_twice.content == b'{"code":"reservation_not_active"}'
    signed.append(cancel_again)

    unknown_reserve = _sign_disposable_native_request(
        client, origin, signer, method="POST",
        path="/synthetic/inventory/reservations",
        body={"sku": "not-in-world", "quantity": 1, "expected_version": 3,
              "idempotency_key": "single-node-unknown-" + uuid4().hex,
              "commit_attempt_id": str(uuid4())},
    )
    rejected = client.send(unknown_reserve)
    assert rejected.status_code == 409, rejected.text
    assert rejected.content == b'{"code":"unknown_synthetic_sku"}'
    signed.append(unknown_reserve)

    # G6：兩份不同 JWS 都已驗證，但同一 World Version 只可提交一次。
    concurrent = [
        _sign_disposable_native_request(
            client, origin, signer, method="POST",
            path="/synthetic/inventory/reservations",
            body={"sku": "sku-1", "quantity": 1, "expected_version": 3,
                  "idempotency_key": "single-node-race-" + str(index) + "-" + uuid4().hex,
                  "commit_attempt_id": str(uuid4())},
        ) for index in range(2)
    ]
    barrier = Barrier(2)

    def send_parallel(original: httpx.Request) -> httpx.Response:
        """同時送出兩個已簽名的同版本請求，製造真 DB CAS 競態。"""
        barrier.wait(timeout=10)
        return client.send(original)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(send_parallel, concurrent))
    assert sorted(response.status_code for response in results) == [200, 503], (
        [(response.status_code, response.text) for response in results]
    )
    race_winner = next(response for response in results if response.status_code == 200)
    race_loser = next(response for response in results if response.status_code == 503)
    assert race_winner.json()["state_version"] == 4
    assert race_winner.json()["reservation"]["sku"] == "sku-1"
    assert race_loser.json() == {"detail": "gateway_delivery_unverifiable"}
    signed.extend(concurrent)

    read_after_race = _sign_disposable_native_request(client, origin, signer)
    latest = client.send(read_after_race)
    assert latest.status_code == 200, latest.text
    assert latest.json() == {"sku": "sku-1", "available": 3, "state_version": 4}
    signed.append(read_after_race)

    for original in signed:
        replay = client.send(original)
        assert replay.status_code == 503
        assert replay.json() == {"detail": "gateway_delivery_unverifiable"}
    # 兩份 CAS JWS 都進 Ingress，但敗者不能建立 Candidate／Admission／Lease。
    return len(signed) - 1


def _exercise_disposable_cart_native_matrix(
        client: httpx.Client, origin: str, signer: Ed25519PrivateKey,
        admin_dsn: str) -> int:
    """從 Creator→Cart→Order 經九容器執行 C-01～C-09，驗原生 200／409 與 CAS。"""
    world = SyntheticCarts(admin_dsn)
    creator = SessionBinding(
        environment_id="disposable", deployment_id="isolated",
        session_id="cart-creator", session_epoch=1, access_mode="cart",
    )
    native_count = 0

    def native(method: str, path: str, *, body: dict | None = None,
               binding: SessionBinding = creator, expected: int = 200,
               code: str | None = None) -> dict:
        """對固定 Cart／Order 原生請求簽一次 JWS，核對 Lease 成功並拒絕重放。"""
        nonlocal native_count
        original = _sign_disposable_native_request(
            client, origin, signer, method=method, path=path, body=body,
            access_mode="cart", session_id=binding.session_id,
            resource_id=binding.resource_id,
        )
        response = client.send(original)
        assert response.status_code == expected, (
            method, path, expected, response.status_code, response.text
        )
        if code is not None:
            assert response.content == json.dumps(
                {"code": code}, separators=(",", ":"),
            ).encode("utf-8")
        else:
            assert response.headers["content-type"] == "application/json"
        replay = client.send(original)
        assert replay.status_code == 503
        assert replay.json() == {"detail": "gateway_delivery_unverifiable"}
        native_count += 1
        return response.json()

    def mutation(version: int, name: str, **fields) -> dict:
        """只為本次測試生成唯一 Attempt 與冪等鍵，版本值由既定案例明示。"""
        return {**fields, "expected_version": version,
                "idempotency_key": "sn-" + name + "-" + uuid4().hex,
                "commit_attempt_id": str(uuid4())}

    def fail_closed(method: str, path: str, *, body: dict | None = None,
                    binding: SessionBinding = creator) -> None:
        """未授權 Creator／Cart Scope 或舊版 CAS 必須由真 Gateway 503 阻斷。"""
        original = _sign_disposable_native_request(
            client, origin, signer, method=method, path=path, body=body,
            access_mode="cart", session_id=binding.session_id,
            resource_id=binding.resource_id,
        )
        denied = client.send(original)
        assert denied.status_code == 503, (method, path, denied.text)
        assert denied.json() == {"detail": "gateway_delivery_unverifiable"}
        assert client.send(original).status_code == 503

    created = native("POST", "/synthetic/carts", body={})
    assert created["state_version"] == 1
    cart_id = created["cart"]["id"]
    assert cart_id.startswith("cart_")
    cart = world.resource_binding(
        cart_id, environment_id="disposable", deployment_id="isolated",
        now=int(time.time()),
    )
    assert cart.access_mode == "cart" and cart.resource_id == cart_id
    cart_path = "/synthetic/carts/" + cart_id
    fetched = native("GET", cart_path, binding=cart)
    assert fetched["cart"] == created["cart"]
    assert fetched["state_version"] == 1

    # Creator 的原始 Session 不得偷用新 Cart 的派生資源權限。
    fail_closed("GET", cart_path)

    assert native(
        "POST", cart_path + "/line-items", binding=cart, expected=409,
        code="unknown_synthetic_variant",
        body=mutation(1, "unknown", variant_id="absent", quantity=1),
    ) == {"code": "unknown_synthetic_variant"}
    add_attempt = str(uuid4())
    added = native(
        "POST", cart_path + "/line-items", binding=cart,
        body={**mutation(1, "add", variant_id="v1", quantity=2),
              "commit_attempt_id": add_attempt},
    )
    assert added["state_version"] == 2
    item = added["cart"]["items"][0]
    assert item["quantity"] == 2
    fail_closed(
        "POST", cart_path + "/line-items", binding=cart,
        body=mutation(1, "stale", variant_id="v1", quantity=1),
    )
    assert native(
        "GET", cart_path + "/operations/" + add_attempt, binding=cart,
    )["commit_attempt_id"] == add_attempt
    assert native(
        "GET", cart_path + "/operations/" + str(uuid4()), binding=cart,
        expected=409, code="operation_not_found",
    ) == {"code": "operation_not_found"}

    item_path = cart_path + "/line-items/" + item["id"]
    updated = native(
        "POST", item_path, binding=cart,
        body=mutation(2, "update", quantity=3),
    )
    assert updated["state_version"] == 3
    assert updated["cart"]["items"][0]["quantity"] == 3
    assert native(
        "POST", cart_path + "/line-items/item_" + "f" * 32,
        binding=cart, expected=409, code="cart_item_not_found",
        body=mutation(3, "update-missing", quantity=1),
    ) == {"code": "cart_item_not_found"}
    removed = native(
        "DELETE", item_path, binding=cart, body=mutation(3, "delete"),
    )
    assert removed["state_version"] == 4
    assert removed["cart"]["items"] == []
    assert native(
        "DELETE", item_path, binding=cart, expected=409,
        code="cart_item_not_found", body=mutation(4, "delete-missing"),
    ) == {"code": "cart_item_not_found"}
    assert native(
        "POST", cart_path + "/complete", binding=cart, expected=409,
        code="empty_synthetic_cart", body=mutation(4, "empty-complete"),
    ) == {"code": "empty_synthetic_cart"}
    assert native(
        "POST", cart_path + "/line-items", binding=cart,
        body=mutation(4, "refill", variant_id="v1", quantity=1),
    )["state_version"] == 5
    completed = native(
        "POST", cart_path + "/complete", binding=cart,
        body=mutation(5, "complete"),
    )
    assert completed["state_version"] == 6
    order_id = completed["order"]["id"]
    assert completed["order"]["cart_id"] == cart_id
    order = world.resource_binding(
        order_id, environment_id="disposable", deployment_id="isolated",
        now=int(time.time()),
    )
    order_path = "/synthetic/orders/" + order_id
    assert native("GET", order_path, binding=order)["order"] == completed["order"]
    fail_closed("GET", order_path, binding=cart)
    cancelled = native(
        "POST", order_path + "/cancel", binding=order,
        body=mutation(6, "order-cancel"),
    )
    assert cancelled["state_version"] == 7
    assert cancelled["order"]["status"] == "cancelled"
    assert native(
        "POST", order_path + "/cancel", binding=order, expected=409,
        code="order_not_cancellable", body=mutation(7, "order-recancel"),
    ) == {"code": "order_not_cancellable"}

    # 不同簽章但相同 Cart 版本的並行 mutation 只有一筆能取得 Lease。
    race_created = native("POST", "/synthetic/carts", body={})
    race_cart_id = race_created["cart"]["id"]
    race_cart = world.resource_binding(
        race_cart_id, environment_id="disposable", deployment_id="isolated",
        now=int(time.time()),
    )
    race_path = "/synthetic/carts/" + race_cart_id
    concurrent = [
        _sign_disposable_native_request(
            client, origin, signer, method="POST", path=race_path + "/line-items",
            body=mutation(1, "race-" + str(index), variant_id="v1", quantity=1),
            access_mode="cart", session_id=race_cart.session_id,
            resource_id=race_cart.resource_id,
        ) for index in range(2)
    ]
    barrier = Barrier(2)

    def send_parallel(original: httpx.Request) -> httpx.Response:
        """同時放行真 Client HTTPS 的兩張 Cart JWS，觀察 PostgreSQL CAS 結果。"""
        barrier.wait(timeout=10)
        return client.send(original)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(send_parallel, concurrent))
    assert sorted(response.status_code for response in results) == [200, 503], (
        [(response.status_code, response.text) for response in results]
    )
    winner = next(response for response in results if response.status_code == 200)
    loser = next(response for response in results if response.status_code == 503)
    assert winner.json()["state_version"] == 2
    assert len(winner.json()["cart"]["items"]) == 1
    assert loser.json() == {"detail": "gateway_delivery_unverifiable"}
    for original in concurrent:
        replay = client.send(original)
        assert replay.status_code == 503
        assert replay.json() == {"detail": "gateway_delivery_unverifiable"}
    after_race = native("GET", race_path, binding=race_cart)
    assert after_race["state_version"] == 2
    assert after_race["cart"]["items"] == winner.json()["cart"]["items"]
    assert native_count == 18
    return native_count + 1


def _exercise_disposable_medusa_native_matrix(
        client: httpx.Client, origin: str, signer: Ed25519PrivateKey,
        admin_dsn: str) -> int:
    """在真九容器驗 M-01～M-07 的 Medusa 原生 200／400／404 與派生能力。"""
    creator = SessionBinding(
        environment_id="disposable", deployment_id="isolated",
        session_id="cart-creator", session_epoch=1, access_mode="cart",
    )
    world = SyntheticCarts(admin_dsn)
    publishable_key = "pk_disposable_single_node_only"
    native_count = 0

    def native(method: str, path: str, *, body: dict | None = None,
               binding: SessionBinding = creator, expected: int = 200) -> dict:
        """固定 Publishable Key 也納入 Ed25519 Fingerprint，核對真 Medusa 回應。"""
        nonlocal native_count
        original = _sign_disposable_native_request(
            client, origin, signer, method=method, path=path, body=body,
            access_mode="cart", session_id=binding.session_id,
            resource_id=binding.resource_id,
            extra_headers={"content-type": "application/json",
                           "x-publishable-api-key": publishable_key},
        )
        response = client.send(original)
        assert response.status_code == expected, (
            method, path, expected, response.status_code, response.text
        )
        assert response.headers["content-type"] == "application/json"
        replay = client.send(original)
        assert replay.status_code == 503
        assert replay.json() == {"detail": "gateway_delivery_unverifiable"}
        native_count += 1
        return response.json()

    def fail_closed(method: str, path: str, *, body: dict | None = None,
                    binding: SessionBinding = creator,
                    key: str = publishable_key) -> None:
        """錯 Publishable Key、越權派生資源及無 Error Source 一律不能發送。"""
        original = _sign_disposable_native_request(
            client, origin, signer, method=method, path=path, body=body,
            access_mode="cart", session_id=binding.session_id,
            resource_id=binding.resource_id,
            extra_headers={"content-type": "application/json",
                           "x-publishable-api-key": key},
        )
        response = client.send(original)
        assert response.status_code == 503, (method, path, response.text)
        assert response.json() == {"detail": "gateway_delivery_unverifiable"}

    created = native(
        "POST", "/store/carts",
        body={"email": "ci@example.invalid", "items": []},
    )
    assert set(created) == {"cart"}
    cart_id = created["cart"]["id"]
    assert created["cart"]["items"] == []
    cart = world.resource_binding(
        cart_id, environment_id="disposable", deployment_id="isolated",
        now=int(time.time()),
    )
    assert cart.resource_id == cart_id
    cart_path = "/store/carts/" + cart_id
    assert native("GET", cart_path, binding=cart)["cart"]["id"] == cart_id
    fail_closed("GET", cart_path, binding=cart, key="incorrect_public_key")
    fail_closed("GET", cart_path)

    line_path = cart_path + "/line-items"
    invalid = native(
        "POST", line_path, binding=cart, expected=400,
        body={"variant_id": "known", "quantity": 0},
    )
    assert invalid == {
        "message": "The requested cart operation is not supported.",
        "type": "invalid_data",
    }
    missing = native(
        "POST", line_path, binding=cart, expected=404,
        body={"variant_id": "missing", "quantity": 1},
    )
    assert missing == {
        "message": "The requested cart operation could not be completed.",
        "type": "not_found",
    }
    added = native(
        "POST", line_path, binding=cart,
        body={"variant_id": "known", "quantity": 2},
    )
    assert added["cart"]["id"] == cart_id
    item = added["cart"]["items"][0]
    assert item["quantity"] == 2
    item_path = line_path + "/" + item["id"]
    updated = native(
        "POST", item_path, binding=cart, body={"quantity": 3},
    )
    assert updated["cart"]["items"][0]["quantity"] == 3
    deleted = native("DELETE", item_path, binding=cart)
    assert set(deleted) == {"id", "object", "deleted", "parent"}
    assert deleted["id"] == item["id"]
    assert deleted["deleted"] is True
    assert deleted["parent"]["items"] == []
    fail_closed("DELETE", item_path, binding=cart)
    fail_closed("POST", cart_path + "/complete", binding=cart)

    refilled = native(
        "POST", line_path, binding=cart,
        body={"variant_id": "known", "quantity": 1},
    )
    assert refilled["cart"]["items"][0]["quantity"] == 1
    completed = native("POST", cart_path + "/complete", binding=cart)
    assert completed["type"] == "order"
    order_id = completed["order"]["id"]
    assert completed["order"]["payment_status"] == "not_paid"
    assert completed["order"]["fulfillment_status"] == "not_fulfilled"
    order = world.resource_binding(
        order_id, environment_id="disposable", deployment_id="isolated",
        now=int(time.time()),
    )
    order_path = "/store/orders/" + order_id
    read_order = native("GET", order_path, binding=order)
    assert read_order["order"]["id"] == order_id
    assert read_order["order"]["customer_id"] is None
    fail_closed("GET", order_path, binding=cart)
    assert native_count == 10
    return native_count


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


def _isolated_receipt_sender_override(tmp_path: Path, project: str,
                                      database: str) -> Path:
    """只在亂數拋棄式 DB 測試專案覆寫 Sender CLI，正式 Compose 永不載入。"""
    assert re.fullmatch(r"mirage-sn-full-[0-9a-f]{12}", project)
    assert re.fullmatch(r"mirage_sn_full_[0-9a-f]{10}", database)
    script = """
import os
from pathlib import Path
from psycopg.conninfo import conninfo_to_dict
from deception.security.protected_rpc import (
    create_receipt_proxy_sender_candidate_app, serve_fixed_sender_mtls,
)
from deception.security.protected_services import create_sender_service
from deception.world.protected_send import PostgresProtectedSender

config = os.environ
assert config.get("MIRAGE_TRUSTED_SEND_ENABLE") == "false"
assert config.get("MIRAGE_SINGLE_NODE_ISOLATED_CANDIDATE_ONLY") == "true"
assert config.get("MIRAGE_SINGLE_NODE_CANDIDATE_PROJECT", "").startswith("mirage-sn-full-")
assert config.get("MIRAGE_SINGLE_NODE_CANDIDATE_DATABASE", "").startswith("mirage_sn_full_")
assert config.get("MIRAGE_RESTORE_PROFILE") == "standard_single_node"
dsn = Path(config["MIRAGE_G4_SENDER_DSN_FILE"]).read_text(encoding="utf-8").strip()
assert conninfo_to_dict(dsn).get("dbname") == config["MIRAGE_SINGLE_NODE_CANDIDATE_DATABASE"]
# 沿用正式 Sender 的 Login、SCRAM、ACL、Restore Profile 與可選 Marker 前置檢查。
create_sender_service(config)
sender = PostgresProtectedSender(dsn, expected_login=config["MIRAGE_G4_SENDER_LOGIN"])
app = create_receipt_proxy_sender_candidate_app(sender=sender)
serve_fixed_sender_mtls(
    app=app, host=config["MIRAGE_G3B_BIND_HOST"],
    port=int(config["MIRAGE_G3B_BIND_PORT"]),
    server_cert=Path(config["MIRAGE_G4_SENDER_SERVER_CERT_FILE"]),
    server_key=Path(config["MIRAGE_G4_SENDER_SERVER_KEY_FILE"]),
    sender_client_ca=Path(config["MIRAGE_G4_SENDER_CLIENT_CA_FILE"]),
)
"""
    override = tmp_path / "isolated-receipt-sender.override.yaml"
    override.write_text(yaml.safe_dump({"services": {"sender": {
        "command": ["python", "-c", script],
        "environment": {
            "MIRAGE_SINGLE_NODE_ISOLATED_CANDIDATE_ONLY": "true",
            "MIRAGE_SINGLE_NODE_CANDIDATE_PROJECT": project,
            "MIRAGE_SINGLE_NODE_CANDIDATE_DATABASE": database,
        },
    }}}), encoding="utf-8")
    override.chmod(0o600)
    return override


@pytest.mark.parametrize("sender_mode", (
    "sealed", "isolated_receipt_candidate", "isolated_cart_candidate",
    "isolated_medusa_candidate",
))
def test_true_nine_service_compose_sealed_stack_with_physical_scram_and_tls(
        tmp_path, sender_mode: str):
    """各以拋棄式九容器驗證正式 Sender 封閉，及測試專用 Receipt 起送候選。"""
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
    if sender_mode != "sealed":
        # 只針對本次隨機 Project／DB，既不改標準部署檔，也不賦予正式 Sender 開關。
        base.extend(["-f", str(_isolated_receipt_sender_override(
            tmp_path, project, database,
        ))])
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
        signer = Ed25519PrivateKey.generate()
        material = _material(tmp_path, dsns, password, signer)
        _seed_disposable_native_inventory(admin_dsn, material)
        if sender_mode in ("isolated_cart_candidate", "isolated_medusa_candidate"):
            _seed_disposable_native_cart(
                admin_dsn, material, medusa=sender_mode == "isolated_medusa_candidate",
            )
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
            if sender_mode == "sealed":
                _verify_required_headers_for_all_routes(client, origin)
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
        with httpx.Client(verify=ssl.create_default_context(cafile=str(ca)),
                          timeout=30, trust_env=False) as client:
            authorized = _sign_disposable_native_request(client, origin, signer)
            actual = client.send(authorized)
            expected_authorizations = 1
            if sender_mode == "sealed":
                # 正式 CLI 刻意封閉，不能鑄造 Send Lease 或任何原生業務 bytes。
                assert actual.status_code == 503
                assert actual.json() == {"detail": "gateway_delivery_unverifiable"}
                assert b"available" not in actual.content
            else:
                # Test-only ASGI 候選：由真 Sender 起送已 Pin 原生 HTTP，而非 Gateway 仿造。
                assert actual.status_code == 200
                assert actual.headers["content-type"].startswith("application/json")
                assert actual.json() == {"sku": "sku-1", "available": 4,
                                         "state_version": 1}
                if sender_mode == "isolated_cart_candidate":
                    expected_authorizations += _exercise_disposable_cart_native_matrix(
                        client, origin, signer, admin_dsn,
                    )
                elif sender_mode == "isolated_medusa_candidate":
                    expected_authorizations += _exercise_disposable_medusa_native_matrix(
                        client, origin, signer, admin_dsn,
                    )
                else:
                    _verify_client_reset_after_native_status(client, origin, signer, ca)
                    expected_authorizations += 1
                    expected_authorizations += _exercise_disposable_inventory_native_matrix(
                        client, origin, signer,
                    )
            replay = client.send(authorized)
            assert replay.status_code == 503
            assert replay.json() == {"detail": "gateway_delivery_unverifiable"}
        with psycopg.connect(admin_dsn) as conn:
            if sender_mode == "isolated_medusa_candidate":
                for table in ("candidate_records", "protected_candidate_promotions",
                              "response_admissions", "protected_send_leases"):
                    assert conn.execute("SELECT count(*) FROM " + table).fetchone() == (
                        expected_authorizations,
                    )
                assert conn.execute(
                    "SELECT count(*) FROM protected_cart_creations"
                ).fetchone() == (1,)
                assert conn.execute(
                    "SELECT count(*) FROM protected_world_commit_sources"
                ).fetchone() == (5,)
                assert conn.execute(
                    "SELECT count(*) FROM protected_medusa_rejection_sources"
                ).fetchone() == (2,)
                return
            if sender_mode == "isolated_cart_candidate":
                for table in ("candidate_records", "protected_candidate_promotions",
                              "response_admissions", "protected_send_leases"):
                    assert conn.execute("SELECT count(*) FROM " + table).fetchone() == (
                        expected_authorizations,
                    )
                assert conn.execute(
                    "SELECT count(*) FROM protected_cart_creations"
                ).fetchone() == (2,)
                # 同版雙 JWS 敗者不可生成第八筆 Cart／Order World Commit。
                assert conn.execute(
                    "SELECT count(*) FROM protected_world_commit_sources"
                ).fetchone() == (7,)
                assert conn.execute(
                    "SELECT count(*) FROM protected_world_rejection_sources"
                ).fetchone() == (5,)
                return
            for table in ("replay_entries", "ingress_receipts", "read_admissions",
                          "protected_world_read_sources", "candidate_records",
                          "protected_candidate_promotions", "response_admissions"):
                # 每個原生 409 也需授權 Pin，而非 Gateway 仿造錯誤。
                expected = expected_authorizations + int(
                    sender_mode == "isolated_receipt_candidate" and
                    table in ("replay_entries", "ingress_receipts", "read_admissions",
                              "protected_world_read_sources")
                )
                assert conn.execute("SELECT count(*) FROM " + table).fetchone() == (
                    expected,
                )
            assert conn.execute("SELECT count(*) FROM protected_send_leases").fetchone() == (
                0 if sender_mode == "sealed" else expected_authorizations,
            )
            assert conn.execute(
                "SELECT count(*) FROM protected_world_commit_sources"
            ).fetchone() == (0 if sender_mode == "sealed" else 3,)
            assert conn.execute(
                "SELECT count(*) FROM protected_world_rejection_sources"
            ).fetchone() == (0 if sender_mode == "sealed" else 2,)
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
