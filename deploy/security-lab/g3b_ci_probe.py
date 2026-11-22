"""四個真容器的 mTLS／ACL／Secret／Network 實測與隔離 HTTP 對帳。"""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import re
import socket
import ssl
import subprocess
import time
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import httpx
import psycopg
import yaml

from deception.api.fingerprint import fingerprint_httpx_request
from deception.security.operation_binding import _pinned_medusa_operations
from deception.domains.ecommerce.cart_http import cart_specification
from deception.domains.ecommerce.inventory_http import inventory_specification


def _twenty_native_routes() -> tuple[tuple[str, str, str, str], ...]:
    """由三份固定 Operation Registry 推導平台／方法／路由／Handler 的 20 個實測案例。"""
    cases = []
    for platform, specification in (
            ("synthetic-inventory", inventory_specification()),
            ("synthetic-carts", cart_specification())):
        for path, methods in specification["paths"].items():
            for method, data in methods.items():
                cases.append((platform, method.upper(), "/synthetic" + path,
                              data["operationId"]))
    for path, method, operation_id in _pinned_medusa_operations():
        cases.append(("medusa-native-cart", method.upper(), path, operation_id))
    if len(cases) != 20 or len(set(cases)) != 20:
        raise RuntimeError("g3b_ci_twenty_route_contract_drift")
    return tuple(cases)


def _probe_path(template: str) -> str:
    """將固定規格的變數只映射成合法不敏感 CI ID，不採用 Runtime 提供的路由。"""
    placeholders = {
        "reservation_id": "a" * 32, "attempt": str(uuid4()),
        "sku": "sku-1", "cart_id": "cart_" + "a" * 32,
        "item_id": "item_" + "b" * 32, "order_id": "order_" + "c" * 32,
        "id": "cart_" + "a" * 32, "line_id": "b" * 32,
    }
    return re.sub(r"\{([a-z_]+)\}", lambda match: placeholders[match.group(1)], template)


def _encode(value: dict) -> str:
    """以固定 JSON 與 URL-safe base64 產生 CI Ed25519 JWS 的一個不可變欄位。"""
    data = json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _sign(key: Ed25519PrivateKey, *, fingerprint: str, session: str,
          mode: str, resource_id: str | None = None) -> str:
    """只為 CI 已緩衝的 HTTPX 原始訊息簽短效 JWS，不提供任意 claims 補簽。"""
    now = int(time.time())
    claims = {
        "iss": "gateway", "aud": "mirage", "iat": now - 5, "nbf": now - 5,
        "exp": now + 45, "jti": uuid4().hex, "environment_id": "env",
        "deployment_id": "deploy", "session_id": session, "session_epoch": 1,
        "access_mode": mode, "request_fingerprint": fingerprint,
        "assessment_id": "assessment", "assessment_digest": "b" * 64,
    }
    if resource_id is not None:
        claims["resource_id"] = resource_id
    prefix = _encode({"alg": "Ed25519", "kid": "old", "protocol_version": "1.1",
                      "typ": "mirage-trusted-session+jwt"}) + "." + _encode(claims)
    return prefix + "." + base64.urlsafe_b64encode(
        key.sign(prefix.encode("ascii"))).decode("ascii").rstrip("=")


def _gateway() -> None:
    """僅從 Gateway 私網進行真 TLS/JWS/Executor/Validator 連接、負面與重放測試。"""
    root = Path("/lab/probe")
    data = json.loads((root / "world.json").read_text(encoding="utf-8"))
    key = Ed25519PrivateKey.from_private_bytes((root / "signing.key").read_bytes())
    context = ssl.create_default_context(cafile=str(root / "gateway-ca.pem"))
    context.load_cert_chain(str(root / "gateway-client.pem"),
                            str(root / "gateway-client.key"))
    origin = "https://verifier:8443"
    with httpx.Client(verify=context, trust_env=False, timeout=8.0) as gateway:
        last_error = "no_connection_attempt"
        for _ in range(60):
            try:
                ready = gateway.get(origin + "/internal/ready")
                if ready.status_code == 200:
                    break
                last_error = "http_status_" + str(ready.status_code)
            except httpx.ConnectError as exc:
                last_error = type(exc).__name__ + ":" + str(exc)
            time.sleep(0.2)
        else:
            raise RuntimeError("g3b_ci_verifier_not_ready:" + last_error)
        if ready.json().get("trusted_send") != "disabled":
            raise RuntimeError("g3b_ci_trusted_send_enabled")
        if gateway.post(origin + "/internal/v1/execute", json={
                "operation": "forged", "binding": {}}).status_code != 503:
            raise RuntimeError("g3b_ci_verifier_runtime_rpc_open")
        for platform, method, template, operation_id in _twenty_native_routes():
            headers = {"x-request-id": "g3b-unsigned-" + uuid4().hex[:16]}
            if platform == "medusa-native-cart":
                headers["x-publishable-api-key"] = "pk_g3b_ci_only"
            if method != "GET":
                headers["content-type"] = "application/json"
            unsigned = gateway.build_request(
                method, origin + _probe_path(template), content=b"{}" if method != "GET" else b"",
                headers=headers,
            )
            status = gateway.send(unsigned).status_code
            if status != 403:
                raise RuntimeError("g3b_ci_unsigned_operation_not_denied:" + method + " " + template)
            # 每條直接 HTTPS 入口留下獨立路由證據；此紀錄僅證明無 JWS 拒絕，
            # 不代表 Executor 原生 2xx 或業務 4xx 已通過。
            print("G3B_ROUTE_UNAUTHENTICATED_DENIAL " + json.dumps({
                "platform": platform, "operation_id": operation_id,
                "method": method, "template": template, "status": status,
                "provenance": "gateway-mtls-verifier", "native_business_response": False,
            }, sort_keys=True))
        body = json.dumps({"sku": "sku-1", "quantity": 2, "expected_version": 1,
                           "idempotency_key": "g3b-container-once",
                           "commit_attempt_id": str(uuid4())}).encode("utf-8")
        request = gateway.build_request("POST", origin + "/synthetic/inventory/reservations",
                                        content=body, headers={
                                            "x-request-id": "g3b-ci-inventory",
                                            "content-type": "application/json",
                                        })
        if gateway.send(request).status_code != 403:
            raise RuntimeError("g3b_ci_missing_jws_not_rejected")
        fingerprint = fingerprint_httpx_request(request, "g3b-ci-inventory")
        request.headers["x-trusted-session"] = _sign(
            key, fingerprint=fingerprint, session="session", mode="inventory")
        tampered = gateway.build_request(
            "POST", origin + "/synthetic/inventory/reservations", content=body,
            headers={**dict(request.headers), "x-request-id": "forged-request-id"},
        )
        if gateway.send(tampered).status_code != 403:
            raise RuntimeError("g3b_ci_mutated_request_not_rejected")
        accepted = gateway.send(request)
        if accepted.status_code != 200:
            raise RuntimeError("g3b_ci_inventory_rpc_unverifiable:" + str(accepted.status_code))
        inventory_result = accepted.json()
        if (inventory_result.get("operation_id") != "reserveSyntheticInventory"
                or inventory_result.get("executor_result", {}).get("status") != "committed"):
            raise RuntimeError("g3b_ci_inventory_handler_mismatch")
        print("G3B_ROUTE_PROTECTED_COMMIT " + json.dumps({
            "operation_id": "reserveSyntheticInventory", "http_status": accepted.status_code,
            "executor_kind": inventory_result["executor_result"]["kind"],
            "source": "protected_world_commit_sources", "native_business_response": False,
        }, sort_keys=True))
        if gateway.send(request).status_code != 403:
            raise RuntimeError("g3b_ci_replay_accepted")
        for suffix, payload, status, template in (
                ("bad-item", b'{"variant_id":"known","quantity":0}', 400,
                 "native-cart-invalid"),
                ("missing-item", b'{"variant_id":"missing","quantity":1}', 404,
                 "native-cart-rejected")):
            path = "/store/carts/" + data["cart_id"] + "/line-items"
            raw = gateway.build_request(
                "POST", origin + path, content=payload, headers={
                    "x-request-id": "g3b-ci-" + suffix,
                    "content-type": "application/json",
                    "x-publishable-api-key": "pk_g3b_ci_only",
                })
            raw.headers["x-trusted-session"] = _sign(
                key, fingerprint=fingerprint_httpx_request(raw, "g3b-ci-" + suffix),
                session=data["cart_session"], mode="cart", resource_id=data["cart_id"],
            )
            response = gateway.send(raw)
            if response.status_code != 200:
                raise RuntimeError("g3b_ci_medusa_rejection_rpc_failed:" + str(response.status_code))
            outcome = response.json()
            result = outcome.get("executor_result", {})
            projection = outcome.get("native_projection", {})
            if (result.get("kind") != "medusa_rejection" or result.get("status_code") != status
                    or result.get("template_id") != template
                    or projection.get("status_code") != status
                    or projection.get("envelope_hash") != result.get("envelope_hash")
                    or gateway.send(raw).status_code != 403):
                raise RuntimeError("g3b_ci_medusa_rejection_proof_mismatch")
            print("G3B_ROUTE_PROTECTED_MEDUSA_REJECTION " + json.dumps({
                "operation_id": "PostCartsIdLineItems", "http_status": response.status_code,
                "validated_native_status": status, "template_id": template,
                "source": "protected_medusa_rejection_sources", "native_business_response": False,
            }, sort_keys=True))
    with httpx.Client(verify=ssl.create_default_context(cafile=str(root / "gateway-ca.pem")),
                      trust_env=False, timeout=2.0) as anonymous:
        try:
            anonymous.get(origin + "/internal/ready")
        except httpx.TransportError:
            pass
        else:
            raise RuntimeError("g3b_ci_anonymous_verifier_access")
    for hostname in ("inventory-executor", "cart-executor", "native-validator", "g3b-postgres"):
        try:
            socket.getaddrinfo(hostname, 8444)
        except socket.gaierror:
            continue
        raise RuntimeError("g3b_ci_gateway_network_leak:" + hostname)
    print("G3B_GATEWAY_PASS unsigned_routes=20/20 inventory_commit=1 medusa_400=1 "
          "medusa_404=1 replay=denied anonymous=denied execution_network=unreachable trusted_send=off")


def _docker_json(*args: str):
    """唯讀檢查 Docker 實際執行狀態；拒絕失敗命令或不合法 JSON。"""
    result = subprocess.run(["docker", *args], check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def _audit(root: Path) -> None:
    """核對四個真容器的 Mount、Network、非 root、無 Port 與物理 PG ACL。"""
    compose_file = Path("deploy/security-lab/g3b-compose.yaml")
    blueprint = yaml.safe_load(compose_file.read_text(encoding="utf-8"))
    actual_networks = {
        "g3b_gateway": "mirage-g3b-gateway-net",
        "g3b_execution": "mirage-g3b-execution-net",
        "g3b_database": "mirage-g3b-database-net",
    }
    for name, service in blueprint["services"].items():
        result = subprocess.run([
            "docker", "compose", "-f", str(compose_file),
            "-f", str(root / "ci-override.yaml"), "--profile", "g3b-isolated",
            "ps", "-q", name,
        ], check=True, capture_output=True, text=True)
        container_id = result.stdout.strip()
        if not container_id:
            raise RuntimeError("g3b_ci_service_missing:" + name)
        container = _docker_json("inspect", container_id)[0]
        expected_secrets = {"/run/secrets/" + secret for secret in service["secrets"]}
        mounted = {mount["Destination"] for mount in container["Mounts"]
                   if mount["Destination"].startswith("/run/secrets/")}
        networks = set(container["NetworkSettings"]["Networks"])
        expected_networks = {actual_networks[key] for key in service["networks"]}
        if (mounted != expected_secrets or networks != expected_networks
                or container["Config"]["User"] != service["user"]
                or container["HostConfig"]["ReadonlyRootfs"] is not True
                or container["HostConfig"].get("PortBindings")
                or container["State"]["Running"] is not True
                or "ALL" not in (container["HostConfig"].get("CapDrop") or [])):
            raise RuntimeError("g3b_ci_container_isolation_violation:" + name)
        visible = subprocess.run([
            "docker", "exec", container_id, "python", "-c",
            "import os,json; print(json.dumps(sorted(os.listdir('/run/secrets'))))",
        ], check=True, capture_output=True, text=True)
        if set(json.loads(visible.stdout)) != set(service["secrets"]):
            raise RuntimeError("g3b_ci_cross_role_secret_exposure:" + name)
    with psycopg.connect("postgresql://mirage_ci_owner:mirage_ci_only@127.0.0.1:55433/"
                         "mirage_g3b_ci?connect_timeout=5") as admin:
        if admin.execute("SELECT count(*) FROM protected_world_commit_sources").fetchone()[0] != 1:
            raise RuntimeError("g3b_ci_inventory_commit_evidence_missing")
        if admin.execute("SELECT count(*) FROM protected_medusa_rejection_sources").fetchone()[0] != 2:
            raise RuntimeError("g3b_ci_medusa_rejection_evidence_missing")
        if admin.execute("SELECT count(*) FROM protected_http_operation_bindings").fetchone()[0] != 3:
            raise RuntimeError("g3b_ci_operation_proof_count_mismatch")
        for role, forbidden in (
                ("mirage_g3b_ci_verifier", "protected_world_commit_sources"),
                ("mirage_g3b_ci_validator", "protected_medusa_rejection_sources"),
                ("mirage_g3b_ci_runtime", "ingress_receipts")):
            if admin.execute("SELECT has_table_privilege(%s,%s,'INSERT')",
                             (role, forbidden)).fetchone() != (False,):
                raise RuntimeError("g3b_ci_forbidden_acl:" + role)
    runtime_dsn = (root / "probe" / "runtime-host.dsn").read_text(encoding="utf-8")
    with psycopg.connect(runtime_dsn) as runtime:
        if runtime.execute("SELECT current_user,session_user").fetchone() != (
                "mirage_g3b_ci_runtime", "mirage_g3b_ci_runtime"):
            raise RuntimeError("g3b_ci_runtime_login_mismatch")
        try:
            runtime.execute("SELECT receipt_id FROM ingress_receipts LIMIT 1")
        except psycopg.errors.InsufficientPrivilege:
            pass
        else:
            raise RuntimeError("g3b_ci_runtime_can_read_receipts")
    print("G3B_CONTAINER_AUDIT_PASS services=4 networks=3 distinct_mounts=verified "
          "runtime_acl=denied provenance=3 trusted_send=off")


def main() -> None:
    """嚴格選擇 Gateway 網路測試或 Host Container ACL 檢查，不混用權限。"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True, choices=("gateway", "audit"))
    parser.add_argument("--root", type=Path)
    args = parser.parse_args()
    if args.mode == "gateway":
        _gateway()
    else:
        if args.root is None:
            raise RuntimeError("g3b_ci_audit_requires_root")
        _audit(args.root.resolve(strict=True))


if __name__ == "__main__":
    main()
