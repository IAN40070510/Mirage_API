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
from psycopg.conninfo import conninfo_to_dict, make_conninfo
import yaml

from deception.api.fingerprint import fingerprint_httpx_request
from deception.security.operation_binding import _pinned_medusa_operations
from deception.domains.ecommerce.cart_http import cart_specification
from deception.domains.ecommerce.inventory_http import inventory_specification
from deception.world.protected_native_http import fixed_synthetic_rejection_bytes
from deception.world.transmission import response_hashes


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
        # I-01 成功 200 候選也必須由獨立 Validator 的不可變 Commit Source 重建。
        # 注意外層仍是內部對帳 HTTP 200，沒有 G4 授權，不能視為 Client Native 200。
        committed = inventory_result.get("executor_result", {})
        native = inventory_result.get("native_projection", {})
        native_body = base64.b64decode(native.get("body_b64", ""), validate=True)
        if (native.get("status_code") != 200
                or native.get("headers") != [["content-type", "application/json"]]
                or native.get("source", {}).get("kind") != "committed_operation"
                or native["source"].get("operation_result_digest") != committed.get("result_digest")
                or native["source"].get("committed_state_version") != committed.get("state_version")
                or native["source"].get("committed_state_hash") != committed.get("state_hash")
                or native.get("scope", {}).get("session_id") != "session"
                or native.get("delivery") != "candidate_only_no_send_authorization"
                or native.get("envelope_hash") != response_hashes(
                    200, (("content-type", "application/json"),), native_body)[0]):
            raise RuntimeError("g3b_ci_inventory_success_candidate_unverifiable")
        native_json = json.loads(native_body)
        if (native_json.get("commit_attempt_id") != committed.get("commit_attempt_id")
                or native_json.get("state_version") != committed.get("state_version")
                or native_json.get("state_hash") != committed.get("state_hash")
                or native_json.get("reservation", {}).get("sku") != "sku-1"
                or native_json.get("reservation", {}).get("quantity") != 2
                or native_json.get("reservation", {}).get("status") != "reserved"):
            raise RuntimeError("g3b_ci_inventory_success_payload_mismatch")
        print("G3B_ROUTE_PROTECTED_INVENTORY_MUTATION_200 " + json.dumps({
            "operation_id": "reserveSyntheticInventory", "outer_http_status": accepted.status_code,
            "validated_native_status": 200, "source": "protected_world_commit_sources",
            "native_business_response": False,
        }, sort_keys=True))
        if gateway.send(request).status_code != 403:
            raise RuntimeError("g3b_ci_replay_accepted")
        # I-04 的 200 唯讀庫存資料須從獨立 Validator 查實際 Snapshot 版本，
        # 不是把 Executor 的 ReadAdmission Metadata 當成原生客戶端 200。
        inventory_get = gateway.build_request(
            "GET", origin + "/synthetic/inventory/sku-1",
            headers={"x-request-id": "g3b-ci-inventory-get-200"},
        )
        inventory_get.headers["x-trusted-session"] = _sign(
            key, fingerprint=fingerprint_httpx_request(
                inventory_get, "g3b-ci-inventory-get-200"),
            session="session", mode="inventory",
        )
        read_result = gateway.send(inventory_get)
        if read_result.status_code != 200:
            raise RuntimeError("g3b_ci_inventory_snapshot_internal_rpc_unverifiable")
        read_candidate = read_result.json().get("native_projection", {})
        read_bytes = base64.b64decode(read_candidate.get("body_b64", ""), validate=True)
        read_headers = (("content-type", "application/json"),)
        if (read_candidate.get("status_code") != 200
                or read_candidate.get("source", {}).get("kind") != "snapshot"
                or read_candidate.get("source", {}).get("state_version") != 2
                or read_candidate.get("scope", {}).get("session_id") != "session"
                or read_candidate.get("delivery") != "candidate_only_no_send_authorization"
                or read_candidate.get("envelope_hash") != response_hashes(200, read_headers, read_bytes)[0]
                or json.loads(read_bytes) != {"sku": "sku-1", "available": 3, "state_version": 2}
                or gateway.send(inventory_get).status_code != 403):
            raise RuntimeError("g3b_ci_inventory_snapshot_validator_source_mismatch")
        print("G3B_ROUTE_PROTECTED_INVENTORY_SNAPSHOT " + json.dumps({
            "operation_id": "getSyntheticInventory", "http_status": read_result.status_code,
            "validated_native_status": 200, "source": "protected_world_read_sources",
            "native_business_response": False,
        }, sort_keys=True))
        for label, route, native_status, expected_operation in (
                ("operation-200", "/synthetic/operations/" + json.loads(body)["commit_attempt_id"],
                 200, "getSyntheticOperation"),
                ("missing-sku-409", "/synthetic/inventory/missing-sku", 409,
                 "getSyntheticInventory")):
            request_id = "g3b-ci-" + label
            original = gateway.build_request(
                "GET", origin + route, headers={"x-request-id": request_id},
            )
            original.headers["x-trusted-session"] = _sign(
                key, fingerprint=fingerprint_httpx_request(original, request_id),
                session="session", mode="inventory",
            )
            result = gateway.send(original)
            if result.status_code != 200:
                raise RuntimeError("g3b_ci_inventory_additional_internal_rpc_unverifiable:" + label)
            internal = result.json().get("executor_result", {})
            projected = result.json().get("native_projection", {})
            payload = base64.b64decode(projected.get("body_b64", ""), validate=True)
            if (internal.get("operation") != expected_operation
                    or projected.get("status_code") != native_status
                    or projected.get("source", {}).get("read_admission_id")
                    != internal.get("read_admission_id")
                    or projected.get("scope", {}).get("world_generation_id")
                    != internal.get("world_generation_id")
                    or projected.get("envelope_hash") != response_hashes(
                        native_status, read_headers, payload)[0]
                    or projected.get("delivery") != "candidate_only_no_send_authorization"
                    or gateway.send(original).status_code != 403):
                raise RuntimeError("g3b_ci_inventory_additional_source_mismatch:" + label)
            parsed = json.loads(payload)
            if label == "operation-200":
                if (parsed.get("commit_attempt_id") != json.loads(body)["commit_attempt_id"]
                        or parsed.get("state_version") != 2
                        or parsed.get("reservation", {}).get("status") != "reserved"
                        or parsed.get("reservation", {}).get("sku") != "sku-1"):
                    raise RuntimeError("g3b_ci_operation_result_native_payload_invalid")
            elif parsed != {"code": "unknown_synthetic_sku"}:
                raise RuntimeError("g3b_ci_inventory_absence_409_payload_invalid")
            print("G3B_ROUTE_PROTECTED_INVENTORY_CANDIDATE " + json.dumps({
                "operation_id": expected_operation, "http_status": result.status_code,
                "validated_native_status": native_status, "source": "protected_world_read_sources",
                "native_business_response": False,
            }, sort_keys=True))
        missing_attempt_id = "g3b-ci-no-commit"
        missing_attempt = gateway.build_request(
            "GET", origin + "/synthetic/operations/" + str(uuid4()),
            headers={"x-request-id": missing_attempt_id},
        )
        missing_attempt.headers["x-trusted-session"] = _sign(
            key, fingerprint=fingerprint_httpx_request(missing_attempt, missing_attempt_id),
            session="session", mode="inventory",
        )
        unknown = gateway.send(missing_attempt)
        if unknown.status_code != 200:
            raise RuntimeError("g3b_ci_missing_operation_read_source_unverifiable")
        missing_candidate = unknown.json().get("native_projection", {})
        if (missing_candidate.get("status_code") != 409
                or missing_candidate.get("source", {}).get("kind") != "snapshot"
                or missing_candidate.get("delivery") != "candidate_only_no_send_authorization"
                or missing_candidate.get("headers") != [["content-type", "application/json"]]
                or base64.b64decode(missing_candidate.get("body_b64", ""), validate=True)
                    != b'{"code":"operation_not_found"}'
                or gateway.send(missing_attempt).status_code != 403):
            raise RuntimeError("g3b_ci_missing_operation_409_not_attested")
        print("G3B_ROUTE_PROTECTED_INVENTORY_MISSING_OPERATION " + json.dumps({
            "native_business_response": False, "outer_http_status": unknown.status_code,
            "validated_native_status": 409, "source": "protected_world_read_sources",
        }, sort_keys=True))
        # 真實四容器與兩組 mTLS CA：已拒絕的 Handler 結果只能由獨立 Validator
        # 還原 409 候選，外層控制面 200 不能冒稱 Client 已收到原生 409。
        rejection_body = json.dumps({
            "sku": "sku-does-not-exist", "quantity": 1, "expected_version": 2,
            "idempotency_key": "g3b-container-rejected", "commit_attempt_id": str(uuid4()),
        }).encode("utf-8")
        rejected = gateway.build_request(
            "POST", origin + "/synthetic/inventory/reservations", content=rejection_body,
            headers={"x-request-id": "g3b-ci-inventory-409", "content-type": "application/json"},
        )
        rejected.headers["x-trusted-session"] = _sign(
            key, fingerprint=fingerprint_httpx_request(rejected, "g3b-ci-inventory-409"),
            session="session", mode="inventory",
        )
        business_denial = gateway.send(rejected)
        if business_denial.status_code != 200:
            raise RuntimeError("g3b_ci_synthetic_409_internal_rpc_unverifiable")
        denial = business_denial.json()
        source = denial.get("native_projection", {})
        headers, expected_body = fixed_synthetic_rejection_bytes(
            "synthetic-inventory", "unknown_synthetic_sku")
        expected_envelope = response_hashes(409, headers, expected_body)[0]
        if (denial.get("executor_result", {}).get("status") != "rejected"
                or source.get("status_code") != 409
                or source.get("headers") != [list(header) for header in headers]
                or source.get("envelope_hash") != expected_envelope
                or source.get("scope", {}).get("session_id") != "session"
                or source.get("delivery") != "candidate_only_no_send_authorization"
                or base64.b64decode(source.get("body_b64", ""), validate=True) != expected_body
                or gateway.send(rejected).status_code != 403):
            raise RuntimeError("g3b_ci_synthetic_409_validator_source_mismatch")
        print("G3B_ROUTE_PROTECTED_SYNTHETIC_REJECTION " + json.dumps({
            "operation_id": "reserveSyntheticInventory", "http_status": business_denial.status_code,
            "validated_native_status": 409, "template_id": "unknown_synthetic_sku",
            "source": "protected_world_rejection_sources", "native_business_response": False,
        }, sort_keys=True))
        # I-02：直接沿用 I-01 真 Commit 的 Reservation ID，版本 2→3 取消。
        # 同資源第二次取消必須是 Handler 的 reservation_not_active 409 來源，
        # 不能被誤解成未知授權的內部 503，也不能再提交一次 Inventory 變更。
        reservation_id = native_json.get("reservation", {}).get("reservation_id")
        if (not isinstance(reservation_id, str)
                or re.fullmatch(r"[0-9a-f]{32}", reservation_id) is None):
            raise RuntimeError("g3b_ci_inventory_committed_reservation_id_invalid")
        cancel_route = origin + "/synthetic/inventory/reservations/" + reservation_id + "/cancel"
        for label, version, expected_status in (
                ("first", 2, 200), ("second", 3, 409)):
            cancel_id = "g3b-ci-inventory-cancel-" + label
            cancel_attempt = str(uuid4())
            cancel_body = json.dumps({
                "expected_version": version,
                "idempotency_key": "g3b-inventory-cancel-" + label,
                "commit_attempt_id": cancel_attempt,
            }, separators=(",", ":"), sort_keys=True).encode("utf-8")
            cancellation = gateway.build_request(
                "POST", cancel_route, content=cancel_body,
                headers={"x-request-id": cancel_id, "content-type": "application/json"},
            )
            cancellation.headers["x-trusted-session"] = _sign(
                key, fingerprint=fingerprint_httpx_request(cancellation, cancel_id),
                session="session", mode="inventory",
            )
            cancel_response = gateway.send(cancellation)
            if cancel_response.status_code != 200:
                raise RuntimeError("g3b_ci_inventory_cancel_" + label + "_rpc_unverifiable")
            cancel_json = cancel_response.json()
            cancel_metadata = cancel_json.get("executor_result", {})
            cancel_projection = cancel_json.get("native_projection", {})
            cancel_bytes = base64.b64decode(
                cancel_projection.get("body_b64", ""), validate=True,
            )
            if (cancel_metadata.get("kind") != "world_mutation"
                    or cancel_metadata.get("operation") != "cancelSyntheticInventory"
                    or cancel_metadata.get("status")
                        != ("committed" if expected_status == 200 else "rejected")
                    or cancel_projection.get("status_code") != expected_status
                    or cancel_projection.get("scope", {}).get("session_id") != "session"
                    or cancel_projection.get("delivery")
                        != "candidate_only_no_send_authorization"
                    or cancel_projection.get("envelope_hash") != response_hashes(
                        expected_status, read_headers, cancel_bytes)[0]
                    or gateway.send(cancellation).status_code != 403):
                raise RuntimeError("g3b_ci_inventory_cancel_" + label + "_source_mismatch")
            if expected_status == 200:
                payload = json.loads(cancel_bytes)
                if (cancel_metadata.get("state_version") != 3
                        or cancel_metadata.get("commit_attempt_id") != cancel_attempt
                        or cancel_projection.get("source", {}).get("kind")
                            != "committed_operation"
                        or cancel_projection.get("source", {}).get("operation_result_digest")
                            != cancel_metadata.get("result_digest")
                        or cancel_projection.get("source", {}).get("committed_state_version") != 3
                        or cancel_projection.get("source", {}).get("committed_state_hash")
                            != cancel_metadata.get("state_hash")
                        or payload.get("state_version") != 3
                        or payload.get("state_hash") != cancel_metadata.get("state_hash")
                        or payload.get("commit_attempt_id") != cancel_attempt
                        or payload.get("reservation", {}).get("reservation_id") != reservation_id
                        or payload.get("reservation", {}).get("sku") != "sku-1"
                        or payload.get("reservation", {}).get("quantity") != 2
                        or payload.get("reservation", {}).get("status") != "cancelled"):
                    raise RuntimeError("g3b_ci_inventory_cancel_commit_candidate_mismatch")
            else:
                denial_headers, denial_body = fixed_synthetic_rejection_bytes(
                    "synthetic-inventory", "reservation_not_active")
                if (cancel_projection.get("source", {}).get("template_id")
                        != "reservation_not_active"
                        or cancel_projection.get("headers") != [list(h) for h in denial_headers]
                        or cancel_bytes != denial_body):
                    raise RuntimeError("g3b_ci_inventory_cancel_rejection_source_mismatch")
            print("G3B_ROUTE_INVENTORY_CANCEL_CANDIDATE " + json.dumps({
                "operation_id": "cancelSyntheticInventory", "source": (
                    "protected_world_commit_sources" if expected_status == 200
                    else "protected_world_rejection_sources"),
                "validated_native_status": expected_status, "case": label,
                "native_business_response": False,
            }, sort_keys=True))
        # C-01：合法 Creator JWS 真走四容器建立 Cart，獨立 Validator 只能由
        # 新派生世界建立 200 候選，不得把 Derived Scope 當成 Creator Admission。
        create_request_id = "g3b-ci-cart-create-200"
        # 顯式 UUID4 鍵才能再以另一張有效 Receipt 驗證 cross-receipt reuse。
        cart_create_body = json.dumps({
            "idempotency_key": str(uuid4()), "commit_attempt_id": str(uuid4()),
        }, separators=(",", ":"), sort_keys=True).encode("utf-8")
        cart_create = gateway.build_request(
            "POST", origin + "/synthetic/carts", content=cart_create_body,
            headers={"x-request-id": create_request_id, "content-type": "application/json"},
        )
        cart_create.headers["x-trusted-session"] = _sign(
            key, fingerprint=fingerprint_httpx_request(cart_create, create_request_id),
            session="g3b-ci-cart-creator", mode="cart",
        )
        created_result = gateway.send(cart_create)
        if created_result.status_code != 200:
            # Only the fixed, generic API failure category is logged; never
            # print tokens, receipt contents, DSNs or native candidate bytes.
            try:
                failure_detail = created_result.json().get("detail", "unavailable")
            except (ValueError, AttributeError):
                failure_detail = "non_json"
            if not isinstance(failure_detail, str) or len(failure_detail) > 120:
                failure_detail = "invalid_detail"
            raise RuntimeError(
                "g3b_ci_cart_creation_rpc_unverifiable:"
                + str(created_result.status_code) + ":" + failure_detail)
        created_json = created_result.json()
        created_metadata = created_json.get("executor_result", {})
        created_projection = created_json.get("native_projection", {})
        created_source = created_projection.get("source", {})
        created_body = base64.b64decode(created_projection.get("body_b64", ""), validate=True)
        created_payload = json.loads(created_body)
        if (created_metadata.get("kind") != "cart_created"
                or created_metadata.get("operation") != "createGuestCart"
                or created_metadata.get("status") != "committed"
                or created_projection.get("status_code") != 200
                or created_projection.get("operation_id") is not None
                or created_source.get("kind") != "cart_creation"
                or created_source.get("resource_id") != created_metadata.get("resource_id")
                or created_source.get("commit_attempt_id") != created_metadata.get("commit_attempt_id")
                or created_source.get("derived_session_id") == "g3b-ci-cart-creator"
                or created_projection.get("scope", {}).get("session_id") != "g3b-ci-cart-creator"
                or created_projection.get("scope", {}).get("world_generation_id")
                    == created_source.get("derived_world_generation_id")
                or created_projection.get("delivery") != "candidate_only_no_send_authorization"
                or created_payload.get("cart", {}).get("id") != created_metadata.get("resource_id")
                or created_payload.get("cart", {}).get("items") != []
                or created_payload.get("state_version") != 1
                or created_payload.get("commit_attempt_id") != created_metadata.get("commit_attempt_id")
                or created_payload.get("state_hash") != created_source.get("state_hash")
                or created_projection.get("envelope_hash") != response_hashes(
                    200, read_headers, created_body)[0]
                or gateway.send(cart_create).status_code != 403):
            raise RuntimeError("g3b_ci_cart_creation_validator_source_mismatch")
        print("G3B_ROUTE_PROTECTED_CART_CREATION_CANDIDATE " + json.dumps({
            "operation_id": "createGuestCart", "outer_http_status": created_result.status_code,
            "validated_native_status": 200, "source": "protected_cart_creations",
            "authorization_scope": "creator", "native_business_response": False,
        }, sort_keys=True))
        # M-01 最小原生建立只接受部署固定 Email 與空 items；原生成功
        # Payload 須由另一個獨立 Validator 從 Creator→Derived Cart Lineage 投影。
        medusa_create_id = "g3b-ci-medusa-create"
        medusa_create_body = b'{"email":"ci@example.invalid","items":[]}'
        medusa_create = gateway.build_request(
            "POST", origin + "/store/carts", content=medusa_create_body,
            headers={"x-request-id": medusa_create_id, "content-type": "application/json",
                     "x-publishable-api-key": "pk_g3b_ci_only"},
        )
        medusa_create.headers["x-trusted-session"] = _sign(
            key, fingerprint=fingerprint_httpx_request(medusa_create, medusa_create_id),
            session="g3b-ci-cart-creator", mode="cart",
        )
        medusa_created = gateway.send(medusa_create)
        if medusa_created.status_code != 200:
            raise RuntimeError("g3b_ci_medusa_create_rpc_unverifiable:" + str(medusa_created.status_code))
        medusa_created_json = medusa_created.json()
        medusa_created_meta = medusa_created_json.get("executor_result", {})
        medusa_created_projection = medusa_created_json.get("native_projection", {})
        medusa_created_source = medusa_created_projection.get("source", {})
        medusa_created_bytes = base64.b64decode(
            medusa_created_projection.get("body_b64", ""), validate=True,
        )
        medusa_created_payload = json.loads(medusa_created_bytes)
        if (medusa_created_meta.get("kind") != "cart_created"
                or medusa_created_meta.get("operation") != "PostCarts"
                or medusa_created_meta.get("status") != "committed"
                or medusa_created_projection.get("status_code") != 200
                or medusa_created_source.get("kind") != "cart_creation"
                or medusa_created_source.get("resource_id") != medusa_created_meta.get("resource_id")
                or medusa_created_source.get("commit_attempt_id")
                    != medusa_created_meta.get("commit_attempt_id")
                or medusa_created_source.get("derived_session_id") == "g3b-ci-cart-creator"
                or medusa_created_projection.get("scope", {}).get("session_id")
                    != "g3b-ci-cart-creator"
                or medusa_created_projection.get("delivery")
                    != "candidate_only_no_send_authorization"
                or medusa_created_payload.get("cart", {}).get("id")
                    != medusa_created_meta.get("resource_id")
                or medusa_created_payload.get("cart", {}).get("items") != []
                or medusa_created_payload.get("cart", {}).get("currency_code") != "usd"
                or medusa_created_payload.get("cart", {}).get("email") != "ci@example.invalid"
                or "state_hash" in medusa_created_payload
                or medusa_created_projection.get("envelope_hash") != response_hashes(
                    200, read_headers, medusa_created_bytes)[0]
                or gateway.send(medusa_create).status_code != 403):
            raise RuntimeError("g3b_ci_medusa_create_validator_source_mismatch")
        print("G3B_ROUTE_MEDUSA_CREATE_CANDIDATE " + json.dumps({
            "operation_id": "PostCarts", "validated_native_status": 200,
            "source": "protected_cart_creations", "authorization_scope": "creator",
            "native_business_response": False, "native_validator_200": True,
        }, sort_keys=True))
        # M-03 使用本次 M-01 真建立的另一個 Derived Cart，不改動合成 Cart
        # 已驗收的版本鏈；有效 JWS→Executor Commit→獨立 Validator 200 候選。
        medusa_add_id = "g3b-ci-medusa-derived-add-200"
        medusa_cart_id = medusa_created_meta["resource_id"]
        medusa_cart_session = medusa_created_source["derived_session_id"]
        medusa_add = gateway.build_request(
            "POST", origin + "/store/carts/" + medusa_cart_id + "/line-items",
            content=b'{"variant_id":"known","quantity":2}',
            headers={"x-request-id": medusa_add_id, "content-type": "application/json",
                     "x-publishable-api-key": "pk_g3b_ci_only"},
        )
        medusa_add.headers["x-trusted-session"] = _sign(
            key, fingerprint=fingerprint_httpx_request(medusa_add, medusa_add_id),
            session=medusa_cart_session, mode="cart", resource_id=medusa_cart_id,
        )
        medusa_added = gateway.send(medusa_add)
        if medusa_added.status_code != 200:
            raise RuntimeError("g3b_ci_medusa_add_rpc_unverifiable:" + str(medusa_added.status_code))
        medusa_add_result = medusa_added.json()
        medusa_add_meta = medusa_add_result.get("executor_result", {})
        medusa_add_projection = medusa_add_result.get("native_projection", {})
        medusa_add_source = medusa_add_projection.get("source", {})
        medusa_add_bytes = base64.b64decode(
            medusa_add_projection.get("body_b64", ""), validate=True,
        )
        medusa_add_cart = json.loads(medusa_add_bytes).get("cart", {})
        if (medusa_add_meta.get("kind") != "medusa_mutation"
                or medusa_add_meta.get("operation") != "PostCartsIdLineItems"
                or medusa_add_meta.get("status") != "committed"
                or medusa_add_meta.get("state_version") != 2
                or medusa_add_projection.get("status_code") != 200
                or medusa_add_source.get("kind") != "committed_operation"
                or medusa_add_source.get("operation_result_digest")
                    != medusa_add_meta.get("result_digest")
                or medusa_add_source.get("committed_state_version") != 2
                or medusa_add_source.get("committed_state_hash")
                    != medusa_add_meta.get("state_hash")
                or medusa_add_projection.get("scope", {}).get("session_id") != medusa_cart_session
                or medusa_add_projection.get("scope", {}).get("world_generation_id")
                    != medusa_created_source.get("derived_world_generation_id")
                or medusa_add_cart.get("id") != medusa_cart_id
                or medusa_add_cart.get("total") != 2.0
                or not isinstance(medusa_add_cart.get("items"), list)
                or len(medusa_add_cart["items"]) != 1
                or medusa_add_cart["items"][0].get("variant_id") != "known"
                or medusa_add_cart["items"][0].get("quantity") != 2
                or medusa_add_projection.get("delivery")
                    != "candidate_only_no_send_authorization"
                or medusa_add_projection.get("envelope_hash") != response_hashes(
                    200, read_headers, medusa_add_bytes)[0]
                or gateway.send(medusa_add).status_code != 403):
            raise RuntimeError("g3b_ci_medusa_add_candidate_source_mismatch")
        print("G3B_ROUTE_MEDUSA_ADD_CANDIDATE " + json.dumps({
            "operation_id": "PostCartsIdLineItems", "source": "protected_world_commit_sources",
            "validated_native_status": 200, "state_version": 2,
            "native_business_response": False, "trusted_send": "off",
        }, sort_keys=True))
        forbidden_body = b'{"email":"ci@example.invalid","items":[{"variant_id":"known","quantity":1}]}'
        forbidden_request_id = "g3b-ci-medusa-create-items-denied"
        forbidden_create = gateway.build_request(
            "POST", origin + "/store/carts", content=forbidden_body,
            headers={"x-request-id": forbidden_request_id, "content-type": "application/json",
                     "x-publishable-api-key": "pk_g3b_ci_only"},
        )
        forbidden_create.headers["x-trusted-session"] = _sign(
            key, fingerprint=fingerprint_httpx_request(forbidden_create, forbidden_request_id),
            session="g3b-ci-cart-creator", mode="cart",
        )
        if gateway.send(forbidden_create).status_code != 503:
            raise RuntimeError("g3b_ci_medusa_unapproved_initial_items_not_denied")
        # M-01 同一可信 Creator 即使持有有效 JWS，也不能藉原生新增欄位、
        # 重複 JSON Key、URL Query 或 Header 自訂世界／價格／提交身份。
        for suffix, body, extra_headers, query, api_key in (
                ("email-drift", b'{"email":"changed@example.invalid","items":[]}',
                 {}, "", "pk_g3b_ci_only"),
                ("currency-drift", b'{"email":"ci@example.invalid","currency_code":"eur"}',
                 {}, "", "pk_g3b_ci_only"),
                ("duplicate-key", b'{"email":"ci@example.invalid","email":"changed@example.invalid"}',
                 {}, "", "pk_g3b_ci_only"),
                ("extra-world", b'{"email":"ci@example.invalid","inventory":{"known":100}}',
                 {}, "", "pk_g3b_ci_only"),
                ("client-idempotency", medusa_create_body,
                 {"idempotency-key": "chosen-by-client"}, "", "pk_g3b_ci_only"),
                ("query", medusa_create_body, {}, "?unexpected=1", "pk_g3b_ci_only"),
                ("wrong-key", medusa_create_body, {}, "", "pk_wrong"),
        ):
            forbidden_id = "g3b-ci-medusa-create-" + suffix
            forbidden = gateway.build_request(
                "POST", origin + "/store/carts" + query, content=body,
                headers={"x-request-id": forbidden_id, "content-type": "application/json",
                         "x-publishable-api-key": api_key, **extra_headers},
            )
            forbidden.headers["x-trusted-session"] = _sign(
                key, fingerprint=fingerprint_httpx_request(forbidden, forbidden_id),
                session="g3b-ci-cart-creator", mode="cart",
            )
            rejected = gateway.send(forbidden)
            # Query 於 Verifier 的 derive_verified_operation() 前置規則拒絕，
            # 尚無 Receipt／Proof，故回 403；另外六組具 Proof，Executor 回 503。
            expected_status = 403 if suffix == "query" else 503
            if rejected.status_code != expected_status:
                raise RuntimeError("g3b_ci_medusa_create_input_not_denied:" + suffix
                                   + ":status=" + str(rejected.status_code))
        print("G3B_ROUTE_MEDUSA_CREATE_INPUT_DENIED " + json.dumps({
            "operation_id": "PostCarts", "cases": 7, "native_business_response": False,
            "query_pre_receipt_status": 403, "executor_denials": 6,
            "new_cart_source": False,
        }, sort_keys=True))
        # 新 JWS／JTI／Request ID 是另一張 Receipt，不可借用已提交的 Cart Source。
        duplicate_request_id = "g3b-ci-cart-cross-receipt-denied"
        cross_receipt = gateway.build_request(
            "POST", origin + "/synthetic/carts", content=cart_create_body,
            headers={"x-request-id": duplicate_request_id,
                     "content-type": "application/json"},
        )
        cross_receipt.headers["x-trusted-session"] = _sign(
            key, fingerprint=fingerprint_httpx_request(
                cross_receipt, duplicate_request_id),
            session="g3b-ci-cart-creator", mode="cart",
        )
        if gateway.send(cross_receipt).status_code != 503:
            raise RuntimeError("g3b_ci_cart_cross_receipt_key_not_rejected")
        print("G3B_ROUTE_CART_CREATION_CROSS_RECEIPT_DENIED " + json.dumps({
            "operation_id": "createGuestCart", "outcome": "fail_closed",
            "second_protected_creation": False, "native_business_response": False,
        }, sort_keys=True))
        # 真 HTTP／mTLS 路徑下，重複 JSON 欄位與 Client 偽造庫存均需在
        # Executor 原始 Proof 檢查拒絕，不能建立額外 Cart 或從外部選初始世界。
        for case, invalid_body in (
                ("duplicate-json", b'{"idempotency_key":"x","idempotency_key":"y"}'),
                ("client-inventory", b'{"inventory":{"sku-1":999}}')):
            denied_id = "g3b-ci-cart-deny-" + case
            invalid_create = gateway.build_request(
                "POST", origin + "/synthetic/carts", content=invalid_body,
                headers={"x-request-id": denied_id,
                         "content-type": "application/json"},
            )
            invalid_create.headers["x-trusted-session"] = _sign(
                key, fingerprint=fingerprint_httpx_request(invalid_create, denied_id),
                session="g3b-ci-cart-creator", mode="cart",
            )
            if gateway.send(invalid_create).status_code != 503:
                raise RuntimeError("g3b_ci_cart_invalid_body_not_denied:" + case)
        print("G3B_ROUTE_CART_CREATION_INVALID_BODY_DENIED " + json.dumps({
            "operation_id": "createGuestCart", "cases": 2,
            "native_business_response": False,
        }, sort_keys=True))
        # C-02：不要只讀 Owner 事先準備的 Cart；直接以 C-01 真 HTTP 新建的
        # Derived Session／Resource 簽新 JWS，驗證跨 Creator→Derived 邊界
        # 的 ReadAdmission 和獨立 Validator 仍只接受該資源的最新快照。
        derived_session = created_source.get("derived_session_id")
        derived_id = created_metadata.get("resource_id")
        if (not isinstance(derived_session, str)
                or re.fullmatch(r"[0-9a-f]{32}", derived_session) is None
                or not isinstance(derived_id, str)
                or re.fullmatch(r"cart_[0-9a-f]{32}", derived_id) is None):
            raise RuntimeError("g3b_ci_cart_derived_identity_unverifiable")
        derived_request_id = "g3b-ci-cart-created-then-read"
        derived_get = gateway.build_request(
            "GET", origin + "/synthetic/carts/" + derived_id,
            headers={"x-request-id": derived_request_id},
        )
        derived_get.headers["x-trusted-session"] = _sign(
            key, fingerprint=fingerprint_httpx_request(derived_get, derived_request_id),
            session=derived_session, mode="cart", resource_id=derived_id,
        )
        derived_response = gateway.send(derived_get)
        if derived_response.status_code != 200:
            raise RuntimeError("g3b_ci_cart_derived_read_rpc_unverifiable")
        derived_result = derived_response.json()
        derived_metadata = derived_result.get("executor_result", {})
        derived_projection = derived_result.get("native_projection", {})
        derived_body = base64.b64decode(derived_projection.get("body_b64", ""), validate=True)
        derived_payload = json.loads(derived_body)
        if (derived_metadata.get("kind") != "cart_read_admitted"
                or derived_metadata.get("operation") != "getGuestCart"
                or derived_projection.get("status_code") != 200
                or derived_projection.get("source", {}).get("kind") != "snapshot"
                or derived_projection.get("source", {}).get("read_admission_id")
                    != derived_metadata.get("read_admission_id")
                or derived_projection.get("scope", {}).get("session_id") != derived_session
                or derived_projection.get("scope", {}).get("world_generation_id")
                    != created_source.get("derived_world_generation_id")
                or derived_payload.get("cart") != created_payload.get("cart")
                or derived_payload.get("commit_attempt_id", "unexpected") is not None
                or derived_payload.get("state_version") != 1
                or derived_payload.get("state_hash") != created_source.get("state_hash")
                or derived_projection.get("delivery") != "candidate_only_no_send_authorization"
                or derived_projection.get("envelope_hash") != response_hashes(
                    200, read_headers, derived_body)[0]
                or gateway.send(derived_get).status_code != 403):
            raise RuntimeError("g3b_ci_cart_derived_read_source_mismatch")
        print("G3B_ROUTE_CART_CREATED_THEN_READ_CANDIDATE " + json.dumps({
            "operation_id": "getGuestCart", "source": "protected_world_read_sources",
            "validated_native_status": 200, "derived_scope": True,
            "native_business_response": False,
        }, sort_keys=True))
        # Creator 先前有權建立 Cart，並不因此取得該 Derived Session 的讀權。
        # 以新簽章、同一真 Cart ID 冒名讀取必須 fail closed，不能有 200 Candidate。
        cross_scope_id = "g3b-ci-cart-creator-cannot-read-derived"
        cross_scope_get = gateway.build_request(
            "GET", origin + "/synthetic/carts/" + derived_id,
            headers={"x-request-id": cross_scope_id},
        )
        cross_scope_get.headers["x-trusted-session"] = _sign(
            key, fingerprint=fingerprint_httpx_request(cross_scope_get, cross_scope_id),
            session="g3b-ci-cart-creator", mode="cart", resource_id=derived_id,
        )
        if gateway.send(cross_scope_get).status_code != 503:
            raise RuntimeError("g3b_ci_creator_cross_scope_cart_read_not_denied")
        print("G3B_ROUTE_CART_CREATOR_CROSS_SCOPE_READ_DENIED " + json.dumps({
            "operation_id": "getGuestCart", "outcome": "fail_closed",
            "native_business_response": False,
        }, sort_keys=True))
        # C-03：C-01 真建立、C-02 真讀取的 Derived Cart 可在同 Scope 依
        # 版本 1 CAS 加入合法 variant；Commit 和獨立 Validator 200 必須
        # 同時核對精確 Receipt／State Hash／Envelope，不把內部 RPC 當 Client Send。
        add_request_id = "g3b-ci-cart-derived-add-200"
        add_attempt = str(uuid4())
        add_body = json.dumps({
            "variant_id": "known", "quantity": 2, "expected_version": 1,
            "idempotency_key": "g3b-cart-derived-add-once",
            "commit_attempt_id": add_attempt,
        }, separators=(",", ":"), sort_keys=True).encode("utf-8")
        add_request = gateway.build_request(
            "POST", origin + "/synthetic/carts/" + derived_id + "/line-items",
            content=add_body,
            headers={"x-request-id": add_request_id, "content-type": "application/json"},
        )
        add_request.headers["x-trusted-session"] = _sign(
            key, fingerprint=fingerprint_httpx_request(add_request, add_request_id),
            session=derived_session, mode="cart", resource_id=derived_id,
        )
        added = gateway.send(add_request)
        if added.status_code != 200:
            raise RuntimeError("g3b_ci_derived_cart_add_rpc_unverifiable")
        added_result = added.json()
        add_metadata = added_result.get("executor_result", {})
        add_projection = added_result.get("native_projection", {})
        add_source = add_projection.get("source", {})
        add_payload_bytes = base64.b64decode(add_projection.get("body_b64", ""), validate=True)
        add_payload = json.loads(add_payload_bytes)
        items = add_payload.get("cart", {}).get("items", [])
        if (add_metadata.get("kind") != "world_mutation"
                or add_metadata.get("operation") != "addGuestCartItem"
                or add_metadata.get("status") != "committed"
                or add_metadata.get("commit_attempt_id") != add_attempt
                or add_metadata.get("state_version") != 2
                or add_projection.get("status_code") != 200
                or add_source.get("kind") != "committed_operation"
                or add_source.get("operation_result_digest") != add_metadata.get("result_digest")
                or add_source.get("committed_state_version") != 2
                or add_source.get("committed_state_hash") != add_metadata.get("state_hash")
                or add_projection.get("scope", {}).get("session_id") != derived_session
                or add_projection.get("scope", {}).get("world_generation_id")
                    != created_source.get("derived_world_generation_id")
                or add_projection.get("delivery") != "candidate_only_no_send_authorization"
                or add_payload.get("state_version") != 2
                or add_payload.get("state_hash") != add_metadata.get("state_hash")
                or add_payload.get("commit_attempt_id") != add_attempt
                or add_payload.get("cart", {}).get("id") != derived_id
                or add_payload.get("cart", {}).get("status") != "active"
                or add_payload.get("cart", {}).get("total") != 200
                or not isinstance(items, list) or len(items) != 1
                or items[0].get("variant_id") != "known"
                or items[0].get("sku") != "sku-1"
                or items[0].get("unit_price") != 100
                or items[0].get("quantity") != 2
                or add_projection.get("envelope_hash") != response_hashes(
                    200, read_headers, add_payload_bytes)[0]
                or gateway.send(add_request).status_code != 403):
            raise RuntimeError("g3b_ci_derived_cart_add_candidate_source_mismatch")
        print("G3B_ROUTE_CART_CREATED_READ_THEN_ADD_CANDIDATE " + json.dumps({
            "operation_id": "addGuestCartItem", "source": "protected_world_commit_sources",
            "validated_native_status": 200, "derived_scope": True,
            "state_version": 2, "native_business_response": False,
        }, sort_keys=True))
        # C-03：同一真 Derived Cart 已有版本 2，但 Client 選不存在的 Variant。
        # 唯有實際受保護 Handler 拒絕與獨立 Rejection Source 才可重建固定 409。
        bad_variant_id = "g3b-ci-cart-derived-missing-variant"
        bad_variant_body = json.dumps({
            "variant_id": "not-in-catalog", "quantity": 1, "expected_version": 2,
            "idempotency_key": "g3b-cart-unknown-variant-once",
            "commit_attempt_id": str(uuid4()),
        }, separators=(",", ":"), sort_keys=True).encode("utf-8")
        bad_variant = gateway.build_request(
            "POST", origin + "/synthetic/carts/" + derived_id + "/line-items",
            content=bad_variant_body,
            headers={"x-request-id": bad_variant_id, "content-type": "application/json"},
        )
        bad_variant.headers["x-trusted-session"] = _sign(
            key, fingerprint=fingerprint_httpx_request(bad_variant, bad_variant_id),
            session=derived_session, mode="cart", resource_id=derived_id,
        )
        denied_variant = gateway.send(bad_variant)
        if denied_variant.status_code != 200:
            raise RuntimeError("g3b_ci_derived_cart_unknown_variant_rpc_unverifiable")
        denied_result = denied_variant.json()
        denied_metadata = denied_result.get("executor_result", {})
        denied_projection = denied_result.get("native_projection", {})
        rejection_headers, rejection_payload = fixed_synthetic_rejection_bytes(
            "synthetic-carts", "unknown_synthetic_variant")
        if (denied_metadata.get("kind") != "world_mutation"
                or denied_metadata.get("operation") != "addGuestCartItem"
                or denied_metadata.get("status") != "rejected"
                or denied_projection.get("status_code") != 409
                or denied_projection.get("source", {}).get("template_id")
                    != "unknown_synthetic_variant"
                or denied_projection.get("headers")
                    != [list(header) for header in rejection_headers]
                or denied_projection.get("scope", {}).get("session_id") != derived_session
                or denied_projection.get("scope", {}).get("world_generation_id")
                    != created_source.get("derived_world_generation_id")
                or denied_projection.get("delivery") != "candidate_only_no_send_authorization"
                or denied_projection.get("envelope_hash") != response_hashes(
                    409, rejection_headers, rejection_payload)[0]
                or base64.b64decode(denied_projection.get("body_b64", ""), validate=True)
                    != rejection_payload
                or gateway.send(bad_variant).status_code != 403):
            raise RuntimeError("g3b_ci_derived_cart_unknown_variant_409_source_mismatch")
        print("G3B_ROUTE_CART_DERIVED_UNKNOWN_VARIANT_REJECTION " + json.dumps({
            "operation_id": "addGuestCartItem", "source": "protected_world_rejection_sources",
            "validated_native_status": 409, "template_id": "unknown_synthetic_variant",
            "native_business_response": False,
        }, sort_keys=True))
        # C-04／C-05：同一 Derived Cart 的受保護 CAS 版本 2→3→4。
        # 不接受 Runtime 自稱的 item ID；只能從上一個 Validator 200 候選取值。
        item_id = items[0].get("id")
        if not isinstance(item_id, str) or re.fullmatch(r"item_[0-9a-f]{32}", item_id) is None:
            raise RuntimeError("g3b_ci_derived_cart_committed_item_id_invalid")
        mutation_route = origin + "/synthetic/carts/" + derived_id + "/line-items/" + item_id
        for label, method, operation_id, expected_version, next_version, quantity in (
                ("update", "POST", "updateGuestCartItem", 2, 3, 3),
                ("remove", "DELETE", "removeGuestCartItem", 3, 4, None)):
            mutation_request_id = "g3b-ci-derived-cart-" + label
            mutation_attempt = str(uuid4())
            mutation_input = {
                "expected_version": expected_version,
                "idempotency_key": "g3b-derived-cart-" + label + "-once",
                "commit_attempt_id": mutation_attempt,
            }
            if quantity is not None:
                mutation_input["quantity"] = quantity
            mutation_bytes = json.dumps(
                mutation_input, separators=(",", ":"), sort_keys=True,
            ).encode("utf-8")
            mutation = gateway.build_request(
                method, mutation_route, content=mutation_bytes,
                headers={"x-request-id": mutation_request_id,
                         "content-type": "application/json"},
            )
            mutation.headers["x-trusted-session"] = _sign(
                key, fingerprint=fingerprint_httpx_request(mutation, mutation_request_id),
                session=derived_session, mode="cart", resource_id=derived_id,
            )
            mutation_result = gateway.send(mutation)
            if mutation_result.status_code != 200:
                raise RuntimeError("g3b_ci_derived_cart_" + label + "_rpc_unverifiable")
            mutation_json = mutation_result.json()
            mutation_metadata = mutation_json.get("executor_result", {})
            mutation_projection = mutation_json.get("native_projection", {})
            mutation_source = mutation_projection.get("source", {})
            mutation_body = base64.b64decode(
                mutation_projection.get("body_b64", ""), validate=True,
            )
            mutation_payload = json.loads(mutation_body)
            mutation_cart = mutation_payload.get("cart", {})
            mutation_items = mutation_cart.get("items", [])
            if (mutation_metadata.get("kind") != "world_mutation"
                    or mutation_metadata.get("operation") != operation_id
                    or mutation_metadata.get("status") != "committed"
                    or mutation_metadata.get("commit_attempt_id") != mutation_attempt
                    or mutation_metadata.get("state_version") != next_version
                    or mutation_projection.get("status_code") != 200
                    or mutation_source.get("kind") != "committed_operation"
                    or mutation_source.get("operation_result_digest")
                        != mutation_metadata.get("result_digest")
                    or mutation_source.get("committed_state_version") != next_version
                    or mutation_source.get("committed_state_hash")
                        != mutation_metadata.get("state_hash")
                    or mutation_projection.get("scope", {}).get("session_id") != derived_session
                    or mutation_projection.get("scope", {}).get("world_generation_id")
                        != created_source.get("derived_world_generation_id")
                    or mutation_projection.get("delivery")
                        != "candidate_only_no_send_authorization"
                    or mutation_payload.get("state_version") != next_version
                    or mutation_payload.get("state_hash") != mutation_metadata.get("state_hash")
                    or mutation_payload.get("commit_attempt_id") != mutation_attempt
                    or mutation_cart.get("id") != derived_id
                    or mutation_cart.get("status") != "active"
                    or mutation_cart.get("total") != (quantity or 0) * 100
                    or not isinstance(mutation_items, list)
                    or len(mutation_items) != (1 if quantity is not None else 0)
                    or quantity is not None and (
                        mutation_items[0].get("id") != item_id
                        or mutation_items[0].get("quantity") != quantity)
                    or mutation_projection.get("envelope_hash") != response_hashes(
                        200, read_headers, mutation_body)[0]
                    or gateway.send(mutation).status_code != 403):
                raise RuntimeError("g3b_ci_derived_cart_" + label + "_candidate_source_mismatch")
            print("G3B_ROUTE_CART_DERIVED_ITEM_MUTATION_CANDIDATE " + json.dumps({
                "operation_id": operation_id, "source": "protected_world_commit_sources",
                "validated_native_status": 200, "state_version": next_version,
                "native_business_response": False,
            }, sort_keys=True))
        # C-06：刪光品項後版本 4 的合法 Cart，不得完成空 Cart 訂單。
        # 這是 Handler 真拒絕＋獨立來源 409 候選，不是欠缺授權的內部 503。
        empty_complete_id = "g3b-ci-derived-cart-empty-complete"
        empty_complete_body = json.dumps({
            "expected_version": 4, "idempotency_key": "g3b-empty-complete-once",
            "commit_attempt_id": str(uuid4()),
        }, separators=(",", ":"), sort_keys=True).encode("utf-8")
        empty_complete = gateway.build_request(
            "POST", origin + "/synthetic/carts/" + derived_id + "/complete",
            content=empty_complete_body,
            headers={"x-request-id": empty_complete_id,
                     "content-type": "application/json"},
        )
        empty_complete.headers["x-trusted-session"] = _sign(
            key, fingerprint=fingerprint_httpx_request(empty_complete, empty_complete_id),
            session=derived_session, mode="cart", resource_id=derived_id,
        )
        empty_result = gateway.send(empty_complete)
        if empty_result.status_code != 200:
            raise RuntimeError("g3b_ci_derived_empty_cart_rejection_rpc_unverifiable")
        empty_json = empty_result.json()
        empty_metadata = empty_json.get("executor_result", {})
        empty_projection = empty_json.get("native_projection", {})
        empty_headers, empty_payload = fixed_synthetic_rejection_bytes(
            "synthetic-carts", "empty_synthetic_cart")
        if (empty_metadata.get("kind") != "world_mutation"
                or empty_metadata.get("operation") != "completeGuestCart"
                or empty_metadata.get("status") != "rejected"
                or empty_projection.get("status_code") != 409
                or empty_projection.get("source", {}).get("template_id")
                    != "empty_synthetic_cart"
                or empty_projection.get("headers") != [list(h) for h in empty_headers]
                or empty_projection.get("scope", {}).get("session_id") != derived_session
                or empty_projection.get("scope", {}).get("world_generation_id")
                    != created_source.get("derived_world_generation_id")
                or empty_projection.get("delivery") != "candidate_only_no_send_authorization"
                or empty_projection.get("envelope_hash") != response_hashes(
                    409, empty_headers, empty_payload)[0]
                or base64.b64decode(empty_projection.get("body_b64", ""), validate=True)
                    != empty_payload
                or gateway.send(empty_complete).status_code != 403):
            raise RuntimeError("g3b_ci_derived_empty_cart_409_source_mismatch")
        print("G3B_ROUTE_CART_DERIVED_EMPTY_COMPLETE_REJECTION " + json.dumps({
            "operation_id": "completeGuestCart", "source": "protected_world_rejection_sources",
            "validated_native_status": 409, "template_id": "empty_synthetic_cart",
            "native_business_response": False,
        }, sort_keys=True))
        # 重新對同一 Cart 版本 4 加商品，證明先前 409 沒有偷渡狀態提交。
        refill_id = "g3b-ci-derived-cart-refill"
        refill_attempt = str(uuid4())
        refill_body = json.dumps({
            "variant_id": "known", "quantity": 1, "expected_version": 4,
            "idempotency_key": "g3b-cart-refill-once",
            "commit_attempt_id": refill_attempt,
        }, separators=(",", ":"), sort_keys=True).encode("utf-8")
        refill = gateway.build_request(
            "POST", origin + "/synthetic/carts/" + derived_id + "/line-items",
            content=refill_body,
            headers={"x-request-id": refill_id, "content-type": "application/json"},
        )
        refill.headers["x-trusted-session"] = _sign(
            key, fingerprint=fingerprint_httpx_request(refill, refill_id),
            session=derived_session, mode="cart", resource_id=derived_id,
        )
        refilled = gateway.send(refill)
        if refilled.status_code != 200:
            raise RuntimeError("g3b_ci_derived_cart_refill_rpc_unverifiable")
        refill_metadata = refilled.json().get("executor_result", {})
        refill_projection = refilled.json().get("native_projection", {})
        refill_bytes = base64.b64decode(refill_projection.get("body_b64", ""), validate=True)
        refill_payload = json.loads(refill_bytes)
        refill_items = refill_payload.get("cart", {}).get("items", [])
        if (refill_metadata.get("kind") != "world_mutation"
                or refill_metadata.get("operation") != "addGuestCartItem"
                or refill_metadata.get("status") != "committed"
                or refill_metadata.get("commit_attempt_id") != refill_attempt
                or refill_metadata.get("state_version") != 5
                or refill_projection.get("status_code") != 200
                or refill_projection.get("source", {}).get("kind") != "committed_operation"
                or refill_projection.get("source", {}).get("operation_result_digest")
                    != refill_metadata.get("result_digest")
                or refill_projection.get("source", {}).get("committed_state_hash")
                    != refill_metadata.get("state_hash")
                or refill_projection.get("scope", {}).get("session_id") != derived_session
                or refill_projection.get("delivery") != "candidate_only_no_send_authorization"
                or refill_payload.get("state_version") != 5
                or refill_payload.get("state_hash") != refill_metadata.get("state_hash")
                or refill_payload.get("cart", {}).get("id") != derived_id
                or refill_payload.get("cart", {}).get("total") != 100
                or not isinstance(refill_items, list) or len(refill_items) != 1
                or refill_items[0].get("variant_id") != "known"
                or refill_items[0].get("quantity") != 1
                or refill_projection.get("envelope_hash") != response_hashes(
                    200, read_headers, refill_bytes)[0]
                or gateway.send(refill).status_code != 403):
            raise RuntimeError("g3b_ci_derived_cart_refill_source_mismatch")
        # C-06 正向：只有真版本 5 的非空 Cart 才能生成新的 Order ID。
        complete_id = "g3b-ci-derived-cart-complete-200"
        complete_attempt = str(uuid4())
        complete_body = json.dumps({
            "expected_version": 5, "idempotency_key": "g3b-cart-complete-once",
            "commit_attempt_id": complete_attempt,
        }, separators=(",", ":"), sort_keys=True).encode("utf-8")
        complete = gateway.build_request(
            "POST", origin + "/synthetic/carts/" + derived_id + "/complete",
            content=complete_body,
            headers={"x-request-id": complete_id, "content-type": "application/json"},
        )
        complete.headers["x-trusted-session"] = _sign(
            key, fingerprint=fingerprint_httpx_request(complete, complete_id),
            session=derived_session, mode="cart", resource_id=derived_id,
        )
        completed = gateway.send(complete)
        if completed.status_code != 200:
            raise RuntimeError("g3b_ci_derived_cart_complete_rpc_unverifiable")
        completed_metadata = completed.json().get("executor_result", {})
        completed_projection = completed.json().get("native_projection", {})
        completed_bytes = base64.b64decode(
            completed_projection.get("body_b64", ""), validate=True,
        )
        completed_payload = json.loads(completed_bytes)
        completed_order = completed_payload.get("order", {})
        derived_order_id = completed_order.get("id")
        if (not isinstance(derived_order_id, str)
                or re.fullmatch(r"order_[0-9a-f]{32}", derived_order_id) is None
                or completed_metadata.get("kind") != "world_mutation"
                or completed_metadata.get("operation") != "completeGuestCart"
                or completed_metadata.get("status") != "committed"
                or completed_metadata.get("commit_attempt_id") != complete_attempt
                or completed_metadata.get("state_version") != 6
                or completed_projection.get("status_code") != 200
                or completed_projection.get("source", {}).get("kind") != "committed_operation"
                or completed_projection.get("source", {}).get("operation_result_digest")
                    != completed_metadata.get("result_digest")
                or completed_projection.get("source", {}).get("committed_state_version") != 6
                or completed_projection.get("source", {}).get("committed_state_hash")
                    != completed_metadata.get("state_hash")
                or completed_projection.get("scope", {}).get("session_id") != derived_session
                or completed_projection.get("scope", {}).get("world_generation_id")
                    != created_source.get("derived_world_generation_id")
                or completed_projection.get("delivery")
                    != "candidate_only_no_send_authorization"
                or completed_payload.get("state_version") != 6
                or completed_payload.get("state_hash") != completed_metadata.get("state_hash")
                or completed_payload.get("commit_attempt_id") != complete_attempt
                or completed_order.get("cart_id") != derived_id
                or completed_order.get("status") != "placed"
                or completed_order.get("total") != 100
                or completed_order.get("items") != refill_items
                or completed_projection.get("envelope_hash") != response_hashes(
                    200, read_headers, completed_bytes)[0]
                or gateway.send(complete).status_code != 403):
            raise RuntimeError("g3b_ci_derived_cart_complete_source_mismatch")
        print("G3B_ROUTE_CART_DERIVED_COMPLETE_ORDER_CANDIDATE " + json.dumps({
            "operation_id": "completeGuestCart", "source": "protected_world_commit_sources",
            "validated_native_status": 200, "state_version": 6, "derived_scope": True,
            "native_business_response": False,
        }, sort_keys=True))
        # C-07：Order ID 源自已驗證的 complete 候選，而非 Client 自填。
        # 同一派生世界、但新的 Order Resource Capability 才能做 GET。
        order_get_id = "g3b-ci-derived-order-get-200"
        order_get = gateway.build_request(
            "GET", origin + "/synthetic/orders/" + derived_order_id,
            headers={"x-request-id": order_get_id},
        )
        order_get.headers["x-trusted-session"] = _sign(
            key, fingerprint=fingerprint_httpx_request(order_get, order_get_id),
            session=derived_session, mode="cart", resource_id=derived_order_id,
        )
        order_read = gateway.send(order_get)
        if order_read.status_code != 200:
            raise RuntimeError("g3b_ci_derived_order_read_rpc_unverifiable")
        order_read_json = order_read.json()
        order_read_metadata = order_read_json.get("executor_result", {})
        order_read_projection = order_read_json.get("native_projection", {})
        order_read_bytes = base64.b64decode(
            order_read_projection.get("body_b64", ""), validate=True,
        )
        order_read_payload = json.loads(order_read_bytes)
        if (order_read_metadata.get("kind") != "cart_read_admitted"
                or order_read_metadata.get("operation") != "getSyntheticOrder"
                or order_read_metadata.get("resource_id") != derived_order_id
                or order_read_metadata.get("state_version") != 6
                or order_read_metadata.get("state_hash") != completed_metadata.get("state_hash")
                or order_read_projection.get("status_code") != 200
                or order_read_projection.get("source", {}).get("kind") != "snapshot"
                or order_read_projection.get("source", {}).get("read_admission_id")
                    != order_read_metadata.get("read_admission_id")
                or order_read_projection.get("scope", {}).get("session_id") != derived_session
                or order_read_projection.get("scope", {}).get("world_generation_id")
                    != created_source.get("derived_world_generation_id")
                or order_read_projection.get("delivery")
                    != "candidate_only_no_send_authorization"
                or order_read_payload.get("order") != completed_order
                or order_read_payload.get("state_version") != 6
                or order_read_payload.get("state_hash") != completed_metadata.get("state_hash")
                or order_read_payload.get("commit_attempt_id", "missing") is not None
                or order_read_projection.get("envelope_hash") != response_hashes(
                    200, read_headers, order_read_bytes)[0]
                or gateway.send(order_get).status_code != 403):
            raise RuntimeError("g3b_ci_derived_order_read_source_mismatch")
        # M-07：同一真 Order 的 Medusa 原始 GET 在獨立 Executor 建立
        # ReadAdmission，但沒有 Medusa 200 Validator，所以不得有 Native Projection。
        native_order_id = "g3b-ci-medusa-order-get-source"
        native_order_get = gateway.build_request(
            "GET", origin + "/store/orders/" + derived_order_id,
            headers={"x-request-id": native_order_id,
                     "x-publishable-api-key": "pk_g3b_ci_only"},
        )
        native_order_get.headers["x-trusted-session"] = _sign(
            key, fingerprint=fingerprint_httpx_request(native_order_get, native_order_id),
            session=derived_session, mode="cart", resource_id=derived_order_id,
        )
        native_order_result = gateway.send(native_order_get)
        if native_order_result.status_code != 200:
            raise RuntimeError("g3b_ci_medusa_order_read_rpc_unverifiable")
        native_order_json = native_order_result.json()
        native_order_meta = native_order_json.get("executor_result", {})
        native_order_projection = native_order_json.get("native_projection", {})
        native_order_bytes = base64.b64decode(
            native_order_projection.get("body_b64", ""), validate=True,
        )
        native_order_payload = json.loads(native_order_bytes)
        if (native_order_meta.get("kind") != "medusa_read_admitted"
                or native_order_meta.get("operation") != "GetOrdersId"
                or native_order_meta.get("resource_id") != derived_order_id
                or native_order_meta.get("state_version") != 6
                or native_order_meta.get("state_hash") != completed_metadata.get("state_hash")
                or not isinstance(native_order_meta.get("read_admission_id"), str)
                or native_order_meta.get("world_generation_id")
                    != created_source.get("derived_world_generation_id")
                or native_order_projection.get("status_code") != 200
                or native_order_projection.get("source", {}).get("kind") != "snapshot"
                or native_order_projection.get("source", {}).get("read_admission_id")
                    != native_order_meta.get("read_admission_id")
                or native_order_projection.get("scope", {}).get("session_id") != derived_session
                or native_order_projection.get("delivery") != "candidate_only_no_send_authorization"
                or native_order_payload.get("order", {}).get("id") != derived_order_id
                or native_order_payload.get("order", {}).get("payment_status") != "not_paid"
                or native_order_payload.get("order", {}).get("customer_id", "missing") is not None
                or native_order_projection.get("envelope_hash") != response_hashes(
                    200, read_headers, native_order_bytes)[0]
                or gateway.send(native_order_get).status_code != 403):
            raise RuntimeError("g3b_ci_medusa_order_read_source_mismatch")
        print("G3B_ROUTE_MEDUSA_ORDER_READ_SOURCE " + json.dumps({
            "operation_id": "GetOrdersId", "outer_http_status": native_order_result.status_code,
            "source": "protected_world_read_sources", "validated_native_status": 200,
            "native_business_response": False, "native_validator_200": True,
        }, sort_keys=True))
        print("G3B_ROUTE_DERIVED_ORDER_READ_CANDIDATE " + json.dumps({
            "operation_id": "getSyntheticOrder", "source": "protected_world_read_sources",
            "validated_native_status": 200, "state_version": 6,
            "native_business_response": False,
        }, sort_keys=True))
        # C-08：受保護 Order Capability、CAS 版本 6、獨立 Receipt 才能取消。
        cancel_order_id = "g3b-ci-derived-order-cancel-200"
        cancel_order_attempt = str(uuid4())
        cancel_order_body = json.dumps({
            "expected_version": 6, "idempotency_key": "g3b-order-cancel-once",
            "commit_attempt_id": cancel_order_attempt,
        }, separators=(",", ":"), sort_keys=True).encode("utf-8")
        cancel_order = gateway.build_request(
            "POST", origin + "/synthetic/orders/" + derived_order_id + "/cancel",
            content=cancel_order_body,
            headers={"x-request-id": cancel_order_id, "content-type": "application/json"},
        )
        cancel_order.headers["x-trusted-session"] = _sign(
            key, fingerprint=fingerprint_httpx_request(cancel_order, cancel_order_id),
            session=derived_session, mode="cart", resource_id=derived_order_id,
        )
        canceled = gateway.send(cancel_order)
        if canceled.status_code != 200:
            raise RuntimeError("g3b_ci_derived_order_cancel_rpc_unverifiable")
        canceled_metadata = canceled.json().get("executor_result", {})
        canceled_projection = canceled.json().get("native_projection", {})
        canceled_bytes = base64.b64decode(
            canceled_projection.get("body_b64", ""), validate=True,
        )
        canceled_payload = json.loads(canceled_bytes)
        canceled_order = canceled_payload.get("order", {})
        if (canceled_metadata.get("kind") != "world_mutation"
                or canceled_metadata.get("operation") != "cancelSyntheticOrder"
                or canceled_metadata.get("status") != "committed"
                or canceled_metadata.get("commit_attempt_id") != cancel_order_attempt
                or canceled_metadata.get("state_version") != 7
                or canceled_projection.get("status_code") != 200
                or canceled_projection.get("source", {}).get("kind") != "committed_operation"
                or canceled_projection.get("source", {}).get("operation_result_digest")
                    != canceled_metadata.get("result_digest")
                or canceled_projection.get("source", {}).get("committed_state_version") != 7
                or canceled_projection.get("source", {}).get("committed_state_hash")
                    != canceled_metadata.get("state_hash")
                or canceled_projection.get("scope", {}).get("session_id") != derived_session
                or canceled_projection.get("scope", {}).get("world_generation_id")
                    != created_source.get("derived_world_generation_id")
                or canceled_projection.get("delivery")
                    != "candidate_only_no_send_authorization"
                or canceled_payload.get("state_version") != 7
                or canceled_payload.get("state_hash") != canceled_metadata.get("state_hash")
                or canceled_payload.get("commit_attempt_id") != cancel_order_attempt
                or canceled_order.get("id") != derived_order_id
                or canceled_order.get("cart_id") != derived_id
                or canceled_order.get("status") != "cancelled"
                or canceled_order.get("total") != 100
                or canceled_order.get("items") != completed_order.get("items")
                or canceled_projection.get("envelope_hash") != response_hashes(
                    200, read_headers, canceled_bytes)[0]
                or gateway.send(cancel_order).status_code != 403):
            raise RuntimeError("g3b_ci_derived_order_cancel_source_mismatch")
        print("G3B_ROUTE_DERIVED_ORDER_CANCEL_CANDIDATE " + json.dumps({
            "operation_id": "cancelSyntheticOrder", "source": "protected_world_commit_sources",
            "validated_native_status": 200, "state_version": 7,
            "native_business_response": False,
        }, sort_keys=True))
        # C-09：Order 已取消後，仍只能用原 Cart ID 查其歷史操作。
        # Validator 要由舊 World Operation＋Commit Source＋Receipt 還原版本 2，
        # 不能將目前版本 7 的世界狀態偷換成舊操作的結果。
        for operation_label, attempt, native_status in (
                ("historical", add_attempt, 200),
                ("missing", str(uuid4()), 409)):
            op_id = "g3b-ci-derived-cart-operation-" + operation_label
            op_read = gateway.build_request(
                "GET", origin + "/synthetic/carts/" + derived_id
                + "/operations/" + attempt,
                headers={"x-request-id": op_id},
            )
            op_read.headers["x-trusted-session"] = _sign(
                key, fingerprint=fingerprint_httpx_request(op_read, op_id),
                session=derived_session, mode="cart", resource_id=derived_id,
            )
            op_response = gateway.send(op_read)
            if op_response.status_code != 200:
                raise RuntimeError("g3b_ci_derived_cart_" + operation_label
                                   + "_operation_rpc_unverifiable")
            op_response_json = op_response.json()
            op_metadata = op_response_json.get("executor_result", {})
            op_projection = op_response_json.get("native_projection", {})
            op_bytes = base64.b64decode(op_projection.get("body_b64", ""), validate=True)
            op_payload = json.loads(op_bytes)
            if (op_metadata.get("kind") != "cart_read_admitted"
                    or op_metadata.get("operation") != "getCartOperation"
                    or op_metadata.get("resource_id") != derived_id
                    or op_metadata.get("attempt_id") != attempt
                    or op_metadata.get("state_version") != 7
                    or op_metadata.get("state_hash") != canceled_metadata.get("state_hash")
                    or op_projection.get("status_code") != native_status
                    or op_projection.get("source", {}).get("kind") != "snapshot"
                    or op_projection.get("source", {}).get("read_admission_id")
                        != op_metadata.get("read_admission_id")
                    or op_projection.get("scope", {}).get("session_id") != derived_session
                    or op_projection.get("scope", {}).get("world_generation_id")
                        != created_source.get("derived_world_generation_id")
                    or op_projection.get("delivery")
                        != "candidate_only_no_send_authorization"
                    or op_projection.get("envelope_hash") != response_hashes(
                        native_status, read_headers, op_bytes)[0]
                    or gateway.send(op_read).status_code != 403):
                raise RuntimeError("g3b_ci_derived_cart_" + operation_label
                                   + "_operation_source_mismatch")
            if operation_label == "historical":
                if (op_payload.get("cart") != add_payload.get("cart")
                        or op_payload.get("state_version") != 2
                        or op_payload.get("state_hash") != add_metadata.get("state_hash")
                        or op_payload.get("commit_attempt_id") != add_attempt):
                    raise RuntimeError("g3b_ci_derived_cart_historical_operation_mismatch")
            elif op_payload != {"code": "operation_not_found"}:
                raise RuntimeError("g3b_ci_derived_cart_absent_operation_409_mismatch")
            print("G3B_ROUTE_CART_DERIVED_OPERATION_CANDIDATE " + json.dumps({
                "operation_id": "getCartOperation", "source": "protected_world_read_sources",
                "validated_native_status": native_status, "case": operation_label,
                "native_business_response": False,
            }, sort_keys=True))
        # C-02：同樣透過真 Gateway→Cart Executor→獨立唯讀 Validator，
        # 只能查驗與既有派生 Cart Session 相符的原生成功 JSON 候選。
        cart_request_id = "g3b-ci-cart-get-200"
        cart_get = gateway.build_request(
            "GET", origin + "/synthetic/carts/" + data["cart_id"],
            headers={"x-request-id": cart_request_id},
        )
        cart_get.headers["x-trusted-session"] = _sign(
            key, fingerprint=fingerprint_httpx_request(cart_get, cart_request_id),
            session=data["cart_session"], mode="cart", resource_id=data["cart_id"],
        )
        cart_outcome = gateway.send(cart_get)
        if cart_outcome.status_code != 200:
            raise RuntimeError("g3b_ci_cart_get_rpc_unverifiable")
        cart_metadata = cart_outcome.json().get("executor_result", {})
        cart_projection = cart_outcome.json().get("native_projection", {})
        cart_payload = base64.b64decode(cart_projection.get("body_b64", ""), validate=True)
        cart_result = json.loads(cart_payload)
        if (cart_metadata.get("kind") != "cart_read_admitted"
                or cart_metadata.get("operation") != "getGuestCart"
                or cart_projection.get("status_code") != 200
                or cart_result.get("cart", {}).get("id") != data["cart_id"]
                or cart_result.get("commit_attempt_id", "unexpected") is not None
                or cart_result.get("state_version") != cart_metadata.get("state_version")
                or cart_result.get("state_hash") != cart_metadata.get("state_hash")
                or cart_projection.get("source", {}).get("read_admission_id")
                != cart_metadata.get("read_admission_id")
                or cart_projection.get("scope", {}).get("session_id") != data["cart_session"]
                or cart_projection.get("delivery") != "candidate_only_no_send_authorization"
                or cart_projection.get("envelope_hash") != response_hashes(
                    200, read_headers, cart_payload)[0]
                or gateway.send(cart_get).status_code != 403):
            raise RuntimeError("g3b_ci_cart_get_validator_source_mismatch")
        print("G3B_ROUTE_PROTECTED_CART_GET_CANDIDATE " + json.dumps({
            "operation_id": "getGuestCart", "http_status": cart_outcome.status_code,
            "validated_native_status": 200, "source": "protected_world_read_sources",
            "native_business_response": False,
        }, sort_keys=True))
        # M-02：在實際四服務上用 Medusa Key 與完整 JWS 取派生 Cart 的讀取來源。
        # 不把內部 RPC 200 或 Read Source 冒稱原生客戶端 200。
        native_cart_id = "g3b-ci-medusa-cart-get-source"
        native_cart_get = gateway.build_request(
            "GET", origin + "/store/carts/" + data["cart_id"],
            headers={"x-request-id": native_cart_id,
                     "x-publishable-api-key": "pk_g3b_ci_only"},
        )
        native_cart_get.headers["x-trusted-session"] = _sign(
            key, fingerprint=fingerprint_httpx_request(native_cart_get, native_cart_id),
            session=data["cart_session"], mode="cart", resource_id=data["cart_id"],
        )
        native_cart_result = gateway.send(native_cart_get)
        if native_cart_result.status_code != 200:
            raise RuntimeError("g3b_ci_medusa_cart_read_rpc_unverifiable")
        native_cart_json = native_cart_result.json()
        native_cart_meta = native_cart_json.get("executor_result", {})
        native_cart_projection = native_cart_json.get("native_projection", {})
        native_cart_bytes = base64.b64decode(
            native_cart_projection.get("body_b64", ""), validate=True,
        )
        native_cart_payload = json.loads(native_cart_bytes)
        if (native_cart_meta.get("kind") != "medusa_read_admitted"
                or native_cart_meta.get("operation") != "GetCartsId"
                or native_cart_meta.get("resource_id") != data["cart_id"]
                or native_cart_meta.get("state_hash") != cart_metadata.get("state_hash")
                or native_cart_meta.get("state_version") != cart_metadata.get("state_version")
                or native_cart_meta.get("world_generation_id")
                    != cart_metadata.get("world_generation_id")
                or not isinstance(native_cart_meta.get("read_admission_id"), str)
                or native_cart_projection.get("status_code") != 200
                or native_cart_projection.get("source", {}).get("kind") != "snapshot"
                or native_cart_projection.get("source", {}).get("read_admission_id")
                    != native_cart_meta.get("read_admission_id")
                or native_cart_projection.get("scope", {}).get("session_id") != data["cart_session"]
                or native_cart_projection.get("delivery") != "candidate_only_no_send_authorization"
                or native_cart_payload.get("cart", {}).get("id") != data["cart_id"]
                or native_cart_payload.get("cart", {}).get("currency_code") != "usd"
                or native_cart_projection.get("envelope_hash") != response_hashes(
                    200, read_headers, native_cart_bytes)[0]
                or gateway.send(native_cart_get).status_code != 403):
            raise RuntimeError("g3b_ci_medusa_cart_read_source_mismatch")
        print("G3B_ROUTE_MEDUSA_CART_READ_SOURCE " + json.dumps({
            "operation_id": "GetCartsId", "outer_http_status": native_cart_result.status_code,
            "source": "protected_world_read_sources", "validated_native_status": 200,
            "native_business_response": False, "native_validator_200": True,
        }, sort_keys=True))
        bad_key_id = "g3b-ci-medusa-cart-get-bad-key"
        wrong_key_get = gateway.build_request(
            "GET", origin + "/store/carts/" + data["cart_id"],
            headers={"x-request-id": bad_key_id,
                     "x-publishable-api-key": "invalid_for_native"},
        )
        wrong_key_get.headers["x-trusted-session"] = _sign(
            key, fingerprint=fingerprint_httpx_request(wrong_key_get, bad_key_id),
            session=data["cart_session"], mode="cart", resource_id=data["cart_id"],
        )
        if gateway.send(wrong_key_get).status_code != 503:
            raise RuntimeError("g3b_ci_medusa_wrong_key_not_failed_closed")
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
    print("G3B_GATEWAY_PASS unsigned_routes=20/20 inventory_commit=1 inventory_read_200=1 "
          "inventory_operation_200=1 inventory_absence_409=1 unknown_operation=503 "
          "synthetic_409=1 cart_create_200=1 cart_cross_receipt_key=denied "
          "cart_invalid_body=2_denied "
          "cart_read_200=1 cart_created_then_read_200=1 "
          "cart_creator_cross_scope_read=denied cart_derived_add_200=1 "
          "cart_derived_unknown_variant_409=1 cart_derived_update_200=1 "
          "cart_derived_remove_200=1 "
          "cart_derived_empty_complete_409=1 "
          "cart_derived_complete_200=1 "
          "derived_order_get_200=1 derived_order_cancel_200=1 "
          "cart_historical_operation_200=1 cart_missing_operation_409=1 "
          "inventory_cancel_200=1 inventory_repeat_cancel_409=1 "
          "medusa_400=1 medusa_404=1 medusa_create_candidate_200=1 medusa_add_candidate_200=1 "
          "medusa_create_items=denied medusa_create_inputs=7_denied medusa_get_cart_source=1 "
          "medusa_get_order_source=1 medusa_get_cart_candidate_200=1 "
          "medusa_get_order_candidate_200=1 medusa_bad_key=denied "
          "replay=denied anonymous=denied "
          "execution_network=unreachable trusted_send=off")


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
        if admin.execute("SELECT count(*) FROM protected_world_commit_sources").fetchone()[0] != 9:
            raise RuntimeError("g3b_ci_inventory_commit_evidence_missing")
        if admin.execute("SELECT count(*) FROM protected_medusa_rejection_sources").fetchone()[0] != 2:
            raise RuntimeError("g3b_ci_medusa_rejection_evidence_missing")
        if admin.execute("SELECT count(*) FROM protected_world_rejection_sources").fetchone()[0] != 4:
            raise RuntimeError("g3b_ci_synthetic_rejection_evidence_missing")
        proof_counts = dict(admin.execute(
            """SELECT operation_id,count(*) FROM protected_http_operation_bindings
               GROUP BY operation_id""",
        ).fetchall())
        if proof_counts != {
                "reserveSyntheticInventory": 2,
                "cancelSyntheticInventory": 2,
                "getSyntheticInventory": 2,
                "getSyntheticOperation": 2,
                "createGuestCart": 4,
                "getGuestCart": 3,
                "addGuestCartItem": 3,
                "updateGuestCartItem": 1,
                "removeGuestCartItem": 1,
                "completeGuestCart": 2,
                "getSyntheticOrder": 1,
                "GetCartsId": 2,
                "GetOrdersId": 1,
                "cancelSyntheticOrder": 1,
                "getCartOperation": 2,
                # M-01：合法一張、非空 items 一張、六個 Executor 503；
                # 第七個 Query 在 Verifier 403，不允許鑄造 Operation Proof。
                "PostCarts": 8,
                "PostCartsIdLineItems": 3,
        }:
            raise RuntimeError("g3b_ci_operation_proof_count_mismatch")
        # Owner fixture、synthetic HTTP 與受限 Medusa M-01 各建立一筆；
        # 跨 Receipt 重用 synthetic 建立鍵與 M-01 非空 items 均不得產生第四筆。
        if (admin.execute(
                "SELECT count(*) FROM protected_cart_creations "
                "WHERE creator_session_id=%s", ("g3b-ci-cart-creator",),
        ).fetchone() != (3,) or admin.execute(
                "SELECT count(*) FROM guest_cart_creations "
                "WHERE creator_session_id=%s", ("g3b-ci-cart-creator",),
        ).fetchone() != (3,)):
            raise RuntimeError("g3b_ci_cart_cross_receipt_created_second_world")
        if admin.execute(
                "SELECT count(*) FROM protected_world_read_sources WHERE session_id=%s",
                ("g3b-ci-cart-creator",),
        ).fetchone() != (0,):
            raise RuntimeError("g3b_ci_creator_cross_scope_read_source_created")
        for role, forbidden in (
                ("mirage_g3b_ci_verifier", "protected_world_commit_sources"),
                ("mirage_g3b_ci_validator", "protected_medusa_rejection_sources"),
                ("mirage_g3b_ci_validator", "protected_world_rejection_sources"),
                ("mirage_g3b_ci_validator", "protected_cart_creations"),
                ("mirage_g3b_ci_validator", "guest_cart_creations"),
                ("mirage_g3b_ci_runtime", "ingress_receipts")):
            if admin.execute("SELECT has_table_privilege(%s,%s,'INSERT')",
                             (role, forbidden)).fetchone() != (False,):
                raise RuntimeError("g3b_ci_forbidden_acl:" + role)
        for table in ("protected_cart_creations", "guest_cart_creations"):
            if (admin.execute("SELECT has_table_privilege(%s,%s,'SELECT')",
                              ("mirage_g3b_ci_validator", table)).fetchone() != (True,)
                    or admin.execute("SELECT has_table_privilege(%s,%s,'SELECT')",
                                     ("mirage_g3b_ci_runtime", table)).fetchone() != (False,)):
                raise RuntimeError("g3b_ci_cart_creation_source_acl_mismatch:" + table)
        if (admin.execute("SELECT has_table_privilege(%s,%s,'INSERT')",
                          ("mirage_g3b_ci_cart", "native_response_contexts")).fetchone() != (True,)
                or any(admin.execute("SELECT has_table_privilege(%s,%s,'INSERT')",
                                     (role, "native_response_contexts")).fetchone() != (False,)
                       for role in ("mirage_g3b_ci_verifier", "mirage_g3b_ci_validator",
                                    "mirage_g3b_ci_runtime", "mirage_g3b_ci_inventory"))):
            raise RuntimeError("g3b_ci_native_context_writer_acl_mismatch")
        if (admin.execute("SELECT has_table_privilege(%s,%s,'INSERT')",
                          ("mirage_g3b_ci_cart", "world_initializations")).fetchone() != (True,)
                or any(admin.execute("SELECT has_table_privilege(%s,%s,'INSERT')",
                                     (role, "world_initializations")).fetchone() != (False,)
                       for role in ("mirage_g3b_ci_verifier", "mirage_g3b_ci_validator",
                                    "mirage_g3b_ci_runtime", "mirage_g3b_ci_inventory"))):
            raise RuntimeError("g3b_ci_world_initialization_audit_acl_mismatch")
        if admin.execute(
                "SELECT has_column_privilege(%s,%s,%s,'UPDATE'),"
                "has_table_privilege(%s,%s,'UPDATE')",
                ("mirage_g3b_ci_cart", "synthetic_resources", "resource_kind",
                 "mirage_g3b_ci_cart", "synthetic_resources"),
        ).fetchone() != (True, False):
            raise RuntimeError("g3b_ci_resource_lock_column_acl_mismatch")
        if any(admin.execute("SELECT has_column_privilege(%s,%s,%s,'UPDATE')",
                             (role, "synthetic_resources", "resource_kind")).fetchone() != (False,)
               for role in ("mirage_g3b_ci_verifier", "mirage_g3b_ci_validator",
                            "mirage_g3b_ci_runtime", "mirage_g3b_ci_inventory")):
            raise RuntimeError("g3b_ci_resource_lock_cross_role_acl_mismatch")
    # 真 SQL UPDATE 仍必須由不可變 Trigger 拒絕；不能只相信 Privilege Dump。
    cart_connection = conninfo_to_dict(
        (root / "secrets" / "g3b_cart_executor_dsn").read_text(encoding="utf-8"))
    cart_connection.update(host="127.0.0.1", port="55433")
    with psycopg.connect(make_conninfo(**cart_connection)) as cart:
        try:
            cart.execute(
                "UPDATE synthetic_resources SET resource_kind='order' WHERE resource_id=%s",
                (json.loads((root / "probe" / "world.json").read_text())["cart_id"],),
            )
        except psycopg.errors.InsufficientPrivilege:
            pass
        else:
            raise RuntimeError("g3b_ci_synthetic_resource_immutable_trigger_missing")
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
