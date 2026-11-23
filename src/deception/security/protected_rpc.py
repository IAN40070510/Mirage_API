"""受保護業務服務的獨立 mTLS 傳輸入口；業務 RPC 未驗收前一律 sealed。"""

from __future__ import annotations

import base64
import binascii
import json
import os
from pathlib import Path
import re
import ssl
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request
import httpx
from pydantic import Field, UUID4
import uvicorn

from deception.common.models import SyntheticModel
from deception.api.fingerprint import FINGERPRINT_HEADERS
from deception.api.ingress import NormalizedRequest
from mirage_validator.json_utils import reject_constant, unique_object


class ProtectedRpcConfigurationError(ValueError):
    """mTLS 憑證、受信任 Client CA 或隔離設定不完整時拒絕啟動。"""


class FixedOriginalHTTP(SyntheticModel):
    """轉送只影響已驗證 Fingerprint 的原始 HTTP 欄位，不包含 Trusted JWS。"""

    request_id: str = Field(min_length=1, max_length=128)
    raw_url: str = Field(min_length=1, max_length=4096)
    headers: tuple[tuple[str, str], ...] = Field(max_length=32)


class FixedExecutorCall(SyntheticModel):
    """只接收 Receipt 身份與原始 HTTP bytes，不接受操作／Scope／權限欄位。"""

    receipt_id: UUID4
    raw_path_b64: str = Field(min_length=4, max_length=4096)
    raw_body_b64: str = Field(max_length=1398108)
    original_http: FixedOriginalHTTP | None = None


class FixedNativeProjectionCall(SyntheticModel):
    """獨立 Validator 僅允許查不可變 Receipt，不接受 Runtime 候選 Status 或 Body。"""

    receipt_id: UUID4


class FixedExecutorMTLSClient:
    """獨立 Verifier 用專屬 Client Cert 對已固定 Receipt 單次呼叫 Executor。"""

    def __init__(self, *, origin: str, client_cert: Path, client_key: Path,
                 server_ca: Path) -> None:
        """固定 HTTPS Server 身份與專屬 Verifier 私鑰，拒絕明文／URL 注入。

        不共用 HTTP Runtime Secret，不提供重試或可變 Handler 參數；
        如果 Executor COMMIT ACK 遺失，上游只能進入 UNVERIFIABLE 對帳。
        """
        if not isinstance(origin, str):
            raise ProtectedRpcConfigurationError("fixed_executor_origin_invalid")
        url = urlsplit(origin)
        if (url.scheme != "https" or not url.hostname or url.port is None
                or url.path not in {"", "/"} or url.query or url.fragment
                or url.username is not None or url.password is not None):
            raise ProtectedRpcConfigurationError("fixed_executor_origin_invalid")
        require_mtls_files(server_cert=client_cert, server_key=client_key, client_ca=server_ca)
        context = ssl.create_default_context(cafile=str(server_ca))
        context.load_cert_chain(str(client_cert), str(client_key))
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise ProtectedRpcConfigurationError("fixed_executor_server_verification_required")
        self._origin = origin.rstrip("/")
        self._tls = context

    async def execute_receipt(self, *, receipt_id: UUID, operation_id: str,
                              raw_path: bytes, raw_body: bytes,
                              original_request: NormalizedRequest | None = None) -> dict[str, object]:
        """只傳不可變 Receipt／原始 Bytes，單次 mTLS 呼叫且拒絕回應操作錯綁。"""
        payload = {"receipt_id": str(receipt_id),
                   "raw_path_b64": base64.b64encode(raw_path).decode("ascii"),
                   "raw_body_b64": base64.b64encode(raw_body).decode("ascii")}
        if original_request is not None:
            payload["original_http"] = {
                "request_id": original_request.request_id,
                "raw_url": original_request.raw_url,
                "headers": [(name, value) for name, value in original_request.headers
                            if name.lower() in FINGERPRINT_HEADERS],
            }
        async with httpx.AsyncClient(verify=self._tls, trust_env=False, timeout=8.0) as client:
            response = await client.post(self._origin + "/internal/v1/execute", json=payload)
        if response.status_code != 200:
            raise ProtectedRpcConfigurationError("fixed_executor_result_unverifiable")
        try:
            result = json.loads(response.content, object_pairs_hook=unique_object,
                                parse_constant=reject_constant)
        except ValueError as exc:
            raise ProtectedRpcConfigurationError("fixed_executor_result_invalid") from exc
        fields = {
            "world_mutation": {"kind", "operation", "commit_attempt_id", "status",
                               "state_version", "state_hash", "result_digest"},
            "inventory_read_admitted": {"kind", "operation", "resource_id", "read_admission_id",
                                        "world_generation_id", "state_version", "state_hash"},
            "cart_created": {"kind", "operation", "resource_id", "commit_attempt_id", "status"},
            "cart_read_admitted": {"kind", "operation", "resource_id", "attempt_id",
                                   "world_generation_id", "state_version", "state_hash"},
            "medusa_rejection": {"kind", "operation", "status_code", "template_id",
                                 "contract_revision", "envelope_hash"},
        }
        if (not isinstance(result, dict) or result.get("operation") != operation_id
                or result.get("kind") not in fields
                or set(result) != fields[result["kind"]]
                or (result["kind"] == "world_mutation" and result.get("status") not in {
                    "committed", "already_committed", "rejected"})
                or (result["kind"] == "medusa_rejection" and
                    (result.get("status_code") not in {400, 404}
                     or result.get("template_id") not in {"native-cart-invalid", "native-cart-rejected"}
                     or result.get("contract_revision") != "medusa-cart-1"))
                or (result["kind"] == "cart_created" and result.get("status") != "committed")):
            raise ProtectedRpcConfigurationError("fixed_executor_result_binding_mismatch")
        if result["kind"] == "inventory_read_admitted" and (
                operation_id not in {"getSyntheticInventory", "getSyntheticOperation"}
                or not isinstance(result.get("resource_id"), str)
                or not isinstance(raw_path, bytes) or not isinstance(raw_body, bytes)
                or raw_body != b""
                or raw_path != (
                    b"/synthetic/inventory/" if operation_id == "getSyntheticInventory"
                    else b"/synthetic/operations/") + result["resource_id"].encode("utf-8")
                or not all(isinstance(result.get(field), str)
                           and re.fullmatch(r"[0-9a-f]{32}", result[field]) is not None
                           for field in ("read_admission_id", "world_generation_id"))
                or type(result.get("state_version")) is not int or result["state_version"] < 1
                or not isinstance(result.get("state_hash"), str)
                or re.fullmatch(r"[0-9a-f]{64}", result["state_hash"]) is None):
            raise ProtectedRpcConfigurationError("fixed_executor_result_binding_mismatch")
        return result


class FixedNativeValidatorMTLSClient:
    """Verifier 以第三條專用 mTLS 邊驗證受保護 Medusa 原生候選封套。"""

    def __init__(self, *, origin: str, client_cert: Path, client_key: Path,
                 server_ca: Path) -> None:
        """固定 HTTPS Validator 身份與憑證，禁止 URL 帶路徑／Userinfo／明文。"""
        parsed = urlsplit(origin) if isinstance(origin, str) else None
        if (parsed is None or parsed.scheme != "https" or not parsed.hostname
                or parsed.port is None or parsed.path not in {"", "/"}
                or parsed.query or parsed.fragment or parsed.username or parsed.password):
            raise ProtectedRpcConfigurationError("native_validator_origin_invalid")
        require_mtls_files(server_cert=client_cert, server_key=client_key, client_ca=server_ca)
        context = ssl.create_default_context(cafile=str(server_ca))
        context.load_cert_chain(str(client_cert), str(client_key))
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise ProtectedRpcConfigurationError("native_validator_server_verification_required")
        self._origin = origin.rstrip("/")
        self._tls = context

    async def project_receipt(self, *, receipt_id: UUID, operation_id: str,
                              request_fingerprint: str, expected_status: int,
                              expected_envelope_hash: str,
                              expected_environment_id: str, expected_deployment_id: str,
                              expected_session_id: str) -> dict[str, object]:
        """綁定受保護來源與已驗簽的 Session Scope，保留精確原生候選 bytes。

        此結果仍是內部候選，不得作為已授權的 HTTP Send；只有後續獨立
        Authorizer／Sender 對精確 Snapshot 完成 Lease 才能交給客戶端。
        """
        from deception.world.transmission import response_hashes

        async with httpx.AsyncClient(verify=self._tls, trust_env=False, timeout=8.0) as client:
            response = await client.post(
                self._origin + "/internal/v1/project-medusa-rejection",
                json={"receipt_id": str(receipt_id)},
            )
        if response.status_code != 200:
            raise ProtectedRpcConfigurationError("native_validator_projection_unverifiable")
        try:
            result = json.loads(response.content, object_pairs_hook=unique_object,
                                parse_constant=reject_constant)
            if not isinstance(result, dict) or set(result) != {
                    "receipt_id", "operation_id", "scope", "request_fingerprint",
                    "status_code", "headers", "body_b64", "envelope_hash", "source",
                    "trusted_send"}:
                raise ValueError("native_validator_response_shape_invalid")
            body = _canonical_base64(result["body_b64"], max_bytes=4096)
            headers = result["headers"]
            if (headers != [["content-type", "application/json"]]
                    or result["receipt_id"] != str(receipt_id)
                    or result["operation_id"] != operation_id
                    or result["request_fingerprint"] != request_fingerprint
                    or type(result["status_code"]) is not int
                    or result["status_code"] != expected_status
                    or expected_status not in {400, 404}
                    or result["envelope_hash"] != expected_envelope_hash
                    or result["trusted_send"] != "disabled"
                    or result["source"] != {
                        "kind": "security_error",
                        "template_id": "native-cart-invalid" if expected_status == 400 else "native-cart-rejected",
                        "contract_revision": "medusa-cart-1",
                    }
                    or not isinstance(result["scope"], dict)
                    or set(result["scope"]) != {
                        "environment_id", "deployment_id", "session_id", "world_generation_id"}
                    or result["scope"].get("environment_id") != expected_environment_id
                    or result["scope"].get("deployment_id") != expected_deployment_id
                    or result["scope"].get("session_id") != expected_session_id
                    or not isinstance(result["scope"].get("world_generation_id"), str)
                    or not result["scope"]["world_generation_id"]
                    or response_hashes(expected_status, (("content-type", "application/json"),), body)[0]
                    != expected_envelope_hash):
                raise ValueError("native_validator_projection_binding_mismatch")
        except (ValueError, KeyError, TypeError) as exc:
            raise ProtectedRpcConfigurationError("native_validator_projection_binding_mismatch") from exc
        return {
            "status_code": expected_status,
            "headers": [["content-type", "application/json"]],
            "body_b64": base64.b64encode(body).decode("ascii"),
            "envelope_hash": expected_envelope_hash,
            "body_sha256": response_hashes(expected_status, (("content-type", "application/json"),), body)[1],
            "scope": dict(result["scope"]), "source": dict(result["source"]),
            "delivery": "candidate_only_no_send_authorization",
        }

    async def project_synthetic_rejection(
        self, *, receipt_id: UUID, operation_id: str, platform: str,
        request_fingerprint: str, expected_environment_id: str,
        expected_deployment_id: str, expected_session_id: str,
    ) -> dict[str, object]:
        """只由獨立 Validator 的受保護 DB 拒絕來源取得真正 409 候選。

        Verifier 不傳錯誤碼、Body、Template 或 Scope 選擇值；收到的 JSON
        必須與本地固定合成契約的精確 bytes/hash、Receipt／JWS Scope 一致。
        """
        from deception.world.protected_native_http import (
            _SYNTHETIC_MUTATION_HANDLERS, fixed_synthetic_rejection_bytes,
        )
        from deception.world.transmission import response_hashes

        expected = _SYNTHETIC_MUTATION_HANDLERS.get(operation_id)
        if expected is None or expected[0] != platform:
            raise ProtectedRpcConfigurationError("synthetic_validator_operation_unapproved")
        async with httpx.AsyncClient(verify=self._tls, trust_env=False, timeout=8.0) as client:
            response = await client.post(
                self._origin + "/internal/v1/project-synthetic-rejection",
                json={"receipt_id": str(receipt_id)},
            )
        if response.status_code != 200:
            raise ProtectedRpcConfigurationError("synthetic_validator_projection_unverifiable")
        try:
            result = json.loads(response.content, object_pairs_hook=unique_object,
                                parse_constant=reject_constant)
            if not isinstance(result, dict) or set(result) != {
                    "receipt_id", "operation_id", "scope", "request_fingerprint",
                    "status_code", "headers", "body_b64", "envelope_hash", "source",
                    "trusted_send"}:
                raise ValueError("synthetic_validator_response_shape_invalid")
            body = _canonical_base64(result["body_b64"], max_bytes=4096)
            source = result["source"]
            if (not isinstance(source, dict)
                    or set(source) != {"kind", "template_id", "contract_revision"}
                    or source.get("kind") != "security_error"
                    or source.get("contract_revision") != platform + "-1"):
                raise ValueError("synthetic_validator_source_invalid")
            headers, expected_body = fixed_synthetic_rejection_bytes(platform, source.get("template_id"))
            envelope_hash, body_hash, _ = response_hashes(409, headers, expected_body)
            if (result["receipt_id"] != str(receipt_id)
                    or result["operation_id"] != operation_id
                    or result["request_fingerprint"] != request_fingerprint
                    or type(result["status_code"]) is not int or result["status_code"] != 409
                    or result["headers"] != [["content-type", "application/json"]]
                    or body != expected_body or result["envelope_hash"] != envelope_hash
                    or result["trusted_send"] != "disabled"
                    or not isinstance(result["scope"], dict)
                    or set(result["scope"]) != {
                        "environment_id", "deployment_id", "session_id", "world_generation_id"}
                    or result["scope"].get("environment_id") != expected_environment_id
                    or result["scope"].get("deployment_id") != expected_deployment_id
                    or result["scope"].get("session_id") != expected_session_id
                    or not isinstance(result["scope"].get("world_generation_id"), str)
                    or not result["scope"]["world_generation_id"]):
                raise ValueError("synthetic_validator_projection_binding_mismatch")
        except (ValueError, KeyError, TypeError, UnicodeError) as exc:
            raise ProtectedRpcConfigurationError("synthetic_validator_projection_binding_mismatch") from exc
        return {
            "status_code": 409, "headers": [["content-type", "application/json"]],
            "body_b64": base64.b64encode(body).decode("ascii"),
            "envelope_hash": envelope_hash, "body_sha256": body_hash,
            "scope": dict(result["scope"]), "source": dict(source),
            "delivery": "candidate_only_no_send_authorization",
        }

    async def project_inventory_snapshot(
        self, *, receipt_id: UUID, operation_id: str, resource_id: str,
        request_fingerprint: str, expected_environment_id: str,
        expected_deployment_id: str, expected_session_id: str,
        expected_read_admission_id: str, expected_world_generation_id: str,
        expected_state_version: int, expected_state_hash: str,
    ) -> dict[str, object]:
        """只從唯讀 Validator 的固定 I-04 ReadAdmission 重建 200／409 候選。

        Verifier 不傳回應碼、庫存數量、版本或 Body；獨立校驗契約、來源
        ReadAdmission、Scope、Envelope 和精確 JSON bytes，絕不允許直接 Send。
        """
        from deception.world.transmission import response_hashes

        if (operation_id != "getSyntheticInventory"
                or not isinstance(resource_id, str)
                or re.fullmatch(r"[A-Za-z0-9._-]{1,128}", resource_id) is None):
            raise ProtectedRpcConfigurationError("inventory_validator_operation_unapproved")
        async with httpx.AsyncClient(verify=self._tls, trust_env=False, timeout=8.0) as client:
            response = await client.post(
                self._origin + "/internal/v1/project-inventory-snapshot",
                json={"receipt_id": str(receipt_id)},
            )
        if response.status_code != 200:
            raise ProtectedRpcConfigurationError("inventory_validator_projection_unverifiable")
        try:
            result = json.loads(response.content, object_pairs_hook=unique_object,
                                parse_constant=reject_constant)
            if not isinstance(result, dict) or set(result) != {
                    "receipt_id", "operation_id", "scope", "request_fingerprint",
                    "status_code", "headers", "body_b64", "envelope_hash", "source",
                    "trusted_send"}:
                raise ValueError("inventory_validator_shape_invalid")
            body = _canonical_base64(result["body_b64"], max_bytes=4096)
            parsed_body = json.loads(body, object_pairs_hook=unique_object,
                                     parse_constant=reject_constant)
            source = result["source"]
            scope = result["scope"]
            status = result["status_code"]
            valid_body = False
            if type(status) is int and status == 200 and isinstance(parsed_body, dict):
                valid_body = (set(parsed_body) == {"sku", "available", "state_version"}
                              and parsed_body["sku"] == resource_id
                              and type(parsed_body["available"]) is int
                              and parsed_body["available"] >= 0
                              and type(parsed_body["state_version"]) is int
                              and parsed_body["state_version"] >= 1)
            elif type(status) is int and status == 409:
                from deception.world.protected_native_http import fixed_synthetic_rejection_bytes
                _, expected_body = fixed_synthetic_rejection_bytes(
                    "synthetic-inventory", "unknown_synthetic_sku")
                valid_body = (parsed_body == {"code": "unknown_synthetic_sku"}
                              and body == expected_body)
            if (not valid_body
                    or not isinstance(source, dict) or set(source) != {
                        "kind", "read_admission_id", "world_generation_id",
                        "state_version", "state_hash"}
                    or source["kind"] != "snapshot"
                    or not isinstance(source["read_admission_id"], str)
                    or re.fullmatch(r"[0-9a-f]{32}", source["read_admission_id"]) is None
                    or source["read_admission_id"] != expected_read_admission_id
                    or (status == 200
                        and source["state_version"] != parsed_body["state_version"])
                    or source["state_version"] != expected_state_version
                    or not isinstance(source["state_hash"], str)
                    or re.fullmatch(r"[0-9a-f]{64}", source["state_hash"]) is None
                    or source["state_hash"] != expected_state_hash
                    or not isinstance(scope, dict) or set(scope) != {
                        "environment_id", "deployment_id", "session_id", "world_generation_id"}
                    or (scope.get("environment_id"), scope.get("deployment_id"),
                        scope.get("session_id")) != (
                        expected_environment_id, expected_deployment_id, expected_session_id)
                    or not isinstance(scope.get("world_generation_id"), str)
                    or not scope["world_generation_id"]
                    or source["world_generation_id"] != scope["world_generation_id"]
                    or source["world_generation_id"] != expected_world_generation_id
                    or body != json.dumps(parsed_body, ensure_ascii=False, sort_keys=True,
                                          separators=(",", ":")).encode("utf-8")
                    or result["receipt_id"] != str(receipt_id)
                    or result["operation_id"] != operation_id
                    or result["request_fingerprint"] != request_fingerprint
                    or type(result["status_code"]) is not int or status not in {200, 409}
                    or result["headers"] != [["content-type", "application/json"]]
                    or result["trusted_send"] != "disabled"
                    or result["envelope_hash"] != response_hashes(
                        status, (("content-type", "application/json"),), body)[0]):
                raise ValueError("inventory_validator_binding_mismatch")
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            raise ProtectedRpcConfigurationError("inventory_validator_binding_mismatch") from exc
        return {
            "status_code": status, "headers": [["content-type", "application/json"]],
            "body_b64": base64.b64encode(body).decode("ascii"),
            "body_sha256": response_hashes(status, (("content-type", "application/json"),), body)[1],
            "envelope_hash": result["envelope_hash"], "source": dict(source),
            "scope": dict(scope), "delivery": "candidate_only_no_send_authorization",
        }

    async def project_inventory_operation(
        self, *, receipt_id: UUID, operation_id: str, resource_id: str,
        request_fingerprint: str, expected_environment_id: str,
        expected_deployment_id: str, expected_session_id: str,
        expected_read_admission_id: str, expected_world_generation_id: str,
        expected_state_version: int, expected_state_hash: str,
    ) -> dict[str, object]:
        """以獨立 Validator 的 I-03 真 Commit/Read 證據取得固定成功候選。

        Verifier 無權提供 Status、Body 或回應操作結果；歷史 Commit 的版本
        可小於當前 ReadAdmission 的快照版本，不能偷換成當前版本。
        """
        from deception.world.transmission import response_hashes

        if operation_id != "getSyntheticOperation" or not isinstance(resource_id, str):
            raise ProtectedRpcConfigurationError("inventory_operation_validator_unapproved")
        try:
            attempt = UUID(resource_id)
        except ValueError as exc:
            raise ProtectedRpcConfigurationError("inventory_operation_validator_unapproved") from exc
        if attempt.version != 4 or str(attempt) != resource_id:
            raise ProtectedRpcConfigurationError("inventory_operation_validator_unapproved")
        async with httpx.AsyncClient(verify=self._tls, trust_env=False, timeout=8.0) as client:
            response = await client.post(
                self._origin + "/internal/v1/project-inventory-operation",
                json={"receipt_id": str(receipt_id)},
            )
        if response.status_code != 200:
            raise ProtectedRpcConfigurationError("inventory_operation_projection_unverifiable")
        try:
            result = json.loads(response.content, object_pairs_hook=unique_object,
                                parse_constant=reject_constant)
            if not isinstance(result, dict) or set(result) != {
                    "receipt_id", "operation_id", "scope", "request_fingerprint",
                    "status_code", "headers", "body_b64", "envelope_hash", "source",
                    "trusted_send"}:
                raise ValueError("inventory_operation_shape_invalid")
            body = _canonical_base64(result["body_b64"], max_bytes=4096)
            parsed = json.loads(body, object_pairs_hook=unique_object,
                                parse_constant=reject_constant)
            source, scope = result["source"], result["scope"]
            reservation = parsed.get("reservation") if isinstance(parsed, dict) else None
            if (not isinstance(parsed, dict) or set(parsed) != {
                    "commit_attempt_id", "state_version", "state_hash", "reservation"}
                    or parsed["commit_attempt_id"] != resource_id
                    or type(parsed["state_version"]) is not int
                    or not 1 <= parsed["state_version"] <= expected_state_version
                    or not isinstance(parsed["state_hash"], str)
                    or re.fullmatch(r"[0-9a-f]{64}", parsed["state_hash"]) is None
                    or not isinstance(reservation, dict)
                    or set(reservation) != {"reservation_id", "sku", "quantity", "status"}
                    or not isinstance(reservation["reservation_id"], str)
                    or re.fullmatch(r"[0-9a-f]{32}", reservation["reservation_id"]) is None
                    or not isinstance(reservation["sku"], str)
                    or not 1 <= len(reservation["sku"]) <= 128
                    or type(reservation["quantity"]) is not int or reservation["quantity"] < 1
                    or reservation["status"] not in {"reserved", "cancelled"}
                    or not isinstance(source, dict) or set(source) != {
                        "kind", "read_admission_id", "world_generation_id",
                        "state_version", "state_hash"}
                    or source["kind"] != "snapshot"
                    or source["read_admission_id"] != expected_read_admission_id
                    or source["state_version"] != expected_state_version
                    or source["state_hash"] != expected_state_hash
                    or source["world_generation_id"] != expected_world_generation_id
                    or not isinstance(scope, dict) or set(scope) != {
                        "environment_id", "deployment_id", "session_id", "world_generation_id"}
                    or (scope["environment_id"], scope["deployment_id"], scope["session_id"],
                        scope["world_generation_id"]) != (
                            expected_environment_id, expected_deployment_id, expected_session_id,
                            expected_world_generation_id)
                    or result["receipt_id"] != str(receipt_id)
                    or result["operation_id"] != operation_id
                    or result["request_fingerprint"] != request_fingerprint
                    or type(result["status_code"]) is not int or result["status_code"] != 200
                    or result["headers"] != [["content-type", "application/json"]]
                    or result["trusted_send"] != "disabled"
                    or body != json.dumps(parsed, ensure_ascii=False, sort_keys=True,
                                          separators=(",", ":")).encode("utf-8")
                    or result["envelope_hash"] != response_hashes(
                        200, (("content-type", "application/json"),), body)[0]):
                raise ValueError("inventory_operation_binding_mismatch")
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            raise ProtectedRpcConfigurationError("inventory_operation_binding_mismatch") from exc
        return {
            "status_code": 200, "headers": [["content-type", "application/json"]],
            "body_b64": base64.b64encode(body).decode("ascii"),
            "body_sha256": response_hashes(200, (("content-type", "application/json"),), body)[1],
            "envelope_hash": result["envelope_hash"], "scope": dict(scope),
            "source": dict(source), "delivery": "candidate_only_no_send_authorization",
        }


def _canonical_base64(raw: str, *, max_bytes: int) -> bytes:
    """嚴格拒絕替代編碼與超大資料，避免 RPC 與 Verifier 解析分歧。"""
    if not isinstance(raw, str) or not raw.isascii():
        raise ValueError("invalid_base64_rpc_field")
    try:
        decoded = base64.b64decode(raw, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid_base64_rpc_field") from exc
    if len(decoded) > max_bytes or base64.b64encode(decoded).decode("ascii") != raw:
        raise ValueError("invalid_base64_rpc_field")
    return decoded


def create_fixed_executor_app(*, executor) -> FastAPI:
    """隔離 Executor mTLS 專用 HTTP 入口，所有 Handler／Scope 由 DB Receipt 決定。

    不接受 Runtime 自選 operation、binding、expected version 或初始世界。
    這個 App 僅准在專用 mTLS Listener 與實體 Executor SCRAM Role 執行；
    正式 Send Release Fuse 仍維持封閉，Medusa 未具 400/404 來源時禁止執行。
    """
    from deception.world.protected_world import PostgresProtectedWorldExecutor

    if not isinstance(executor, PostgresProtectedWorldExecutor):
        raise ProtectedRpcConfigurationError("fixed_executor_requires_protected_world")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/internal/ready")
    async def ready() -> dict[str, str]:
        """表明隔離固定 Handler RPC 已掛載，正式傳輸依舊關閉。"""
        return {"control_plane": "executor-lab-only", "trusted_send": "disabled"}

    @app.post("/internal/v1/execute")
    async def execute(request: Request) -> dict[str, object]:
        """從唯一 Receipt 與原始 bytes 在獨立 Executor 取回受保護業務結果。

        RPC 內容重複 JSON 欄位、替代 base64、超大封包或平台／操作不一致，
        在操作前拒絕；任何不明 COMMIT 只回固定 503，不重新起送。
        回傳只供獨立服務對帳，不得直接當成已授權 Client HTTP Response。
        """
        from deception.api.ingress import MAX_BODY_BYTES

        if request.scope.get("scheme") != "https":
            raise HTTPException(status_code=503, detail="fixed_executor_tls_required")
        received = bytearray()
        async for chunk in request.stream():
            if len(received) + len(chunk) > MAX_BODY_BYTES * 2:
                raise HTTPException(status_code=413, detail="fixed_executor_rpc_too_large")
            received.extend(chunk)
        try:
            parsed = json.loads(received, object_pairs_hook=unique_object,
                                parse_constant=reject_constant)
            if not isinstance(parsed, dict):
                raise ValueError("fixed_executor_rpc_object_required")
            # strict UUID4 模型允許 JSON 字串 UUID，但不接受 Python 字串隱式轉型。
            call = FixedExecutorCall.model_validate_json(bytes(received))
            path = _canonical_base64(call.raw_path_b64, max_bytes=2048)
            body = _canonical_base64(call.raw_body_b64, max_bytes=MAX_BODY_BYTES)
            original = None
            if call.original_http is not None:
                if any(name.lower() not in FINGERPRINT_HEADERS
                       or not name.isascii() or "\r" in value or "\n" in value
                       for name, value in call.original_http.headers):
                    raise ValueError("fixed_executor_original_headers_denied")
                original = NormalizedRequest(
                    request_id=call.original_http.request_id,
                    method="", raw_url=call.original_http.raw_url,
                    path="", raw_path=path, query_string=b"", query=(),
                    headers=call.original_http.headers, body=body,
                )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="fixed_executor_rpc_invalid") from exc
        try:
            return executor.execute_verified_http(
                receipt_id=UUID(str(call.receipt_id)), raw_path=path, raw_body=body,
                original_http=original,
            )
        except Exception as exc:
            # 不泄露受保護 DB／業務／重試細節；不可把未知 COMMIT 當安全重試。
            raise HTTPException(status_code=503, detail="fixed_executor_unverifiable") from exc

    return app


def create_native_validator_app(*, projector) -> FastAPI:
    """在專用 Validator mTLS 入口重建受保護的 Medusa 原生拒絕候選。

    只接受 Receipt，不接受 Caller 指定模板、Scope、Status 或 Payload。
    回傳的是內部候選交接資料，**不能**作為已授權的客戶端 HTTP 回應。
    """
    from deception.world.protected_native_http import PostgresProtectedNativeProjector

    if not isinstance(projector, PostgresProtectedNativeProjector):
        raise ProtectedRpcConfigurationError("native_validator_requires_protected_projector")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/internal/ready")
    async def ready() -> dict[str, str]:
        """只回報 Validator 已掛載且 Sender 關閉，不承諾來源或 Profile 已核准。"""
        return {"control_plane": "native-validator-candidate-only", "trusted_send": "disabled"}

    @app.post("/internal/v1/project-inventory-snapshot")
    @app.post("/internal/v1/project-inventory-operation")
    @app.post("/internal/v1/project-synthetic-rejection")
    @app.post("/internal/v1/project-medusa-rejection")
    async def project(request: Request) -> dict[str, object]:
        """按固定 URL 選 Medusa 400/404 或 Synthetic 409，不接受 Caller 選模板。"""
        if request.scope.get("scheme") != "https":
            raise HTTPException(status_code=503, detail="native_validator_tls_required")
        received = bytearray()
        async for chunk in request.stream():
            if len(received) + len(chunk) > 1024:
                raise HTTPException(status_code=413, detail="native_validator_request_too_large")
            received.extend(chunk)
        try:
            parsed = json.loads(received, object_pairs_hook=unique_object,
                                parse_constant=reject_constant)
            if not isinstance(parsed, dict):
                raise ValueError("native_validator_object_required")
            call = FixedNativeProjectionCall.model_validate_json(received)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="native_validator_request_invalid") from exc
        try:
            if request.scope.get("path") == "/internal/v1/project-inventory-snapshot":
                projected = projector.project_inventory_snapshot(UUID(str(call.receipt_id)))
            elif request.scope.get("path") == "/internal/v1/project-inventory-operation":
                projected = projector.project_inventory_operation(UUID(str(call.receipt_id)))
            elif request.scope.get("path") == "/internal/v1/project-synthetic-rejection":
                projected = projector.project_synthetic_rejection(UUID(str(call.receipt_id)))
            else:
                projected = projector.project_medusa_rejection(UUID(str(call.receipt_id)))
        except Exception as exc:
            raise HTTPException(status_code=503, detail="native_validator_source_unverifiable") from exc
        return {
            "receipt_id": str(projected.receipt_id), "operation_id": projected.operation_id,
            "scope": projected.scope.model_dump(),
            "request_fingerprint": projected.request_fingerprint,
            "status_code": projected.status_code,
            "headers": list(projected.headers),
            "body_b64": base64.b64encode(projected.body_bytes).decode("ascii"),
            "envelope_hash": projected.envelope_hash,
            "source": projected.source.model_dump(),
            "trusted_send": "disabled",
        }

    return app


def create_fixed_sender_app(*, sender) -> FastAPI:
    """建立獨立 Sender 的封閉 mTLS API；G5 Fence 前絕不觸發一次性 Lease。

    即使已經配置專用資料庫 Login，HTTP Caller 也不能提供 Admission、Receipt、
    Snapshot 或啟用旗標來要求 StartSend。此 API 僅供 G4 服務隔離驗收。
    """
    from deception.world.protected_send import PostgresProtectedSender

    if not isinstance(sender, PostgresProtectedSender):
        raise ProtectedRpcConfigurationError("fixed_sender_requires_protected_sender")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/internal/ready")
    async def ready() -> dict[str, str]:
        """只回報 Sender mTLS 服務存活，不聲稱可起送或完成 G5。"""
        return {"control_plane": "sender-sealed-until-restore-fence",
                "trusted_send": "disabled"}

    @app.post("/internal/v1/send")
    async def send() -> None:
        """任何起送或偽造 Payload 嘗試都固定封閉，且不呼叫 Sender。"""
        raise HTTPException(status_code=503, detail="fixed_sender_restore_fence_required")

    return app


def create_direct_verifier_app(
    *, verifier, postgres_dsn: str, environment_id: str, deployment_id: str,
    expected_issuer: str, expected_audience: str,
    executor_client: FixedExecutorMTLSClient | None = None,
    executor_clients: Mapping[str, FixedExecutorMTLSClient] | None = None,
    native_validator_client: FixedNativeValidatorMTLSClient | None = None,
) -> FastAPI:
    """在獨立 Gateway mTLS 入口由實際 HTTP 訊息建立受保護 Operation Receipt。

    直接使用 ASGI 原始 path/header/body；不接受 Runtime 送入的 claims、
    已驗證旗標、Handler 名稱或用 JSON 重建的 Request。只提供內部 Receipt
    身份，不建立候選、不執行業務且絕不核發正式 HTTP Send 權。
    專用 Client CA 必須只簽發給原始 HTTP Gateway，不能供 Runtime 使用。
    """
    from deception.security.trusted_session import TrustedSessionVerifier

    if not isinstance(verifier, TrustedSessionVerifier):
        raise ProtectedRpcConfigurationError("direct_verifier_requires_trusted_verifier")
    if executor_client is not None and not isinstance(executor_client, FixedExecutorMTLSClient):
        raise ProtectedRpcConfigurationError("direct_verifier_executor_client_invalid")
    if executor_client is not None and executor_clients is not None:
        raise ProtectedRpcConfigurationError("direct_verifier_executor_routes_ambiguous")
    if native_validator_client is not None and not isinstance(native_validator_client, FixedNativeValidatorMTLSClient):
        raise ProtectedRpcConfigurationError("direct_verifier_native_validator_invalid")
    if executor_clients is not None and (
            not isinstance(executor_clients, Mapping) or not executor_clients
            or any(platform not in {"synthetic-inventory", "synthetic-carts", "medusa-native-cart"}
                   or not isinstance(client, FixedExecutorMTLSClient)
                   for platform, client in executor_clients.items())):
        raise ProtectedRpcConfigurationError("direct_verifier_executor_routes_invalid")
    fixed_clients = MappingProxyType(dict(executor_clients or {}))
    if not isinstance(postgres_dsn, str) or not postgres_dsn.strip():
        raise ProtectedRpcConfigurationError("direct_verifier_requires_db")
    if any(not isinstance(value, str) or not 1 <= len(value) <= 128 for value in (
            environment_id, deployment_id, expected_issuer, expected_audience)):
        raise ProtectedRpcConfigurationError("direct_verifier_identity_invalid")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/internal/ready")
    async def ready() -> dict[str, str]:
        """只證明內部 Verifier HTTP Listener 存活，正式發送仍封閉。"""
        return {"control_plane": "verifier-dispatch" if executor_client or fixed_clients else "verifier-only",
                "trusted_send": "disabled"}

    @app.post("/internal/v1/execute")
    async def execute_disabled() -> dict[str, str]:
        """阻擋將 Verifier 誤作可由 Runtime 指定 Handler 的業務 RPC。"""
        raise HTTPException(status_code=503, detail="direct_verifier_execution_not_available")

    @app.api_route("/{original_path:path}", methods=["GET", "POST", "DELETE"])
    async def verify_original(request: Request, original_path: str) -> dict[str, object]:
        """先從 ASGI 取得可信原始快照，再驗簽並原子記錄 Replay／Receipt／Operation。

        不接受 http／proxy header 模擬 TLS；只有 mTLS Listener 的真實 HTTPS
        Scope 可以進入。結果供專用 Gateway 對帳及日後獨立 Executor 使用；
        這裡不返回業務 200／400／404 或任何可被當成已授權的 Payload。
        """
        from deception.api.fingerprint import fingerprint_request
        from deception.api.ingress import normalize_request, resolve_request_id
        from deception.security.ingress_receipt import PostgresIngressReceiptWriter
        from deception.security.operation_binding import derive_verified_operation

        if request.scope.get("scheme") != "https":
            raise HTTPException(status_code=503, detail="direct_verifier_tls_required")
        normalized = await normalize_request(request, resolve_request_id(request))
        try:
            operation = derive_verified_operation(normalized)
            if fixed_clients and operation.platform not in fixed_clients:
                raise HTTPException(status_code=503,
                                    detail="direct_verifier_executor_platform_unavailable")
            tokens = [value for name, value in normalized.headers
                      if name.lower() == "x-trusted-session"]
            if len(tokens) != 1 or not tokens[0]:
                raise ValueError("trusted_session_header_missing_or_duplicate")
            writer = PostgresIngressReceiptWriter(
                postgres_dsn, environment_id=environment_id,
                deployment_id=deployment_id, verified_request=normalized,
            )
            claims, receipt_id = verifier.verify_with_receipt(
                tokens[0], expected_issuer=expected_issuer,
                expected_audience=expected_audience,
                request_fingerprint=fingerprint_request(normalized),
                environment_id=environment_id, deployment_id=deployment_id,
                receipt_writer=writer,
            )
        except ValueError as exc:
            raise HTTPException(status_code=403, detail="direct_verifier_request_denied") from exc
        # 已建立 Receipt 後的 RPC 結果不明，不能重新消費 JTI 或盲目重執行。
        outcome = None
        selected_client = (fixed_clients.get(operation.platform) if fixed_clients else executor_client)
        if selected_client is not None:
            try:
                outcome = await selected_client.execute_receipt(
                    receipt_id=receipt_id, operation_id=operation.operation_id,
                    raw_path=normalized.raw_path, raw_body=normalized.body,
                    original_request=normalized,
                )
            except Exception as exc:
                raise HTTPException(status_code=503,
                                    detail="direct_verifier_executor_unverifiable") from exc
        projection = None
        if isinstance(outcome, dict) and outcome.get("kind") == "medusa_rejection":
            if native_validator_client is None:
                raise HTTPException(status_code=503,
                                    detail="direct_verifier_native_validator_not_wired")
            try:
                projection = await native_validator_client.project_receipt(
                    receipt_id=receipt_id, operation_id=operation.operation_id,
                    request_fingerprint=fingerprint_request(normalized),
                    expected_status=outcome["status_code"],
                    expected_envelope_hash=outcome["envelope_hash"],
                    expected_environment_id=claims.environment_id,
                    expected_deployment_id=claims.deployment_id,
                    expected_session_id=claims.session_id,
                )
            except Exception as exc:
                raise HTTPException(status_code=503,
                                    detail="direct_verifier_native_projection_unverifiable") from exc
        elif (isinstance(outcome, dict) and outcome.get("kind") == "inventory_read_admitted"
              and operation.operation_id == "getSyntheticInventory"):
            if native_validator_client is None:
                raise HTTPException(status_code=503,
                                    detail="direct_verifier_native_validator_not_wired")
            try:
                projection = await native_validator_client.project_inventory_snapshot(
                    receipt_id=receipt_id, operation_id=operation.operation_id,
                    resource_id=outcome["resource_id"],
                    request_fingerprint=fingerprint_request(normalized),
                    expected_environment_id=claims.environment_id,
                    expected_deployment_id=claims.deployment_id,
                    expected_session_id=claims.session_id,
                    expected_read_admission_id=outcome["read_admission_id"],
                    expected_world_generation_id=outcome["world_generation_id"],
                    expected_state_version=outcome["state_version"],
                    expected_state_hash=outcome["state_hash"],
                )
            except Exception as exc:
                raise HTTPException(status_code=503,
                                    detail="direct_verifier_inventory_projection_unverifiable") from exc
        elif (isinstance(outcome, dict) and outcome.get("kind") == "inventory_read_admitted"
              and operation.operation_id == "getSyntheticOperation"):
            if native_validator_client is None:
                raise HTTPException(status_code=503,
                                    detail="direct_verifier_native_validator_not_wired")
            try:
                projection = await native_validator_client.project_inventory_operation(
                    receipt_id=receipt_id, operation_id=operation.operation_id,
                    resource_id=outcome["resource_id"],
                    request_fingerprint=fingerprint_request(normalized),
                    expected_environment_id=claims.environment_id,
                    expected_deployment_id=claims.deployment_id,
                    expected_session_id=claims.session_id,
                    expected_read_admission_id=outcome["read_admission_id"],
                    expected_world_generation_id=outcome["world_generation_id"],
                    expected_state_version=outcome["state_version"],
                    expected_state_hash=outcome["state_hash"],
                )
            except Exception as exc:
                raise HTTPException(status_code=503,
                                    detail="direct_verifier_operation_projection_unverifiable") from exc
        elif (isinstance(outcome, dict) and outcome.get("kind") == "world_mutation"
              and outcome.get("status") == "rejected"):
            if native_validator_client is None:
                raise HTTPException(status_code=503,
                                    detail="direct_verifier_native_validator_not_wired")
            try:
                projection = await native_validator_client.project_synthetic_rejection(
                    receipt_id=receipt_id, operation_id=operation.operation_id,
                    platform=operation.platform,
                    request_fingerprint=fingerprint_request(normalized),
                    expected_environment_id=claims.environment_id,
                    expected_deployment_id=claims.deployment_id,
                    expected_session_id=claims.session_id,
                )
            except Exception as exc:
                raise HTTPException(status_code=503,
                                    detail="direct_verifier_synthetic_projection_unverifiable") from exc
        # 不能在 HTTP 回應暴露已驗證 claims 或受保護 DB Secret；此結果非 Sender。
        result: dict[str, object] = {"receipt_id": str(receipt_id),
                                     "operation_id": operation.operation_id}
        if outcome is not None:
            result["executor_result"] = outcome
        if projection is not None:
            result["native_projection"] = projection
        return result

    return app


def require_mtls_files(*, server_cert: Path, server_key: Path, client_ca: Path) -> None:
    """確認三種不同用途的 TLS 檔案都已存在且不是同一個實體檔案。

    憑證與 key 必須由部署管理者透過唯讀 Secret Mount 提供；不建立預設
    自簽憑證，也不接受以 request headers 模擬 client identity。
    """
    paths = (server_cert, server_key, client_ca)
    if any(not isinstance(path, Path) or not path.is_file() for path in paths):
        raise ProtectedRpcConfigurationError("protected_rpc_mtls_files_required")
    if len({path.resolve() for path in paths}) != 3:
        raise ProtectedRpcConfigurationError("protected_rpc_mtls_file_reuse_denied")
    for path in paths:
        if path.stat().st_size == 0:
            raise ProtectedRpcConfigurationError("protected_rpc_empty_mtls_file")


def create_sealed_app() -> FastAPI:
    """提供不含敏感資料的控制面健康檢查；禁止一切尚未核准的業務呼叫。"""
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/internal/ready")
    async def ready() -> dict[str, str]:
        """表明 mTLS 傳輸已啟動，但執行與發送權仍然關閉。"""
        return {"control_plane": "sealed", "trusted_send": "disabled"}

    @app.post("/internal/v1/execute")
    async def execute_disabled() -> dict[str, str]:
        """拒絕未完成 Receipt/Operation 綁定的任意 RPC，不處理請求副作用。"""
        from fastapi import HTTPException

        raise HTTPException(status_code=503, detail="protected_rpc_operation_binding_not_ready")

    return app


def serve_sealed_mtls(*, host: str, port: int, server_cert: Path,
                      server_key: Path, client_ca: Path) -> None:
    """以 TLS Client Certificate Required 啟動專屬服務，拒絕普通 HTTPS 客戶端。

    服務只提供 sealed endpoint；獨立 Executor 憑證及其資料庫連線不得在
    HTTP Runtime 程序環境中配置。不能把此函式當作 G3b 業務接線成功。
    """
    require_mtls_files(server_cert=server_cert, server_key=server_key, client_ca=client_ca)
    if not isinstance(host, str) or not host or type(port) is not int or not 1 <= port <= 65535:
        raise ProtectedRpcConfigurationError("protected_rpc_bind_invalid")
    config = uvicorn.Config(
        create_sealed_app(), host=host, port=port,
        ssl_certfile=str(server_cert), ssl_keyfile=str(server_key),
        ssl_ca_certs=str(client_ca), ssl_cert_reqs=ssl.CERT_REQUIRED,
        ssl_version=ssl.PROTOCOL_TLS_SERVER, http="h11", log_level="warning",
        proxy_headers=False,
    )
    if config.ssl_cert_reqs is not ssl.CERT_REQUIRED:
        raise ProtectedRpcConfigurationError("protected_rpc_mtls_not_required")
    uvicorn.Server(config).run()


def serve_direct_verifier_mtls(
    *, app: FastAPI, host: str, port: int, server_cert: Path,
    server_key: Path, client_ca: Path,
) -> None:
    """以獨立 Gateway 專用 Client CA 啟動直接 HTTP Verifier，拒絕非 mTLS 流量。

    呼叫者只能傳入同一專屬 Verifier 程序建立的 App；沒有環境變數可
    自行關閉 Client Cert 驗證，也沒有 generic execute／Sender 後門。
    """
    if not isinstance(app, FastAPI):
        raise ProtectedRpcConfigurationError("direct_verifier_app_required")
    require_mtls_files(server_cert=server_cert, server_key=server_key, client_ca=client_ca)
    if not isinstance(host, str) or not host or type(port) is not int or not 1 <= port <= 65535:
        raise ProtectedRpcConfigurationError("direct_verifier_bind_invalid")
    config = uvicorn.Config(
        app, host=host, port=port,
        ssl_certfile=str(server_cert), ssl_keyfile=str(server_key),
        ssl_ca_certs=str(client_ca), ssl_cert_reqs=ssl.CERT_REQUIRED,
        ssl_version=ssl.PROTOCOL_TLS_SERVER, http="h11", log_level="warning",
        proxy_headers=False, access_log=False,
    )
    if config.ssl_cert_reqs is not ssl.CERT_REQUIRED:
        raise ProtectedRpcConfigurationError("direct_verifier_mtls_not_required")
    uvicorn.Server(config).run()


def serve_fixed_executor_mtls(
    *, app: FastAPI, host: str, port: int, server_cert: Path,
    server_key: Path, verifier_client_ca: Path,
) -> None:
    """使用只信任獨立 Verifier 的 Client CA 啟動 Executor，禁止明文回退。

    此入口目前只供隔離 Lab：執行業務不代表核發候選發送權，Medusa
    400／404 及完整 Gateway→Verifier→Executor 實體拓樸仍須逐項驗收。
    """
    if not isinstance(app, FastAPI):
        raise ProtectedRpcConfigurationError("fixed_executor_app_required")
    require_mtls_files(server_cert=server_cert, server_key=server_key,
                       client_ca=verifier_client_ca)
    if not isinstance(host, str) or not host or type(port) is not int or not 1 <= port <= 65535:
        raise ProtectedRpcConfigurationError("fixed_executor_bind_invalid")
    config = uvicorn.Config(
        app, host=host, port=port,
        ssl_certfile=str(server_cert), ssl_keyfile=str(server_key),
        ssl_ca_certs=str(verifier_client_ca), ssl_cert_reqs=ssl.CERT_REQUIRED,
        ssl_version=ssl.PROTOCOL_TLS_SERVER, http="h11", log_level="warning",
        proxy_headers=False, access_log=False,
    )
    if config.ssl_cert_reqs is not ssl.CERT_REQUIRED:
        raise ProtectedRpcConfigurationError("fixed_executor_mtls_not_required")
    uvicorn.Server(config).run()


def serve_native_validator_mtls(
    *, app: FastAPI, host: str, port: int, server_cert: Path,
    server_key: Path, verifier_client_ca: Path,
) -> None:
    """以獨立 Validator Server TLS 與專屬 Verifier Client CA 啟動只讀候選入口。"""
    if not isinstance(app, FastAPI):
        raise ProtectedRpcConfigurationError("native_validator_app_required")
    require_mtls_files(server_cert=server_cert, server_key=server_key,
                       client_ca=verifier_client_ca)
    if not isinstance(host, str) or not host or type(port) is not int or not 1 <= port <= 65535:
        raise ProtectedRpcConfigurationError("native_validator_bind_invalid")
    config = uvicorn.Config(
        app, host=host, port=port,
        ssl_certfile=str(server_cert), ssl_keyfile=str(server_key),
        ssl_ca_certs=str(verifier_client_ca), ssl_cert_reqs=ssl.CERT_REQUIRED,
        ssl_version=ssl.PROTOCOL_TLS_SERVER, http="h11", log_level="warning",
        proxy_headers=False, access_log=False,
    )
    if config.ssl_cert_reqs is not ssl.CERT_REQUIRED:
        raise ProtectedRpcConfigurationError("native_validator_mtls_not_required")
    uvicorn.Server(config).run()


def serve_fixed_sender_mtls(
    *, app: FastAPI, host: str, port: int, server_cert: Path,
    server_key: Path, sender_client_ca: Path,
) -> None:
    """用獨立 Sender Server 身分與專用 Caller CA 啟動封閉起送服務。"""
    if not isinstance(app, FastAPI):
        raise ProtectedRpcConfigurationError("fixed_sender_app_required")
    require_mtls_files(server_cert=server_cert, server_key=server_key,
                       client_ca=sender_client_ca)
    if not isinstance(host, str) or not host or type(port) is not int or not 1 <= port <= 65535:
        raise ProtectedRpcConfigurationError("fixed_sender_bind_invalid")
    config = uvicorn.Config(
        app, host=host, port=port,
        ssl_certfile=str(server_cert), ssl_keyfile=str(server_key),
        ssl_ca_certs=str(sender_client_ca), ssl_cert_reqs=ssl.CERT_REQUIRED,
        ssl_version=ssl.PROTOCOL_TLS_SERVER, http="h11", log_level="warning",
        proxy_headers=False, access_log=False,
    )
    if config.ssl_cert_reqs is not ssl.CERT_REQUIRED:
        raise ProtectedRpcConfigurationError("fixed_sender_mtls_not_required")
    uvicorn.Server(config).run()


def from_environment() -> None:
    """只接收專屬 mTLS Secret Mount，預設綁 loopback 且永遠封閉業務執行。"""
    names = ("MIRAGE_PROTECTED_RPC_CERT_FILE", "MIRAGE_PROTECTED_RPC_KEY_FILE",
             "MIRAGE_PROTECTED_RPC_CLIENT_CA_FILE")
    if any(not os.environ.get(name) for name in names):
        raise ProtectedRpcConfigurationError("protected_rpc_mtls_environment_required")
    raw_port = os.environ.get("MIRAGE_PROTECTED_RPC_PORT", "8444")
    if not raw_port.isascii() or not raw_port.isdecimal():
        raise ProtectedRpcConfigurationError("protected_rpc_port_invalid")
    serve_sealed_mtls(
        host=os.environ.get("MIRAGE_PROTECTED_RPC_HOST", "127.0.0.1"),
        port=int(raw_port), server_cert=Path(os.environ[names[0]]),
        server_key=Path(os.environ[names[1]]), client_ca=Path(os.environ[names[2]]),
    )


if __name__ == "__main__":
    from_environment()
