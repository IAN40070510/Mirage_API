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


class FixedAuthorizerCall(SyntheticModel):
    """授權 RPC 只收由 Verifier 已簽驗的 Receipt ID，不收候選或決策資料。"""

    receipt_id: UUID4


class FixedAuthorizerMTLSClient:
    """獨立 Verifier 以固定 mTLS 身分單次呼叫 Authorizer，不重送未知 COMMIT。"""

    def __init__(self, *, origin: str, client_cert: Path, client_key: Path,
                 server_ca: Path) -> None:
        """固定 Authorizer HTTPS 身分與專屬 Client 憑證，拒絕 URL 指向任意端點。"""
        url = urlsplit(origin) if isinstance(origin, str) else None
        if (url is None or url.scheme != "https" or not url.hostname or url.port is None
                or url.path not in {"", "/"} or url.query or url.fragment
                or url.username is not None or url.password is not None):
            raise ProtectedRpcConfigurationError("fixed_authorizer_origin_invalid")
        require_mtls_files(server_cert=client_cert, server_key=client_key, client_ca=server_ca)
        context = ssl.create_default_context(cafile=str(server_ca))
        context.load_cert_chain(str(client_cert), str(client_key))
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise ProtectedRpcConfigurationError("fixed_authorizer_tls_verification_required")
        self._origin = origin.rstrip("/")
        self._tls = context

    async def authorize_receipt(self, receipt_id: UUID) -> dict[str, str]:
        """只送單一 Receipt UUID4，精確核對回傳身分並拒絕任何補發指示。"""
        if not isinstance(receipt_id, UUID) or receipt_id.version != 4:
            raise ProtectedRpcConfigurationError("fixed_authorizer_receipt_invalid")
        async with httpx.AsyncClient(verify=self._tls, trust_env=False, timeout=8.0) as client:
            response = await client.post(
                self._origin + "/internal/v1/authorize-receipt",
                json={"receipt_id": str(receipt_id)},
            )
        if response.status_code != 200:
            raise ProtectedRpcConfigurationError("fixed_authorizer_result_unverifiable")
        try:
            data = json.loads(response.content, object_pairs_hook=unique_object,
                              parse_constant=reject_constant)
        except ValueError as exc:
            raise ProtectedRpcConfigurationError("fixed_authorizer_result_invalid") from exc
        if (not isinstance(data, dict)
                or set(data) != {"receipt_id", "admission_id", "send_owner",
                                 "request_fingerprint", "candidate_hash", "trusted_send"}
                or data["receipt_id"] != str(receipt_id)
                or data["send_owner"] != "protected-sender-" + receipt_id.hex
                or not isinstance(data["admission_id"], str)
                or not re.fullmatch(r"[0-9a-f]{32}", data["admission_id"])
                or any(not isinstance(data[name], str)
                       or not re.fullmatch(r"[0-9a-f]{64}", data[name])
                       for name in ("request_fingerprint", "candidate_hash"))
                or data["trusted_send"] != "disabled"):
            raise ProtectedRpcConfigurationError("fixed_authorizer_result_binding_mismatch")
        return data


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
        from deception.security.operation_binding import (
            OperationBindingError, decode_verified_inventory_sku_path,
        )

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
                                   "read_admission_id", "world_generation_id",
                                   "state_version", "state_hash"},
            "medusa_read_admitted": {"kind", "operation", "resource_id",
                                     "read_admission_id", "world_generation_id",
                                     "state_version", "state_hash"},
            "medusa_rejection": {"kind", "operation", "status_code", "template_id",
                                 "contract_revision", "envelope_hash"},
            "medusa_mutation": {"kind", "operation", "commit_attempt_id", "status",
                                 "state_version", "state_hash", "result_digest"},
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
                or (result["kind"] == "medusa_mutation" and result.get("status") != "committed")
                or (result["kind"] == "cart_created" and result.get("status") != "committed")):
            raise ProtectedRpcConfigurationError("fixed_executor_result_binding_mismatch")
        valid_sku_path = False
        if result["kind"] == "inventory_read_admitted" and operation_id == "getSyntheticInventory":
            try:
                valid_sku_path = decode_verified_inventory_sku_path(raw_path) == result.get("resource_id")
            except OperationBindingError:
                pass
        if result["kind"] == "inventory_read_admitted" and (
                operation_id not in {"getSyntheticInventory", "getSyntheticOperation"}
                or not isinstance(result.get("resource_id"), str)
                or not isinstance(raw_path, bytes) or not isinstance(raw_body, bytes)
                or raw_body != b""
                or (not valid_sku_path if operation_id == "getSyntheticInventory"
                    else raw_path != b"/synthetic/operations/" + result["resource_id"].encode("utf-8"))
                or not all(isinstance(result.get(field), str)
                           and re.fullmatch(r"[0-9a-f]{32}", result[field]) is not None
                           for field in ("read_admission_id", "world_generation_id"))
                or type(result.get("state_version")) is not int or result["state_version"] < 1
                or not isinstance(result.get("state_hash"), str)
                or re.fullmatch(r"[0-9a-f]{64}", result["state_hash"]) is None):
            raise ProtectedRpcConfigurationError("fixed_executor_result_binding_mismatch")
        if result["kind"] == "cart_read_admitted":
            cart_routes = {
                "getGuestCart": (b"/synthetic/carts/", b"cart_"),
                "getSyntheticOrder": (b"/synthetic/orders/", b"order_"),
                "getCartOperation": (b"/synthetic/carts/", b"cart_"),
            }
            route = cart_routes.get(operation_id)
            valid_resource = (isinstance(result.get("resource_id"), str)
                              and re.fullmatch(r"(?:cart|order)_[0-9a-f]{32}",
                                               result["resource_id"]) is not None)
            expected_path = (route[0] + result["resource_id"].encode("ascii")) if (
                route is not None and valid_resource) else b""
            attempt = result.get("attempt_id")
            if operation_id == "getCartOperation" and isinstance(attempt, str):
                try:
                    decoded_attempt = UUID(attempt)
                except ValueError:
                    decoded_attempt = None
                if decoded_attempt is not None and decoded_attempt.version == 4 and str(decoded_attempt) == attempt:
                    expected_path += b"/operations/" + attempt.encode("ascii")
                else:
                    expected_path = b""
            elif operation_id == "getCartOperation":
                expected_path = b""
            elif attempt is not None:
                expected_path = b""
            if (not valid_resource or route is None
                    or not result["resource_id"].startswith(route[1].decode("ascii"))
                    or raw_body != b"" or raw_path != expected_path
                    or not all(isinstance(result.get(field), str)
                               and re.fullmatch(r"[0-9a-f]{32}", result[field]) is not None
                               for field in ("read_admission_id", "world_generation_id"))
                    or type(result.get("state_version")) is not int
                    or result["state_version"] < 1
                    or not isinstance(result.get("state_hash"), str)
                    or re.fullmatch(r"[0-9a-f]{64}", result["state_hash"]) is None):
                raise ProtectedRpcConfigurationError("fixed_executor_result_binding_mismatch")
        if result["kind"] == "medusa_read_admitted":
            routes = {"GetCartsId": (b"/store/carts/", "cart_"),
                      "GetOrdersId": (b"/store/orders/", "order_")}
            route = routes.get(operation_id)
            resource = result.get("resource_id")
            if (route is None or not isinstance(resource, str)
                    or re.fullmatch(re.escape(route[1]) + r"[0-9a-f]{32}", resource) is None
                    or raw_path != route[0] + resource.encode("ascii") or raw_body != b""
                    or not all(isinstance(result.get(field), str)
                               and re.fullmatch(r"[0-9a-f]{32}", result[field]) is not None
                               for field in ("read_admission_id", "world_generation_id"))
                    or type(result.get("state_version")) is not int
                    or result["state_version"] < 1
                    or not isinstance(result.get("state_hash"), str)
                    or re.fullmatch(r"[0-9a-f]{64}", result["state_hash"]) is None):
                raise ProtectedRpcConfigurationError("fixed_executor_result_binding_mismatch")
        if result["kind"] == "medusa_mutation":
            try:
                attempt = UUID(result["commit_attempt_id"])
            except (TypeError, ValueError) as exc:
                raise ProtectedRpcConfigurationError("fixed_executor_result_binding_mismatch") from exc
            medusa_mutations = {
                "PostCartsIdLineItems": (
                    rb"/store/carts/cart_[0-9a-f]{32}/line-items", 2,
                ),
                "PostCartsIdLineItemsLine_id": (
                    rb"/store/carts/cart_[0-9a-f]{32}/line-items/item_[0-9a-f]{32}", 3,
                ),
                "DeleteCartsIdLineItemsLine_id": (
                    rb"/store/carts/cart_[0-9a-f]{32}/line-items/item_[0-9a-f]{32}", 4,
                ),
                "PostCartsIdComplete": (
                    rb"/store/carts/cart_[0-9a-f]{32}/complete", 3,
                ),
            }
            allowed = medusa_mutations.get(operation_id)
            if (allowed is None or re.fullmatch(allowed[0], raw_path) is None
                    or attempt.version != 4 or str(attempt) != result["commit_attempt_id"]
                    or type(result["state_version"]) is not int
                    or result["state_version"] < allowed[1]
                    or not all(isinstance(result[field], str)
                               and re.fullmatch(r"[0-9a-f]{64}", result[field]) is not None
                               for field in ("state_hash", "result_digest"))):
                raise ProtectedRpcConfigurationError("fixed_executor_result_binding_mismatch")
        if result["kind"] == "cart_created":
            try:
                created_attempt = UUID(result["commit_attempt_id"])
            except (TypeError, ValueError) as exc:
                raise ProtectedRpcConfigurationError("fixed_executor_result_binding_mismatch") from exc
            if (operation_id not in {"createGuestCart", "PostCarts"}
                    or raw_path != (b"/synthetic/carts" if operation_id == "createGuestCart"
                                    else b"/store/carts")
                    or not isinstance(result["resource_id"], str)
                    or re.fullmatch(r"cart_[0-9a-f]{32}", result["resource_id"]) is None
                    or created_attempt.version != 4
                    or str(created_attempt) != result["commit_attempt_id"]):
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

    async def project_cart_creation(
        self, *, receipt_id: UUID, operation_id: str, resource_id: str,
        commit_attempt_id: str, request_fingerprint: str,
        expected_environment_id: str, expected_deployment_id: str,
        expected_session_id: str,
    ) -> dict[str, object]:
        """獨立 mTLS Validator 核實 C-01 的 Creator Scope 與跨 Scope Cart Source。"""
        from jsonschema import Draft202012Validator
        from deception.domains.ecommerce.cart_http import cart_specification
        from deception.world.transmission import response_hashes

        try:
            attempt = UUID(commit_attempt_id)
        except (TypeError, ValueError) as exc:
            raise ProtectedRpcConfigurationError("cart_creation_attempt_invalid") from exc
        if (operation_id != "createGuestCart" or attempt.version != 4
                or str(attempt) != commit_attempt_id
                or not isinstance(resource_id, str)
                or re.fullmatch(r"cart_[0-9a-f]{32}", resource_id) is None):
            raise ProtectedRpcConfigurationError("cart_creation_operation_unapproved")
        async with httpx.AsyncClient(verify=self._tls, trust_env=False, timeout=8.0) as client:
            response = await client.post(
                self._origin + "/internal/v1/project-receipt",
                json={"receipt_id": str(receipt_id)},
            )
        if response.status_code != 200:
            raise ProtectedRpcConfigurationError("cart_creation_projection_unverifiable")
        try:
            result = json.loads(response.content, object_pairs_hook=unique_object,
                                parse_constant=reject_constant)
            if not isinstance(result, dict) or set(result) != {
                    "receipt_id", "operation_id", "scope", "request_fingerprint",
                    "status_code", "headers", "body_b64", "envelope_hash", "source",
                    "trusted_send"}:
                raise ValueError("cart_creation_shape_invalid")
            body = _canonical_base64(result["body_b64"], max_bytes=1048576)
            payload = json.loads(body, object_pairs_hook=unique_object,
                                 parse_constant=reject_constant)
            schema = cart_specification()["paths"]["/carts"]["post"]["responses"]["200"][
                "content"]["application/json"]["schema"]
            source, scope = result["source"], result["scope"]
            if (not isinstance(payload, dict)
                    or not Draft202012Validator(schema).is_valid(payload)
                    or not isinstance(payload.get("cart"), dict)
                    or payload["cart"].get("id") != resource_id
                    or payload["cart"].get("items") != []
                    or payload.get("state_version") != 1
                    or payload.get("commit_attempt_id") != commit_attempt_id
                    or not isinstance(source, dict)
                    or set(source) != {
                        "kind", "derived_session_id", "derived_world_generation_id",
                        "resource_id", "commit_attempt_id", "state_version", "state_hash"}
                    or source["kind"] != "cart_creation"
                    or source["resource_id"] != resource_id
                    or source["commit_attempt_id"] != commit_attempt_id
                    or source["state_version"] != payload["state_version"]
                    or source["state_hash"] != payload["state_hash"]
                    or not isinstance(source["derived_session_id"], str)
                    or not source["derived_session_id"]
                    or not isinstance(source["derived_world_generation_id"], str)
                    or not source["derived_world_generation_id"]
                    or not isinstance(scope, dict)
                    or set(scope) != {
                        "environment_id", "deployment_id", "session_id", "world_generation_id"}
                    or (scope["environment_id"], scope["deployment_id"], scope["session_id"]) != (
                        expected_environment_id, expected_deployment_id, expected_session_id)
                    or not isinstance(scope["world_generation_id"], str)
                    or not scope["world_generation_id"]
                    or scope["session_id"] == source["derived_session_id"]
                    or result["receipt_id"] != str(receipt_id)
                    or result["operation_id"] != operation_id
                    or result["request_fingerprint"] != request_fingerprint
                    or type(result["status_code"]) is not int or result["status_code"] != 200
                    or result["headers"] != [["content-type", "application/json"]]
                    or result["trusted_send"] != "disabled"
                    or body != json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                          separators=(",", ":")).encode("utf-8")
                    or result["envelope_hash"] != response_hashes(
                        200, (("content-type", "application/json"),), body)[0]):
                raise ValueError("cart_creation_binding_mismatch")
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            raise ProtectedRpcConfigurationError("cart_creation_binding_mismatch") from exc
        return {
            "status_code": 200, "headers": [["content-type", "application/json"]],
            "body_b64": base64.b64encode(body).decode("ascii"),
            "body_sha256": response_hashes(200, (("content-type", "application/json"),), body)[1],
            "envelope_hash": result["envelope_hash"], "source": dict(source),
            "scope": dict(scope), "delivery": "candidate_only_no_send_authorization",
        }

    async def project_medusa_creation(
        self, *, receipt_id: UUID, operation_id: str, resource_id: str,
        commit_attempt_id: str, request_fingerprint: str,
        expected_environment_id: str, expected_deployment_id: str,
        expected_session_id: str,
    ) -> dict[str, object]:
        """M-01：只接收獨立 Validator 的固定來源原生 Cart 200，不允許發送。"""
        from deception.world.transmission import response_hashes

        try:
            attempt = UUID(commit_attempt_id)
        except (TypeError, ValueError) as exc:
            raise ProtectedRpcConfigurationError("medusa_creation_attempt_invalid") from exc
        if (operation_id != "PostCarts" or attempt.version != 4
                or str(attempt) != commit_attempt_id or not isinstance(resource_id, str)
                or re.fullmatch(r"cart_[0-9a-f]{32}", resource_id) is None):
            raise ProtectedRpcConfigurationError("medusa_creation_operation_unapproved")
        async with httpx.AsyncClient(verify=self._tls, trust_env=False, timeout=8.0) as client:
            response = await client.post(
                self._origin + "/internal/v1/project-receipt",
                json={"receipt_id": str(receipt_id)},
            )
        if response.status_code != 200:
            raise ProtectedRpcConfigurationError("medusa_creation_projection_unverifiable")
        try:
            result = json.loads(response.content, object_pairs_hook=unique_object,
                                parse_constant=reject_constant)
            if not isinstance(result, dict) or set(result) != {
                    "receipt_id", "operation_id", "scope", "request_fingerprint",
                    "status_code", "headers", "body_b64", "envelope_hash", "source",
                    "trusted_send"}:
                raise ValueError("medusa_creation_shape_invalid")
            body = _canonical_base64(result["body_b64"], max_bytes=1048576)
            payload = json.loads(body, object_pairs_hook=unique_object,
                                 parse_constant=reject_constant)
            source, scope = result["source"], result["scope"]
            if (not isinstance(payload, dict) or set(payload) != {"cart"}
                    or not isinstance(payload["cart"], dict)
                    or payload["cart"].get("id") != resource_id
                    or payload["cart"].get("items") != []
                    or not isinstance(source, dict) or set(source) != {
                        "kind", "derived_session_id", "derived_world_generation_id",
                        "resource_id", "commit_attempt_id", "state_version", "state_hash"}
                    or source["kind"] != "cart_creation"
                    or source["resource_id"] != resource_id
                    or source["commit_attempt_id"] != commit_attempt_id
                    or type(source["state_version"]) is not int or source["state_version"] != 1
                    or not isinstance(source["state_hash"], str)
                    or re.fullmatch(r"[0-9a-f]{64}", source["state_hash"]) is None
                    or not isinstance(source["derived_session_id"], str)
                    or re.fullmatch(r"[0-9a-f]{32}", source["derived_session_id"]) is None
                    or not isinstance(source["derived_world_generation_id"], str)
                    or re.fullmatch(r"[0-9a-f]{32}", source["derived_world_generation_id"]) is None
                    or not isinstance(scope, dict) or set(scope) != {
                        "environment_id", "deployment_id", "session_id", "world_generation_id"}
                    or (scope["environment_id"], scope["deployment_id"], scope["session_id"]) != (
                        expected_environment_id, expected_deployment_id, expected_session_id)
                    or not isinstance(scope["world_generation_id"], str)
                    or not scope["world_generation_id"]
                    or scope["session_id"] == source["derived_session_id"]
                    or result["receipt_id"] != str(receipt_id)
                    or result["operation_id"] != operation_id
                    or result["request_fingerprint"] != request_fingerprint
                    or type(result["status_code"]) is not int or result["status_code"] != 200
                    or result["headers"] != [["content-type", "application/json"]]
                    or result["trusted_send"] != "disabled"
                    or body != json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                          separators=(",", ":")).encode("utf-8")
                    or result["envelope_hash"] != response_hashes(
                        200, (("content-type", "application/json"),), body)[0]):
                raise ValueError("medusa_creation_binding_mismatch")
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            raise ProtectedRpcConfigurationError("medusa_creation_binding_mismatch") from exc
        return {
            "status_code": 200, "headers": [["content-type", "application/json"]],
            "body_b64": base64.b64encode(body).decode("ascii"),
            "body_sha256": response_hashes(200, (("content-type", "application/json"),), body)[1],
            "envelope_hash": result["envelope_hash"], "source": dict(source),
            "scope": dict(scope), "delivery": "candidate_only_no_send_authorization",
        }

    async def project_cart_read(
        self, *, receipt_id: UUID, operation_id: str, resource_id: str,
        request_fingerprint: str, expected_environment_id: str,
        expected_deployment_id: str, expected_session_id: str,
        expected_read_admission_id: str, expected_world_generation_id: str,
        expected_state_version: int, expected_state_hash: str,
        expected_attempt_id: str | None = None,
    ) -> dict[str, object]:
        """由獨立 Validator 校驗 Cart／Order／Operation 200 候選的精確 JSON 與來源。

        歷史 Cart／Order 亦須綁回 GET 原始 Cart ID，不能僅靠格式及雜湊；
        只傳 Receipt，固定 Operation 與真實 Executor ReadAdmission 必須匹配；
        此路徑不提供客戶端 HTTP Send，也不能接受呼叫端提供的 Status／Body。
        """
        from jsonschema import Draft202012Validator

        from deception.domains.ecommerce.cart_http import cart_specification
        from deception.world.transmission import response_hashes

        approved = {
            "getGuestCart": ("cart", "/carts/{cart_id}"),
            "getSyntheticOrder": ("order", "/orders/{order_id}"),
            "getCartOperation": ("operation", "/carts/{cart_id}/operations/{attempt}"),
        }
        selected = approved.get(operation_id)
        prefix = "cart" if operation_id == "getCartOperation" else (selected[0] if selected else "")
        if (selected is None or not isinstance(resource_id, str)
                or re.fullmatch(prefix + r"_[0-9a-f]{32}", resource_id) is None):
            raise ProtectedRpcConfigurationError("cart_validator_operation_unapproved")
        if operation_id == "getCartOperation":
            try:
                decoded_attempt = UUID(expected_attempt_id)
            except (TypeError, ValueError) as exc:
                raise ProtectedRpcConfigurationError("cart_validator_attempt_invalid") from exc
            if decoded_attempt.version != 4 or str(decoded_attempt) != expected_attempt_id:
                raise ProtectedRpcConfigurationError("cart_validator_attempt_invalid")
        elif expected_attempt_id is not None:
            raise ProtectedRpcConfigurationError("cart_validator_unexpected_attempt")
        async with httpx.AsyncClient(verify=self._tls, trust_env=False, timeout=8.0) as client:
            response = await client.post(
                self._origin + "/internal/v1/project-receipt",
                json={"receipt_id": str(receipt_id)},
            )
        if response.status_code != 200:
            raise ProtectedRpcConfigurationError("cart_validator_projection_unverifiable")
        try:
            result = json.loads(response.content, object_pairs_hook=unique_object,
                                parse_constant=reject_constant)
            if not isinstance(result, dict) or set(result) != {
                    "receipt_id", "operation_id", "scope", "request_fingerprint",
                    "status_code", "headers", "body_b64", "envelope_hash", "source",
                    "trusted_send"}:
                raise ValueError("cart_validator_shape_invalid")
            body = _canonical_base64(result["body_b64"], max_bytes=1048576)
            payload = json.loads(body, object_pairs_hook=unique_object,
                                 parse_constant=reject_constant)
            source, scope = result["source"], result["scope"]
            native_status = result["status_code"]
            if (type(native_status) is not int or native_status not in {200, 409}
                    or native_status == 409 and operation_id != "getCartOperation"):
                raise ValueError("cart_validator_status_unapproved")
            schema = (cart_specification()["paths"][selected[1]]["get"]
                      ["responses"][str(native_status)]["content"]["application/json"]["schema"])
            if native_status == 409:
                from deception.world.protected_native_http import fixed_synthetic_rejection_bytes
                _, missing_body = fixed_synthetic_rejection_bytes(
                    "synthetic-carts", "operation_not_found")
                valid_payload = payload == {"code": "operation_not_found"} and body == missing_body
            elif operation_id == "getCartOperation":
                entity = payload.get("cart", payload.get("order")) if isinstance(payload, dict) else None
                valid_payload = (
                    isinstance(entity, dict) and ("cart" in payload) != ("order" in payload)
                    and isinstance(entity.get("id"), str)
                    and re.fullmatch(
                        (r"cart_" if "cart" in payload else r"order_") + r"[0-9a-f]{32}",
                        entity["id"],
                    ) is not None
                    and (entity.get("id") == resource_id if "cart" in payload
                         else entity.get("cart_id") == resource_id)
                    and payload.get("commit_attempt_id") == expected_attempt_id
                    and type(payload.get("state_version")) is int
                    and 1 <= payload["state_version"] <= expected_state_version
                    and isinstance(payload.get("state_hash"), str)
                    and re.fullmatch(r"[0-9a-f]{64}", payload["state_hash"]) is not None
                )
            else:
                valid_payload = (
                    isinstance(payload, dict)
                    and isinstance(payload.get(selected[0]), dict)
                    and payload[selected[0]].get("id") == resource_id
                    and payload.get("commit_attempt_id") is None
                    and payload.get("state_version") == expected_state_version
                    and payload.get("state_hash") == expected_state_hash
                )
            if (not valid_payload
                    or not Draft202012Validator(schema).is_valid(payload)
                    or not isinstance(source, dict) or set(source) != {
                        "kind", "read_admission_id", "world_generation_id",
                        "state_version", "state_hash"}
                    or source["kind"] != "snapshot"
                    or source["read_admission_id"] != expected_read_admission_id
                    or source["world_generation_id"] != expected_world_generation_id
                    or source["state_version"] != expected_state_version
                    or source["state_hash"] != expected_state_hash
                    or not isinstance(scope, dict) or set(scope) != {
                        "environment_id", "deployment_id", "session_id", "world_generation_id"}
                    or (scope["environment_id"], scope["deployment_id"], scope["session_id"],
                        scope["world_generation_id"]) != (
                        expected_environment_id, expected_deployment_id,
                        expected_session_id, expected_world_generation_id)
                    or result["receipt_id"] != str(receipt_id)
                    or result["operation_id"] != operation_id
                    or result["request_fingerprint"] != request_fingerprint
                    or type(result["status_code"]) is not int or native_status not in {200, 409}
                    or result["headers"] != [["content-type", "application/json"]]
                    or result["trusted_send"] != "disabled"
                    or body != json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                          separators=(",", ":")).encode("utf-8")
                    or result["envelope_hash"] != response_hashes(
                        native_status, (("content-type", "application/json"),), body)[0]):
                raise ValueError("cart_validator_binding_mismatch")
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            raise ProtectedRpcConfigurationError("cart_validator_binding_mismatch") from exc
        return {
            "status_code": native_status, "headers": [["content-type", "application/json"]],
            "body_b64": base64.b64encode(body).decode("ascii"),
            "body_sha256": response_hashes(native_status, (("content-type", "application/json"),), body)[1],
            "envelope_hash": result["envelope_hash"], "source": dict(source),
            "scope": dict(scope), "delivery": "candidate_only_no_send_authorization",
        }

    async def project_medusa_read(
        self, *, receipt_id: UUID, operation_id: str, resource_id: str,
        request_fingerprint: str, expected_environment_id: str,
        expected_deployment_id: str, expected_session_id: str,
        expected_read_admission_id: str, expected_world_generation_id: str,
        expected_state_version: int, expected_state_hash: str,
    ) -> dict[str, object]:
        """從獨立 Medusa Validator 對帳 M-02／M-07 200：固定原生 JSON／來源。

        與已提交的 Executor ReadAdmission 和原始 JWS Session 逐欄相符才接收；
        附帶或遺漏任何未核准欄位、錯誤資源、未驗封套即 503，不構成發送權。
        """
        from deception.world.transmission import response_hashes

        routes = {"GetCartsId": ("cart", "cart_"),
                  "GetOrdersId": ("order", "order_")}
        chosen = routes.get(operation_id)
        if (chosen is None or not isinstance(resource_id, str)
                or re.fullmatch(re.escape(chosen[1]) + r"[0-9a-f]{32}", resource_id) is None):
            raise ProtectedRpcConfigurationError("medusa_validator_operation_unapproved")
        async with httpx.AsyncClient(verify=self._tls, trust_env=False, timeout=8.0) as client:
            response = await client.post(
                self._origin + "/internal/v1/project-receipt",
                json={"receipt_id": str(receipt_id)},
            )
        if response.status_code != 200:
            raise ProtectedRpcConfigurationError("medusa_validator_projection_unverifiable")
        try:
            result = json.loads(response.content, object_pairs_hook=unique_object,
                                parse_constant=reject_constant)
            if not isinstance(result, dict) or set(result) != {
                    "receipt_id", "operation_id", "scope", "request_fingerprint",
                    "status_code", "headers", "body_b64", "envelope_hash", "source",
                    "trusted_send"}:
                raise ValueError("medusa_validator_shape_invalid")
            body = _canonical_base64(result["body_b64"], max_bytes=1048576)
            payload = json.loads(body, object_pairs_hook=unique_object,
                                 parse_constant=reject_constant)
            source, scope = result["source"], result["scope"]
            if (not isinstance(payload, dict) or set(payload) != {chosen[0]}
                    or not isinstance(payload[chosen[0]], dict)
                    or payload[chosen[0]].get("id") != resource_id
                    or not isinstance(source, dict) or set(source) != {
                        "kind", "read_admission_id", "world_generation_id",
                        "state_version", "state_hash"}
                    or source != {
                        "kind": "snapshot", "read_admission_id": expected_read_admission_id,
                        "world_generation_id": expected_world_generation_id,
                        "state_version": expected_state_version,
                        "state_hash": expected_state_hash,
                    }
                    or not isinstance(scope, dict) or scope != {
                        "environment_id": expected_environment_id,
                        "deployment_id": expected_deployment_id,
                        "session_id": expected_session_id,
                        "world_generation_id": expected_world_generation_id,
                    }
                    or result["receipt_id"] != str(receipt_id)
                    or result["operation_id"] != operation_id
                    or result["request_fingerprint"] != request_fingerprint
                    or type(result["status_code"]) is not int or result["status_code"] != 200
                    or result["headers"] != [["content-type", "application/json"]]
                    or result["trusted_send"] != "disabled"
                    or body != json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                          separators=(",", ":")).encode("utf-8")
                    or result["envelope_hash"] != response_hashes(
                        200, (("content-type", "application/json"),), body)[0]):
                raise ValueError("medusa_validator_binding_mismatch")
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            raise ProtectedRpcConfigurationError("medusa_validator_binding_mismatch") from exc
        return {
            "status_code": 200, "headers": [["content-type", "application/json"]],
            "body_b64": base64.b64encode(body).decode("ascii"),
            "body_sha256": response_hashes(200, (("content-type", "application/json"),), body)[1],
            "envelope_hash": result["envelope_hash"], "source": dict(source),
            "scope": dict(scope), "delivery": "candidate_only_no_send_authorization",
        }

    async def project_medusa_add_success(
        self, *, receipt_id: UUID, operation_id: str, resource_id: str,
        request_fingerprint: str, expected_environment_id: str,
        expected_deployment_id: str, expected_session_id: str,
        expected_commit_attempt_id: str, expected_result_digest: str,
        expected_state_version: int, expected_state_hash: str,
        expected_line_item_id: str | None = None,
    ) -> dict[str, object]:
        """mTLS 核對 M-03～M-06 的固定 Medusa 200 候選，絕不賦予 Send 權限。"""
        from deception.world.transmission import response_hashes
        from deception.security.operation_binding import _receipt_uuid4

        markers = {
            "PostCartsIdLineItems": b"medusa-m03-add",
            "PostCartsIdLineItemsLine_id": b"medusa-m04-update",
            "DeleteCartsIdLineItemsLine_id": b"medusa-m05-delete",
            "PostCartsIdComplete": b"medusa-m06-complete",
        }
        marker = markers.get(operation_id)
        deleting = operation_id == "DeleteCartsIdLineItemsLine_id"
        completing = operation_id == "PostCartsIdComplete"
        if (marker is None
                or not isinstance(resource_id, str)
                or re.fullmatch(r"cart_[0-9a-f]{32}", resource_id) is None
                or (deleting and (not isinstance(expected_line_item_id, str)
                                  or re.fullmatch(r"item_[0-9a-f]{32}", expected_line_item_id) is None))
                or (not deleting and expected_line_item_id is not None)
                or expected_commit_attempt_id != str(
                    _receipt_uuid4(receipt_id, marker))):
            raise ProtectedRpcConfigurationError("medusa_add_validator_operation_unapproved")
        async with httpx.AsyncClient(verify=self._tls, trust_env=False, timeout=8.0) as client:
            response = await client.post(
                self._origin + "/internal/v1/project-receipt",
                json={"receipt_id": str(receipt_id)},
            )
        if response.status_code != 200:
            raise ProtectedRpcConfigurationError("medusa_add_validator_projection_unverifiable")
        try:
            result = json.loads(response.content, object_pairs_hook=unique_object,
                                parse_constant=reject_constant)
            if not isinstance(result, dict) or set(result) != {
                    "receipt_id", "operation_id", "scope", "request_fingerprint",
                    "status_code", "headers", "body_b64", "envelope_hash", "source",
                    "trusted_send"}:
                raise ValueError("medusa_add_validator_shape_invalid")
            body = _canonical_base64(result["body_b64"], max_bytes=1048576)
            payload = json.loads(body, object_pairs_hook=unique_object,
                                 parse_constant=reject_constant)
            source, scope = result["source"], result["scope"]
            if (not isinstance(scope, dict) or set(scope) != {
                    "environment_id", "deployment_id", "session_id", "world_generation_id"}
                    or not isinstance(payload, dict)
                    or (not deleting and not completing and (
                        set(payload) != {"cart"}
                        or not isinstance(payload["cart"], dict)
                        or payload["cart"].get("id") != resource_id))
                    or (deleting and (
                        set(payload) != {"id", "object", "deleted", "parent"}
                        or payload.get("id") != expected_line_item_id
                        or payload.get("object") != "line-item"
                        or payload.get("deleted") is not True
                        or not isinstance(payload.get("parent"), dict)
                        or payload["parent"].get("id") != resource_id
                        or not isinstance(payload["parent"].get("items"), list)
                        or any(not isinstance(item, dict)
                               or item.get("id") == expected_line_item_id
                               for item in payload["parent"]["items"])))
                    or (completing and (
                        set(payload) != {"type", "order"}
                        or payload.get("type") != "order"
                        or not isinstance(payload.get("order"), dict)
                        or not isinstance(payload["order"].get("id"), str)
                        or re.fullmatch(r"order_[0-9a-f]{32}", payload["order"]["id"]) is None
                        or payload["order"].get("status") != "pending"
                        or payload["order"].get("payment_status") != "not_paid"
                        or payload["order"].get("fulfillment_status") != "not_fulfilled"
                        or not isinstance(payload["order"].get("items"), list)
                        or not payload["order"]["items"]))
                    or source != {
                        "kind": "committed_operation",
                        "world_generation_id": scope["world_generation_id"],
                        "operation_result_digest": expected_result_digest,
                        "committed_state_version": expected_state_version,
                        "committed_state_hash": expected_state_hash,
                    }
                    or (scope["environment_id"], scope["deployment_id"], scope["session_id"])
                        != (expected_environment_id, expected_deployment_id, expected_session_id)
                    or result["receipt_id"] != str(receipt_id)
                    or result["operation_id"] != operation_id
                    or result["request_fingerprint"] != request_fingerprint
                    or type(result["status_code"]) is not int or result["status_code"] != 200
                    or result["headers"] != [["content-type", "application/json"]]
                    or result["trusted_send"] != "disabled"
                    or body != json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                          separators=(",", ":")).encode("utf-8")
                    or result["envelope_hash"] != response_hashes(
                        200, (("content-type", "application/json"),), body)[0]):
                raise ValueError("medusa_add_validator_binding_mismatch")
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            raise ProtectedRpcConfigurationError("medusa_add_validator_binding_mismatch") from exc
        return {
            "status_code": 200, "headers": [["content-type", "application/json"]],
            "body_b64": base64.b64encode(body).decode("ascii"),
            "body_sha256": response_hashes(200, (("content-type", "application/json"),), body)[1],
            "envelope_hash": result["envelope_hash"], "source": dict(source),
            "scope": dict(scope), "delivery": "candidate_only_no_send_authorization",
        }

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
                self._origin + "/internal/v1/project-receipt",
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
                self._origin + "/internal/v1/project-receipt",
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

    async def project_synthetic_success(
        self, *, receipt_id: UUID, operation_id: str, platform: str,
        request_fingerprint: str, expected_environment_id: str,
        expected_deployment_id: str, expected_session_id: str,
        expected_commit_attempt_id: str, expected_result_digest: str,
        expected_state_version: int, expected_state_hash: str,
    ) -> dict[str, object]:
        """獨立 Validator 重新查驗成功 Commit 與完整合成 HTTP 200 候選。

        mTLS 的固定來源只有 Receipt；其餘參數均是本次已驗證 Executor/JWS
        的預期值，不能讓 RPC 以任意 Header、Body 或 Status 補造成功。
        """
        from jsonschema import Draft202012Validator
        from deception.domains.ecommerce.cart_http import cart_specification
        from deception.domains.ecommerce.inventory_http import inventory_specification
        from deception.world.protected_native_http import _SYNTHETIC_MUTATION_HANDLERS
        from deception.world.transmission import response_hashes

        expected = _SYNTHETIC_MUTATION_HANDLERS.get(operation_id)
        if expected is None or expected[0] != platform:
            raise ProtectedRpcConfigurationError("synthetic_success_operation_unapproved")
        try:
            attempt = UUID(expected_commit_attempt_id)
        except (ValueError, TypeError) as exc:
            raise ProtectedRpcConfigurationError("synthetic_success_attempt_invalid") from exc
        if attempt.version != 4 or str(attempt) != expected_commit_attempt_id:
            raise ProtectedRpcConfigurationError("synthetic_success_attempt_invalid")
        async with httpx.AsyncClient(verify=self._tls, trust_env=False, timeout=8.0) as client:
            response = await client.post(
                self._origin + "/internal/v1/project-receipt",
                json={"receipt_id": str(receipt_id)},
            )
        if response.status_code != 200:
            raise ProtectedRpcConfigurationError("synthetic_success_projection_unverifiable")
        try:
            result = json.loads(response.content, object_pairs_hook=unique_object,
                                parse_constant=reject_constant)
            if not isinstance(result, dict) or set(result) != {
                    "receipt_id", "operation_id", "scope", "request_fingerprint",
                    "status_code", "headers", "body_b64", "envelope_hash", "source",
                    "trusted_send"}:
                raise ValueError("synthetic_success_shape_invalid")
            body = _canonical_base64(result["body_b64"], max_bytes=1048576)
            payload = json.loads(body, object_pairs_hook=unique_object,
                                 parse_constant=reject_constant)
            spec = inventory_specification() if platform == "synthetic-inventory" else cart_specification()
            schema = spec["paths"][expected[2].removeprefix("/synthetic")][expected[1].lower()][
                "responses"]["200"]["content"]["application/json"]["schema"]
            source = result["source"]
            scope = result["scope"]
            if (not isinstance(payload, dict)
                    or not Draft202012Validator(schema).is_valid(payload)
                    or payload.get("commit_attempt_id") != expected_commit_attempt_id
                    or payload.get("state_version") != expected_state_version
                    or payload.get("state_hash") != expected_state_hash
                    or not isinstance(source, dict)
                    or source != {
                        "kind": "committed_operation",
                        "world_generation_id": source.get("world_generation_id"),
                        "operation_result_digest": expected_result_digest,
                        "committed_state_version": expected_state_version,
                        "committed_state_hash": expected_state_hash,
                    }
                    or not isinstance(source.get("world_generation_id"), str)
                    or not source["world_generation_id"]
                    or not isinstance(scope, dict)
                    or set(scope) != {
                        "environment_id", "deployment_id", "session_id", "world_generation_id"}
                    or (scope["environment_id"], scope["deployment_id"], scope["session_id"],
                        scope["world_generation_id"]) != (
                        expected_environment_id, expected_deployment_id,
                        expected_session_id, source["world_generation_id"])
                    or result["receipt_id"] != str(receipt_id)
                    or result["operation_id"] != operation_id
                    or result["request_fingerprint"] != request_fingerprint
                    or type(result["status_code"]) is not int or result["status_code"] != 200
                    or result["headers"] != [["content-type", "application/json"]]
                    or result["trusted_send"] != "disabled"
                    or body != json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                          separators=(",", ":")).encode("utf-8")
                    or result["envelope_hash"] != response_hashes(
                        200, (("content-type", "application/json"),), body)[0]):
                raise ValueError("synthetic_success_source_mismatch")
        except (ValueError, KeyError, TypeError, UnicodeError) as exc:
            raise ProtectedRpcConfigurationError("synthetic_success_source_mismatch") from exc
        return {
            "status_code": 200, "headers": [["content-type", "application/json"]],
            "body_b64": base64.b64encode(body).decode("ascii"),
            "body_sha256": response_hashes(200, (("content-type", "application/json"),), body)[1],
            "envelope_hash": result["envelope_hash"], "source": dict(source), "scope": dict(scope),
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
        UTF-8 SKU 使用與受保護 GET 相同的原始路徑規則，不另設 ASCII 限制。
        """
        from deception.security.operation_binding import (
            OperationBindingError, decode_verified_inventory_sku_path,
        )
        from deception.world.transmission import response_hashes

        if operation_id != "getSyntheticInventory" or not isinstance(resource_id, str):
            raise ProtectedRpcConfigurationError("inventory_validator_operation_unapproved")
        try:
            verified_sku = decode_verified_inventory_sku_path(
                ("/synthetic/inventory/" + resource_id).encode("utf-8"))
        except (OperationBindingError, UnicodeError) as exc:
            raise ProtectedRpcConfigurationError("inventory_validator_operation_unapproved") from exc
        if verified_sku != resource_id:
            raise ProtectedRpcConfigurationError("inventory_validator_operation_unapproved")
        async with httpx.AsyncClient(verify=self._tls, trust_env=False, timeout=8.0) as client:
            response = await client.post(
                self._origin + "/internal/v1/project-receipt",
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
        """以獨立 Validator 的 I-03 真 Commit／缺少操作 Read 證據取得 200／409 候選。

        Verifier 不提供 Body 或回應碼；200 必須有真 Commit；
        409 僅允許 Validator 確定缺少操作而重建固定 operation_not_found。
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
                self._origin + "/internal/v1/project-receipt",
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
            native_status = result["status_code"]
            reservation = parsed.get("reservation") if isinstance(parsed, dict) else None
            if type(native_status) is int and native_status == 200:
                valid_body = (
                    isinstance(parsed, dict)
                    and set(parsed) == {"commit_attempt_id", "state_version", "state_hash", "reservation"}
                    and parsed["commit_attempt_id"] == resource_id
                    and type(parsed["state_version"]) is int
                    and 1 <= parsed["state_version"] <= expected_state_version
                    and isinstance(parsed["state_hash"], str)
                    and re.fullmatch(r"[0-9a-f]{64}", parsed["state_hash"]) is not None
                    and isinstance(reservation, dict)
                    and set(reservation) == {"reservation_id", "sku", "quantity", "status"}
                    and isinstance(reservation["reservation_id"], str)
                    and re.fullmatch(r"[0-9a-f]{32}", reservation["reservation_id"]) is not None
                    and isinstance(reservation["sku"], str)
                    and 1 <= len(reservation["sku"]) <= 128
                    and type(reservation["quantity"]) is int and reservation["quantity"] >= 1
                    and reservation["status"] in {"reserved", "cancelled"})
            elif type(native_status) is int and native_status == 409:
                from deception.world.protected_native_http import fixed_synthetic_rejection_bytes
                _, missing_body = fixed_synthetic_rejection_bytes(
                    "synthetic-inventory", "operation_not_found")
                valid_body = parsed == {"code": "operation_not_found"} and body == missing_body
            else:
                valid_body = False
            if (not valid_body
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
                    or type(result["status_code"]) is not int or native_status not in {200, 409}
                    or result["headers"] != [["content-type", "application/json"]]
                    or result["trusted_send"] != "disabled"
                    or body != json.dumps(parsed, ensure_ascii=False, sort_keys=True,
                                          separators=(",", ":")).encode("utf-8")
                    or result["envelope_hash"] != response_hashes(
                        native_status, (("content-type", "application/json"),), body)[0]):
                raise ValueError("inventory_operation_binding_mismatch")
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            raise ProtectedRpcConfigurationError("inventory_operation_binding_mismatch") from exc
        return {
            "status_code": native_status, "headers": [["content-type", "application/json"]],
            "body_b64": base64.b64encode(body).decode("ascii"),
            "body_sha256": response_hashes(native_status, (("content-type", "application/json"),), body)[1],
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
            if os.environ.get("MIRAGE_G3B_CI_DIAGNOSTIC") == "opaque-failure-classes":
                reason = str(exc)
                if re.fullmatch(r"[a-z][a-z0-9_]{0,99}", reason) is None:
                    reason = "redacted"
                sqlstate = getattr(exc, "sqlstate", None)
                if not isinstance(sqlstate, str) or not re.fullmatch(r"[0-9A-Z]{5}", sqlstate):
                    sqlstate = None
                # PostgreSQL's first-line error identifies only a SQL object;
                # never print its query, DETAIL, HINT or connection string.
                object_match = re.fullmatch(
                    r"permission denied for (?:table|sequence|function) ([a-z_][a-z0-9_]*)",
                    str(exc).splitlines()[0] if str(exc) else "",
                )
                print("G3B_EXECUTOR_FAIL_CLOSED " + json.dumps({
                    "class": type(exc).__name__, "code": sqlstate, "reason": reason,
                    "denied_object": object_match.group(1) if object_match else "redacted",
                }, sort_keys=True), flush=True)
            raise HTTPException(status_code=503, detail="fixed_executor_unverifiable") from exc

    return app


def create_native_validator_app(*, projector) -> FastAPI:
    """在專用 Validator mTLS 入口唯讀重建 20 種原生 HTTP 候選。

    只接受 Receipt，不接受 Caller 指定模板、Scope、Status 或 Payload。
    回傳的是內部候選交接資料，**不能**作為已授權的客戶端 HTTP 回應。
    """
    from deception.world.protected_native_http import PostgresProtectedNativeProjector
    from starlette.concurrency import run_in_threadpool

    if not isinstance(projector, PostgresProtectedNativeProjector):
        raise ProtectedRpcConfigurationError("native_validator_requires_protected_projector")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/internal/ready")
    async def ready() -> dict[str, str]:
        """只回報 Validator 已掛載且 Sender 關閉，不承諾來源或 Profile 已核准。"""
        return {"control_plane": "native-validator-candidate-only", "trusted_send": "disabled"}

    @app.post("/internal/v1/project-inventory-snapshot")
    @app.post("/internal/v1/project-receipt")
    @app.post("/internal/v1/project-inventory-operation")
    @app.post("/internal/v1/project-cart-read")
    @app.post("/internal/v1/project-medusa-creation")
    @app.post("/internal/v1/project-medusa-read")
    @app.post("/internal/v1/project-medusa-add-success")
    @app.post("/internal/v1/project-cart-creation")
    @app.post("/internal/v1/project-synthetic-success")
    @app.post("/internal/v1/project-synthetic-rejection")
    @app.post("/internal/v1/project-medusa-rejection")
    async def project(request: Request) -> dict[str, object]:
        """依已驗 Receipt 或相容固定路徑分派可信投影，隔離同步 DB 鎖等待。"""
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
            if request.scope.get("path") == "/internal/v1/project-receipt":
                selected = projector.project_verified_receipt
            elif request.scope.get("path") == "/internal/v1/project-inventory-snapshot":
                selected = projector.project_inventory_snapshot
            elif request.scope.get("path") == "/internal/v1/project-inventory-operation":
                selected = projector.project_inventory_operation
            elif request.scope.get("path") == "/internal/v1/project-cart-read":
                selected = projector.project_cart_read
            elif request.scope.get("path") == "/internal/v1/project-medusa-creation":
                selected = projector.project_medusa_creation
            elif request.scope.get("path") == "/internal/v1/project-medusa-read":
                selected = projector.project_medusa_read
            elif request.scope.get("path") == "/internal/v1/project-medusa-add-success":
                selected = projector.project_medusa_add_success
            elif request.scope.get("path") == "/internal/v1/project-cart-creation":
                selected = projector.project_cart_creation
            elif request.scope.get("path") == "/internal/v1/project-synthetic-success":
                selected = projector.project_synthetic_success
            elif request.scope.get("path") == "/internal/v1/project-synthetic-rejection":
                selected = projector.project_synthetic_rejection
            else:
                selected = projector.project_medusa_rejection
            projected = await run_in_threadpool(selected, call.receipt_id)
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


def create_fixed_authorizer_app(*, authorizer) -> FastAPI:
    """以獨立 mTLS Authorizer 提供只接收 Receipt UUID4 的固定一次性授權 RPC。

    不允許 Caller 指定 Body、Status、Candidate、Scope、Owner、Deadline 或
    Policy Revision；所有真正授權資料在 Authorizer 實體 Login 的 DB 查回。
    本入口只產生已授權的 Snapshot，不向 Client／Gateway 發送業務 bytes。
    """
    from deception.world.protected_grant import PostgresProtectedAuthorizer, ProtectedGrantError
    from starlette.concurrency import run_in_threadpool
    import psycopg

    if not isinstance(authorizer, PostgresProtectedAuthorizer):
        raise ProtectedRpcConfigurationError("fixed_authorizer_requires_protected_authorizer")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/internal/ready")
    async def ready() -> dict[str, str]:
        """只回報獨立 Authorizer 入口存活，不冒稱已完成業務回應。"""
        return {"control_plane": "authorizer-receipt-only", "trusted_send": "disabled"}

    @app.post("/internal/v1/authorize-receipt")
    async def authorize_receipt(request: Request) -> dict[str, str]:
        """嚴格解析單一 Receipt，COMMIT／ACL 不明一律 503 且不自行重試。"""
        if request.scope.get("scheme") != "https":
            raise HTTPException(status_code=503, detail="fixed_authorizer_tls_required")
        received = bytearray()
        async for chunk in request.stream():
            if len(received) + len(chunk) > 2048:
                raise HTTPException(status_code=413, detail="fixed_authorizer_rpc_too_large")
            received.extend(chunk)
        body = bytes(received)
        try:
            data = json.loads(body, object_pairs_hook=unique_object,
                              parse_constant=reject_constant)
            if not isinstance(data, dict) or set(data) != {"receipt_id"}:
                raise ValueError("fixed_authorizer_fields_invalid")
            # SyntheticModel 的 strict UUID4 不接受 Python str 隱式轉型；
            # 在獨立 JSON 重複鍵檢查後，使用 JSON 模式解析線上 UUID 字串。
            call = FixedAuthorizerCall.model_validate_json(body)
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=400, detail="fixed_authorizer_rpc_invalid") from exc
        try:
            # 同步 PostgreSQL 鎖等待不得卡住 mTLS Event Loop 的其他請求。
            admission, owner = await run_in_threadpool(
                authorizer.authorize_promoted_receipt_once, call.receipt_id)
        except (ProtectedGrantError, psycopg.Error, ValueError) as exc:
            raise HTTPException(status_code=503,
                                detail="fixed_authorizer_result_unverifiable") from exc
        return {"receipt_id": str(call.receipt_id), "admission_id": admission.admission_id,
                "send_owner": owner,
                "request_fingerprint": admission.request_binding_digest,
                "candidate_hash": admission.candidate_hash, "trusted_send": "disabled"}

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
        return {"control_plane": "sender-sealed-pending-security-acceptance",
                "trusted_send": "disabled"}

    @app.post("/internal/v1/send")
    async def send() -> None:
        """任何起送或偽造 Payload 嘗試都固定封閉，且不呼叫 Sender。"""
        raise HTTPException(status_code=503, detail="fixed_sender_release_gates_not_met")

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
        import psycopg

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
        except psycopg.Error as exc:
            # 無法判定 Replay／Receipt 的 Commit 結果，禁止回傳 500 或盲目重試 JTI。
            raise HTTPException(status_code=503,
                                detail="direct_verifier_ingress_storage_unverifiable") from exc
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
        elif (isinstance(outcome, dict) and outcome.get("kind") == "medusa_mutation"
              and operation.operation_id in {"PostCartsIdLineItems", "PostCartsIdLineItemsLine_id",
                                             "DeleteCartsIdLineItemsLine_id", "PostCartsIdComplete"}):
            if native_validator_client is None:
                raise HTTPException(status_code=503,
                                    detail="direct_verifier_medusa_validator_not_wired")
            patterns = {
                "PostCartsIdLineItems": r"/store/carts/(cart_[0-9a-f]{32})/line-items",
                "PostCartsIdLineItemsLine_id": (
                    r"/store/carts/(cart_[0-9a-f]{32})/line-items/item_[0-9a-f]{32}"),
                "DeleteCartsIdLineItemsLine_id": (
                    r"/store/carts/(cart_[0-9a-f]{32})/line-items/item_[0-9a-f]{32}"),
                "PostCartsIdComplete": r"/store/carts/(cart_[0-9a-f]{32})/complete",
            }
            pattern = patterns[operation.operation_id]
            match = re.fullmatch(pattern, normalized.path)
            if match is None:
                raise HTTPException(status_code=503,
                                    detail="direct_verifier_medusa_resource_invalid")
            try:
                projection = await native_validator_client.project_medusa_add_success(
                    receipt_id=receipt_id, operation_id=operation.operation_id,
                    resource_id=match[1],
                    request_fingerprint=fingerprint_request(normalized),
                    expected_environment_id=claims.environment_id,
                    expected_deployment_id=claims.deployment_id,
                    expected_session_id=claims.session_id,
                    expected_commit_attempt_id=outcome["commit_attempt_id"],
                    expected_result_digest=outcome["result_digest"],
                    expected_state_version=outcome["state_version"],
                    expected_state_hash=outcome["state_hash"],
                    expected_line_item_id=(normalized.path.rsplit("/", 1)[-1]
                                           if operation.operation_id == "DeleteCartsIdLineItemsLine_id"
                                           else None),
                )
            except Exception as exc:
                raise HTTPException(status_code=503,
                                    detail="direct_verifier_medusa_add_unverifiable") from exc
        elif (isinstance(outcome, dict) and outcome.get("kind") == "medusa_read_admitted"
              and operation.operation_id in {"GetCartsId", "GetOrdersId"}):
            if native_validator_client is None:
                raise HTTPException(status_code=503,
                                    detail="direct_verifier_medusa_validator_not_wired")
            try:
                projection = await native_validator_client.project_medusa_read(
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
                                    detail="direct_verifier_medusa_projection_unverifiable") from exc
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
        elif (isinstance(outcome, dict) and outcome.get("kind") == "cart_read_admitted"
              and operation.operation_id in {"getGuestCart", "getSyntheticOrder", "getCartOperation"}):
            if native_validator_client is None:
                raise HTTPException(status_code=503,
                                    detail="direct_verifier_native_validator_not_wired")
            try:
                projection = await native_validator_client.project_cart_read(
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
                    expected_attempt_id=outcome["attempt_id"],
                )
            except Exception as exc:
                raise HTTPException(status_code=503,
                                    detail="direct_verifier_cart_projection_unverifiable") from exc
        elif (isinstance(outcome, dict) and outcome.get("kind") == "cart_created"
              and operation.operation_id in {"createGuestCart", "PostCarts"}):
            if native_validator_client is None:
                raise HTTPException(status_code=503,
                                    detail="direct_verifier_native_validator_not_wired")
            try:
                project_creation = (native_validator_client.project_medusa_creation
                                    if operation.operation_id == "PostCarts"
                                    else native_validator_client.project_cart_creation)
                projection = await project_creation(
                    receipt_id=receipt_id, operation_id=operation.operation_id,
                    resource_id=outcome["resource_id"],
                    commit_attempt_id=outcome["commit_attempt_id"],
                    request_fingerprint=fingerprint_request(normalized),
                    expected_environment_id=claims.environment_id,
                    expected_deployment_id=claims.deployment_id,
                    expected_session_id=claims.session_id,
                )
            except Exception as exc:
                raise HTTPException(status_code=503,
                                    detail="direct_verifier_cart_creation_unverifiable") from exc
        elif (isinstance(outcome, dict) and outcome.get("kind") == "world_mutation"
              and outcome.get("status") in {"committed", "already_committed"}):
            if native_validator_client is None:
                raise HTTPException(status_code=503,
                                    detail="direct_verifier_native_validator_not_wired")
            try:
                projection = await native_validator_client.project_synthetic_success(
                    receipt_id=receipt_id, operation_id=operation.operation_id,
                    platform=operation.platform,
                    request_fingerprint=fingerprint_request(normalized),
                    expected_environment_id=claims.environment_id,
                    expected_deployment_id=claims.deployment_id,
                    expected_session_id=claims.session_id,
                    expected_commit_attempt_id=outcome["commit_attempt_id"],
                    expected_result_digest=outcome["result_digest"],
                    expected_state_version=outcome["state_version"],
                    expected_state_hash=outcome["state_hash"],
                )
            except Exception as exc:
                raise HTTPException(status_code=503,
                                    detail="direct_verifier_synthetic_success_unverifiable") from exc
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


def serve_fixed_authorizer_mtls(
    *, app: FastAPI, host: str, port: int, server_cert: Path,
    server_key: Path, verifier_client_ca: Path,
) -> None:
    """以專屬 HTTPS Server 與 Verifier Client CA 啟動真正憑證驗證的 Authorizer。"""
    if not isinstance(app, FastAPI):
        raise ProtectedRpcConfigurationError("fixed_authorizer_app_required")
    require_mtls_files(server_cert=server_cert, server_key=server_key,
                       client_ca=verifier_client_ca)
    if not isinstance(host, str) or not host or type(port) is not int or not 1 <= port <= 65535:
        raise ProtectedRpcConfigurationError("fixed_authorizer_bind_invalid")
    config = uvicorn.Config(
        app, host=host, port=port,
        ssl_certfile=str(server_cert), ssl_keyfile=str(server_key),
        ssl_ca_certs=str(verifier_client_ca), ssl_cert_reqs=ssl.CERT_REQUIRED,
        ssl_version=ssl.PROTOCOL_TLS_SERVER, http="h11", log_level="warning",
        proxy_headers=False, access_log=False,
    )
    if config.ssl_cert_reqs is not ssl.CERT_REQUIRED:
        raise ProtectedRpcConfigurationError("fixed_authorizer_mtls_not_required")
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
