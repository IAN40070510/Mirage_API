"""合成庫存 API 的明確契約、輸入驗證與結果投影。"""

import hashlib
import json
from pathlib import Path
import re
from uuid import UUID

from pydantic import Field, UUID4

from deception.common.models import SyntheticModel
from deception.core.models import CandidateIdentity, CandidateResponse
from deception.world import CommitSource, SecurityErrorSource, WorldStoreError
from mirage_validator.gate import OfficialResponseGate, PlatformRegistry
from mirage_validator.json_utils import reject_constant, unique_object
from .inventory import SyntheticInventory


class ReserveBody(SyntheticModel):
    """核對預留參數與可重用業務鍵，不接受 Client 選擇 World。"""

    sku: str = Field(min_length=1, max_length=128)
    quantity: int = Field(ge=1)
    expected_version: int = Field(ge=1)
    idempotency_key: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    commit_attempt_id: UUID4


class CancelBody(SyntheticModel):
    """核對取消的 CAS 版本、業務鍵與操作查詢識別碼。"""

    expected_version: int = Field(ge=1)
    idempotency_key: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    commit_attempt_id: UUID4


ERROR_CODES = ["unknown_synthetic_sku", "insufficient_synthetic_inventory", "reservation_not_active",
               "inventory_write_not_authorized", "invalid_synthetic_operation", "version_conflict",
               "idempotency_content_conflict", "operation_not_found"]


def inventory_specification() -> dict:
    """產生本專案明確支援的四個合成操作與 200／409 回應契約。"""
    result = {"type": "object", "additionalProperties": False,
        "required": ["commit_attempt_id", "state_version", "state_hash", "reservation"],
        "properties": {"commit_attempt_id": {"type": "string", "format": "uuid"},
            "state_version": {"type": "integer", "minimum": 1},
            "state_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "reservation": {"type": "object", "additionalProperties": False,
                "required": ["reservation_id", "sku", "quantity", "status"], "properties": {
                    "reservation_id": {"type": "string", "pattern": "^[0-9a-f]{32}$"},
                    "sku": {"type": "string"}, "quantity": {"type": "integer", "minimum": 1},
                    "status": {"type": "string", "enum": ["reserved", "cancelled"]}}}}}
    inventory = {"type": "object", "required": ["sku", "available", "state_version"],
        "additionalProperties": False, "properties": {"sku": {"type": "string"},
            "available": {"type": "integer", "minimum": 0}, "state_version": {"type": "integer", "minimum": 1}}}
    error = {"type": "object", "required": ["code"], "additionalProperties": False,
             "properties": {"code": {"type": "string", "enum": ERROR_CODES}}}
    definitions = [
        ("/inventory/reservations", "post", "reserveSyntheticInventory", None, ReserveBody, result),
        ("/inventory/reservations/{reservation_id}/cancel", "post", "cancelSyntheticInventory", "reservation_id", CancelBody, result),
        ("/operations/{attempt}", "get", "getSyntheticOperation", "attempt", None, result),
        ("/inventory/{sku}", "get", "getSyntheticInventory", "sku", None, inventory),
    ]
    paths = {}
    for path, method, operation, parameter, body, response in definitions:
        value = {"operationId": operation, "responses": {
            "200": {"description": "Synthetic result", "content": {"application/json": {"schema": response}}},
            "409": {"description": "Fixed synthetic rejection", "content": {"application/json": {"schema": error}}}}}
        if parameter:
            value["parameters"] = [{"name": parameter, "in": "path", "required": True, "schema": {"type": "string"}}]
        if body:
            value["requestBody"] = {"required": True, "content": {"application/json": {"schema": body.model_json_schema()}}}
        paths[path] = {method: value}
    return {"openapi": "3.1.0", "info": {"title": "Mirage synthetic inventory", "version": "1"}, "paths": paths}


class InventoryHTTP:
    """以本地核准的合成 OpenAPI 驗證庫存操作回應，不代表 Medusa 原生 API。"""

    def __init__(self, *, dsn: str, origin: str, output: Path, specification=None, platform_id="synthetic-inventory"):
        """保存合成規格與來源摘要，建立現有 OfficialResponseGate 的獨立註冊表。"""
        self.service = SyntheticInventory(dsn)
        self.platform_id = platform_id
        self.specification = inventory_specification() if specification is None else specification
        raw = json.dumps(self.specification, sort_keys=True, ensure_ascii=False).encode()
        self.spec_hash = hashlib.sha256(raw).hexdigest()
        directory = output / platform_id
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "openapi.yaml").write_bytes(raw)
        manifest = dict(platform_id=platform_id, platform_version="1", spec_sha256=self.spec_hash,
            source_url="https://example.invalid/mirage/synthetic-inventory", source_revision="synthetic-inventory-1",
            approved=True, openapi_file="openapi.yaml", base_urls=[origin + "/synthetic"], query_contexts=[{}])
        (directory / "manifest.yaml").write_text(json.dumps(manifest), encoding="utf-8")
        self.gate = OfficialResponseGate(PlatformRegistry(output))

    @staticmethod
    def _json_body(request, model):
        """先拒絕重複欄位與非有限 JSON，再用嚴格模型檢查 body。"""
        content_types = [value for name, value in request.headers if name.lower() == "content-type"]
        if len(content_types) != 1 or content_types[0].split(";", 1)[0].strip().lower() != "application/json":
            raise ValueError("JSON content type required")
        json.loads(request.body, object_pairs_hook=unique_object, parse_constant=reject_constant)
        return model.model_validate_json(request.body)

    def execute(self, request, binding, read, *, now: int):
        """從核准路由執行或查詢合成操作，回傳候選、ResponseSource 與操作模板。"""
        path = request.path.removeprefix("/synthetic")
        operation, template = "", ""
        status, payload, source = 200, None, read.source
        try:
            if request.query_string:
                raise ValueError("query context not supported")
            if path == "/inventory/reservations" and request.method == "POST":
                operation, template = "reserveSyntheticInventory", path
                body = self._json_body(request, ReserveBody)
                result = self.service.reserve(binding, now=now, **body.model_dump())
            elif re.fullmatch(r"/inventory/reservations/[0-9a-f]{32}/cancel", path) and request.method == "POST":
                operation, template = "cancelSyntheticInventory", "/inventory/reservations/{reservation_id}/cancel"
                body = self._json_body(request, CancelBody)
                result = self.service.cancel(binding, reservation_id=path.split("/")[3], now=now, **body.model_dump())
            elif path.startswith("/operations/") and request.method == "GET":
                operation, template = "getSyntheticOperation", "/operations/{attempt}"
                if binding.access_mode != "inventory":
                    raise WorldStoreError("inventory_write_not_authorized")
                result = self.service.operation_result(binding, UUID(path.split("/")[2]), now=now)
                if result is None:
                    raise WorldStoreError("operation_not_found")
            elif path.startswith("/inventory/") and request.method == "GET":
                operation, template = "getSyntheticInventory", "/inventory/{sku}"
                sku = path.split("/")[2]
                available = read.snapshot.state["inventory"].get(sku)
                if type(available) is not int:
                    raise WorldStoreError("unknown_synthetic_sku")
                payload = {"sku": sku, "available": available, "state_version": read.snapshot.version}
                result = None
            else:
                raise ValueError("unsupported synthetic inventory route")
            if result is not None:
                if result.status == "rejected":
                    raise WorldStoreError(result.result["code"])
                payload = {"commit_attempt_id": str(result.commit_attempt_id), "state_version": result.state_version,
                           "state_hash": result.state_hash, "reservation": result.result}
                result_digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                source = CommitSource(world_generation_id=read.snapshot.scope.world_generation_id,
                    operation_result_digest=result_digest, committed_state_version=result.state_version,
                    committed_state_hash=result.state_hash)
        except (ValueError, WorldStoreError, KeyError) as exc:
            if not operation:
                raise ValueError("unsupported inventory route") from exc
            code = str(exc) if str(exc) in ERROR_CODES else "invalid_synthetic_operation"
            payload, status = {"code": code}, 409
            source = SecurityErrorSource(template_id=code, contract_revision="synthetic-inventory-1")
        candidate = CandidateResponse(
            CandidateIdentity(site_id="demo-store", platform_id="synthetic-inventory", platform_version="1",
                spec_sha256=self.spec_hash, scenario_id="synthetic-inventory", run_id="synthetic-inventory-1",
                operation_id=operation, method=request.method, path=template, source_approved=True),
            status, (("content-type", "application/json"),), json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                                                       separators=(",", ":")))
        return candidate, source
