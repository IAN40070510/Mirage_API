import os
from pathlib import Path

from fastapi import FastAPI

from .gate import GateRequest, GateResult, OfficialResponseGate, PlatformRegistry

from .models import ValidationRequest, ValidationResult
from .validator import ResponseContractValidator

app = FastAPI(title="Mirage Response Contract Validator PoC", version="0.1.0")
validator = ResponseContractValidator()
gate = OfficialResponseGate(PlatformRegistry(Path(os.environ.get("MIRAGE_PLATFORMS_DIR", "inputs/platforms"))))


@app.post("/v1/poc/validate", response_model=ValidationResult, deprecated=True)
def validate_response(request: ValidationRequest) -> ValidationResult:
    """依指定的 PoC 契約驗證回應，回傳驗證結果與錯誤明細。"""
    return validator.validate(request)


@app.post("/v1/validate", response_model=GateResult)
def validate_official_response(request: GateRequest) -> GateResult:
    """依網站綁定的官方 OpenAPI 契約驗證回應並回傳放行決策。"""
    return gate.validate(request)
