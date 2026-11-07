from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)


class ValidationRequest(StrictModel):
    platform_id: str = Field(min_length=1)
    operation_id: str = Field(min_length=1)
    contract_version: str = "poc-v1"
    status_code: int = Field(ge=100, le=599)
    headers: dict[str, str]
    body: JsonValue = Field(...)
    body_encoding: Literal["json", "raw"] = "json"

    @model_validator(mode="after")
    def check_raw(self):
        if self.body_encoding == "raw" and not isinstance(self.body, str):
            raise ValueError("raw body 必須是字串")
        return self


class ValidationIssue(StrictModel):
    location: Literal["contract", "status", "headers", "body"]
    path: str
    code: str
    reason: str
    schema_path: str | None = None


class ValidationResult(StrictModel):
    valid: bool
    contract_id: str | None
    errors: list[ValidationIssue]
