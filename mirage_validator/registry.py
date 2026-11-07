from pathlib import Path

from jsonschema import Draft202012Validator
from pydantic import Field

from .models import StrictModel


class Contract(StrictModel):
    platform_id: str
    operation_id: str
    contract_version: str
    status_code: int = Field(ge=100, le=599)
    description: str
    content_types: list[str] = Field(min_length=1)
    required_headers: dict[str, dict]
    body_schema: dict

    @property
    def key(self):
        return (self.platform_id, self.operation_id, self.contract_version, self.status_code)

    @property
    def contract_id(self):
        return ":".join(map(str, self.key))


class SchemaRegistry:
    """Load trusted local contracts once; no request-controlled file paths."""

    def __init__(self, directory: Path | None = None):
        self._contracts = {}
        directory = directory or Path(__file__).with_name("contracts")
        for path in sorted(directory.glob("*.json")):
            contract = Contract.model_validate_json(path.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(contract.body_schema)
            for schema in contract.required_headers.values():
                Draft202012Validator.check_schema(schema)
            if contract.key in self._contracts:
                raise ValueError(f"Duplicate contract: {contract.contract_id}")
            self._contracts[contract.key] = contract
        if not self._contracts:
            raise ValueError("Schema registry is empty")

    def select(self, platform, operation, version, status):
        return self._contracts.get((platform, operation, version, status))

    def statuses(self, platform, operation, version):
        return sorted(k[3] for k in self._contracts if k[:3] == (platform, operation, version))
