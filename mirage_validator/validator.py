import json

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry

from .models import ValidationIssue, ValidationRequest, ValidationResult
from .registry import SchemaRegistry
from .json_utils import pointer, reject_constant, unique_object


class ResponseContractValidator:
    def __init__(self, registry: SchemaRegistry | None = None):
        self.registry = registry or SchemaRegistry()

    def validate(self, request: ValidationRequest) -> ValidationResult:
        errors = []

        def issue(location, path, code, reason, schema_path=None):
            errors.append(ValidationIssue(location=location, path=path, code=code,
                                          reason=reason, schema_path=schema_path))

        contract = self.registry.select(request.platform_id, request.operation_id,
                                        request.contract_version, request.status_code)
        if contract is None:
            statuses = self.registry.statuses(request.platform_id, request.operation_id,
                                              request.contract_version)
            if statuses:
                issue("status", "/status_code", "unsupported_status", f"此契約允許的狀態碼：{statuses}")
            else:
                issue("contract", "", "contract_not_found", "找不到平台、操作及版本的契約")
            return ValidationResult(valid=False, contract_id=None, errors=errors)

        headers = {}
        for name, value in request.headers.items():
            key = name.lower()
            if key in headers:
                issue("headers", pointer([key]), "duplicate_header", "header 名稱忽略大小寫後重複")
            headers[key] = value
        content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type not in contract.content_types:
            issue("headers", "/content-type", "content_type", f"Content-Type 必須是 {contract.content_types}")

        def check(instance, schema, location, prefix=()):
            # Empty referencing registry prevents implicit network retrieval of $ref.
            validator = Draft202012Validator(schema, format_checker=FormatChecker(), registry=Registry())
            for error in validator.iter_errors(instance):
                issue(location, pointer([*prefix, *error.absolute_path]), str(error.validator),
                      error.message, pointer(error.absolute_schema_path))

        for name, schema in contract.required_headers.items():
            name = name.lower()
            if name not in headers:
                issue("headers", pointer([name]), "required", "缺少必要 header")
            else:
                check(headers[name], schema, "headers", (name,))

        body = request.body
        if request.body_encoding == "raw":
            try:
                body = json.loads(body, parse_constant=reject_constant, object_pairs_hook=unique_object)
                # Also rejects numeric overflow, e.g. 1e999.
                json.dumps(body, allow_nan=False)
            except (ValueError, RecursionError) as error:
                issue("body", "", "invalid_json", str(error))
                return ValidationResult(valid=False, contract_id=contract.contract_id, errors=errors)
        check(body, contract.body_schema, "body")
        return ValidationResult(valid=not errors, contract_id=contract.contract_id, errors=errors)
