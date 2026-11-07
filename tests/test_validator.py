import copy
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mirage_validator import ResponseContractValidator, SchemaRegistry, ValidationRequest
from mirage_validator.api import app

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
client = TestClient(app)
validator = ResponseContractValidator()


def load(name="woocommerce_200_valid.json"):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def validate(data):
    return validator.validate(ValidationRequest.model_validate(data))


@pytest.mark.parametrize("path", sorted(FIXTURES.glob("*.json")), ids=lambda p: p.name)
def test_fixtures(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    response = client.post("/v1/poc/validate", json=data)
    assert response.status_code == 200
    assert response.json()["valid"] == ("_valid" in path.name)


@pytest.mark.parametrize("body,code,path", [
    ([], "type", ""),
    ({"id": 1}, "required", ""),
    ({**load()["body"], "id": "101"}, "type", "/id"),
    ({**load()["body"], "id": True}, "type", "/id"),
    ({**load()["body"], "status": "unknown"}, "enum", "/status"),
    ({**load()["body"], "extra": 1}, "additionalProperties", ""),
    ({**load()["body"], "price": 19.90}, "type", "/price"),
    (None, "type", ""),
])
def test_body_rules(body, code, path):
    data = load()
    data["body"] = body
    result = validate(data)
    assert not result.valid
    assert any(e.code == code and e.path == path and e.schema_path is not None for e in result.errors)


def test_nested_path_and_allowed_extra():
    data = load("medusa_200_valid.json")
    data["body"]["product"]["custom"] = "allowed"
    assert validate(data).valid
    data["body"]["product"]["id"] = 42
    assert any(e.path == "/product/id" for e in validate(data).errors)


@pytest.mark.parametrize("field,value,code", [
    ("status_code", 201, "unsupported_status"),
    ("platform_id", "unknown", "contract_not_found"),
    ("operation_id", "unknown", "contract_not_found"),
    ("contract_version", "poc-v2", "contract_not_found"),
])
def test_selection(field, value, code):
    data = load()
    data[field] = value
    assert validate(data).errors[0].code == code


@pytest.mark.parametrize("headers,code", [
    ({}, "required"),
    ({"Content-Type": "text/html", "X-Request-ID": "a"}, "content_type"),
    ({"Content-Type": "application/json", "X-Request-ID": ""}, "minLength"),
    ({"Content-Type": "application/json", "content-type": "text/plain"}, "duplicate_header"),
])
def test_headers(headers, code):
    data = load()
    data["headers"] = headers
    assert any(e.code == code for e in validate(data).errors)


def test_content_type_case_and_parameters():
    data = load()
    data["headers"] = {"CONTENT-TYPE": "Application/JSON; charset=UTF-8", "x-request-ID": "a"}
    assert validate(data).valid


@pytest.mark.parametrize("raw", ['{', '{"id":NaN}', '{"id":1,"id":2}', '{"id":1e999}'])
def test_malformed_raw_json(raw):
    data = load()
    data.update(body=raw, body_encoding="raw")
    assert validate(data).errors[-1].code == "invalid_json"


def test_parseable_json_is_insufficient_and_no_mutation():
    data = load()
    data.update(body='{"id":"wrong"}', body_encoding="raw")
    original = copy.deepcopy(data)
    assert not validate(data).valid
    assert data == original
    data["body"] = json.dumps(load()["body"])
    assert validate(data).valid


@pytest.mark.parametrize("change", [{"status_code": "200"}, {"status_code": True},
    {"body_encoding": "raw", "body": {}}, {"unexpected": 1}])
def test_invalid_envelope(change):
    data = load()
    data.update(change)
    assert client.post("/v1/poc/validate", json=data).status_code == 422


def test_missing_body():
    data = load()
    del data["body"]
    assert client.post("/v1/poc/validate", json=data).status_code == 422


def test_registry_rejects_bad_schema_and_duplicate(tmp_path):
    source = Path(__file__).resolve().parents[1] / "mirage_validator/contracts/woocommerce.get_product.poc-v1.200.json"
    contract = json.loads(source.read_text(encoding="utf-8"))
    (tmp_path / "a.json").write_text(json.dumps(contract), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps(contract), encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate"):
        SchemaRegistry(tmp_path)
    contract["body_schema"] = {"type": "not-a-type"}
    (tmp_path / "a.json").write_text(json.dumps(contract), encoding="utf-8")
    from jsonschema.exceptions import SchemaError
    with pytest.raises(SchemaError):
        SchemaRegistry(tmp_path)
