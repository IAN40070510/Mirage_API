"""P2-6A: audit the pinned Medusa product contract without approving deployment.

These tests intentionally prove the current demo template is NOT a valid Medusa
StoreProductResponse. Production deception must remain disabled until the full
response adapter, deployment review and live reference validation exist.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator, RefResolver

from deception.common import DatasetScope
from deception.domains.ecommerce.scenarios import ScenarioPolicy
from deception.domains.ecommerce.synthetic import SyntheticConfig, generate_dataset

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "domains/ecommerce/inputs/sources/medusa"
POLICIES = ROOT / "domains/ecommerce/inputs/policies"
PINNED_SHA256 = "ced300a2de92b9829e6e600964588e894b760f07f8d79c1df657e1abe0529058"


@pytest.fixture(scope="module")
def medusa_spec() -> dict:
    """Load the checked-in immutable vendor specification, without network access."""
    raw = (SOURCE / "openapi.yaml").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == PINNED_SHA256
    return yaml.safe_load(raw)


def test_pinned_medusa_product_operation_and_unapproved_source(medusa_spec: dict) -> None:
    """Bind the chosen scenario to a real GET operation, not demo /api/products."""
    source = yaml.safe_load((SOURCE / "source.yaml").read_text(encoding="utf-8"))
    assert source["spec_sha256"] == PINNED_SHA256
    assert source["platform_id"] == "medusa"
    assert source["platform_version"] == "2.22.4"
    assert source["approved"] is False
    operation = medusa_spec["paths"]["/store/products/{id}"]["get"]
    assert operation["operationId"] == "GetProductsId"
    assert any(
        p["name"] == "id" and p["in"] == "path" and p["required"]
        for p in operation["parameters"]
    )
    assert any(
        p["name"] == "x-publishable-api-key" and p["in"] == "header" and p["required"]
        for p in operation["parameters"]
    )
    assert operation["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/StoreProductResponse"
    }
    assert "404" in operation["responses"]


def test_synthetic_dataset_isolated_and_deterministic() -> None:
    """Existing E data generation is reproducible and contains no real identities."""
    scope = DatasetScope(
        site_id="p2-audit", platform_id="medusa", platform_version="2.22.4",
        spec_sha256=PINNED_SHA256, scenario_id="product-lookup", run_id="contract-audit",
    )
    config = SyntheticConfig(scope=scope, seed=20261111, product_count=2)
    first = generate_dataset(config)
    second = generate_dataset(config)
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert first.synthetic_only is True
    assert first.real_data_imported is False
    assert len(first.products) == 2
    assert all(product.id and product.title and product.handle for product in first.products)


def test_medusa_schema_rejects_legacy_minimal_product_template(medusa_spec: dict) -> None:
    """The real StoreProduct schema rejects the {id,title} demo success body."""
    response_schema = medusa_spec["components"]["schemas"]["StoreProductResponse"]
    product_schema = medusa_spec["components"]["schemas"]["StoreProduct"]
    required = set(product_schema["required"])
    assert {"id", "title", "variants", "options", "images", "created_at"} <= required
    legacy = {"product": {"id": "prod-synthetic", "title": "Synthetic product"}}
    validator = Draft202012Validator(
        response_schema, resolver=RefResolver.from_schema(medusa_spec)
    )
    errors = list(validator.iter_errors(legacy))
    assert errors
    assert any(error.validator == "required" for error in errors)


def test_not_found_template_shape_matches_pinned_medusa_error_schema(
    medusa_spec: dict,
) -> None:
    """404 response shape is schema-compatible, but unapproved for live use."""
    operation = medusa_spec["paths"]["/store/products/{id}"]["get"]
    error_response = operation["responses"]["404"]
    assert error_response["$ref"] == "#/components/responses/not_found_error"
    error_schema = medusa_spec["components"]["schemas"]["Error"]
    staging = yaml.safe_load(
        (POLICIES / "medusa-product-lookup.p2-6a.yaml").read_text(encoding="utf-8")
    )
    missing = next(
        t["body"] for t in staging["templates"]
        if t["template_id"] == "medusa-p2-6a-missing-unreviewed"
    )
    Draft202012Validator(error_schema).validate(missing)
    assert missing["type"] == "not_found"


def test_medusa_staging_policy_is_disabled_and_bound_to_pinned_operation() -> None:
    """Prevent release of a partial template as an approved, live Mirage scenario."""
    data = yaml.safe_load(
        (POLICIES / "medusa-product-lookup.p2-6a.yaml").read_text(encoding="utf-8")
    )
    policy = ScenarioPolicy.model_validate(data)
    assert not policy.enabled
    assert len(policy.rules) == 1
    rule = policy.rules[0]
    assert not rule.enabled
    assert rule.platform_id == "medusa"
    assert rule.platform_version == "2.22.4"
    assert rule.spec_sha256 == PINNED_SHA256
    assert rule.operation_id == "GetProductsId"
    assert rule.path == "/store/products/{id}"
    assert rule.method == "GET"
    assert rule.query_contexts == [{}]
    assert rule.scenario_id == "product-lookup"
