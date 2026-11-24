"""P2-6A: pin a real Medusa GET product contract, with synthetic 404 only.

A temporary test registry may approve copied contract bytes solely to exercise
the official Gate. The checked-in Medusa source/manifest remain unapproved.
No real customer, payment, product mutation or production deception is enabled.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from deception.api.ingress import NormalizedRequest
from deception.common import DatasetScope
from deception.core import CompositionError, ResponseComposer, verify_candidate
from deception.discovery import (
    BindingConfig, DeploymentBinding, PlatformIdentifier, RuntimeContext,
)
from deception.domains.ecommerce.scenarios import ScenarioPolicy
from deception.domains.ecommerce.synthetic import SyntheticConfig, generate_dataset
from deception.profile_builder import ProfileTool, build_profile
from deception.scenarios import AttackAssessment, ScenarioEngine, fingerprint_request
from mirage_validator.gate import OfficialResponseGate, PlatformRegistry


ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = ROOT / "domains/ecommerce/inputs/sources/medusa/source.yaml"
POLICY_PATH = ROOT / "domains/ecommerce/inputs/policies/deception.yaml"
PINNED_HASH = "ced300a2de92b9829e6e600964588e894b760f07f8d79c1df657e1abe0529058"
NOW = datetime(2026, 11, 11, 0, 0, tzinfo=timezone.utc)


def _contract() -> dict:
    """Read the pinned Medusa source without modifying official review flags."""
    return yaml.safe_load((SOURCE_PATH.parent / "openapi.yaml").read_bytes())


def _request(product_id: str) -> NormalizedRequest:
    """Construct an immutable GET request for the selected Medusa operation."""
    path = "/store/products/" + product_id
    return NormalizedRequest(
        request_id="p2-6a-product-001", method="GET",
        raw_url="https://shop.example" + path,
        path=path, raw_path=path.encode("ascii"),
        query_string=b"", query=(),
        headers=(("host", "shop.example"), ("x-request-id", "p2-6a-product-001")),
        body=b"",
    )


def test_selected_medusa_contract_is_pinned_and_read_only() -> None:
    """Require exact Medusa operation, response refs and still-unapproved source."""
    source = yaml.safe_load(SOURCE_PATH.read_bytes())
    sample = yaml.safe_load(POLICY_PATH.read_bytes())
    contract = _contract()
    assert source["approved"] is False
    assert sample["enabled"] is False
    assert source["spec_sha256"] == PINNED_HASH
    assert hashlib.sha256((SOURCE_PATH.parent / "openapi.yaml").read_bytes()).hexdigest() == PINNED_HASH
    operation = contract["paths"]["/store/products/{id}"]["get"]
    assert operation["operationId"] == "GetProductsId"
    assert operation["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/StoreProductResponse"
    }
    assert operation["responses"]["404"]["$ref"] == "#/components/responses/not_found_error"
    assert contract["components"]["schemas"]["StoreProductResponse"]["required"] == ["product"]
    assert "id" in contract["components"]["schemas"]["StoreProduct"]["required"]
    assert "title" in contract["components"]["schemas"]["StoreProduct"]["required"]
    assert any(
        item.get("name") == "x-publishable-api-key" and item.get("required") is True
        for item in operation["parameters"]
    )
    assert "post" not in contract["paths"]["/store/products/{id}"]


def test_medusa_product_missing_uses_real_contract_and_synthetic_dataset(tmp_path: Path) -> None:
    """Identify exact Medusa API, select missing, compose and Gate-check real 404."""
    source = yaml.safe_load(SOURCE_PATH.read_bytes())
    profile_root = tmp_path / "profiles"
    build_profile(SOURCE_PATH, profile_root)
    version = str(source["platform_version"])
    contract_root = tmp_path / "test-only-gate" / "medusa"
    contract_root.mkdir(parents=True)
    raw = (SOURCE_PATH.parent / "openapi.yaml").read_bytes()
    (contract_root / "openapi.yaml").write_bytes(raw)
    # Ephemeral approval is a TEST FIXTURE ONLY; do not mutate pinned source.
    (contract_root / "manifest.yaml").write_text(
        yaml.safe_dump({
            **{key: value for key, value in source.items() if key != "schema_version"},
            "approved": True,
            "platform_version": version,
            "base_urls": ["https://shop.example"],
            "query_contexts": [{}],
        }), encoding="utf-8",
    )
    registry = PlatformRegistry(contract_root.parent)
    runtime = RuntimeContext(
        environment_id="p2-test", deployment_id="p2-local", service_id="sample-store",
    )
    binding = DeploymentBinding(
        binding_id="p2-6a-binding", **runtime.model_dump(),
        site_id="synthetic-shop", base_url="https://shop.example",
        platform_id="medusa", platform_version=version,
        spec_sha256=PINNED_HASH, enabled=True,
    )
    identifier = PlatformIdentifier(registry, BindingConfig(bindings=[binding]))
    scope = DatasetScope(
        site_id="synthetic-shop", platform_id="medusa",
        platform_version=version, spec_sha256=PINNED_HASH,
        scenario_id="product-lookup", run_id="p2-6a-local",
    )
    data = generate_dataset(SyntheticConfig(
        scope=scope, seed=20261111, product_count=2, variants_per_product=1,
    ))
    before = data.model_dump_json()
    request = _request("prod-synthetic-missing")
    identified = identifier.identify_request(request, context=runtime)
    assert identified.decision == "identified" and identified.identity is not None
    assert identified.identity.operation_id == "GetProductsId"
    profile = ProfileTool(profile_root).get_operation(
        **identified.identity.profile_arguments(), allow_unreviewed=True,
    )
    assert profile.source.approved is False

    rule = {
        "rule_id": "medusa-product-lookup", "priority": 100, "enabled": True,
        **runtime.model_dump(), "site_id": scope.site_id,
        "platform_id": scope.platform_id, "platform_version": scope.platform_version,
        "spec_sha256": PINNED_HASH, "operation_id": "GetProductsId",
        "method": "GET", "path": "/store/products/{id}",
        "scenario_id": scope.scenario_id, "id_parameter": "id",
        "id_decoding": "raw", "product_id_target": "/product/id",
        "attack_types": ["sql-injection"], "query_contexts": [{}],
        "found": {"status_code": 200, "template_id": "found"},
        "missing": {"status_code": 404, "template_id": "missing"},
    }
    policy = ScenarioPolicy.model_validate({
        "schema_version": 1, "domain": "ecommerce",
        "policy_id": "medusa-p2-6a-test", "policy_version": "1",
        "enabled": True, "trusted_sources": ["trusted-client"],
        "rules": [rule], "templates": [
            {
                "template_id": "found",
                "body": {"product": {"id": "", "title": ""}},
                "bindings": [
                    {"source_field": "id", "target_pointer": "/product/id"},
                    {"source_field": "title", "target_pointer": "/product/title"},
                ],
            },
            {
                "template_id": "missing",
                "body": {"type": "not_found", "message": "Synthetic product was not found"},
                "bindings": [],
            },
        ],
    })
    engine = ScenarioEngine(policy, domain="ecommerce")
    assessment = AttackAssessment(
        assessment_id="p2-6a-assessment", source_id="trusted-client",
        request_id=request.request_id,
        request_fingerprint=fingerprint_request(request),
        **runtime.model_dump(), site_id=scope.site_id,
        verdict="malicious", attack_types=["sql-injection"],
        observed_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(seconds=30),
    )
    prepared = engine.prepare(
        request, identified, profile, assessment,
        run_id=scope.run_id, now=NOW, allow_unreviewed=True,
    )
    assert prepared.decision == "prepared", prepared
    selected = engine.resolve(prepared.prepared, data, now=NOW)
    assert selected.decision == "selected" and selected.outcome_id == "missing"
    assert selected.composition_plan is not None
    assert selected.composition_plan.status_code == 404
    assert selected.composition_plan.bindings == []
    composer = ResponseComposer(profile_root)
    candidate = composer.compose(
        selected.composition_plan, dataset=data, allow_unreviewed=True,
    )
    assert candidate.identity.source_approved is False
    assert json.loads(candidate.body) == {
        "type": "not_found", "message": "Synthetic product was not found",
    }
    assert verify_candidate(
        candidate, OfficialResponseGate(registry), request.raw_url,
    ).valid is True
    assert data.model_dump_json() == before

    # The demo 200 skeleton MUST NOT be promoted as a Medusa 200 contract.
    found = policy.templates[0].body
    assert set(found["product"]) == {"id", "title"}
    assert set(_contract()["components"]["schemas"]["StoreProduct"]["required"]) - set(
        found["product"]
    )
