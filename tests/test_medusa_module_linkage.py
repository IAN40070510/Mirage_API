"""Post-merge A/B/D/E/H/I integration checks against the pinned Medusa Store/Auth subset.

All approved manifests and sources in this suite are isolated, disposable TEST FIXTURES.
They do not grant approval to the repository's real Medusa contract or deployment.
No external Medusa site, network traffic, LLM, or HTTP renderer is exercised.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from deception.api.app import create_app
from deception.api.identified import make_identification_handler
from deception.core import CompositionError, CompositionPlan, DataBinding, ResponseComposer, verify_candidate
from deception.discovery import BindingConfig, DeploymentBinding, PlatformIdentifier, RuntimeContext
from deception.profile_builder import ProfileTool, build_profile
from deception.synthetic import DatasetScope, SyntheticConfig, SyntheticTool, generate_dataset
from mirage_validator.gate import OfficialResponseGate, PlatformRegistry

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_SOURCE = ROOT / "inputs/sources/medusa/source.yaml"
ORIGINAL_SPEC = ROOT / "inputs/sources/medusa/openapi.yaml"
TEST_ORIGIN = "https://medusa-integration.test"
TEST_CONTEXT = RuntimeContext(environment_id="test-env", deployment_id="test-deploy", service_id="store")


def product_response_template() -> dict:
    """Explicit local fixture matching the real pinned schema, not a live Medusa sample."""
    stamp = "2020-01-01T00:00:00Z"
    variant = {
        "options": [], "title": "", "id": "", "created_at": stamp,
        "updated_at": stamp, "thumbnail": "", "width": 0, "weight": 0,
        "length": 0, "height": 0, "origin_country": "TW",
        "hs_code": "synthetic", "mid_code": "synthetic", "material": "synthetic",
        "deleted_at": stamp, "manage_inventory": True, "allow_backorder": False,
        "sku": "", "ean": "synthetic", "upc": "synthetic",
        "barcode": "synthetic", "product_id": "",
    }
    return {"product": {
        "variants": [variant], "options": [], "images": [], "length": 0, "title": "",
        "status": "published", "description": "Synthetic fixture", "id": "",
        "created_at": stamp, "updated_at": stamp, "subtitle": "",
        "thumbnail": "", "handle": "", "is_giftcard": False,
        "width": 0, "weight": 0, "height": 0, "origin_country": "TW",
        "hs_code": "synthetic", "mid_code": "synthetic", "material": "synthetic",
        "collection_id": "col-synthetic", "type_id": "type-synthetic",
        "discountable": False, "external_id": "external-synthetic", "deleted_at": stamp,
    }}


@pytest.fixture(scope="module")
def integration(tmp_path_factory):
    """Generate one contract-consistent isolated test deployment; leave repository unchanged."""
    production_source = yaml.safe_load(ORIGINAL_SOURCE.read_bytes())
    raw_spec = ORIGINAL_SPEC.read_bytes()
    assert production_source["approved"] is False
    assert hashlib.sha256(raw_spec).hexdigest() == production_source["spec_sha256"]

    root = tmp_path_factory.mktemp("medusa-contract-linkage")
    platform_dir = root / "platforms" / "isolated-medusa"
    platform_dir.mkdir(parents=True)
    (platform_dir / "openapi.yaml").write_bytes(raw_spec)

    # Testing routing and gate success requires an approved *temporary* contract.
    # Never modify the source/manifest in the tracked repository.
    ephemeral_source = {**production_source, "approved": True}
    (platform_dir / "source.yaml").write_text(
        yaml.safe_dump(ephemeral_source, sort_keys=False), encoding="utf-8")
    manifest = dict(ephemeral_source)
    manifest.update(base_urls=[TEST_ORIGIN], query_contexts=[{}])
    (platform_dir / "manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")

    profile_root = root / "generated"
    profile = build_profile(platform_dir / "source.yaml", profile_root)
    assert len(profile.operations) == 77
    registry = PlatformRegistry(platform_dir.parent)
    binding = DeploymentBinding(
        binding_id="medusa-test-only", site_id="medusa-test",
        environment_id=TEST_CONTEXT.environment_id,
        deployment_id=TEST_CONTEXT.deployment_id,
        service_id=TEST_CONTEXT.service_id, base_url=TEST_ORIGIN,
        platform_id=ephemeral_source["platform_id"],
        platform_version=ephemeral_source["platform_version"],
        spec_sha256=ephemeral_source["spec_sha256"], enabled=True)
    identifier = PlatformIdentifier(registry, BindingConfig(bindings=[binding]))
    scope = DatasetScope(
        site_id=binding.site_id, platform_id=binding.platform_id,
        platform_version=binding.platform_version, spec_sha256=binding.spec_sha256,
        scenario_id="product-found", run_id="module-linkage")
    dataset = generate_dataset(SyntheticConfig(
        scope=scope, seed=20261108, product_count=1, variants_per_product=1))
    url = f"{TEST_ORIGIN}/store/products/{dataset.products[0].id}"

    bindings = [
        DataBinding(source_pointer=f"/products/0/{key}", target_pointer=f"/product/{key}")
        for key in ("id", "title", "handle", "status")
    ] + [
        DataBinding(source_pointer=f"/variants/0/{key}", target_pointer=f"/product/variants/0/{key}")
        for key in ("id", "title", "sku", "product_id")
    ]
    plan = CompositionPlan(scope=scope, method="GET", path="/store/products/{id}",
                           status_code=200, body=product_response_template(), bindings=bindings)
    composer = ResponseComposer(profile_root)
    candidate = composer.compose(plan, dataset=dataset)
    return {
        "root": root, "dir": platform_dir, "profile_root": profile_root,
        "production_source": production_source, "raw_spec": raw_spec,
        "registry": registry, "binding": binding, "identifier": identifier,
        "scope": scope, "dataset": dataset, "url": url,
        "plan": plan, "composer": composer, "candidate": candidate,
        "gate": OfficialResponseGate(registry),
    }


def test_post_merge_contract_identity_remains_isolated(integration):
    cfg = yaml.safe_load(ORIGINAL_SOURCE.read_bytes())
    spec = ORIGINAL_SPEC.read_bytes()
    assert cfg["approved"] is False
    assert cfg["spec_sha256"] == hashlib.sha256(spec).hexdigest()
    assert spec == integration["raw_spec"]
    assert integration["candidate"].identity.source_approved is True
    assert integration["binding"].spec_sha256 == integration["candidate"].identity.spec_sha256
    # Temporary approval belongs to this test's isolated root only.
    assert not (ROOT / "inputs/platforms/medusa/manifest.yaml").exists()


def test_a_b_identifies_medusa_without_trusting_spoofed_headers(integration):
    identifier = integration["identifier"]
    app = create_app(make_identification_handler(identifier, context=TEST_CONTEXT))
    client = TestClient(app, base_url=TEST_ORIGIN)
    response = client.get(
        "/store/products/" + integration["dataset"].products[0].id,
        headers={"X-Forwarded-Host": "malicious.example",
                 "X-Environment-ID": "another-environment",
                 "X-Request-ID": "linked-001"})
    # A→B works; C/M are not wired, so no deceptive response is emitted.
    assert response.status_code == 501
    data = response.json()
    assert data["code"] == "orchestrator_not_implemented"
    assert data["identification"]["operation_id"] == "GetProductsId"
    assert data["identification"]["environment_id"] == "test-env"
    assert data["identification"]["spec_sha256"] == integration["binding"].spec_sha256
    assert response.headers["x-request-id"] == "linked-001"


def test_b_d_e_h_i_pinned_medusa_200_passes_without_mutation(integration):
    result = integration["identifier"].identify(integration["url"], "GET", context=TEST_CONTEXT)
    assert result.decision == "identified", result
    identity = result.identity
    context = ProfileTool(integration["profile_root"]).get_operation(**identity.profile_arguments())
    scope = integration["scope"]
    dataset = integration["dataset"]
    synthetic = SyntheticTool(dataset, expected_scope=scope, profile=context)
    product = synthetic.get_product(identity.path_parameters["id"])
    assert product.id == dataset.products[0].id

    candidate = integration["candidate"]
    body = json.loads(candidate.body)
    assert body["product"]["id"] == product.id
    assert body["product"]["variants"][0]["product_id"] == product.id
    assert body["product"]["variants"][0]["id"] == dataset.variants[0].id
    assert candidate.identity.operation_id == identity.operation_id == context.operation.operation_id
    assert candidate.identity.spec_sha256 == identity.spec_sha256
    result = verify_candidate(candidate, integration["gate"], integration["url"])
    assert result.valid and result.decision == "pass", result
    assert result.spec_sha256 == candidate.identity.spec_sha256
    assert integration["raw_spec"] == ORIGINAL_SPEC.read_bytes()


def test_h_i_rejects_tampered_medusa_body(integration):
    candidate = integration["candidate"]
    value = json.loads(candidate.body)
    value["product"]["id"] = 987654  # No schema type coercion allowed.
    tampered = replace(candidate, body=json.dumps(value, ensure_ascii=False))
    result = verify_candidate(tampered, integration["gate"], integration["url"])
    assert result.valid is False
    assert result.decision == "reject"
    assert result.errors


def test_h_i_does_not_authorize_another_operation(integration):
    candidate = integration["candidate"]
    # GET /store/products is a distinct operation from GET /store/products/{id}.
    result = verify_candidate(candidate, integration["gate"], TEST_ORIGIN + "/store/products")
    assert result.valid is False
    assert result.decision == "unverifiable"
    assert any(issue.code == "candidate_identity_mismatch" for issue in result.errors)


def test_b_i_both_fail_closed_on_unreviewed_query(integration):
    url = integration["url"] + "?fields=id"
    identity = integration["identifier"].identify(url, "GET", context=TEST_CONTEXT)
    assert identity.decision == "unverifiable"
    assert identity.errors[0].code == "unsupported_context"
    gate_result = verify_candidate(integration["candidate"], integration["gate"], url)
    assert gate_result.decision == "unverifiable"
    assert gate_result.valid is False
    assert gate_result.errors[0].code == "unsupported_context"


def test_b_rejects_mismatched_binding_without_guessing_contract(integration):
    invalid_binding = integration["binding"].model_copy(
        update={"spec_sha256": "f" * 64})
    identifier = PlatformIdentifier(integration["registry"],
                                    BindingConfig(bindings=[invalid_binding]))
    result = identifier.identify(integration["url"], "GET", context=TEST_CONTEXT)
    assert result.decision == "unverifiable"
    assert result.errors[0].code == "binding_contract_mismatch"


def test_h_rejects_dataset_from_different_run(integration):
    other_scope = integration["scope"].model_copy(update={"run_id": "other-run"})
    altered_plan = integration["plan"].model_copy(update={"scope": other_scope})
    with pytest.raises(CompositionError, match="scope_mismatch"):
        integration["composer"].compose(altered_plan, dataset=integration["dataset"])


def test_b_i_do_not_approve_repository_medusa_when_temp_manifest_is_unapproved(integration, tmp_path):
    cfg = dict(integration["production_source"])
    assert cfg["approved"] is False
    directory = tmp_path / "platforms" / "medusa"
    directory.mkdir(parents=True)
    (directory / "openapi.yaml").write_bytes(integration["raw_spec"])
    cfg.update(base_urls=[TEST_ORIGIN], query_contexts=[{}])
    (directory / "manifest.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")
    registry = PlatformRegistry(directory.parent)
    identifier = PlatformIdentifier(registry, BindingConfig(bindings=[integration["binding"]]))
    result = identifier.identify(integration["url"], "GET", context=TEST_CONTEXT)
    assert result.decision == "unverifiable"
    assert result.errors[0].code == "contract_not_approved"
    gate_result = OfficialResponseGate(registry).validate(
        integration["candidate"].to_gate_request(integration["url"]))
    assert gate_result.valid is False and gate_result.decision == "unverifiable"
    assert gate_result.errors[0].code == "contract_not_approved"
