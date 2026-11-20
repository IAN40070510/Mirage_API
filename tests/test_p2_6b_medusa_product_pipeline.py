"""P2-6B pinned Medusa Store product: native F/E/H/I contract integration.

Production source.yaml stays approved:false; the only enabled manifest in these
tests is an ephemeral isolated fixture, NOT a production review approval.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import yaml

from deception.api.ingress import NormalizedRequest
from deception.common import DatasetScope
from deception.core import CompositionError, ResponseComposer, verify_candidate
from deception.core.orchestrator import PipelineResult
from deception.core.renderer import ResponseRenderer
from deception.generation.models import digest
from deception.discovery import BindingConfig, DeploymentBinding, PlatformIdentifier, RuntimeContext
from deception.domains.ecommerce.medusa_product import (
    MEDUSA_PRODUCT_PATH, MEDUSA_STORE_SHA256, MEDUSA_VERSION, adapt_medusa_product_plan,
)
from deception.domains.ecommerce.scenarios import ScenarioPolicy
from deception.domains.ecommerce.synthetic import SyntheticConfig, generate_dataset
from deception.profile_builder import ProfileTool, build_profile
from deception.scenarios import AttackAssessment, ScenarioEngine, fingerprint_request
from mirage_validator.gate import OfficialResponseGate, PlatformRegistry

ROOT = Path(__file__).resolve().parents[1]
PINNED = ROOT / "domains/ecommerce/inputs/sources/medusa"
STAGING_POLICY = ROOT / "domains/ecommerce/inputs/policies/medusa-product-lookup.p2-6a.yaml"


def build_contract_stack(
    tmp_path: Path, base_url: str, *, test_assessment_max_age: int = 30
) -> dict:
    """Build a temporary reviewed-test fixture at one explicit Mirage origin."""
    source = yaml.safe_load((PINNED / "source.yaml").read_text(encoding="utf-8"))
    assert source["approved"] is False
    temp_source = {**source, "approved": True}
    root = tmp_path / "contracts"
    directory = root / "isolated-medusa-test"
    directory.mkdir(parents=True)
    (directory / "openapi.yaml").write_bytes((PINNED / "openapi.yaml").read_bytes())
    (directory / "source.yaml").write_text(yaml.safe_dump(temp_source), encoding="utf-8")
    (directory / "manifest.yaml").write_text(yaml.safe_dump({
        **{key: value for key, value in temp_source.items() if key != "schema_version"},
        "base_urls": [base_url], "query_contexts": [{}],
    }), encoding="utf-8")
    profiles = tmp_path / "profiles"
    build_profile(directory / "source.yaml", profiles)
    registry = PlatformRegistry(root)
    runtime = RuntimeContext(
        environment_id="test-env", deployment_id="test-deploy", service_id="test-store",
    )
    scope = DatasetScope(
        site_id="p2-review", platform_id="medusa", platform_version=MEDUSA_VERSION,
        spec_sha256=MEDUSA_STORE_SHA256, scenario_id="product-lookup", run_id="p2-6b",
    )
    config = SyntheticConfig(
        scope=scope, seed=20261111, product_count=2, variants_per_product=2,
        synthetic_created_at="2026-11-11T00:00:00Z",
    )
    dataset = generate_dataset(config)
    binding = DeploymentBinding(
        **runtime.model_dump(), binding_id="medusa-test", site_id=scope.site_id,
        platform_id=scope.platform_id, platform_version=scope.platform_version,
        spec_sha256=scope.spec_sha256, base_url=base_url, enabled=True,
    )
    policy_data = yaml.safe_load(STAGING_POLICY.read_text(encoding="utf-8"))
    assert policy_data["enabled"] is False
    policy_data["enabled"] = True
    # Test-only increase: full vendor OpenAPI compilation is CPU-intensive.
    policy_data["max_age_seconds"] = test_assessment_max_age
    policy_data["rules"][0].update({
        "enabled": True, **runtime.model_dump(), "site_id": scope.site_id,
    })
    policy = ScenarioPolicy.model_validate(policy_data)
    return {
        "base_url": base_url, "root": root, "directory": directory,
        "profiles": profiles, "registry": registry, "runtime": runtime,
        "scope": scope, "config": config, "dataset": dataset, "policy": policy,
        "identifier": PlatformIdentifier(registry, BindingConfig(bindings=[binding])),
        "gate": OfficialResponseGate(registry),
        "composer": ResponseComposer(profiles),
        "engine": ScenarioEngine(policy, domain="ecommerce"),
    }



@pytest.fixture(scope="module")
def contract_stack(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """Build the full pinned 900 KiB OpenAPI once per module."""
    return build_contract_stack(tmp_path_factory.mktemp("medusa-review"), "http://127.0.0.1:18991")


def _request(stack: dict, product_id: str, request_id: str = "medusa-synthetic-001") -> NormalizedRequest:
    """Represent the Mirage ingress after the signed Gateway route."""
    path = "/store/products/" + product_id
    return NormalizedRequest(
        request_id=request_id, method="GET", raw_url=stack["base_url"] + path,
        path=path, raw_path=path.encode("ascii"), query_string=b"", query=(),
        headers=(("host", urlsplit(stack["base_url"]).netloc),), body=b"",
    )


def _selected(stack: dict, product_id: str, *, request_id: str = "medusa-synthetic-001"):
    """Run real B/D/F/E, rather than constructing a fake composition plan."""
    request = _request(stack, product_id, request_id)
    identified = stack["identifier"].identify_request(request, context=stack["runtime"])
    assert identified.decision == "identified", identified
    profile = ProfileTool(stack["profiles"]).get_operation(
        **identified.identity.profile_arguments()
    )
    now = datetime.now(timezone.utc)
    assessment = AttackAssessment(
        assessment_id=request.request_id, source_id="sentinel-approved",
        request_id=request.request_id, request_fingerprint=fingerprint_request(request),
        **stack["runtime"].model_dump(), site_id=stack["scope"].site_id,
        verdict="malicious", attack_types=["sql-injection"],
        observed_at=now-timedelta(seconds=1), expires_at=now+timedelta(seconds=30),
    )
    prepared = stack["engine"].prepare(
        request, identified, profile, assessment, run_id=stack["scope"].run_id, now=now,
    )
    assert prepared.decision == "prepared", prepared
    selected = stack["engine"].resolve(prepared.prepared, stack["dataset"], now=now)
    assert selected.decision == "selected", selected
    return request, selected.composition_plan


@pytest.mark.parametrize("missing", [False, True])
def test_real_medusa_composer_and_openapi_gate(contract_stack: dict, missing: bool) -> None:
    """Check actual F -> adapter -> H preflight -> I gate against pinned vendor bytes."""
    stack = contract_stack
    product = stack["dataset"].products[0]
    product_id = "prod-synthetic-missing" if missing else product.id
    request, plan = _selected(stack, product_id)
    assert plan.status_code == (404 if missing else 200)
    assert plan.bindings == []
    if not missing:
        view = plan.body["product"]
        assert view["id"] == product.id
        assert view["title"] == product.title
        assert view["handle"] == product.handle
        assert {item["id"] for item in view["variants"]} == set(product.variant_ids)
        assert len(view["variants"]) == 2
        assert "status" not in view and "deleted_at" not in view and "external_id" not in view
        assert view["created_at"] == "2026-11-11T00:00:00Z"
        assert view["updated_at"] == view["created_at"]
        assert view["collection_id"] is None and view["height"] is None
        assert len(view["options"]) == 1
        option = view["options"][0]
        assert len(option["values"]) == len(view["variants"])
        assert {v["options"][0]["option_id"] for v in view["variants"]} == {option["id"]}
        assert all(v["deleted_at"] is None for v in view["variants"])
        assert all(v["options"][0]["value"] == v["title"] for v in view["variants"])
        assert view["images"] == []
        # Frozen 2.22.3 schema requires status/external_id/deleted_at.
        # Never fill with fictitious values or emit an unvalidated HTTP 200.
        with pytest.raises(CompositionError, match="contract_mismatch"):
            stack["composer"].compose(plan, dataset=stack["dataset"])
        return
    candidate = stack["composer"].compose(plan, dataset=stack["dataset"])
    result = verify_candidate(candidate, stack["gate"], request.raw_url)
    assert result.valid is True and result.decision == "pass", result
    assert result.operation_id == "GetProductsId"
    body = json.loads(candidate.body)
    assert missing is True
    assert body == {
        "type": "not_found",
        "message": f"Product with id: {product_id} was not found",
    }


def test_missing_required_medusa_field_is_rejected_by_real_composer(contract_stack: dict) -> None:
    """Removing variants from a 200 response cannot be repaired by H or I."""
    stack = contract_stack
    _, plan = _selected(stack, stack["dataset"].products[0].id)
    bad = plan.model_dump(mode="json")
    del bad["body"]["product"]["variants"]
    with pytest.raises(CompositionError, match="contract_mismatch"):
        stack["composer"].compose(type(plan).model_validate(bad), dataset=stack["dataset"])


def test_wrong_scope_and_scenario_status_fail_closed(contract_stack: dict) -> None:
    """Prevent another E run or a fabricated 200 on a missing product."""
    stack = contract_stack
    _, plan = _selected(stack, stack["dataset"].products[0].id)
    other = stack["config"].model_copy(
        update={"scope": stack["scope"].model_copy(update={"run_id": "other-run"})}
    )
    unrelated = generate_dataset(other)
    with pytest.raises(ValueError, match="scope"):
        adapt_medusa_product_plan(plan, unrelated, product_id=stack["dataset"].products[0].id)
    with pytest.raises(ValueError, match="status"):
        adapt_medusa_product_plan(plan, stack["dataset"], product_id="unknown-product")


def test_real_gate_denies_unapproved_source_even_with_valid_body(contract_stack: dict) -> None:
    """OfficialResponseGate cannot be persuaded by a schema-conformant candidate."""
    stack = contract_stack
    request, plan = _selected(stack, "prod-unapproved-missing")
    candidate = stack["composer"].compose(plan, dataset=stack["dataset"])
    source = yaml.safe_load((PINNED / "source.yaml").read_text(encoding="utf-8"))
    manifest = {
        **{key: value for key, value in source.items() if key != "schema_version"},
        "base_urls": [stack["base_url"]], "query_contexts": [{}],
    }
    manifest_path = stack["directory"] / "manifest.yaml"
    originally_approved = manifest_path.read_bytes()
    try:
        manifest_path.write_text(yaml.safe_dump(manifest), encoding="utf-8")
        denied = OfficialResponseGate(PlatformRegistry(stack["root"]))
        result = verify_candidate(candidate, denied, request.raw_url)
        assert result.decision == "unverifiable"
        assert any(item.code == "contract_not_approved" for item in result.errors)
    finally:
        manifest_path.write_bytes(originally_approved)


def test_wrong_platform_adapter_selection_is_rejected(contract_stack: dict) -> None:
    """The adapter requires the exact pinned Medusa operation and cannot run for a demo."""
    stack = contract_stack
    policy = stack["policy"].model_dump(mode="json")
    policy["rules"][0]["platform_version"] = "future"
    with pytest.raises(ValueError, match="exact pinned"):
        ScenarioPolicy.model_validate(policy)

@pytest.mark.parametrize("requested_id", ["prod-synthetic-missing", "prod-other-unseen"])
def test_final_medusa_404_renderer_uses_original_id_message(
    contract_stack: dict, requested_id: str,
) -> None:
    """Seal two request-specific 404 bytes/status/headers with real M and I."""

    request, plan = _selected(
        contract_stack, requested_id,
        request_id="50cd410b-a73e-4931-937a-4c267b2df794",
    )
    candidate = contract_stack["composer"].compose(
        plan, dataset=contract_stack["dataset"],
    )
    gate = contract_stack["gate"]
    result = PipelineResult(
        decision="validated", candidate=candidate,
        gate_result=verify_candidate(candidate, gate, request.raw_url),
        trace={
            "request_id": request.request_id,
            "request_fingerprint": fingerprint_request(request),
            "candidate_sha256": digest(candidate.to_dict()),
            "release_deadline_monotonic": time.monotonic() + 90,
        },
    )
    response = ResponseRenderer(gate).render(result, request)
    messages: list[dict] = []

    async def receive() -> dict:
        """Return a completed empty GET request."""
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict) -> None:
        """Collect exactly what the sealed response emitted to the ASGI server."""
        messages.append(message)

    async def emit() -> None:
        """Exercise the actual sealed M response without a stub renderer."""
        await response(
            {
                "type": "http", "scheme": "http", "method": request.method,
                "path": request.path, "raw_path": request.raw_path,
                "query_string": request.query_string,
                "headers": [
                    (key.encode("latin-1"), value.encode("latin-1"))
                    for key, value in request.headers
                ],
                "server": ("127.0.0.1", 18991),
            }, receive, send,
        )

    asyncio.run(emit())
    assert len(messages) == 2
    assert messages[0]["status"] == 404
    assert json.loads(messages[1]["body"]) == {
        "type": "not_found",
        "message": f"Product with id: {requested_id} was not found",
    }
    assert messages[1]["body"] == candidate.body_bytes
    sent_headers = {
        k.decode("latin-1"): v.decode("latin-1")
        for k, v in messages[0]["headers"]
    }
    assert sent_headers["content-length"] == str(len(candidate.body_bytes))
    assert sent_headers["x-request-id"] == request.request_id
    assert sent_headers["content-type"].startswith("application/json")


def test_medusa_200_never_invents_missing_lifecycle_time(contract_stack: dict) -> None:
    """Refuse 200 when E has no synthetic creation event provenance."""
    from deception.domains.ecommerce.medusa_product import _product_view

    product = contract_stack["dataset"].products[0]
    variants = [
        variant for variant in contract_stack["dataset"].variants
        if variant.product_id == product.id
    ]
    with pytest.raises(ValueError, match="explicit synthetic creation event"):
        _product_view(product, variants, lifecycle_at=None)


@pytest.mark.parametrize("bad_time", [
    "2026-11-11T00:00:00", "no-date", "",
])
def test_medusa_200_rejects_invalid_synthetic_clock(
    contract_stack: dict, bad_time: str,
) -> None:
    """Synthetic event timestamps require valid timezone-aware RFC3339."""
    from deception.domains.ecommerce.synthetic import SyntheticConfig

    raw = contract_stack["config"].model_dump(mode="json")
    raw["synthetic_created_at"] = bad_time
    with pytest.raises(ValueError):
        SyntheticConfig.model_validate(raw)
