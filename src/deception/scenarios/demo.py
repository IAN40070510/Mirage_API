"""僅限離線合成契約的 F 展示；不連線、不核准 repository 的任何真實平台。"""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from deception.api.ingress import NormalizedRequest
from deception.core import ResponseComposer, verify_candidate
from deception.discovery import BindingConfig, DeploymentBinding, PlatformIdentifier, RuntimeContext
from deception.profile_builder import ProfileTool, build_profile
from deception.profile_builder.builder import _atomic_write, local_path
from deception.synthetic import DatasetScope, SyntheticConfig, generate_dataset
from mirage_validator.gate import OfficialResponseGate, PlatformRegistry

from .engine import ScenarioEngine, fingerprint_request
from .models import AttackAssessment
from .domains.ecommerce import ScenarioPolicy
from .registry import default_registry


def _json_bytes(value) -> bytes:
    """以固定格式保存展示輸入與完整報告，檔名使用實際 bytes 的摘要。"""
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def _specification() -> dict:
    """自建最小商品契約，刻意與 Medusa／WooCommerce 正式規格分開。"""
    product = {"type": "object", "required": ["product"], "additionalProperties": False,
               "properties": {"product": {
                   "type": "object", "required": ["id", "title"], "additionalProperties": False,
                   "properties": {"id": {"type": "string"}, "title": {"type": "string"}}}}}
    missing = {"type": "object", "required": ["type", "message"], "additionalProperties": False,
               "properties": {"type": {"type": "string", "enum": ["not_found"]},
                              "message": {"type": "string"}}}
    return {"openapi": "3.1.0", "info": {"title": "F offline synthetic demo only", "version": "1.0"},
            "paths": {"/products/{id}": {"get": {
                "operationId": "getProduct", "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {str(status): {"description": "Synthetic demo response", "content": {
                    "application/json": {"schema": schema}}} for status, schema in
                    ((200, product), (404, missing))}}}}}


def _policy(scope: DatasetScope) -> ScenarioPolicy:
    """只有展示站點與合成契約可命中；判定也由離線展示程序自行建立。"""
    rule = dict(rule_id="demo-product-lookup", priority=100, enabled=True,
                environment_id="offline-demo", deployment_id="offline-demo", service_id="demo-store",
                site_id=scope.site_id, platform_id=scope.platform_id, platform_version=scope.platform_version,
                spec_sha256=scope.spec_sha256, operation_id="getProduct", method="GET", path="/products/{id}",
                scenario_id=scope.scenario_id, id_parameter="id", id_decoding="raw",
                found={"status_code": 200, "template_id": "found"},
                missing={"status_code": 404, "template_id": "missing"})
    return ScenarioPolicy.model_validate(dict(
        domain="ecommerce", policy_id="offline-demo", policy_version="1", enabled=True,
        trusted_sources=["offline-demo-detector"],
        rules=[rule], templates=[
            {"template_id": "found", "body": {"product": {"id": "", "title": ""}}, "bindings": [
                {"source_field": "id", "target_pointer": "/product/id"},
                {"source_field": "title", "target_pointer": "/product/title"}]},
            {"template_id": "missing", "body": {"type": "not_found", "message": "Product was not found"}}]))


def _request(product_id: str, sequence: int) -> NormalizedRequest:
    """建立與 A 相同格式的離線請求快照，不啟動 HTTP listener 或向外送出流量。"""
    path = "/api/products/" + product_id
    return NormalizedRequest(request_id=f"offline-request-{sequence}", method="GET",
                             raw_url="https://shop.invalid" + path, path=path, raw_path=path.encode("ascii"),
                             query_string=b"", query=(), headers=(("host", "shop.invalid"),), body=b"")


def run_demo(output_root: Path, *, domain: str) -> Path:
    """明確選電商後串接 B/D/E/F/H/I，驗證 200→404→200 與唯讀一致性。"""
    default_registry().get(domain)
    if domain != "ecommerce":
        raise ValueError("This synthetic product demo is available for ecommerce only")
    clock = datetime.now(timezone.utc)
    spec = _specification()
    raw = _json_bytes(spec)
    source = dict(platform_id="synthetic-demo", platform_version="1.0", source_url="https://example.invalid/demo",
                  source_revision="offline-demo-v1", spec_sha256=hashlib.sha256(raw).hexdigest(),
                  approved=True, openapi_file="openapi.yaml")
    scope = DatasetScope(site_id="offline-demo", platform_id=source["platform_id"], platform_version="1.0",
                         spec_sha256=source["spec_sha256"], scenario_id="product-lookup", run_id="offline-demo")
    config = SyntheticConfig(scope=scope, seed=42, product_count=2, variants_per_product=1)
    dataset = generate_dataset(config)
    original_dataset = dataset.model_dump_json()
    policy = _policy(scope)
    engine = ScenarioEngine(policy, domain=domain)
    runtime = RuntimeContext(environment_id="offline-demo", deployment_id="offline-demo", service_id="demo-store")
    results = []
    with TemporaryDirectory(prefix="mirage-f-synthetic-demo-") as temporary:
        temporary_root = Path(temporary)
        contract_root = temporary_root / "contracts"
        source_dir = contract_root / "synthetic-demo"
        source_dir.mkdir(parents=True)
        # 核准標記僅存在於將自動移除的合成測試目錄；不讀寫 repo 正式來源或 manifest。
        (source_dir / "openapi.yaml").write_bytes(raw)
        (source_dir / "source.yaml").write_bytes(_json_bytes(source))
        (source_dir / "manifest.yaml").write_bytes(_json_bytes(dict(
            source, base_urls=["https://shop.invalid/api"], query_contexts=[{}])))
        profiles = temporary_root / "generated"
        build_profile(source_dir / "source.yaml", profiles)
        registry = PlatformRegistry(contract_root)
        binding = DeploymentBinding(**runtime.model_dump(), binding_id="offline-demo", site_id=scope.site_id,
                                    base_url="https://shop.invalid/api", platform_id=scope.platform_id,
                                    platform_version=scope.platform_version, spec_sha256=scope.spec_sha256, enabled=True)
        identifier = PlatformIdentifier(registry, BindingConfig(bindings=[binding]))
        composer, gate = ResponseComposer(profiles), OfficialResponseGate(registry)
        cases = ((dataset.products[0].id, "found", 200), ("prod-synthetic-missing", "missing", 404),
                 (dataset.products[0].id, "found", 200))
        for sequence, (product_id, expected_outcome, expected_status) in enumerate(cases, start=1):
            request = _request(product_id, sequence)
            identified = identifier.identify_request(request, context=runtime)
            if identified.decision != "identified" or identified.identity is None:
                raise RuntimeError("Synthetic demo B identification failed")
            profile = ProfileTool(profiles).get_operation(**identified.identity.profile_arguments())
            assessment = AttackAssessment(
                assessment_id=f"offline-assessment-{sequence}", source_id="offline-demo-detector",
                request_id=request.request_id, request_fingerprint=fingerprint_request(request),
                **runtime.model_dump(), site_id=scope.site_id, verdict="malicious",
                observed_at=clock - timedelta(seconds=1), expires_at=clock + timedelta(seconds=60))
            preparation = engine.prepare(request, identified, profile, assessment, run_id=scope.run_id, now=clock)
            if preparation.decision != "prepared" or preparation.prepared is None:
                raise RuntimeError("Synthetic demo F preparation failed")
            decision = engine.resolve(preparation.prepared, dataset, now=clock)
            if (decision.decision != "selected" or decision.outcome_id != expected_outcome or
                    decision.composition_plan is None or decision.composition_plan.status_code != expected_status or
                    decision.composition_plan.scope != scope):
                raise RuntimeError("Synthetic demo F outcome or scope mismatch")
            candidate = composer.compose(decision.composition_plan, dataset=dataset)
            validation = verify_candidate(candidate, gate, request.raw_url)
            if validation.decision != "pass" or validation.valid is not True:
                raise RuntimeError("Synthetic demo H/I validation failed")
            if dataset.model_dump_json() != original_dataset:
                raise RuntimeError("Synthetic demo changed the E snapshot")
            results.append(dict(sequence=sequence, decision=decision.model_dump(mode="json"),
                                candidate=candidate.to_dict(), gate=validation.model_dump(mode="json")))
    if results[0]["candidate"]["body"] != results[2]["candidate"]["body"]:
        raise RuntimeError("Synthetic demo repeat lookup returned a different product")
    report = dict(test_only=True, domain=domain, generated_at=clock.isoformat(), contract=spec, contract_source=source,
                  scope=scope.model_dump(mode="json"), policy=policy.model_dump(mode="json"),
                  policy_sha256=engine.policy_sha256, dataset_config=config.model_dump(mode="json"),
                  dataset_namespace=dataset.namespace, state_sha256=results[0]["decision"]["trace"]["state_sha256"],
                  checks={"all_candidates_passed_synthetic_gate": True, "e_snapshot_unchanged": True,
                          "repeat_product_body_identical": True, "outcome_statuses": [200, 404, 200]},
                  results=results)
    data = _json_bytes(report)
    output = local_path(output_root, f"scenarios/{hashlib.sha256(data).hexdigest()}.json")
    _atomic_write(output, data)
    return output
