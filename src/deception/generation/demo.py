"""C/G 真本機模型的離線展示；合成契約及核准只存在於臨時測試目錄。"""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from deception.api.ingress import NormalizedRequest
from deception.core import ResponseComposer
from deception.core.orchestrator import DeceptionOrchestrator
from deception.discovery import BindingConfig, DeploymentBinding, PlatformIdentifier, RuntimeContext
from deception.llm import LLMConfig, PydanticAIBackend
from deception.profile_builder import ProfileTool, build_profile
from deception.profile_builder.builder import _atomic_write, local_path
from deception.scenarios import AttackAssessment, ScenarioEngine, ScenarioPolicy, fingerprint_request
from deception.synthetic import DatasetScope, SyntheticConfig, generate_dataset
from mirage_validator.gate import OfficialResponseGate, PlatformRegistry

from .cache import ContentCache
from .generator import ContentGenerator
from .models import GenerationPolicy, digest


def _bytes(value) -> bytes:
    """以固定 JSON bytes 保存輸入及報告，SHA-256 對應實際寫出的檔案。"""
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def _specification() -> dict:
    """專用最小契約含描述與錯誤訊息，不能當成完整 Medusa／WooCommerce body。"""
    product = {"type": "object", "required": ["product"], "additionalProperties": False,
               "properties": {"product": {"type": "object", "required": ["id", "title", "description"],
                   "additionalProperties": False, "properties": {
                       "id": {"type": "string"}, "title": {"type": "string"},
                       "description": {"type": "string", "minLength": 10, "maxLength": 120}}}}}
    missing = {"type": "object", "required": ["type", "message"], "additionalProperties": False,
               "properties": {"type": {"type": "string", "enum": ["not_found"]},
                              "message": {"type": "string", "minLength": 10, "maxLength": 120}}}
    return {"openapi": "3.1.0", "info": {"title": "C/G local-model synthetic demo only", "version": "1.0"},
            "paths": {"/products/{id}": {"get": {"operationId": "getProduct", "parameters": [
                {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {str(code): {"description": "Synthetic demo response", "content": {
                    "application/json": {"schema": schema}}} for code, schema in ((200, product), (404, missing))}}}}}


def _policies(scope: DatasetScope, runtime: RuntimeContext) -> tuple[ScenarioPolicy, GenerationPolicy]:
    """分開定義 F 事實映射與 G 可生成欄位，兩者只綁定這份合成契約。"""
    common = dict(platform_id=scope.platform_id, platform_version=scope.platform_version,
                  spec_sha256=scope.spec_sha256, operation_id="getProduct", method="GET", path="/products/{id}")
    scenario = ScenarioPolicy.model_validate(dict(
        domain="ecommerce", policy_id="local-demo-scenarios", policy_version="1", enabled=True,
        trusted_sources=["local-demo-detector"], max_age_seconds=600, rules=[dict(
            common, **runtime.model_dump(), site_id=scope.site_id, rule_id="product-lookup",
            scenario_id=scope.scenario_id, found={"status_code": 200, "template_id": "found"},
            missing={"status_code": 404, "template_id": "missing"})], templates=[
                {"template_id": "found", "body": {"product": {"id": "", "title": "", "description": ""}},
                 "bindings": [{"source_field": "id", "target_pointer": "/product/id"},
                              {"source_field": "title", "target_pointer": "/product/title"}]},
                {"template_id": "missing", "body": {"type": "not_found", "message": ""}}]))
    generation = GenerationPolicy.model_validate(dict(
        domain="ecommerce", policy_id="local-demo-generation", policy_version="1", prompt_version="1", enabled=True,
        limits={"timeout_seconds": 300, "max_model_requests": 8, "max_tool_calls": 8,
                "max_input_tokens": 32000, "max_output_tokens": 4096, "max_repairs": 1},
        rules=[dict(common, rule_id="product-description", outcome_id="found", status_code=200,
                    protected_pointers=["/product/id", "/product/title"], fields=[dict(
                        field_id="description", target_pointer="/product/description", cache_scope="entity",
                        entity_pointer="/product_id", instruction=(
                            "Write one short English description of this synthetic product in 20 to 80 characters. "
                            "Preserve the supplied product facts."))]),
               dict(common, rule_id="missing-message", outcome_id="missing", status_code=404,
                    protected_pointers=["/type"], fields=[dict(
                        field_id="message", target_pointer="/message", cache_scope="request", instruction=(
                            "Write one short English sentence in 20 to 80 characters explaining that the requested "
                            "synthetic product does not exist."))])]))
    return scenario, generation


def _request(product_id: str, sequence: int) -> NormalizedRequest:
    """只建立 A 格式快照，不啟動 HTTP listener，也不對真實商店送出流量。"""
    path = "/api/products/" + product_id
    return NormalizedRequest(request_id=f"cg-local-demo-{sequence}", method="GET",
                             raw_url="https://shop.invalid" + path, path=path, raw_path=path.encode("ascii"),
                             query_string=b"", query=(), headers=(("host", "shop.invalid"),), body=b"")


async def run_demo(output_root: Path, *, domain: str, llm_config: LLMConfig) -> Path:
    """以真 Ollama 跑 200→404→200，檢查權威資料、相同商品內容與每次 I 結果。"""
    if domain != "ecommerce":
        raise ValueError("The local-model product demo requires domain ecommerce")
    llm_config = LLMConfig.model_validate(llm_config.model_dump(mode="json"))
    if llm_config.execution_mode != "local":
        raise ValueError("This demo requires a real local Ollama model; test models are not accepted")
    started = datetime.now(timezone.utc)
    raw = _bytes(_specification())
    source = dict(platform_id="synthetic-cg-demo", platform_version="1.0", source_url="https://example.invalid/cg-demo",
                  source_revision="local-model-demo-v1", spec_sha256=hashlib.sha256(raw).hexdigest(),
                  approved=True, openapi_file="openapi.yaml")
    scope = DatasetScope(site_id="cg-local-demo", platform_id=source["platform_id"], platform_version="1.0",
                         spec_sha256=source["spec_sha256"], scenario_id="product-lookup", run_id="cg-local-demo")
    config = SyntheticConfig(scope=scope, seed=20261108, product_count=2, variants_per_product=1)
    data = generate_dataset(config)
    before = data.model_dump_json()
    runtime = RuntimeContext(environment_id="offline-demo", deployment_id="offline-demo", service_id="demo-store")
    scenario_policy, generation_policy = _policies(scope, runtime)
    # 每次展示用新檔，確保本次真正生成；同一次展示的第三次查詢則須重用第一筆內容。
    cache_relative = f"generation/cache/{uuid4().hex}.sqlite3"
    cache = ContentCache(local_path(output_root, cache_relative))
    backend = None
    results = []
    failure = None
    try:
        backend = PydanticAIBackend(llm_config)
        generator = ContentGenerator(generation_policy, backend, cache=cache)
        with TemporaryDirectory(prefix="mirage-cg-local-demo-") as temporary:
            root = Path(temporary)
            contract_root, profiles = root / "contracts", root / "generated"
            directory = contract_root / source["platform_id"]
            directory.mkdir(parents=True)
            # 這些 approved 只存在臨時合成目錄，絕不變更 repo 的平台來源或部署核准。
            (directory / "openapi.yaml").write_bytes(raw)
            (directory / "source.yaml").write_bytes(_bytes(source))
            (directory / "manifest.yaml").write_bytes(_bytes(dict(
                source, base_urls=["https://shop.invalid/api"], query_contexts=[{}])))
            build_profile(directory / "source.yaml", profiles)
            registry = PlatformRegistry(contract_root)
            binding = DeploymentBinding(**runtime.model_dump(), binding_id="cg-local-demo", site_id=scope.site_id,
                                        platform_id=scope.platform_id, platform_version=scope.platform_version,
                                        spec_sha256=scope.spec_sha256, base_url="https://shop.invalid/api", enabled=True)
            pipeline = DeceptionOrchestrator(
                identifier=PlatformIdentifier(registry, BindingConfig(bindings=[binding])), profiles=ProfileTool(profiles),
                scenarios=ScenarioEngine(scenario_policy, domain=domain), generator=generator,
                composer=ResponseComposer(profiles), gate=OfficialResponseGate(registry))
            for sequence, (product_id, status) in enumerate(
                    ((data.products[0].id, 200), ("prod-synthetic-missing", 404), (data.products[0].id, 200)), start=1):
                request = _request(product_id, sequence)
                clock = datetime.now(timezone.utc)
                assessment = AttackAssessment(
                    assessment_id=f"cg-local-demo-{sequence}", source_id="local-demo-detector",
                    request_id=request.request_id, request_fingerprint=fingerprint_request(request),
                    **runtime.model_dump(), site_id=scope.site_id, verdict="malicious",
                    observed_at=clock - timedelta(seconds=1), expires_at=clock + timedelta(seconds=600))
                print(f"Real local model case {sequence}/3: expecting HTTP {status}.", flush=True)
                result = await pipeline.run(request, assessment, runtime=runtime, generation_config=config, dataset=data)
                results.append(result.model_dump(mode="json"))
                if (result.decision != "validated" or result.candidate is None or result.gate_result is None or
                        result.gate_result.decision != "pass" or result.gate_result.valid is not True or
                        result.candidate.status_code != status):
                    failure = f"Case {sequence} did not pass the synthetic C/G/H/I flow"
                    print(f"Case {sequence}: {result.decision}; codes={[issue.code for issue in result.errors]}.", flush=True)
                    break
                model = result.trace.get("model", {})
                if model.get("execution_mode") != "local" or model.get("provider") != "ollama":
                    failure = "The demo did not use the configured real local model"
                    break
                if data.model_dump_json() != before:
                    failure = "The synthetic E snapshot changed during generation"
                    break
                if status == 200:
                    product = json.loads(result.candidate.body)["product"]
                    if product["id"] != data.products[0].id or product["title"] != data.products[0].title:
                        failure = "Generated content changed authoritative product facts"
                        break
                print(f"Case {sequence}: validated; cache_hit={result.trace.get('generation', {}).get('cache_hit')}; "
                      f"usage={result.trace.get('usage', {})}.", flush=True)
            if failure is None:
                if results[0]["candidate"]["body"] != results[2]["candidate"]["body"]:
                    failure = "Repeated product lookup returned a different generated description"
                elif (results[0]["trace"]["generation"]["cache_hit"] is not False or
                      results[1]["trace"]["generation"]["cache_hit"] is not False or
                      results[2]["trace"]["generation"]["cache_hit"] is not True):
                    failure = "Expected two real generations followed by an entity content cache hit"
    finally:
        if backend is not None:
            await backend.aclose()
        cache.close()
    verified_local_model = bool(results) and all(
        result.get("trace", {}).get("model", {}).get("execution_mode") == "local" for result in results)
    report = dict(test_only=True, real_model=verified_local_model, success=failure is None, domain=domain,
                  started_at=started.isoformat(), completed_at=datetime.now(timezone.utc).isoformat(),
                  contract=json.loads(raw), contract_source=source, scope=scope.model_dump(mode="json"),
                  llm_config=llm_config.model_dump(mode="json"), scenario_policy=scenario_policy.model_dump(mode="json"),
                  generation_policy=generation_policy.model_dump(mode="json"), dataset_config=config.model_dump(mode="json"),
                  dataset_namespace=data.namespace, state_sha256=digest(data.model_dump(mode="json")),
                  model_identity=results[0].get("trace", {}).get("model") if results else None,
                  cache_file=cache_relative,
                  checks={"outcome_statuses": [r["candidate"]["status_code"] for r in results if r.get("candidate")],
                          "e_snapshot_unchanged": data.model_dump_json() == before,
                          "repeat_product_body_identical": failure is None}, results=results, failure=failure)
    encoded = _bytes(report)
    output = local_path(output_root, f"generation/{hashlib.sha256(encoded).hexdigest()}.json")
    _atomic_write(output, encoded)
    if failure is not None:
        raise RuntimeError(f"{failure}; diagnostic report: {output}")
    return output
