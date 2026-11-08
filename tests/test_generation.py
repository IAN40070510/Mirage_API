"""G 的生成邊界：真實 Pydantic AI 代理搭配可控模型，不依賴外部模型服務。"""

import asyncio
import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import FunctionModel

from deception.core import CompositionPlan, ResponseComposer
from deception.core.orchestrator import DeceptionOrchestrator
from deception.discovery import BindingConfig, DeploymentBinding, PlatformIdentifier, RuntimeContext
from deception.generation import (ContentCache, ContentGenerator, GenerationContext, GenerationIntent,
                                  GenerationPolicy)
from deception.generation.schema import _resolve, field_schema
from deception.llm import LLMConfig, PydanticAIBackend, RunBudget
from deception.profile_builder import ProfileTool, build_profile
from deception.scenarios import ScenarioEngine, ScenarioPolicy
from deception.synthetic import DatasetScope, SyntheticConfig, generate_dataset
from mirage_validator.gate import OfficialResponseGate, PlatformRegistry

from test_scenarios import NOW, assessment_for, request_for


def function_backend(field_id="description", value="Generated synthetic product description", *,
                     tool_name="read_facts", planner_instructions="", generator_function=None,
                     model_digest="0" * 64):
    """用真正 FunctionModel 驅動工具調用及結構輸出，保留呼叫紀錄供預算與快取驗證。"""
    calls = {"planner": [], "generator": []}

    async def plan(messages, info):
        """先提出受控工具呼叫，再以框架輸出工具回傳指定欄位的生成計畫。"""
        calls["planner"].append(messages)
        if not any(isinstance(part, ToolReturnPart) for message in messages for part in message.parts):
            return ModelResponse(parts=[ToolCallPart(tool_name, {})])
        assert info.output_tools, "Planner must declare its typed output tool"
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, {
            "field_ids": [field_id], "instructions": planner_instructions,
        })])

    async def generate(messages, info):
        """記錄 G 呼叫並回傳可控 JSON，或委派測試指定的模型行為。"""
        calls["generator"].append(messages)
        if generator_function is not None:
            return await generator_function(messages, info)
        return ModelResponse(parts=[TextPart(json.dumps({field_id: value}, ensure_ascii=False))])

    config = LLMConfig(execution_mode="test", model_name="function-test", model_digest=model_digest,
                       base_url="http://127.0.0.1:11434/v1", max_output_tokens=512, temperature=0.0)
    backend = PydanticAIBackend(config, planner_model=FunctionModel(plan), generator_model=FunctionModel(generate))
    return backend, calls


@pytest.fixture
def generation_stack(tmp_path):
    """獨立建立含可生成描述的 B/D/E/F/H/I 契約，保留商品 ID/title 的 E 映射。"""
    product_schema = {
        "type": "object", "required": ["product"], "additionalProperties": False,
        "properties": {"product": {
            "type": "object", "required": ["id", "title", "description"], "additionalProperties": False,
            "properties": {"id": {"type": "string"}, "title": {"type": "string"},
                           "description": {"type": "string", "minLength": 10, "maxLength": 120}},
        }},
    }
    missing_schema = {
        "type": "object", "required": ["type", "message"], "additionalProperties": False,
        "properties": {"type": {"type": "string", "enum": ["not_found"]},
                       "message": {"type": "string", "minLength": 10, "maxLength": 120}},
    }
    spec = {"openapi": "3.1.0", "info": {"title": "C/G synthetic test only", "version": "1.0"},
            "paths": {"/products/{id}": {"get": {"operationId": "getProduct", "parameters": [
                {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {str(code): {"description": "Synthetic response", "content": {
                    "application/json": {"schema": schema}}} for code, schema in
                    ((200, product_schema), (404, missing_schema))}}}}}
    raw = yaml.safe_dump(spec).encode("utf-8")
    source = dict(platform_id="synthetic", platform_version="1.0", source_url="https://example.invalid/cg-test",
                  source_revision="cg-test-only", spec_sha256=hashlib.sha256(raw).hexdigest(),
                  openapi_file="openapi.yaml", approved=True)
    directory = tmp_path / "contracts" / "synthetic"
    directory.mkdir(parents=True)
    (directory / "openapi.yaml").write_bytes(raw)
    (directory / "source.yaml").write_text(yaml.safe_dump(source), encoding="utf-8")
    (directory / "manifest.yaml").write_text(yaml.safe_dump(dict(
        source, base_urls=["https://shop.test/api"], query_contexts=[{}])), encoding="utf-8")
    registry = PlatformRegistry(tmp_path / "contracts")
    runtime = RuntimeContext(environment_id="test-env", deployment_id="test-deploy", service_id="store")
    binding = DeploymentBinding(**runtime.model_dump(), binding_id="cg-binding", site_id="shop-test",
                                base_url="https://shop.test/api", platform_id="synthetic", platform_version="1.0",
                                spec_sha256=source["spec_sha256"], enabled=True)
    identifier = PlatformIdentifier(registry, BindingConfig(bindings=[binding]))
    output = tmp_path / "generated"
    build_profile(directory / "source.yaml", output)
    scope = DatasetScope(site_id="shop-test", platform_id="synthetic", platform_version="1.0",
                         spec_sha256=source["spec_sha256"], scenario_id="product-lookup", run_id="run-a")
    config = SyntheticConfig(scope=scope, seed=20261108, product_count=2, variants_per_product=1)
    dataset = generate_dataset(config)
    request = request_for(dataset.products[0].id)
    identified = identifier.identify_request(request, context=runtime)
    assert identified.decision == "identified", identified
    profile = ProfileTool(output).get_operation(**identified.identity.profile_arguments())
    identity = identified.identity
    common = {key: getattr(identity, key) for key in (
        "environment_id", "deployment_id", "service_id", "site_id", "platform_id", "platform_version",
        "spec_sha256", "operation_id", "method", "path")}
    scenario_policy = dict(domain="ecommerce", policy_id="cg-scenario", policy_version="1", enabled=True,
                           trusted_sources=["detector"], rules=[dict(
                               common, rule_id="lookup", scenario_id="product-lookup",
                               found={"status_code": 200, "template_id": "found"},
                               missing={"status_code": 404, "template_id": "missing"})], templates=[
                               {"template_id": "found", "body": {"product": {"id": "", "title": "", "description": ""}},
                                "bindings": [{"source_field": "id", "target_pointer": "/product/id"},
                                             {"source_field": "title", "target_pointer": "/product/title"}]},
                               {"template_id": "missing", "body": {"type": "not_found", "message": ""}},
                           ])
    generation_common = {key: getattr(identity, key) for key in (
        "platform_id", "platform_version", "spec_sha256", "operation_id", "method", "path")}
    policy_data = dict(domain="ecommerce", policy_id="cg-generation", policy_version="1", prompt_version="1",
                       enabled=True, rules=[
                           dict(generation_common, rule_id="describe-product", outcome_id="found", status_code=200,
                                protected_pointers=["/product/id", "/product/title"], fields=[{
                                    "field_id": "description", "target_pointer": "/product/description",
                                    "instruction": "Describe this synthetic product without changing its facts.",
                                    "cache_scope": "entity", "entity_pointer": "/product_id"}]),
                           dict(generation_common, rule_id="missing-message", outcome_id="missing", status_code=404,
                                protected_pointers=["/type"], fields=[{
                                    "field_id": "message", "target_pointer": "/message",
                                    "instruction": "Explain that the requested product does not exist.",
                                    "cache_scope": "request"}]),
                       ])
    return dict(identifier=identifier, runtime=runtime, registry=registry, gate=OfficialResponseGate(registry),
                output=output, directory=directory, profile=profile, source=source, config=config, dataset=dataset,
                request=request, identified=identified, scenario_policy=scenario_policy, policy_data=policy_data,
                cache_root=tmp_path / "content-cache")


def make_pipeline(stack, *, backend=None, policy_data=None, scenario_policy=None, cache=None):
    """每個工具以明確快照組合；測試可替換模型或政策，但不跳過 B/F/H/I。"""
    if backend is None:
        backend, calls = function_backend()
    else:
        calls = None
    policy = GenerationPolicy.model_validate(policy_data or stack["policy_data"])
    generator = ContentGenerator(policy, backend, cache=ContentCache() if cache is None else cache)
    pipeline = DeceptionOrchestrator(
        identifier=stack["identifier"], profiles=ProfileTool(stack["output"]),
        scenarios=ScenarioEngine(ScenarioPolicy.model_validate(scenario_policy or stack["scenario_policy"])),
        generator=generator, composer=ResponseComposer(stack["output"]), gate=stack["gate"],
    )
    return pipeline, generator, calls


def run_pipeline(stack, pipeline, *, request=None, assessment=None, config=None, dataset=None):
    """同步測試入口仍執行真正 async pipeline，不需 pytest-asyncio 額外套件。"""
    request = stack["request"] if request is None else request
    assessment = assessment_for(request) if assessment is None else assessment
    return asyncio.run(pipeline.run(
        request, assessment, runtime=stack["runtime"], generation_config=stack["config"] if config is None else config,
        dataset=stack["dataset"] if dataset is None else dataset, now=NOW,
    ))


def test_real_agent_generates_description_and_preserves_e_facts(generation_stack):
    """工具調用和 JSON 生成都經 Pydantic AI，最終商品 ID/title 仍取自原 E 快照。"""
    stack = generation_stack
    original = stack["dataset"].model_dump_json()
    pipeline, _, calls = make_pipeline(stack)
    result = run_pipeline(stack, pipeline)
    assert result.decision == "validated", result
    assert result.gate_result.valid is True and result.gate_result.decision == "pass"
    product = stack["dataset"].products[0]
    assert json.loads(result.candidate.body) == {"product": {
        "id": product.id, "title": product.title, "description": "Generated synthetic product description"}}
    assert len(calls["planner"]) == 2 and len(calls["generator"]) == 1
    assert stack["dataset"].model_dump_json() == original


@pytest.mark.parametrize("value", [1, True, None, "short", "x" * 121, {"nested": "description"}])
def test_generated_value_must_satisfy_the_original_field_schema(generation_stack, value):
    """解碼器或模型回傳合法 JSON 仍需符合欄位型別與長度，不隱含轉型或補值。"""
    backend, calls = function_backend(value=value)
    pipeline, _, _ = make_pipeline(generation_stack, backend=backend)
    result = run_pipeline(generation_stack, pipeline)
    assert result.decision != "validated" and result.candidate is None, result
    assert calls["generator"], "The invalid value must actually reach the generator boundary"


def test_entity_content_is_reused_across_request_ids(generation_stack):
    """同商品的描述由資料身份定址，換 request_id 仍重用已通過驗證的生成內容。"""
    stack = generation_stack
    pipeline, _, calls = make_pipeline(stack)
    first = run_pipeline(stack, pipeline)
    second_request = replace(stack["request"], request_id="cg-second-request")
    second = run_pipeline(stack, pipeline, request=second_request)
    assert first.decision == second.decision == "validated", (first, second)
    assert first.candidate.body == second.candidate.body
    assert len(calls["generator"]) == 1


def test_different_products_do_not_share_generated_content(generation_stack):
    """共用 schema 與種子的不同商品必須有不同內容快取身份。"""
    stack = generation_stack
    pipeline, _, calls = make_pipeline(stack)
    first = run_pipeline(stack, pipeline)
    request = request_for(stack["dataset"].products[1].id, request_id="cg-other-product")
    second = run_pipeline(stack, pipeline, request=request)
    assert first.decision == second.decision == "validated", (first, second)
    assert json.loads(first.candidate.body)["product"]["id"] != json.loads(second.candidate.body)["product"]["id"]
    assert len(calls["generator"]) == 2


@pytest.mark.parametrize("target", ["/product", "/product/id", "/product/title"])
def test_generation_cannot_overwrite_protected_product_facts(generation_stack, target):
    """白名單目標不可直接或經父物件覆蓋 E 映射／明確保護欄位。"""
    stack = generation_stack
    policy_data = copy.deepcopy(stack["policy_data"])
    policy_data["rules"][0]["fields"][0]["target_pointer"] = target
    try:
        pipeline, _, _ = make_pipeline(stack, policy_data=policy_data)
    except ValueError:
        return  # 載入政策時拒絕同樣是有效的 fail-closed 邊界。
    result = run_pipeline(stack, pipeline)
    assert result.decision != "validated" and result.candidate is None, result


def test_model_cannot_add_undeclared_generation_fields(generation_stack):
    """模型額外提出商品 ID 或任意欄位時，整份輸出拒絕而非忽略越權值。"""
    async def extra_output(messages, info):
        """模擬模型夾帶未授權的商品 ID，以驗證額外欄位會被整份拒絕。"""
        return ModelResponse(parts=[TextPart(json.dumps({
            "description": "A generated synthetic product", "id": "attacker-selected-id"}))])

    backend, _ = function_backend(generator_function=extra_output)
    pipeline, _, _ = make_pipeline(generation_stack, backend=backend)
    result = run_pipeline(generation_stack, pipeline)
    assert result.decision != "validated" and result.candidate is None, result


def test_model_failure_does_not_publish_a_cache_entry(generation_stack):
    """失敗內容不成為可重用快取；後續有效模型必須重新生成後才能通過。"""
    stack = generation_stack
    cache = ContentCache()
    bad_backend, bad_calls = function_backend(value="short")
    bad_pipeline, _, _ = make_pipeline(stack, backend=bad_backend, cache=cache)
    bad = run_pipeline(stack, bad_pipeline)
    assert bad.decision != "validated" and bad.candidate is None, bad
    good_backend, good_calls = function_backend()
    good_pipeline, _, _ = make_pipeline(stack, backend=good_backend, cache=cache)
    good = run_pipeline(stack, good_pipeline)
    assert good.decision == "validated", good
    assert good_calls["generator"]
    assert bad_calls["generator"]


def test_validated_content_survives_reopening_the_persistent_cache(generation_stack):
    """已通過 H/I 的描述可在工具重建後重用，而不是依賴單一 Python 物件記憶體。"""
    stack = generation_stack
    path = stack["cache_root"] / "content.sqlite3"
    first_cache = ContentCache(path)
    first_pipeline, _, _ = make_pipeline(stack, cache=first_cache)
    first = run_pipeline(stack, first_pipeline)
    assert first.decision == "validated", first
    first_cache.close()
    second_cache = ContentCache(path)
    backend, calls = function_backend(value="A different description that should not replace the saved value.")
    second_pipeline, _, _ = make_pipeline(stack, backend=backend, cache=second_cache)
    second = run_pipeline(stack, second_pipeline, request=replace(stack["request"], request_id="after-restart"))
    assert second.decision == "validated", second
    assert first.candidate.body == second.candidate.body
    assert calls["generator"] == []
    second_cache.close()


@pytest.mark.parametrize("changed", ["policy_version", "prompt_version", "model_digest"])
def test_generation_versions_do_not_reuse_incompatible_cached_content(generation_stack, changed):
    """政策、提示或實際模型摘要變動時，必須以新身份生成並重新驗證。"""
    stack = generation_stack
    cache = ContentCache()
    first_pipeline, _, _ = make_pipeline(stack, cache=cache)
    first = run_pipeline(stack, first_pipeline)
    assert first.decision == "validated", first
    policy_data = copy.deepcopy(stack["policy_data"])
    if changed != "model_digest":
        policy_data[changed] = "2"
    backend, calls = function_backend(value="A newly generated description for the changed version.",
                                      model_digest="1" * 64 if changed == "model_digest" else "0" * 64)
    second_pipeline, _, _ = make_pipeline(stack, backend=backend, policy_data=policy_data, cache=cache)
    second = run_pipeline(stack, second_pipeline)
    assert second.decision == "validated", second
    assert calls["generator"]
    assert first.candidate.body != second.candidate.body


def test_generation_policy_digest_tracks_a_read_only_snapshot(generation_stack):
    """追溯與快取不得採用可由呼叫者改寫、卻不對應實際政策的摘要。"""
    pipeline, generator, _ = make_pipeline(generation_stack)
    expected = hashlib.sha256(json.dumps(generator.policy.model_dump(mode="json"), ensure_ascii=False,
                                        sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    assert generator.policy_sha256 == expected
    with pytest.raises(AttributeError):
        generator.policy_sha256 = "0" * 64
    result = run_pipeline(generation_stack, pipeline)
    assert result.decision == "validated", result
    assert generator.policy_sha256 == expected


def test_generated_field_alias_with_a_hyphen_survives_backend_revalidation(generation_stack):
    """動態欄位的內部名稱不可取代對外 alias，合法含連字號的 field ID 必須可生成。"""
    stack = generation_stack
    policy_data = copy.deepcopy(stack["policy_data"])
    policy_data["rules"][0]["fields"][0]["field_id"] = "product-description"
    backend, calls = function_backend(field_id="product-description")
    pipeline, _, _ = make_pipeline(stack, backend=backend, policy_data=policy_data)
    result = run_pipeline(stack, pipeline)
    assert result.decision == "validated", result
    assert json.loads(result.candidate.body)["product"]["description"] == "Generated synthetic product description"
    assert len(calls["generator"]) == 1


@pytest.mark.parametrize("second_field", [
    {"cache_scope": "request"},
    {"cache_scope": "entity", "entity_pointer": "/another_product_id"},
])
def test_one_generation_bundle_cannot_mix_cache_scopes_or_entities(generation_stack, second_field):
    """首版共同發布一組欄位，只允許同範圍與同實體，避免其他欄位破壞 entity 穩定性。"""
    policy_data = copy.deepcopy(generation_stack["policy_data"])
    policy_data["rules"][0]["fields"].append(dict(
        field_id="request-note", target_pointer="/product/note", instruction="Write a synthetic note.",
        **second_field))
    with pytest.raises(ValueError):
        GenerationPolicy.model_validate(policy_data)


def test_scenario_policy_change_invalidates_entity_generated_content(generation_stack):
    """F 的政策與模板屬於生成依據；即使 E 和 G 政策不變，也不能重用舊 F 版本的內容。"""
    stack = generation_stack
    cache = ContentCache()
    first_pipeline, _, _ = make_pipeline(stack, cache=cache)
    first = run_pipeline(stack, first_pipeline)
    assert first.decision == "validated", first
    scenario_policy = copy.deepcopy(stack["scenario_policy"])
    scenario_policy["policy_version"] = "2"
    backend, calls = function_backend(value="A new synthetic description after the scenario policy changed.")
    second_pipeline, _, _ = make_pipeline(stack, backend=backend, scenario_policy=scenario_policy, cache=cache)
    second = run_pipeline(stack, second_pipeline)
    assert second.decision == "validated", second
    assert calls["generator"], "A different F policy must not reuse the original entity cache entry"
    assert first.candidate.body != second.candidate.body


def _direct_generation_inputs(stack, generator, backend):
    """用真 F 建立 G 輸入，讓快取鍵測試不依賴 C 的私有上下文建立方法。"""
    scenarios = ScenarioEngine(ScenarioPolicy.model_validate(stack["scenario_policy"]))
    preparation = scenarios.prepare(stack["request"], stack["identified"], stack["profile"],
                                    assessment_for(stack["request"]), run_id=stack["config"].scope.run_id, now=NOW)
    assert preparation.decision == "prepared", preparation
    prepared = preparation.prepared
    selected = scenarios.resolve(prepared, stack["dataset"], now=NOW)
    assert selected.decision == "selected", selected
    identity = stack["identified"].identity
    budget = RunBudget(generator.policy.limits)
    model = asyncio.run(backend.check_ready(budget))
    context = GenerationContext(
        domain=prepared.domain, request_id=stack["request"].request_id,
        request_fingerprint=prepared.request_fingerprint, environment_id=identity.environment_id,
        deployment_id=identity.deployment_id, service_id=identity.service_id, scope=prepared.scope,
        operation_id=identity.operation_id, outcome_id=selected.outcome_id,
        scenario_decision_id=selected.trace["decision_id"], scenario_policy_sha256=scenarios.policy_sha256,
        generation_policy_sha256=generator.policy_sha256, data_namespace=selected.trace["data_namespace"],
        state_sha256=selected.trace["state_sha256"], domain_context=prepared.domain_context, model_identity=model)
    return selected.composition_plan, context, budget


@pytest.mark.parametrize("change,expected_hit", [("base_plan", False), ("request_ids", True)])
def test_entity_cache_binds_the_base_plan_but_not_request_bound_ids(generation_stack, change, expected_hit):
    """回應骨架變更須重新生成；換請求追蹤 ID 或 F decision ID 仍可重用同實體內容。"""
    stack = generation_stack
    backend, calls = function_backend()
    generator = ContentGenerator(GenerationPolicy.model_validate(stack["policy_data"]), backend)
    plan, context, budget = _direct_generation_inputs(stack, generator, backend)
    intent = GenerationIntent(field_ids=["description"])

    async def generate_and_publish():
        """先發布有效內容，再比較變更骨架或請求追蹤資訊後的實體快取行為。"""
        first = await generator.generate(plan, context, stack["profile"], facts={}, budget=budget, intent=intent)
        generator.cache.publish(first.cache_key, first.values)
        changed_plan = CompositionPlan.model_validate(plan.model_dump(mode="json"))
        changed_context = context.model_copy(deep=True)
        if change == "base_plan":
            changed_plan.headers["X-Synthetic-Template-Version"] = "2"
        else:
            changed_context.request_id = "different-request"
            changed_context.request_fingerprint = "1" * 64
            changed_context.scenario_decision_id = "2" * 64
        second = await generator.generate(changed_plan, changed_context, stack["profile"],
                                          facts={}, budget=budget, intent=intent)
        return first, second

    first, second = asyncio.run(generate_and_publish())
    assert second.cache_hit is expected_hit
    assert (first.cache_key == second.cache_key) is expected_hit
    assert len(calls["generator"]) == (1 if expected_hit else 2)


def test_generation_schema_rejects_structural_siblings_at_an_intermediate_ref():
    """解引用的每一層都須保留限制或拒絕，不能把中間的 maxLength 默默丟棄。"""
    spec = {"components": {"schemas": {
        "first": {"$ref": "#/components/schemas/last", "maxLength": 5},
        "last": {"type": "string", "maxLength": 20},
    }}}
    with pytest.raises(ValueError):
        _resolve(spec, {"$ref": "#/components/schemas/first"})


def test_field_schema_checks_intermediate_parent_ref_siblings(generation_stack):
    """走訪欄位路徑時也必須檢查祖先引用，不能只保護最末欄位的 schema。"""
    stack = generation_stack
    profile = stack["profile"].model_copy(deep=True)
    response = profile.operation.responses["200"]["content"]["application/json"]
    original = copy.deepcopy(response["schema"])
    profile.specification.setdefault("components", {}).setdefault("schemas", {}).update({
        "first": {"$ref": "#/components/schemas/last", "maxProperties": 1},
        "last": original,
    })
    response["schema"] = {"$ref": "#/components/schemas/first"}
    plan = CompositionPlan(scope=stack["config"].scope, method="GET", path="/products/{id}",
                           status_code=200, body={"product": {"description": ""}})
    with pytest.raises(ValueError):
        field_schema(profile, plan, "/product/description")


def test_decoder_receives_a_self_contained_string_schema_and_the_candidate_passes_h_i(generation_stack, monkeypatch):
    """給解碼器的欄位 schema 必須直接限制字串，避免 JsonValue 引用讓本機模型輸出物件。"""
    backend, _ = function_backend()
    captured = []
    value = "Valid synthetic generated description"

    async def generate_with_schema_check(prompt, output_type, budget):
        """驗證實際模型輸出型別所送出的 schema，接著回傳合法片段供完整流程驗證。"""
        schema = output_type.model_json_schema()
        captured.append(schema)
        field = schema["properties"]["description"]
        # 解碼器不應再依賴 JsonValue 引用及其結構 sibling 才知道這個欄位是字串。
        assert "$ref" not in field
        validator = Draft202012Validator(field)
        assert validator.is_valid(value)
        assert not validator.is_valid({"field_id": "description", "value": value})
        assert not validator.is_valid("short")
        assert not validator.is_valid("x" * 121)
        Draft202012Validator(schema).validate({"description": value})
        return output_type.model_validate({"description": value})

    monkeypatch.setattr(backend, "generate", generate_with_schema_check)
    pipeline, _, _ = make_pipeline(generation_stack, backend=backend)
    result = run_pipeline(generation_stack, pipeline)
    assert result.decision == "validated", result
    assert result.gate_result.valid is True and result.gate_result.decision == "pass"
    assert json.loads(result.candidate.body)["product"]["description"] == value
    assert len(captured) == 1
