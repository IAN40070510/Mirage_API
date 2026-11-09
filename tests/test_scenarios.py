"""F 的隔離契約測試：可信判定、確定性選擇及 B/D/E/F/H/I 交接。"""

import copy
import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from deception.api.ingress import NormalizedRequest
from deception.core import CompositionError, ResponseComposer, verify_candidate
from deception.discovery import BindingConfig, DeploymentBinding, PlatformIdentifier, RuntimeContext
from deception.profile_builder import ProfileTool, build_profile
from deception.scenarios import AttackAssessment, ScenarioEngine, ScenarioPolicy, fingerprint_request, load_policy
from deception.synthetic import DatasetScope, SyntheticConfig, generate_dataset
from mirage_validator.gate import OfficialResponseGate, PlatformRegistry


NOW = datetime(2026, 11, 8, 4, 0, tzinfo=timezone.utc)


def request_for(product_id, *, request_id="scenario-request-001"):
    """重建 A 的原始請求快照；不同商品只改 URL 與原始 path。"""
    path = "/api/products/" + product_id
    return NormalizedRequest(request_id=request_id, method="GET", raw_url="https://shop.test" + path,
                             path=path, raw_path=path.encode("ascii"), query_string=b"", query=(),
                             headers=(("host", "shop.test"),), body=b"")


def assessment_for(request, **changes):
    """判定必須由伺服器信任來源提供，並綁定整份 A 請求與部署身份。"""
    values = dict(assessment_id="assessment-001", source_id="detector", request_id=request.request_id,
                  request_fingerprint=fingerprint_request(request), environment_id="test-env",
                  deployment_id="test-deploy", service_id="store", site_id="shop-test",
                  verdict="malicious", attack_types=[], observed_at=NOW - timedelta(seconds=5),
                  expires_at=NOW + timedelta(seconds=60))
    values.update(changes)
    return AttackAssessment(**values)


@pytest.fixture
def scenario_stack(tmp_path):
    """臨時合成規格與部署只用於測試，不變更真實平台的 approved 狀態。"""
    product_schema = {"type": "object", "required": ["product"], "additionalProperties": False,
                      "properties": {"product": {"type": "object", "required": ["id", "title"],
                                                  "additionalProperties": False,
                                                  "properties": {"id": {"type": "string"},
                                                                 "title": {"type": "string"}}}}}
    missing_schema = {"type": "object", "required": ["type", "message"], "additionalProperties": False,
                      "properties": {"type": {"type": "string", "enum": ["not_found"]},
                                     "message": {"type": "string"}}}
    spec = {"openapi": "3.1.0", "info": {"title": "F synthetic test only", "version": "1.0"},
            "paths": {"/products/{id}": {"get": {"operationId": "getProduct", "parameters": [
                {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {str(code): {"description": "Synthetic test response", "content": {
                    "application/json": {"schema": schema}}} for code, schema in
                    ((200, product_schema), (404, missing_schema))}}}}}
    raw = yaml.safe_dump(spec).encode("utf-8")
    source = {"platform_id": "synthetic", "platform_version": "1.0", "source_url": "https://example.org/test-only",
              "source_revision": "test-only-fixed", "spec_sha256": hashlib.sha256(raw).hexdigest(),
              "openapi_file": "openapi.yaml", "approved": True}
    directory = tmp_path / "contracts" / "test-only"
    directory.mkdir(parents=True)
    (directory / "openapi.yaml").write_bytes(raw)
    (directory / "source.yaml").write_text(yaml.safe_dump(source), encoding="utf-8")
    manifest = dict(source, base_urls=["https://shop.test/api"], query_contexts=[{}])
    (directory / "manifest.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    registry = PlatformRegistry(tmp_path / "contracts")
    binding = DeploymentBinding(binding_id="test-binding", environment_id="test-env", deployment_id="test-deploy",
                                service_id="store", site_id="shop-test", base_url="https://shop.test/api",
                                platform_id="synthetic", platform_version="1.0", spec_sha256=source["spec_sha256"],
                                enabled=True)
    runtime = RuntimeContext(environment_id="test-env", deployment_id="test-deploy", service_id="store")
    identifier = PlatformIdentifier(registry, BindingConfig(bindings=[binding]))
    output = tmp_path / "generated"
    build_profile(directory / "source.yaml", output)
    scope = DatasetScope(site_id="shop-test", platform_id="synthetic", platform_version="1.0",
                         spec_sha256=source["spec_sha256"], scenario_id="product-lookup", run_id="run-a")
    dataset = generate_dataset(SyntheticConfig(scope=scope, seed=20261108, product_count=2, variants_per_product=1))
    request = request_for(dataset.products[0].id)
    identified = identifier.identify_request(request, context=runtime)
    assert identified.decision == "identified", identified
    profile = ProfileTool(output).get_operation(**identified.identity.profile_arguments())
    rule = dict(rule_id="product-rule", priority=100, enabled=True,
                environment_id="test-env", deployment_id="test-deploy", service_id="store", site_id="shop-test",
                platform_id="synthetic", platform_version="1.0", spec_sha256=source["spec_sha256"],
                operation_id="getProduct", method="GET", path="/products/{id}", scenario_id="product-lookup",
                attack_types=[], query_contexts=[{}], id_parameter="id", id_decoding="raw",
                product_id_target="/product/id",
                found=dict(status_code=200, media_type="application/json", template_id="found"),
                missing=dict(status_code=404, media_type="application/json", template_id="missing"))
    policy_data = dict(schema_version=1, domain="ecommerce", policy_id="test-policy", policy_version="1", enabled=True,
                       trusted_sources=["detector"], max_age_seconds=300, rules=[rule], templates=[
                           dict(template_id="found", headers={}, body={"product": {"id": "", "title": ""}},
                                bindings=[dict(source_field="id", target_pointer="/product/id"),
                                          dict(source_field="title", target_pointer="/product/title")]),
                           dict(template_id="missing", headers={},
                                body={"type": "not_found", "message": "Product was not found"}, bindings=[])])
    return dict(identifier=identifier, runtime=runtime, registry=registry, source=source, directory=directory,
                output=output, scope=scope, dataset=dataset, request=request, identified=identified,
                profile=profile, policy_data=policy_data)


def prepare(stack, *, request=None, identified=None, profile=None, assessment=None, policy_data=None, **options):
    """每次建立獨立 F 工具，以免不同測試共享可變規則或準備結果。"""
    request = request or stack["request"]
    engine = ScenarioEngine(ScenarioPolicy.model_validate(policy_data or stack["policy_data"]))
    result = engine.prepare(request, identified or stack["identified"], profile or stack["profile"],
                            assessment or assessment_for(request), run_id="run-a", now=NOW, **options)
    return engine, result


@pytest.mark.parametrize("product_index", [0, 1])
def test_found_product_uses_its_actual_index_and_passes_h_i(scenario_stack, product_index):
    """查找第二筆商品也必須映射正確 E 索引，並交由 H 組合、I 驗證。"""
    stack = scenario_stack
    dataset = stack["dataset"]
    before = dataset.model_dump_json()
    product = dataset.products[product_index]
    request = request_for(product.id)
    identified = stack["identifier"].identify_request(request, context=stack["runtime"])
    engine, preparation = prepare(stack, request=request, identified=identified)
    assert preparation.decision == "prepared", preparation
    assert preparation.prepared.scope == stack["scope"]
    assert preparation.prepared.domain_context["product_id"] == product.id
    result = engine.resolve(preparation.prepared, dataset, now=NOW)
    assert result.decision == "selected" and result.outcome_id == "found", result
    assert result.composition_plan.status_code == 200
    assert result.composition_plan.scope == stack["scope"]
    candidate = ResponseComposer(stack["output"]).compose(result.composition_plan, dataset=dataset)
    assert json.loads(candidate.body) == {"product": {"id": product.id, "title": product.title}}
    verified = verify_candidate(candidate, OfficialResponseGate(stack["registry"]), request.raw_url)
    assert verified.valid is True and verified.decision == "pass", verified
    assert dataset.model_dump_json() == before


def test_missing_product_keeps_the_same_e_scope_and_passes_h_i(scenario_stack):
    """不存在商品只切換回應結果，不換 scenario_id 或重新生成商品資料。"""
    stack = scenario_stack
    before = stack["dataset"].model_dump_json()
    request = request_for("prod-missing")
    identified = stack["identifier"].identify_request(request, context=stack["runtime"])
    engine, preparation = prepare(stack, request=request, identified=identified)
    assert preparation.decision == "prepared", preparation
    result = engine.resolve(preparation.prepared, stack["dataset"], now=NOW)
    assert result.decision == "selected" and result.outcome_id == "missing", result
    assert result.composition_plan.scope == preparation.prepared.scope == stack["scope"]
    assert result.composition_plan.status_code == 404
    assert result.composition_plan.bindings == []
    candidate = ResponseComposer(stack["output"]).compose(result.composition_plan, dataset=stack["dataset"])
    assert json.loads(candidate.body) == {"type": "not_found", "message": "Product was not found"}
    assert verify_candidate(candidate, OfficialResponseGate(stack["registry"]), request.raw_url).valid is True
    assert stack["dataset"].model_dump_json() == before


@pytest.mark.parametrize("changes", [
    {"source_id": "untrusted"}, {"request_id": "another-request"}, {"request_fingerprint": "0" * 64},
    {"environment_id": "other-env"}, {"deployment_id": "other-deploy"}, {"service_id": "other-service"},
    {"site_id": "other-site"}, {"observed_at": NOW - timedelta(seconds=301)},
    {"observed_at": NOW + timedelta(seconds=1)}, {"expires_at": NOW - timedelta(seconds=1)},
    {"verdict": "unknown"},
])
def test_untrusted_stale_or_unbound_assessment_cannot_prepare(scenario_stack, changes):
    """惡意旗標本身不足以啟動 F；來源、時效、請求與環境都必須一致。"""
    stack = scenario_stack
    _, result = prepare(stack, assessment=assessment_for(stack["request"], **changes))
    assert result.decision == "unverifiable", result
    assert result.prepared is None and result.errors


def test_benign_assessment_is_not_applicable(scenario_stack):
    """可信正常流量不產生欺敵組合指令。"""
    stack = scenario_stack
    _, result = prepare(stack, assessment=assessment_for(stack["request"], verdict="benign"))
    assert result.decision == "not_applicable" and result.prepared is None


@pytest.mark.parametrize("changes", [
    {"method": "POST"}, {"body": b"changed"}, {"headers": (("host", "shop.test"), ("x-test", "changed"))},
    {"raw_url": "https://shop.test/api/products/other"}, {"query_string": b"a=1&a=2"},
])
def test_request_change_invalidates_prior_assessment(scenario_stack, changes):
    """同 request_id 的資料遭替換時，舊判定不可沿用。"""
    stack = scenario_stack
    changed = replace(stack["request"], **changes)
    _, result = prepare(stack, request=changed, assessment=assessment_for(stack["request"]))
    assert result.decision == "unverifiable" and result.prepared is None, result


@pytest.mark.parametrize("changes", [
    {"site_id": "other-site"}, {"platform_version": "2.0"}, {"spec_sha256": "0" * 64},
    {"operation_id": "otherOperation"}, {"path": "/other/{id}"}, {"method": "POST"},
])
def test_b_operation_identity_cannot_disagree_with_d_or_policy(scenario_stack, changes):
    """F 比對 B 的確切操作身份，不只使用平台名稱或 URL 前綴。"""
    stack = scenario_stack
    identity = stack["identified"].identity.model_copy(update=changes)
    identified = stack["identified"].model_copy(update={"identity": identity})
    _, result = prepare(stack, identified=identified)
    assert result.decision == "unverifiable" and result.prepared is None, result


def test_b_must_identify_the_same_request(scenario_stack):
    """拒絕沒有識別結果，以及另一個 request_id 的 B 結果。"""
    stack = scenario_stack
    for identified in (
        stack["identified"].model_copy(update={"decision": "unverifiable", "identity": None}),
        stack["identified"].model_copy(update={"request_id": "another-request"}),
    ):
        _, result = prepare(stack, identified=identified)
        assert result.decision == "unverifiable" and result.prepared is None, result


@pytest.mark.parametrize("part,changes", [
    ("source", {"platform_version": "2.0"}), ("source", {"spec_sha256": "0" * 64}),
    ("operation", {"operation_id": "otherOperation"}), ("operation", {"path": "/other/{id}"}),
    ("operation", {"method": "POST"}),
])
def test_d_context_must_match_b_exactly(scenario_stack, part, changes):
    """D 若來自不同版本、契約或操作，不能借用既有規則。"""
    stack = scenario_stack
    nested = getattr(stack["profile"], part).model_copy(update=changes)
    profile = stack["profile"].model_copy(update={part: nested})
    _, result = prepare(stack, profile=profile)
    assert result.decision == "unverifiable" and result.prepared is None, result


@pytest.mark.parametrize("field,value", [
    ("site_id", "other-site"), ("platform_version", "2.0"), ("spec_sha256", "0" * 64),
    ("scenario_id", "other-scenario"), ("run_id", "other-run"),
])
def test_resolution_rejects_dataset_from_another_scope(scenario_stack, field, value):
    """解析階段再次檢查 E 隔離身份，避免跨站點、版本、情境或 run 取值。"""
    stack = scenario_stack
    engine, preparation = prepare(stack)
    assert preparation.decision == "prepared", preparation
    scope = stack["scope"].model_copy(update={field: value})
    dataset = generate_dataset(stack["dataset"].config.model_copy(update={"scope": scope}))
    result = engine.resolve(preparation.prepared, dataset, now=NOW)
    assert result.decision == "unverifiable" and result.composition_plan is None, result


def test_resolution_rechecks_expiration(scenario_stack):
    """prepare 後排隊超過判定期限，也不可再選出回應。"""
    stack = scenario_stack
    engine, preparation = prepare(stack)
    assert preparation.decision == "prepared", preparation
    result = engine.resolve(preparation.prepared, stack["dataset"], now=NOW + timedelta(seconds=61))
    assert result.decision == "unverifiable" and result.composition_plan is None, result


@pytest.mark.parametrize("target", ["policy", "rule"])
def test_disabled_policy_or_rule_does_not_prepare(scenario_stack, target):
    """部署必須明確啟用規則；停用不能默默沿用原先的情境。"""
    policy_data = copy.deepcopy(scenario_stack["policy_data"])
    (policy_data if target == "policy" else policy_data["rules"][0])["enabled"] = False
    _, result = prepare(scenario_stack, policy_data=policy_data)
    assert result.decision == "not_applicable" and result.prepared is None, result


@pytest.mark.parametrize("decoding,outcome", [("raw", "missing"), ("percent_decode_once", "found")])
def test_percent_encoding_requires_explicit_decoding_policy(scenario_stack, decoding, outcome):
    """保留 B 的原始 path 參數；只有規則指定時才解碼一次。"""
    stack = scenario_stack
    product_id = stack["dataset"].products[0].id
    encoded = "%{:02X}".format(ord(product_id[0])) + product_id[1:]
    request = request_for(encoded)
    identified = stack["identifier"].identify_request(request, context=stack["runtime"])
    assert identified.decision == "identified", identified
    assert identified.identity.path_parameters["id"] == encoded
    policy_data = copy.deepcopy(stack["policy_data"])
    policy_data["rules"][0]["id_decoding"] = decoding
    engine, preparation = prepare(stack, request=request, identified=identified, policy_data=policy_data)
    assert preparation.decision == "prepared", preparation
    result = engine.resolve(preparation.prepared, stack["dataset"], now=NOW)
    assert result.decision == "selected" and result.outcome_id == outcome, result


def test_attack_type_rule_requires_an_explicit_matching_type(scenario_stack):
    """規則限定攻擊類型時，不把任何 malicious 判定都當成符合。"""
    stack = scenario_stack
    policy_data = copy.deepcopy(stack["policy_data"])
    policy_data["rules"][0]["attack_types"] = ["credential-stuffing"]
    _, result = prepare(stack, policy_data=policy_data,
                        assessment=assessment_for(stack["request"], attack_types=["sql-injection"]))
    assert result.decision == "not_applicable" and result.prepared is None, result


def test_preparation_does_not_approve_an_unreviewed_source(scenario_stack):
    """F 遵守來源審查狀態，不把規則啟用視為契約已核准。"""
    stack = scenario_stack
    source = stack["profile"].source.model_copy(update={"approved": False})
    profile = stack["profile"].model_copy(update={"source": source})
    _, result = prepare(stack, profile=profile)
    assert result.decision == "unverifiable" and result.prepared is None, result
    assert profile.source.approved is False


@pytest.mark.parametrize("reverse_order", [False, True])
def test_highest_priority_selection_is_independent_of_rule_order(scenario_stack, reverse_order):
    """優先權決定選擇；檔案排列順序不可以改變相同請求的情境。"""
    policy_data = copy.deepcopy(scenario_stack["policy_data"])
    high = dict(policy_data["rules"][0], rule_id="high-priority", priority=200, scenario_id="higher-priority")
    policy_data["rules"].append(high)
    if reverse_order:
        policy_data["rules"].reverse()
    _, result = prepare(scenario_stack, policy_data=policy_data)
    assert result.decision == "prepared", result
    assert result.prepared.rule_id == "high-priority"
    assert result.prepared.scope.scenario_id == "higher-priority"


def test_tied_matching_rules_are_ambiguous(scenario_stack):
    """最高優先權同時命中兩個規則時，拒絕用排列順序隨意選擇。"""
    policy_data = copy.deepcopy(scenario_stack["policy_data"])
    policy_data["rules"].append(dict(policy_data["rules"][0], rule_id="same-priority"))
    _, result = prepare(scenario_stack, policy_data=policy_data)
    assert result.decision == "unverifiable" and result.prepared is None, result


def test_tied_priorities_in_other_sites_do_not_make_matching_rule_ambiguous(scenario_stack):
    """不同站點可以使用相同 priority，只計算此次請求真正命中的規則。"""
    policy_data = copy.deepcopy(scenario_stack["policy_data"])
    policy_data["rules"].append(dict(policy_data["rules"][0], rule_id="other-site", site_id="other-site"))
    _, result = prepare(scenario_stack, policy_data=policy_data)
    assert result.decision == "prepared", result
    assert result.prepared.rule_id == "product-rule"


@pytest.mark.parametrize("changes", [
    {"domain_context": {"product_id": "prod-missing"}}, {"rule_id": "other-rule"}, {"request_id": "other-request"},
    {"seal": "0" * 64},
])
def test_tampered_preparation_cannot_resolve(scenario_stack, changes):
    """準備封套被改寫後，resolve 必須驗證 seal 而不是只信任可解析欄位。"""
    stack = scenario_stack
    engine, preparation = prepare(stack)
    assert preparation.decision == "prepared", preparation
    tampered = preparation.prepared.model_copy(update=changes)
    result = engine.resolve(tampered, stack["dataset"], now=NOW)
    assert result.decision == "unverifiable" and result.composition_plan is None, result


def test_preparation_belongs_to_the_issuing_engine(scenario_stack):
    """另一個同設定工具實例也不可直接接受不屬於自己的交接封套。"""
    stack = scenario_stack
    _, preparation = prepare(stack)
    assert preparation.decision == "prepared", preparation
    other_engine = ScenarioEngine(ScenarioPolicy.model_validate(stack["policy_data"]))
    result = other_engine.resolve(preparation.prepared, stack["dataset"], now=NOW)
    assert result.decision == "unverifiable" and result.composition_plan is None, result


def test_policy_loader_preserves_explicit_configuration(scenario_stack, tmp_path):
    """載入設定不會自行啟用其他平台或增加預設規則。"""
    path = tmp_path / "scenario-policy.yaml"
    path.write_text(yaml.safe_dump(scenario_stack["policy_data"]), encoding="utf-8")
    policy = load_policy(path)
    assert policy.model_dump() == ScenarioPolicy.model_validate(scenario_stack["policy_data"]).model_dump()


def test_policy_loader_rejects_duplicate_yaml_keys(tmp_path):
    """重複鍵不得採用最後一筆值，避免審查者看到的規則與載入結果不同。"""
    path = tmp_path / "duplicate-policy.yaml"
    path.write_text("schema_version: 1\nenabled: false\nenabled: true\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_policy(path)


@pytest.mark.parametrize("mutation", ["unknown-template", "missing-id-binding", "missing-product-binding",
                                      "nonexistent-target", "overlapping-target", "duplicate-rule-id"])
def test_invalid_template_or_rule_configuration_is_rejected(scenario_stack, mutation):
    """在接受請求前發現錯誤引用與映射，避免組合出錯誤商品或任意欄位。"""
    policy_data = copy.deepcopy(scenario_stack["policy_data"])
    if mutation == "unknown-template":
        policy_data["rules"][0]["found"]["template_id"] = "unknown"
    elif mutation == "missing-id-binding":
        policy_data["templates"][0]["bindings"] = [dict(source_field="title", target_pointer="/product/title")]
    elif mutation == "missing-product-binding":
        policy_data["templates"][1]["bindings"] = [dict(source_field="id", target_pointer="/message")]
    elif mutation == "nonexistent-target":
        policy_data["templates"][0]["bindings"][1]["target_pointer"] = "/product/nonexistent"
    elif mutation == "overlapping-target":
        policy_data["templates"][0]["bindings"].append(dict(source_field="title", target_pointer="/product"))
    else:
        policy_data["rules"].append(copy.deepcopy(policy_data["rules"][0]))
    with pytest.raises(ValueError):
        ScenarioEngine(ScenarioPolicy.model_validate(policy_data))


def test_absent_assessment_never_activates_scenario(scenario_stack):
    """沒有外部偵測判定時，F 不從請求內容自行猜測惡意流量。"""
    stack = scenario_stack
    engine = ScenarioEngine(ScenarioPolicy.model_validate(stack["policy_data"]))
    result = engine.prepare(stack["request"], stack["identified"], stack["profile"], None,
                            run_id="run-a", now=NOW)
    assert result.decision == "unverifiable" and result.prepared is None, result


def test_assessment_expiration_boundary_is_rejected(scenario_stack):
    """expires_at 是不含端點的截止時間，恰好到期也不可使用。"""
    stack = scenario_stack
    _, result = prepare(stack, assessment=assessment_for(stack["request"], expires_at=NOW))
    assert result.decision == "unverifiable" and result.prepared is None, result


@pytest.mark.parametrize("age,decision", [
    (timedelta(seconds=300), "unverifiable"),
    (timedelta(seconds=300) - timedelta(microseconds=1), "prepared"),
])
def test_assessment_maximum_age_is_an_exclusive_deadline(scenario_stack, age, decision):
    """最大判定年齡與 expires_at 共用不含端點的截止語義。"""
    stack = scenario_stack
    _, result = prepare(stack, assessment=assessment_for(stack["request"], observed_at=NOW - age))
    assert result.decision == decision, result


@pytest.mark.parametrize("changes", [
    {"path_parameters": {"id": "prod-other"}}, {"query": {"fields": ["id"]}},
])
def test_b_parameters_must_still_describe_the_original_request(scenario_stack, changes):
    """B 封套若只改參數但保留操作身份，F 仍須與 A 的原始 URL 交叉核對。"""
    stack = scenario_stack
    identity = stack["identified"].identity.model_copy(update=changes)
    identified = stack["identified"].model_copy(update={"identity": identity})
    _, result = prepare(stack, identified=identified)
    assert result.decision == "unverifiable" and result.prepared is None, result


def test_percent_decoding_rejects_invalid_utf8(scenario_stack):
    """一次解碼使用嚴格 UTF-8，不把無效位元組替換後繼續查商品。"""
    stack = scenario_stack
    request = request_for("%FF")
    identified = stack["identifier"].identify_request(request, context=stack["runtime"])
    assert identified.decision == "identified", identified
    policy_data = copy.deepcopy(stack["policy_data"])
    policy_data["rules"][0]["id_decoding"] = "percent_decode_once"
    _, result = prepare(stack, request=request, identified=identified, policy_data=policy_data)
    assert result.decision == "unverifiable" and result.prepared is None, result


def test_percent_decoding_does_not_decode_twice(scenario_stack):
    """雙重編碼不應在一次解碼規則中變成已存在商品。"""
    stack = scenario_stack
    product_id = stack["dataset"].products[0].id
    encoded_twice = "%25{:02X}".format(ord(product_id[0])) + product_id[1:]
    request = request_for(encoded_twice)
    identified = stack["identifier"].identify_request(request, context=stack["runtime"])
    assert identified.decision == "identified", identified
    policy_data = copy.deepcopy(stack["policy_data"])
    policy_data["rules"][0]["id_decoding"] = "percent_decode_once"
    engine, preparation = prepare(stack, request=request, identified=identified, policy_data=policy_data)
    assert preparation.decision == "prepared", preparation
    assert preparation.prepared.domain_context["product_id"] != product_id
    result = engine.resolve(preparation.prepared, stack["dataset"], now=NOW)
    assert result.decision == "selected" and result.outcome_id == "missing", result


def test_resolution_rejects_a_changed_product_even_if_types_are_valid(scenario_stack):
    """只改文字仍通過模型型別，但不再是 E 的可重現資料，F 必須拒絕。"""
    stack = scenario_stack
    engine, preparation = prepare(stack)
    assert preparation.decision == "prepared", preparation
    changed = stack["dataset"].model_copy(deep=True)
    changed.products[0].title = "Changed after E verification"
    result = engine.resolve(preparation.prepared, changed, now=NOW)
    assert result.decision == "unverifiable" and result.composition_plan is None, result


def test_engine_does_not_share_the_callers_mutable_policy(scenario_stack):
    """呼叫者修改原政策模型，不可以在工具運作中偷偷變更既有規則。"""
    stack = scenario_stack
    policy = ScenarioPolicy.model_validate(stack["policy_data"])
    engine = ScenarioEngine(policy)
    policy.rules[0].scenario_id = "changed-by-caller"
    policy.templates[0].body["product"]["title"] = "Changed by caller"
    result = engine.prepare(stack["request"], stack["identified"], stack["profile"], assessment_for(stack["request"]),
                            run_id="run-a", now=NOW)
    assert result.decision == "prepared", result
    assert result.prepared.scope == stack["scope"]


@pytest.mark.parametrize("outcome", ["found", "missing"])
def test_selected_template_still_requires_h_contract_preflight(scenario_stack, outcome):
    """F 的 selected 只代表選擇成功；模板違反 schema 必須在 H 被拒絕。"""
    stack = scenario_stack
    policy_data = copy.deepcopy(stack["policy_data"])
    template_index = 0 if outcome == "found" else 1
    policy_data["templates"][template_index]["body"]["unexpected"] = "not allowed by the contract"
    request = request_for(stack["dataset"].products[0].id if outcome == "found" else "prod-missing")
    identified = stack["identifier"].identify_request(request, context=stack["runtime"])
    engine, preparation = prepare(stack, request=request, identified=identified, policy_data=policy_data)
    assert preparation.decision == "prepared", preparation
    result = engine.resolve(preparation.prepared, stack["dataset"], now=NOW)
    assert result.decision == "selected" and result.outcome_id == outcome, result
    with pytest.raises(CompositionError) as error:
        ResponseComposer(stack["output"]).compose(result.composition_plan, dataset=stack["dataset"])
    assert error.value.code == "contract_mismatch"


def test_repeated_lookup_keeps_same_product_after_a_missing_lookup(scenario_stack):
    """同一工具與 E 快照交替查詢，不會因 missing 分支消耗亂數或變更商品。"""
    stack = scenario_stack
    engine = ScenarioEngine(ScenarioPolicy.model_validate(stack["policy_data"]))
    before = stack["dataset"].model_dump_json()
    snapshots = []
    product = stack["dataset"].products[1]
    for number, product_id in enumerate((product.id, "prod-missing", product.id)):
        request = request_for(product_id, request_id=f"lookup-{number}")
        identified = stack["identifier"].identify_request(request, context=stack["runtime"])
        preparation = engine.prepare(request, identified, stack["profile"], assessment_for(request),
                                     run_id="run-a", now=NOW)
        assert preparation.decision == "prepared", preparation
        result = engine.resolve(preparation.prepared, stack["dataset"], now=NOW)
        assert result.decision == "selected", result
        assert result.composition_plan.scope == stack["scope"]
        candidate = ResponseComposer(stack["output"]).compose(result.composition_plan, dataset=stack["dataset"])
        assert verify_candidate(candidate, OfficialResponseGate(stack["registry"]), request.raw_url).valid is True
        snapshots.append((result.outcome_id, candidate.body))
    assert [snapshot[0] for snapshot in snapshots] == ["found", "missing", "found"]
    assert snapshots[0] == snapshots[2]
    assert json.loads(snapshots[2][1]) == {"product": {"id": product.id, "title": product.title}}
    assert stack["dataset"].model_dump_json() == before


def test_resolution_and_trace_are_reproducible_without_sharing_mutable_plans(scenario_stack):
    """相同快照產生相同決策摘要，修改前次輸出也不能污染後續計畫。"""
    stack = scenario_stack
    engine, preparation = prepare(stack)
    assert preparation.decision == "prepared", preparation
    first = engine.resolve(preparation.prepared, stack["dataset"], now=NOW)
    assert first.decision == "selected", first
    expected_plan = first.composition_plan.model_dump()
    expected_trace = copy.deepcopy(first.trace)
    first.composition_plan.body["product"]["title"] = "Caller changed the first result"
    second = engine.resolve(preparation.prepared, stack["dataset"], now=NOW)
    assert second.decision == "selected", second
    assert second.composition_plan.model_dump() == expected_plan
    assert second.trace == expected_trace
    other_engine, other_preparation = prepare(stack)
    assert other_preparation.decision == "prepared", other_preparation
    other = other_engine.resolve(other_preparation.prepared, stack["dataset"], now=NOW)
    assert other.decision == "selected", other
    assert other.trace["decision_id"] == second.trace["decision_id"]


def test_policy_digest_is_read_only_and_tracks_the_actual_snapshot(scenario_stack):
    """公開政策摘要不可偽造；準備封套與追溯資料必須指向實際政策快照。"""
    stack = scenario_stack
    policy = ScenarioPolicy.model_validate(stack["policy_data"])
    # 獨立依公開的固定 JSON 格式計算摘要，不重用引擎的私有雜湊函式。
    encoded = json.dumps(policy.model_dump(mode="json"), ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    expected_digest = hashlib.sha256(encoded).hexdigest()
    engine = ScenarioEngine(policy)
    assert engine.policy_sha256 == expected_digest
    with pytest.raises(AttributeError):
        engine.policy_sha256 = "0" * 64
    preparation = engine.prepare(stack["request"], stack["identified"], stack["profile"],
                                 assessment_for(stack["request"]), run_id="run-a", now=NOW)
    assert preparation.decision == "prepared", preparation
    assert preparation.prepared.policy_sha256 == expected_digest
    result = engine.resolve(preparation.prepared, stack["dataset"], now=NOW)
    assert result.decision == "selected", result
    assert result.trace["policy_sha256"] == engine.policy_sha256 == expected_digest


def test_repository_policy_example_is_valid_and_disabled_by_default():
    """隨附政策範本可由正式載入器解析，並保留明確停用的預設值。"""
    root = Path(__file__).resolve().parents[1]
    policy = load_policy(root / "domains" / "ecommerce" / "inputs" / "policies" / "deception.yaml")
    assert isinstance(policy, ScenarioPolicy)
    assert policy.enabled is False
