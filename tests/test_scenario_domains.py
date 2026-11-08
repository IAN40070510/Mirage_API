"""F 領域選擇回歸：電商可明選，其他領域由已註冊的處理器獨立執行。"""

import copy
import hashlib
import json
from pathlib import Path

import pytest
import yaml
from pydantic import model_validator

from deception.api.ingress import NormalizedRequest
from deception.core import CompositionPlan, ResponseComposer, verify_candidate
from deception.discovery import BindingConfig, DeploymentBinding, PlatformIdentifier, RuntimeContext
from deception.profile_builder import ProfileTool, build_profile
from deception.scenarios import (DomainOutcome, DomainPolicy, DomainRegistry, ScenarioEngine,
                                 ScenarioPolicy, ScenarioRuleBase, default_registry, load_policy)
from mirage_validator.gate import OfficialResponseGate, PlatformRegistry

from test_scenarios import NOW, assessment_for, scenario_stack


class HelpdeskRule(ScenarioRuleBase):
    """擴充領域自己的參數欄位，不需要商品查詢的 id_parameter 或 found/missing。"""

    ticket_parameter: str


class HelpdeskPolicy(DomainPolicy):
    """測試專用政策型別，確認引擎快照仍使用已註冊的領域模型解析。"""

    rules: list[HelpdeskRule]
    reply_status: str


class HelpdeskHandler:
    """測試用非電商處理器，讀取工單資料，完全不依賴 E 的商品或變體欄位。"""

    domain_id = "helpdesk"
    policy_type = HelpdeskPolicy

    def __init__(self):
        """為測試處理器建立獨立呼叫紀錄，供派送順序及次數斷言使用。"""
        self.calls = []

    def prepare(self, rule, identity, profile, operation):
        """只取受 B 核對的工單參數，並保留呼叫紀錄以確認實際派送。"""
        self.calls.append("prepare")
        assert isinstance(rule, HelpdeskRule)
        return {"ticket_id": identity.path_parameters[rule.ticket_parameter]}

    def resolve(self, policy, rule, prepared, data):
        """以普通工單 dict 產生 POST／201 計畫，不讓核心引擎強制讀取 products。"""
        self.calls.append("resolve")
        assert isinstance(data, dict)
        assert isinstance(policy, HelpdeskPolicy)
        assert data["ticket_id"] == prepared.domain_context["ticket_id"]
        template = policy.templates[0]
        assert data["status"] == policy.reply_status
        body = {"ticket": {"id": data["ticket_id"], "status": policy.reply_status}}
        plan = CompositionPlan(scope=prepared.scope, method=prepared.method, path=prepared.path,
                               status_code=201, headers=template.headers, body=body)
        state = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return DomainOutcome(outcome_id="ticket-created", composition_plan=plan,
                             template_id=template.template_id, data_namespace="1" * 64,
                             state_sha256=hashlib.sha256(state).hexdigest(), reason_code="ticket_created")


@pytest.fixture
def helpdesk_stack(tmp_path):
    """非電商測試契約包含不同路徑、方法及實體，仍經真實 B、D、H、I。"""
    schema = {"type": "object", "required": ["ticket"], "additionalProperties": False,
              "properties": {"ticket": {"type": "object", "required": ["id", "status"],
                                         "additionalProperties": False,
                                         "properties": {"id": {"type": "string"},
                                                        "status": {"type": "string", "enum": ["open"]}}}}}
    spec = {"openapi": "3.1.0", "info": {"title": "Noncommerce extension test", "version": "1.0"},
            "paths": {"/tickets/{ticket_id}": {"post": {"operationId": "createTicket", "parameters": [
                {"name": "ticket_id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"201": {"description": "Synthetic ticket created", "content": {
                    "application/json": {"schema": schema}}}}}}}}
    raw = yaml.safe_dump(spec).encode("utf-8")
    source = dict(platform_id="synthetic-helpdesk", platform_version="1.0",
                  source_url="https://example.invalid/helpdesk-test", source_revision="test-only",
                  spec_sha256=hashlib.sha256(raw).hexdigest(), openapi_file="openapi.yaml", approved=True)
    directory = tmp_path / "contracts" / "synthetic-helpdesk"
    directory.mkdir(parents=True)
    (directory / "openapi.yaml").write_bytes(raw)
    (directory / "source.yaml").write_text(yaml.safe_dump(source), encoding="utf-8")
    manifest = dict(source, base_urls=["https://shop.test/api"], query_contexts=[{}])
    (directory / "manifest.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    registry = PlatformRegistry(tmp_path / "contracts")
    runtime = RuntimeContext(environment_id="test-env", deployment_id="test-deploy", service_id="store")
    binding = DeploymentBinding(**runtime.model_dump(), binding_id="helpdesk-test", site_id="shop-test",
                                base_url="https://shop.test/api", platform_id=source["platform_id"],
                                platform_version="1.0", spec_sha256=source["spec_sha256"], enabled=True)
    identifier = PlatformIdentifier(registry, BindingConfig(bindings=[binding]))
    path = "/api/tickets/ticket-001"
    request = NormalizedRequest(request_id="helpdesk-request-001", method="POST", raw_url="https://shop.test" + path,
                                path=path, raw_path=path.encode("ascii"), query_string=b"", query=(),
                                headers=(("host", "shop.test"),), body=b"")
    identified = identifier.identify_request(request, context=runtime)
    assert identified.decision == "identified", identified
    output = tmp_path / "generated"
    build_profile(directory / "source.yaml", output)
    profile = ProfileTool(output).get_operation(**identified.identity.profile_arguments())
    rule = dict(rule_id="ticket-rule", priority=10, enabled=True, **runtime.model_dump(), site_id="shop-test",
                platform_id=source["platform_id"], platform_version="1.0", spec_sha256=source["spec_sha256"],
                operation_id="createTicket", method="POST", path="/tickets/{ticket_id}", scenario_id="ticket-reply",
                ticket_parameter="ticket_id")
    policy_data = dict(schema_version=1, domain="helpdesk", policy_id="helpdesk-policy", policy_version="1",
                       enabled=True, trusted_sources=["detector"], rules=[rule],
                       templates=[dict(template_id="ticket-response", body={"ticket": {"id": "", "status": "open"}})],
                       reply_status="open")
    return dict(policy_data=policy_data, request=request, identified=identified, profile=profile, output=output,
                gate=OfficialResponseGate(registry), data={"ticket_id": "ticket-001", "status": "open"})


def test_ecommerce_is_a_selectable_registered_domain(scenario_stack):
    """選定電商後仍能依 E 選到正確商品，並維持 F→H→I 的真實交接。"""
    stack = scenario_stack
    engine = ScenarioEngine(ScenarioPolicy.model_validate(stack["policy_data"]), domain="ecommerce")
    assert engine.domain_id == "ecommerce"
    preparation = engine.prepare(stack["request"], stack["identified"], stack["profile"],
                                 assessment_for(stack["request"]), run_id="run-a", now=NOW)
    assert preparation.decision == "prepared", preparation
    assert preparation.prepared.domain == "ecommerce"
    assert preparation.prepared.domain_context["product_id"] == stack["dataset"].products[0].id
    decision = engine.resolve(preparation.prepared, stack["dataset"], now=NOW)
    assert decision.decision == "selected" and decision.outcome_id == "found", decision
    assert decision.trace["domain"] == "ecommerce"
    candidate = ResponseComposer(stack["output"]).compose(decision.composition_plan, dataset=stack["dataset"])
    result = verify_candidate(candidate, OfficialResponseGate(stack["registry"]), stack["request"].raw_url)
    assert result.valid is True and result.decision == "pass", result


def test_policy_domain_is_an_explicit_required_selection(scenario_stack):
    """政策必須指出領域，不讓舊格式靜默套用電商的商品邏輯。"""
    policy_data = copy.deepcopy(scenario_stack["policy_data"])
    policy_data.pop("domain")
    with pytest.raises(ValueError):
        ScenarioPolicy.model_validate(policy_data)


def test_unknown_or_conflicting_domain_never_falls_back_to_ecommerce(scenario_stack):
    """執行端選擇不同領域或尚未註冊的領域時，拒絕建立引擎。"""
    policy = ScenarioPolicy.model_validate(scenario_stack["policy_data"])
    for domain in ("unknown-domain", "helpdesk"):
        with pytest.raises(ValueError):
            ScenarioEngine(policy, domain=domain)
    registry = default_registry()
    registry.register(HelpdeskHandler())
    with pytest.raises(ValueError):
        ScenarioEngine(policy, domain="helpdesk", registry=registry)


def test_registry_reports_domains_and_rejects_duplicates():
    """註冊表以明確 ID 選處理器，重複定義不能依載入順序蓋掉前者。"""
    registry = default_registry()
    assert registry.domain_ids() == ("ecommerce",)
    handler = HelpdeskHandler()
    registry.register(handler)
    assert registry.domain_ids() == ("ecommerce", "helpdesk")
    assert registry.get("helpdesk") is handler
    with pytest.raises(ValueError):
        registry.get("unknown-domain")
    with pytest.raises(ValueError):
        registry.register(HelpdeskHandler())
    assert default_registry().domain_ids() == ("ecommerce",)


def test_noncommerce_handler_runs_without_product_models_and_passes_h_i(helpdesk_stack):
    """新領域可用非商品資料、非 GET 方法及自己的結果分支，不修改 F 核心。"""
    stack = helpdesk_stack
    handler = HelpdeskHandler()
    registry = DomainRegistry([handler])
    engine = ScenarioEngine(HelpdeskPolicy.model_validate(stack["policy_data"]), registry=registry)
    assert engine.domain_id == "helpdesk"
    preparation = engine.prepare(stack["request"], stack["identified"], stack["profile"],
                                 assessment_for(stack["request"]), run_id="run-a", now=NOW)
    assert preparation.decision == "prepared", preparation
    assert preparation.prepared.domain == "helpdesk"
    assert preparation.prepared.domain_context == {"ticket_id": "ticket-001"}
    decision = engine.resolve(preparation.prepared, stack["data"], now=NOW)
    assert decision.decision == "selected" and decision.outcome_id == "ticket-created", decision
    assert decision.trace["domain"] == "helpdesk"
    assert handler.calls == ["prepare", "resolve"]
    candidate = ResponseComposer(stack["output"]).compose(decision.composition_plan)
    assert json.loads(candidate.body) == {"ticket": {"id": "ticket-001", "status": "open"}}
    result = verify_candidate(candidate, stack["gate"], stack["request"].raw_url)
    assert result.valid is True and result.decision == "pass", result


def test_prepared_domain_is_sealed_against_cross_domain_reuse(scenario_stack):
    """即使其他欄位都相同，改寫 prepared 的 domain 也不能套用電商資料。"""
    stack = scenario_stack
    engine = ScenarioEngine(ScenarioPolicy.model_validate(stack["policy_data"]))
    preparation = engine.prepare(stack["request"], stack["identified"], stack["profile"],
                                 assessment_for(stack["request"]), run_id="run-a", now=NOW)
    assert preparation.decision == "prepared", preparation
    changed = preparation.prepared.model_copy(update={"domain": "helpdesk"})
    result = engine.resolve(changed, stack["dataset"], now=NOW)
    assert result.decision == "unverifiable" and result.composition_plan is None, result


def test_prepare_handler_cannot_mutate_the_verified_scope_or_original_b_input(helpdesk_stack):
    """處理器改寫收到的身份及規則，只影響自己的副本，不能污染核心已核對的 scope。"""
    class MutatingPrepareHandler(HelpdeskHandler):
        def prepare(self, rule, identity, profile, operation):
            """取得有效工單 ID 後，模擬擴充程式意外改寫部署與 family。"""
            context = super().prepare(rule, identity, profile, operation)
            identity.site_id = "other-site"
            rule.scenario_id = "other-family"
            return context

    stack = helpdesk_stack
    before_identity = stack["identified"].model_dump(mode="json")
    engine = ScenarioEngine(HelpdeskPolicy.model_validate(stack["policy_data"]),
                            registry=DomainRegistry([MutatingPrepareHandler()]))
    preparation = engine.prepare(stack["request"], stack["identified"], stack["profile"],
                                 assessment_for(stack["request"]), run_id="run-a", now=NOW)
    assert preparation.decision == "prepared", preparation
    assert preparation.prepared.scope.site_id == "shop-test"
    assert preparation.prepared.scope.scenario_id == "ticket-reply"
    assert stack["identified"].model_dump(mode="json") == before_identity
    assert engine.resolve(preparation.prepared, stack["data"], now=NOW).decision == "selected"


def test_resolve_handler_cannot_rewrite_the_prepared_comparison_baseline(helpdesk_stack):
    """改 prepared 再照改過的 scope 回計畫，仍須相對原始封套身份拒絕。"""
    class MutatingResolveHandler(HelpdeskHandler):
        def resolve(self, policy, rule, prepared, data):
            """模擬 callback 同時改寫準備身份與輸出，避免相同參考造成錯誤放行。"""
            prepared.scope.run_id = "other-run"
            return super().resolve(policy, rule, prepared, data)

    stack = helpdesk_stack
    engine = ScenarioEngine(HelpdeskPolicy.model_validate(stack["policy_data"]),
                            registry=DomainRegistry([MutatingResolveHandler()]))
    preparation = engine.prepare(stack["request"], stack["identified"], stack["profile"],
                                 assessment_for(stack["request"]), run_id="run-a", now=NOW)
    assert preparation.decision == "prepared", preparation
    before_prepared = preparation.prepared.model_dump_json()
    result = engine.resolve(preparation.prepared, stack["data"], now=NOW)
    assert result.decision == "unverifiable" and result.composition_plan is None, result
    assert preparation.prepared.model_dump_json() == before_prepared


def test_policy_validator_cannot_switch_the_selected_domain(helpdesk_stack, tmp_path):
    """領域政策的自訂 validator 也不能把 YAML／原模型指定的領域改成另一個。"""
    class DomainChangingPolicy(HelpdeskPolicy):
        @model_validator(mode="after")
        def switch_domain(self):
            """模擬錯誤的擴充政策驗證器，在型別驗證後改變領域欄位。"""
            self.domain = "other-domain"
            return self

    class DomainChangingHandler(HelpdeskHandler):
        policy_type = DomainChangingPolicy

    registry = DomainRegistry([DomainChangingHandler()])
    path = tmp_path / "domain-changing-policy.yaml"
    path.write_text(yaml.safe_dump(helpdesk_stack["policy_data"]), encoding="utf-8")
    with pytest.raises(ValueError):
        load_policy(path, registry=registry)
    original = HelpdeskPolicy.model_validate(helpdesk_stack["policy_data"])
    with pytest.raises(ValueError):
        ScenarioEngine(original, registry=registry)
    assert original.domain == "helpdesk"


@pytest.mark.parametrize("change", ["scope", "method", "path"])
def test_registered_handler_cannot_change_the_prepared_request_identity(helpdesk_stack, change):
    """領域處理器也不能把回應計畫改成另一個 run、方法或操作路徑。"""
    class WrongPlanHandler(HelpdeskHandler):
        def resolve(self, policy, rule, prepared, data):
            """回傳結構合法但身份錯誤的計畫，讓共用核心驗證交接邊界。"""
            outcome = super().resolve(policy, rule, prepared, data)
            plan = outcome.composition_plan
            if change == "scope":
                plan = plan.model_copy(update={"scope": plan.scope.model_copy(update={"run_id": "other-run"})})
            elif change == "method":
                plan = plan.model_copy(update={"method": "GET"})
            else:
                plan = plan.model_copy(update={"path": "/other/{ticket_id}"})
            return DomainOutcome(outcome_id=outcome.outcome_id, composition_plan=plan,
                                 template_id=outcome.template_id, data_namespace=outcome.data_namespace,
                                 state_sha256=outcome.state_sha256, reason_code=outcome.reason_code)

    stack = helpdesk_stack
    engine = ScenarioEngine(HelpdeskPolicy.model_validate(stack["policy_data"]),
                            registry=DomainRegistry([WrongPlanHandler()]))
    preparation = engine.prepare(stack["request"], stack["identified"], stack["profile"],
                                 assessment_for(stack["request"]), run_id="run-a", now=NOW)
    assert preparation.decision == "prepared", preparation
    result = engine.resolve(preparation.prepared, stack["data"], now=NOW)
    assert result.decision == "unverifiable" and result.composition_plan is None, result


def test_engine_domain_cannot_be_reassigned(scenario_stack):
    """公開領域選擇為唯讀，避免 prepare／resolve 之間被切成另一個處理器。"""
    engine = ScenarioEngine(ScenarioPolicy.model_validate(scenario_stack["policy_data"]))
    with pytest.raises(AttributeError):
        engine.domain_id = "helpdesk"
    assert engine.domain_id == "ecommerce"


def test_load_policy_uses_registry_to_parse_the_selected_domain(helpdesk_stack, tmp_path):
    """同一安全 YAML 讀取器可依選定領域載入政策，不強迫工單填商品欄位。"""
    path = tmp_path / "helpdesk-policy.yaml"
    path.write_text(yaml.safe_dump(helpdesk_stack["policy_data"]), encoding="utf-8")
    registry = DomainRegistry([HelpdeskHandler()])
    policy = load_policy(path, domain="helpdesk", registry=registry)
    assert isinstance(policy, HelpdeskPolicy)
    assert policy.domain == "helpdesk" and policy.rules[0].method == "POST"
    assert policy.reply_status == "open" and policy.rules[0].ticket_parameter == "ticket_id"
    with pytest.raises(ValueError):
        load_policy(path)
    with pytest.raises(ValueError):
        load_policy(path, domain="ecommerce", registry=registry)


def test_default_policy_explicitly_selects_ecommerce():
    """可交付的政策範本清楚標示電商，並維持原本停用的審查邊界。"""
    path = Path(__file__).resolve().parents[1] / "inputs" / "policies" / "deception.yaml"
    policy = load_policy(path)
    assert policy.domain == "ecommerce"
    assert policy.enabled is False
