"""以非電商工單驗證整個共用流程，資料映射不依賴商品或變體模型。"""

import asyncio
import copy
import hashlib
import json

from deception.api.ingress import NormalizedRequest
from deception.common.data import CompositionData
from deception.common.models import DatasetScope, SyntheticModel
from deception.core import CompositionPlan, DataBinding, ResponseComposer
from deception.core.orchestrator import DeceptionOrchestrator
from deception.core.renderer import ResponseRenderer
from deception.discovery import BindingConfig, DeploymentBinding, PlatformIdentifier, RuntimeContext
from deception.generation import ContentGenerator, GenerationPolicy
from deception.generation.models import digest
from deception.profile_builder import ProfileTool, build_profile
from deception.scenarios import DomainOutcome, DomainPolicy, DomainRegistry, ScenarioEngine, ScenarioRuleBase
from mirage_validator.gate import OfficialResponseGate, PlatformRegistry

from test_generation import function_backend
from test_scenarios import NOW, assessment_for


class TicketRule(ScenarioRuleBase):
    """測試領域只使用工單路徑參數，沒有商品存在／不存在的分支。"""

    ticket_parameter: str = "ticket_id"


class TicketPolicy(DomainPolicy):
    """工單自己的政策型別，沿用共用信任與唯一規則檢查。"""

    rules: list[TicketRule]


class TicketConfig(SyntheticModel):
    """資料供應器只要求自己的隔離 scope，不使用電商生成設定。"""

    scope: DatasetScope


class TicketProvider:
    """將領域驗證過的工單資料投影為通用 JSON payload。"""

    def __init__(self, scope):
        """固定本次測試的資料隔離身份，不在請求間保存可變業務狀態。"""
        self.scope = scope.model_copy(deep=True)

    def load(self, config, data, expected_scope):
        """核對本領域設定與資料型態後回獨立複本，避免借用其他 run 的資料。"""
        checked = TicketConfig.model_validate(config.model_dump(mode="json"))
        if checked.scope != expected_scope or expected_scope != self.scope:
            raise ValueError("Ticket data scope does not match")
        if data != {"id": "ticket-001", "state": "open"}:
            raise ValueError("Unexpected synthetic ticket data")
        return copy.deepcopy(data)

    def facts(self, data, plan):
        """僅提供已核對的工單 ID 及狀態，不把原始請求放入模型。"""
        return {"ticket_id": data["id"], "state": data["state"]}

    def composition_data(self, data):
        """提供工單根節點的通用映射，不需要 products 或 variants。"""
        return CompositionData(scope=self.scope, payload={"tickets": [copy.deepcopy(data)]})


class TicketHandler:
    """測試用領域處理器，驗證可使用不同實體、方法、狀態及映射根節點。"""

    domain_id = "helpdesk"
    policy_type = TicketPolicy

    def prepare(self, rule, identity, profile, operation):
        """將已識別的工單 ID 放入封存上下文，不自行讀取 HTTP 標頭。"""
        return {"ticket_id": identity.path_parameters[rule.ticket_parameter]}

    def resolve(self, policy, rule, prepared, data):
        """依虛構工單狀態產生 201 計畫，ID／狀態皆由通用資料映射帶入。"""
        if data["id"] != prepared.domain_context["ticket_id"]:
            raise ValueError("Ticket identity changed")
        plan = CompositionPlan(scope=prepared.scope, method=prepared.method, path=prepared.path, status_code=201,
                               body={"ticket": {"id": "", "state": "", "note": ""}}, bindings=[
                                   DataBinding(source_pointer="/tickets/0/id", target_pointer="/ticket/id"),
                                   DataBinding(source_pointer="/tickets/0/state", target_pointer="/ticket/state")])
        return DomainOutcome(outcome_id="created", composition_plan=plan, template_id="ticket-created",
                             data_namespace="1" * 64, state_sha256=digest(data), reason_code="ticket_created")


def test_noncommerce_domain_runs_full_generation_mapping_validation_and_rendering(tmp_path):
    """非電商領域通過完整協調、模型生成、通用資料映射、契約驗證及最終回送。"""
    response_schema = {"type": "object", "required": ["ticket"], "additionalProperties": False,
                       "properties": {"ticket": {"type": "object", "required": ["id", "state", "note"],
                                                  "additionalProperties": False, "properties": {
                           "id": {"type": "string"}, "state": {"type": "string", "enum": ["open"]},
                           "note": {"type": "string", "minLength": 10, "maxLength": 120}}}}}
    specification = {"openapi": "3.1.0", "info": {"title": "Isolated ticket contract", "version": "1.0"},
                     "paths": {"/tickets/{ticket_id}": {"post": {"operationId": "createTicket", "parameters": [
                         {"name": "ticket_id", "in": "path", "required": True, "schema": {"type": "string"}}],
                         "responses": {"201": {"description": "Synthetic ticket reply", "content": {
                             "application/json": {"schema": response_schema}}}}}}}}
    raw = json.dumps(specification, sort_keys=True).encode("utf-8")
    source = {"platform_id": "ticket-service", "platform_version": "1.0", "spec_sha256": hashlib.sha256(raw).hexdigest(),
              "source_url": "https://example.invalid/ticket-test", "source_revision": "isolated-ticket-v1",
              "approved": True, "openapi_file": "openapi.yaml"}
    directory = tmp_path / "contracts/tickets"
    directory.mkdir(parents=True)
    (directory / "openapi.yaml").write_bytes(raw)
    (directory / "source.yaml").write_text(json.dumps(source), encoding="utf-8")
    (directory / "manifest.yaml").write_text(json.dumps({**source, "base_urls": ["https://shop.test/api"], "query_contexts": [{}]}), encoding="utf-8")
    output = tmp_path / "generated"
    build_profile(directory / "source.yaml", output)
    runtime = RuntimeContext(environment_id="test-env", deployment_id="test-deploy", service_id="store")
    scope = DatasetScope(site_id="shop-test", platform_id=source["platform_id"], platform_version="1.0",
                         spec_sha256=source["spec_sha256"], scenario_id="ticket-response", run_id="helpdesk-run")
    registry = PlatformRegistry(directory.parent)
    binding = DeploymentBinding(**runtime.model_dump(), site_id=scope.site_id, binding_id="ticket-service",
                                platform_id=scope.platform_id, platform_version=scope.platform_version,
                                spec_sha256=scope.spec_sha256, base_url="https://shop.test/api", enabled=True)
    common = {"platform_id": scope.platform_id, "platform_version": scope.platform_version,
              "spec_sha256": scope.spec_sha256, "operation_id": "createTicket", "method": "POST", "path": "/tickets/{ticket_id}"}
    scenario_policy = TicketPolicy(domain="helpdesk", policy_id="ticket-policy", policy_version="1", enabled=True,
                                   trusted_sources=["detector"], rules=[{**common, **runtime.model_dump(), "site_id": scope.site_id,
                                       "rule_id": "ticket-rule", "scenario_id": scope.scenario_id}],
                                   templates=[{"template_id": "ticket-created", "body": {"ticket": {"id": "", "state": "", "note": ""}}}])
    backend, calls = function_backend(field_id="note", value="Your synthetic support ticket is open.")
    generation_policy = GenerationPolicy(domain="helpdesk", policy_id="ticket-content", policy_version="1", enabled=True,
                                         rules=[{**common, "rule_id": "ticket-note", "outcome_id": "created", "status_code": 201,
                                                 "protected_pointers": ["/ticket/id", "/ticket/state"], "fields": [
                                                     {"field_id": "note", "target_pointer": "/ticket/note", "instruction": "Write a short ticket note."}]}])
    generator = ContentGenerator(generation_policy, backend)
    pipeline = DeceptionOrchestrator(
        identifier=PlatformIdentifier(registry, BindingConfig(bindings=[binding])), profiles=ProfileTool(output),
        scenarios=ScenarioEngine(scenario_policy, domain="helpdesk", registry=DomainRegistry([TicketHandler()])),
        generator=generator, composer=ResponseComposer(output), gate=OfficialResponseGate(registry),
        data_provider=TicketProvider(scope))
    request = NormalizedRequest(request_id="ticket-run", method="POST", raw_url="https://shop.test/api/tickets/ticket-001",
                                path="/api/tickets/ticket-001", raw_path=b"/api/tickets/ticket-001", query_string=b"", query=(),
                                headers=(("host", "shop.test"),), body=b"{}")
    result = asyncio.run(pipeline.run(request, assessment_for(request), runtime=runtime,
                                     generation_config=TicketConfig(scope=scope), dataset={"id": "ticket-001", "state": "open"}, now=NOW))
    assert result.decision == "validated", result
    rendered = ResponseRenderer(pipeline.gate).render(result, request)
    assert rendered.status_code == 201 and rendered.gate_result.valid is True
    assert json.loads(rendered.body) == {"ticket": {"id": "ticket-001", "state": "open", "note": "Your synthetic support ticket is open."}}
    assert result.trace["domain"] == "helpdesk" and calls["generator"]
    generator.cache.close()
