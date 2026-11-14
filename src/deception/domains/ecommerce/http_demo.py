"""隔離電商展示服務：用明確的模擬判定串接完整生成／備援／驗證／HTTP 回送。"""

import hashlib
import os
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import FastAPI
from pydantic import Field, field_validator

from deception.core import ResponseComposer
from deception.core.orchestrator import DeceptionOrchestrator
from deception.core.recovery import REQUEST_ENTITY_ID_TOKEN, RecoveryPolicy, RecoveryTool
from deception.discovery import BindingConfig, DeploymentBinding, PlatformIdentifier, RuntimeContext
from deception.generation import ContentCache, ContentGenerator
from .generation_demo import _bytes, _policies, _specification
from deception.generation.models import digest
from deception.llm import LLMConfig, PydanticAIBackend
from deception.profile_builder import ProfileTool, build_profile
from deception.profile_builder.builder import read_yaml
from deception.scenarios import AttackAssessment, ScenarioEngine, fingerprint_request
from deception.common.models import SLUG, DatasetScope, SyntheticModel
from .synthetic import SyntheticConfig, generate_dataset
from mirage_validator.gate import OfficialResponseGate, PlatformRegistry
from mirage_validator.request_matching import base_identity
from deception.security import load_catalog
from .weaknesses import configure_policies, configure_specification

from deception.api.pipeline import make_pipeline_handler
from deception.api.app import create_app as create_ingress_app


class DemoConfig(SyntheticModel):
    """只設定隔離合成服務；不能藉此核准正式平台或建立可信遠端偵測來源。"""

    schema_version: Literal[1] = 1
    domain: Literal["ecommerce"] = "ecommerce"
    origin: str = "http://127.0.0.1:8000"
    mode: Literal["fallback", "local"] = "fallback"
    seed: int = Field(default=20261109, ge=0, le=2**32 - 1)
    product_count: int = Field(default=2, ge=2, le=10)
    run_id: str = Field(default="isolated-demo", pattern=SLUG)
    weakness_scenario: str | None = Field(default=None, pattern=SLUG)
    fallback_description: str = Field(default="This is a reviewed synthetic demonstration product.", min_length=10, max_length=120)
    fallback_missing_message: str = Field(default="Entity with requested id {request_entity_id} was not found.", min_length=10, max_length=120)

    @field_validator("origin")
    @classmethod
    def check_origin(cls, value):
        """只接受明確 HTTP origin，拒絕帳密、query、fragment 或路徑前綴。"""
        parsed = urlsplit(value)
        base_identity(value)
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError("The demonstration origin must not contain a path, query or fragment")
        return value.rstrip("/")


class TemplateOnlyBackend:
    """明確停用模型，讓管理者核准的固定備援走完整驗證；不冒充模型推論。"""

    async def check_ready(self, budget):
        """確認共用期限後回報模型刻意停用，使協調器選取明確備援。"""
        budget.check()
        raise ValueError("Model execution is explicitly disabled for the isolated fallback demonstration")

    async def aclose(self):
        """此模式不建立模型連線，提供與真模型相同的關閉介面。"""


class _ObservedPipeline:
    """僅在隔離展示保留有上限的結果摘要，區分真模型、快取與明確備援。"""

    def __init__(self, pipeline, history):
        """使用原協調器及 gate，紀錄容器驗證需要的固定追溯欄位。"""
        self.pipeline, self.history, self.gate = pipeline, history, pipeline.gate

    async def run(self, request, assessment, **kwargs):
        """沿用完整協調器，不保存訪客 body／headers／路徑或模型提示。"""
        result = await self.pipeline.run(request, assessment, **kwargs)
        generation = result.trace.get("generation", {})
        source = ("fallback" if generation.get("source") == "fallback" else
                  "cache" if generation.get("cache_hit") else "model") if result.decision == "validated" else None
        self.history.append({"request_id": request.request_id, "decision": result.decision,
                             "status_code": result.candidate.status_code if result.candidate else None,
                             "generation_source": source, "model": result.trace.get("model"),
                             "usage": result.trace.get("usage", {})})
        return result


def load_demo_config(path: Path) -> DemoConfig:
    """讀管理者 YAML 並套用明確的展示環境設定；不讀取訪客 HTTP 欄位。"""
    value = read_yaml(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("The demonstration configuration must be an object")
    overrides = {key: os.environ[name] for key, name in (
        ("origin", "MIRAGE_DEMO_ORIGIN"), ("mode", "MIRAGE_DEMO_MODE")) if name in os.environ}
    return DemoConfig.model_validate({**value, **overrides})


def _recovery_policy(config, scenarios, generator) -> RecoveryPolicy:
    """只為本次合成契約建立同結果固定值，綁定情境與生成政策的完整摘要。"""
    rules = []
    for rule in generator.policy.rules:
        selector = rule.model_dump(mode="json", exclude={"rule_id", "fields", "protected_pointers"})
        field = rule.fields[0].field_id
        if rule.outcome_id == "found":
            value = config.fallback_description
        else:
            value = config.fallback_missing_message.rstrip(".")
            if REQUEST_ENTITY_ID_TOKEN not in value:
                value += f" (requested id: {REQUEST_ENTITY_ID_TOKEN})"
            value += "."
        rules.append({**selector, "rule_id": "reviewed-" + rule.outcome_id, "generation_rule_id": rule.rule_id,
                      "generation_policy_sha256": generator.policy_sha256,
                      "scenario_policy_sha256": scenarios.policy_sha256, "values": {field: value}})
    return RecoveryPolicy(domain=config.domain, policy_id="isolated-demo-recovery", policy_version="1",
                          enabled=True, rules=rules)


def create_app(config: DemoConfig | None = None, *, output_root: Path | None = None, config_path: Path | None = None,
               weakness_catalog: Path | None = None) -> FastAPI:
    """建立可由 Docker 啟動的完整展示 app；輸入只有管理者設定，所有契約核准均限合成目錄。

    每次啟動建立獨立輸出目錄，保留固定種子資料與生成內容快取；不改 repo 的來源核准。
    模擬判定將每個目標請求標為測試攻擊，只驗證處理流程，不提供實際攻擊偵測或來源認證。
    """
    if config is None:
        config = load_demo_config(Path(os.environ.get("MIRAGE_DEMO_CONFIG") or config_path or "domains/ecommerce/configs/demo.yaml"))
    else:
        config = DemoConfig.model_validate(config.model_dump(mode="json"))
    selected_weakness = None
    if config.weakness_scenario is not None:
        catalog_path = weakness_catalog or Path("domains/ecommerce/security/owasp-scenarios.yaml")
        catalog = load_catalog(catalog_path, domain=config.domain,
                               taxonomy_root=Path(os.environ.get("MIRAGE_SECURITY_TAXONOMIES_DIR", "inputs/security_taxonomies")))
        selected_weakness = catalog.select(config.weakness_scenario)
    specification = _specification()
    configure_specification(specification, selected_weakness)
    output = Path(os.environ.get("MIRAGE_DEMO_OUTPUT", "generated/domains/ecommerce")) if output_root is None else Path(output_root)
    run_root = output / uuid4().hex
    directory = run_root / "contracts" / "synthetic-store"
    directory.mkdir(parents=True)
    specification["info"]["title"] = "Isolated synthetic ecommerce demonstration"
    raw = _bytes(specification)
    source = dict(platform_id="synthetic-store", platform_version="1.0",
                  source_url="https://example.invalid/isolated-synthetic-contract",
                  source_revision="synthetic-contract-v1", spec_sha256=hashlib.sha256(raw).hexdigest(),
                  approved=True, openapi_file="openapi.yaml")
    (directory / "openapi.yaml").write_bytes(raw)
    (directory / "source.yaml").write_bytes(_bytes(source))
    (directory / "manifest.yaml").write_bytes(_bytes({**source, "base_urls": [config.origin + "/api"], "query_contexts": [{}]}))
    profiles = run_root
    build_profile(directory / "source.yaml", profiles)
    scope = DatasetScope(site_id="demo-store", platform_id=source["platform_id"], platform_version=source["platform_version"],
                         spec_sha256=source["spec_sha256"], scenario_id="product-lookup", run_id=config.run_id)
    data_config = SyntheticConfig(scope=scope, seed=config.seed, product_count=config.product_count, variants_per_product=1)
    dataset = generate_dataset(data_config)
    (run_root / "dataset.json").write_bytes(_bytes(dataset.model_dump(mode="json")))
    runtime = RuntimeContext(environment_id="isolated-demo", deployment_id="isolated-demo", service_id="synthetic-store")
    scenario_policy, generation_policy = _policies(scope, runtime)
    configure_policies(scenario_policy, generation_policy, selected_weakness)
    scenario_policy = type(scenario_policy).model_validate(scenario_policy.model_dump(mode="json"))
    generation_policy = type(generation_policy).model_validate(generation_policy.model_dump(mode="json"))
    scenarios = ScenarioEngine(scenario_policy, domain=config.domain)
    registry = PlatformRegistry(directory.parent)
    binding = DeploymentBinding(**runtime.model_dump(), binding_id="isolated-demo", site_id=scope.site_id,
                                platform_id=scope.platform_id, platform_version=scope.platform_version,
                                spec_sha256=scope.spec_sha256, base_url=config.origin + "/api", enabled=True)
    if config.mode == "local":
        llm_config = LLMConfig.model_validate(read_yaml(Path(os.environ.get("MIRAGE_LLM_CONFIG", "configs/llm.yaml")).read_bytes()))
        if llm_config.execution_mode != "local":
            raise ValueError("The local demonstration mode requires a real local model configuration")
        backend = PydanticAIBackend(llm_config)
    else:
        backend = TemplateOnlyBackend()
    cache = ContentCache(run_root / "content.sqlite3")
    generator = ContentGenerator(generation_policy, backend, cache=cache)
    recovery_policy = _recovery_policy(config, scenarios, generator)
    pipeline = DeceptionOrchestrator(
        identifier=PlatformIdentifier(registry, BindingConfig(bindings=[binding])), profiles=ProfileTool(profiles),
        scenarios=scenarios, generator=generator, composer=ResponseComposer(profiles), gate=OfficialResponseGate(registry),
        recovery=RecoveryTool(recovery_policy))
    (run_root / "scenario-policy.json").write_bytes(_bytes(scenario_policy.model_dump(mode="json")))
    (run_root / "generation-policy.json").write_bytes(_bytes(generation_policy.model_dump(mode="json")))
    (run_root / "recovery-policy.json").write_bytes(_bytes(recovery_policy.model_dump(mode="json")))

    def simulated_assessment(request):
        """為隔離展示明確產生模擬惡意判定，不信任訪客自稱來源、verdict 或環境標頭。"""
        now = datetime.now(timezone.utc)
        return AttackAssessment(assessment_id=uuid4().hex, source_id="local-demo-detector",
                                request_id=request.request_id, request_fingerprint=fingerprint_request(request),
                                **runtime.model_dump(), site_id=scope.site_id, verdict="malicious",
                                observed_at=now - timedelta(seconds=1), expires_at=now + timedelta(seconds=600))

    history = deque(maxlen=64)
    handler = make_pipeline_handler(_ObservedPipeline(pipeline, history), runtime=runtime, generation_config=data_config,
                                    dataset=dataset, assessment_provider=simulated_assessment)

    @asynccontextmanager
    async def lifespan(app):
        """應用程式停止時關閉自有模型連線與 SQLite；不刪除本次可檢查產物。"""
        try:
            yield
        finally:
            await backend.aclose()
            cache.close()

    app = FastAPI(title="Mirage isolated ecommerce demonstration", docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=lifespan, redirect_slashes=False)

    @app.get("/healthz", include_in_schema=False)
    async def health():
        """提供獨立容器健康診斷；不是商品契約回應，也不宣稱模型已可用。"""
        return {"status": "ok", "test_only": True, "mode": config.mode}

    @app.get("/demo/info", include_in_schema=False)
    async def information():
        """僅公開合成測試身份、商品資料及快照摘要，方便呼叫及一致性檢查。"""
        return {"test_only": True, "assessment_mode": "simulated_malicious", "domain": config.domain, "mode": config.mode,
                "product_ids": [product.id for product in dataset.products], "product_path_template": "/api/products/{id}",
                "products": [{"id": product.id, "title": product.title} for product in dataset.products],
                "dataset_sha256": digest(dataset.model_dump(mode="json")), "transactions_supported": False,
                "recent_results": list(history),
                "security_scenario": None if selected_weakness is None else {
                    "scenario_id": selected_weakness.scenario_id,
                    "categories": [reference.model_dump(mode="json") for reference in selected_weakness.categories]}}

    app.mount("/", create_ingress_app(handler))
    return app
