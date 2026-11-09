"""F 共用的領域政策與兩階段封套；業務模型由各領域自行定義。"""

from datetime import datetime, timezone
from typing import Literal

from pydantic import AwareDatetime, Field, JsonValue, field_validator, model_validator

from deception.core.models import CompositionPlan
from deception.common.models import SLUG, DatasetScope, SyntheticModel


class AttackAssessment(SyntheticModel):
    """整合層驗證來源後提供的判定；source_id 自稱或白名單都不是驗簽。"""

    assessment_id: str = Field(pattern=SLUG)
    source_id: str = Field(pattern=SLUG)
    request_id: str = Field(min_length=1, max_length=128)
    request_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    environment_id: str = Field(pattern=SLUG)
    deployment_id: str = Field(pattern=SLUG)
    service_id: str = Field(pattern=SLUG)
    site_id: str = Field(pattern=SLUG)
    verdict: Literal["malicious", "benign", "unknown"]
    attack_types: list[str] = Field(default_factory=list, max_length=64)
    observed_at: AwareDatetime
    expires_at: AwareDatetime

    @field_validator("observed_at", "expires_at")
    @classmethod
    def utc_time(cls, value: datetime) -> datetime:
        """統一為 UTC，避免同一時刻使用不同時區而產生不同追溯身份。"""
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def check_times(self):
        """過期時間必須晚於觀察時間，實際時效由可注入時鐘的引擎檢查。"""
        if self.expires_at <= self.observed_at:
            raise ValueError("expires_at must be later than observed_at")
        return self


class ResponseTemplateBase(SyntheticModel):
    """共用的明確 JSON 模板；各領域再增加自己的受限資料映射。"""

    template_id: str = Field(pattern=SLUG)
    headers: dict[str, str] = Field(default_factory=dict)
    body: JsonValue = Field(...)


class ScenarioRuleBase(SyntheticModel):
    """所有領域共用的部署、契約、操作與條件，不包含商品或訂單假設。"""

    rule_id: str = Field(pattern=SLUG)
    priority: int = Field(default=0, ge=-10000, le=10000)
    enabled: bool = True
    environment_id: str = Field(pattern=SLUG)
    deployment_id: str = Field(pattern=SLUG)
    service_id: str = Field(pattern=SLUG)
    site_id: str = Field(pattern=SLUG)
    platform_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    platform_version: str = Field(min_length=1, max_length=128)
    spec_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation_id: str = Field(min_length=1)
    method: str = Field(pattern=r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$")
    path: str = Field(pattern=r"^/")
    scenario_id: str = Field(pattern=SLUG)
    attack_types: list[str] = Field(default_factory=list, max_length=64)
    query_contexts: list[dict[str, list[str]]] = Field(default_factory=lambda: [{}], min_length=1, max_length=64)


class DomainPolicy(SyntheticModel):
    """明確選擇領域的共用政策；領域子類別提供嚴格的規則與模板模型。"""

    schema_version: Literal[1] = 1
    domain: str = Field(pattern=SLUG)
    policy_id: str = Field(pattern=SLUG)
    policy_version: str = Field(min_length=1, max_length=128)
    enabled: bool = False
    trusted_sources: list[str] = Field(default_factory=list, max_length=64)
    max_age_seconds: int = Field(default=300, ge=1, le=3600)
    rules: list[ScenarioRuleBase] = Field(default_factory=list, max_length=256)
    templates: list[ResponseTemplateBase] = Field(default_factory=list, max_length=256)

    @model_validator(mode="after")
    def check_identifiers(self):
        """所有領域都拒絕重複 ID，避免規則或模板因排列順序被覆寫。"""
        for values in ([r.rule_id for r in self.rules], [t.template_id for t in self.templates], self.trusted_sources):
            if len(values) != len(set(values)):
                raise ValueError("Rule, template and trusted source IDs must be unique")
        return self


class ScenarioIssue(SyntheticModel):
    """不回顯憑證、body、URL 或攻擊文字的失敗原因。"""

    code: str
    reason: str


class PreparedScenario(SyntheticModel):
    """同引擎實例內封存的依據；seal 同時綁定領域及領域專用選擇資料。"""

    domain: str = Field(pattern=SLUG)
    preparation_id: str
    policy_sha256: str
    rule_id: str
    scope: DatasetScope
    request_id: str
    request_fingerprint: str
    assessment_id: str
    assessment_source: str
    environment_id: str
    deployment_id: str
    service_id: str
    operation_id: str
    method: str = Field(pattern=r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$")
    path: str
    domain_context: dict[str, JsonValue]
    valid_from: AwareDatetime
    valid_until: AwareDatetime
    offline_preview: bool
    seal: str = Field(repr=False)


class ScenarioPreparation(SyntheticModel):
    """第一階段回固定 family scope，交由選定領域建立／讀取對應資料。"""

    decision: Literal["prepared", "not_applicable", "unverifiable"]
    prepared: PreparedScenario | None = None
    errors: list[ScenarioIssue] = Field(default_factory=list)


class DomainOutcome(SyntheticModel):
    """處理器提供通用計畫及資料事實；結果名稱由領域定義，不限 found/missing。"""

    outcome_id: str = Field(pattern=SLUG)
    composition_plan: CompositionPlan
    template_id: str = Field(pattern=SLUG)
    data_namespace: str = Field(min_length=1)
    state_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason_code: str = Field(pattern=SLUG)


class ScenarioDecision(SyntheticModel):
    """第二階段提供給 H 的計畫與追溯資料；selected 並非 gate pass。"""

    decision: Literal["selected", "unverifiable"]
    outcome_id: str | None = Field(default=None, pattern=SLUG)
    composition_plan: CompositionPlan | None = None
    trace: dict[str, JsonValue] = Field(default_factory=dict)
    errors: list[ScenarioIssue] = Field(default_factory=list)
