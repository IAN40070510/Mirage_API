"""F 的白名單政策與兩階段結果；情境選擇不等於 I 已放行。"""

import re
from datetime import datetime, timezone
from typing import Literal

from pydantic import AwareDatetime, Field, JsonValue, field_validator, model_validator

from deception.core.models import CompositionPlan
from deception.synthetic.models import SLUG, DatasetScope, SyntheticModel


def pointer_tokens(pointer: str) -> tuple[str, ...]:
    """只允許指向既有位置的 RFC 6901 Pointer，不接受 fragment 或錯誤 escape。"""
    if not pointer.startswith("/") or re.search(r"~(?![01])", pointer):
        raise ValueError("A non-root JSON Pointer is required")
    return tuple(token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/"))


def template_value(body, tokens: tuple[str, ...]):
    """驗證模板的目標確實存在；陣列 index 不接受負值、前導零或 append。"""
    for token in tokens:
        if isinstance(body, list):
            if not re.fullmatch(r"0|[1-9][0-9]*", token):
                raise ValueError("Invalid template array index")
            body = body[int(token)]
        elif isinstance(body, dict):
            body = body[token]
        else:
            raise ValueError("Template pointer traverses a scalar")
    return body


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


class TemplateBinding(SyntheticModel):
    """僅開放 E 商品的四個文字欄位，不執行任意表達式或讀取設定資料。"""

    source_field: Literal["id", "title", "handle", "status"]
    target_pointer: str

    @field_validator("target_pointer")
    @classmethod
    def valid_pointer(cls, value):
        """在政策載入時拒絕無效 Pointer，避免延後到組合階段才發現拼寫錯誤。"""
        pointer_tokens(value)
        return value


class ResponseTemplate(SyntheticModel):
    """管理者明確寫出的 JSON 模板；F 只選模板，H 才填值與驗證契約。"""

    template_id: str = Field(pattern=SLUG)
    headers: dict[str, str] = Field(default_factory=dict)
    body: JsonValue = Field(...)
    bindings: list[TemplateBinding] = Field(default_factory=list, max_length=64)

    @model_validator(mode="after")
    def check_targets(self):
        """提前拒絕不存在、重複及父子重疊的映射位置。"""
        targets = []
        for binding in self.bindings:
            tokens = pointer_tokens(binding.target_pointer)
            if any(tokens[:len(other)] == other or other[:len(tokens)] == tokens for other in targets):
                raise ValueError("Template binding targets must not overlap")
            try:
                template_value(self.body, tokens)
            except (LookupError, TypeError) as exc:
                raise ValueError("Template binding target does not exist") from exc
            targets.append(tokens)
        return self


class OutcomeDefinition(SyntheticModel):
    """明確狀態、媒體及模板，不從攻擊文字推測回應內容。"""

    status_code: int = Field(ge=200, le=599)
    media_type: Literal["application/json"] = "application/json"
    template_id: str = Field(pattern=SLUG)


class ScenarioRule(SyntheticModel):
    """首版規則只涵蓋 GET 商品明細，精確綁定部署／操作及允許的 query。"""

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
    method: Literal["GET"] = "GET"
    path: str = Field(pattern=r"^/")
    scenario_id: str = Field(pattern=SLUG)
    attack_types: list[str] = Field(default_factory=list, max_length=64)
    query_contexts: list[dict[str, list[str]]] = Field(default_factory=lambda: [{}], min_length=1, max_length=64)
    id_parameter: str = Field(default="id", min_length=1)
    id_decoding: Literal["raw", "percent_decode_once"] = "raw"
    product_id_target: str = "/product/id"
    found: OutcomeDefinition
    missing: OutcomeDefinition

    @model_validator(mode="after")
    def check_lookup(self):
        """固定 200／404 分支，且商品 ID 必須來自明確的 path parameter。"""
        if self.found.status_code != 200 or self.missing.status_code != 404:
            raise ValueError("Product lookup requires found=200 and missing=404")
        if "{" + self.id_parameter + "}" not in self.path:
            raise ValueError("id_parameter must exist in the path template")
        pointer_tokens(self.product_id_target)
        return self


class ScenarioPolicy(SyntheticModel):
    """管理者維護的固定白名單；不下載規則、不執行 Python／LLM 表達式。"""

    schema_version: Literal[1] = 1
    policy_id: str = Field(pattern=SLUG)
    policy_version: str = Field(min_length=1, max_length=128)
    enabled: bool = False
    trusted_sources: list[str] = Field(default_factory=list, max_length=64)
    max_age_seconds: int = Field(default=300, ge=1, le=3600)
    rules: list[ScenarioRule] = Field(default_factory=list, max_length=256)
    templates: list[ResponseTemplate] = Field(default_factory=list, max_length=256)

    @model_validator(mode="after")
    def check_references(self):
        """拒絕重複 ID、錯誤模板引用及會回傳錯誤商品 ID 的 found 模板。"""
        if len({r.rule_id for r in self.rules}) != len(self.rules):
            raise ValueError("rule_id must be unique")
        templates = {t.template_id: t for t in self.templates}
        if len(templates) != len(self.templates):
            raise ValueError("template_id must be unique")
        if len(set(self.trusted_sources)) != len(self.trusted_sources):
            raise ValueError("trusted_sources must be unique")
        for rule in self.rules:
            if rule.found.template_id not in templates or rule.missing.template_id not in templates:
                raise ValueError("Rule references an unknown template")
            found, missing = templates[rule.found.template_id], templates[rule.missing.template_id]
            if not any(b.source_field == "id" and b.target_pointer == rule.product_id_target for b in found.bindings):
                raise ValueError("Found template must bind the selected E product ID")
            if missing.bindings:
                raise ValueError("Missing product templates must not bind a product")
        return self


class ScenarioIssue(SyntheticModel):
    """不回顯憑證、body、URL 或攻擊文字的失敗原因。"""

    code: str
    reason: str


class PreparedScenario(SyntheticModel):
    """同引擎實例內封存的選擇依據；seal 防止兩階段交接時被修改。"""

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
    method: Literal["GET"]
    path: str
    product_id: str
    valid_from: AwareDatetime
    valid_until: AwareDatetime
    offline_preview: bool
    seal: str = Field(repr=False)


class ScenarioPreparation(SyntheticModel):
    """第一階段只回固定 family scope；可據此建立／讀取同一份 E 資料。"""

    decision: Literal["prepared", "not_applicable", "unverifiable"]
    prepared: PreparedScenario | None = None
    errors: list[ScenarioIssue] = Field(default_factory=list)


class ScenarioDecision(SyntheticModel):
    """第二階段提供給 H 的計畫與追溯資料；selected 並非 gate pass。"""

    decision: Literal["selected", "unverifiable"]
    outcome_id: Literal["found", "missing"] | None = None
    composition_plan: CompositionPlan | None = None
    trace: dict[str, JsonValue] = Field(default_factory=dict)
    errors: list[ScenarioIssue] = Field(default_factory=list)
