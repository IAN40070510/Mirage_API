"""G 的生成白名單與 J 上下文；模型只輸出 field_id 對應的 JSON 值。"""

import hashlib
import json
from typing import Literal

from pydantic import Field, JsonValue, model_validator

from deception.core.models import CompositionPlan
from deception.llm.models import RunLimits
from deception.synthetic.models import SLUG, DatasetScope, SyntheticModel

from .pointers import tokens as pointer_tokens


def digest(value) -> str:
    """統一政策、上下文及生成內容的固定 JSON 摘要。"""
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


class GenerationField(SyntheticModel):
    """可生成欄位由管理者定義；entity 快取的實體引用來自 F 封存的 context。"""

    field_id: str = Field(pattern=SLUG)
    target_pointer: str
    instruction: str = Field(min_length=1, max_length=1000)
    cache_scope: Literal["entity", "request"] = "request"
    entity_pointer: str | None = None

    @model_validator(mode="after")
    def check_pointers(self):
        """拒絕根層替換及沒有明確實體引用的 entity 快取。"""
        pointer_tokens(self.target_pointer)
        if self.cache_scope == "entity":
            if self.entity_pointer is None:
                raise ValueError("Entity caching requires an explicit domain context pointer")
            pointer_tokens(self.entity_pointer)
        elif self.entity_pointer is not None:
            raise ValueError("Request fields must not supply an entity pointer")
        return self


class GenerationRule(SyntheticModel):
    """精確選定契約分支；保護欄位及 F 的 E 映射都不能與生成目標重疊。"""

    rule_id: str = Field(pattern=SLUG)
    platform_id: str = Field(pattern=SLUG)
    platform_version: str
    spec_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation_id: str
    method: str = Field(pattern=r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$")
    path: str = Field(pattern=r"^/")
    outcome_id: str = Field(pattern=SLUG)
    status_code: int = Field(ge=200, le=599)
    media_type: Literal["application/json"] = "application/json"
    protected_pointers: list[str] = Field(default_factory=list, max_length=128)
    fields: list[GenerationField] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def check_fields(self):
        """生成欄位不可重複、互為父子，或覆寫政策明列的權威資料。"""
        if len({f.field_id for f in self.fields}) != len(self.fields):
            raise ValueError("Generated field IDs must be unique per rule")
        # 同一組內容原子發布，故首版只允許同一快取範圍與同一實體來源。
        # 混合 request/entity 會讓請求指紋改變時連 entity 描述都重新生成。
        if len({(f.cache_scope, f.entity_pointer) for f in self.fields}) != 1:
            raise ValueError("Fields in one rule must share their cache scope and entity pointer")
        targets = []
        protected = [pointer_tokens(value) for value in self.protected_pointers]
        for field in self.fields:
            tokens = pointer_tokens(field.target_pointer)
            if any(tokens[:len(other)] == other or other[:len(tokens)] == tokens for other in targets + protected):
                raise ValueError("Generated and protected targets must not overlap")
            targets.append(tokens)
        return self


class GenerationPolicy(SyntheticModel):
    """C/G 政策獨立於 E 的種子設定；同一政策可對不同平台 operation 明確配置。"""

    schema_version: Literal[1] = 1
    domain: str = Field(pattern=SLUG)
    policy_id: str = Field(pattern=SLUG)
    policy_version: str = Field(min_length=1, max_length=128)
    prompt_version: str = Field(default="1", min_length=1, max_length=128)
    enabled: bool = False
    limits: RunLimits = Field(default_factory=RunLimits)
    rules: list[GenerationRule] = Field(default_factory=list, max_length=256)

    @model_validator(mode="after")
    def check_unique(self):
        """重複 rule ID 拒絕載入；多條命中在執行時也會被拒絕。"""
        if len({r.rule_id for r in self.rules}) != len(self.rules):
            raise ValueError("Generation rule IDs must be unique")
        return self


class GenerationIntent(SyntheticModel):
    """C 模型的生成提議；只可選已公開的 field ID，不能提交指標或改 HTTP 狀態。"""

    field_ids: list[str] = Field(min_length=1, max_length=16)
    instructions: str = Field(default="", max_length=1000)


class GenerationContext(SyntheticModel):
    """J：C 從已核對工具結果建置，原始 body、Cookie、Authorization 不放入模型 context。"""

    domain: str = Field(pattern=SLUG)
    request_id: str
    request_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    environment_id: str
    deployment_id: str
    service_id: str
    scope: DatasetScope
    operation_id: str
    outcome_id: str
    scenario_decision_id: str
    scenario_policy_sha256: str
    generation_policy_sha256: str
    data_namespace: str
    state_sha256: str
    domain_context: dict[str, JsonValue]
    model_identity: dict[str, JsonValue]

    @property
    def context_id(self) -> str:
        """每次請求的追溯身份；不作跨請求實體快取鍵。"""
        return digest(self.model_dump(mode="json"))


class GeneratedContent(SyntheticModel):
    """G 暫存結果；只有 C 經 H/I 驗證後才可發布至內容快取。"""

    plan: CompositionPlan
    values: dict[str, JsonValue]
    cache_key: str
    cache_hit: bool
    trace: dict[str, JsonValue] = Field(default_factory=dict)
