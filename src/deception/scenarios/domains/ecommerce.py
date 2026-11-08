"""電商領域：商品 GET 查詢、E 快照驗證與 200／404 模板規則。"""

import hashlib
import json
import re
from typing import Literal
from urllib.parse import unquote

from pydantic import Field, field_validator, model_validator

from deception.core.models import CompositionPlan, DataBinding
from deception.synthetic.generator import checked_dataset
from deception.synthetic.models import SLUG, SyntheticModel
from mirage_validator.request_matching import deref

from ..models import (DomainOutcome, DomainPolicy, ResponseTemplateBase, ScenarioRuleBase)


def pointer_tokens(pointer: str) -> tuple[str, ...]:
    """僅接受非根層 RFC 6901 Pointer，不接受 fragment 或錯誤 escape。"""
    if not pointer.startswith("/") or re.search(r"~(?![01])", pointer):
        raise ValueError("A non-root JSON Pointer is required")
    return tuple(token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/"))


def template_value(body, tokens: tuple[str, ...]):
    """確認目標存在；陣列 index 不接受負值、前導零或 append。"""
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


class TemplateBinding(SyntheticModel):
    """電商商品的四個文字欄位白名單，不執行任意表達式或讀取設定。"""

    source_field: Literal["id", "title", "handle", "status"]
    target_pointer: str

    @field_validator("target_pointer")
    @classmethod
    def valid_pointer(cls, value):
        """載入政策時檢查 Pointer，避免將錯誤映射交給 H。"""
        pointer_tokens(value)
        return value


class ResponseTemplate(ResponseTemplateBase):
    """電商 JSON 模板，只有明確指定的商品欄位可由 H 填入。"""

    bindings: list[TemplateBinding] = Field(default_factory=list, max_length=64)

    @model_validator(mode="after")
    def check_targets(self):
        """拒絕不存在、重複及父子重疊的映射位置。"""
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
    """電商分支的明確狀態、媒體及模板。"""

    status_code: int = Field(ge=200, le=599)
    media_type: Literal["application/json"] = "application/json"
    template_id: str = Field(pattern=SLUG)


class ScenarioRule(ScenarioRuleBase):
    """電商首版支援 GET 商品明細，不把商品欄位強加到其他領域。"""

    method: Literal["GET"] = "GET"
    id_parameter: str = Field(default="id", min_length=1)
    id_decoding: Literal["raw", "percent_decode_once"] = "raw"
    product_id_target: str = "/product/id"
    found: OutcomeDefinition
    missing: OutcomeDefinition

    @model_validator(mode="after")
    def check_lookup(self):
        """固定電商查詢的 200／404，商品 ID 必須來自明確 path parameter。"""
        if self.found.status_code != 200 or self.missing.status_code != 404:
            raise ValueError("Product lookup requires found=200 and missing=404")
        if "{" + self.id_parameter + "}" not in self.path:
            raise ValueError("id_parameter must exist in the path template")
        pointer_tokens(self.product_id_target)
        return self


class ScenarioPolicy(DomainPolicy):
    """電商政策；舊公開類別名稱保留，但現在必須明確選擇 domain。"""

    domain: Literal["ecommerce"]
    rules: list[ScenarioRule] = Field(default_factory=list, max_length=256)
    templates: list[ResponseTemplate] = Field(default_factory=list, max_length=256)

    @model_validator(mode="after")
    def check_references(self):
        """檢查電商模板引用，found 必須映射真實 E 商品 ID，missing 不可映射商品。"""
        templates = {t.template_id: t for t in self.templates}
        for rule in self.rules:
            if rule.found.template_id not in templates or rule.missing.template_id not in templates:
                raise ValueError("Rule references an unknown template")
            found, missing = templates[rule.found.template_id], templates[rule.missing.template_id]
            if not any(b.source_field == "id" and b.target_pointer == rule.product_id_target for b in found.bindings):
                raise ValueError("Found template must bind the selected E product ID")
            if missing.bindings:
                raise ValueError("Missing product templates must not bind a product")
        return self


class EcommerceDomain:
    """封裝電商業務；共用引擎只透過領域介面呼叫，不自行查商品。"""

    domain_id = "ecommerce"
    policy_type = ScenarioPolicy

    def prepare(self, rule, identity, profile, operation):
        """確認兩個分支有 JSON schema，再依明確政策擷取／解碼商品 ID。"""
        responses = operation.get("responses", {})
        for outcome in (rule.found, rule.missing):
            status = outcome.status_code
            response = responses.get(str(status), responses.get(f"{status // 100}XX", responses.get("default")))
            response = deref(profile.specification, response)
            content = response.get("content", {}) if isinstance(response, dict) else {}
            media = content.get(outcome.media_type, content.get("application/*", content.get("*/*")))
            if not isinstance(media, dict) or "schema" not in media or media["schema"] is False:
                raise ValueError("Product lookup outcome requires a usable response schema")
        product_id = identity.path_parameters.get(rule.id_parameter)
        if not product_id:
            raise ValueError("Request has no product ID for this policy")
        if rule.id_decoding == "percent_decode_once":
            product_id = unquote(product_id, errors="strict")
        return {"product_id": product_id}

    def resolve(self, policy, rule, prepared, data):
        """驗證同一份 E 快照，選 found／missing 並建立電商映射，不修改狀態。"""
        checked = checked_dataset(data, data.config)
        if checked.config.scope != prepared.scope:
            raise ValueError("E dataset does not match the prepared scope")
        product_index = next((index for index, product in enumerate(checked.products)
                              if product.id == prepared.domain_context["product_id"]), None)
        outcome_id = "found" if product_index is not None else "missing"
        outcome = rule.found if outcome_id == "found" else rule.missing
        template = next(template for template in policy.templates if template.template_id == outcome.template_id)
        bindings = [DataBinding(source_pointer=f"/products/{product_index}/{binding.source_field}",
                                target_pointer=binding.target_pointer) for binding in template.bindings]
        plan = CompositionPlan(scope=prepared.scope, method=prepared.method, path=prepared.path,
                               status_code=outcome.status_code, media_type=outcome.media_type,
                               headers=template.headers, body=template.body, bindings=bindings)
        raw = json.dumps(checked.model_dump(mode="json"), ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
        return DomainOutcome(outcome_id=outcome_id, composition_plan=plan, template_id=template.template_id,
                             data_namespace=checked.namespace, state_sha256=hashlib.sha256(raw).hexdigest(),
                             reason_code="product_exists" if outcome_id == "found" else "product_absent")
