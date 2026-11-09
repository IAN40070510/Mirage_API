"""電商專用弱點回應模擬；只修改已宣告的合成模板，不執行 SQL、shell 或外部 URL。"""

from pydantic import Field

from deception.common.models import SyntheticModel


class ProductExposure(SyntheticModel):
    """虛構的內部商品註記，資料來自管理者領域包而非真實系統或使用者輸入。"""

    internal_note: str = Field(min_length=1, max_length=160)


class DebugDisclosure(SyntheticModel):
    """虛構的相容版本識別，不讀取主機版本、堆疊、檔案或真實憑證。"""

    legacy_version: str = Field(pattern=r"^[a-zA-Z0-9._-]{1,64}$")


def configure_specification(specification, scenario):
    """在建立來源摘要前宣告模擬欄位，仍讓後續完整候選接受同一契約驗證。"""
    if scenario is None:
        return
    if scenario.handler_id == "product-property-exposure":
        parameters = ProductExposure.model_validate(scenario.parameters)
        schema = specification["paths"]["/products/{id}"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
        product = schema["properties"]["product"]
        product["properties"]["internal_note"] = {"type": "string", "minLength": 1, "maxLength": 160,
                                                    "enum": [parameters.internal_note]}
        product["required"].append("internal_note")
    elif scenario.handler_id == "debug-header-disclosure":
        parameters = DebugDisclosure.model_validate(scenario.parameters)
        responses = specification["paths"]["/products/{id}"]["get"]["responses"]
        for status in ("200", "404"):
            responses[status].setdefault("headers", {})["X-Legacy-Store-Version"] = {
                "required": True, "schema": {"type": "string", "enum": [parameters.legacy_version]}}
    else:
        raise ValueError("No controlled ecommerce weakness handler is registered")


def configure_policies(scenario_policy, generation_policy, scenario):
    """只在明確選定情境時套用固定值，並保護該值不被模型生成覆寫。"""
    if scenario is None:
        return
    if scenario.handler_id == "product-property-exposure":
        parameters = ProductExposure.model_validate(scenario.parameters)
        for template in scenario_policy.templates:
            if template.template_id == "found":
                template.body["product"]["internal_note"] = parameters.internal_note
        for rule in generation_policy.rules:
            if rule.outcome_id == "found":
                rule.protected_pointers.append("/product/internal_note")
    elif scenario.handler_id == "debug-header-disclosure":
        parameters = DebugDisclosure.model_validate(scenario.parameters)
        for template in scenario_policy.templates:
            template.headers["X-Legacy-Store-Version"] = parameters.legacy_version
    else:
        raise ValueError("No controlled ecommerce weakness handler is registered")
