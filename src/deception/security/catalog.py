"""將版本固定的安全分類與各領域的誘餌情境分開，拒絕未知分類或未實作情境。"""

from pathlib import Path
import re
from typing import Literal

from pydantic import Field, JsonValue, model_validator

from deception.common.models import SLUG, SyntheticModel
from deception.profile_builder.builder import local_path, read_yaml


class SecurityCategory(SyntheticModel):
    """官方分類的固定識別與來源連結，分類本身不等同可執行漏洞。"""

    category_id: str = Field(min_length=1, max_length=64)
    title_en: str = Field(min_length=1)
    title_zh: str = Field(min_length=1)
    url: str = Field(pattern=r"^https://")


class SecurityTaxonomy(SyntheticModel):
    """跨領域共用的榜單及版次，禁止把不同年份的相同編號混在一起。"""

    schema_version: Literal[1] = 1
    taxonomy_id: str = Field(pattern=SLUG)
    title: str = Field(min_length=1)
    edition: str = Field(min_length=1, max_length=32)
    source_url: str = Field(pattern=r"^https://")
    license: str = Field(min_length=1)
    categories: list[SecurityCategory] = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def check_categories(self):
        """分類 ID 必須唯一；已知 OWASP 榜單另核對年份及完整十項 ID，其他分類保持可擴充。"""
        if len({category.category_id for category in self.categories}) != len(self.categories):
            raise ValueError("Security category IDs must be unique")
        known = re.fullmatch(r"owasp-(api-security|web)-([0-9]{4})", self.taxonomy_id)
        if known is not None:
            family, year = known.groups()
            if self.edition != year:
                raise ValueError("OWASP taxonomy edition must match its versioned taxonomy ID")
            expected = ({f"API{index}:{year}" for index in range(1, 11)} if family == "api-security" else
                        {f"A{index:02d}:{year}" for index in range(1, 11)})
            if {category.category_id for category in self.categories} != expected:
                raise ValueError("OWASP taxonomy must contain its exact ten versioned category IDs")
        return self


class CategoryReference(SyntheticModel):
    """明確指定榜單版次及分類，不依漏洞文字或模型猜測 ID。"""

    taxonomy_id: str = Field(pattern=SLUG)
    category_id: str = Field(min_length=1, max_length=64)


class WeaknessScenario(SyntheticModel):
    """一個領域的受控弱點模擬；參數只是資料，沒有程式碼或工具執行權。"""

    scenario_id: str = Field(pattern=SLUG)
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    categories: list[CategoryReference] = Field(min_length=1, max_length=16)
    status: Literal["designed", "implemented"] = "designed"
    simulation_mode: Literal["synthetic_response"] = "synthetic_response"
    handler_id: str | None = Field(default=None, pattern=SLUG)
    parameters: dict[str, JsonValue] = Field(default_factory=dict)
    verification: list[str] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def check_execution(self):
        """設計項目不得偽裝已可執行，已實作項目必須選明確的受控處理器。"""
        if self.status == "implemented" and self.handler_id is None:
            raise ValueError("Implemented scenarios require a registered handler ID")
        if self.status == "designed" and self.handler_id is not None:
            raise ValueError("Designed scenarios must not select an executable handler")
        references = [(item.taxonomy_id, item.category_id) for item in self.categories]
        if len(references) != len(set(references)):
            raise ValueError("Scenario category references must be unique")
        return self


class ScenarioCatalog(SyntheticModel):
    """每個領域獨立維護自己的弱點情境，只有分類字典與驗證格式由核心共用。"""

    schema_version: Literal[1] = 1
    domain: str = Field(pattern=SLUG)
    catalog_id: str = Field(pattern=SLUG)
    catalog_version: str = Field(min_length=1)
    taxonomy_ids: list[str] = Field(min_length=1, max_length=16)
    scenarios: list[WeaknessScenario] = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def check_identifiers(self):
        """拒絕重複情境或榜單，以及未宣告榜單的分類引用。"""
        if (any(not re.fullmatch(SLUG, item) for item in self.taxonomy_ids) or
                len(set(self.taxonomy_ids)) != len(self.taxonomy_ids) or
                len({item.scenario_id for item in self.scenarios}) != len(self.scenarios)):
            raise ValueError("Scenario and taxonomy IDs must be unique")
        if any(ref.taxonomy_id not in self.taxonomy_ids for item in self.scenarios for ref in item.categories):
            raise ValueError("Scenario references an undeclared security taxonomy")
        return self

    def select(self, scenario_id: str) -> WeaknessScenario:
        """只回已實作且唯一命中的情境副本；未知或尚在設計的情境不可默默啟用。"""
        matches = [scenario for scenario in self.scenarios if scenario.scenario_id == scenario_id]
        if len(matches) != 1 or matches[0].status != "implemented":
            raise ValueError("The requested weakness scenario is unknown or not implemented")
        return matches[0].model_copy(deep=True)


def load_catalog(path: Path, *, domain: str, taxonomy_root: Path = Path("inputs/security_taxonomies")) -> ScenarioCatalog:
    """離線讀取領域情境與 taxonomy_root 分類，回傳引用完整的 ScenarioCatalog。

    domain 須與情境目錄相同；缺檔、無效模型、版次或分類 ID 不符會拒絕。
    此函式只核對資料，不啟用 handler、不連網、不核准任何契約或來源。
    """
    catalog = ScenarioCatalog.model_validate(read_yaml(path.read_bytes()))
    if catalog.domain != domain:
        raise ValueError("Weakness catalog does not match the selected domain")
    taxonomies = {}
    for taxonomy_id in catalog.taxonomy_ids:
        file = local_path(taxonomy_root, taxonomy_id + ".yaml")
        taxonomy = SecurityTaxonomy.model_validate(read_yaml(file.read_bytes()))
        if taxonomy.taxonomy_id != taxonomy_id:
            raise ValueError("Security taxonomy file does not match the requested ID")
        taxonomies[taxonomy_id] = {category.category_id for category in taxonomy.categories}
    for scenario in catalog.scenarios:
        if any(ref.category_id not in taxonomies[ref.taxonomy_id] for ref in scenario.categories):
            raise ValueError("Weakness scenario references an unknown versioned category")
    return catalog
