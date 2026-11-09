"""共用安全分類與領域弱點情境目錄；不執行真實弱點或任意外部輸入。"""

from .catalog import CategoryReference, ScenarioCatalog, SecurityTaxonomy, WeaknessScenario, load_catalog

__all__ = ["CategoryReference", "ScenarioCatalog", "SecurityTaxonomy", "WeaknessScenario", "load_catalog"]
