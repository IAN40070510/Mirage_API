"""共用安全分類與 Trusted Session；延後載入需要重型 API 驗證依賴的目錄。"""

__all__ = [
    "CategoryReference",
    "ScenarioCatalog",
    "SecurityTaxonomy",
    "TrustedKeyRegistry",
    "TrustedSessionClaims",
    "TrustedSessionError",
    "TrustedSessionHeader",
    "TrustedSessionVerifier",
    "TrustedSessionAssessmentProvider",
    "WeaknessScenario",
    "load_catalog",
]


def __getattr__(name: str):
    """依請求延後載入安全 API，讓純 JWS 驗證不依賴 OpenAPI 工具鏈。"""
    if name in {"CategoryReference", "ScenarioCatalog", "SecurityTaxonomy", "WeaknessScenario", "load_catalog"}:
        from . import catalog

        return getattr(catalog, name)
    if name in {
        "TrustedKeyRegistry",
        "TrustedSessionClaims",
        "TrustedSessionError",
        "TrustedSessionHeader",
        "TrustedSessionVerifier",
    }:
        from . import trusted_session

        return getattr(trusted_session, name)
    if name == "TrustedSessionAssessmentProvider":
        from .trusted_ingress import TrustedSessionAssessmentProvider

        return TrustedSessionAssessmentProvider
    raise AttributeError(name)
