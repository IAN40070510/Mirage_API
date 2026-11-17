"""由部署設定組裝既有 Gateway 注入點，不修改偵測器或自動切換服務。"""

import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import Field

from deception.common.models import SyntheticModel
from deception.domains.ecommerce.carts import SyntheticCarts
from deception.security.anonymous_identity import AnonymousGroups, AnonymousIdentityProvider, HybridIdentityProvider
from deception.security.medusa_identity import IdentitySessions, MedusaIdentityProvider
from deception.security.resource_identity import ResourceIdentityProvider
from deception.security.trusted_deployment import TrustedDeploymentSettings


class GatewayIntegrationSettings(SyntheticModel):
    """部署者提供的公開設定；私鑰、身份 HMAC 與 DB 憑證分開注入。"""

    deployment: TrustedDeploymentSettings
    kid: str = Field(min_length=1)
    mirage_origin: str
    medusa_origin: str
    allow_loopback_identity_http: bool = False
    enforcement_enabled: bool = False
    deception_approved: bool = False
    policy_version: str = "mirage-trusted-v1"
    minimum_class_score: float = Field(default=0.90, gt=0, le=1)
    enable_medusa_store: bool = False


def configure_gateway_state(state, *, settings: GatewayIntegrationSettings, postgres_dsn: str,
                            signing_key: bytes, identity_key: bytes, publishable_key: str) -> None:
    """在原 Gateway lifespan 建好 client 後組裝身份、政策與 dispatcher。

    驗證所有元件後才更新 state；金鑰須匹配指定 kid 的公開金鑰。未明確啟用的
    enforcement／approval 維持 False，不替部署者核准攔截。DB 連線延至請求發生，
    本函式不執行 migration、不載入模型、不改原上游與既有網路 client。
    """
    from msdss.adapters.attack_assessment import AssessmentScope
    from msdss.decision.policy import DecisionPolicy
    from .trusted_session_dispatch import TrustedSessionDispatcher

    settings = GatewayIntegrationSettings.model_validate(settings.model_dump())
    if getattr(state, "deception_dispatcher", None) is not None:
        raise ValueError("gateway dispatcher is already configured")
    client = getattr(state, "client", None)
    if client is None:
        raise ValueError("gateway HTTP client must be initialized first")
    private = Ed25519PrivateKey.from_private_bytes(signing_key)
    deployment = settings.deployment
    public = deployment.public_keys.get(settings.kid)
    if public is None or bytes.fromhex(public) != private.public_key().public_bytes_raw():
        raise ValueError("gateway signing key does not match deployment kid")
    scope = AssessmentScope(source_id=deployment.source_id, environment_id=deployment.environment_id,
        deployment_id=deployment.deployment_id, service_id=deployment.service_id, site_id=deployment.site_id,
        lifetime_seconds=deployment.max_lifetime)
    policy = DecisionPolicy(version=settings.policy_version, enforcement_enabled=settings.enforcement_enabled,
        deception_approved=settings.deception_approved, minimum_class_score=settings.minimum_class_score)
    identity_scope = dict(environment_id=deployment.environment_id, deployment_id=deployment.deployment_id)
    customer = MedusaIdentityProvider(client=client, origin=settings.medusa_origin,
        publishable_key=publishable_key, identity_key=identity_key, sessions=IdentitySessions(postgres_dsn),
        allow_loopback_http=settings.allow_loopback_identity_http, **identity_scope)
    anonymous = AnonymousIdentityProvider(key=identity_key, groups=AnonymousGroups(postgres_dsn), **identity_scope)
    identity = ResourceIdentityProvider(fallback=HybridIdentityProvider(customer, anonymous),
        resources=SyntheticCarts(postgres_dsn), **identity_scope)
    if settings.enable_medusa_store:
        identity = ResourceIdentityProvider(fallback=identity, resources=SyntheticCarts(postgres_dsn),
                                            prefix="/store", **identity_scope)
    dispatcher = TrustedSessionDispatcher(private_key=private, kid=settings.kid, issuer=deployment.issuer,
        audience=deployment.audience, scope=scope, mirage_origin=settings.mirage_origin, identity_provider=identity)
    state.deception_dispatcher = dispatcher
    state.decision_policy = policy


def configure_from_environment(state) -> None:
    """從部署檔路徑讀公開設定與分開保存的秘密，錯誤時阻止啟動而不輸出秘密。

    由已核准的 Gateway lifespan 明確呼叫；沒有自動 monkey patch 或路由修改。
    原 Gateway 負責 client 與模型生命週期，部署者負責 TLS 信任及私鑰檔權限。
    """
    names = ("MIRAGE_GATEWAY_SETTINGS_FILE", "MIRAGE_GATEWAY_SIGNING_KEY_FILE",
             "MIRAGE_IDENTITY_KEY_FILE", "MIRAGE_MEDUSA_PUBLISHABLE_KEY_FILE", "MIRAGE_POSTGRES_DSN")
    if any(not os.environ.get(name) for name in names):
        raise ValueError("gateway integration requires settings, secret file paths and isolated DSN")
    settings = GatewayIntegrationSettings.model_validate_json(
        Path(os.environ[names[0]]).read_text(encoding="utf-8"))
    configure_gateway_state(state, settings=settings, postgres_dsn=os.environ[names[4]],
        signing_key=Path(os.environ[names[1]]).read_bytes(),
        identity_key=Path(os.environ[names[2]]).read_bytes(),
        publishable_key=Path(os.environ[names[3]]).read_text(encoding="utf-8").strip())
