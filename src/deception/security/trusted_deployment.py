"""從部署者核准設定建立共享 Replay 的 Trusted Session 入口。"""

from pydantic import Field

from deception.common.models import SyntheticModel
from deception.world import PostgresReplayStore
from .trusted_session import TrustedKeyRegistry, TrustedSessionVerifier
from .trusted_ingress import OriginalAssessmentLookup, TrustedSessionAssessmentProvider
from .key_revocation import PostgresTrustedKeyRevocations


class TrustedDeploymentSettings(SyntheticModel):
    """保存 Gateway 身份、公鑰與服務綁定；不包含私鑰或資料庫憑證。"""

    issuer: str = Field(min_length=1)
    audience: str = Field(min_length=1)
    environment_id: str = Field(min_length=1)
    deployment_id: str = Field(min_length=1)
    source_id: str = Field(min_length=1)
    service_id: str = Field(min_length=1)
    site_id: str = Field(min_length=1)
    public_keys: dict[str, str] = Field(min_length=1)
    max_clock_skew: int = Field(default=30, ge=0, le=30)
    max_lifetime: int = Field(default=60, ge=1, le=60)
    require_original_assessment: bool = False

    def build_provider(self, *, postgres_dsn: str,
                       original_lookup: OriginalAssessmentLookup | None = None) -> TrustedSessionAssessmentProvider:
        """以 kid→32-byte hex 公鑰建立 provider；無效設定拒絕，DSN 不寫入設定。

        回傳值可注入 pipeline.create_app；有效簽章後先查共享 key 墓碑並持鎖至
        JTI 消費完成。需 migration 014；資料庫不可用不退回記憶體儲存。
        """
        keys = {(self.issuer, kid): bytes.fromhex(value)
                for kid, value in self.public_keys.items()}
        if any(not kid for kid in self.public_keys):
            raise ValueError("kid must not be empty")
        if self.require_original_assessment and not callable(original_lookup):
            raise ValueError("strict original assessment requires a trusted lookup")
        if not self.require_original_assessment and original_lookup is not None:
            raise ValueError("original lookup requires strict mode")
        return TrustedSessionAssessmentProvider(
            TrustedSessionVerifier(
                keys=TrustedKeyRegistry(keys),
                replay_store=PostgresReplayStore(postgres_dsn),
                key_revocations=PostgresTrustedKeyRevocations(postgres_dsn,
                    environment_id=self.environment_id, deployment_id=self.deployment_id),
                max_clock_skew=self.max_clock_skew,
                max_lifetime=self.max_lifetime,
            ),
            expected_issuer=self.issuer, expected_audience=self.audience,
            environment_id=self.environment_id, deployment_id=self.deployment_id,
            source_id=self.source_id, service_id=self.service_id, site_id=self.site_id,
            original_lookup=original_lookup,
            require_original_assessment=self.require_original_assessment,
        )
