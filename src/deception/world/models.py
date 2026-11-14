"""Synthetic World 的嚴格身份、快照與回應來源型別。"""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, model_validator
from pydantic import JsonValue

from deception.common.models import SyntheticModel


def canonical_state_hash(state: dict[str, JsonValue]) -> str:
    """以固定 JSON 編碼計算世界狀態雜湊，避免欄位順序造成不同版本。"""
    encoded = json.dumps(state, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class WorldScope(SyntheticModel):
    """綁定環境、部署、Session 與 World 世代，阻止跨隔離範圍讀取資料。"""

    environment_id: str = Field(min_length=1, max_length=128)
    deployment_id: str = Field(min_length=1, max_length=128)
    session_id: str = Field(min_length=1, max_length=128)
    world_generation_id: str = Field(min_length=1, max_length=128)


class WorldSnapshot(SyntheticModel):
    """描述同一版本的不可變世界資料與完整性證據。"""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True, allow_inf_nan=False)

    scope: WorldScope
    version: int = Field(ge=1)
    expires_at: int | None = Field(default=None, ge=1)
    state: dict[str, JsonValue]
    state_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def verify_state_hash(self) -> "WorldSnapshot":
        """拒絕內容與保存雜湊不一致的快照，避免讀取被竄改的世界。"""
        if canonical_state_hash(self.state) != self.state_hash:
            raise ValueError("state_hash does not match state")
        return self

    @classmethod
    def create(
        cls,
        scope: WorldScope,
        state: dict[str, JsonValue],
        *,
        version: int = 1,
        expires_at: int | None = None,
    ) -> "WorldSnapshot":
        """建立含正確完整性雜湊的唯讀快照。"""
        return cls(
            scope=scope,
            version=version,
            expires_at=expires_at,
            state=state,
            state_hash=canonical_state_hash(state),
        )


class SnapshotSource(SyntheticModel):
    """指出回應來自已核准的 ReadAdmission 快照。"""

    kind: Literal["snapshot"] = "snapshot"
    read_admission_id: str = Field(min_length=1, max_length=128)
    world_generation_id: str = Field(min_length=1, max_length=128)
    state_version: int = Field(ge=1)
    state_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class CommitSource(SyntheticModel):
    """指出回應來自已提交且可查詢的操作結果。"""

    kind: Literal["committed_operation"] = "committed_operation"
    world_generation_id: str = Field(min_length=1, max_length=128)
    operation_result_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    committed_state_version: int = Field(ge=1)
    committed_state_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class SecurityErrorSource(SyntheticModel):
    """指出回應只使用固定安全錯誤模板，不代表 Synthetic World 資料。"""

    kind: Literal["security_error"] = "security_error"
    template_id: str = Field(min_length=1, max_length=128)
    contract_revision: str = Field(min_length=1, max_length=128)


ResponseSource = Annotated[
    SnapshotSource | CommitSource | SecurityErrorSource,
    Field(discriminator="kind"),
]


class ProjectionCompatibilityProfile(SyntheticModel):
    """保存官方規格、世界結構與領域適配器之間的相容性證據。"""

    profile_id: str = Field(min_length=1, max_length=128)
    profile_version: str = Field(min_length=1, max_length=64)
    profile_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    platform_id: str = Field(min_length=1, max_length=128)
    platform_version: str = Field(min_length=1, max_length=128)
    source_spec_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    world_schema_version: str = Field(min_length=1, max_length=64)
    domain_adapter_version: str = Field(min_length=1, max_length=64)


class DeviationApproval(SyntheticModel):
    """證明有效投影與官方規格差異已由受信任流程核准。"""

    approval_id: str = Field(min_length=1, max_length=128)
    approval_revision: str = Field(min_length=1, max_length=128)
    source_spec_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    projection_contract_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    approved_profile_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: str = Field(min_length=1, max_length=512)


class ProjectionEvidence(SyntheticModel):
    """固定官方 Schema、有效投影與差異核准的驗證結果。"""

    source_spec_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    compatibility_profile: ProjectionCompatibilityProfile
    projection_contract_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    official_schema_valid: bool
    effective_projection_valid: bool
    deviation_approval: DeviationApproval | None = None

    @model_validator(mode="after")
    def verify_projection_evidence(self) -> "ProjectionEvidence":
        """拒絕缺少來源一致性或差異核准的投影證據。"""
        if self.compatibility_profile.source_spec_sha256 != self.source_spec_sha256:
            raise ValueError("projection source spec does not match compatibility profile")
        if self.official_schema_valid is False and self.effective_projection_valid:
            approval = self.deviation_approval
            if approval is None:
                raise ValueError("effective projection requires deviation approval")
            if approval.source_spec_sha256 != self.source_spec_sha256:
                raise ValueError("deviation approval source spec does not match")
            if approval.projection_contract_hash != self.projection_contract_hash:
                raise ValueError("deviation approval contract does not match")
            if approval.approved_profile_sha256 != self.compatibility_profile.profile_sha256:
                raise ValueError("deviation approval profile does not match")
        return self


class ResponseAdmission(SyntheticModel):
    """保存一次性回應准入的不可變內容與單一控制序列證據。"""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True, allow_inf_nan=False)

    admission_id: str = Field(min_length=1, max_length=128)
    request_binding_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    world_generation_id: str = Field(min_length=1, max_length=128)
    grant_revision: int = Field(ge=1)
    projection_registry_revision: int = Field(ge=1)
    candidate_ref: str = Field(min_length=1, max_length=256)
    candidate_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    immutable_body_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    semantic_headers_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    projection_contract_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorization_revision: str = Field(min_length=1, max_length=128)
    authorization_deadline: int = Field(ge=1)
    transmission_deadline: int = Field(ge=1)
    source: ResponseSource
    projection_evidence: ProjectionEvidence

    @model_validator(mode="after")
    def verify_deadlines(self) -> "ResponseAdmission":
        """確保傳輸期限不早於授權期限，避免合法准入無法安全完成。"""
        if self.transmission_deadline < self.authorization_deadline:
            raise ValueError("transmission_deadline must not precede authorization_deadline")
        return self
