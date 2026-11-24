"""Synthetic World 的嚴格身份、快照與回應來源型別。"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, field_validator, model_validator
from pydantic import JsonValue

from deception.common.models import SyntheticModel


def _immutable(self, *args, **kwargs):
    """拒絕對已保存快照內部 JSON 的所有原地變更。"""
    raise TypeError("world snapshot state is immutable")


class _FrozenDict(dict):
    """保留 JSON dict 序列化能力，但封鎖所有會改變內容的方法。"""

    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = __ior__ = _immutable

    def __deepcopy__(self, memo):
        """領域事件可明確複製成可變提案，原快照維持不變。"""
        return {key: deepcopy(value, memo) for key, value in self.items()}


class _FrozenList(list):
    """保留 JSON array 序列化能力，封鎖索引、排序與增刪變更。"""

    __setitem__ = __delitem__ = append = extend = insert = pop = remove = clear = sort = reverse = _immutable
    __iadd__ = __imul__ = _immutable

    def __deepcopy__(self, memo):
        """為事件提案建立一般 list，避免提案改寫原快照。"""
        return [deepcopy(value, memo) for value in self]


def _freeze_json(value):
    """遞迴凍結已通過型別與 hash 驗證的 JSON 容器。"""
    if isinstance(value, dict):
        return _FrozenDict({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return _FrozenList(_freeze_json(item) for item in value)
    return value


def canonical_state_hash(state: dict[str, JsonValue]) -> str:
    """以固定 JSON 編碼計算世界狀態雜湊，避免欄位順序造成不同版本。"""
    encoded = json.dumps(state, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class WorldScope(SyntheticModel):
    """綁定環境、部署、Session 與 World 世代，阻止跨隔離範圍讀取資料。"""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True, allow_inf_nan=False)

    environment_id: str = Field(min_length=1, max_length=128)
    deployment_id: str = Field(min_length=1, max_length=128)
    session_id: str = Field(min_length=1, max_length=128)
    world_generation_id: str = Field(min_length=1, max_length=128)


WORLD_COMPATIBILITY_KEY = "_mirage_world_compatibility"


class WorldCompatibility(SyntheticModel):
    """固定世界引擎版本、資料來源與可投影的精確 Profile 集合，摘要涵蓋全部政策。"""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True, allow_inf_nan=False)

    world_schema_version: str = Field(min_length=1, max_length=64)
    domain_adapter_version: str = Field(min_length=1, max_length=64)
    source_spec_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    compatibility_profile_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    projection_profiles: dict[str, dict[str, str]] = Field(min_length=1)

    @model_validator(mode="after")
    def verify_policy(self):
        """驗證整份精確投影資料與政策摘要，禁止未列入集合的 Profile 自動相容。"""
        for key, value in self.projection_profiles.items():
            profile = ProjectionCompatibilityProfile.model_validate(value)
            if key != profile.profile_sha256 or profile.world_schema_version != self.world_schema_version:
                raise ValueError("world projection profile does not match policy")
        data = self.model_dump(mode="json", exclude={"compatibility_profile_hash"})
        if canonical_state_hash(data) != self.compatibility_profile_hash:
            raise ValueError("world compatibility policy hash does not match")
        object.__setattr__(self, "projection_profiles", _freeze_json(self.projection_profiles))
        return self

    @classmethod
    def create(cls, *, world_schema_version: str, domain_adapter_version: str,
               source_spec_sha256: str, profiles: list["ProjectionCompatibilityProfile"]):
        """由部署已審查的投影集合建立世界政策；摘要不綁定單一 operation。"""
        selected = {}
        for profile in profiles:
            value = profile.model_dump(mode="json")
            if profile.profile_sha256 in selected and selected[profile.profile_sha256] != value:
                raise ValueError("conflicting world projection profile")
            selected[profile.profile_sha256] = value
        data = dict(world_schema_version=world_schema_version, domain_adapter_version=domain_adapter_version,
                    source_spec_sha256=source_spec_sha256, projection_profiles=selected)
        return cls(**data, compatibility_profile_hash=canonical_state_hash(data))

    def permits(self, evidence: "ProjectionEvidence") -> bool:
        """只接受精確列入政策的 Profile；契約是否撤銷仍須另查共享 Registry。"""
        profile = evidence.compatibility_profile
        return self.projection_profiles.get(profile.profile_sha256) == profile.model_dump(mode="json")


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
        if WORLD_COMPATIBILITY_KEY in self.state:
            WorldCompatibility.model_validate(self.state[WORLD_COMPATIBILITY_KEY])
        object.__setattr__(self, "state", _freeze_json(self.state))
        return self

    @property
    def compatibility(self) -> WorldCompatibility | None:
        """讀取由同一 state_hash 保護的世界政策；舊原型快照沒有政策時明確回 None。"""
        value = self.state.get(WORLD_COMPATIBILITY_KEY)
        return None if value is None else WorldCompatibility.model_validate(value)

    def model_copy(self, *, update=None, deep=False):
        """沿用 Pydantic 複製語意並凍結複製後的容器，更新值仍由後續入口驗證。"""
        copied = super().model_copy(update=update, deep=deep)
        object.__setattr__(copied, "state", _freeze_json(copied.state))
        return copied

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

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True, allow_inf_nan=False)

    kind: Literal["snapshot"] = "snapshot"
    read_admission_id: str = Field(min_length=1, max_length=128)
    world_generation_id: str = Field(min_length=1, max_length=128)
    state_version: int = Field(ge=1)
    state_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class CommitSource(SyntheticModel):
    """指出回應來自已提交且可查詢的操作結果。"""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True, allow_inf_nan=False)

    kind: Literal["committed_operation"] = "committed_operation"
    world_generation_id: str = Field(min_length=1, max_length=128)
    operation_result_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    committed_state_version: int = Field(ge=1)
    committed_state_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class CartCreationSource(SyntheticModel):
    """Creator Receipt 經受保護 lineage 指向獨立派生 Cart 世界的建立來源。"""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True, allow_inf_nan=False)

    kind: Literal["cart_creation"] = "cart_creation"
    derived_session_id: str = Field(min_length=1, max_length=128)
    derived_world_generation_id: str = Field(min_length=1, max_length=128)
    resource_id: str = Field(pattern=r"^cart_[0-9a-f]{32}$")
    commit_attempt_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    state_version: int = Field(ge=1)
    state_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class SecurityErrorSource(SyntheticModel):
    """指出回應只使用固定安全錯誤模板，不代表 Synthetic World 資料。"""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True, allow_inf_nan=False)

    kind: Literal["security_error"] = "security_error"
    template_id: str = Field(min_length=1, max_length=128)
    contract_revision: str = Field(min_length=1, max_length=128)


ResponseSource = Annotated[
    SnapshotSource | CommitSource | CartCreationSource | SecurityErrorSource,
    Field(discriminator="kind"),
]


class ProjectionCompatibilityProfile(SyntheticModel):
    """保存官方規格、世界結構與領域適配器之間的相容性證據。"""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True, allow_inf_nan=False)

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

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True, allow_inf_nan=False)

    approval_id: str = Field(min_length=1, max_length=128)
    approval_revision: str = Field(min_length=1, max_length=128)
    source_spec_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    projection_contract_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    approved_profile_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: str = Field(min_length=1, max_length=512)


class ProjectionEvidence(SyntheticModel):
    """固定官方 Schema、有效投影與差異核准的驗證結果。"""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True, allow_inf_nan=False)

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
    hash_encoding_version: Literal[1] = 1
    candidate_serialization_version: Literal[1] = 1
    candidate_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    immutable_body_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    semantic_headers_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    projection_contract_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorization_revision: str = Field(min_length=1, max_length=128)
    authorization_deadline: int = Field(ge=1)
    transmission_deadline: int = Field(ge=1)
    source: ResponseSource
    projection_evidence: ProjectionEvidence

    @field_validator("hash_encoding_version", "candidate_serialization_version", mode="before")
    @classmethod
    def require_integer_encoding_version(cls, value):
        """只接受整數版本，不將 bool 或等值浮點數誤解為已支援的編碼。"""
        if type(value) is not int:
            raise ValueError("encoding version must be an integer")
        return value

    @model_validator(mode="after")
    def verify_deadlines(self) -> "ResponseAdmission":
        """核對期限、來源世代與已驗證投影契約，避免混用不同回應的准入證據。"""
        if self.transmission_deadline < self.authorization_deadline:
            raise ValueError("transmission_deadline must not precede authorization_deadline")
        if self.source.kind == "cart_creation":
            # 只有受保護 C-01 source 可跨 Scope；此欄是 Creator Admission 世代，
            # 派生 Cart 世代必須獨立存在且不與其混同。
            if self.source.derived_world_generation_id == self.world_generation_id:
                raise ValueError("cart creation source must use a distinct derived generation")
        elif self.source.kind != "security_error" and self.source.world_generation_id != self.world_generation_id:
            raise ValueError("response source generation does not match admission")
        if self.projection_evidence.projection_contract_hash != self.projection_contract_hash:
            raise ValueError("projection evidence contract does not match admission")
        if not self.projection_evidence.effective_projection_valid:
            raise ValueError("response admission requires a valid effective projection")
        return self
