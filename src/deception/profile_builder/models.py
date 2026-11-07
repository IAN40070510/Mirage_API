"""D 工具的來源、Profile 與操作查詢結果。"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue


class ProfileModel(BaseModel):
    """拒絕未定義欄位與型別轉換，避免來源設定被默默改寫。"""

    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)


class ProfileSource(ProfileModel):
    """來源資訊由維護者提供；approved 只記錄來源審查，不代表網站部署核准。"""

    schema_version: Literal[1] = 1
    platform_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]*$")
    platform_version: str = Field(min_length=1)
    source_url: str = Field(pattern=r"^https://")
    source_revision: str = Field(min_length=1)
    spec_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    approved: bool = False
    openapi_file: str = "openapi.yaml"


class OperationProfile(ProfileModel):
    """從單一 OpenAPI operation 擷取的契約摘要，schema 的 $ref 原樣保留。"""

    operation_id: str
    method: str
    path: str
    schema_pointer: str
    tags: list[str]
    summary: str | None
    parameters: list[dict[str, JsonValue]]
    request_body: dict[str, JsonValue] | None
    security: list[dict[str, JsonValue]]
    responses: dict[str, dict[str, JsonValue]]


class PlatformProfile(ProfileModel):
    """可重現的產物；版本與原始規格雜湊共同識別其適用範圍。"""

    schema_version: Literal[1] = 1
    source: ProfileSource
    openapi_version: str
    spec_info_version: str
    schema_file: str
    operations: list[OperationProfile]
    warnings: list[str]


class OperationContext(ProfileModel):
    """交給 C 的 D 工具結果，包含可解析所有內部引用的完整規格快照。"""

    source: ProfileSource
    operation: OperationProfile
    specification: dict[str, JsonValue]
