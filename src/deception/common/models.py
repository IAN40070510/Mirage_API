"""共用型別與資料隔離身份；不包含商品、價格或其他領域實體。"""

from pydantic import BaseModel, ConfigDict, Field, field_validator

SLUG = r"^[a-z0-9][a-z0-9._-]{0,63}$"


class SyntheticModel(BaseModel):
    """跨領域拒絕額外欄位、非有限數值與隱含型別轉換。"""

    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)

    @field_validator("schema_version", mode="before", check_fields=False)
    @classmethod
    def check_schema_version_type(cls, value):
        """Literal 版本欄位僅接受真正整數，避免 True 等值被當作版本 1。"""
        if type(value) is not int:
            raise ValueError("schema_version must be an integer")
        return value


class DatasetScope(SyntheticModel):
    """固定站點、契約與執行身份，保持既有資料 namespace 與序列化相容。"""

    site_id: str = Field(pattern=SLUG)
    platform_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    platform_version: str = Field(min_length=1, max_length=128)
    spec_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    scenario_id: str = Field(pattern=SLUG)
    run_id: str = Field(pattern=SLUG)
