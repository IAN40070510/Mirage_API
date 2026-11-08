"""B 的明確部署綁定與識別結果；identified 不代表回應已通過 I。"""

from typing import Literal

from pydantic import Field, field_validator, model_validator

from mirage_validator.models import StrictModel
from mirage_validator.request_matching import base_identity

LABEL = r"^[a-z0-9][a-z0-9._-]{0,63}$"


class RuntimeContext(StrictModel):
    """由伺服器設定提供環境身份；不得從 HTTP 自稱的 header 自動填入。"""

    environment_id: str = Field(pattern=LABEL)
    deployment_id: str = Field(pattern=LABEL)
    service_id: str = Field(pattern=LABEL)


class DeploymentBinding(RuntimeContext):
    """將一個測試站點綁定到明確版本與規格，不由 URL 前綴推測平台名稱。"""

    binding_id: str = Field(pattern=LABEL)
    site_id: str = Field(pattern=LABEL)
    base_url: str
    platform_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    platform_version: str = Field(min_length=1)
    spec_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    enabled: bool = False

    @field_validator("base_url")
    @classmethod
    def check_base_url(cls, value):
        """啟用前先檢查完整 HTTP origin／prefix，不接受 query、帳密或歧義 URL。"""
        base_identity(value)
        return value


class BindingConfig(StrictModel):
    """集中綁定檔的本地格式；enabled 與 manifest approved 是獨立條件。"""

    schema_version: Literal[1] = 1
    bindings: list[DeploymentBinding]

    @field_validator("schema_version", mode="before")
    @classmethod
    def check_version_type(cls, value):
        if type(value) is not int:
            raise ValueError("schema_version must be an integer")
        return value

    @model_validator(mode="after")
    def check_unique_ids(self):
        """binding_id 是設定識別鍵，不允許兩筆不同部署共用同一 ID。"""
        ids = [binding.binding_id for binding in self.bindings]
        if len(ids) != len(set(ids)):
            raise ValueError("binding_id must be unique")
        return self


class IdentifiedOperation(DeploymentBinding):
    """已核對部署與契約的操作身份，參數仍保留原始 path 編碼。"""

    operation_id: str
    method: str
    path: str
    path_parameters: dict[str, str]
    query: dict[str, list[str]]

    def profile_arguments(self) -> dict[str, str]:
        """交給 D 的精確 lookup keys，不用實際路徑冒充 path template。"""
        return {"platform_id": self.platform_id, "platform_version": self.platform_version,
                "spec_sha256": self.spec_sha256, "method": self.method, "path": self.path}


class IdentificationIssue(StrictModel):
    code: str
    reason: str


class IdentificationResult(StrictModel):
    """只區分已識別／無法確認，不提供 response valid 或 gate pass。"""

    decision: Literal["identified", "unverifiable"]
    identity: IdentifiedOperation | None = None
    errors: list[IdentificationIssue] = Field(default_factory=list)
    request_id: str | None = None
