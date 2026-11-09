"""H 的組合指令與不可變候選回應，候選本身不代表 I 已放行。"""

from dataclasses import asdict, dataclass

from pydantic import Field, JsonValue

from deception.common.models import DatasetScope, SyntheticModel
from mirage_validator.gate import GateRequest


class DataBinding(SyntheticModel):
    """以 JSON Pointer 把 E 的商品／變體值放入已存在的 body 模板位置。"""

    source_pointer: str
    target_pointer: str


class CompositionPlan(SyntheticModel):
    """C 提供明確值與映射；H 不依 schema 猜測缺少的欄位。"""

    scope: DatasetScope
    method: str = Field(default="GET", pattern=r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$")
    path: str = Field(pattern=r"^/")
    status_code: int = Field(ge=200, le=599)
    media_type: str = "application/json"
    headers: dict[str, str] = Field(default_factory=dict)
    body: JsonValue = Field(...)
    bindings: list[DataBinding] = Field(default_factory=list)


@dataclass(frozen=True)
class CandidateIdentity:
    """保留此次組合的來源與 run 身份，全部使用不可變純量。"""

    site_id: str
    platform_id: str
    platform_version: str
    spec_sha256: str
    scenario_id: str
    run_id: str
    operation_id: str
    method: str
    path: str
    source_approved: bool


@dataclass(frozen=True)
class CandidateResponse:
    """綁定同一份 status、單值 headers 與最終 UTF-8 JSON 字串。"""

    identity: CandidateIdentity
    status_code: int
    headers: tuple[tuple[str, str], ...]
    body: str

    @property
    def body_bytes(self) -> bytes:
        """提供精確待驗證的 UTF-8 bytes，不重新序列化 JSON。"""
        return self.body.encode("utf-8")

    def to_gate_request(self, request_url: str) -> GateRequest:
        """只轉換完全相同的 triple；含契約身份核對的交接應用 verify_candidate。"""
        return GateRequest(request_url=request_url, request_method=self.identity.method,
                           status_code=self.status_code, headers=dict(self.headers), body=self.body)

    def to_dict(self) -> dict:
        """輸出可保存的候選封套；body 已是字串，不是對外 HTTP renderer。"""
        return asdict(self)
