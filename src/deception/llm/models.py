"""本機模型設定及 C/G 共用預算；不從訪客請求或環境變數選擇 endpoint。"""

from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from deception.common.models import SyntheticModel


class TaskModelConfig(SyntheticModel):
    """由管理者覆寫單一任務的模型與解碼配方；換模型必須同時固定完整摘要。"""

    model_name: str | None = Field(default=None, min_length=1, max_length=256)
    model_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    temperature: float | None = Field(default=None, ge=0, le=1)
    max_output_tokens: int | None = Field(default=None, ge=32, le=8192)

    @model_validator(mode="after")
    def check_model_pair(self):
        """拒絕只有模型名稱或只有摘要的半份選擇，避免沿用另一模型身份。"""
        if (self.model_name is None) != (self.model_digest is None):
            raise ValueError("Task model selection requires both name and digest")
        return self


class LLMConfig(SyntheticModel):
    """固定模型名稱及內容摘要；local 模式只允許 loopback Ollama。"""

    schema_version: Literal[1] = 1
    execution_mode: Literal["local", "test"] = "local"
    base_url: str = "http://127.0.0.1:11434/v1"
    model_name: str = Field(min_length=1, max_length=256)
    model_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    planner_mode: Literal["native_tools", "structured_actions"] = "native_tools"
    temperature: float = Field(default=0.0, ge=0, le=1)
    max_output_tokens: int = Field(default=512, ge=32, le=8192)
    tasks: dict[Literal["planner", "generation", "repair"], TaskModelConfig] = Field(default_factory=dict)

    @model_validator(mode="after")
    def check_tasks(self):
        """將每份任務覆寫重驗為相同 loopback 限制的完整設定。"""
        for task in self.tasks:
            self.for_task(task)
        return self

    def for_task(self, task: Literal["planner", "generation", "repair"]) -> "LLMConfig":
        """解析任務的實際模型與設定；省略的值繼承基準，回傳不含遞迴覆寫的副本。"""
        if task not in ("planner", "generation", "repair"):
            raise ValueError("Unknown model task")
        data = self.model_dump(mode="json", exclude={"tasks"})
        if task in self.tasks:
            data.update(self.tasks[task].model_dump(mode="json", exclude_none=True))
        return LLMConfig.model_validate(data)

    @field_validator("base_url")
    @classmethod
    def check_local_url(cls, value):
        """拒絕代理、帳密、非本機位置與額外 query；使用明確的本機相容 API。"""
        url = urlsplit(value)
        if (url.scheme != "http" or url.hostname not in ("127.0.0.1", "localhost", "::1") or
                url.username is not None or url.password is not None or url.query or url.fragment or
                url.path.rstrip("/") != "/v1" or any(ord(c) <= 32 for c in value)):
            raise ValueError("Only an explicit loopback HTTP Ollama /v1 endpoint is supported")
        url.port
        return value.rstrip("/")

    @field_validator("model_name")
    @classmethod
    def check_local_name(cls, value):
        """名稱不能選 cloud 模型；連線時還會核對 Ollama 實際 metadata。"""
        if "cloud" in value.lower() or any(ord(c) <= 32 for c in value):
            raise ValueError("Cloud model aliases and whitespace are not allowed")
        return value

    def identity_fields(self) -> dict:
        """追溯使用明確模型身份；test 不能被誤報為本機真模型。"""
        identity = dict(provider="ollama" if self.execution_mode == "local" else "test",
                    execution_mode=self.execution_mode, model_name=self.model_name, model_digest=self.model_digest,
                    temperature=self.temperature, max_output_tokens=self.max_output_tokens,
                    planner_mode=self.planner_mode)
        if self.tasks:
            identity["tasks"] = {task: self.for_task(task).identity_fields()
                                 for task in ("planner", "generation", "repair")}
        return identity


class RunLimits(SyntheticModel):
    """整個 C/G run 共用限制，不因切換 agent 或有限修正而重新起算。"""

    timeout_seconds: int = Field(default=120, ge=1, le=600)
    max_model_requests: int = Field(default=8, ge=1, le=32)
    max_tool_calls: int = Field(default=8, ge=0, le=64)
    max_input_tokens: int = Field(default=32000, ge=1, le=200000)
    max_output_tokens: int = Field(default=4096, ge=1, le=32768)
    max_repairs: int = Field(default=1, ge=0, le=2)
