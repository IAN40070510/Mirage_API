"""已驗證請求的假名化觀察與原子 Grant 關聯，不保存 Token、原始請求或模型上下文。"""

from uuid import uuid4
from typing import Literal

from pydantic import ConfigDict, Field, UUID4, model_validator

from deception.common.models import SyntheticModel
from .models import ResponseAdmission, WorldScope, WorldSnapshot
from .postgres_store import PostgresWorldStore


class RequestObservation(SyntheticModel):
    """保存已驗證請求的摘要與基底快照；觀察本身不證明業務已提交或回應已發送。"""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    observation_id: UUID4 = Field(default_factory=uuid4)
    request_id_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    trusted_context_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_binding_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    base_scope: WorldScope
    base_state_version: int = Field(ge=1, le=2**63-1)
    base_state_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def revalidate_scope(self):
        """重新驗證 scope 物件，避免透過未驗證的 model_copy 更新帶入非法隔離欄位。"""
        object.__setattr__(self, "base_scope", WorldScope.model_validate(self.base_scope.model_dump()))
        return self

    @classmethod
    def from_snapshot(cls, snapshot: WorldSnapshot, *, request_id_digest: str, trusted_context_digest: str,
                      request_binding_digest: str):
        """只從通過 hash 驗證的快照擷取身份與版本，不保存 state 或任何原始請求資料。"""
        checked = WorldSnapshot.model_validate(snapshot.model_dump())
        return cls(base_scope=checked.scope, base_state_version=checked.version, base_state_hash=checked.state_hash,
            request_id_digest=request_id_digest, trusted_context_digest=trusted_context_digest,
            request_binding_digest=request_binding_digest)

    def model_copy(self, *, update=None, deep=False):
        """複製時重驗所有欄位，不讓 bool、錯誤 UUID 或 scope 繞過嚴格型別。"""
        values = self.model_dump(mode="python")
        values.update(update or {})
        return type(self).model_validate(values)


class RequestAuditLink(SyntheticModel):
    """把已保存的觀察連到最終來源世界；購物車初始化可與基底匿名讀取世界不同。"""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    observation: RequestObservation
    target_scope: WorldScope
    domain_validation: Literal["passed"]
    contract_validation: Literal["passed"]

    @model_validator(mode="after")
    def validate_deployment(self):
        """只允許同環境／部署的結果，並重新驗證巢狀型別；跨 Session 初始化不混稱同一基底世界。"""
        checked = RequestObservation.model_validate(self.observation.model_dump())
        target = WorldScope.model_validate(self.target_scope.model_dump())
        if (checked.base_scope.environment_id, checked.base_scope.deployment_id) != (target.environment_id, target.deployment_id):
            raise ValueError("request audit deployment mismatch")
        object.__setattr__(self, "observation", checked)
        object.__setattr__(self, "target_scope", target)
        return self


class PostgresRequestAudit:
    """分開保存請求開始與結果；正向結果在 Grant 交易內保存，未知結果不猜測提交與發送。"""

    def __init__(self, dsn: str):
        """重用共用連線政策，但不暴露 WorldStore 的世界寫入介面。"""
        self._store = PostgresWorldStore(dsn)
        self._dsn = dsn

    def _connection(self):
        """依共用 Store 的 DSN 設定延後建立連線，不在建構時執行 I/O。"""
        return self._store._connection()

    @staticmethod
    def _observation_values(observation: RequestObservation) -> tuple:
        """以固定 SQL 欄位順序輸出已驗證的假名化觀察內容。"""
        checked = RequestObservation.model_validate(observation.model_dump())
        return (checked.observation_id, checked.request_id_digest, checked.trusted_context_digest,
            checked.request_binding_digest, *PostgresWorldStore._scope_params(checked.base_scope),
            checked.base_state_version, checked.base_state_hash)

    def begin(self, observation: RequestObservation) -> None:
        """單次提交不可變的 request_observed；儲存故障向上傳遞，呼叫端必須停止業務處理。"""
        values = self._observation_values(observation)
        with self._connection() as connection:
            connection.execute("INSERT INTO request_observations "
                "(observation_id,request_id_digest,trusted_context_digest,request_binding_digest,base_environment_id,"
                "base_deployment_id,base_session_id,base_world_generation_id,base_state_version,base_state_hash) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", values)

    @staticmethod
    def _require_observation(executor, expected):
        """鎖住並核對完整保存內容，不讓錯誤 observation ID／摘要組合關閉或挪用另一請求。"""
        row = executor.execute("SELECT observation_id,request_id_digest,trusted_context_digest,request_binding_digest,"
            "base_environment_id,base_deployment_id,base_session_id,base_world_generation_id,base_state_version,base_state_hash "
            "FROM request_observations WHERE observation_id=%s FOR SHARE", (expected[0],)).fetchone()
        if row != expected:
            raise ValueError("request audit observation mismatch")

    @classmethod
    def record_admission(cls, cursor, link: RequestAuditLink, admission: ResponseAdmission) -> None:
        """以同一 Grant cursor 保存已通過的 Domain／Contract 與來源；任一不符會回滾整張 Grant。"""
        checked = RequestAuditLink.model_validate(link.model_dump())
        expected = cls._observation_values(checked.observation)
        cls._require_observation(cursor, expected)
        if (admission.request_binding_digest != checked.observation.request_binding_digest
                or admission.world_generation_id != checked.target_scope.world_generation_id
                or admission.source.kind not in {
                    "snapshot", "committed_operation", "cart_creation", "security_error"}):
            raise ValueError("request audit admission mismatch")
        committed = admission.source.kind == "committed_operation"
        created = admission.source.kind == "cart_creation"
        version = (admission.source.committed_state_version if committed else
                   admission.source.state_version if created else None)
        state_hash = (admission.source.committed_state_hash if committed else
                      admission.source.state_hash if created else None)
        cursor.execute("INSERT INTO request_observation_results "
            "(observation_id,admission_id,outcome,target_environment_id,target_deployment_id,target_session_id,"
            "target_world_generation_id,source_kind,committed_state_version,committed_state_hash,projection_contract_hash,"
            "candidate_hash,domain_validation,contract_validation) VALUES (%s,%s,'admitted',%s,%s,%s,%s,%s,%s,%s,%s,%s,'passed','passed')",
            (expected[0], admission.admission_id, *PostgresWorldStore._scope_params(checked.target_scope), admission.source.kind,
             version, state_hash, admission.projection_contract_hash, admission.candidate_hash))

    def close_unverifiable(self, observation: RequestObservation) -> None:
        """請求已停止但無法證明業務結果時留固定分類；不覆寫可能已提交的正向 Grant 關聯。"""
        values = self._observation_values(observation)
        with self._connection() as connection:
            self._require_observation(connection, values)
            connection.execute("INSERT INTO request_observation_results "
                "(observation_id,outcome,domain_validation,contract_validation) "
                "VALUES (%s,'unverifiable','unverifiable','unverifiable') ON CONFLICT (observation_id) DO NOTHING", (values[0],))
