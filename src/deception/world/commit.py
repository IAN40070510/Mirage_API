"""WorldEvent 共用提交結果、結果摘要與嚴格 metadata 驗證。"""

import hashlib
import json
import re
from typing import Literal
from uuid import UUID

from pydantic import ConfigDict, Field, JsonValue, UUID4, field_validator, model_validator

from deception.common.models import SyntheticModel
from .models import WorldScope, _freeze_json


def validate_commit_metadata(operation, expected_version, key, attempt, now) -> None:
    """交易前拒絕不合法操作、版本、業務鍵、UUIDv4 或非 Unix 整數時間，不開資料庫連線。"""
    if (not isinstance(operation, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", operation)
            or type(expected_version) is not int or not 1 <= expected_version <= 2**63-1
            or not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", key)
            or not isinstance(attempt, UUID) or attempt.version != 4 or type(now) is not int or now < 0):
        raise ValueError("invalid world operation metadata")


def operation_result_digest(result: dict, version: int, state_hash: str, attempt: UUID, status: str) -> str:
    """依 stored-operation-result-v1 摘要原始結果與提交身份，不把重播旗標當成新結果。"""
    value = {"result": result, "version": version, "hash": state_hash, "attempt": str(attempt), "status": status}
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class CommitResult(SyntheticModel):
    """不可變的五類提交結果；未知結果只提供原 scope／attempt，不捏造已提交版本。"""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True, allow_inf_nan=False)

    status: Literal["committed", "already_committed", "conflict", "rejected", "unverifiable"]
    scope: WorldScope
    operation: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    idempotency_key: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$", repr=False)
    commit_attempt_id: UUID4
    result_encoding_version: Literal[1] = 1
    committed_state_version: int | None = Field(default=None, ge=1, le=2**63-1)
    committed_state_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    observed_state_version: int | None = Field(default=None, ge=1, le=2**63-1)
    observed_state_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    result_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    result: dict[str, JsonValue] | None = Field(default=None, repr=False)
    failure_code: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{0,127}$")
    replayed: bool = False

    @field_validator("result_encoding_version", mode="before")
    @classmethod
    def validate_encoding_version(cls, value):
        """只接受真正的整數版本 1，禁止 bool 或等值浮點繞過 Literal 驗證。"""
        if type(value) is not int:
            raise ValueError("result encoding version must be an integer")
        return value

    @model_validator(mode="after")
    def validate_outcome(self):
        """核對成功／失敗所能攜帶的證據，重算已保存結果摘要並凍結巢狀 JSON。"""
        scope = WorldScope.model_validate(self.scope.model_dump())
        object.__setattr__(self, "scope", scope)
        successful = self.status in {"committed", "already_committed"}
        if (self.committed_state_version is None) != (self.committed_state_hash is None):
            raise ValueError("committed version and hash must be paired")
        if (self.observed_state_version is None) != (self.observed_state_hash is None):
            raise ValueError("observed version and hash must be paired")
        if successful:
            if (self.failure_code is not None or self.committed_state_version is None
                    or self.result is None or self.result_digest is None
                    or self.observed_state_version != self.committed_state_version
                    or self.observed_state_hash != self.committed_state_hash):
                raise ValueError("successful commit requires complete committed evidence")
            if self.replayed != (self.status == "already_committed"):
                raise ValueError("replay flag must match committed status")
        elif self.failure_code is None or self.committed_state_version is not None:
            raise ValueError("failed commit cannot claim committed evidence")
        if self.status in {"conflict", "unverifiable"} and (
                self.result is not None or self.result_digest is not None or self.replayed):
            raise ValueError("uncertain or conflicting outcome cannot claim a saved result")
        if self.result is None:
            if self.result_digest is not None or self.replayed:
                raise ValueError("result evidence requires a saved payload")
        else:
            if self.observed_state_version is None or self.result_digest is None:
                raise ValueError("saved result requires observed state evidence")
            stored = "committed" if successful else "rejected"
            expected = operation_result_digest(self.result, self.observed_state_version,
                self.observed_state_hash, self.commit_attempt_id, stored)
            if self.result_digest != expected:
                raise ValueError("operation result digest mismatch")
            object.__setattr__(self, "result", _freeze_json(json.loads(json.dumps(self.result, allow_nan=False))))
        return self

    @classmethod
    def from_record(cls, *, scope, operation, idempotency_key, status, result,
                    state_version, state_hash, commit_attempt_id, replayed=False):
        """把同交易保存的 committed／rejected 紀錄轉成共用結果，重試保留原 attempt 及摘要。"""
        if status not in {"committed", "rejected"}:
            raise ValueError("invalid persisted operation status")
        committed = status == "committed"
        code = None if committed else result.get("code", "business_rejected")
        return cls(status="already_committed" if committed and replayed else status,
            scope=scope, operation=operation, idempotency_key=idempotency_key, commit_attempt_id=commit_attempt_id,
            committed_state_version=state_version if committed else None,
            committed_state_hash=state_hash if committed else None,
            observed_state_version=state_version, observed_state_hash=state_hash,
            result=result, result_digest=operation_result_digest(result, state_version, state_hash, commit_attempt_id, status),
            failure_code=code, replayed=replayed)

    def model_copy(self, *, update=None, deep=False):
        """複製時重新驗證結果與摘要，禁止未驗證的更新製造提交成功或可變 payload。"""
        values = self.model_dump(mode="python")
        values.update(update or {})
        return type(self).model_validate(values)
