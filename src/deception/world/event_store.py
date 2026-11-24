"""共用 PostgreSQL WorldEvent 交易核心，不包含商品或購物車欄位。"""

from collections.abc import Mapping
from contextlib import nullcontext
import hashlib
import inspect
import json
import re
from types import MappingProxyType
from typing import Protocol

from pydantic import JsonValue, TypeAdapter

from .commit import CommitResult, validate_commit_metadata
from .models import WorldScope, WorldSnapshot, _freeze_json
from .postgres_store import psycopg
from .session import PostgresSessionWorlds, SessionBinding
from .store import CommitLookupResult, WorldStore, WorldStoreError, require_unchanged_compatibility


def prepare_event_command(command):
    """交易前驗證並凍結同一份 JSON 命令，確保等待期間外部改寫不會穿越已計算摘要。"""
    command = TypeAdapter(dict[str, JsonValue]).validate_python(command, strict=True)
    encoded = json.dumps(command, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return _freeze_json(json.loads(encoded)), hashlib.sha256(encoded.encode()).hexdigest()


class EventWorldStore(WorldStore, Protocol):
    """在既有 Snapshot／CAS 介面外，定義有可信 scope 的共用事件提交結果。"""

    def commit_event(self, binding: SessionBinding, *, authorized_scope: WorldScope, operation: str,
                     command: dict, expected_version: int, idempotency_key: str, commit_attempt_id,
                     now: int) -> CommitResult:
        """執行一次核准事件，回傳五類明確結果；未知提交只能循同 scope 唯讀查詢。"""
        ...

    def get_event_result(self, binding: SessionBinding, *, authorized_scope: WorldScope, operation: str,
                         command: dict, idempotency_key: str, commit_attempt_id, now: int) -> CommitLookupResult:
        """重新確認當前身份與操作摘要後唯讀查原 attempt，保留五類查詢狀態及可驗證的共用結果。"""
        ...


class PostgresEventWorldStore(PostgresSessionWorlds):
    """原子保存狀態、事件、業務結果與收據，以部署提供的純函式產生狀態提案。"""

    write_modes = frozenset()
    allowed_operations = frozenset()
    write_denied_code = "world_write_not_authorized"

    def __init__(self, dsn, *, compatibility=None, handlers=None, write_modes=None):
        """固定伺服器 handler 與寫入能力；基礎類別預設不准寫入，領域子類可宣告固定操作。"""
        super().__init__(dsn, compatibility=compatibility)
        if handlers is not None:
            if not isinstance(handlers, Mapping) or any(
                    not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", name)
                    or not callable(handler) or inspect.iscoroutinefunction(handler)
                    for name, handler in handlers.items()):
                raise ValueError("world handlers must be fixed synchronous callables")
            self.allowed_operations = frozenset(handlers)
        self._handlers = MappingProxyType(dict(handlers or {}))
        if write_modes is not None:
            if not isinstance(write_modes, (set, frozenset, tuple)) or not set(write_modes) <= {"inventory", "cart"}:
                raise ValueError("invalid world write capability modes")
            self.write_modes = frozenset(write_modes)

    def _apply(self, state, operation, command):
        """呼叫伺服器固定的純提案函式，沒有從請求載入程式或自行推斷業務規則。"""
        return self._handlers[operation](state, command)

    def _after_event(self, state, *, now):
        """讓受信任領域子類補充事件衍生欄位；基礎類別保持提案內容。"""
        return state

    def _persist_resources(self, connection, binding, operation, result, snapshot):
        """提供同交易資源映射擴充點；共用核心不建立領域資源。"""

    def _commit_transaction(self, binding, operation, command, expected_version, key, attempt, now,
                            *, authorized_scope=None, result_buffer=None, require_saved_digest=True,
                            prepared_command=None, _trusted_connection=None) -> CommitResult:
        """在原 epoch／世代／CAS 交易保存事件、結果與受保護 Executor 的同交易能力。

        既有 API 未提供連線時維持原來的單一交易；受保護 Executor 可注入其已
        認證實體連線，與權威 Receipt／提交證據在同一交易原子提交，不自行 commit。
        """
        validate_commit_metadata(operation, expected_version, key, attempt, now)
        binding = SessionBinding.model_validate(binding.model_dump())
        command, digest = prepare_event_command(command) if prepared_command is None else prepared_command
        if binding.access_mode not in self.write_modes:
            raise WorldStoreError(self.write_denied_code)
        if operation not in self.allowed_operations:
            raise WorldStoreError("unknown_world_operation")
        raw_key, stored_key = key, hashlib.sha256(key.encode()).hexdigest()
        params = self._binding_params(binding)
        with (nullcontext(_trusted_connection) if _trusted_connection is not None
              else self._connection()) as connection:
            head = connection.execute("SELECT session_epoch FROM session_heads WHERE environment_id=%s "
                "AND deployment_id=%s AND session_id=%s FOR SHARE", params[:3]).fetchone()
            if head != (binding.session_epoch,):
                raise WorldStoreError("session_epoch_stale")
            row = connection.execute("SELECT world_generation_id FROM session_world_bindings WHERE environment_id=%s "
                "AND deployment_id=%s AND session_id=%s AND session_epoch=%s FOR UPDATE", params).fetchone()
            if row is None:
                raise WorldStoreError("session_binding_unverifiable")
            generation = row[0]
            scope = WorldScope(environment_id=binding.environment_id, deployment_id=binding.deployment_id,
                               session_id=binding.session_id, world_generation_id=generation)
            if authorized_scope is not None and scope != authorized_scope:
                raise WorldStoreError("scope_mismatch")
            control = connection.execute("SELECT sealed,emergency_revision FROM generation_controls "
                "WHERE world_generation_id=%s FOR UPDATE", (generation,)).fetchone()
            if control is None or control[0] or control[1] is not None:
                raise WorldStoreError("world_generation_unavailable")
            scope_params = self._scope_params(scope)
            connection.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", (self._attempt_key(scope, attempt),))
            previous = connection.execute(
                "SELECT operation_digest,status,result,state_version,state_hash,commit_attempt_id,result_encoding_version,"
                "result_digest FROM world_operations "
                "WHERE environment_id=%s AND deployment_id=%s AND session_id=%s AND world_generation_id=%s "
                "AND operation=%s AND idempotency_key=%s", (*scope_params, operation, stored_key)).fetchone()
            row = connection.execute("SELECT version,expires_at,state,state_hash FROM world_snapshots WHERE environment_id=%s "
                "AND deployment_id=%s AND session_id=%s AND world_generation_id=%s FOR UPDATE", scope_params).fetchone()
            current = self._snapshot_from_row(scope, row)
            if current.expires_at is not None and now >= current.expires_at:
                raise WorldStoreError("session_world_expired")
            if previous is not None:
                if previous[0] != digest:
                    raise WorldStoreError("idempotency_content_conflict")
                outcome = CommitResult.from_record(scope=scope, operation=operation, idempotency_key=raw_key,
                    status=previous[1], result=previous[2], state_version=previous[3], state_hash=previous[4],
                    commit_attempt_id=previous[5], replayed=True)
                if (previous[6:] != (None, None) and previous[6:] != (1, outcome.result_digest)) or (
                        require_saved_digest and previous[6:] == (None, None)):
                    raise WorldStoreError("operation_result_unverifiable")
            else:
                if current.version != expected_version:
                    raise WorldStoreError("version_conflict")
                state, result, accepted = self._apply(current.state, operation, command)
                if type(accepted) is not bool or not isinstance(state, dict) or not isinstance(result, dict):
                    raise ValueError("invalid world event proposal")
                if accepted:
                    state = self._after_event(state, now=now)
                    require_unchanged_compatibility(current, state)
                # JSONB 可能改變數值表示，必須先固定真正保存的 state／result 再計算各自摘要。
                normalized = self._normalize_jsonb(connection, {"state": state if accepted else {}, "result": result})
                result = normalized["result"]
                if accepted:
                    state = normalized["state"]
                updated = WorldSnapshot.create(scope, state, version=current.version+1,
                    expires_at=current.expires_at) if accepted else current
                status = "committed" if accepted else "rejected"
                outcome = CommitResult.from_record(scope=scope, operation=operation, idempotency_key=raw_key,
                    status=status, result=result, state_version=updated.version, state_hash=updated.state_hash,
                    commit_attempt_id=attempt)
                connection.execute("INSERT INTO world_operations "
                    "(environment_id,deployment_id,session_id,world_generation_id,operation,idempotency_key,operation_digest,"
                    "commit_attempt_id,status,result,state_version,state_hash,result_encoding_version,result_digest) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s,%s)",
                    (*scope_params, operation, stored_key, digest, attempt, status, json.dumps(result), updated.version,
                     updated.state_hash, outcome.result_encoding_version, outcome.result_digest))
                if accepted:
                    connection.execute("UPDATE session_world_bindings SET watermark_version=GREATEST(watermark_version,%s) "
                        "WHERE environment_id=%s AND deployment_id=%s AND session_id=%s AND session_epoch=%s",
                        (updated.version, *params))
                    connection.execute("UPDATE world_snapshots SET version=%s,state=%s::jsonb,state_hash=%s "
                        "WHERE environment_id=%s AND deployment_id=%s AND session_id=%s AND world_generation_id=%s",
                        (updated.version, json.dumps(updated.state), updated.state_hash, *scope_params))
                    connection.execute("INSERT INTO world_events VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                        (attempt, *scope_params, updated.version, operation, digest, updated.state_hash))
                    connection.execute("INSERT INTO world_commit_receipts VALUES (%s,%s,%s,%s,%s,%s,%s)",
                        (*scope_params, attempt, updated.version, updated.state_hash))
                    self._persist_resources(connection, binding, operation, result, updated)
            if result_buffer is not None:
                result_buffer.append(outcome)
            return outcome

    def commit_event(self, binding: SessionBinding, *, authorized_scope: WorldScope, operation: str,
                     command: dict, expected_version: int, idempotency_key: str, commit_attempt_id,
                     now: int) -> CommitResult:
        """回傳五類明確提交結果；固定 scope／attempt 供未知結果查回，不自動重試任何寫入。"""
        validate_commit_metadata(operation, expected_version, idempotency_key, commit_attempt_id, now)
        scope = WorldScope.model_validate(authorized_scope.model_dump())
        binding = SessionBinding.model_validate(binding.model_dump())
        prepared_command = prepare_event_command(command)
        metadata = dict(scope=scope, operation=operation, idempotency_key=idempotency_key, commit_attempt_id=commit_attempt_id)
        if (scope.environment_id, scope.deployment_id, scope.session_id) != (
                binding.environment_id, binding.deployment_id, binding.session_id):
            return CommitResult(status="rejected", failure_code="scope_mismatch", **metadata)
        prepared = []
        try:
            return self._commit_transaction(binding, operation, command, expected_version, idempotency_key,
                commit_attempt_id, now, authorized_scope=scope, result_buffer=prepared, prepared_command=prepared_command)
        except WorldStoreError as error:
            code = str(error)
            if code in {"version_conflict", "idempotency_content_conflict"}:
                return CommitResult(status="conflict", failure_code=code, **metadata)
            if code in {"scope_mismatch", "session_epoch_stale", "session_binding_unverifiable",
                    "world_generation_unavailable", "session_world_expired", "world_not_found",
                    "world_compatibility_change_forbidden", "unknown_world_operation", self.write_denied_code}:
                return CommitResult(status="rejected", failure_code=code, **metadata)
        except Exception as error:
            if psycopg is not None and isinstance(error, psycopg.IntegrityError):
                return CommitResult(status="conflict", failure_code="commit_constraint_conflict", **metadata)
        if prepared:
            # 冪等舊結果可能使用原 attempt；讀取交易失聯時也須提供能查回該結果的原識別。
            metadata["commit_attempt_id"] = prepared[-1].commit_attempt_id
        return CommitResult(status="unverifiable", failure_code="commit_unverifiable", **metadata)

    def get_event_result(self, binding: SessionBinding, *, authorized_scope: WorldScope, operation: str,
                         command: dict, idempotency_key: str, commit_attempt_id, now: int) -> CommitLookupResult:
        """以新交易重查有效 epoch／scope／lease 及命令摘要，不因查詢建立事件或重送未知操作。"""
        validate_commit_metadata(operation, 1, idempotency_key, commit_attempt_id, now)
        scope = WorldScope.model_validate(authorized_scope.model_dump())
        binding = SessionBinding.model_validate(binding.model_dump())
        if (operation not in self.allowed_operations or
                (scope.environment_id, scope.deployment_id, scope.session_id) != (
                    binding.environment_id, binding.deployment_id, binding.session_id)):
            return CommitLookupResult("unverifiable")
        _, digest = prepare_event_command(command)
        key_hash = hashlib.sha256(idempotency_key.encode()).hexdigest()
        try:
            with self._connection() as connection:
                active = connection.execute(
                    "SELECT b.world_generation_id FROM session_heads h JOIN session_world_bindings b "
                    "USING(environment_id,deployment_id,session_id,session_epoch) JOIN generation_controls g "
                    "USING(world_generation_id) WHERE h.environment_id=%s AND h.deployment_id=%s AND h.session_id=%s "
                    "AND h.session_epoch=%s AND NOT g.sealed AND g.emergency_revision IS NULL FOR SHARE OF h,b,g",
                    self._binding_params(binding)).fetchone()
                if active != (scope.world_generation_id,):
                    return CommitLookupResult("unverifiable")
                row = connection.execute("SELECT version,expires_at,state,state_hash FROM world_snapshots "
                    "WHERE environment_id=%s AND deployment_id=%s AND session_id=%s AND world_generation_id=%s",
                    self._scope_params(scope)).fetchone()
                snapshot = self._snapshot_from_row(scope, row)
                if snapshot.expires_at is not None and now >= snapshot.expires_at:
                    return CommitLookupResult("unverifiable")
                available, = connection.execute("SELECT pg_try_advisory_xact_lock(hashtextextended(%s,0))",
                    (self._attempt_key(scope, commit_attempt_id),)).fetchone()
                if not available:
                    return CommitLookupResult("pending")
                row = connection.execute("SELECT operation,idempotency_key,operation_digest,status,result,state_version,"
                    "state_hash,commit_attempt_id,result_encoding_version,result_digest FROM world_operations "
                    "WHERE environment_id=%s AND deployment_id=%s "
                    "AND session_id=%s AND world_generation_id=%s AND commit_attempt_id=%s",
                    (*self._scope_params(scope), commit_attempt_id)).fetchone()
                if row is None:
                    return CommitLookupResult("not_found")
                if row[:3] != (operation, key_hash, digest):
                    return CommitLookupResult("unverifiable")
                outcome = CommitResult.from_record(scope=scope, operation=operation, idempotency_key=idempotency_key,
                    status=row[3], result=row[4], state_version=row[5], state_hash=row[6], commit_attempt_id=row[7], replayed=True)
                if row[8:] != (1, outcome.result_digest):
                    return CommitLookupResult("unverifiable")
                return CommitLookupResult(row[3], row[5], row[6], outcome)
        except Exception:
            return CommitLookupResult("unverifiable")
