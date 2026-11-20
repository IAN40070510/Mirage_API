"""可信 SessionBinding 的原子世界映射、唯讀准入與單調 Watermark。"""

import json
from copy import deepcopy
from dataclasses import dataclass
from uuid import uuid4
from typing import Literal

from pydantic import Field

from deception.common.models import SyntheticModel
from .models import WORLD_COMPATIBILITY_KEY, WorldCompatibility, SnapshotSource, WorldScope, WorldSnapshot
from .postgres_store import PostgresWorldStore, psycopg
from .store import WorldStoreError


# Disaster-restore quarantine sentinel: a retired Session ID cannot be
# restarted by presenting this maximum PostgreSQL BIGINT as a new signed epoch.
RECOVERY_RETIRED_SESSION_EPOCH = (1 << 63) - 1


class SessionBinding(SyntheticModel):
    """保存已由可信身份元件確認的 Session 與 epoch，呼叫端須先驗證身份。"""

    environment_id: str = Field(min_length=1, max_length=128)
    deployment_id: str = Field(min_length=1, max_length=128)
    session_id: str = Field(min_length=1, max_length=128)
    session_epoch: int = Field(ge=0)
    resource_id: str | None = Field(default=None, max_length=128)
    access_mode: Literal["read_only", "inventory", "cart"] = "read_only"


@dataclass(frozen=True)
class WorldRead:
    """封裝單次交易取得的快照與 ReadAdmission 來源，尚未提供發送權。"""

    snapshot: WorldSnapshot
    source: SnapshotSource


class PostgresSessionWorlds(PostgresWorldStore):
    """在單一交易內保存 Session 到 World 的唯一映射，沿用父類資料庫連線。"""

    def __init__(self, dsn: str, *, compatibility: WorldCompatibility | None = None):
        """可要求精確世界政策；未配置者僅供既有原型及唯讀資源定位，不代表符合性。"""
        super().__init__(dsn)
        self._compatibility = None if compatibility is None else WorldCompatibility.model_validate(
            compatibility.model_dump(mode="json"))

    def _snapshot_from_row(self, scope, row):
        """重驗 hash 與保存的世界政策；舊世界缺少政策或政策不符時停止，不補寫。"""
        snapshot = super()._snapshot_from_row(scope, row)
        if self._compatibility is not None and snapshot.compatibility != self._compatibility:
            raise WorldStoreError("world_compatibility_mismatch")
        return snapshot

    def _initial_state(self, state: dict) -> dict:
        """在新世界提案加入部署政策；不接受呼叫端提供另一份政策或改寫原輸入。"""
        if self._compatibility is None:
            return state
        expected = self._compatibility.model_dump(mode="json")
        if WORLD_COMPATIBILITY_KEY in state and state[WORLD_COMPATIBILITY_KEY] != expected:
            raise WorldStoreError("world_compatibility_mismatch")
        return {**deepcopy(state), WORLD_COMPATIBILITY_KEY: expected}

    def create_if_absent(self, scope, state, *, expires_at=None):
        """直接使用 Store 介面初始化時也保存部署政策，不繞過 Session 服務的版本要求。"""
        return super().create_if_absent(scope, self._initial_state(state), expires_at=expires_at)

    @staticmethod
    def _binding_params(binding: SessionBinding) -> tuple:
        """以固定 SQL 順序取得已驗證 binding 的四個欄位。"""
        checked = SessionBinding.model_validate(binding.model_dump())
        if checked.session_epoch >= RECOVERY_RETIRED_SESSION_EPOCH:
            raise WorldStoreError("session_recovery_fenced")
        return (checked.environment_id, checked.deployment_id, checked.session_id, checked.session_epoch)

    def resolve(self, binding: SessionBinding, state: dict, *, now: int, ttl: int) -> WorldSnapshot:
        """原子映射並初始化合成世界，同 epoch 重啟保留、較新 epoch 建新世代。

        ttl 是部署者核准的正整數秒。過期或結果未知時拋出固定錯誤，
        呼叫端可用 inspect_binding 唯讀恢復，不得更換 epoch 或世代盲目重建。
        """
        if type(now) is not int or type(ttl) is not int or now < 0 or ttl < 1:
            raise ValueError("invalid session world lifetime")
        with self._connection() as connection:
            return self._resolve_in_transaction(connection, binding, state, now=now, ttl=ttl)

    def _resolve_in_transaction(self, connection, binding, state, *, now: int, ttl: int) -> WorldSnapshot:
        """在呼叫端交易內初始化 World，讓資源 ID 與世界映射能一起提交。"""
        state = self._initial_state(state)
        params = self._binding_params(binding)
        generation = uuid4().hex
        scope = WorldScope(environment_id=binding.environment_id, deployment_id=binding.deployment_id,
                           session_id=binding.session_id, world_generation_id=generation)
        initial = WorldSnapshot.create(scope, state, expires_at=now + ttl)
        connection.execute(
            "INSERT INTO session_heads VALUES (%s,%s,%s,%s) ON CONFLICT DO NOTHING", params)
        epoch, = connection.execute(
            "SELECT session_epoch FROM session_heads WHERE environment_id=%s AND deployment_id=%s "
            "AND session_id=%s FOR UPDATE", params[:3]).fetchone()
        # Unlike normal epoch advance, a disaster-restore retirement is
        # terminal for the old Session ID. Do not create a fresh generation
        # even when a compromised/old issuer signs the reserved max epoch.
        if epoch == RECOVERY_RETIRED_SESSION_EPOCH:
            raise WorldStoreError("session_recovery_fenced")
        if epoch > binding.session_epoch:
            raise WorldStoreError("session_epoch_stale")
        if epoch < binding.session_epoch:
            previous = connection.execute(
                "SELECT world_generation_id FROM session_world_bindings WHERE environment_id=%s "
                "AND deployment_id=%s AND session_id=%s AND session_epoch=%s", (*params[:3], epoch)).fetchone()
            if previous is not None:
                connection.execute(
                    "UPDATE generation_controls SET sealed=TRUE, "
                    "cutover_revision=COALESCE(cutover_revision,control_revision+1), "
                    "control_revision=CASE WHEN cutover_revision IS NULL THEN control_revision+1 "
                    "ELSE control_revision END WHERE world_generation_id=%s", previous)
        connection.execute(
            "UPDATE session_heads SET session_epoch=%s WHERE environment_id=%s AND deployment_id=%s "
            "AND session_id=%s", (binding.session_epoch, *params[:3]))
        connection.execute(
            "INSERT INTO session_world_bindings "
            "(environment_id,deployment_id,session_id,session_epoch,world_generation_id) "
            "VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING", (*params, generation))
        selected, = connection.execute(
            "SELECT world_generation_id FROM session_world_bindings WHERE environment_id=%s "
            "AND deployment_id=%s AND session_id=%s AND session_epoch=%s", params).fetchone()
        if selected == generation:
            initial = WorldSnapshot.create(scope, self._normalize_jsonb(connection, initial.state), expires_at=now + ttl)
            connection.execute(
                "INSERT INTO world_snapshots VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s)",
                (*self._scope_params(scope), 1, initial.expires_at,
                 json.dumps(initial.state, ensure_ascii=False), initial.state_hash))
            self._ensure_generation(connection, generation)
        else:
            scope = scope.model_copy(update={"world_generation_id": selected})
        snapshot = self._snapshot_from_row(scope, self._select_row(connection.cursor(), scope))
        if snapshot.expires_at is not None and now >= snapshot.expires_at:
            raise WorldStoreError("session_world_expired")
        return snapshot

    @staticmethod
    def _ensure_generation(connection, generation: str) -> None:
        """在同一世界建立交易中保存可供 Grant／Cutover 上鎖的世代列。"""
        connection.execute(
            "INSERT INTO generation_controls(world_generation_id, control_revision, sealed) "
            "VALUES (%s,0,FALSE) ON CONFLICT DO NOTHING", (generation,))

    def inspect_binding(self, binding: SessionBinding, *, now: int) -> WorldSnapshot:
        """依重新驗證的 binding 唯讀查回世界，查無、舊 epoch、到期均停止。"""
        params = self._binding_params(binding)
        with self._connection() as connection:
            connection.read_only = True
            row = connection.execute(
                "SELECT b.world_generation_id FROM session_world_bindings b JOIN session_heads h "
                "USING(environment_id,deployment_id,session_id,session_epoch) "
                "WHERE b.environment_id=%s AND b.deployment_id=%s AND b.session_id=%s AND b.session_epoch=%s",
                params).fetchone()
            if row is None:
                raise WorldStoreError("session_binding_unverifiable")
            scope = WorldScope(environment_id=binding.environment_id, deployment_id=binding.deployment_id,
                               session_id=binding.session_id, world_generation_id=row[0])
            snapshot = self._snapshot_from_row(scope, self._select_row(connection.cursor(), scope))
        if snapshot.expires_at is not None and now >= snapshot.expires_at:
            raise WorldStoreError("session_world_expired")
        return snapshot

    def admit_read(self, binding: SessionBinding, *, request_binding_digest: str,
                   now: int, expires_at: int) -> WorldRead:
        """在一致性交易確認當前 epoch、世代、快照與 Watermark，登記唯讀准入。

        request_binding_digest 由可信入口計算。一般 Client header 不提供版本下限。
        Cutover 或緊急撤銷後的一般讀取拒絕，並行回應抵達順序由傳輸層決定。
        """
        import re

        if not re.fullmatch(r"[0-9a-f]{64}", request_binding_digest) or expires_at <= now:
            raise ValueError("invalid read admission binding or deadline")
        params = self._binding_params(binding)
        with self._connection() as connection:
            head = connection.execute(
                "SELECT session_epoch FROM session_heads WHERE environment_id=%s AND deployment_id=%s "
                "AND session_id=%s FOR SHARE", params[:3]).fetchone()
            if head != (binding.session_epoch,):
                raise WorldStoreError("session_epoch_stale")
            row = connection.execute(
                "SELECT world_generation_id,watermark_version FROM session_world_bindings "
                "WHERE environment_id=%s AND deployment_id=%s AND session_id=%s AND session_epoch=%s FOR UPDATE",
                params).fetchone()
            if row is None:
                raise WorldStoreError("session_binding_unverifiable")
            generation, watermark = row
            control = connection.execute(
                "SELECT sealed,emergency_revision FROM generation_controls WHERE world_generation_id=%s FOR SHARE",
                (generation,)).fetchone()
            if control is None or control[0] or control[1] is not None:
                raise WorldStoreError("world_generation_unavailable")
            scope = WorldScope(environment_id=binding.environment_id, deployment_id=binding.deployment_id,
                               session_id=binding.session_id, world_generation_id=generation)
            snapshot_row = connection.execute(
                "SELECT version,expires_at,state,state_hash FROM world_snapshots WHERE environment_id=%s "
                "AND deployment_id=%s AND session_id=%s AND world_generation_id=%s FOR SHARE",
                self._scope_params(scope)).fetchone()
            snapshot = self._snapshot_from_row(scope, snapshot_row)
            if snapshot.version < watermark:
                raise WorldStoreError("world_below_watermark")
            if snapshot.expires_at is not None and (now >= snapshot.expires_at or expires_at > snapshot.expires_at):
                raise WorldStoreError("session_world_expired")
            source = SnapshotSource(read_admission_id=uuid4().hex, world_generation_id=generation,
                                    state_version=snapshot.version, state_hash=snapshot.state_hash)
            connection.execute(
                "UPDATE session_world_bindings SET watermark_version=GREATEST(watermark_version,%s) "
                "WHERE environment_id=%s AND deployment_id=%s AND session_id=%s AND session_epoch=%s",
                (snapshot.version, *params))
            connection.execute(
                "INSERT INTO read_admissions VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (source.read_admission_id, *self._scope_params(scope), request_binding_digest,
                 snapshot.version, snapshot.state_hash, expires_at))
        return WorldRead(snapshot, source)
