"""只在合成 World 中執行庫存預留與取消，與真實商店完全隔離。"""

from copy import deepcopy
from dataclasses import dataclass
import re
from uuid import UUID, uuid4

from deception.world.models import WorldScope
from deception.world.session import SessionBinding
from deception.world.event_store import PostgresEventWorldStore
from deception.world.commit import operation_result_digest
from deception.world.store import WorldStoreError


@dataclass(frozen=True)
class InventoryResult:
    """保存冪等操作的結果與提交版本，replayed 表示重用同一次提交結果。"""

    status: str
    result: dict
    state_version: int
    state_hash: str
    commit_attempt_id: UUID
    replayed: bool = False


class SyntheticInventory(PostgresEventWorldStore):
    """在單一 PostgreSQL 交易執行合成庫存事件、CAS、冪等及結果保存。"""

    write_modes = frozenset({"inventory"})
    allowed_operations = frozenset({"reserve", "cancel"})
    write_denied_code = "inventory_write_not_authorized"

    def reserve(self, binding: SessionBinding, *, sku: str, quantity: int, expected_version: int,
                idempotency_key: str, commit_attempt_id: UUID, now: int) -> InventoryResult:
        """預留正整數庫存，傳回 reservation_id；不足時保存 rejected 結果且不改 World。"""
        if not isinstance(sku, str) or not 1 <= len(sku) <= 128 or type(quantity) is not int or quantity < 1:
            raise ValueError("invalid synthetic inventory reservation")
        return self._commit(binding, "reserve", {"sku": sku, "quantity": quantity}, expected_version,
                            idempotency_key, commit_attempt_id, now)

    def cancel(self, binding: SessionBinding, *, reservation_id: str, expected_version: int,
               idempotency_key: str, commit_attempt_id: UUID, now: int) -> InventoryResult:
        """取消同一 World 的有效預留並歸還庫存；未知或已取消的預留回 rejected。"""
        if not isinstance(reservation_id, str) or not re.fullmatch(r"[0-9a-f]{32}", reservation_id):
            raise ValueError("invalid synthetic reservation identifier")
        return self._commit(binding, "cancel", {"reservation_id": reservation_id}, expected_version,
                            idempotency_key, commit_attempt_id, now)

    @staticmethod
    def _apply(state: dict, operation: str, command: dict) -> tuple[dict, dict, bool]:
        """純領域判定與狀態提案，不執行 SQL 或副作用；拒絕不合法的庫存資料。"""
        proposed = deepcopy(state)
        inventory = proposed.get("inventory")
        reservations = proposed.setdefault("reservations", {})
        if (not isinstance(inventory, dict) or not isinstance(reservations, dict)
                or any(not isinstance(sku, str) or type(value) is not int or value < 0
                       for sku, value in inventory.items())):
            raise WorldStoreError("invalid_synthetic_inventory_world")
        if operation == "reserve":
            sku, quantity = command["sku"], command["quantity"]
            if sku not in inventory:
                return state, {"code": "unknown_synthetic_sku"}, False
            if inventory[sku] < quantity:
                return state, {"code": "insufficient_synthetic_inventory"}, False
            reservation_id = uuid4().hex
            reservation = {"sku": sku, "quantity": quantity, "status": "reserved"}
            reservations[reservation_id] = reservation
            inventory[sku] -= quantity
            return proposed, {"reservation_id": reservation_id, **reservation}, True
        reservation_id = command["reservation_id"]
        reservation = reservations.get(reservation_id)
        if not isinstance(reservation, dict) or reservation.get("status") != "reserved":
            return state, {"code": "reservation_not_active"}, False
        sku, quantity = reservation.get("sku"), reservation.get("quantity")
        if sku not in inventory or type(quantity) is not int or quantity < 1:
            raise WorldStoreError("invalid_synthetic_inventory_world")
        inventory[sku] += quantity
        reservation["status"] = "cancelled"
        return proposed, {"reservation_id": reservation_id, **reservation}, True

    def _commit(self, binding, operation, command, expected_version, key, attempt, now) -> InventoryResult:
        """透過共用原子交易取得標準結果，再維持既有領域 status／replayed 與例外契約。"""
        outcome = self._commit_transaction(binding, operation, command, expected_version, key, attempt, now,
                                           require_saved_digest=False)
        committed = outcome.status in {"committed", "already_committed"}
        version = outcome.committed_state_version if committed else outcome.observed_state_version
        state_hash = outcome.committed_state_hash if committed else outcome.observed_state_hash
        if outcome.result is None or version is None or state_hash is None:
            raise WorldStoreError("operation_result_unverifiable")
        return InventoryResult("committed" if committed else "rejected", deepcopy(outcome.result),
                               version, state_hash, outcome.commit_attempt_id, replayed=outcome.replayed)

    def _persist_resources(self, connection, binding, operation, result, snapshot) -> None:
        """庫存事件本身沒有額外資源映射；購物車子類在此同一交易保存訂單 ID。"""

    def _after_event(self, state: dict, *, now: int) -> dict:
        """讓領域子類在提交前補充事件衍生欄位，基礎庫存提案維持原樣。"""
        return state

    def operation_result(self, binding: SessionBinding, attempt: UUID, *, now: int) -> InventoryResult | None:
        """重新確認當前 SessionBinding 後唯讀查該 World 的操作結果，不產生事件。"""
        with self._connection() as connection:
            params = self._binding_params(binding)
            active = connection.execute(
                "SELECT b.world_generation_id FROM session_heads h JOIN session_world_bindings b "
                "USING(environment_id,deployment_id,session_id,session_epoch) JOIN generation_controls g "
                "USING(world_generation_id) WHERE h.environment_id=%s AND h.deployment_id=%s AND h.session_id=%s "
                "AND h.session_epoch=%s AND NOT g.sealed AND g.emergency_revision IS NULL FOR SHARE OF h,b,g",
                params).fetchone()
            if active is None:
                raise WorldStoreError("operation_lookup_unverifiable")
            scope = WorldScope(environment_id=binding.environment_id, deployment_id=binding.deployment_id,
                               session_id=binding.session_id, world_generation_id=active[0])
            world = connection.execute(
                "SELECT version,expires_at,state,state_hash FROM world_snapshots WHERE environment_id=%s "
                "AND deployment_id=%s AND session_id=%s AND world_generation_id=%s FOR SHARE",
                self._scope_params(scope)).fetchone()
            snapshot = self._snapshot_from_row(scope, world)
            if snapshot.expires_at is not None and now >= snapshot.expires_at:
                raise WorldStoreError("session_world_expired")
            row = connection.execute(
                "SELECT status,result,state_version,state_hash,commit_attempt_id,result_encoding_version,result_digest "
                "FROM world_operations "
                "WHERE environment_id=%s AND deployment_id=%s AND session_id=%s AND world_generation_id=%s "
                "AND commit_attempt_id=%s", (*self._scope_params(snapshot.scope), attempt)).fetchone()
        if row and row[5:] != (None, None) and row[5:] != (
                1, operation_result_digest(row[1], row[2], row[3], row[4], row[0])):
            raise WorldStoreError("operation_result_unverifiable")
        return InventoryResult(*row[:5], replayed=True) if row else None
