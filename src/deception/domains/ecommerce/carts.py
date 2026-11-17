"""匿名合成購物車、資源 ID 隔離與下單／取消的庫存事件。"""

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import re
from uuid import UUID, uuid4
from datetime import datetime, timezone

from deception.world import WorldStoreError
from deception.world.models import WorldScope, canonical_state_hash
from deception.world.session import SessionBinding
from .inventory import InventoryResult, SyntheticInventory
from .native_time import validate_native_times


@dataclass(frozen=True)
class CartCreation:
    """返回新購物車的可信 binding 與可重試的已提交建立結果。"""

    binding: SessionBinding
    outcome: InventoryResult


class SyntheticCarts(SyntheticInventory):
    """只以伺服器登記的合成 cart／order ID 定位可寫世界，不依賴登入或 Cookie。"""

    write_modes = frozenset({"cart"})
    allowed_operations = frozenset({"cart.add", "cart.update", "cart.remove", "cart.complete", "cart.cancel_order"})

    def create_cart(self, creator: SessionBinding, *, catalog: dict, inventory: dict,
                    idempotency_key: UUID, commit_attempt_id: UUID, now: int, ttl: int,
                    native_context: dict | None = None, initial_items: list | None = None,
                    creation_digest: str | None = None) -> CartCreation:
        """以新隨機 cart ID 原子建立資源與世界，相同建立鍵回傳原結果。

        creator 只作已驗證的建立請求分組。購物車後續憑原生資源 ID 存取，
        不使用 IP／UA 來判斷同一個人。catalog 與 inventory 必須由部署的合成資料供應。
        native_context 為適配器已驗證的地區及聯絡欄位；initial_items 在初始化交易
        內套用，不預留庫存。creation_digest 綁定原生建立內容，同鍵異內容或初始
        品項不可接受時整筆回滾。成功同時保存資源、快照、收據與原生回應上下文。
        """
        if (not isinstance(idempotency_key, UUID) or idempotency_key.version != 4
                or not isinstance(commit_attempt_id, UUID) or commit_attempt_id.version != 4
                or type(ttl) is not int or ttl < 1):
            raise ValueError("cart creation requires UUIDv4 metadata and positive lifetime")
        if creation_digest is not None and not re.fullmatch(r"[0-9a-f]{64}", creation_digest):
            raise ValueError("invalid cart creation digest")
        params = self._binding_params(creator)
        lock_key = json.dumps([*params, str(idempotency_key)])
        with self._connection() as connection:
            current = connection.execute(
                "SELECT session_epoch FROM session_heads WHERE environment_id=%s AND deployment_id=%s "
                "AND session_id=%s FOR SHARE", params[:3]).fetchone()
            if current != (creator.session_epoch,):
                raise WorldStoreError("session_epoch_stale")
            connection.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", (lock_key,))
            previous = connection.execute(
                "SELECT cart_id,operation_result,state_version,state_hash,commit_attempt_id,operation_digest FROM guest_cart_creations "
                "WHERE environment_id=%s AND deployment_id=%s AND creator_session_id=%s AND creator_epoch=%s "
                "AND idempotency_key=%s", (*params, idempotency_key)).fetchone()
            if previous:
                if previous[5] != creation_digest:
                    raise WorldStoreError("idempotency_content_conflict")
                binding = self._resource_binding(connection, previous[0], creator.environment_id,
                                                 creator.deployment_id, now)
                return CartCreation(binding, InventoryResult("committed", *previous[1:5], replayed=True))
            cart_id = "cart_" + uuid4().hex
            binding = SessionBinding(environment_id=creator.environment_id, deployment_id=creator.deployment_id,
                session_id=uuid4().hex, session_epoch=1, resource_id=cart_id, access_mode="cart")
            cart = {"id": cart_id, "items": {}, "currency_code": "usd", "total": 0, "status": "active"}
            state = {"catalog": deepcopy(catalog), "inventory": deepcopy(inventory), "reservations": {},
                     "cart": cart, "orders": {}}
            self._validate_catalog(state)
            if native_context is not None:
                state["native_context"] = deepcopy(native_context)
                state["native_context"].update(created_at=self._event_time(now), updated_at=self._event_time(now))
            for item in initial_items or []:
                if not isinstance(item, dict) or set(item) != {"variant_id", "quantity"}:
                    raise ValueError("invalid initial cart item")
                state, rejected, accepted = self._apply(state, "cart.add", {**item, "resource_id": cart_id})
                if not accepted:
                    raise WorldStoreError(rejected["code"])
            cart = state["cart"]
            snapshot = self._resolve_in_transaction(connection, binding, state, now=now, ttl=ttl)
            result = self.public_cart(cart)
            connection.execute("INSERT INTO synthetic_resources VALUES (%s,'cart',%s,%s,%s,%s,%s,%s)",
                (cart_id, *params[:2], binding.session_id, binding.session_epoch,
                 snapshot.scope.world_generation_id, snapshot.expires_at))
            connection.execute("INSERT INTO guest_cart_creations VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s,%s)",
                (*params, idempotency_key, cart_id, json.dumps(result), snapshot.version,
                 snapshot.state_hash, commit_attempt_id, creation_digest))
            connection.execute("INSERT INTO world_commit_receipts VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (*self._scope_params(snapshot.scope), commit_attempt_id, snapshot.version, snapshot.state_hash))
            self._persist_native_context(connection, snapshot, commit_attempt_id)
        return CartCreation(binding, InventoryResult("committed", result, snapshot.version,
                                                     snapshot.state_hash, commit_attempt_id))

    @staticmethod
    def _event_time(now: int) -> str:
        """將受信任事件時間轉成原生資源的 UTC 毫秒時間，不讀取訪客時間。"""
        return datetime.fromtimestamp(now, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def _after_event(self, state: dict, *, now: int) -> dict:
        """在同一快照提案維持原生資源時間單調，不改 Lease、授權期限或舊合成契約。

        接收端時鐘回撥時沿用既有邏輯更新時間；新訂單不得早於購物車。
        已保存的時間必須仍為伺服器使用的 UTC 毫秒格式，損壞時拒絕提案。
        """
        if "native_context" in state:
            context = state["native_context"]
            effective = max(self._event_time(now), validate_native_times(context))
            context["updated_at"] = effective
            if state["orders"] and "order_created_at" not in context:
                context["order_created_at"] = effective
        return state

    @staticmethod
    def _validate_catalog(state):
        """核對部署提供的價格與庫存均為非負整數，避免 Client 任意輸入權威數據。"""
        if not isinstance(state["catalog"], dict) or not isinstance(state["inventory"], dict):
            raise WorldStoreError("invalid_synthetic_cart_catalog")
        for variant, item in state["catalog"].items():
            if (not isinstance(variant, str) or not isinstance(item, dict)
                    or not isinstance(item.get("sku"), str) or type(item.get("unit_price")) is not int
                    or item["unit_price"] < 0 or item["sku"] not in state["inventory"]
                    or type(state["inventory"][item["sku"]]) is not int or state["inventory"][item["sku"]] < 0):
                raise WorldStoreError("invalid_synthetic_cart_catalog")

    @staticmethod
    def public_cart(cart: dict) -> dict:
        """把內部品項索引投影成固定購物車回應，不輸出世界或客戶身份。"""
        return {**cart, "items": list(cart["items"].values())}

    def resource_binding(self, resource_id: str, *, environment_id: str, deployment_id: str, now: int):
        """只解析伺服器已核發、當前且未封存的合成資源 ID；未知 ID 不讀真實 Backend。"""
        if not re.fullmatch(r"(?:cart|order)_[0-9a-f]{32}", resource_id):
            raise WorldStoreError("synthetic_resource_unverifiable")
        with self._connection() as connection:
            return self._resource_binding(connection, resource_id, environment_id, deployment_id, now)

    def _resource_binding(self, connection, resource_id, environment_id, deployment_id, now):
        """在同一交易核對資源 scope、當前 epoch、期限、世界完整性與版本政策。"""
        row = connection.execute(
            "SELECT r.session_id,r.session_epoch,r.expires_at,r.world_generation_id,"
            "w.version,w.expires_at,w.state,w.state_hash FROM synthetic_resources r "
            "JOIN session_heads h USING(environment_id,deployment_id,session_id,session_epoch) "
            "JOIN generation_controls g USING(world_generation_id) "
            "JOIN world_snapshots w USING(environment_id,deployment_id,session_id,world_generation_id) WHERE r.resource_id=%s "
            "AND r.environment_id=%s AND r.deployment_id=%s AND NOT g.sealed AND g.emergency_revision IS NULL "
            "FOR SHARE OF r,h,g", (resource_id, environment_id, deployment_id)).fetchone()
        if row is None or now >= row[2]:
            raise WorldStoreError("synthetic_resource_unverifiable")
        scope = WorldScope(environment_id=environment_id, deployment_id=deployment_id,
                           session_id=row[0], world_generation_id=row[3])
        snapshot = self._snapshot_from_row(scope, row[4:])
        if snapshot.expires_at is not None and now >= snapshot.expires_at:
            raise WorldStoreError("synthetic_resource_unverifiable")
        return SessionBinding(environment_id=environment_id, deployment_id=deployment_id, session_id=row[0],
                              session_epoch=row[1], resource_id=resource_id, access_mode="cart")

    def mutate_cart(self, binding: SessionBinding, *, action: str, command: dict, expected_version: int,
                    idempotency_key: str, commit_attempt_id: UUID, now: int) -> InventoryResult:
        """提交 add／update／remove／complete／cancel_order，所有權威價格取自合成 catalog。"""
        if action not in {"add", "update", "remove", "complete", "cancel_order"}:
            raise ValueError("unsupported synthetic cart operation")
        if not binding.resource_id:
            raise WorldStoreError("synthetic_resource_unverifiable")
        command = {**deepcopy(command), "resource_id": binding.resource_id}
        outcome = self._commit(binding, "cart." + action, command, expected_version,
                               idempotency_key, commit_attempt_id, now)
        return outcome

    @staticmethod
    def _apply(state, operation, command):
        """產生購物車／訂單的合法狀態提案，只有下單與取消訂單會改庫存。"""
        proposed = deepcopy(state)
        SyntheticCarts._validate_catalog(proposed)
        cart, action = proposed["cart"], operation.removeprefix("cart.")
        if action == "cancel_order":
            order = proposed["orders"].get(command["resource_id"])
            if order is None or order["status"] != "placed":
                return state, {"code": "order_not_cancellable"}, False
            for item in order["items"]:
                proposed["inventory"][item["sku"]] += item["quantity"]
            order["status"] = "cancelled"
            return proposed, deepcopy(order), True
        if cart["id"] != command["resource_id"] or cart["status"] != "active":
            return state, {"code": "cart_not_active"}, False
        items = cart["items"]
        if action in {"add", "update"}:
            quantity = command.get("quantity")
            if type(quantity) is not int or quantity < 1:
                raise ValueError("cart quantity must be a positive integer")
            if action == "add":
                variant = command.get("variant_id")
                definition = proposed["catalog"].get(variant)
                if definition is None:
                    return state, {"code": "unknown_synthetic_variant"}, False
                existing = next((item for item in items.values() if item["variant_id"] == variant), None)
                identifier = existing["id"] if existing else "item_" + uuid4().hex
                quantity += existing["quantity"] if existing else 0
                items[identifier] = {"id": identifier, "variant_id": variant, "sku": definition["sku"],
                                     "unit_price": definition["unit_price"], "quantity": quantity}
            else:
                identifier = command.get("item_id")
                if identifier not in items:
                    return state, {"code": "cart_item_not_found"}, False
                items[identifier]["quantity"] = quantity
            required = {}
            for item in items.values():
                required[item["sku"]] = required.get(item["sku"], 0) + item["quantity"]
            if any(value > proposed["inventory"][sku] for sku, value in required.items()):
                return state, {"code": "insufficient_synthetic_inventory"}, False
        elif action == "remove":
            if command.get("item_id") not in items:
                return state, {"code": "cart_item_not_found"}, False
            del items[command["item_id"]]
        elif action == "complete":
            if not items:
                return state, {"code": "empty_synthetic_cart"}, False
            for item in items.values():
                if proposed["inventory"][item["sku"]] < item["quantity"]:
                    return state, {"code": "insufficient_synthetic_inventory"}, False
                proposed["inventory"][item["sku"]] -= item["quantity"]
            order = {"id": "order_" + uuid4().hex, "cart_id": cart["id"], "items": list(items.values()),
                     "total": cart["total"], "currency_code": cart["currency_code"], "status": "placed"}
            proposed["orders"][order["id"]] = order
            cart["status"] = "completed"
            return proposed, deepcopy(order), True
        else:
            raise ValueError("unsupported synthetic cart event")
        cart["total"] = sum(item["quantity"] * item["unit_price"] for item in items.values())
        return proposed, SyntheticCarts.public_cart(cart), True

    def _persist_resources(self, connection, binding, operation, result, snapshot) -> None:
        """在訂單事件交易內原子保存 order.id 對應的合成世界，回滾時一起移除。"""
        if operation == "cart.complete":
            connection.execute("INSERT INTO synthetic_resources VALUES (%s,'order',%s,%s,%s,%s,%s,%s)",
                (result["id"], binding.environment_id, binding.deployment_id, binding.session_id,
                 binding.session_epoch, snapshot.scope.world_generation_id, snapshot.expires_at))
        if operation.startswith("cart.") and "native_context" in snapshot.state:
            attempt, = connection.execute("SELECT commit_attempt_id FROM world_operations WHERE environment_id=%s "
                "AND deployment_id=%s AND session_id=%s AND world_generation_id=%s AND state_version=%s "
                "AND status='committed'", (*self._scope_params(snapshot.scope), snapshot.version)).fetchone()
            self._persist_native_context(connection, snapshot, attempt)

    def _persist_native_context(self, connection, snapshot, attempt) -> None:
        """與原事件同交易保存原生回應上下文，避免重試拼入後續時間或 catalog。"""
        if "native_context" not in snapshot.state:
            return
        context = {**snapshot.state["native_context"], "catalog": snapshot.state["catalog"]}
        connection.execute("INSERT INTO native_response_contexts VALUES (%s,%s,%s,%s,%s,%s::jsonb,%s)",
            (*self._scope_params(snapshot.scope), attempt, json.dumps(context), canonical_state_hash(context)))

    def native_response_context(self, binding: SessionBinding, attempt: UUID, *, now: int) -> dict:
        """重新核對有效資源能力後，唯讀查該次原生提交的上下文；查無時停止而不猜測。"""
        with self._connection() as connection:
            active = self._resource_binding(connection, binding.resource_id, binding.environment_id,
                                             binding.deployment_id, now)
            if active != binding:
                raise WorldStoreError("native_context_authority_mismatch")
            row = connection.execute("SELECT c.context,c.context_hash FROM native_response_contexts c "
                "JOIN session_world_bindings b USING(environment_id,deployment_id,session_id,world_generation_id) "
                "WHERE c.environment_id=%s AND c.deployment_id=%s AND c.session_id=%s AND b.session_epoch=%s "
                "AND c.commit_attempt_id=%s", (*self._binding_params(binding), attempt)).fetchone()
        if row is None:
            raise WorldStoreError("native_context_unavailable")
        if canonical_state_hash(row[0]) != row[1]:
            raise WorldStoreError("native_context_corrupted")
        return row[0]
