"""由獨立 World Executor 建立不可被 Runtime 偽造的 Read／Commit 來源證據。"""

from __future__ import annotations

from copy import deepcopy
import json
import re
from types import MappingProxyType
from uuid import UUID

from deception.security.key_revocation import PostgresTrustedKeyRevocations
from deception.security.operation_binding import (
    VerifiedOperationBinding, decode_verified_cart_mutation,
    decode_verified_inventory_mutation,
)

from .commit import CommitResult, validate_commit_metadata
from .event_store import PostgresEventWorldStore, prepare_event_command
from .models import WorldScope
from .protected_grant import (_ProtectedConnection, ProtectedGrantError,
                              _protected_lock, _require_digest, _scope_values)
from .session import PostgresSessionWorlds, SessionBinding, WorldRead
from .transmission import response_hashes


class PostgresProtectedWorldExecutor(_ProtectedConnection):
    """僅用專用實體 DB Login 執行固定 World 業務與來源見證，不共用 HTTP Runtime Pool。"""

    def __init__(self, dsn: str, *, expected_login: str,
                 world_store: PostgresEventWorldStore,
                 cart_initial_state: dict | None = None,
                 rejection_templates: dict[str, str] | None = None) -> None:
        """綁定由部署者預先配置固定 handlers／write_modes 的 World Store。

        所有信任用的 DB 交易都經 `_connection` 檢查實體 Login。正式 HTTP
        Runtime 不可持有本角色憑證或直接授權寫入此服務的 protected tables。
        """
        super().__init__(dsn, expected_login=expected_login)
        if not isinstance(world_store, PostgresEventWorldStore) or world_store._dsn != dsn:
            raise ProtectedGrantError("protected_world_store_mismatch")
        self._world_store = world_store
        self._reads = PostgresSessionWorlds(dsn, compatibility=world_store._compatibility)
        self._cart_initial_state = deepcopy(cart_initial_state)
        templates = rejection_templates or {}
        if not isinstance(templates, dict) or any(
                not isinstance(code, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,127}", code) is None
                or not isinstance(revision, str) or not 1 <= len(revision) <= 128
                for code, revision in templates.items()):
            raise ProtectedGrantError("protected_rejection_templates_invalid")
        self._rejection_templates = MappingProxyType(dict(templates))

    def create_cart(self, *, receipt_id: UUID, creator: SessionBinding,
                    request_fingerprint: str, idempotency_key: UUID,
                    commit_attempt_id: UUID, creation_digest: str,
                    ttl: int) -> object:
        """在同一受保護交易產生衍生 Cart Scope、資源映射及一次性 Creator Lineage。

        僅支援部署端預先固定的合成 Cart 初始資料；不能使用 Runtime 提供的
        catalog、inventory 或任意初始世界。Receipt 的 creator Scope 不等於
        新 Cart Scope；重試只回傳完全相同的既有結果，否則整筆回滾。
        """
        from deception.domains.ecommerce.carts import SyntheticCarts

        if not isinstance(self._world_store, SyntheticCarts) or self._cart_initial_state is None:
            raise ProtectedGrantError("protected_cart_handler_unavailable")
        if type(ttl) is not int or not 60 <= ttl <= 3600:
            raise ProtectedGrantError("protected_cart_ttl_out_of_policy")
        if not isinstance(self._cart_initial_state, dict) or set(self._cart_initial_state) != {"catalog", "inventory"}:
            raise ProtectedGrantError("protected_cart_initial_state_invalid")
        _require_digest(creation_digest)
        if creator.access_mode != "cart" or creator.resource_id is not None:
            raise ProtectedGrantError("protected_cart_creator_capability_invalid")
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET LOCAL lock_timeout='3s'")
                self._verify_receipt(cursor, receipt_id=receipt_id, binding=creator,
                                     fingerprint=request_fingerprint)
                cursor.execute(
                    """SELECT environment_id,deployment_id,creator_session_id,creator_epoch,
                              idempotency_key,commit_attempt_id,request_fingerprint,
                              operation_digest,derived_session_id,derived_world_generation_id,
                              resource_id FROM protected_cart_creations WHERE receipt_id=%s""",
                    (receipt_id,),
                )
                previous = cursor.fetchone()
                expected = (*PostgresSessionWorlds._binding_params(creator),
                            idempotency_key, commit_attempt_id, request_fingerprint,
                            creation_digest)
                if previous is not None and previous[:8] != expected:
                    raise ProtectedGrantError("protected_cart_receipt_rebound")
                if previous is None:
                    cursor.execute(
                        """SELECT 1 FROM guest_cart_creations
                           WHERE environment_id=%s AND deployment_id=%s
                             AND creator_session_id=%s AND creator_epoch=%s
                             AND idempotency_key=%s""", expected[:5],
                    )
                    if cursor.fetchone() is not None:
                        raise ProtectedGrantError("untrusted_prior_cart_creation")
                cursor.execute("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                now = cursor.fetchone()[0]
                initial = self._cart_initial_state
                created = self._world_store.create_cart(
                    creator, catalog=deepcopy(initial["catalog"]),
                    inventory=deepcopy(initial["inventory"]),
                    idempotency_key=idempotency_key, commit_attempt_id=commit_attempt_id,
                    creation_digest=creation_digest, now=now, ttl=ttl,
                    _trusted_connection=connection,
                )
                derived_scope = self._world_store._resource_binding(
                    connection, created.binding.resource_id, creator.environment_id,
                    creator.deployment_id, now,
                )
                if derived_scope != created.binding:
                    raise ProtectedGrantError("protected_cart_resource_binding_mismatch")
                cursor.execute(
                    """SELECT world_generation_id FROM session_world_bindings
                       WHERE environment_id=%s AND deployment_id=%s AND session_id=%s
                         AND session_epoch=%s""",
                    PostgresSessionWorlds._binding_params(created.binding),
                )
                generation = cursor.fetchone()
                if generation is None:
                    raise ProtectedGrantError("protected_cart_generation_missing")
                actual = (created.binding.session_id, generation[0],
                          created.binding.resource_id)
                if previous is not None:
                    if previous[8:] != actual:
                        raise ProtectedGrantError("protected_cart_derived_scope_mismatch")
                    return created
                cursor.execute(
                    """INSERT INTO protected_cart_creations (
                           receipt_id,environment_id,deployment_id,creator_session_id,
                           creator_epoch,idempotency_key,commit_attempt_id,
                           request_fingerprint,operation_digest,derived_session_id,
                           derived_world_generation_id,resource_id)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (receipt_id, *expected, *actual),
                )
                return created

    def _verify_receipt(self, cursor, *, receipt_id: UUID, binding: SessionBinding,
                        fingerprint: str) -> WorldScope:
        """依既定 Session→Binding→Receipt→Generation→Key 順序鎖定並核對來源能力。

        `access_mode`／`resource_id` 只取自獨立 Verifier 原始 Receipt，不能
        接受呼叫者自稱 inventory/cart；舊版缺少能力欄位的 Receipt 固定拒絕。
        """
        if not isinstance(receipt_id, UUID) or receipt_id.version != 4:
            raise ProtectedGrantError("invalid_world_receipt_id")
        _require_digest(fingerprint)
        cursor.execute("SELECT current_setting('transaction_isolation')")
        if cursor.fetchone()[0] != "read committed":
            raise ProtectedGrantError("protected_world_requires_read_committed")
        binding = SessionBinding.model_validate(binding.model_dump())
        identity = {"environment_id": binding.environment_id,
                    "deployment_id": binding.deployment_id, "session_id": binding.session_id}
        if not _protected_lock(cursor, "session_head", identity):
            raise ProtectedGrantError("protected_world_session_missing")
        cursor.execute(
            """SELECT session_epoch FROM session_heads WHERE environment_id=%s
               AND deployment_id=%s AND session_id=%s""",
            (binding.environment_id, binding.deployment_id, binding.session_id),
        )
        head = cursor.fetchone()
        if head is None or head[0] != binding.session_epoch:
            raise ProtectedGrantError("protected_world_epoch_stale")
        cursor.execute(
            """SELECT world_generation_id FROM session_world_bindings
               WHERE environment_id=%s AND deployment_id=%s AND session_id=%s
                 AND session_epoch=%s FOR UPDATE""",
            (binding.environment_id, binding.deployment_id,
             binding.session_id, binding.session_epoch),
        )
        generation = cursor.fetchone()
        if generation is None:
            raise ProtectedGrantError("protected_world_generation_missing")
        if not _protected_lock(cursor, "receipt", {"receipt_id": str(receipt_id)}):
            raise ProtectedGrantError("protected_world_receipt_missing")
        cursor.execute(
            """SELECT environment_id,deployment_id,session_id,session_epoch,
                      request_fingerprint,issuer,key_id,token_expires_at,
                      access_mode,resource_id
               FROM ingress_receipts WHERE receipt_id=%s""", (receipt_id,),
        )
        receipt = cursor.fetchone()
        if (receipt is None or receipt[:5] !=
                (binding.environment_id, binding.deployment_id, binding.session_id,
                 binding.session_epoch, fingerprint)
                or receipt[8:10] != (binding.access_mode, binding.resource_id)):
            raise ProtectedGrantError("protected_world_receipt_capability_mismatch")
        cursor.execute("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
        db_now = cursor.fetchone()[0]
        if db_now >= receipt[7]:
            raise ProtectedGrantError("protected_world_receipt_expired")
        cursor.execute(
            """SELECT sealed,emergency_revision FROM generation_controls
               WHERE world_generation_id=%s FOR UPDATE""", (generation[0],),
        )
        state = cursor.fetchone()
        if state is None or state[0] or state[1] is not None:
            raise ProtectedGrantError("protected_world_generation_revoked")
        key = PostgresTrustedKeyRevocations(
            self._dsn,
            environment_id=binding.environment_id, deployment_id=binding.deployment_id,
        )
        key._lock(cursor, receipt[5], receipt[6])
        if key._select(cursor, receipt[5], receipt[6]) is not None:
            raise ProtectedGrantError("protected_world_key_revoked")
        if binding.access_mode == "cart" and binding.resource_id is not None:
            cursor.execute(
                """SELECT 1 FROM protected_cart_creations p
                   JOIN synthetic_resources r
                     ON r.environment_id=p.environment_id
                    AND r.deployment_id=p.deployment_id
                    AND r.session_id=p.derived_session_id
                    AND r.world_generation_id=p.derived_world_generation_id
                   WHERE p.environment_id=%s AND p.deployment_id=%s
                     AND p.derived_session_id=%s AND p.derived_world_generation_id=%s
                     AND r.resource_id=%s""",
                (binding.environment_id, binding.deployment_id,
                 binding.session_id, generation[0], binding.resource_id),
            )
            if cursor.fetchone() is None:
                raise ProtectedGrantError("protected_world_cart_lineage_missing")
        return WorldScope(environment_id=binding.environment_id,
                          deployment_id=binding.deployment_id, session_id=binding.session_id,
                          world_generation_id=generation[0])

    def admit_read(self, *, receipt_id: UUID, binding: SessionBinding,
                   request_fingerprint: str, expires_at: int) -> WorldRead:
        """在同一 PostgreSQL Transaction 建立 ReadAdmission 與不可變來源證明。

        有效期以資料庫時計算，受 JWS exp 限制；無 Receipt／Epoch／Snapshot
        或 Key 撤銷不能建立可信來源；網路 COMMIT 不明時呼叫端不得盲目重做。
        """
        checked = SessionBinding.model_validate(binding.model_dump())
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET LOCAL lock_timeout='3s'")
                scope = self._verify_receipt(
                    cursor, receipt_id=receipt_id, binding=checked,
                    fingerprint=request_fingerprint,
                )
                cursor.execute("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                now = cursor.fetchone()[0]
                cursor.execute("SELECT token_expires_at FROM ingress_receipts WHERE receipt_id=%s",
                               (receipt_id,))
                token_expires = cursor.fetchone()[0]
                if (type(expires_at) is not int or expires_at <= now
                        or expires_at > token_expires):
                    raise ProtectedGrantError("protected_world_read_deadline_invalid")
                read = self._reads.admit_read(
                    checked, request_binding_digest=request_fingerprint,
                    now=now, expires_at=expires_at, _trusted_connection=connection,
                )
                if read.snapshot.scope != scope:
                    raise ProtectedGrantError("protected_world_read_scope_mismatch")
                cursor.execute(
                    """INSERT INTO protected_world_read_sources (
                           read_admission_id,receipt_id,environment_id,deployment_id,
                           session_id,world_generation_id,request_fingerprint,
                           state_version,state_hash)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (read.source.read_admission_id, receipt_id, *_scope_values(scope),
                     request_fingerprint, read.source.state_version, read.source.state_hash),
                )
                return read

    def commit_verified_inventory_http(
        self, *, receipt_id: UUID, binding: SessionBinding,
        authorized_scope: WorldScope, raw_path: bytes, raw_body: bytes,
    ) -> CommitResult:
        """僅按受保護 Receipt 的原始 HTTP Operation 決定庫存 Handler 與參數。

        呼叫端不能指定 `operation`、`expected_version`、`idempotency_key` 或
        `commit_attempt_id`，它們全由原始 body 模型還原。舊 Proof 沒有原始
        path／Content-Type 時固定拒絕。Proof 不可變；實際提交仍由
        `commit_event` 在新交易重查 Receipt／Read Source／Generation／Key。
        獨立 mTLS 業務路由尚未啟用，不能把此 primitive 當作 HTTP 接線完成。
        """
        from deception.domains.ecommerce.inventory import SyntheticInventory

        if not isinstance(self._world_store, SyntheticInventory) or self._world_store.write_modes != frozenset({"inventory"}):
            raise ProtectedGrantError("verified_inventory_handler_unavailable")
        proof = self._http_operation_proof(receipt_id)
        mutation = decode_verified_inventory_mutation(
            proof, raw_path=raw_path, raw_body=raw_body,
        )
        return self.commit_event(
            receipt_id=receipt_id, binding=binding,
            request_fingerprint=proof.request_fingerprint,
            authorized_scope=authorized_scope, operation=mutation.operation,
            command=mutation.command, expected_version=mutation.expected_version,
            idempotency_key=mutation.idempotency_key,
            commit_attempt_id=mutation.commit_attempt_id,
        )

    def _http_operation_proof(self, receipt_id: UUID) -> VerifiedOperationBinding:
        """只用專屬 Executor DB Login 按 Receipt 取回不可變的 Verifier HTTP Proof。"""
        if not isinstance(receipt_id, UUID) or receipt_id.version != 4:
            raise ProtectedGrantError("invalid_world_receipt_id")
        with self._connection() as connection:
            row = connection.execute(
                """SELECT platform,operation_id,method,path_template,request_fingerprint,
                          request_body_sha256,request_path,request_content_type
                   FROM protected_http_operation_bindings WHERE receipt_id=%s""",
                (receipt_id,),
            ).fetchone()
        if row is None or row[6] is None:
            raise ProtectedGrantError("verified_http_operation_proof_missing")
        return VerifiedOperationBinding(*row)

    def commit_verified_cart_http(
        self, *, receipt_id: UUID, binding: SessionBinding,
        authorized_scope: WorldScope, raw_path: bytes, raw_body: bytes,
    ) -> CommitResult:
        """僅由 Receipt 精確 HTTP path/body 映射 Cart／Order 固定事件與提交鍵。

        不接受 Runtime 自稱 action、品項、資源 ID 或提交鍵；它們必須全部
        來自 Verifier 原始 Request 與已簽 Receipt capability。這是受保護內部
        primitive，尚未暴露為 mTLS／正式 Trusted HTTP 業務 RPC。
        """
        from deception.domains.ecommerce.carts import SyntheticCarts

        if not isinstance(self._world_store, SyntheticCarts):
            raise ProtectedGrantError("verified_cart_handler_unavailable")
        checked = SessionBinding.model_validate(binding.model_dump())
        if checked.access_mode != "cart" or not checked.resource_id:
            raise ProtectedGrantError("verified_cart_resource_capability_denied")
        # 只有從可信 Creator Receipt 原子派生的 World 可以進入正式 Cart RPC。
        # 不能把 Runtime 先前建立的 guest_cart_creations 當作可信來源。
        with self._connection() as connection:
            lineage = connection.execute(
                """SELECT 1 FROM protected_cart_creations
                   WHERE environment_id=%s AND deployment_id=%s
                     AND derived_session_id=%s AND derived_world_generation_id=%s""",
                (checked.environment_id, checked.deployment_id, checked.session_id,
                 authorized_scope.world_generation_id),
            ).fetchone()
        if lineage is None:
            raise ProtectedGrantError("verified_cart_derived_lineage_missing")
        proof = self._http_operation_proof(receipt_id)
        mutation = decode_verified_cart_mutation(
            proof, receipt_id=receipt_id, resource_id=checked.resource_id,
            raw_path=raw_path, raw_body=raw_body,
        )
        return self.commit_event(
            receipt_id=receipt_id, binding=binding,
            request_fingerprint=proof.request_fingerprint,
            authorized_scope=authorized_scope, operation=mutation.operation,
            command=mutation.command, expected_version=mutation.expected_version,
            idempotency_key=mutation.idempotency_key,
            commit_attempt_id=mutation.commit_attempt_id,
        )

    def commit_event(self, *, receipt_id: UUID, binding: SessionBinding,
                     request_fingerprint: str, authorized_scope: WorldScope,
                     operation: str, command: dict, expected_version: int,
                     idempotency_key: str, commit_attempt_id: UUID) -> CommitResult:
        """用固定純 Handler 將 World Mutation 與不可偽造 Commit Source 原子提交。

        維持原本業務結果與冪等操作鍵；只有同一 Receipt 已經建立受保護
        ReadAdmission 才能寫入，舊 Runtime 所建 `world_operations` 不能補簽。
        任何例外或 COMMIT 結果不明都向上拋出，禁止當成已拒絕而重做副作用。
        """
        checked = SessionBinding.model_validate(binding.model_dump())
        prepared = prepare_event_command(command)
        # 固定參數在取得 DB 連線前驗證，避免無效命令消耗特權連線配額。
        validate_commit_metadata(operation, expected_version, idempotency_key,
                                 commit_attempt_id, 0)
        if checked.access_mode not in self._world_store.write_modes:
            raise ProtectedGrantError("protected_world_write_mode_denied")
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET LOCAL lock_timeout='3s'")
                scope = self._verify_receipt(
                    cursor, receipt_id=receipt_id, binding=checked,
                    fingerprint=request_fingerprint,
                )
                if scope != authorized_scope:
                    raise ProtectedGrantError("protected_world_commit_scope_mismatch")
                cursor.execute(
                    """SELECT 1 FROM protected_world_read_sources WHERE receipt_id=%s
                       AND environment_id=%s AND deployment_id=%s AND session_id=%s
                       AND world_generation_id=%s AND request_fingerprint=%s""",
                    (receipt_id, *_scope_values(scope), request_fingerprint),
                )
                if cursor.fetchone() is None:
                    raise ProtectedGrantError("protected_world_read_source_missing")
                cursor.execute("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                now = cursor.fetchone()[0]
                result = self._world_store._commit_transaction(
                    checked, operation, command, expected_version,
                    idempotency_key, commit_attempt_id, now,
                    authorized_scope=scope, prepared_command=prepared,
                    _trusted_connection=connection,
                )
                if result.status == "already_committed":
                    cursor.execute(
                        """SELECT result_digest FROM protected_world_commit_sources
                           WHERE commit_attempt_id=%s AND receipt_id=%s""",
                        (result.commit_attempt_id, receipt_id),
                    )
                    proof = cursor.fetchone()
                    if proof is None or proof[0] != result.result_digest:
                        raise ProtectedGrantError("untrusted_prior_world_commit")
                    return result
                if result.status == "rejected" and result.result is not None:
                    code = result.result.get("code")
                    revision = self._rejection_templates.get(code) if isinstance(code, str) else None
                    if revision is None or result.failure_code != code:
                        raise ProtectedGrantError("protected_world_rejection_template_denied")
                    body = json.dumps({"code": code}, ensure_ascii=False, sort_keys=True,
                                      separators=(",", ":")).encode("utf-8")
                    envelope_hash = response_hashes(
                        409, (("content-type", "application/json"),), body,
                    )[0]
                    if result.replayed:
                        cursor.execute(
                            """SELECT result_digest,template_id,contract_revision,envelope_hash
                               FROM protected_world_rejection_sources
                               WHERE commit_attempt_id=%s AND receipt_id=%s
                                 AND environment_id=%s AND deployment_id=%s
                                 AND session_id=%s AND world_generation_id=%s
                                 AND request_fingerprint=%s AND operation=%s""",
                            (result.commit_attempt_id, receipt_id, *_scope_values(scope),
                             request_fingerprint, operation),
                        )
                        if cursor.fetchone() != (result.result_digest, code, revision, envelope_hash):
                            raise ProtectedGrantError("untrusted_prior_world_rejection")
                        return result
                    cursor.execute(
                        """INSERT INTO protected_world_rejection_sources (
                               commit_attempt_id,receipt_id,environment_id,deployment_id,
                               session_id,world_generation_id,request_fingerprint,
                               operation,result_digest,template_id,contract_revision,envelope_hash)
                           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (result.commit_attempt_id, receipt_id, *_scope_values(scope),
                         request_fingerprint, operation, result.result_digest,
                         code, revision, envelope_hash),
                    )
                    return result
                if result.status != "committed":
                    return result
                cursor.execute(
                    """INSERT INTO protected_world_commit_sources (
                           commit_attempt_id,receipt_id,environment_id,deployment_id,
                           session_id,world_generation_id,request_fingerprint,operation,
                           command_digest,result_digest,state_version,state_hash)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (result.commit_attempt_id, receipt_id, *_scope_values(scope),
                     request_fingerprint, operation, prepared[1], result.result_digest,
                     result.committed_state_version, result.committed_state_hash),
                )
                return result
