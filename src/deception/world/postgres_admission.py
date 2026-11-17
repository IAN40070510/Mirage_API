"""PostgreSQL 共享 ResponseAdmission 交易控制。"""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

from .admission import AdmissionOperationResult, AdmissionState
from .models import ProjectionEvidence, ResponseAdmission, ResponseSource
from .postgres_store import psycopg
from .projection_registry import ProjectionAuthorizationResult, PostgresProjectionRegistry
from .store import WorldStoreError, WorldStoreStatus
from .request_audit import PostgresRequestAudit, RequestAuditLink


class PostgresAdmissionControl:
    """以 Generation row lock 實作跨 Instance 的准入狀態機。"""

    def __init__(self, dsn: str) -> None:
        """建立共享准入控制器；連線在每次交易開始時建立。"""
        if not dsn.strip():
            raise ValueError("dsn must not be empty")
        self._dsn = dsn

    def grant(
        self,
        *,
        world_generation_id: str,
        request_binding_digest: str,
        candidate_ref: str,
        candidate_hash: str,
        immutable_body_hash: str,
        semantic_headers_hash: str,
        projection_contract_hash: str,
        authorization_revision: str,
        authorization_deadline: int,
        transmission_deadline: int,
        source: ResponseSource,
        projection_evidence: ProjectionEvidence,
        projection_registry: PostgresProjectionRegistry,
        request_audit: RequestAuditLink | None = None,
    ) -> ResponseAdmission | None:
        """在同一交易鎖住世代與核准列並建立 Grant，拒絕不共用儲存的 Registry。

        request_audit 是可信最終 Renderer 提供的既有觀察與通過結果；提供時必須
        與 Grant 同交易保存，內容不符或保存失敗會使整張 Grant 回滾。舊控制面
        原型可省略，正式 HTTP 入口一律提供；此參數不接收訪客自填的驗證結論。
        """
        if not isinstance(projection_registry, PostgresProjectionRegistry) or not projection_registry.shares_store(self._dsn):
            return None
        with self._connection() as connection:
            with connection.cursor() as cursor:
                self._ensure_generation(cursor, world_generation_id)
                cursor.execute(
                    """
                    SELECT control_revision, sealed, emergency_revision
                    FROM generation_controls
                    WHERE world_generation_id = %s
                    FOR UPDATE
                    """,
                    (world_generation_id,),
                )
                revision, sealed, emergency = cursor.fetchone()
                if sealed or emergency is not None:
                    return None
                authorization = projection_registry.authorize_for_grant(
                    cursor,
                    projection_contract_hash=projection_contract_hash,
                    source_spec_sha256=projection_evidence.source_spec_sha256,
                    compatibility_profile_sha256=projection_evidence.compatibility_profile.profile_sha256,
                )
                if (
                    authorization.result is not ProjectionAuthorizationResult.AUTHORIZED
                    or authorization.authorization is None
                    or projection_evidence.projection_contract_hash != projection_contract_hash
                ):
                    return None
                grant_revision = revision + 1
                cursor.execute(
                    """
                    UPDATE generation_controls
                    SET control_revision = %s
                    WHERE world_generation_id = %s
                    """,
                    (grant_revision, world_generation_id),
                )
                admission = ResponseAdmission(
                    admission_id=uuid4().hex,
                    request_binding_digest=request_binding_digest,
                    world_generation_id=world_generation_id,
                    grant_revision=grant_revision,
                    projection_registry_revision=authorization.authorization.registry_revision,
                    candidate_ref=candidate_ref,
                    candidate_hash=candidate_hash,
                    immutable_body_hash=immutable_body_hash,
                    semantic_headers_hash=semantic_headers_hash,
                    projection_contract_hash=projection_contract_hash,
                    authorization_revision=authorization_revision,
                    authorization_deadline=authorization_deadline,
                    transmission_deadline=transmission_deadline,
                    source=source,
                    projection_evidence=projection_evidence,
                )
                cursor.execute(
                    """
                    INSERT INTO response_admissions (
                        admission_id, world_generation_id,
                        authorization_deadline, transmission_deadline,
                        state, admission
                    ) VALUES (%s, %s, %s, %s, %s, %s::jsonb)
                    """,
                    (
                        admission.admission_id,
                        world_generation_id,
                        authorization_deadline,
                        transmission_deadline,
                        AdmissionState.GRANTED.value,
                        json.dumps(admission.model_dump(mode="json"), ensure_ascii=False),
                    ),
                )
                if request_audit is not None:
                    PostgresRequestAudit.record_admission(cursor, request_audit, admission)
                return admission

    def cutover(self, world_generation_id: str) -> int:
        """在同一 Generation 鎖內封存世代並配置 Cutover revision。"""
        with self._connection() as connection:
            with connection.cursor() as cursor:
                self._ensure_generation(cursor, world_generation_id)
                cursor.execute(
                    """
                    SELECT control_revision, sealed, cutover_revision
                    FROM generation_controls
                    WHERE world_generation_id = %s
                    FOR UPDATE
                    """,
                    (world_generation_id,),
                )
                revision, sealed, cutover_revision = cursor.fetchone()
                if sealed and cutover_revision is not None:
                    return cutover_revision
                next_revision = revision + 1
                cursor.execute(
                    """
                    UPDATE generation_controls
                    SET control_revision = %s, sealed = TRUE, cutover_revision = %s
                    WHERE world_generation_id = %s
                    """,
                    (next_revision, next_revision, world_generation_id),
                )
                return next_revision

    def emergency_revoke(self, world_generation_id: str) -> int:
        """持久化整個世代的緊急撤銷；重複呼叫回傳原 revision，已核發的發送授權保留。"""
        with self._connection() as connection:
            with connection.cursor() as cursor:
                self._ensure_generation(cursor, world_generation_id)
                cursor.execute(
                    """UPDATE generation_controls SET
                           emergency_revision = COALESCE(emergency_revision, control_revision + 1),
                           control_revision = CASE WHEN emergency_revision IS NULL
                                                   THEN control_revision + 1 ELSE control_revision END
                       WHERE world_generation_id = %s RETURNING emergency_revision""",
                    (world_generation_id,),
                )
                return cursor.fetchone()[0]

    def claim(self, admission_id: str, *, owner: str, now: int) -> AdmissionOperationResult:
        """以 Generation 與 Admission 雙重 row lock 取得一次 Claim。"""
        with self._connection() as connection:
            with connection.cursor() as cursor:
                row = self._lock_admission(cursor, admission_id)
                if row is None:
                    return AdmissionOperationResult.REJECTED
                generation_id, state, deadline, emergency = row
                if state != AdmissionState.GRANTED.value:
                    return AdmissionOperationResult.ALREADY_CLAIMED
                if emergency:
                    self._set_state(cursor, admission_id, AdmissionState.ABANDONED.value)
                    return AdmissionOperationResult.REJECTED
                if now >= deadline:
                    self._set_state(cursor, admission_id, AdmissionState.EXPIRED.value)
                    return AdmissionOperationResult.EXPIRED
                revision = self._next_generation_revision(cursor, generation_id)
                self._set_state(
                    cursor,
                    admission_id,
                    AdmissionState.CLAIMED.value,
                    owner,
                    revision,
                )
                return AdmissionOperationResult.SUCCESS

    def authorize_send(
        self,
        admission_id: str,
        *,
        now: int,
        revoked: bool = False,
    ) -> AdmissionOperationResult:
        """在共享 Send Authorization 邊界檢查期限與撤銷。"""
        with self._connection() as connection:
            with connection.cursor() as cursor:
                row = self._lock_admission(cursor, admission_id, for_send=True)
                if row is None or row[1] != AdmissionState.CLAIMED.value:
                    return AdmissionOperationResult.REJECTED
                generation_id, _, deadline, emergency = row
                revoked = revoked or emergency
                if revoked or now >= deadline:
                    state = AdmissionState.ABANDONED.value if revoked else AdmissionState.EXPIRED.value
                    self._set_state(cursor, admission_id, state)
                    return AdmissionOperationResult.REJECTED
                revision = self._next_generation_revision(cursor, generation_id)
                self._set_state(
                    cursor,
                    admission_id,
                    AdmissionState.SEND_AUTHORIZED.value,
                    send_revision=revision,
                )
                return AdmissionOperationResult.SUCCESS

    def get_admission(self, admission_id: str) -> ResponseAdmission | None:
        """讀回資料庫保存的准入，讓 Renderer 比對所持授權是否被替換。"""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT admission FROM response_admissions WHERE admission_id = %s", (admission_id,)
            ).fetchone()
        return None if row is None else ResponseAdmission.model_validate(row[0])

    def start_send(self, admission_id: str, *, owner: str, now: int) -> AdmissionOperationResult:
        """在共享鎖內確認唯一 owner、發送期限與緊急撤銷，持久化傳輸起點。"""
        with self._connection() as connection:
            with connection.cursor() as cursor:
                row = self._lock_admission(cursor, admission_id, for_send=True)
                if row is None or row[1] != AdmissionState.SEND_AUTHORIZED.value:
                    return AdmissionOperationResult.REJECTED
                cursor.execute("SELECT claim_owner FROM response_admissions WHERE admission_id=%s", (admission_id,))
                if cursor.fetchone()[0] != owner:
                    return AdmissionOperationResult.REJECTED
                if row[3] or now >= row[2]:
                    state = AdmissionState.ABANDONED if row[3] else AdmissionState.EXPIRED
                    self._set_state(cursor, admission_id, state.value)
                    return AdmissionOperationResult.REJECTED
                self._set_state(cursor, admission_id, AdmissionState.SEND_STARTED.value)
                cursor.execute(
                    "INSERT INTO response_audit(admission_id,sequence,event_name,final_response_hash) "
                    "SELECT admission_id,0,'send_started',admission->>'candidate_hash' "
                    "FROM response_admissions WHERE admission_id=%s", (admission_id,))
                return AdmissionOperationResult.SUCCESS

    def finish_send(self, admission_id: str, *, owner: str, outcome: AdmissionState,
                    attempted: bool = False) -> AdmissionOperationResult:
        """以 owner 與原狀態條件寫入終態，不重開結果未知或已完成的傳輸。"""
        if outcome not in {AdmissionState.SEND_COMPLETED, AdmissionState.SEND_FAILED,
                           AdmissionState.SEND_PARTIAL_FAILURE}:
            raise ValueError("invalid transmission outcome")
        with self._connection() as connection:
            row = connection.execute(
                """UPDATE response_admissions SET state=%s
                   WHERE admission_id=%s AND claim_owner=%s AND state=%s RETURNING admission_id""",
                (outcome.value, admission_id, owner, AdmissionState.SEND_STARTED.value),
            ).fetchone()
            if row:
                if attempted or outcome is AdmissionState.SEND_COMPLETED:
                    connection.execute(
                        "INSERT INTO response_audit(admission_id,sequence,event_name,final_response_hash) "
                        "SELECT admission_id,1,'response_send_attempted',admission->>'candidate_hash' "
                        "FROM response_admissions WHERE admission_id=%s", (admission_id,))
                connection.execute(
                    "INSERT INTO response_audit(admission_id,sequence,event_name,final_response_hash,outcome) "
                    "SELECT admission_id,2,%s,admission->>'candidate_hash',%s FROM response_admissions "
                    "WHERE admission_id=%s", ("asgi_send_completed" if outcome is AdmissionState.SEND_COMPLETED
                                               else "asgi_send_failed", outcome.value, admission_id))
        return AdmissionOperationResult.SUCCESS if row else AdmissionOperationResult.REJECTED

    def transmission_events(self, admission_id: str) -> tuple[dict, ...]:
        """依順序讀取只含事件名稱、最終封套 hash 與終態的稽核摘要。"""
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT event_name,final_response_hash,outcome FROM response_audit WHERE admission_id=%s "
                "ORDER BY sequence", (admission_id,)).fetchall()
        return tuple({"event_name": row[0], "final_response_hash": row[1],
                      **({"outcome": row[2]} if row[2] is not None else {})} for row in rows)

    def state(self, admission_id: str) -> AdmissionState | None:
        """讀取共享准入狀態，不因遺失紀錄而重建授權。"""
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT state FROM response_admissions WHERE admission_id = %s", (admission_id,))
                row = cursor.fetchone()
        return None if row is None else AdmissionState(row[0])

    def event_revision(self, admission_id: str, event: str) -> int | None:
        """讀取 Grant、Claim、Cutover 或 Send Authorization 的共同 revision。"""
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT a.admission->>'grant_revision', a.claim_revision,
                           a.send_authorization_revision, g.cutover_revision, g.emergency_revision
                    FROM response_admissions a
                    JOIN generation_controls g USING (world_generation_id)
                    WHERE a.admission_id = %s
                    """,
                    (admission_id,),
                )
                row = cursor.fetchone()
        if row is None:
            return None
        values = {"grant": row[0], "claim": row[1], "send_authorization": row[2], "cutover": row[3],
                  "emergency_revocation": row[4]}
        value = values.get(event)
        if event not in values:
            raise ValueError(f"unsupported admission event: {event}")
        return None if value is None else int(value)

    def active_candidate_refs(self, *, now: int) -> frozenset[str]:
        """從共享資料庫列出期限內仍受 Admission 保護的 Candidate 引用。"""
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT admission->>'candidate_ref'
                    FROM response_admissions
                    WHERE state IN (%s, %s, %s, %s)
                      AND (
                        (state = %s AND authorization_deadline > %s)
                        OR (state IN (%s, %s, %s) AND transmission_deadline > %s)
                      )
                    """,
                    (
                        AdmissionState.GRANTED.value,
                        AdmissionState.CLAIMED.value,
                        AdmissionState.SEND_AUTHORIZED.value,
                        AdmissionState.SEND_STARTED.value,
                        AdmissionState.GRANTED.value,
                        now,
                        AdmissionState.CLAIMED.value,
                        AdmissionState.SEND_AUTHORIZED.value,
                        AdmissionState.SEND_STARTED.value,
                        now,
                    ),
                )
                return frozenset(row[0] for row in cursor.fetchall())

    def _connection(self) -> Any:
        """建立共享資料庫連線，缺少驅動或服務時明確 Fail-Closed。"""
        if psycopg is None:
            raise WorldStoreError(WorldStoreStatus.STORAGE_UNAVAILABLE.value)
        try:
            return psycopg.connect(self._dsn)
        except psycopg.Error as exc:
            raise WorldStoreError(WorldStoreStatus.STORAGE_UNAVAILABLE.value) from exc

    @staticmethod
    def _ensure_generation(cursor: Any, generation_id: str) -> None:
        """確保 Generation 有可鎖定的控制列，不建立替代世界資料。"""
        cursor.execute(
            """
            INSERT INTO generation_controls (world_generation_id, control_revision, sealed)
            VALUES (%s, 0, FALSE)
            ON CONFLICT (world_generation_id) DO NOTHING
            """,
            (generation_id,),
        )

    @staticmethod
    def _lock_admission(cursor: Any, admission_id: str, *, for_send: bool = False) -> tuple[str, str, int, bool] | None:
        """鎖定准入及世代，再以 Profile 共享控制鎖核對緊急墓碑；回傳撤銷旗標而非混用 revision。"""
        cursor.execute(
            """
            SELECT world_generation_id, state,
                   CASE WHEN %s THEN transmission_deadline ELSE authorization_deadline END,
                   admission#>>'{projection_evidence,compatibility_profile,profile_sha256}'
            FROM response_admissions
            WHERE admission_id = %s
            FOR UPDATE
            """,
            (for_send, admission_id),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        cursor.execute(
            "SELECT emergency_revision FROM generation_controls WHERE world_generation_id = %s FOR UPDATE",
            (row[0],),
        )
        generation_emergency = cursor.fetchone()[0]
        profile = PostgresProjectionRegistry.profile_state_in_transaction(cursor, row[3])
        return (*row[:3], generation_emergency is not None or bool(profile and profile.emergency))

    @staticmethod
    def _next_generation_revision(cursor: Any, generation_id: str) -> int:
        """在已鎖定的 Generation 控制列配置下一個共同 revision。"""
        cursor.execute(
            """
            UPDATE generation_controls
            SET control_revision = control_revision + 1
            WHERE world_generation_id = %s
            RETURNING control_revision
            """,
            (generation_id,),
        )
        return cursor.fetchone()[0]

    @staticmethod
    def _set_state(
        cursor: Any,
        admission_id: str,
        state: str,
        owner: str | None = None,
        claim_revision: int | None = None,
        send_revision: int | None = None,
    ) -> None:
        """以單一 UPDATE 保存 Admission 狀態與相應控制證據。"""
        cursor.execute(
            """
            UPDATE response_admissions
            SET state = %s,
                claim_owner = COALESCE(%s, claim_owner),
                claim_revision = COALESCE(%s, claim_revision),
                send_authorization_revision = COALESCE(%s, send_authorization_revision)
            WHERE admission_id = %s
            """,
            (state, owner, claim_revision, send_revision, admission_id),
        )
