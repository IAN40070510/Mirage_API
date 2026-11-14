"""PostgreSQL 共享 ResponseAdmission 交易控制。"""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

from .admission import AdmissionOperationResult, AdmissionState
from .models import ProjectionEvidence, ResponseAdmission, ResponseSource
from .postgres_store import psycopg
from .projection_registry import ProjectionAuthorizationResult, ProjectionRegistryProtocol
from .store import WorldStoreError, WorldStoreStatus


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
        projection_registry: ProjectionRegistryProtocol,
    ) -> ResponseAdmission | None:
        """驗證共享 Projection Registry 後，在控制列鎖內建立 Grant。"""
        with self._connection() as connection:
            with connection.cursor() as cursor:
                self._ensure_generation(cursor, world_generation_id)
                cursor.execute(
                    """
                    SELECT control_revision, sealed
                    FROM generation_controls
                    WHERE world_generation_id = %s
                    FOR UPDATE
                    """,
                    (world_generation_id,),
                )
                revision, sealed = cursor.fetchone()
                if sealed:
                    return None
                authorization = projection_registry.authorize(
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

    def claim(self, admission_id: str, *, owner: str, now: int) -> AdmissionOperationResult:
        """以 Generation 與 Admission 雙重 row lock 取得一次 Claim。"""
        with self._connection() as connection:
            with connection.cursor() as cursor:
                row = self._lock_admission(cursor, admission_id)
                if row is None:
                    return AdmissionOperationResult.REJECTED
                generation_id, state, deadline = row
                if state != AdmissionState.GRANTED.value:
                    return AdmissionOperationResult.ALREADY_CLAIMED
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
                row = self._lock_admission(cursor, admission_id)
                if row is None or row[1] != AdmissionState.CLAIMED.value:
                    return AdmissionOperationResult.REJECTED
                generation_id, _, deadline = row
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
                           a.send_authorization_revision, g.cutover_revision
                    FROM response_admissions a
                    JOIN generation_controls g USING (world_generation_id)
                    WHERE a.admission_id = %s
                    """,
                    (admission_id,),
                )
                row = cursor.fetchone()
        if row is None:
            return None
        values = {"grant": row[0], "claim": row[1], "send_authorization": row[2], "cutover": row[3]}
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
                    WHERE state IN (%s, %s, %s)
                      AND (
                        (state = %s AND authorization_deadline > %s)
                        OR (state IN (%s, %s) AND transmission_deadline > %s)
                      )
                    """,
                    (
                        AdmissionState.GRANTED.value,
                        AdmissionState.CLAIMED.value,
                        AdmissionState.SEND_AUTHORIZED.value,
                        AdmissionState.GRANTED.value,
                        now,
                        AdmissionState.CLAIMED.value,
                        AdmissionState.SEND_AUTHORIZED.value,
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
    def _lock_admission(cursor: Any, admission_id: str) -> tuple[str, str, int] | None:
        """鎖定 Admission 對應 Generation 與記錄，保護跨 Instance 狀態轉換。"""
        cursor.execute(
            """
            SELECT world_generation_id, state, authorization_deadline
            FROM response_admissions
            WHERE admission_id = %s
            FOR UPDATE
            """,
            (admission_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        cursor.execute(
            "SELECT 1 FROM generation_controls WHERE world_generation_id = %s FOR UPDATE",
            (row[0],),
        )
        return row

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
