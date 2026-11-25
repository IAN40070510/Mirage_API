"""獨立 Sender 專用的不可變 Payload／一次性 Send Lease 與 ASGI 傳輸守衛。"""

from __future__ import annotations

import asyncio
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
import hashlib
import hmac
import re
from typing import Callable
from uuid import UUID, uuid4

from deception.api.fingerprint import fingerprint_request

from .admission import AdmissionOperationResult, AdmissionState
from .models import ResponseAdmission
from .protected_grant import (_ProtectedConnection, _verified_envelope_fields,
                              _verified_envelope_hashes, ProtectedGrantError)
from .transmission import TransmissionError, current_time, response_envelope, response_hashes


# 固定 PostgreSQL transaction-level advisory lock：同一 DB/schema 的 Recorder 與
# Sender 在取得新 Lease 前序列化「已知 Restore」通知；不能防止整機快照倒退。
_RESTORE_LOCK_NAMESPACE = 1296650823  # MIRG
_RESTORE_LOCK_KEY = 1380275028        # REST


class PostgresKnownRestoreRecorder(_ProtectedConnection):
    """由受信任部署控制面落盤已知 Restore 事件，持久阻止後續的新 Send Lease。"""

    def mark_known_restore(self, restore_event_id: UUID) -> bool:
        """以單一 UUID4 在真實 PostgreSQL 寫入不可變事件；重送同 ID 不改寫。

        呼叫方必須在 World Restore 前停止新的入口，且不得把此函式當作
        整機快照回滾偵測。COMMIT ACK 不明時只可沿用原 ID 對帳；沒有
        自動解封或人工 override，待單機復原驗證契約完成才能另行實作。
        """
        if not isinstance(restore_event_id, UUID) or restore_event_id.version != 4:
            raise ProtectedGrantError("known_restore_event_id_invalid")
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET LOCAL lock_timeout='3s'")
                cursor.execute("SELECT current_setting('transaction_isolation')")
                if cursor.fetchone()[0] != "read committed":
                    raise ProtectedGrantError("known_restore_requires_read_committed")
                cursor.execute("SELECT pg_advisory_xact_lock(%s,%s)",
                               (_RESTORE_LOCK_NAMESPACE, _RESTORE_LOCK_KEY))
                cursor.execute(
                    "INSERT INTO protected_local_restore_events(restore_event_id) "
                    "VALUES (%s) ON CONFLICT DO NOTHING",
                    (restore_event_id,),
                )
                # 不使用 RETURNING，讓專用 Recorder 只需 INSERT、無需 SELECT。
                return cursor.rowcount == 1


@dataclass(frozen=True)
class ProtectedSendLease:
    """已在資料庫一次性消費的發送憑據；Payload bytes 只能來自受保護 Pin。"""

    lease_id: UUID
    admission_id: str
    send_owner: str
    receipt_id: UUID
    request_fingerprint: str
    candidate_hash: str
    envelope_bytes: bytes
    transmission_deadline: int


@dataclass(frozen=True)
class ProtectedReceiptSendPin:
    """只由獨立 Sender 的受保護資料庫推導，供單一 Receipt 傳輸使用的 Pin。"""

    admission_id: str
    receipt_id: UUID
    send_owner: str
    request_fingerprint: str
    transmission_deadline: int
    envelope_bytes: bytes


@dataclass(frozen=True)
class ProtectedSendReconciliation:
    """唯讀 Lease 對帳證據；沒有任何狀態可以用來核發新的傳輸權。"""

    observation: str
    state: AdmissionState | None
    lease_observed: bool

    @property
    def retry_permitted(self) -> bool:
        """即使資料庫看不到 Lease，也不能排除 ACK 遺失或已還原的舊狀態。"""
        return False


class PostgresProtectedSender(_ProtectedConnection):
    """由獨立實體 Sender Login 消費已 Authorize 的 Snapshot，不重新判定政策。"""

    def resolve_authorized_receipt(self, receipt_id: UUID) -> ProtectedReceiptSendPin | None:
        """只按 Receipt 查出原 Authorizer 的 Pin，絕不讓 Gateway 指定回應內容。

        只認可 Receipt-only 授權鏈及固定 Owner；此查詢完全唯讀，不能核發
        Lease 或起送。真正的狀態、Snapshot、Purge、Restore 與 DB Deadline
        必須由隨後的 start_send() 在同一筆一次性交易內重新核對。
        """
        if not isinstance(receipt_id, UUID) or receipt_id.version != 4:
            raise ProtectedGrantError("protected_sender_receipt_invalid")
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """SELECT a.admission_id,a.admission,a.state,a.claim_owner,
                              a.authorization_deadline,a.transmission_deadline,
                              a.world_generation_id,s.send_owner,s.request_fingerprint,
                              s.candidate_hash,s.envelope_bytes,s.transmission_deadline,
                              s.world_generation_id,s.candidate_ref,
                              b.receipt_id,b.candidate_ref,b.candidate_version,
                              r.request_fingerprint,b.operation_id
                       FROM protected_authorized_http_snapshots s
                       JOIN response_admissions a ON a.admission_id=s.admission_id
                       JOIN protected_grant_bindings b
                         ON b.admission_id=a.admission_id AND b.receipt_id=s.receipt_id
                       JOIN ingress_receipts r ON r.receipt_id=s.receipt_id
                       WHERE s.receipt_id=%s""", (receipt_id,),
                )
                row = cursor.fetchone()
        if row is None or row[2] != AdmissionState.SEND_AUTHORIZED.value:
            return None
        try:
            admission = ResponseAdmission.model_validate(row[1])
            pinned = bytes(row[10])
            hashes = _verified_envelope_hashes(pinned)
        except (TypeError, ValueError):
            raise ProtectedGrantError("protected_sender_receipt_pin_unverifiable") from None
        owner = "protected-sender-" + receipt_id.hex
        if (admission.admission_id != row[0]
                or admission.authorization_revision != "protected-receipt-v1"
                or admission.request_binding_digest != row[8]
                or admission.request_binding_digest != row[17]
                or admission.candidate_hash != row[9]
                or admission.candidate_hash != hashes[0]
                or (admission.immutable_body_hash, admission.semantic_headers_hash)
                   != hashes[1:]
                or admission.candidate_ref != row[13]
                or admission.world_generation_id != row[6]
                or admission.world_generation_id != row[12]
                or admission.authorization_deadline != row[4]
                or admission.transmission_deadline != row[5]
                or admission.transmission_deadline != row[11]
                or row[3] != owner or row[7] != owner
                or row[14] != receipt_id or row[15] != row[13]
                or row[16] != 1 or row[18] != receipt_id):
            raise ProtectedGrantError("protected_sender_receipt_binding_mismatch")
        return ProtectedReceiptSendPin(
            admission_id=row[0], receipt_id=receipt_id, send_owner=owner,
            request_fingerprint=row[8], transmission_deadline=row[5],
            envelope_bytes=pinned,
        )

    @contextmanager
    def known_restore_delivery_window(self):
        """在 ASGI 傳輸期間持有本機共享 Session Lock，讓 Restore 事件不能插隊。

        此窗口**必須在 StartSend COMMIT 之後**取得，避免 Recorder 已排隊時
        Sender 另一連線的 transaction lock 造成環狀等待。取得 Session Lock
        後再查一次已提交 Restore 事件；若 Restore 先提交，零 bytes 拒絕。
        Session Lock 在正常／例外結束時釋放，連線死亡時由 PG 自動釋放。
        本控制只處理已知 Restore，不偵測 VM 整體回滾或已在別處發出的 bytes。
        """
        with closing(self._connection()) as connection:
            # 身分 preflight 的 SELECT 已開啟 read transaction，先提交後使用
            # autocommit，避免在網路傳輸期間長期保留 MVCC snapshot。
            connection.commit()
            connection.autocommit = True
            with connection.cursor() as cursor:
                cursor.execute("SET lock_timeout='3s'")
                cursor.execute("SELECT pg_advisory_lock_shared(%s,%s)",
                               (_RESTORE_LOCK_NAMESPACE, _RESTORE_LOCK_KEY))
                try:
                    cursor.execute("SELECT 1 FROM protected_local_restore_events LIMIT 1")
                    if cursor.fetchone() is not None:
                        raise ProtectedGrantError("protected_delivery_restore_quarantined")
                    yield
                finally:
                    # 若連線中斷，close() 會在 PostgreSQL 端釋放 Session Lock；
                    # Caller 一律把窗口異常視為不能重送的傳輸結果不明。
                    cursor.execute("SELECT pg_advisory_unlock_shared(%s,%s)",
                                   (_RESTORE_LOCK_NAMESPACE, _RESTORE_LOCK_KEY))

    def start_send(
        self, *, admission_id: str, receipt_id: UUID, owner: str, request_fingerprint: str,
        expected_envelope: bytes,
    ) -> ProtectedSendLease | None:
        """鎖定 Admission、比對不可變 Pin、原子寫入一次性 Lease 與 SEND_STARTED。

        只接受原本 SEND_AUTHORIZED 的 owner；用 DB 時鐘判斷傳輸期限，
        不回查 SEND_AUTHORIZED 後的新撤銷政策。網路 COMMIT 不明時不能重試
        StartSend；同 admission 的唯一鍵永久禁止第二把 Lease。

        G5 獨立 Restore Fence 尚未接線，此方法只供隔離測試及獨立服務內
        未對外啟用的 primitive，絕不可讓 Runtime 憑此直接發送。
        """
        if (not isinstance(admission_id, str) or not admission_id or len(admission_id) > 128
                or not isinstance(receipt_id, UUID) or receipt_id.version != 4
                or not isinstance(owner, str) or not 1 <= len(owner) <= 128
                or not isinstance(request_fingerprint, str) or len(request_fingerprint) != 64
                or not isinstance(expected_envelope, bytes)):
            raise ProtectedGrantError("protected_send_request_invalid")
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET LOCAL lock_timeout='3s'")
                cursor.execute("SELECT current_setting('transaction_isolation')")
                if cursor.fetchone()[0] != "read committed":
                    raise ProtectedGrantError("protected_send_requires_read_committed")
                cursor.execute(
                    """SELECT a.state,a.claim_owner,a.transmission_deadline,a.admission,
                              s.receipt_id,s.request_fingerprint,s.candidate_hash,
                              s.envelope_bytes,s.send_owner,s.transmission_deadline,
                              s.world_generation_id,s.candidate_ref,
                              a.authorization_deadline,a.world_generation_id
                       FROM response_admissions a
                       JOIN protected_authorized_http_snapshots s
                         ON s.admission_id=a.admission_id
                       JOIN protected_grant_bindings b
                         ON b.admission_id=a.admission_id AND b.receipt_id=s.receipt_id
                       WHERE a.admission_id=%s AND s.receipt_id=%s
                         AND b.receipt_id=%s FOR UPDATE OF a""",
                    (admission_id, receipt_id, receipt_id),
                )
                row = cursor.fetchone()
                if (row is None or row[0] != AdmissionState.SEND_AUTHORIZED.value
                        or row[1] != owner or row[8] != owner
                        or row[2] != row[9] or row[4] != receipt_id
                        or row[5] != request_fingerprint):
                    return None
                # 必須先取得 Admission FOR UPDATE，**另發第二條 SQL** 才讀
                # 物理 Purge Fence；同一 SELECT 的 MVCC Snapshot 可能早於競爭
                # GC Commit。Fence 不是新一輪 Policy/Emergency 授權判斷。
                cursor.execute(
                    "SELECT 1 FROM protected_authorized_snapshot_purge_fences "
                    "WHERE admission_id=%s", (admission_id,),
                )
                if cursor.fetchone() is not None:
                    return None
                # 對同一資料庫的已知 Restore 通知取得共享交易鎖；部署控制面
                # 只能在排他鎖下新增事件，確保標記提交後的新 StartSend 必拒絕。
                cursor.execute("SELECT pg_advisory_xact_lock_shared(%s,%s)",
                               (_RESTORE_LOCK_NAMESPACE, _RESTORE_LOCK_KEY))
                cursor.execute("SELECT 1 FROM protected_local_restore_events LIMIT 1")
                if cursor.fetchone() is not None:
                    return None
                pinned = bytes(row[7])
                admission = ResponseAdmission.model_validate(row[3])
                verified_hashes = _verified_envelope_hashes(pinned)
                if (admission.admission_id != admission_id
                        or admission.authorization_deadline != row[12]
                        or admission.transmission_deadline != row[2]
                        or admission.world_generation_id != row[13]
                        or verified_hashes != (
                        admission.candidate_hash, admission.immutable_body_hash,
                        admission.semantic_headers_hash) or row[6] != admission.candidate_hash
                        or row[10] != admission.world_generation_id
                        or row[11] != admission.candidate_ref
                        or row[5] != admission.request_binding_digest
                        or not hmac.compare_digest(hashlib.sha256(pinned).hexdigest(), row[6])):
                    raise ProtectedGrantError("protected_send_pinned_payload_invalid")
                if not hmac.compare_digest(pinned, expected_envelope):
                    return None
                cursor.execute("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                db_now = cursor.fetchone()[0]
                if db_now >= row[2]:
                    cursor.execute("UPDATE response_admissions SET state=%s WHERE admission_id=%s",
                                   (AdmissionState.EXPIRED.value, admission_id))
                    return None
                lease_id = uuid4()
                cursor.execute(
                    """UPDATE response_admissions SET state=%s WHERE admission_id=%s""",
                    (AdmissionState.SEND_STARTED.value, admission_id),
                )
                cursor.execute(
                    """INSERT INTO protected_send_leases (
                           admission_id,lease_id,receipt_id,send_owner,request_fingerprint,
                           candidate_hash,transmission_deadline)
                       VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                    (admission_id, lease_id, row[4], owner, row[5], row[6], row[2]),
                )
                cursor.execute(
                    """INSERT INTO response_audit(admission_id,sequence,event_name,final_response_hash)
                       VALUES (%s,0,'send_started',%s)""",
                    (admission_id, row[6]),
                )
                return ProtectedSendLease(
                    lease_id=lease_id, admission_id=admission_id, send_owner=owner,
                    receipt_id=row[4], request_fingerprint=row[5],
                    candidate_hash=row[6], envelope_bytes=pinned,
                    transmission_deadline=row[2],
                )

    def reconcile_send(self, *, admission_id: str, receipt_id: UUID,
                       owner: str, request_fingerprint: str) -> ProtectedSendReconciliation:
        """唯讀重查 StartSend／FinishSend 已提交狀態，不根據查核結果允許重送。

        供同一 Sender 在 COMMIT ACK 遺失／程序重啟後調查，必須使用受保護的
        原始 Receipt、Owner、Fingerprint；不接受來自 HTTP 客戶端的任意查詢。

        `NO_LEASE_OBSERVED` 僅代表本次資料庫可見的快照沒有 Lease，**不**
        證明先前起送未發生；真正的外部復原域一致性仍是 G5 的獨立責任。
        """
        if (not isinstance(admission_id, str) or not 1 <= len(admission_id) <= 128
                or not isinstance(receipt_id, UUID) or receipt_id.version != 4
                or not isinstance(owner, str) or not 1 <= len(owner) <= 128
                or not isinstance(request_fingerprint, str)
                or not re.fullmatch(r"[0-9a-f]{64}", request_fingerprint)):
            raise ProtectedGrantError("protected_send_reconciliation_request_invalid")
        unknown = ProtectedSendReconciliation("UNVERIFIABLE", None, False)
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """SELECT a.state,a.claim_owner,a.transmission_deadline,a.admission,
                              s.receipt_id,s.send_owner,s.request_fingerprint,
                              s.candidate_hash,s.transmission_deadline,
                              s.world_generation_id,s.candidate_ref,b.receipt_id,
                              l.lease_id,l.receipt_id,l.send_owner,
                              l.request_fingerprint,l.candidate_hash,l.transmission_deadline
                       FROM response_admissions a
                       JOIN protected_authorized_http_snapshots s
                         ON s.admission_id=a.admission_id
                       JOIN protected_grant_bindings b
                         ON b.admission_id=a.admission_id AND b.receipt_id=s.receipt_id
                       LEFT JOIN protected_send_leases l
                         ON l.admission_id=a.admission_id
                       WHERE a.admission_id=%s""",
                    (admission_id,),
                )
                row = cursor.fetchone()
                if (row is None or row[1] != owner or row[4] != receipt_id
                        or row[5] != owner or row[6] != request_fingerprint
                        or row[2] != row[8] or row[11] != receipt_id):
                    return unknown
                try:
                    state = AdmissionState(row[0])
                    admission = ResponseAdmission.model_validate(row[3])
                except ValueError:
                    return unknown
                if (admission.admission_id != admission_id
                        or admission.request_binding_digest != request_fingerprint
                        or admission.candidate_hash != row[7]
                        or admission.transmission_deadline != row[2]
                        or admission.world_generation_id != row[9]
                        or admission.candidate_ref != row[10]):
                    return unknown
                if row[12] is None:
                    if state is AdmissionState.SEND_AUTHORIZED:
                        return ProtectedSendReconciliation("NO_LEASE_OBSERVED", state, False)
                    return unknown
                if (not isinstance(row[12], UUID) or row[12].version != 4
                        or row[13] != receipt_id or row[14] != owner
                        or row[15] != request_fingerprint or row[16] != row[7]
                        or row[17] != row[2]):
                    return unknown
                if state is AdmissionState.SEND_STARTED:
                    return ProtectedSendReconciliation("STARTED_DELIVERY_UNKNOWN", state, True)
                if state in (AdmissionState.SEND_COMPLETED, AdmissionState.SEND_FAILED,
                             AdmissionState.SEND_PARTIAL_FAILURE):
                    # 這是 DB 終態，不代表遠端 Client 已收到所有 bytes。
                    return ProtectedSendReconciliation("TERMINAL_RECORDED", state, True)
                return unknown

    def finish_send(self, *, admission_id: str, owner: str, lease_id: UUID,
                    outcome: AdmissionState, attempted: bool) -> AdmissionOperationResult:
        """依永久 Lease ID／owner 將單次 SEND_STARTED 寫為終態，保留故障稽核。"""
        if (not isinstance(lease_id, UUID) or lease_id.version != 4
                or not isinstance(owner, str) or not 1 <= len(owner) <= 128
                or type(attempted) is not bool
                or not isinstance(outcome, AdmissionState)
                or outcome not in {AdmissionState.SEND_COMPLETED, AdmissionState.SEND_FAILED,
                                   AdmissionState.SEND_PARTIAL_FAILURE}):
            raise ProtectedGrantError("protected_send_terminal_invalid")
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET LOCAL lock_timeout='3s'")
                cursor.execute(
                    """SELECT a.state,a.claim_owner,l.lease_id,l.send_owner,l.candidate_hash
                       FROM response_admissions a JOIN protected_send_leases l
                         ON l.admission_id=a.admission_id
                       WHERE a.admission_id=%s FOR UPDATE OF a""",
                    (admission_id,),
                )
                row = cursor.fetchone()
                if (row is None or row[:2] != (AdmissionState.SEND_STARTED.value, owner)
                        or row[2] != lease_id or row[3] != owner):
                    return AdmissionOperationResult.REJECTED
                cursor.execute("UPDATE response_admissions SET state=%s WHERE admission_id=%s",
                               (outcome.value, admission_id))
                if attempted or outcome is AdmissionState.SEND_COMPLETED:
                    cursor.execute(
                        """INSERT INTO response_audit(admission_id,sequence,event_name,final_response_hash)
                           VALUES (%s,1,'response_send_attempted',%s)""",
                        (admission_id, row[4]),
                    )
                cursor.execute(
                    """INSERT INTO response_audit(
                           admission_id,sequence,event_name,final_response_hash,outcome)
                       VALUES (%s,2,%s,%s,%s)""",
                    (admission_id,
                     "asgi_send_completed" if outcome is AdmissionState.SEND_COMPLETED
                     else "asgi_send_failed", row[4], outcome.value),
                )
                return AdmissionOperationResult.SUCCESS


class PostgresProtectedSnapshotPurger(_ProtectedConnection):
    """專用 GC Login 在 DB 中不可逆封閉 Snapshot 執行資格；不修改原授權紀錄。"""

    def fence_snapshot(self, *, admission_id: str, gc_operation_id: UUID,
                       purge_reason: str) -> bool:
        """以唯一 GC Operation 建立 Fence，未知 COMMIT 只能按原 ID 查核對帳。

        DB Trigger 必須在 INSERT 前鎖 Admission，再核對活躍／未知 Send Lease；
        Fence 成功不表示 bytes 已被刪除，後續 GC 必須另行通過保留期驗收。
        此 primitive 尚未接上正式 Restore Fence 或任何 Runtime 路由。
        """
        if (not isinstance(admission_id, str) or not 1 <= len(admission_id) <= 128
                or not isinstance(gc_operation_id, UUID) or gc_operation_id.version != 4
                or not isinstance(purge_reason, str)
                or purge_reason not in {"retention_expired", "snapshot_corrupt"}):
            raise ProtectedGrantError("protected_snapshot_purge_request_invalid")
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET LOCAL lock_timeout='3s'")
                cursor.execute("SELECT current_setting('transaction_isolation')")
                if cursor.fetchone()[0] != "read committed":
                    raise ProtectedGrantError("protected_snapshot_purge_requires_read_committed")
                cursor.execute(
                    "SELECT gc_operation_id,purge_reason "
                    "FROM protected_authorized_snapshot_purge_fences "
                    "WHERE admission_id=%s", (admission_id,),
                )
                existing = cursor.fetchone()
                if existing is not None:
                    if existing != (gc_operation_id, purge_reason):
                        raise ProtectedGrantError("protected_snapshot_purge_rebound")
                    return True
                cursor.execute(
                    """INSERT INTO protected_authorized_snapshot_purge_fences (
                           admission_id,gc_operation_id,purge_reason)
                       VALUES (%s,%s,%s)""",
                    (admission_id, gc_operation_id, purge_reason),
                )
        return True


@dataclass
class ProtectedLeaseTransmission:
    """把獨立 Sender 的不可變 Snapshot 單次 Lease 接到既有 ValidatedHTTPResponse。"""

    sender: PostgresProtectedSender
    admission: ResponseAdmission
    receipt_id: UUID
    owner: str
    clock: Callable[[], int] = current_time
    _expected_envelope: bytes | None = field(default=None, init=False)
    _fingerprint: str | None = field(default=None, init=False)
    _lease: ProtectedSendLease | None = field(default=None, init=False)
    _start_attempted: bool = field(default=False, init=False)

    def prepare(self, candidate, request) -> None:
        """ASGI 起送前比對原始 Request 與精確 Payload，之後不可再改 Candidate。"""
        if not isinstance(self.receipt_id, UUID) or self.receipt_id.version != 4:
            raise TransmissionError("protected_send_receipt_invalid")
        if (self._expected_envelope is not None or self._lease is not None
                or self._start_attempted):
            raise TransmissionError("protected_send_already_prepared")
        fingerprint = fingerprint_request(request)
        expected = response_hashes(candidate.status_code, candidate.headers, candidate.body_bytes)
        if (fingerprint != self.admission.request_binding_digest
                or expected != (self.admission.candidate_hash, self.admission.immutable_body_hash,
                                self.admission.semantic_headers_hash)):
            raise TransmissionError("protected_send_response_binding_mismatch")
        self._expected_envelope = response_envelope(
            candidate.status_code, candidate.headers, candidate.body_bytes,
        )
        self._fingerprint = fingerprint

    def start(self) -> None:
        """首個 ASGI 訊息前單次提交 DB Lease，且只放行 Pin 確認的相同 bytes。"""
        if (self._expected_envelope is None or self._fingerprint is None
                or self._lease is not None or self._start_attempted):
            raise TransmissionError("protected_send_not_prepared_or_reused")
        # PG COMMIT ACK 遺失時不能知道 Lease 是否已被消費；在呼叫 DB 前即毒化
        # 此 Transmission 實例，連 NULL/503/網路失敗均不得再次送 StartSend。
        self._start_attempted = True
        lease = self.sender.start_send(
            admission_id=self.admission.admission_id, receipt_id=self.receipt_id,
            owner=self.owner,
            request_fingerprint=self._fingerprint,
            expected_envelope=self._expected_envelope,
        )
        if (not isinstance(lease, ProtectedSendLease)
                or not isinstance(lease.lease_id, UUID) or lease.lease_id.version != 4
                or lease.admission_id != self.admission.admission_id
                or lease.receipt_id != self.receipt_id
                or lease.send_owner != self.owner
                or lease.request_fingerprint != self._fingerprint
                or lease.candidate_hash != self.admission.candidate_hash
                or lease.envelope_bytes != self._expected_envelope
                or type(lease.transmission_deadline) is not int
                or lease.transmission_deadline != self.admission.transmission_deadline):
            raise TransmissionError("protected_send_lease_refused")
        self._lease = lease

    def check_deadline(self) -> None:
        """在每次 ASGI 發送前依獲准期限拒絕超時，不重新授權政策。"""
        if self.clock() >= self.admission.transmission_deadline:
            raise TransmissionError("protected_send_deadline_exceeded")

    def finish(self, outcome: AdmissionState, *, attempted: bool = False) -> None:
        """將單次 Lease 的真實發送結果回寫，失敗時絕不要求重啟送出。"""
        lease = self._lease
        if lease is None or self.sender.finish_send(
                admission_id=lease.admission_id, owner=self.owner,
                lease_id=lease.lease_id, outcome=outcome, attempted=attempted,
        ) is not AdmissionOperationResult.SUCCESS:
            raise TransmissionError("protected_send_terminal_unverifiable")


@dataclass
class ProtectedPinnedASGIResponse:
    """只從持久化受保護 Snapshot 的一次性 Lease 發出原生 ASGI HTTP 訊息。

    本類別是獨立 Sender 的**內部傳輸元件**，不是可由 Runtime 呼叫的 HTTP
    路由；外層仍須完成可信 Caller/Request 身分、G5 與正式 Release Gate。
    """

    sender: PostgresProtectedSender
    admission_id: str
    receipt_id: UUID
    owner: str
    request_fingerprint: str
    expected_transmission_deadline: int
    expected_envelope: bytes
    clock: Callable[[], int] = current_time
    _used: bool = field(default=False, init=False)

    async def __call__(self, scope, receive, send) -> None:
        """核發單把 Lease 後輸出 DB Pin 原始 status／headers／body，並稽核傳輸結果。

        首個 ASGI byte 前必須完成資料庫 COMMIT；任何起送失敗都不輸出
        `http.response.start`。未知 COMMIT、重入、非法封套或逾期不可重試。
        送出時僅以呼叫者已核准的 Deadline 做本地守衛，不宣稱遠端已收 bytes。
        """
        if self._used:
            raise TransmissionError("protected_pinned_asgi_reused")
        self._used = True
        if scope.get("type") != "http" or scope.get("scheme") != "https":
            raise TransmissionError("protected_pinned_asgi_tls_required")
        if (not isinstance(self.expected_envelope, bytes)
                or type(self.expected_transmission_deadline) is not int):
            raise TransmissionError("protected_pinned_asgi_envelope_invalid")
        lease = self.sender.start_send(
            admission_id=self.admission_id, receipt_id=self.receipt_id,
            owner=self.owner, request_fingerprint=self.request_fingerprint,
            expected_envelope=self.expected_envelope,
        )
        if (not isinstance(lease, ProtectedSendLease)
                or not isinstance(lease.lease_id, UUID) or lease.lease_id.version != 4
                or lease.admission_id != self.admission_id
                or lease.receipt_id != self.receipt_id or lease.send_owner != self.owner
                or lease.request_fingerprint != self.request_fingerprint
                or not hmac.compare_digest(lease.envelope_bytes, self.expected_envelope)
                or type(lease.transmission_deadline) is not int
                or lease.transmission_deadline != self.expected_transmission_deadline
                or not hmac.compare_digest(hashlib.sha256(lease.envelope_bytes).hexdigest(),
                                           lease.candidate_hash)):
            raise TransmissionError("protected_pinned_asgi_lease_refused")
        attempted = False
        try:
            with self.sender.known_restore_delivery_window():
                status, headers, body = _verified_envelope_fields(lease.envelope_bytes)
                if (not 200 <= status <= 599 or status in {204, 205, 304}
                        or any(name in {"connection", "keep-alive", "proxy-authenticate",
                                        "proxy-authorization", "te", "trailer", "transfer-encoding",
                                        "upgrade", "content-encoding"} for name, _ in headers)):
                    raise TransmissionError("protected_pinned_asgi_http_unsupported")
                for message in (
                    {"type": "http.response.start", "status": status,
                     "headers": [(name.encode("ascii"), value.encode("latin-1"))
                                 for name, value in headers]},
                    {"type": "http.response.body", "body": body},
                ):
                    remaining = lease.transmission_deadline - self.clock()
                    if remaining <= 0:
                        raise TransmissionError("protected_pinned_asgi_deadline_exceeded")
                    attempted = True
                    async with asyncio.timeout(remaining):
                        await send(message)
        except BaseException:
            result = self.sender.finish_send(
                admission_id=lease.admission_id, owner=lease.send_owner,
                lease_id=lease.lease_id,
                outcome=(AdmissionState.SEND_PARTIAL_FAILURE if attempted
                         else AdmissionState.SEND_FAILED), attempted=attempted,
            )
            if result is not AdmissionOperationResult.SUCCESS:
                raise TransmissionError("protected_pinned_asgi_terminal_unverifiable") from None
            raise
        result = self.sender.finish_send(
            admission_id=lease.admission_id, owner=lease.send_owner,
            lease_id=lease.lease_id,
            outcome=AdmissionState.SEND_COMPLETED, attempted=True,
        )
        if result is not AdmissionOperationResult.SUCCESS:
            raise TransmissionError("protected_pinned_asgi_terminal_unverifiable")
