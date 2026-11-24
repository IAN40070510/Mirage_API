"""獨立 Sender 專用的不可變 Payload／一次性 Send Lease 與 ASGI 傳輸守衛。"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
from typing import Callable
from uuid import UUID, uuid4

from deception.api.fingerprint import fingerprint_request

from .admission import AdmissionOperationResult, AdmissionState
from .models import ResponseAdmission
from .protected_grant import _ProtectedConnection, _verified_envelope_hashes, ProtectedGrantError
from .transmission import TransmissionError, current_time, response_envelope, response_hashes


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


class PostgresProtectedSender(_ProtectedConnection):
    """由獨立實體 Sender Login 消費已 Authorize 的 Snapshot，不重新判定政策。"""

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
                              s.world_generation_id,s.candidate_ref
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
                pinned = bytes(row[7])
                admission = ResponseAdmission.model_validate(row[3])
                verified_hashes = _verified_envelope_hashes(pinned)
                if (verified_hashes != (
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
