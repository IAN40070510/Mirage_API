"""將受信任 Ingress Receipt 與不可變 Candidate 一次性綁定至 Admission。"""

from __future__ import annotations

import hashlib
import json
import re
from uuid import UUID, uuid4

from deception.security.key_revocation import PostgresTrustedKeyRevocations

from .admission import AdmissionOperationResult, AdmissionState
from .models import ProjectionEvidence, ResponseAdmission, ResponseSource, WorldScope
from .postgres_store import psycopg
from .projection_registry import PostgresProjectionRegistry
from .store import WorldStoreError, WorldStoreStatus
from .transmission import response_envelope, response_hashes


class ProtectedGrantError(ValueError):
    """表示證據、有效資料庫身分或受保護交易不符合安全合約。"""


def _scope_values(scope: WorldScope) -> tuple[str, str, str, str]:
    """固定完整環境、部署、Session、世代順序，避免跨 Scope 組合查詢。"""
    checked = WorldScope.model_validate(scope.model_dump())
    return (checked.environment_id, checked.deployment_id,
            checked.session_id, checked.world_generation_id)


def _require_digest(value: str) -> str:
    """限定授權證據為精確小寫 SHA-256，不將任意字串當作 hash。"""
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ProtectedGrantError("invalid_authorization_digest")
    return value


def _decode_fields(data: bytes, *, expected: int | None = None) -> tuple[bytes, ...]:
    """嚴格解碼 Envelope v1 長度前綴，拒絕截斷、超長與非正規分段。"""
    values = []
    index = 0
    while index < len(data):
        if len(data) - index < 8:
            raise ProtectedGrantError("candidate_envelope_truncated")
        size = int.from_bytes(data[index:index + 8], "big")
        index += 8
        if size > len(data) - index:
            raise ProtectedGrantError("candidate_envelope_invalid_length")
        values.append(data[index:index + size])
        index += size
    if expected is not None and len(values) != expected:
        raise ProtectedGrantError("candidate_envelope_wrong_fields")
    return tuple(values)


def _verified_envelope_hashes(envelope: bytes) -> tuple[str, str, str]:
    """從**實際保存**的 v1 Envelope 重新計算 body／semantic headers 摘要。

    不能只驗 supplied envelope_hash 就採信 Runtime 或 Validator 傳入的另外
    兩個摘要；本函式亦拒絕非規範 status/header 的重序列化歧義。
    """
    version, status_data, encoded_headers, body = _decode_fields(envelope, expected=4)
    if version != b"1" or not status_data.isdigit():
        raise ProtectedGrantError("candidate_envelope_invalid_version_or_status")
    status = int(status_data)
    if str(status).encode("ascii") != status_data or not 100 <= status <= 599:
        raise ProtectedGrantError("candidate_envelope_invalid_status")
    headers = []
    for part in _decode_fields(encoded_headers):
        name_data, value_data = _decode_fields(part, expected=2)
        try:
            name = name_data.decode("ascii")
            value = value_data.decode("latin-1")
        except UnicodeError as exc:
            raise ProtectedGrantError("candidate_envelope_invalid_header") from exc
        if (not name or name.encode("ascii") != name_data or name.lower() != name
                or "\r" in name or "\n" in name or "\r" in value or "\n" in value):
            raise ProtectedGrantError("candidate_envelope_invalid_header")
        headers.append((name, value))
    if response_envelope(status, headers, body) != envelope:
        raise ProtectedGrantError("candidate_envelope_not_canonical")
    return response_hashes(status, headers, body)


def _protected_lock(cursor, kind: str, identity: dict[str, str | int]) -> bool:
    """透過白名單 SECURITY DEFINER 取得物理 Row Lock，而不授予敏感欄 UPDATE。

    此入口不是 Runtime 公開 API；DB REVOKE PUBLIC EXECUTE 且只有獨立 Validator
    或 Authorizer Role 可執行。鎖持續至外層同一 transaction commit/rollback。
    """
    cursor.execute("SELECT protected_lock_reference(%s,%s::jsonb)",
                   (kind, json.dumps(identity, sort_keys=True)))
    return cursor.fetchone()[0] is True


def _authorized_registry_revision(cursor, evidence: ProjectionEvidence) -> int | None:
    """先鎖 Profile 撤銷域，再以受保護函式鎖 Registry，才讀最新政策欄位。"""
    profile = evidence.compatibility_profile.profile_sha256
    if PostgresProjectionRegistry.profile_state_in_transaction(cursor, profile) is not None:
        return None
    if not _protected_lock(cursor, "registry", {"contract_hash": evidence.projection_contract_hash}):
        return None
    cursor.execute(
        """SELECT source_spec_sha256,compatibility_profile_sha256,registry_revision,revoked
           FROM projection_registry WHERE projection_contract_hash=%s""",
        (evidence.projection_contract_hash,),
    )
    row = cursor.fetchone()
    if row is None or row[3] or row[0] != evidence.source_spec_sha256 or row[1] != profile:
        return None
    return row[2]


class _ProtectedConnection:
    """每個受保護作業使用獨立實體 Login，不透過 SET ROLE 共用 Runtime Pool。"""

    def __init__(self, dsn: str, *, expected_login: str) -> None:
        """固定受信任服務所屬的 PostgreSQL Login；不接受未命名身分。"""
        if not isinstance(dsn, str) or not dsn.strip() or not expected_login:
            raise ProtectedGrantError("protected_service_identity_required")
        self._dsn = dsn
        self._login = expected_login

    def _connection(self):
        """確認實體 Login 與當前 Role 完全一致，不採信動態 SET ROLE。"""
        if psycopg is None:
            raise WorldStoreError(WorldStoreStatus.STORAGE_UNAVAILABLE.value)
        connection = psycopg.connect(self._dsn, connect_timeout=5)
        try:
            row = connection.execute("SELECT session_user, current_user").fetchone()
            if row != (self._login, self._login):
                raise ProtectedGrantError("protected_service_login_mismatch")
            return connection
        except BaseException:
            connection.close()
            raise


class PostgresCandidatePromoter(_ProtectedConnection):
    """由隔離 Candidate Validator 將低信任暫存封套驗證並複製成唯讀版本。"""

    def promote(
        self, *, receipt_id: UUID, scope: WorldScope, candidate_ref: str,
        request_fingerprint: str,
        envelope_hash: str, immutable_body_hash: str, semantic_headers_hash: str,
        evidence: ProjectionEvidence, source: ResponseSource,
    ) -> int:
        """同交易鎖定來源、核對精確 bytes／政策後建立 version=1 Promotion。

        輸入證據只能由與 Runtime 隔離的 Validator 產生。真正業務投影驗證須在
        該 Validator 邊界完成，這個資料庫交易不把 hash 一致誤稱為業務政策證明。
        複製 bytes 避免 Runtime 事後更新暫存 Candidate 使已核准封套改變。
        """
        checked = ProjectionEvidence.model_validate(evidence.model_dump())
        source_value = source.model_dump(mode="json")
        for digest in (request_fingerprint, envelope_hash, immutable_body_hash, semantic_headers_hash):
            _require_digest(digest)
        if not isinstance(receipt_id, UUID) or receipt_id.version != 4:
            raise ProtectedGrantError("invalid_candidate_receipt_id")
        if not candidate_ref or len(candidate_ref) > 256:
            raise ProtectedGrantError("invalid_candidate_reference")
        with self._connection() as connection:
            with connection.cursor() as cursor:
                candidate_identity = {**scope.model_dump(), "candidate_ref": candidate_ref}
                if not _protected_lock(cursor, "candidate", candidate_identity):
                    raise ProtectedGrantError("candidate_not_found")
                cursor.execute(
                    """SELECT candidate_hash, body, expires_at FROM candidate_records
                       WHERE environment_id=%s AND deployment_id=%s AND session_id=%s
                         AND world_generation_id=%s AND candidate_ref=%s""",
                    (*_scope_values(scope), candidate_ref),
                )
                candidate = cursor.fetchone()
                if candidate is None or candidate[0] != envelope_hash or \
                        hashlib.sha256(bytes(candidate[1])).hexdigest() != envelope_hash:
                    raise ProtectedGrantError("candidate_bytes_not_verified")
                actual_hashes = _verified_envelope_hashes(bytes(candidate[1]))
                if actual_hashes != (envelope_hash, immutable_body_hash, semantic_headers_hash):
                    raise ProtectedGrantError("candidate_hash_components_mismatch")
                if _authorized_registry_revision(cursor, checked) is None:
                    raise ProtectedGrantError("candidate_policy_not_authorized")
                if not self._source_matches(cursor, receipt_id, scope, request_fingerprint,
                                            source, envelope_hash):
                    raise ProtectedGrantError("candidate_source_unverifiable")
                cursor.execute("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                if candidate[2] <= cursor.fetchone()[0]:
                    raise ProtectedGrantError("candidate_expired")
                cursor.execute(
                    """INSERT INTO protected_candidate_promotions (
                           environment_id, deployment_id, session_id, world_generation_id,
                           candidate_ref, candidate_version, request_fingerprint, candidate_hash,
                           immutable_body_hash, semantic_headers_hash, projection_contract_hash,
                           source_spec_sha256, profile_sha256, source, expires_at, envelope_bytes,
                           ingress_receipt_id
                       ) VALUES (%s,%s,%s,%s,%s,1,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s)
                       RETURNING candidate_version""",
                    (*_scope_values(scope), candidate_ref, request_fingerprint, envelope_hash,
                     immutable_body_hash, semantic_headers_hash, checked.projection_contract_hash,
                     checked.source_spec_sha256, checked.compatibility_profile.profile_sha256,
                     json.dumps(source_value, sort_keys=True), candidate[2], candidate[1], receipt_id),
                )
                return cursor.fetchone()[0]

    @staticmethod
    def _source_matches(cursor, receipt_id: UUID, scope: WorldScope,
                        fingerprint: str, source: ResponseSource,
                        envelope_hash: str) -> bool:
        """只接受同 Receipt、完整 Scope 且綁定精確封套的受保護來源證明。"""
        if source.kind == "snapshot":
            if not _protected_lock(cursor, "read_admission", {"read_admission_id": source.read_admission_id}):
                return False
            cursor.execute(
                """SELECT 1 FROM protected_world_read_sources p
                   JOIN read_admissions r USING (read_admission_id)
                   WHERE p.read_admission_id=%s AND p.receipt_id=%s
                   AND p.environment_id=%s AND p.deployment_id=%s AND p.session_id=%s
                   AND p.world_generation_id=%s AND p.request_fingerprint=%s
                   AND p.state_version=%s AND p.state_hash=%s
                   AND (r.environment_id,r.deployment_id,r.session_id,r.world_generation_id)
                       =(p.environment_id,p.deployment_id,p.session_id,p.world_generation_id)
                   AND r.request_binding_digest=p.request_fingerprint
                   AND r.state_version=p.state_version AND r.state_hash=p.state_hash
                   AND r.expires_at>floor(extract(epoch FROM clock_timestamp()))::bigint
                   """,
                (source.read_admission_id, receipt_id, *_scope_values(scope), fingerprint,
                 source.state_version, source.state_hash),
            )
            return cursor.fetchone() is not None
        if source.kind == "committed_operation":
            # 只接受同交易的受保護 Executor 證據；單靠 Runtime 可寫的舊列不足。
            cursor.execute(
                """SELECT 1 FROM protected_world_commit_sources p
                   JOIN world_operations o ON o.commit_attempt_id=p.commit_attempt_id
                   WHERE p.receipt_id=%s AND p.environment_id=%s AND p.deployment_id=%s
                     AND p.session_id=%s AND p.world_generation_id=%s
                     AND p.request_fingerprint=%s AND p.result_digest=%s
                     AND p.state_version=%s AND p.state_hash=%s
                     AND o.status='committed' AND o.result_digest=p.result_digest
                     AND o.state_version=p.state_version AND o.state_hash=p.state_hash
                     AND (o.environment_id,o.deployment_id,o.session_id,o.world_generation_id)
                         =(p.environment_id,p.deployment_id,p.session_id,p.world_generation_id)
                """,
                (receipt_id, *_scope_values(scope), fingerprint,
                 source.operation_result_digest, source.committed_state_version,
                 source.committed_state_hash),
            )
            return cursor.fetchone() is not None
        if source.kind == "cart_creation":
            # 只允許特殊 Creator→Derived 建立鏈；Promotion/Grant 仍使用 Creator Scope。
            from .protected_native_http import _verified_cart_creation

            try:
                _, _, _, payload = _verified_cart_creation(
                    cursor, receipt_id, expected_scope=scope,
                    expected_fingerprint=fingerprint, expected_source=source,
                )
            except (ProtectedGrantError, ValueError):
                return False
            body = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                              separators=(",", ":")).encode("utf-8")
            headers = (("content-type", "application/json"),)
            return response_hashes(200, headers, body)[0] == envelope_hash
        if source.kind == "security_error":
            # 真正 Handler 的 409 或獨立 Executor 已驗證原始 HTTP 的 Medusa 400/404。
            cursor.execute(
                """SELECT 1 FROM protected_world_rejection_sources p
                   JOIN world_operations o ON o.commit_attempt_id=p.commit_attempt_id
                   WHERE p.receipt_id=%s AND p.environment_id=%s AND p.deployment_id=%s
                     AND p.session_id=%s AND p.world_generation_id=%s
                     AND p.request_fingerprint=%s AND p.template_id=%s
                     AND p.contract_revision=%s AND p.envelope_hash=%s
                     AND o.operation=p.operation AND o.status='rejected'
                     AND o.result_digest=p.result_digest
                     AND o.result->>'code'=p.template_id
                     AND (o.environment_id,o.deployment_id,o.session_id,o.world_generation_id)
                         =(p.environment_id,p.deployment_id,p.session_id,p.world_generation_id)
                """,
                (receipt_id, *_scope_values(scope), fingerprint,
                 source.template_id, source.contract_revision, envelope_hash),
            )
            if cursor.fetchone() is not None:
                return True
            cursor.execute(
                """SELECT 1 FROM protected_medusa_rejection_sources p
                   JOIN protected_http_operation_bindings b ON b.receipt_id=p.receipt_id
                   WHERE p.receipt_id=%s
                     AND p.environment_id=%s AND p.deployment_id=%s
                     AND p.session_id=%s AND p.world_generation_id=%s
                     AND p.request_fingerprint=%s
                     AND b.platform='medusa-native-cart' AND b.operation_id=p.operation_id
                     AND b.request_fingerprint=p.request_fingerprint
                     AND p.template_id=%s AND p.contract_revision=%s AND p.envelope_hash=%s
                     AND p.status_code IN (400,404)
                     AND EXISTS (
                            SELECT 1 FROM protected_world_read_sources r
                            JOIN read_admissions a USING (read_admission_id)
                            WHERE r.read_admission_id=p.read_admission_id
                              AND r.receipt_id=p.receipt_id
                              AND (r.environment_id,r.deployment_id,r.session_id,r.world_generation_id)
                                  =(p.environment_id,p.deployment_id,p.session_id,p.world_generation_id)
                              AND r.request_fingerprint=p.request_fingerprint
                              AND a.state_version=r.state_version AND a.state_hash=r.state_hash
                              AND a.request_binding_digest=p.request_fingerprint
                              AND a.expires_at>floor(extract(epoch FROM clock_timestamp()))::bigint)
                """,
                (receipt_id, *_scope_values(scope), fingerprint,
                 source.template_id, source.contract_revision, envelope_hash),
            )
            return cursor.fetchone() is not None
        # 無受保護來源的安全錯誤模板不得借 Candidate Promotion 混入授權。
        return False


class PostgresProtectedAuthorizer(_ProtectedConnection):
    """獨立 Authorizer Login 在同一個 Read Committed Tx 建立唯一 Binding 與 Admission。"""

    def grant(
        self, *, operation_id: UUID, receipt_id: UUID, scope: WorldScope,
        candidate_ref: str, candidate_version: int, authorization_revision: str,
        authorization_deadline: int, transmission_deadline: int,
        evidence: ProjectionEvidence,
    ) -> ResponseAdmission:
        """只從已提交 Receipt 和已 Promotion 的不可變 Candidate 取得授權資料。

        Session Head、Generation、Key／Profile Revocation 與 Registry 均在單一
        實體 PostgreSQL 連線、一次交易中核查。唯一鍵防止同 Receipt 重綁；
        任何失敗都回滾 Admission、Generation revision 及 Binding，沒有降級路徑。
        """
        if not isinstance(operation_id, UUID) or not isinstance(receipt_id, UUID):
            raise ProtectedGrantError("invalid_protected_operation_id")
        if type(candidate_version) is not int or candidate_version != 1:
            raise ProtectedGrantError("unsupported_candidate_version")
        checked = ProjectionEvidence.model_validate(evidence.model_dump())
        if not authorization_revision or len(authorization_revision) > 128:
            raise ProtectedGrantError("invalid_authorization_revision")
        input_digest = self.intent_digest(
            operation_id=operation_id, receipt_id=receipt_id, scope=scope,
            candidate_ref=candidate_ref, candidate_version=candidate_version,
            authorization_revision=authorization_revision,
            authorization_deadline=authorization_deadline,
            transmission_deadline=transmission_deadline, evidence=checked,
        )
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET LOCAL lock_timeout='3s'")
                cursor.execute("SELECT current_setting('transaction_isolation')")
                if cursor.fetchone()[0] != "read committed":
                    raise ProtectedGrantError("protected_grant_requires_read_committed")
                if not _protected_lock(cursor, "session_head", scope.model_dump()):
                    raise ProtectedGrantError("missing_session_head")
                cursor.execute(
                    """SELECT session_epoch FROM session_heads
                       WHERE environment_id=%s AND deployment_id=%s AND session_id=%s""",
                    _scope_values(scope)[:3],
                )
                head = cursor.fetchone()
                if head is None:
                    raise ProtectedGrantError("missing_session_head")
                if not _protected_lock(cursor, "session_binding", {
                        **scope.model_dump(), "session_epoch": head[0]}):
                    raise ProtectedGrantError("session_generation_mismatch")
                cursor.execute(
                    """SELECT 1 FROM session_world_bindings WHERE environment_id=%s
                       AND deployment_id=%s AND session_id=%s AND session_epoch=%s
                       AND world_generation_id=%s""",
                    (*_scope_values(scope)[:3], head[0], scope.world_generation_id),
                )
                if cursor.fetchone() is None:
                    raise ProtectedGrantError("session_generation_mismatch")
                if not _protected_lock(cursor, "receipt", {"receipt_id": str(receipt_id)}):
                    raise ProtectedGrantError("receipt_missing")
                cursor.execute(
                    """SELECT issuer, key_id, environment_id, deployment_id, session_id,
                              session_epoch, request_fingerprint, token_expires_at
                       FROM ingress_receipts WHERE receipt_id=%s""",
                    (receipt_id,),
                )
                receipt = cursor.fetchone()
                if (receipt is None or receipt[2:6] != (*_scope_values(scope)[:3], head[0])):
                    raise ProtectedGrantError("receipt_scope_or_epoch_mismatch")
                if not _protected_lock(cursor, "promotion", {
                        **scope.model_dump(), "candidate_ref": candidate_ref,
                        "candidate_version": candidate_version}):
                    raise ProtectedGrantError("unbound_or_corrupt_candidate")
                cursor.execute(
                    """SELECT request_fingerprint, candidate_hash, immutable_body_hash,
                              semantic_headers_hash, projection_contract_hash,
                              source_spec_sha256, profile_sha256, source, expires_at,
                              envelope_bytes, ingress_receipt_id
                       FROM protected_candidate_promotions
                       WHERE environment_id=%s AND deployment_id=%s AND session_id=%s
                         AND world_generation_id=%s AND candidate_ref=%s AND candidate_version=%s
                       """,
                    (*_scope_values(scope), candidate_ref, candidate_version),
                )
                promoted = cursor.fetchone()
                if (promoted is None or promoted[0] != receipt[6]
                        or promoted[10] != receipt_id
                        or promoted[4:7] != (checked.projection_contract_hash,
                                              checked.source_spec_sha256,
                                              checked.compatibility_profile.profile_sha256)
                        or hashlib.sha256(bytes(promoted[9])).hexdigest() != promoted[1]):
                    raise ProtectedGrantError("unbound_or_corrupt_candidate")
                cursor.execute(
                    """SELECT control_revision, sealed, emergency_revision
                       FROM generation_controls WHERE world_generation_id=%s FOR UPDATE""",
                    (scope.world_generation_id,),
                )
                generation = cursor.fetchone()
                if generation is None or generation[1] or generation[2] is not None:
                    raise ProtectedGrantError("generation_unavailable")
                keys = PostgresTrustedKeyRevocations(
                    self._dsn, environment_id=scope.environment_id, deployment_id=scope.deployment_id)
                keys._lock(cursor, receipt[0], receipt[1])
                if keys._select(cursor, receipt[0], receipt[1]) is not None:
                    raise ProtectedGrantError("receipt_key_revoked")
                registry_revision = _authorized_registry_revision(cursor, checked)
                if registry_revision is None:
                    raise ProtectedGrantError("grant_projection_not_authorized")
                if isinstance(promoted[7], dict) and promoted[7].get("kind") == "cart_creation":
                    # C-01 唯一跨 Scope Source：Promotion 與 Grant 之間派生世界可能
                    # 前進／封存；不能僅憑之前的 immutable Candidate 批准過期 Cart。
                    from .models import CartCreationSource
                    from .protected_native_http import _verified_cart_creation

                    try:
                        source = CartCreationSource.model_validate(promoted[7])
                        _, _, _, payload = _verified_cart_creation(
                            cursor, receipt_id, expected_scope=scope,
                            expected_fingerprint=receipt[6], expected_source=source,
                        )
                    except (ProtectedGrantError, ValueError) as exc:
                        raise ProtectedGrantError("cart_creation_grant_source_unverifiable") from exc
                    body = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                      separators=(",", ":")).encode("utf-8")
                    if response_hashes(200, (("content-type", "application/json"),), body)[0] != promoted[1]:
                        raise ProtectedGrantError("cart_creation_grant_envelope_mismatch")
                cursor.execute("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                decision_time = cursor.fetchone()[0]
                if (decision_time >= receipt[7] or decision_time >= promoted[8]
                        or decision_time >= authorization_deadline
                        or authorization_deadline > transmission_deadline
                        or transmission_deadline > receipt[7]
                        or transmission_deadline > promoted[8]):
                    raise ProtectedGrantError("grant_deadline_not_valid")
                grant_revision = generation[0] + 1
                admission = ResponseAdmission(
                    admission_id=uuid4().hex, request_binding_digest=receipt[6],
                    world_generation_id=scope.world_generation_id,
                    grant_revision=grant_revision,
                    projection_registry_revision=registry_revision,
                    candidate_ref=candidate_ref, candidate_hash=promoted[1],
                    immutable_body_hash=promoted[2], semantic_headers_hash=promoted[3],
                    projection_contract_hash=promoted[4],
                    authorization_revision=authorization_revision,
                    authorization_deadline=authorization_deadline,
                    transmission_deadline=transmission_deadline,
                    source=promoted[7], projection_evidence=checked,
                )
                cursor.execute(
                    """UPDATE generation_controls SET control_revision=%s
                       WHERE world_generation_id=%s""",
                    (grant_revision, scope.world_generation_id),
                )
                cursor.execute(
                    """INSERT INTO response_admissions (
                           admission_id, world_generation_id, authorization_deadline,
                           transmission_deadline, state, admission
                       ) VALUES (%s,%s,%s,%s,%s,%s::jsonb)""",
                    (admission.admission_id, scope.world_generation_id,
                     authorization_deadline, transmission_deadline, AdmissionState.GRANTED.value,
                     json.dumps(admission.model_dump(mode="json"), ensure_ascii=False)),
                )
                cursor.execute(
                    """INSERT INTO protected_grant_bindings (
                           operation_id, input_digest, receipt_id, admission_id,
                           environment_id, deployment_id, session_id, world_generation_id,
                           candidate_ref, candidate_version
                       ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (operation_id, input_digest, receipt_id, admission.admission_id,
                     *_scope_values(scope), candidate_ref, candidate_version),
                )
                return admission

    @staticmethod
    def intent_digest(*, operation_id: UUID, receipt_id: UUID, scope: WorldScope,
                      candidate_ref: str, candidate_version: int,
                      authorization_revision: str, authorization_deadline: int,
                      transmission_deadline: int, evidence: ProjectionEvidence) -> str:
        """在任何 DB 作用前固定一次性意圖摘要，供 COMMIT 不明時核對相同輸入。"""
        data = dict(operation_id=str(operation_id), receipt_id=str(receipt_id),
                    scope=scope.model_dump(mode="json"), candidate_ref=candidate_ref,
                    candidate_version=candidate_version,
                    authorization_revision=authorization_revision,
                    authorization_deadline=authorization_deadline,
                    transmission_deadline=transmission_deadline,
                    evidence=evidence.model_dump(mode="json"))
        return hashlib.sha256(json.dumps(data, ensure_ascii=False, sort_keys=True,
                                         separators=(",", ":")).encode("utf-8")).hexdigest()

    def lookup(self, operation_id: UUID, *, input_digest: str) -> ResponseAdmission | None:
        """未知 COMMIT 只讀同 ID＋同 Digest 結果；不同輸入不可誤取別人授權。"""
        if not isinstance(operation_id, UUID):
            raise ProtectedGrantError("invalid_protected_operation_id")
        _require_digest(input_digest)
        with self._connection() as connection:
            row = connection.execute(
                """SELECT a.admission,b.input_digest FROM protected_grant_bindings b
                   JOIN response_admissions a ON a.admission_id=b.admission_id
                   WHERE b.operation_id=%s""", (operation_id,),
            ).fetchone()
        if row is not None and row[1] != input_digest:
            raise ProtectedGrantError("operation_input_digest_conflict")
        return None if row is None else ResponseAdmission.model_validate(row[0])

    def claim(self, admission_id: str, *, owner: str) -> AdmissionOperationResult:
        """僅在完整可信 Binding 仍有效時持久化一次 Claim；使用鎖後資料庫時間。"""
        return self._advance(admission_id, owner=owner, authorize=False)

    def authorize_send(self, admission_id: str, *, owner: str) -> AdmissionOperationResult:
        """在 SEND_AUTHORIZED 唯一線性化點重查撤銷，之後不再回溯政策判斷。"""
        return self._advance(admission_id, owner=owner, authorize=True)

    def _advance(self, admission_id: str, *, owner: str, authorize: bool) -> AdmissionOperationResult:
        """依 Session → Generation → Admission → Key → Profile 鎖順序進行安全轉移。

        本路徑不能接納沒有 Grant Binding 的舊 Admission，或從 Runtime 提供的
        revoked/now 標記決策。任何 DB 查詢／鎖失敗都向上傳遞並回滾，絕不放行。
        """
        if not admission_id or not owner or len(owner) > 128:
            raise ProtectedGrantError("invalid_authorizer_transition")
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET LOCAL lock_timeout='3s'")
                cursor.execute(
                    """SELECT b.environment_id,b.deployment_id,b.session_id,
                              b.world_generation_id,r.session_epoch,r.issuer,r.key_id,
                              r.token_expires_at,p.profile_sha256
                       FROM protected_grant_bindings b
                       JOIN ingress_receipts r ON r.receipt_id=b.receipt_id
                       JOIN protected_candidate_promotions p
                         ON p.environment_id=b.environment_id
                        AND p.deployment_id=b.deployment_id
                        AND p.session_id=b.session_id
                        AND p.world_generation_id=b.world_generation_id
                        AND p.candidate_ref=b.candidate_ref
                        AND p.candidate_version=b.candidate_version
                       WHERE b.admission_id=%s""", (admission_id,),
                )
                binding = cursor.fetchone()
                if binding is None:
                    return AdmissionOperationResult.REJECTED
                if not _protected_lock(cursor, "session_head", {
                        "environment_id": binding[0], "deployment_id": binding[1],
                        "session_id": binding[2]}):
                    return AdmissionOperationResult.REJECTED
                cursor.execute(
                    """SELECT session_epoch FROM session_heads WHERE environment_id=%s
                       AND deployment_id=%s AND session_id=%s""", binding[:3],
                )
                epoch = cursor.fetchone()
                if epoch is None or epoch[0] != binding[4]:
                    return AdmissionOperationResult.REJECTED
                cursor.execute(
                    """SELECT emergency_revision, sealed FROM generation_controls
                       WHERE world_generation_id=%s FOR UPDATE""", (binding[3],),
                )
                generation = cursor.fetchone()
                if generation is None:
                    return AdmissionOperationResult.REJECTED
                cursor.execute(
                    """SELECT state, authorization_deadline, transmission_deadline,
                              claim_owner, admission FROM response_admissions
                       WHERE admission_id=%s AND world_generation_id=%s FOR UPDATE""",
                    (admission_id, binding[3]),
                )
                row = cursor.fetchone()
                desired = AdmissionState.CLAIMED.value if authorize else AdmissionState.GRANTED.value
                if row is None or row[0] != desired:
                    return AdmissionOperationResult.REJECTED
                if authorize and row[3] != owner:
                    return AdmissionOperationResult.REJECTED
                claims = ResponseAdmission.model_validate(row[4])
                if claims.projection_evidence.compatibility_profile.profile_sha256 != binding[8]:
                    raise ProtectedGrantError("binding_profile_mismatch")
                keys = PostgresTrustedKeyRevocations(
                    self._dsn, environment_id=binding[0], deployment_id=binding[1])
                keys._lock(cursor, binding[5], binding[6])
                revoked_key = keys._select(cursor, binding[5], binding[6]) is not None
                registry_revision = _authorized_registry_revision(cursor, claims.projection_evidence)
                cursor.execute("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                db_now = cursor.fetchone()[0]
                deadline = row[2] if authorize else row[1]
                revoked = (generation[0] is not None or generation[1]
                           or revoked_key or registry_revision is None)
                expired = db_now >= deadline or db_now >= binding[7]
                if revoked or expired:
                    terminal = AdmissionState.ABANDONED.value if revoked else AdmissionState.EXPIRED.value
                    cursor.execute("UPDATE response_admissions SET state=%s WHERE admission_id=%s",
                                   (terminal, admission_id))
                    return AdmissionOperationResult.REJECTED
                cursor.execute(
                    """UPDATE generation_controls SET control_revision=control_revision+1
                       WHERE world_generation_id=%s RETURNING control_revision""", (binding[3],),
                )
                revision = cursor.fetchone()[0]
                if authorize:
                    cursor.execute(
                        """UPDATE response_admissions SET state=%s,
                           send_authorization_revision=%s WHERE admission_id=%s""",
                        (AdmissionState.SEND_AUTHORIZED.value, revision, admission_id),
                    )
                    cursor.execute(
                        """INSERT INTO protected_authorized_http_snapshots (
                               admission_id,operation_id,receipt_id,environment_id,
                               deployment_id,session_id,world_generation_id,candidate_ref,
                               candidate_version,request_fingerprint,candidate_hash,
                               envelope_bytes,send_owner,transmission_deadline)
                           SELECT b.admission_id,b.operation_id,b.receipt_id,
                                  b.environment_id,b.deployment_id,b.session_id,
                                  b.world_generation_id,b.candidate_ref,b.candidate_version,
                                  r.request_fingerprint,p.candidate_hash,p.envelope_bytes,%s,%s
                           FROM protected_grant_bindings b
                           JOIN ingress_receipts r ON r.receipt_id=b.receipt_id
                           JOIN protected_candidate_promotions p
                             ON (p.environment_id,p.deployment_id,p.session_id,
                                 p.world_generation_id,p.candidate_ref,p.candidate_version)
                              =(b.environment_id,b.deployment_id,b.session_id,
                                 b.world_generation_id,b.candidate_ref,b.candidate_version)
                           WHERE b.admission_id=%s AND p.ingress_receipt_id=b.receipt_id
                             AND p.request_fingerprint=r.request_fingerprint
                             AND p.candidate_hash=%s""",
                        (owner, row[2], admission_id, claims.candidate_hash),
                    )
                    if cursor.rowcount != 1:
                        raise ProtectedGrantError("authorized_http_snapshot_unverifiable")
                else:
                    cursor.execute(
                        """UPDATE response_admissions SET state=%s,claim_owner=%s,
                           claim_revision=%s WHERE admission_id=%s""",
                        (AdmissionState.CLAIMED.value, owner, revision, admission_id),
                    )
                return AdmissionOperationResult.SUCCESS
