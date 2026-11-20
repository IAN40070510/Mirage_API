"""P2 original AttackAssessment: durable cross-instance PostgreSQL one-shot ledger.

Gateway writes before signing. Mirage atomically consumes after JWS verification.
The two services must use the same dedicated PostgreSQL database, different DB
credentials and an explicitly provisioned migration. Never create schema at runtime.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    import psycopg

from pydantic import BaseModel

from deception.scenarios.models import AttackAssessment


class OriginalAssessmentStoreError(RuntimeError):
    """原始判定儲存未就緒、重複、無法確定 commit 或消耗異常，一律 fail-closed。"""


class PostgresOriginalAssessmentStore:
    """部署者注入跨實例不可重放的判定儲存；無記憶體 fallback。"""

    def __init__(
        self,
        dsn: str,
        *,
        mode: Literal["publisher", "consumer"],
        environment_id: str,
        deployment_id: str,
        source_id: str,
        service_id: str,
        site_id: str,
    ) -> None:
        """以不可由 HTTP 修改的部署設定綁定 DB 角色與判定身份。"""
        values = (environment_id, deployment_id, source_id, service_id, site_id)
        if (
            not isinstance(dsn, str)
            or not dsn.strip()
            or mode not in ("publisher", "consumer")
            or any(not isinstance(value, str) or not value or len(value) > 64 for value in values)
        ):
            raise ValueError("invalid_original_assessment_store_configuration")
        self._dsn, self._mode = dsn, mode
        self._scope = values

    def _connection(self) -> psycopg.Connection:
        """延遲開啟受 TLS／部署者控制的 psycopg 連線，避免隱式初始化。"""
        import psycopg

        return psycopg.connect(self._dsn, connect_timeout=5)

    def _validate(self, assessment: AttackAssessment) -> None:
        """比對可信部署身份，不能由用戶原始 JWS 自行宣稱來源。"""
        if (
            not isinstance(assessment, AttackAssessment)
            or (
                assessment.environment_id,
                assessment.deployment_id,
                assessment.source_id,
                assessment.service_id,
                assessment.site_id,
            ) != self._scope
            or assessment.verdict != "malicious"
            or not assessment.attack_types
        ):
            raise OriginalAssessmentStoreError("original_assessment_scope_invalid")

    def publish(self, assessment: BaseModel) -> str:
        """接收 Gateway Payload 或 Mirage 模型；相同 canonical bytes 寫入後才可簽章。"""
        if self._mode != "publisher":
            raise OriginalAssessmentStoreError("original_assessment_publish_forbidden")
        if not isinstance(assessment, BaseModel):
            raise OriginalAssessmentStoreError("original_assessment_type_invalid")
        raw = assessment.model_dump_json()
        try:
            parsed = AttackAssessment.model_validate_json(raw)
        except ValueError as error:
            raise OriginalAssessmentStoreError("original_assessment_type_invalid") from error
        self._validate(parsed)
        if raw != parsed.model_dump_json():
            raise OriginalAssessmentStoreError("original_assessment_noncanonical")
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        try:
            with self._connection() as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SET LOCAL statement_timeout = '5s'")
                    # DB SECURITY DEFINER function owns the INSERT privilege and clock.
                    cursor.execute(
                        """SELECT public.msdss_publish_original_assessment(
                            %s,%s,%s,%s,%s,%s,%s,%s)""",
                        (
                            parsed.assessment_id,
                            parsed.environment_id,
                            parsed.deployment_id,
                            parsed.request_id,
                            digest,
                            raw,
                            parsed.expires_at,
                            parsed.observed_at,
                        ),
                    )
                    row = cursor.fetchone()
                    if row is None or row[0] is not True:
                        raise OriginalAssessmentStoreError(
                            "original_assessment_duplicate_or_expired"
                        )
            return digest
        except OriginalAssessmentStoreError:
            raise
        except Exception as error:
            raise OriginalAssessmentStoreError("original_assessment_publish_unavailable") from error

    def __call__(self, assessment_id: str) -> AttackAssessment | None:
        """原子消耗，跨 worker/host 同一 ID 僅一個成功；不重試未知 commit。"""
        if self._mode != "consumer":
            raise OriginalAssessmentStoreError("original_assessment_consume_forbidden")
        if not isinstance(assessment_id, str) or not 1 <= len(assessment_id) <= 128:
            raise OriginalAssessmentStoreError("original_assessment_id_invalid")
        try:
            with self._connection() as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SET LOCAL statement_timeout = '5s'")
                    cursor.execute(
                        """SELECT original_json,digest
                           FROM public.msdss_take_original_assessment(%s,%s,%s)""",
                        (assessment_id, self._scope[0], self._scope[1]),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        return None
                    raw, digest = row
                    if not isinstance(raw, str) or not isinstance(digest, str):
                        raise OriginalAssessmentStoreError("original_assessment_row_invalid")
                    if not hmac.compare_digest(
                        hashlib.sha256(raw.encode("utf-8")).hexdigest(), digest
                    ):
                        raise OriginalAssessmentStoreError(
                            "original_assessment_row_digest_mismatch"
                        )
                    value = AttackAssessment.model_validate_json(raw)
                    self._validate(value)
                    if value.assessment_id != assessment_id:
                        raise OriginalAssessmentStoreError("original_assessment_row_id_mismatch")
                    # A row originally generated by another model version cannot silently
                    # acquire a different canonical digest during deserialization.
                    if not hmac.compare_digest(
                        hashlib.sha256(value.model_dump_json().encode("utf-8")).hexdigest(), digest
                    ):
                        raise OriginalAssessmentStoreError("original_assessment_canonical_mismatch")
            return value
        except OriginalAssessmentStoreError:
            raise
        except Exception as error:
            raise OriginalAssessmentStoreError("original_assessment_consume_unavailable") from error
