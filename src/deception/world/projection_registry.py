"""核准 Projection Evidence 的版本化讀取與撤銷控制。"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Protocol

from .models import ProjectionEvidence
from .postgres_store import psycopg
from .store import WorldStoreError, WorldStoreStatus


class ProjectionAuthorizationResult(StrEnum):
    """描述 Projection Registry 是否允許目前的投影證據。"""

    AUTHORIZED = "AUTHORIZED"
    UNKNOWN_CONTRACT = "UNKNOWN_CONTRACT"
    REVOKED = "REVOKED"
    SOURCE_MISMATCH = "SOURCE_MISMATCH"
    PROFILE_MISMATCH = "PROFILE_MISMATCH"


class ProjectionRegistryError(RuntimeError):
    """表示 Registry 嘗試寫入不合法或過期的核准資料。"""


@dataclass(frozen=True)
class ProjectionAuthorization:
    """保存一次成功 Registry 授權的固定版本證據。"""

    projection_contract_hash: str
    source_spec_sha256: str
    compatibility_profile_sha256: str
    registry_revision: int


@dataclass
class _ProjectionRecord:
    """保存可撤銷的 Projection Evidence 與其 Registry 狀態。"""

    evidence: ProjectionEvidence
    registry_revision: int
    revoked: bool = False


@dataclass(frozen=True)
class ProjectionAuthorizationDecision:
    """封裝授權結果與成功時可供 Admission 引用的證據。"""

    result: ProjectionAuthorizationResult
    authorization: ProjectionAuthorization | None = None


class ProjectionRegistryProtocol(Protocol):
    """定義 Grant 驗證所需的最小 Projection Registry 介面。"""

    def authorize(
        self,
        *,
        projection_contract_hash: str,
        source_spec_sha256: str,
        compatibility_profile_sha256: str,
    ) -> ProjectionAuthorizationDecision:
        """以契約、來源與 Profile 版本核准或拒絕投影。"""
        ...


class ProjectionRegistry:
    """以單調 revision 管理核准 Projection，拒絕未知或撤銷契約。"""

    def __init__(self) -> None:
        """建立空的 Registry；正式部署可由共享資料庫實作同一介面。"""
        self._lock = RLock()
        self._records: dict[str, _ProjectionRecord] = {}

    def register(self, evidence: ProjectionEvidence, *, registry_revision: int) -> None:
        """以遞增 revision 登錄新的核准證據，重複或倒退版本會拒絕。"""
        with self._lock:
            contract_hash = evidence.projection_contract_hash
            current = self._records.get(contract_hash)
            if current is not None:
                if current.revoked:
                    raise ProjectionRegistryError("revoked_contract_cannot_be_reused")
                if registry_revision <= current.registry_revision:
                    raise ProjectionRegistryError("registry_revision_not_monotonic")
            self._records[contract_hash] = _ProjectionRecord(evidence, registry_revision)

    def revoke(self, projection_contract_hash: str, *, registry_revision: int) -> None:
        """以更高 revision 撤銷契約；未知或過期撤銷請求會拒絕。"""
        with self._lock:
            record = self._records.get(projection_contract_hash)
            if record is None:
                raise ProjectionRegistryError("unknown_projection_contract")
            if registry_revision <= record.registry_revision:
                raise ProjectionRegistryError("registry_revision_not_monotonic")
            record.registry_revision = registry_revision
            record.revoked = True

    def authorize(
        self,
        *,
        projection_contract_hash: str,
        source_spec_sha256: str,
        compatibility_profile_sha256: str,
    ) -> ProjectionAuthorizationDecision:
        """核對契約、官方規格與 Profile 版本，通過才回傳授權證據。"""
        with self._lock:
            record = self._records.get(projection_contract_hash)
            if record is None:
                return ProjectionAuthorizationDecision(ProjectionAuthorizationResult.UNKNOWN_CONTRACT)
            if record.revoked:
                return ProjectionAuthorizationDecision(ProjectionAuthorizationResult.REVOKED)
            evidence = record.evidence
            if evidence.source_spec_sha256 != source_spec_sha256:
                return ProjectionAuthorizationDecision(ProjectionAuthorizationResult.SOURCE_MISMATCH)
            if evidence.compatibility_profile.profile_sha256 != compatibility_profile_sha256:
                return ProjectionAuthorizationDecision(ProjectionAuthorizationResult.PROFILE_MISMATCH)
            return ProjectionAuthorizationDecision(
                result=ProjectionAuthorizationResult.AUTHORIZED,
                authorization=ProjectionAuthorization(
                    projection_contract_hash=projection_contract_hash,
                    source_spec_sha256=source_spec_sha256,
                    compatibility_profile_sha256=compatibility_profile_sha256,
                    registry_revision=record.registry_revision,
                ),
            )

    def revision(self, projection_contract_hash: str) -> int | None:
        """讀取契約目前 Registry revision，未知契約回傳空值。"""
        with self._lock:
            record = self._records.get(projection_contract_hash)
            return None if record is None else record.registry_revision


class PostgresProjectionRegistry:
    """以 PostgreSQL row lock 保存跨 Instance 的 Projection 授權與撤銷。"""

    def __init__(self, dsn: str) -> None:
        """建立共享 Registry；資料庫連線延後到每次操作。"""
        if not dsn.strip():
            raise ValueError("dsn must not be empty")
        self._dsn = dsn

    def register(self, evidence: ProjectionEvidence, *, registry_revision: int) -> None:
        """在交易內登錄核准證據，拒絕重用或倒退 revision。"""
        contract_hash = evidence.projection_contract_hash
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT registry_revision, revoked
                    FROM projection_registry
                    WHERE projection_contract_hash = %s
                    FOR UPDATE
                    """,
                    (contract_hash,),
                )
                current = cursor.fetchone()
                if current is not None:
                    if current[1]:
                        raise ProjectionRegistryError("revoked_contract_cannot_be_reused")
                    if registry_revision <= current[0]:
                        raise ProjectionRegistryError("registry_revision_not_monotonic")
                cursor.execute(
                    """
                    INSERT INTO projection_registry (
                        projection_contract_hash, source_spec_sha256,
                        compatibility_profile_sha256, registry_revision,
                        revoked, evidence
                    ) VALUES (%s, %s, %s, %s, FALSE, %s::jsonb)
                    ON CONFLICT (projection_contract_hash) DO UPDATE SET
                        source_spec_sha256 = EXCLUDED.source_spec_sha256,
                        compatibility_profile_sha256 = EXCLUDED.compatibility_profile_sha256,
                        registry_revision = EXCLUDED.registry_revision,
                        revoked = FALSE,
                        evidence = EXCLUDED.evidence
                    """,
                    (
                        contract_hash,
                        evidence.source_spec_sha256,
                        evidence.compatibility_profile.profile_sha256,
                        registry_revision,
                        json.dumps(evidence.model_dump(mode="json"), ensure_ascii=False),
                    ),
                )

    def revoke(self, projection_contract_hash: str, *, registry_revision: int) -> None:
        """在交易內以更高 revision 撤銷 Projection Contract。"""
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT registry_revision
                    FROM projection_registry
                    WHERE projection_contract_hash = %s
                    FOR UPDATE
                    """,
                    (projection_contract_hash,),
                )
                current = cursor.fetchone()
                if current is None:
                    raise ProjectionRegistryError("unknown_projection_contract")
                if registry_revision <= current[0]:
                    raise ProjectionRegistryError("registry_revision_not_monotonic")
                cursor.execute(
                    """
                    UPDATE projection_registry
                    SET registry_revision = %s, revoked = TRUE
                    WHERE projection_contract_hash = %s
                    """,
                    (registry_revision, projection_contract_hash),
                )

    def authorize(
        self,
        *,
        projection_contract_hash: str,
        source_spec_sha256: str,
        compatibility_profile_sha256: str,
    ) -> ProjectionAuthorizationDecision:
        """從共享 Registry 讀取版本證據並以 fail-closed 結果授權。"""
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT source_spec_sha256, compatibility_profile_sha256,
                           registry_revision, revoked
                    FROM projection_registry
                    WHERE projection_contract_hash = %s
                    """,
                    (projection_contract_hash,),
                )
                row = cursor.fetchone()
        if row is None:
            return ProjectionAuthorizationDecision(ProjectionAuthorizationResult.UNKNOWN_CONTRACT)
        if row[3]:
            return ProjectionAuthorizationDecision(ProjectionAuthorizationResult.REVOKED)
        if row[0] != source_spec_sha256:
            return ProjectionAuthorizationDecision(ProjectionAuthorizationResult.SOURCE_MISMATCH)
        if row[1] != compatibility_profile_sha256:
            return ProjectionAuthorizationDecision(ProjectionAuthorizationResult.PROFILE_MISMATCH)
        return ProjectionAuthorizationDecision(
            result=ProjectionAuthorizationResult.AUTHORIZED,
            authorization=ProjectionAuthorization(
                projection_contract_hash=projection_contract_hash,
                source_spec_sha256=source_spec_sha256,
                compatibility_profile_sha256=compatibility_profile_sha256,
                registry_revision=row[2],
            ),
        )

    def _connection(self):
        """建立 PostgreSQL 連線，將驅動或服務不可用轉成安全錯誤。"""
        if psycopg is None:
            raise WorldStoreError(WorldStoreStatus.STORAGE_UNAVAILABLE.value)
        try:
            return psycopg.connect(self._dsn)
        except psycopg.Error as exc:
            raise WorldStoreError(WorldStoreStatus.STORAGE_UNAVAILABLE.value) from exc
