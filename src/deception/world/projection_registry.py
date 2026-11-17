"""核准 Projection Evidence 的版本化讀取與撤銷控制。"""

from __future__ import annotations

import json
import re
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Protocol

from .models import ProjectionEvidence
from .postgres_store import psycopg
from .store import WorldStoreError, WorldStoreStatus


# 以實際墓碑資料表 OID 區分撤銷域，避免不同 schema 的同一 Profile 共用管理鎖。
PROFILE_LOCK_KEY = "hashtextextended('mirage-profile:'||'projection_profile_revocations'::regclass::oid::text||':'||%s,0)"


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
class ProfileRevocation:
    """保存不可復活的 Profile 墓碑；revision 與單一契約或 Generation 的序列分開。"""

    compatibility_profile_sha256: str
    registry_revision: int
    emergency: bool


def validate_profile_hash(profile_hash: str) -> None:
    """僅接受精確 SHA-256 Profile 身份，避免管理者誤撤銷名稱或未版本化標籤。"""
    if not isinstance(profile_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", profile_hash):
        raise ValueError("profile hash must be a lowercase SHA-256 digest")


def validate_profile_revocation(profile_hash: str, revision: int, emergency: bool) -> None:
    """驗證管理端 revision 與模式，拒絕 bool 冒充版本以及非布林緊急旗標。"""
    validate_profile_hash(profile_hash)
    if type(revision) is not int or not 1 <= revision <= 2**63 - 1 or type(emergency) is not bool:
        raise ValueError("profile revocation requires a positive int64 revision and boolean mode")


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

    def profile_guard(self, compatibility_profile_sha256: str):
        """在狀態轉換期間保留 Profile 共享控制鎖，回傳當前墓碑或 None。"""
        ...


class ProjectionRegistry:
    """以單調 revision 管理核准 Projection，拒絕未知或撤銷契約。"""

    def __init__(self) -> None:
        """建立空的 Registry；正式部署可由共享資料庫實作同一介面。"""
        self._lock = RLock()
        self._records: dict[str, _ProjectionRecord] = {}
        self._profile_revocations: dict[str, ProfileRevocation] = {}

    @contextmanager
    def profile_guard(self, compatibility_profile_sha256: str):
        """同程序原型在呼叫端狀態轉換完成前持有 Registry 鎖，不快取撤銷結論。"""
        validate_profile_hash(compatibility_profile_sha256)
        with self._lock:
            yield self._profile_revocations.get(compatibility_profile_sha256)

    def profile_revocation(self, compatibility_profile_sha256: str) -> ProfileRevocation | None:
        """唯讀查詢墓碑，供管理端在寫入結果未知後確認狀態，不重新執行撤銷。"""
        with self.profile_guard(compatibility_profile_sha256) as state:
            return state

    def revoke_profile(self, compatibility_profile_sha256: str, *, registry_revision: int,
                       emergency: bool = False) -> ProfileRevocation:
        """永久停用精確 Profile；一般模式保留既有准入，緊急模式不可降級。"""
        validate_profile_revocation(compatibility_profile_sha256, registry_revision, emergency)
        with self._lock:
            current = self._profile_revocations.get(compatibility_profile_sha256)
            if current is not None:
                if registry_revision <= current.registry_revision:
                    raise ProjectionRegistryError("registry_revision_not_monotonic")
                if current.emergency and not emergency:
                    raise ProjectionRegistryError("emergency_profile_revocation_cannot_be_downgraded")
            state = ProfileRevocation(compatibility_profile_sha256, registry_revision, emergency)
            self._profile_revocations[compatibility_profile_sha256] = state
            return state

    def register(self, evidence: ProjectionEvidence, *, registry_revision: int) -> None:
        """以遞增 revision 登錄新的核准證據，重複或倒退版本會拒絕。"""
        with self._lock:
            if evidence.compatibility_profile.profile_sha256 in self._profile_revocations:
                raise ProjectionRegistryError("revoked_profile_cannot_be_reused")
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
            if compatibility_profile_sha256 in self._profile_revocations:
                return ProjectionAuthorizationDecision(ProjectionAuthorizationResult.REVOKED)
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

    @staticmethod
    def _lock_profile(cursor, compatibility_profile_sha256: str, *, exclusive: bool = False) -> None:
        """在有效交易及 Read Committed 下取得 Profile 鎖，避免等待後仍讀舊快照或立即釋鎖。"""
        validate_profile_hash(compatibility_profile_sha256)
        if cursor.connection.autocommit:
            raise ProjectionRegistryError("profile_control_requires_transaction")
        function = "pg_advisory_xact_lock" if exclusive else "pg_advisory_xact_lock_shared"
        cursor.execute("SELECT current_setting('transaction_isolation'), " + function + "(" + PROFILE_LOCK_KEY + ")",
                       (compatibility_profile_sha256,))
        isolation, _ = cursor.fetchone()
        if isolation != "read committed":
            raise ProjectionRegistryError("profile_control_requires_read_committed")

    @staticmethod
    def profile_state_in_transaction(cursor, compatibility_profile_sha256: str) -> ProfileRevocation | None:
        """以交易共享 advisory lock 防止墓碑尚不存在時，撤銷與授權穿越彼此。"""
        PostgresProjectionRegistry._lock_profile(cursor, compatibility_profile_sha256)
        cursor.execute("SELECT registry_revision,emergency FROM projection_profile_revocations "
                       "WHERE compatibility_profile_sha256=%s", (compatibility_profile_sha256,))
        row = cursor.fetchone()
        return None if row is None else ProfileRevocation(compatibility_profile_sha256, *row)

    @contextmanager
    def profile_guard(self, compatibility_profile_sha256: str):
        """在同一交易持有共享 Profile 控制鎖直到呼叫端完成，不把查無當成永久有效。"""
        validate_profile_hash(compatibility_profile_sha256)
        with self._connection() as connection:
            with connection.cursor() as cursor:
                yield self.profile_state_in_transaction(cursor, compatibility_profile_sha256)

    def profile_revocation(self, compatibility_profile_sha256: str) -> ProfileRevocation | None:
        """等待先行撤銷交易完成後唯讀查墓碑；儲存故障向上傳遞，不能假設尚未撤銷。"""
        with self.profile_guard(compatibility_profile_sha256) as state:
            return state

    def revoke_profile(self, compatibility_profile_sha256: str, *, registry_revision: int,
                       emergency: bool = False) -> ProfileRevocation:
        """以排他 Profile 控制鎖提交永久墓碑，與新 Grant、登記及緊急發送邊界排序。"""
        validate_profile_revocation(compatibility_profile_sha256, registry_revision, emergency)
        with self._connection() as connection:
            with connection.cursor() as cursor:
                self._lock_profile(cursor, compatibility_profile_sha256, exclusive=True)
                cursor.execute("SELECT registry_revision,emergency FROM projection_profile_revocations "
                               "WHERE compatibility_profile_sha256=%s FOR UPDATE", (compatibility_profile_sha256,))
                current = cursor.fetchone()
                if current is not None:
                    if registry_revision <= current[0]:
                        raise ProjectionRegistryError("registry_revision_not_monotonic")
                    if current[1] and not emergency:
                        raise ProjectionRegistryError("emergency_profile_revocation_cannot_be_downgraded")
                cursor.execute("INSERT INTO projection_profile_revocations VALUES (%s,%s,%s) "
                    "ON CONFLICT(compatibility_profile_sha256) DO UPDATE SET "
                    "registry_revision=EXCLUDED.registry_revision,emergency=EXCLUDED.emergency",
                    (compatibility_profile_sha256, registry_revision, emergency))
        return ProfileRevocation(compatibility_profile_sha256, registry_revision, emergency)

    def register(self, evidence: ProjectionEvidence, *, registry_revision: int) -> None:
        """在交易內登錄核准證據，拒絕重用或倒退 revision。"""
        contract_hash = evidence.projection_contract_hash
        with self._connection() as connection:
            with connection.cursor() as cursor:
                if self.profile_state_in_transaction(cursor, evidence.compatibility_profile.profile_sha256) is not None:
                    raise ProjectionRegistryError("revoked_profile_cannot_be_reused")
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
                    WHERE NOT projection_registry.revoked
                      AND projection_registry.registry_revision < EXCLUDED.registry_revision
                    """,
                    (
                        contract_hash,
                        evidence.source_spec_sha256,
                        evidence.compatibility_profile.profile_sha256,
                        registry_revision,
                        json.dumps(evidence.model_dump(mode="json"), ensure_ascii=False),
                    ),
                )
                if cursor.rowcount != 1:
                    raise ProjectionRegistryError("concurrent_registration_rejected")

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
                return self.authorize_for_grant(cursor, projection_contract_hash=projection_contract_hash,
                                                source_spec_sha256=source_spec_sha256,
                                                compatibility_profile_sha256=compatibility_profile_sha256)

    def shares_store(self, dsn: str) -> bool:
        """比對部署提供的連線設定，確保 Grant 查詢同一個資料庫與 schema。"""
        return self._dsn == dsn

    def ensure_registered_batch(self, evidences) -> None:
        """啟動時以單一交易登記已審查契約；既有撤銷或來源不符時全批回滾。

        僅新增未知契約，不更新既有 revision、證據或撤銷狀態。固定排序避免
        多個 instance 同時初始化時的鎖順序分歧，Grant 仍逐次核對當前 Registry。
        """
        expected = {}
        for evidence in evidences:
            checked = ProjectionEvidence.model_validate(evidence.model_dump())
            contract = checked.projection_contract_hash
            if contract in expected and expected[contract] != checked:
                raise ProjectionRegistryError("bootstrap_evidence_conflict")
            expected[contract] = checked
        if not expected:
            return
        with self._connection() as connection:
            with connection.cursor() as cursor:
                profiles = sorted({item.compatibility_profile.profile_sha256 for item in expected.values()})
                for profile in profiles:
                    if self.profile_state_in_transaction(cursor, profile) is not None:
                        raise ProjectionRegistryError("bootstrap_profile_not_authorized")
                cursor.executemany("INSERT INTO projection_registry "
                    "(projection_contract_hash,source_spec_sha256,compatibility_profile_sha256,registry_revision,revoked,evidence) "
                    "VALUES (%s,%s,%s,1,FALSE,%s::jsonb) ON CONFLICT DO NOTHING", [
                        (key, expected[key].source_spec_sha256, expected[key].compatibility_profile.profile_sha256,
                         json.dumps(expected[key].model_dump(mode="json"))) for key in sorted(expected)])
                cursor.execute("SELECT projection_contract_hash,source_spec_sha256,compatibility_profile_sha256,revoked "
                    "FROM projection_registry WHERE projection_contract_hash=ANY(%s) "
                    "ORDER BY projection_contract_hash FOR SHARE", (list(expected),))
                rows = cursor.fetchall()
                if len(rows) != len(expected):
                    raise ProjectionRegistryError("bootstrap_registry_incomplete")
                for contract, source, profile, revoked in rows:
                    evidence = expected[contract]
                    if revoked or source != evidence.source_spec_sha256 or profile != evidence.compatibility_profile.profile_sha256:
                        raise ProjectionRegistryError("bootstrap_registry_not_authorized")

    def authorize_for_grant(
        self, cursor, *, projection_contract_hash: str, source_spec_sha256: str,
        compatibility_profile_sha256: str,
    ) -> ProjectionAuthorizationDecision:
        """在呼叫端交易鎖住核准列並比對來源與 Profile，鎖會保留到交易結束。"""
        if self.profile_state_in_transaction(cursor, compatibility_profile_sha256) is not None:
            return ProjectionAuthorizationDecision(ProjectionAuthorizationResult.REVOKED)
        cursor.execute(
            """
            SELECT source_spec_sha256, compatibility_profile_sha256,
                   registry_revision, revoked
            FROM projection_registry
            WHERE projection_contract_hash = %s FOR SHARE
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
