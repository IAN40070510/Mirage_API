"""唯讀 Synthetic World 的共用模型、保存與輸出准入控制。"""

from .admission import AdmissionControl, AdmissionOperationResult, AdmissionState
from .candidate import CandidateLoadResult, CandidateRecord, CandidateStore, CandidateStoreStatus
from .models import (
    CommitSource,
    DeviationApproval,
    ProjectionCompatibilityProfile,
    ProjectionEvidence,
    ResponseAdmission,
    ResponseSource,
    SecurityErrorSource,
    SnapshotSource,
    WorldScope,
    WorldSnapshot,
)
from .postgres_admission import PostgresAdmissionControl
from .postgres_candidate import PostgresCandidateStore
from .postgres_replay import PostgresReplayStore
from .postgres_store import PostgresWorldStore
from .projection_registry import (
    ProjectionAuthorization,
    ProjectionAuthorizationDecision,
    ProjectionAuthorizationResult,
    ProjectionRegistry,
    ProjectionRegistryError,
    ProjectionRegistryProtocol,
    PostgresProjectionRegistry,
)
from .replay import ReplayConsumeResult, ReplayKey, ReplayStore
from .store import (
    InMemoryWorldStore,
    SnapshotCorruptionError,
    WorldLoadResult,
    WorldStore,
    WorldStoreError,
    WorldStoreStatus,
)

__all__ = [
    "AdmissionControl",
    "AdmissionOperationResult",
    "AdmissionState",
    "CommitSource",
    "CandidateLoadResult",
    "CandidateRecord",
    "CandidateStore",
    "CandidateStoreStatus",
    "DeviationApproval",
    "InMemoryWorldStore",
    "ProjectionCompatibilityProfile",
    "ProjectionEvidence",
    "PostgresAdmissionControl",
    "PostgresCandidateStore",
    "PostgresReplayStore",
    "PostgresWorldStore",
    "ProjectionAuthorization",
    "ProjectionAuthorizationDecision",
    "ProjectionAuthorizationResult",
    "ProjectionRegistry",
    "ProjectionRegistryError",
    "ProjectionRegistryProtocol",
    "PostgresProjectionRegistry",
    "ResponseAdmission",
    "ReplayConsumeResult",
    "ReplayKey",
    "ReplayStore",
    "ResponseSource",
    "SecurityErrorSource",
    "SnapshotCorruptionError",
    "SnapshotSource",
    "WorldScope",
    "WorldSnapshot",
    "WorldLoadResult",
    "WorldStore",
    "WorldStoreError",
    "WorldStoreStatus",
]
