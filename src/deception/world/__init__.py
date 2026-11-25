"""唯讀 Synthetic World 的共用模型、保存與輸出准入控制。"""

from .admission import AdmissionControl, AdmissionOperationResult, AdmissionState
from .candidate import CandidateLoadResult, CandidateRecord, CandidateStore, CandidateStoreStatus
from .commit import CommitResult
from .models import (
    CartCreationSource,
    CommitSource,
    DeviationApproval,
    ProjectionCompatibilityProfile,
    ProjectionEvidence,
    ResponseAdmission,
    ResponseSource,
    SecurityErrorSource,
    SnapshotSource,
    WorldScope,
    WorldCompatibility,
    WorldSnapshot,
)
from .postgres_admission import PostgresAdmissionControl
from .postgres_candidate import PostgresCandidateStore
from .protected_grant import PostgresCandidatePromoter, PostgresProtectedAuthorizer, ProtectedGrantError
from .postgres_replay import PostgresReplayStore
from .postgres_store import PostgresWorldStore
from .projection_registry import (
    ProfileRevocation,
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
    CommitLookupResult,
    InMemoryWorldStore,
    SnapshotCorruptionError,
    WorldLoadResult,
    WorldStore,
    WorldStoreError,
    WorldStoreStatus,
)
from .event_store import EventWorldStore, PostgresEventWorldStore
from .protected_world import PostgresProtectedWorldExecutor
from .protected_send import (PostgresKnownRestoreRecorder, PostgresProtectedSender,
                             PostgresProtectedSnapshotPurger,
                             ProtectedSendLease, ProtectedSendReconciliation, ProtectedLeaseTransmission,
                             ProtectedPinnedASGIResponse)

__all__ = [
    "AdmissionControl",
    "AdmissionOperationResult",
    "AdmissionState",
    "CartCreationSource",
    "CommitSource",
    "CommitResult",
    "EventWorldStore",
    "PostgresEventWorldStore",
    "CommitLookupResult",
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
    "PostgresCandidatePromoter",
    "PostgresProtectedAuthorizer",
    "PostgresProtectedWorldExecutor",
    "PostgresKnownRestoreRecorder",
    "PostgresProtectedSender",
    "PostgresProtectedSnapshotPurger",
    "ProtectedSendLease",
    "ProtectedSendReconciliation",
    "ProtectedLeaseTransmission",
    "ProtectedPinnedASGIResponse",
    "ProtectedGrantError",
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
    "ProfileRevocation",
    "WorldCompatibility",
    "WorldSnapshot",
    "WorldLoadResult",
    "WorldStore",
    "WorldStoreError",
    "WorldStoreStatus",
]
