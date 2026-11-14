"""唯讀 Synthetic World 的共用模型、保存與輸出准入控制。"""

from .admission import AdmissionControl, AdmissionOperationResult, AdmissionState
from .models import (
    CommitSource,
    ResponseAdmission,
    ResponseSource,
    SecurityErrorSource,
    SnapshotSource,
    WorldScope,
    WorldSnapshot,
)
from .store import InMemoryWorldStore, SnapshotCorruptionError, WorldStoreError

__all__ = [
    "AdmissionControl",
    "AdmissionOperationResult",
    "AdmissionState",
    "CommitSource",
    "InMemoryWorldStore",
    "ResponseAdmission",
    "ResponseSource",
    "SecurityErrorSource",
    "SnapshotCorruptionError",
    "SnapshotSource",
    "WorldScope",
    "WorldSnapshot",
    "WorldStoreError",
]
