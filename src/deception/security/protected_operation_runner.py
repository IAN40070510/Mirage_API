"""Fail-closed orchestration of independent Fence intents and World DB work.

This does not provide distributed atomicity or infer COMMIT from a callback
return. A trusted reconciler must inspect World DB evidence independently.
"""
from __future__ import annotations

from typing import Callable, TypeVar

from .fence_operation_journal import FenceOperation, register_operation
from .independent_fence_gate import protected_restore_operation, protected_world_operation
from .restore_fence import RestoreFenceDenied, lock_fence

T = TypeVar("T")


def persist_operation_intent(fence_connection, operation: FenceOperation) -> None:
    """Commit an immutable PENDING intent before any protected World DB work.

    The independent fence row is locked to serialize with restore/release.
    For RESTORE the namespace must already be durably quarantined.
    """
    if getattr(fence_connection, "autocommit", True):
        raise RestoreFenceDenied("intent persistence requires a transaction")
    with fence_connection.transaction():
        with fence_connection.cursor() as cursor:
            row = lock_fence(cursor, operation.namespace)
            if operation.kind == "RESTORE":
                if row[3] != "QUARANTINED":
                    raise RestoreFenceDenied("restore requires committed quarantine")
            elif row[3] != "RELEASED":
                raise RestoreFenceDenied("world operation requires released fence")
            register_operation(cursor, operation)


def run_protected_operation(
    fence_connection,
    operation: FenceOperation,
    world_action: Callable[[], T],
) -> T:
    """Execute one protected action with a previously committed intent.

    After an exception or successful return, the independent journal remains
    PENDING until a separate verifier reconciles authoritative World DB proof.
    The action must complete its World DB transaction before returning; it
    must never send HTTP bytes outside this lock scope.
    """
    persist_operation_intent(fence_connection, operation)
    guard = (protected_restore_operation if operation.kind == "RESTORE"
             else protected_world_operation)
    with guard(fence_connection, operation.namespace):
        return world_action()
