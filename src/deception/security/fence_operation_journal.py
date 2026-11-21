"""Durable independent Fence DB journal for ambiguous cross-database operations.

The journal intentionally never guesses whether World DB committed. Only a
separately verified World DB result may close a pending operation.
"""
from __future__ import annotations

from dataclasses import dataclass

from .restore_fence import RestoreFenceDenied


@dataclass(frozen=True)
class FenceOperation:
    """Bind a single protected World DB operation to an immutable identifier."""

    namespace: str
    operation_id: str
    kind: str
    world_digest: str


def register_operation(cursor, operation: FenceOperation) -> None:
    """Create a durable intent; reject conflicting reuse of an operation ID."""
    if operation.kind not in {"START_SEND", "PURGE", "RESTORE"}:
        raise ValueError("unsupported protected operation")
    cursor.execute(
        """INSERT INTO restore_operation_intents
           (namespace,operation_id,kind,world_digest,state)
           VALUES (%s,%s,%s,%s,'PENDING') ON CONFLICT DO NOTHING""",
        (operation.namespace, operation.operation_id, operation.kind, operation.world_digest),
    )
    cursor.execute(
        """SELECT kind,world_digest,state FROM restore_operation_intents
           WHERE namespace=%s AND operation_id=%s FOR UPDATE""",
        (operation.namespace, operation.operation_id),
    )
    row = cursor.fetchone()
    if row is None or row[0] != operation.kind or row[1] != operation.world_digest:
        raise RestoreFenceDenied("operation identity conflict")
    if row[2] != "PENDING":
        raise RestoreFenceDenied("operation already resolved; no implicit replay")


def require_no_ambiguous_operations(cursor, namespace: str) -> None:
    """Deny release while any independent operation intent remains unresolved."""
    cursor.execute(
        """SELECT 1 FROM restore_operation_intents
           WHERE namespace=%s AND state='PENDING' LIMIT 1""",
        (namespace,),
    )
    if cursor.fetchone() is not None:
        raise RestoreFenceDenied("ambiguous World DB operation requires reconciliation")


def reconcile_operation(cursor, operation: FenceOperation, *, committed: bool) -> None:
    """Record independently proven outcome; caller must supply authoritative proof.

    A boolean without external evidence is not sufficient authorization to call
    this helper. Production callers must verify immutable World DB evidence.
    """
    cursor.execute(
        """UPDATE restore_operation_intents SET state=%s,
                  reconciled_at=clock_timestamp()
           WHERE namespace=%s AND operation_id=%s AND kind=%s
             AND world_digest=%s AND state='PENDING'""",
        ("COMMITTED" if committed else "ABORTED", operation.namespace,
         operation.operation_id, operation.kind, operation.world_digest),
    )
    if cursor.rowcount != 1:
        raise RestoreFenceDenied("unknown or already reconciled operation")
