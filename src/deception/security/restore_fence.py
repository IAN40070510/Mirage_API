"""Transactional Restore Quarantine fence primitives for a dedicated verifier role.

The caller must use one PostgreSQL transaction and hold the namespace fence row
lock for the entire protected send/purge or restore/release transition. These
helpers do not grant permissions, deploy schema or enable trusted transport.
"""
from __future__ import annotations

from dataclasses import dataclass


class RestoreFenceDenied(RuntimeError):
    """Reject a stale or ambiguous restore/send boundary without fallback."""


@dataclass(frozen=True)
class RestoreEvidence:
    """Identify the exact independently checked restore and Anchor head."""

    namespace: str
    epoch: int
    sequence: int
    digest: str
    verifier_version: str


def lock_fence(cursor, namespace: str) -> tuple:
    """Lock the persistent namespace fence until the caller commits or rolls back."""
    cursor.execute(
        """SELECT restore_epoch, anchor_sequence, anchor_digest, state, revision
           FROM restore_quarantine_fences WHERE namespace=%s FOR UPDATE""",
        (namespace,),
    )
    row = cursor.fetchone()
    if row is None:
        raise RestoreFenceDenied("missing fence defaults to quarantine")
    return row


def require_released(cursor, namespace: str) -> None:
    """Hold the same fence lock across a protected send/purge transition."""
    row = lock_fence(cursor, namespace)
    if row[3] != "RELEASED":
        raise RestoreFenceDenied("restore quarantine active")


def enter_quarantine(cursor, namespace: str, epoch: int, digest: str) -> None:
    """Invalidate release and bump revision before beginning a restore.

    The namespace must already exist: do not implicitly bootstrap an absent
    security boundary. Caller must enforce independent epoch monotonicity.
    """
    row = lock_fence(cursor, namespace)
    if type(epoch) is not int or epoch <= row[0]:
        raise RestoreFenceDenied("restore epoch not strictly newer")
    cursor.execute(
        """UPDATE restore_quarantine_fences
           SET restore_epoch=%s, anchor_sequence=0, anchor_digest=%s,
               state='QUARANTINED', revision=revision+1,
               verifier_version=NULL, verified_at=NULL
           WHERE namespace=%s""",
        (epoch, digest, namespace),
    )


def release_if_reconciled(cursor, evidence: RestoreEvidence, expected_revision: int) -> None:
    """Conditionally release only a matching fence with no unresolved intents.

    The independent verifier must validate the Anchor and every protected
    security ledger before calling this function, in the same serialized
    transaction. This is not by itself a complete evidence verifier.
    """
    row = lock_fence(cursor, evidence.namespace)
    if (row[0] != evidence.epoch or row[3] != "QUARANTINED"
            or row[4] != expected_revision):
        raise RestoreFenceDenied("fence changed during verification")
    cursor.execute(
        """SELECT 1 FROM restore_publication_intents
           WHERE namespace=%s AND state <> 'RECONCILED' LIMIT 1""",
        (evidence.namespace,),
    )
    if cursor.fetchone() is not None:
        raise RestoreFenceDenied("unresolved publication intent")
    from .fence_operation_journal import require_no_ambiguous_operations

    require_no_ambiguous_operations(cursor, evidence.namespace)
    cursor.execute(
        """UPDATE restore_quarantine_fences
           SET anchor_sequence=%s, anchor_digest=%s, state='RELEASED',
               revision=revision+1, verifier_version=%s,
               verified_at=clock_timestamp()
           WHERE namespace=%s AND revision=%s AND state='QUARANTINED'""",
        (evidence.sequence, evidence.digest, evidence.verifier_version,
         evidence.namespace, expected_revision),
    )
    if cursor.rowcount != 1:
        raise RestoreFenceDenied("concurrent fence transition")
