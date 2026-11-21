"""Independent Fence DB transaction gate for protected World DB operations.

This module never claims cross-database atomic commit. The caller must route
all trusted send, purge, and restore paths through this gate and independently
reconcile ambiguous World DB commit outcomes before any retry.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from .restore_fence import RestoreFenceDenied, require_released


@contextmanager
def protected_world_operation(fence_connection, namespace: str) -> Iterator[None]:
    """Hold a separate Fence DB row lock for an entire protected World DB action.

    The supplied connection MUST be dedicated, transactional and non-autocommit.
    The caller MUST NOT commit or roll back it inside this scope. A crash releases
    the DB lock, so ambiguous World DB results require durable reconciliation.
    """
    if getattr(fence_connection, "autocommit", True):
        raise RestoreFenceDenied("fence connection must be transactional")
    with fence_connection.transaction():
        with fence_connection.cursor() as cursor:
            require_released(cursor, namespace)
            yield


@contextmanager
def protected_restore_operation(fence_connection, namespace: str) -> Iterator[None]:
    """Hold the independent Fence DB lock while restoring protected World DB.

    The caller MUST durably enter QUARANTINED in a *prior committed*
    transaction before this scope, and MUST NOT release quarantine here.
    """
    if getattr(fence_connection, "autocommit", True):
        raise RestoreFenceDenied("fence connection must be transactional")
    with fence_connection.transaction():
        with fence_connection.cursor() as cursor:
            cursor.execute(
                """SELECT state FROM restore_quarantine_fences
                   WHERE namespace=%s FOR UPDATE""", (namespace,))
            row = cursor.fetchone()
            if row is None or row[0] != "QUARANTINED":
                raise RestoreFenceDenied("restore requires committed quarantine")
            yield
