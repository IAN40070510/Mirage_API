"""Explicit fail-closed StartSend adapter for an independent Fence database.

This is an integration candidate, not a replacement for the legacy admission
path until every caller is routed here and database roles forbid bypass.
"""
from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from .fence_operation_journal import FenceOperation
from .protected_operation_runner import run_protected_operation
from .restore_fence import RestoreFenceDenied


@dataclass
class FencedAdmissionControl:
    """Wrap admission operations with a durable independent StartSend intent."""

    admission_control: object
    fence_connection_factory: object
    namespace: str

    def start_send(self, admission_id: str, *, owner: str, now: int):
        """Persist intent before StartSend; unknown commit is never retried here.

        The independent verifier must reconcile operation_id with World DB
        evidence. The adapter intentionally does not mark an intent resolved.
        """
        if not self.namespace or not callable(self.fence_connection_factory):
            raise RestoreFenceDenied("independent Fence not configured")
        operation = FenceOperation(
            namespace=self.namespace,
            operation_id=uuid4().hex,
            kind="START_SEND",
            world_digest=__import__("hashlib").sha256(
                (admission_id + "\0" + owner).encode("utf-8")).hexdigest(),
        )
        with self.fence_connection_factory() as fence_connection:
            return run_protected_operation(
                fence_connection, operation,
                lambda: self.admission_control.start_send(
                    admission_id, owner=owner, now=now),
            )
