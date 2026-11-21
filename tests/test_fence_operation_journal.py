"""Tests for independent durable cross-database operation reconciliation."""
import unittest

from deception.security.fence_operation_journal import (
    FenceOperation, reconcile_operation, register_operation,
    require_no_ambiguous_operations,
)
from deception.security.restore_fence import RestoreFenceDenied


class FakeCursor:
    """Minimal intent journal cursor with controlled SQL results."""

    def __init__(self, row=None, pending=False, rowcount=1):
        """Initialize simulated operation state."""
        self.row = row
        self.pending = pending
        self.rowcount = rowcount
        self.last_sql = ""

    def execute(self, sql, params):
        """Record the executed SQL for the next fake result."""
        self.last_sql = sql

    def fetchone(self):
        """Return the expected row for the most recent query."""
        if "state='PENDING' LIMIT 1" in self.last_sql:
            return (1,) if self.pending else None
        return self.row


class JournalTests(unittest.TestCase):
    """Check idempotency boundaries and unresolved-commit denial."""

    def setUp(self):
        """Create an immutable operation identity."""
        self.op = FenceOperation("world", "op-1", "START_SEND", "a" * 64)

    def test_new_pending_intent(self):
        """A matching PENDING intent may be registered."""
        register_operation(FakeCursor(("START_SEND", "a" * 64, "PENDING")), self.op)

    def test_duplicate_pending_operation_denied(self):
        """Even identical pending IDs cannot start a second World DB action."""
        with self.assertRaises(RestoreFenceDenied):
            register_operation(FakeCursor(("START_SEND", "a" * 64, "PENDING"), rowcount=0), self.op)

    def test_reused_resolved_operation_denied(self):
        """A resolved operation ID cannot be silently replayed."""
        with self.assertRaises(RestoreFenceDenied):
            register_operation(FakeCursor(("START_SEND", "a" * 64, "COMMITTED")), self.op)

    def test_conflicting_identity_denied(self):
        """An operation ID cannot be rebound to another digest."""
        with self.assertRaises(RestoreFenceDenied):
            register_operation(FakeCursor(("START_SEND", "b" * 64, "PENDING")), self.op)

    def test_ambiguous_operation_blocks_release(self):
        """Unknown World DB commit outcomes must remain blocked."""
        with self.assertRaises(RestoreFenceDenied):
            require_no_ambiguous_operations(FakeCursor(pending=True), "world")

    def test_reconciled_operations_do_not_block(self):
        """Only the absence of pending intents clears this individual gate."""
        require_no_ambiguous_operations(FakeCursor(pending=False), "world")

    def test_reconcile_requires_one_pending_row(self):
        """Missing or previously reconciled operation is rejected."""
        with self.assertRaises(RestoreFenceDenied):
            reconcile_operation(FakeCursor(rowcount=0), self.op, committed=True)

    def test_reconcile_committed_and_aborted(self):
        """Record the independently determined outcome without retrying work."""
        reconcile_operation(FakeCursor(), self.op, committed=True)
        reconcile_operation(FakeCursor(), self.op, committed=False)


if __name__ == "__main__":
    unittest.main()
