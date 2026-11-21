"""Isolated transaction-fence unit checks; PostgreSQL concurrency remains unverified."""
import unittest

from deception.security.restore_fence import (
    RestoreEvidence, RestoreFenceDenied, enter_quarantine,
    release_if_reconciled, require_released,
)


class FakeCursor:
    """Simulate a single locked fence row and publication-intent lookup."""

    def __init__(self, row=None, pending=False):
        """Initialize controlled row and unresolved-intent state."""
        self.row = row
        self.pending = pending
        self.calls = []
        self.rowcount = 1
        self._result = None

    def execute(self, sql, params):
        """Record SQL and return the configured lookup result."""
        self.calls.append((sql, params))
        if "FROM restore_quarantine_fences" in sql:
            self._result = self.row
        elif "FROM restore_operation_intents" in sql:
            self._result = None
        elif "FROM restore_publication_intents" in sql:
            self._result = (1,) if self.pending else None
        else:
            self._result = None

    def fetchone(self):
        """Return the last simulated SELECT result."""
        return self._result


class RestoreFenceTests(unittest.TestCase):
    """Check fail-closed control flow before database integration."""

    def test_missing_fence_denies_send(self):
        """An uninitialized namespace cannot silently permit transport."""
        with self.assertRaises(RestoreFenceDenied):
            require_released(FakeCursor(), "world")

    def test_quarantine_denies_send(self):
        """The persistent quarantine state must block transport."""
        with self.assertRaises(RestoreFenceDenied):
            require_released(FakeCursor((3, 1, "a"*64, "QUARANTINED", 2)), "world")

    def test_released_fence_allows_gate(self):
        """A released row permits only this gate, not a send authorization."""
        require_released(FakeCursor((3, 1, "a"*64, "RELEASED", 2)), "world")

    def test_stale_restore_epoch_denied(self):
        """Restoring at the same or older epoch must fail."""
        for epoch in (2, 3):
            with self.assertRaises(RestoreFenceDenied):
                enter_quarantine(FakeCursor((3, 1, "a"*64, "RELEASED", 2)),
                                 "world", epoch, "b"*64)

    def test_unresolved_publication_blocks_release(self):
        """Pending and published-but-unreconciled intents block release."""
        cursor = FakeCursor((4, 0, "a"*64, "QUARANTINED", 3), pending=True)
        with self.assertRaises(RestoreFenceDenied):
            release_if_reconciled(cursor, RestoreEvidence("world", 4, 2, "b"*64, "v1"), 3)

    def test_revision_race_blocks_release(self):
        """A changed fence revision invalidates a previously observed proof."""
        cursor = FakeCursor((4, 0, "a"*64, "QUARANTINED", 5))
        with self.assertRaises(RestoreFenceDenied):
            release_if_reconciled(cursor, RestoreEvidence("world", 4, 2, "b"*64, "v1"), 4)

    def test_reconciled_release_is_conditional(self):
        """Release SQL binds namespace, revision and quarantined state."""
        cursor = FakeCursor((4, 0, "a"*64, "QUARANTINED", 3))
        release_if_reconciled(cursor, RestoreEvidence("world", 4, 2, "b"*64, "v1"), 3)
        sql, params = cursor.calls[-1]
        self.assertIn("revision=%s AND state='QUARANTINED'", sql)
        self.assertEqual(params[-2:], ("world", 3))


if __name__ == "__main__":
    unittest.main()
