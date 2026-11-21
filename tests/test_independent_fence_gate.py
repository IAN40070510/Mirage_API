"""Fail-closed independent fence gate unit checks (not DB concurrency tests)."""
import unittest
from contextlib import contextmanager

from deception.security.independent_fence_gate import (
    protected_restore_operation, protected_world_operation,
)
from deception.security.restore_fence import RestoreFenceDenied


class Cursor:
    """Minimal cursor supporting lock and state checks."""

    def __init__(self, state):
        """Set simulated persistent fence state."""
        self.state = state
        self.locked = False
        self.state_only = False

    def __enter__(self):
        """Mark row lock acquisition in a fake transaction."""
        self.locked = True
        return self

    def __exit__(self, *_):
        """Release fake cursor resources."""
        self.locked = False

    def execute(self, sql, params):
        """Accept only expected fence lookup SQL."""
        assert "restore_quarantine_fences" in sql
        self.state_only = "SELECT state FROM" in sql

    def fetchone(self):
        """Return the locked fence row or a missing-row result."""
        return None if self.state is None else (
            (self.state,) if self.state_only else (1, 1, "a" * 64, self.state, 1))


class Connection:
    """Minimal separate transactional connection."""

    def __init__(self, state, autocommit=False):
        """Configure fence state and transaction mode."""
        self.autocommit = autocommit
        self.cursor_instance = Cursor(state)
        self.in_transaction = False

    @contextmanager
    def transaction(self):
        """Simulate the lifetime of a separate Fence DB transaction."""
        self.in_transaction = True
        try:
            yield
        finally:
            self.in_transaction = False

    def cursor(self):
        """Return the simulated locked-row cursor."""
        return self.cursor_instance


class IndependentFenceTests(unittest.TestCase):
    """Verify lock scope and default-deny behavior."""

    def test_send_lock_held_during_world_action(self):
        """Keep independent fence transaction open through protected work."""
        conn = Connection("RELEASED")
        with protected_world_operation(conn, "world"):
            self.assertTrue(conn.in_transaction)
            self.assertTrue(conn.cursor_instance.locked)
        self.assertFalse(conn.in_transaction)

    def test_quarantine_blocks_world_action(self):
        """Reject protected send/purge while quarantine is active."""
        with self.assertRaises(RestoreFenceDenied):
            with protected_world_operation(Connection("QUARANTINED"), "world"):
                self.fail("protected work must never execute")

    def test_missing_fence_blocks_world_action(self):
        """Do not implicitly initialize a missing independent fence."""
        with self.assertRaises(RestoreFenceDenied):
            with protected_world_operation(Connection(None), "world"):
                self.fail("protected work must never execute")

    def test_restore_requires_committed_quarantine(self):
        """Restore cannot start while the persistent fence is released."""
        with self.assertRaises(RestoreFenceDenied):
            with protected_restore_operation(Connection("RELEASED"), "world"):
                self.fail("restore must never execute")
        with protected_restore_operation(Connection("QUARANTINED"), "world"):
            pass

    def test_autocommit_rejected(self):
        """A non-transactional fence connection cannot protect an operation."""
        with self.assertRaises(RestoreFenceDenied):
            with protected_world_operation(Connection("RELEASED", autocommit=True), "world"):
                self.fail("autocommit must never execute")


if __name__ == "__main__":
    unittest.main()
