"""Verify independent intent-before-work ordering and ambiguous result handling."""
import unittest
from contextlib import contextmanager
from unittest.mock import patch

from deception.security.fence_operation_journal import FenceOperation
from deception.security.protected_operation_runner import run_protected_operation
from deception.security.restore_fence import RestoreFenceDenied


class Cursor:
    """Model one fence and one operation intent row."""

    def __init__(self, connection):
        """Keep a reference to the transactional fixture."""
        self.connection = connection
        self.sql = ""
        self.rowcount = 1

    def __enter__(self):
        """Open a fake cursor."""
        return self

    def __exit__(self, *_):
        """Close the fake cursor."""
        return None

    def execute(self, sql, params):
        """Simulate a small subset of the independent fence SQL."""
        self.sql = sql
        if "INSERT INTO restore_operation_intents" in sql:
            self.connection.intent = True

    def fetchone(self):
        """Return current fence or pending intent evidence."""
        if "FROM restore_quarantine_fences" in self.sql:
            return (1, 0, "a" * 64, self.connection.state, 0)
        if "FROM restore_operation_intents" in self.sql:
            return ("START_SEND", "b" * 64, "PENDING")
        return None


class Connection:
    """Track separate transaction commit boundaries."""

    autocommit = False

    def __init__(self, state="RELEASED"):
        """Initialize fake independent state."""
        self.state = state
        self.intent = False
        self.transactions = 0
        self.commits = 0

    @contextmanager
    def transaction(self):
        """Record commit only after the transaction context succeeds."""
        self.transactions += 1
        try:
            yield
        except Exception:
            raise
        else:
            self.commits += 1

    def cursor(self):
        """Return a simulated cursor."""
        return Cursor(self)


class RunnerTests(unittest.TestCase):
    """Enforce intent-before-work and fail-closed semantics."""

    def setUp(self):
        """Use a stable unique operation identity."""
        self.op = FenceOperation("world", "op-1", "START_SEND", "b" * 64)

    def test_intent_committed_before_work(self):
        """World action must observe an already committed independent intent."""
        connection = Connection()
        with patch("deception.security.protected_operation_runner.protected_world_operation") as gate:
            @contextmanager
            def fake_gate(*_):
                """Simulate the second independent lock scope."""
                yield
            gate.side_effect = fake_gate
            result = run_protected_operation(
                connection, self.op,
                lambda: (connection.intent, connection.commits),
            )
        self.assertEqual(result, (True, 1))

    def test_quarantine_prevents_world_work(self):
        """No intent or protected action may run while quarantined."""
        connection = Connection("QUARANTINED")
        called = []
        with self.assertRaises(RestoreFenceDenied):
            run_protected_operation(connection, self.op, lambda: called.append(True))
        self.assertEqual(called, [])
        self.assertFalse(connection.intent)

    def test_exception_never_resolves_pending(self):
        """A failed or ambiguous World DB action leaves its intent pending."""
        connection = Connection()
        with patch("deception.security.protected_operation_runner.protected_world_operation") as gate:
            @contextmanager
            def fake_gate(*_):
                """Simulate an acquired independent row lock."""
                yield
            gate.side_effect = fake_gate
            with self.assertRaisesRegex(RuntimeError, "unknown commit"):
                run_protected_operation(connection, self.op,
                                        lambda: (_ for _ in ()).throw(RuntimeError("unknown commit")))
        self.assertTrue(connection.intent)
        self.assertEqual(connection.commits, 1)


if __name__ == "__main__":
    unittest.main()
