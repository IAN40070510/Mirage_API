"""Fail-closed adapter tests without enabling production trusted send."""
import unittest
from unittest.mock import patch

from deception.security.fenced_admission_control import FencedAdmissionControl
from deception.security.restore_fence import RestoreFenceDenied


class Connection:
    """Minimal connection context fixture."""

    def __enter__(self):
        """Open the independent connection fixture."""
        return self

    def __exit__(self, *_):
        """Close the independent connection fixture."""
        return None


class Admission:
    """Track whether StartSend was called."""

    def __init__(self):
        """Initialize the call counter."""
        self.calls = 0

    def start_send(self, admission_id, *, owner, now):
        """Simulate the underlying World DB transition."""
        self.calls += 1
        return "SUCCESS"


class FencedAdmissionTests(unittest.TestCase):
    """Check mandatory configuration and protected execution delegation."""

    def test_existing_control_operations_remain_accessible(self):
        """Non-StartSend methods are forwarded during the lab integration."""
        admission = Admission()
        admission.state = lambda _: "GRANTED"
        adapter = FencedAdmissionControl(admission, Connection, "world")
        self.assertEqual(adapter.state("id"), "GRANTED")
        with self.assertRaises(AttributeError):
            getattr(adapter, "_private")

    def test_missing_fence_denies_before_start_send(self):
        """An absent independent Fence factory must not reach World DB."""
        admission = Admission()
        adapter = FencedAdmissionControl(admission, None, "world")
        with self.assertRaises(RestoreFenceDenied):
            adapter.start_send("admission", owner="owner", now=1)
        self.assertEqual(admission.calls, 0)

    def test_runner_controls_world_transition(self):
        """A protected runner must wrap the actual StartSend invocation."""
        admission = Admission()
        adapter = FencedAdmissionControl(admission, Connection, "world")
        with patch("deception.security.fenced_admission_control.run_protected_operation") as runner:
            runner.side_effect = lambda connection, operation, action: action()
            self.assertEqual(adapter.start_send("admission", owner="owner", now=1), "SUCCESS")
            self.assertEqual(runner.call_args.args[1].kind, "START_SEND")
        self.assertEqual(admission.calls, 1)

    def test_runner_denial_never_calls_world(self):
        """A rejected Fence gate must prevent the StartSend state change."""
        admission = Admission()
        adapter = FencedAdmissionControl(admission, Connection, "world")
        with patch("deception.security.fenced_admission_control.run_protected_operation",
                   side_effect=RestoreFenceDenied("quarantine")):
            with self.assertRaises(RestoreFenceDenied):
                adapter.start_send("admission", owner="owner", now=1)
        self.assertEqual(admission.calls, 0)


if __name__ == "__main__":
    unittest.main()
