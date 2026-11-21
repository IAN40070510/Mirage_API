"""Negative and positive tests for the isolated Restore Anchor adapter."""
import tempfile
import unittest
from pathlib import Path
from deception.security.restore_anchor import AnchorViolation, FileRestoreAnchor


class RestoreAnchorTests(unittest.TestCase):
    """Exercise external checkpoint freshness and tamper refusal."""

    def setUp(self):
        """Create a fresh disposable anchor without touching World DB."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "anchor"
        self.anchor = FileRestoreAnchor(self.path, b"x" * 32)

    def test_missing(self):
        """Missing external evidence must fail closed."""
        with self.assertRaises(AnchorViolation):
            self.anchor.latest()

    def test_stale_and_fresh(self):
        """World DB rollback must not match the newer external checkpoint."""
        self.anchor.append("world", 1, "a"*64, "one")
        self.anchor.append("world", 1, "b"*64, "two")
        with self.assertRaises(AnchorViolation):
            self.anchor.require_fresh("world", 1, 1, "a"*64)
        self.anchor.require_fresh("world", 1, 2, "b"*64)

    def test_tamper_duplicate_and_epoch(self):
        """Detect unauthorized edits, duplicate IDs and epoch rollback."""
        self.anchor.append("world", 3, "a"*64, "one")
        with self.assertRaises(AnchorViolation):
            self.anchor.append("world", 3, "b"*64, "one")
        with self.assertRaises(AnchorViolation):
            self.anchor.append("world", 2, "b"*64, "two")
        self.path.write_bytes(self.path.read_bytes().replace(b'"epoch":3', b'"epoch":4'))
        with self.assertRaises(AnchorViolation):
            self.anchor.latest()

    def test_torn_record(self):
        """Reject an interrupted checkpoint append."""
        self.anchor.append("world", 1, "a"*64, "one")
        with self.path.open("ab") as file:
            file.write(b"{")
        with self.assertRaises(AnchorViolation):
            self.anchor.latest()
