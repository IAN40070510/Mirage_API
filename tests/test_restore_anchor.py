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

    def test_empty_existing_anchor_is_not_genesis(self):
        """A truncated existing anchor cannot silently become a new chain."""
        self.path.touch(mode=0o600)
        with self.assertRaises(AnchorViolation):
            self.anchor.append("world", 1, "a"*64, "one")

    def test_symlink_refused(self):
        """Refuse to follow a symbolic link to another storage boundary."""
        target = Path(self.temp.name) / "target"
        target.write_bytes(b"target")
        self.path.symlink_to(target)
        with self.assertRaises(AnchorViolation):
            self.anchor.append("world", 1, "a"*64, "one")
        with self.assertRaises(AnchorViolation):
            self.anchor.latest()

    def test_world_readable_file_refused(self):
        """Reject an anchor file readable by other local service identities."""
        self.anchor.append("world", 1, "a"*64, "one")
        self.path.chmod(0o644)
        with self.assertRaises(AnchorViolation):
            self.anchor.latest()
        with self.assertRaises(AnchorViolation):
            self.anchor.append("world", 1, "b"*64, "two")

    def test_two_publishers_serialize(self):
        """Concurrent writers must not reuse a checkpoint sequence."""
        import concurrent.futures
        def publish(number):
            """Append one unique publication using a separate adapter instance."""
            return FileRestoreAnchor(self.path, b"x"*32).append(
                "world", 1, format(number, "064x"), "p"+str(number))
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(publish, range(1, 17)))
        self.assertEqual(sorted(item["sequence"] for item in results), list(range(1, 17)))
        self.assertEqual(self.anchor.latest()["sequence"], 16)

    def test_invalid_checkpoint_inputs(self):
        """Reject non-hex digests and booleans masquerading as epoch integers."""
        with self.assertRaises(ValueError):
            self.anchor.append("world", True, "a"*64, "one")
        with self.assertRaises(ValueError):
            self.anchor.append("world", 1, "z"*64, "one")
        with self.assertRaises(ValueError):
            self.anchor.append("world", 1, "a"*64, "")

    def test_cross_namespace_append_refused(self):
        """One anchor chain must never be rebound to another authority namespace."""
        self.anchor.append("world", 1, "a"*64, "one")
        with self.assertRaises(AnchorViolation):
            self.anchor.append("other", 1, "b"*64, "two")
