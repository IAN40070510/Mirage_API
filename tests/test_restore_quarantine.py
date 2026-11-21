"""Restore Quarantine gate tests; never clear real quarantine or send transport."""
import tempfile
import unittest
from pathlib import Path

from deception.security.restore_anchor import AnchorViolation, FileRestoreAnchor
from deception.security.restore_quarantine import (
    QuarantineViolation, release_certificate_mac, require_restore_release,
)


class RestoreQuarantineTests(unittest.TestCase):
    """Check release certificate binding against independent latest checkpoint."""

    def setUp(self):
        """Initialize disposable anchor and an independent operator signing key."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.anchor = FileRestoreAnchor(Path(self.temp.name) / "anchor", b"a" * 32)
        self.operator_key = b"o" * 32
        self.anchor.append("world", 4, "a" * 64, "p1")
        self.fields = dict(namespace="world", epoch=4, sequence=1, world_digest="a" * 64)
        self.certificate = {"version": 1, **self.fields, "decision": "release"}
        self.certificate["mac"] = release_certificate_mac(self.operator_key, self.certificate)

    def test_valid_operator_release_evidence(self):
        """Matching independent checkpoint and operator statement pass evidence gate."""
        require_restore_release(self.anchor, **self.fields,
                                certificate=self.certificate, operator_key=self.operator_key)

    def test_missing_certificate_denied(self):
        """Do not allow implicit release without a separate operator decision."""
        with self.assertRaises(QuarantineViolation):
            require_restore_release(self.anchor, **self.fields,
                                    certificate={}, operator_key=self.operator_key)

    def test_stale_restore_denied(self):
        """An old DB cannot exit quarantine even with an old valid certificate."""
        self.anchor.append("world", 4, "b" * 64, "p2")
        with self.assertRaises(AnchorViolation):
            require_restore_release(self.anchor, **self.fields,
                                    certificate=self.certificate, operator_key=self.operator_key)

    def test_wrong_operator_key_denied(self):
        """An attacker knowing the anchor key cannot forge the operator decision."""
        with self.assertRaises(QuarantineViolation):
            require_restore_release(self.anchor, **self.fields,
                                    certificate=self.certificate, operator_key=b"z" * 32)

    def test_cross_epoch_and_tamper_denied(self):
        """Release evidence is bound to exact epoch, namespace and world digest."""
        for changed in ({"epoch": 5}, {"namespace": "other"}, {"world_digest": "b" * 64}):
            certificate = {**self.certificate, **changed}
            with self.assertRaises(AnchorViolation):
                require_restore_release(self.anchor, **self.fields,
                                        certificate=certificate, operator_key=self.operator_key)
