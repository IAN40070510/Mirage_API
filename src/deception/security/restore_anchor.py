"""Fail-closed independent Restore Anchor laboratory adapter (not production WORM)."""
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path


class AnchorViolation(RuntimeError):
    """Reject missing, stale, damaged or unverifiable anchor evidence."""


def canonical(record):
    """Serialize records in a deterministic byte representation."""
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode()


def authenticate(key, record):
    """Compute a keyed digest over the entire checkpoint."""
    return hmac.new(key, canonical(record), hashlib.sha256).hexdigest()


class FileRestoreAnchor:
    """Keep an authenticated append-only checkpoint chain outside World DB."""

    def __init__(self, path, key):
        """Configure an independent lab file and publisher-only key."""
        if len(key) < 32:
            raise ValueError("key must contain at least 32 bytes")
        self.path, self.key = Path(path), key

    def _verified(self, data):
        """Verify all checkpoint MACs, sequence numbers and predecessor links."""
        if not data or not data.endswith(b"\n"):
            raise AnchorViolation("missing or torn anchor")
        previous, records = "0" * 64, []
        for line in data.splitlines():
            try:
                item = json.loads(line)
                mac = item.pop("mac")
                if type(item["sequence"]) is not int or item["sequence"] != len(records) + 1:
                    raise AnchorViolation("sequence gap")
                if item["previous"] != previous or not hmac.compare_digest(mac, authenticate(self.key, item)):
                    raise AnchorViolation("tampered checkpoint")
                item["mac"] = mac
                previous = hashlib.sha256(canonical(item)).hexdigest()
                records.append(item)
            except (ValueError, KeyError, TypeError) as exc:
                raise AnchorViolation("malformed checkpoint") from exc
        return records

    def latest(self):
        """Read the authenticated latest checkpoint or fail closed."""
        try:
            return self._verified(self.path.read_bytes())[-1]
        except FileNotFoundError as exc:
            raise AnchorViolation("anchor unavailable") from exc

    def append(self, namespace, epoch, world_digest, publication_id):
        """Append and fsync a checkpoint under an exclusive interprocess lock."""
        if not namespace or not publication_id or epoch < 0 or len(world_digest) != 64:
            raise ValueError("invalid checkpoint")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a+b", buffering=0) as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            stream.seek(0)
            data = stream.read()
            records = self._verified(data) if data else []
            if records and (records[-1]["namespace"] != namespace or epoch < records[-1]["epoch"]):
                raise AnchorViolation("namespace or epoch rollback")
            if any(item["publication_id"] == publication_id for item in records):
                raise AnchorViolation("duplicate publication")
            previous = hashlib.sha256(canonical(records[-1])).hexdigest() if records else "0" * 64
            record = dict(version=1, namespace=namespace, epoch=epoch, sequence=len(records)+1,
                          previous=previous, world_digest=world_digest, publication_id=publication_id)
            record["mac"] = authenticate(self.key, record)
            stream.seek(0, os.SEEK_END)
            stream.write(canonical(record) + b"\n")
            os.fsync(stream.fileno())
            return record

    def require_fresh(self, namespace, epoch, sequence, world_digest):
        """Quarantine a World DB whose checkpoint is not the external latest."""
        record = self.latest()
        if (record["namespace"], record["epoch"], record["sequence"], record["world_digest"]) != (
                namespace, epoch, sequence, world_digest):
            raise AnchorViolation("restore quarantine: stale checkpoint")
