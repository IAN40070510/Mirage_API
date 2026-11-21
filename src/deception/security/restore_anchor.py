"""Fail-closed independent Restore Anchor laboratory adapter (not production WORM)."""
import fcntl
import hashlib
import hmac
import json
import os
import stat
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
            if self.path.is_symlink():
                raise AnchorViolation("anchor symlink refused")
            descriptor = os.open(self.path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            with os.fdopen(descriptor, "rb") as stream:
                fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
                self._validate_file(stream)
                return self._verified(stream.read())[-1]
        except (FileNotFoundError, PermissionError, OSError) as exc:
            raise AnchorViolation("anchor unavailable") from exc

    def _validate_file(self, stream):
        """Refuse symlinks, special files, hard links and weak file permissions."""
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise AnchorViolation("anchor must be a single regular file")
        if info.st_mode & 0o077:
            raise AnchorViolation("anchor file accessible to other identities")

    def append(self, namespace, epoch, world_digest, publication_id):
        """Append and fsync a checkpoint under an exclusive interprocess lock."""
        if not namespace or not publication_id or epoch < 0 or len(world_digest) != 64:
            raise ValueError("invalid checkpoint")
        if self.path.is_symlink():
            raise AnchorViolation("anchor symlink refused")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDWR | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW
        created = False
        try:
            descriptor = os.open(self.path, flags | os.O_CREAT | os.O_EXCL, 0o600)
            created = True
        except FileExistsError:
            descriptor = os.open(self.path, flags)
        with os.fdopen(descriptor, "r+b", buffering=0) as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            self._validate_file(stream)
            stream.seek(0)
            data = stream.read()
            if not data and not created:
                raise AnchorViolation("existing anchor was emptied")
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
            if created:
                directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            return record

    def require_fresh(self, namespace, epoch, sequence, world_digest):
        """Quarantine a World DB whose checkpoint is not the external latest."""
        record = self.latest()
        if (record["namespace"], record["epoch"], record["sequence"], record["world_digest"]) != (
                namespace, epoch, sequence, world_digest):
            raise AnchorViolation("restore quarantine: stale checkpoint")
