"""Pure Restore Quarantine admission gate; no send or DB mutation authority."""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Mapping

from .restore_anchor import AnchorViolation, FileRestoreAnchor, canonical


class QuarantineViolation(AnchorViolation):
    """Indicate that a restore lacks independent proof to exit quarantine."""


def release_certificate_mac(key: bytes, payload: Mapping[str, object]) -> str:
    """Authenticate an operator release statement with a distinct release key."""
    if len(key) < 32:
        raise ValueError("release key must be at least 32 bytes")
    return hmac.new(key, canonical(dict(payload)), hashlib.sha256).hexdigest()


def require_restore_release(
    anchor: FileRestoreAnchor,
    *,
    namespace: str,
    epoch: int,
    sequence: int,
    world_digest: str,
    certificate: Mapping[str, object],
    operator_key: bytes,
) -> None:
    """Fail closed unless latest independent anchor and operator certificate agree.

    This function checks evidence only; it cannot remove a database quarantine
    fence. Publication continuity, durable intent reconciliation, and a trusted
    operator certificate issuer remain mandatory integration requirements.
    """
    anchor.require_fresh(namespace, epoch, sequence, world_digest)
    expected = {
        "version": 1, "namespace": namespace, "epoch": epoch,
        "sequence": sequence, "world_digest": world_digest,
        "decision": "release",
    }
    if not isinstance(certificate, Mapping) or set(certificate) != set(expected) | {"mac"}:
        raise QuarantineViolation("missing or malformed operator certificate")
    if any(type(certificate[k]) is not type(value) or certificate[k] != value
           for k, value in expected.items()):
        raise QuarantineViolation("operator certificate does not bind restored checkpoint")
    tag = certificate["mac"]
    if not isinstance(tag, str) or not hmac.compare_digest(
            tag, release_certificate_mac(operator_key, expected)):
        raise QuarantineViolation("operator certificate authentication failed")
