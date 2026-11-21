-- Restore quarantine is default-deny; this table alone does not authorize transport.
-- The independent verifier must serialize restore/reconcile/release against send/purge.
CREATE TABLE IF NOT EXISTS restore_quarantine_fences (
    namespace TEXT PRIMARY KEY CHECK (length(namespace) BETWEEN 1 AND 128),
    restore_epoch BIGINT NOT NULL CHECK (restore_epoch >= 0),
    anchor_sequence BIGINT NOT NULL CHECK (anchor_sequence >= 0),
    anchor_digest CHAR(64) NOT NULL CHECK (anchor_digest ~ '^[0-9a-f]{64}$'),
    state TEXT NOT NULL DEFAULT 'QUARANTINED'
        CHECK (state IN ('QUARANTINED', 'RELEASED')),
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0),
    verifier_version TEXT,
    verified_at TIMESTAMPTZ,
    CHECK (state <> 'RELEASED' OR (verifier_version IS NOT NULL AND verified_at IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS restore_publication_intents (
    namespace TEXT NOT NULL REFERENCES restore_quarantine_fences(namespace) ON DELETE RESTRICT,
    publication_id TEXT NOT NULL,
    restore_epoch BIGINT NOT NULL CHECK (restore_epoch >= 0),
    anchor_sequence BIGINT NOT NULL CHECK (anchor_sequence > 0),
    world_digest CHAR(64) NOT NULL CHECK (world_digest ~ '^[0-9a-f]{64}$'),
    state TEXT NOT NULL CHECK (state IN ('PENDING', 'PUBLISHED', 'RECONCILED')),
    PRIMARY KEY (namespace, publication_id),
    UNIQUE (namespace, restore_epoch, anchor_sequence)
);
-- No grants: explicit DBA-managed verifier role ACL is required before deployment.
REVOKE ALL ON restore_quarantine_fences, restore_publication_intents FROM PUBLIC;
