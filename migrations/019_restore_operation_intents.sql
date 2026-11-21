-- Stored in the independent Fence database, not in World DB backup scope.
-- An unknown cross-database commit must remain PENDING until independently reconciled.
CREATE TABLE IF NOT EXISTS restore_operation_intents (
    namespace TEXT NOT NULL REFERENCES restore_quarantine_fences(namespace) ON DELETE RESTRICT,
    operation_id TEXT NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 128),
    kind TEXT NOT NULL CHECK (kind IN ('START_SEND','PURGE','RESTORE')),
    world_digest CHAR(64) NOT NULL CHECK (world_digest ~ '^[0-9a-f]{64}$'),
    state TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (state IN ('PENDING','COMMITTED','ABORTED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    reconciled_at TIMESTAMPTZ,
    PRIMARY KEY(namespace,operation_id),
    CHECK ((state='PENDING') = (reconciled_at IS NULL))
);
REVOKE ALL ON restore_operation_intents FROM PUBLIC;
