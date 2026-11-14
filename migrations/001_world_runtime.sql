CREATE TABLE IF NOT EXISTS world_snapshots (
    environment_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    world_generation_id TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version >= 1),
    expires_at BIGINT,
    state JSONB NOT NULL,
    state_hash CHAR(64) NOT NULL CHECK (state_hash ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (environment_id, deployment_id, session_id, world_generation_id)
);

CREATE TABLE IF NOT EXISTS generation_controls (
    world_generation_id TEXT PRIMARY KEY,
    control_revision BIGINT NOT NULL CHECK (control_revision >= 0),
    sealed BOOLEAN NOT NULL DEFAULT FALSE,
    cutover_revision BIGINT
);

CREATE TABLE IF NOT EXISTS response_admissions (
    admission_id TEXT PRIMARY KEY,
    world_generation_id TEXT NOT NULL REFERENCES generation_controls(world_generation_id),
    authorization_deadline BIGINT NOT NULL,
    transmission_deadline BIGINT NOT NULL,
    state TEXT NOT NULL,
    claim_owner TEXT,
    claim_revision BIGINT,
    send_authorization_revision BIGINT,
    admission JSONB NOT NULL,
    CHECK (authorization_deadline <= transmission_deadline)
);

CREATE INDEX IF NOT EXISTS response_admissions_generation_idx
    ON response_admissions (world_generation_id);

CREATE TABLE IF NOT EXISTS candidate_records (
    environment_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    world_generation_id TEXT NOT NULL,
    candidate_ref TEXT NOT NULL,
    candidate_hash CHAR(64) NOT NULL CHECK (candidate_hash ~ '^[0-9a-f]{64}$'),
    body BYTEA NOT NULL,
    expires_at BIGINT NOT NULL CHECK (expires_at >= 1),
    PRIMARY KEY (
        environment_id, deployment_id, session_id,
        world_generation_id, candidate_ref
    )
);

CREATE INDEX IF NOT EXISTS candidate_records_ref_idx
    ON candidate_records (candidate_ref);

CREATE TABLE IF NOT EXISTS replay_entries (
    issuer TEXT NOT NULL,
    audience TEXT NOT NULL,
    jti TEXT NOT NULL,
    expires_at BIGINT NOT NULL CHECK (expires_at >= 1),
    PRIMARY KEY (issuer, audience, jti)
);

CREATE INDEX IF NOT EXISTS replay_entries_expiry_idx
    ON replay_entries (expires_at);

CREATE TABLE IF NOT EXISTS projection_registry (
    projection_contract_hash CHAR(64) PRIMARY KEY CHECK (projection_contract_hash ~ '^[0-9a-f]{64}$'),
    source_spec_sha256 CHAR(64) NOT NULL CHECK (source_spec_sha256 ~ '^[0-9a-f]{64}$'),
    compatibility_profile_sha256 CHAR(64) NOT NULL CHECK (compatibility_profile_sha256 ~ '^[0-9a-f]{64}$'),
    registry_revision BIGINT NOT NULL CHECK (registry_revision >= 1),
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    evidence JSONB NOT NULL
);
