CREATE TABLE IF NOT EXISTS session_heads (
    environment_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    session_epoch BIGINT NOT NULL CHECK (session_epoch >= 0),
    PRIMARY KEY (environment_id, deployment_id, session_id)
);

CREATE TABLE IF NOT EXISTS session_world_bindings (
    environment_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    session_epoch BIGINT NOT NULL CHECK (session_epoch >= 0),
    world_generation_id TEXT NOT NULL UNIQUE,
    watermark_version BIGINT NOT NULL DEFAULT 1 CHECK (watermark_version >= 1),
    PRIMARY KEY (environment_id, deployment_id, session_id, session_epoch)
);

CREATE TABLE IF NOT EXISTS read_admissions (
    read_admission_id TEXT PRIMARY KEY,
    environment_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    world_generation_id TEXT NOT NULL,
    request_binding_digest CHAR(64) NOT NULL,
    state_version BIGINT NOT NULL,
    state_hash CHAR(64) NOT NULL,
    expires_at BIGINT NOT NULL
);
