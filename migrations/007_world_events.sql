CREATE TABLE IF NOT EXISTS world_operations (
    environment_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    world_generation_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    operation_digest CHAR(64) NOT NULL,
    commit_attempt_id UUID NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('committed', 'rejected')),
    result JSONB NOT NULL,
    state_version BIGINT NOT NULL,
    state_hash CHAR(64) NOT NULL,
    PRIMARY KEY(environment_id,deployment_id,session_id,world_generation_id,operation,idempotency_key)
);

CREATE TABLE IF NOT EXISTS world_events (
    event_id UUID PRIMARY KEY,
    environment_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    world_generation_id TEXT NOT NULL,
    state_version BIGINT NOT NULL,
    operation TEXT NOT NULL,
    operation_digest CHAR(64) NOT NULL,
    state_hash CHAR(64) NOT NULL,
    UNIQUE(environment_id,deployment_id,session_id,world_generation_id,state_version)
);
