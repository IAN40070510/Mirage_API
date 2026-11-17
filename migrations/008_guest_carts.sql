CREATE TABLE IF NOT EXISTS synthetic_resources (
    resource_id TEXT PRIMARY KEY,
    resource_kind TEXT NOT NULL CHECK (resource_kind IN ('cart','order')),
    environment_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    session_epoch BIGINT NOT NULL,
    world_generation_id TEXT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS guest_cart_creations (
    environment_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    creator_session_id TEXT NOT NULL,
    creator_epoch BIGINT NOT NULL,
    idempotency_key UUID NOT NULL,
    cart_id TEXT NOT NULL,
    operation_result JSONB NOT NULL,
    state_version BIGINT NOT NULL,
    state_hash CHAR(64) NOT NULL,
    commit_attempt_id UUID NOT NULL UNIQUE,
    PRIMARY KEY(environment_id,deployment_id,creator_session_id,creator_epoch,idempotency_key)
);
