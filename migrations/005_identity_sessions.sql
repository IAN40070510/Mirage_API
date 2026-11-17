CREATE TABLE IF NOT EXISTS identity_sessions (
    environment_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    session_id CHAR(64) NOT NULL,
    session_epoch BIGINT NOT NULL DEFAULT 1 CHECK (session_epoch >= 1),
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (environment_id, deployment_id, session_id)
);
