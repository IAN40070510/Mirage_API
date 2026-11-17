CREATE TABLE IF NOT EXISTS anonymous_issuance (
    environment_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    window_start BIGINT NOT NULL,
    issued BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY(environment_id,deployment_id,window_start)
);
CREATE TABLE IF NOT EXISTS anonymous_groups (
    environment_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    group_digest CHAR(64) NOT NULL,
    window_start BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY(environment_id,deployment_id,group_digest,window_start)
);
