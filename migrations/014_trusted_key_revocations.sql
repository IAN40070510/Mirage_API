CREATE TABLE IF NOT EXISTS trusted_key_revocations (
    environment_id TEXT NOT NULL CHECK (length(environment_id) BETWEEN 1 AND 128),
    deployment_id TEXT NOT NULL CHECK (length(deployment_id) BETWEEN 1 AND 128),
    issuer TEXT NOT NULL CHECK (length(issuer) BETWEEN 1 AND 128),
    kid TEXT NOT NULL CHECK (length(kid) BETWEEN 1 AND 128),
    revision BIGINT NOT NULL CHECK (revision >= 1),
    PRIMARY KEY (environment_id,deployment_id,issuer,kid)
);
