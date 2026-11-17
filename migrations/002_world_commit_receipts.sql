-- CAS 與收據共用交易。只保存版本與摘要，不保存回應或業務內容。
CREATE TABLE IF NOT EXISTS world_commit_receipts (
    environment_id text NOT NULL,
    deployment_id text NOT NULL,
    session_id text NOT NULL,
    world_generation_id text NOT NULL,
    commit_attempt_id uuid NOT NULL,
    state_version bigint NOT NULL,
    state_hash text NOT NULL,
    PRIMARY KEY (environment_id, deployment_id, session_id, world_generation_id, commit_attempt_id)
);
