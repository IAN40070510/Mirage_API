-- 請求觀察獨立於 WorldEvent；只保存已驗證世界的假名化摘要與基底版本。
CREATE TABLE IF NOT EXISTS request_observations (
    observation_id UUID PRIMARY KEY,
    event_name TEXT NOT NULL DEFAULT 'request_observed' CHECK (event_name = 'request_observed'),
    request_id_digest CHAR(64) NOT NULL CHECK (request_id_digest ~ '^[0-9a-f]{64}$'),
    trusted_context_digest CHAR(64) NOT NULL CHECK (trusted_context_digest ~ '^[0-9a-f]{64}$'),
    request_binding_digest CHAR(64) NOT NULL CHECK (request_binding_digest ~ '^[0-9a-f]{64}$'),
    base_environment_id TEXT NOT NULL,
    base_deployment_id TEXT NOT NULL,
    base_session_id TEXT NOT NULL,
    base_world_generation_id TEXT NOT NULL,
    base_state_version BIGINT NOT NULL CHECK (base_state_version >= 1),
    base_state_hash CHAR(64) NOT NULL CHECK (base_state_hash ~ '^[0-9a-f]{64}$'),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- 正向關聯與 Grant 同交易；失敗只記無法確認，不假稱業務已回滾。
CREATE TABLE IF NOT EXISTS request_observation_results (
    observation_id UUID PRIMARY KEY REFERENCES request_observations(observation_id),
    admission_id TEXT UNIQUE REFERENCES response_admissions(admission_id),
    outcome TEXT NOT NULL CHECK (outcome IN ('admitted','unverifiable')),
    target_environment_id TEXT,
    target_deployment_id TEXT,
    target_session_id TEXT,
    target_world_generation_id TEXT,
    source_kind TEXT,
    committed_state_version BIGINT CHECK (committed_state_version >= 1),
    committed_state_hash CHAR(64) CHECK (committed_state_hash ~ '^[0-9a-f]{64}$'),
    projection_contract_hash CHAR(64) CHECK (projection_contract_hash ~ '^[0-9a-f]{64}$'),
    candidate_hash CHAR(64) CHECK (candidate_hash ~ '^[0-9a-f]{64}$'),
    domain_validation TEXT NOT NULL CHECK (domain_validation IN ('passed','unverifiable')),
    contract_validation TEXT NOT NULL CHECK (contract_validation IN ('passed','unverifiable')),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK ((committed_state_version IS NULL) = (committed_state_hash IS NULL))
);

-- 此新 migration 尚未正式發布；相容實作期 raw-schema 重複套用，正常部署仍由 checksum 管理。
ALTER TABLE request_observation_results DROP CONSTRAINT IF EXISTS request_observation_results_source_kind_check;
ALTER TABLE request_observation_results ADD CONSTRAINT request_observation_results_source_kind_check
    CHECK (source_kind IN ('snapshot','committed_operation','security_error'));
ALTER TABLE request_observation_results DROP CONSTRAINT IF EXISTS request_observation_results_check1;
ALTER TABLE request_observation_results ADD CONSTRAINT request_observation_results_check1 CHECK (
        (outcome = 'admitted' AND admission_id IS NOT NULL
            AND target_environment_id IS NOT NULL AND target_deployment_id IS NOT NULL
            AND target_session_id IS NOT NULL AND target_world_generation_id IS NOT NULL
            AND source_kind IS NOT NULL AND projection_contract_hash IS NOT NULL AND candidate_hash IS NOT NULL
            AND domain_validation = 'passed' AND contract_validation = 'passed'
            AND ((source_kind IN ('snapshot','security_error') AND committed_state_version IS NULL)
                OR (source_kind = 'committed_operation' AND committed_state_version IS NOT NULL)))
        OR (outcome = 'unverifiable' AND admission_id IS NULL AND source_kind IS NULL
            AND target_environment_id IS NULL AND target_deployment_id IS NULL
            AND target_session_id IS NULL AND target_world_generation_id IS NULL
            AND committed_state_version IS NULL AND projection_contract_hash IS NULL AND candidate_hash IS NULL
            AND domain_validation = 'unverifiable' AND contract_validation = 'unverifiable')
    );
