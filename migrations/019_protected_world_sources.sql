-- MIR-SEC-WORLD-001 / G3：可信 World Executor 的來源證據與 JWS 已驗證能力綁定。
-- 舊 Receipt 不具備 access_mode；不得由 Runtime 補值。只有新 Verifier 寫入完整 Claims。
ALTER TABLE ingress_receipts
    ADD COLUMN IF NOT EXISTS access_mode TEXT
        CHECK (access_mode IN ('read_only', 'inventory', 'cart')),
    ADD COLUMN IF NOT EXISTS resource_id TEXT
        CHECK (resource_id IS NULL OR length(resource_id) BETWEEN 1 AND 128);

-- ReadAdmission 仍是業務快照索引；只有同交易的獨立 Executor 來源列才是可信證據。
CREATE TABLE IF NOT EXISTS protected_world_read_sources (
    read_admission_id TEXT PRIMARY KEY REFERENCES read_admissions(read_admission_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    receipt_id UUID NOT NULL UNIQUE REFERENCES ingress_receipts(receipt_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    environment_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    world_generation_id TEXT NOT NULL,
    request_fingerprint CHAR(64) NOT NULL CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
    state_version BIGINT NOT NULL CHECK (state_version >= 1),
    state_hash CHAR(64) NOT NULL CHECK (state_hash ~ '^[0-9a-f]{64}$'),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- World Commit 仍由原本固定純 handler 產生；此列必須在相同交易與身份下提交。
CREATE TABLE IF NOT EXISTS protected_world_commit_sources (
    commit_attempt_id UUID PRIMARY KEY REFERENCES world_operations(commit_attempt_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    receipt_id UUID NOT NULL UNIQUE REFERENCES ingress_receipts(receipt_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    environment_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    world_generation_id TEXT NOT NULL,
    request_fingerprint CHAR(64) NOT NULL CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
    operation TEXT NOT NULL,
    command_digest CHAR(64) NOT NULL CHECK (command_digest ~ '^[0-9a-f]{64}$'),
    result_digest CHAR(64) NOT NULL CHECK (result_digest ~ '^[0-9a-f]{64}$'),
    state_version BIGINT NOT NULL CHECK (state_version >= 1),
    state_hash CHAR(64) NOT NULL CHECK (state_hash ~ '^[0-9a-f]{64}$'),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- Promotion 使用已驗證 Receipt identity；不接受僅 fingerprint 相同的跨 JTI 挪用。
ALTER TABLE protected_candidate_promotions
    ADD COLUMN IF NOT EXISTS ingress_receipt_id UUID
        REFERENCES ingress_receipts(receipt_id) ON UPDATE RESTRICT ON DELETE RESTRICT;
-- Migration 前的 Promotion 不具備來源身份，不得被新版 Grant 選用。

DROP TRIGGER IF EXISTS protected_world_read_source_immutable ON protected_world_read_sources;
CREATE TRIGGER protected_world_read_source_immutable BEFORE UPDATE OR DELETE
ON protected_world_read_sources FOR EACH ROW EXECUTE FUNCTION reject_protected_mutation();

DROP TRIGGER IF EXISTS protected_world_commit_source_immutable ON protected_world_commit_sources;
CREATE TRIGGER protected_world_commit_source_immutable BEFORE UPDATE OR DELETE
ON protected_world_commit_sources FOR EACH ROW EXECUTE FUNCTION reject_protected_mutation();

REVOKE ALL ON TABLE protected_world_read_sources, protected_world_commit_sources FROM PUBLIC;
