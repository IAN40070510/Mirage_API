-- MIR-SEC-WORLD-001：可信 Ingress Receipt 與 Replay 墓碑在同一資料庫交易提交。
-- 建表本身不證明驗章；只有獨立 Verifier 登入可呼叫受限寫入介面。
-- Runtime 角色不得取得本表 DML；保留 JTI FK，禁止 GC 刪掉仍被引用的墓碑。
CREATE TABLE IF NOT EXISTS ingress_receipts (
    receipt_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer TEXT NOT NULL CHECK (length(issuer) BETWEEN 1 AND 128),
    audience TEXT NOT NULL CHECK (length(audience) BETWEEN 1 AND 128),
    jti TEXT NOT NULL CHECK (length(jti) BETWEEN 1 AND 128),
    key_id TEXT NOT NULL CHECK (length(key_id) BETWEEN 1 AND 128),
    environment_id TEXT NOT NULL CHECK (length(environment_id) BETWEEN 1 AND 128),
    deployment_id TEXT NOT NULL CHECK (length(deployment_id) BETWEEN 1 AND 128),
    session_id TEXT NOT NULL CHECK (length(session_id) BETWEEN 1 AND 128),
    session_epoch BIGINT NOT NULL CHECK (session_epoch >= 0),
    request_fingerprint CHAR(64) NOT NULL CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
    assessment_digest CHAR(64) NOT NULL CHECK (assessment_digest ~ '^[0-9a-f]{64}$'),
    claims_digest CHAR(64) NOT NULL CHECK (claims_digest ~ '^[0-9a-f]{64}$'),
    verification_policy_version TEXT NOT NULL CHECK (length(verification_policy_version) BETWEEN 1 AND 64),
    token_issued_at BIGINT NOT NULL CHECK (token_issued_at >= 0),
    token_not_before BIGINT NOT NULL CHECK (token_not_before >= token_issued_at),
    token_expires_at BIGINT NOT NULL CHECK (token_expires_at > token_not_before),
    verified_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT ingress_receipts_replay_fk
        FOREIGN KEY (issuer, audience, jti) REFERENCES replay_entries(issuer, audience, jti)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ingress_receipts_once_per_jti UNIQUE (issuer, audience, jti)
);

REVOKE ALL ON TABLE ingress_receipts FROM PUBLIC;
