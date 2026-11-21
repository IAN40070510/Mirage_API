-- MIR-SEC-WORLD-001: 先建立 Receipt 的受限儲存契約，尚未啟用正式 Verifier。
-- 只有獨立 Verifier 在已驗證 JWS 後，才能與 Replay INSERT 同交易建立此紀錄。
-- Replay tombstone 本身不證明驗章；Runtime 不得擁有本表直接 DML。
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

-- 新角色僅能按完整列白名單取得 INSERT；不授予 UPDATE/DELETE/TRUNCATE。
-- 角色授權由獨立部署 Migration／ACL 配置控制，不由一般 Runtime 自行 GRANT。
REVOKE ALL ON TABLE ingress_receipts FROM PUBLIC;
