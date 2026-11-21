-- MIR-SEC-WORLD-001 / G3: 將低信任 Candidate、可信 Promotion 及一次性 Grant 分開。
-- 使用部署的 current_schema()，使一次性測試 schema 不會寫進共用 public。
-- 本 migration 不建立 LOGIN、不賦予 Runtime 使用權；正式權限由隔離部署佈署。

CREATE TABLE IF NOT EXISTS protected_candidate_promotions (
    environment_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    world_generation_id TEXT NOT NULL,
    candidate_ref TEXT NOT NULL,
    candidate_version BIGINT NOT NULL DEFAULT 1 CHECK (candidate_version = 1),
    request_fingerprint CHAR(64) NOT NULL CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
    candidate_hash CHAR(64) NOT NULL CHECK (candidate_hash ~ '^[0-9a-f]{64}$'),
    immutable_body_hash CHAR(64) NOT NULL CHECK (immutable_body_hash ~ '^[0-9a-f]{64}$'),
    semantic_headers_hash CHAR(64) NOT NULL CHECK (semantic_headers_hash ~ '^[0-9a-f]{64}$'),
    projection_contract_hash CHAR(64) NOT NULL CHECK (projection_contract_hash ~ '^[0-9a-f]{64}$'),
    source_spec_sha256 CHAR(64) NOT NULL CHECK (source_spec_sha256 ~ '^[0-9a-f]{64}$'),
    profile_sha256 CHAR(64) NOT NULL CHECK (profile_sha256 ~ '^[0-9a-f]{64}$'),
    source JSONB NOT NULL,
    expires_at BIGINT NOT NULL CHECK (expires_at > 0),
    envelope_bytes BYTEA NOT NULL,
    promoted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (environment_id, deployment_id, session_id, world_generation_id,
                 candidate_ref, candidate_version),
    UNIQUE (environment_id, deployment_id, session_id, world_generation_id, candidate_ref),
    FOREIGN KEY (environment_id, deployment_id, session_id, world_generation_id, candidate_ref)
        REFERENCES candidate_records(environment_id, deployment_id, session_id,
                                            world_generation_id, candidate_ref)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK (candidate_hash = encode(sha256(envelope_bytes), 'hex'))
);

CREATE TABLE IF NOT EXISTS protected_grant_bindings (
    operation_id UUID PRIMARY KEY,
    input_digest CHAR(64) NOT NULL CHECK (input_digest ~ '^[0-9a-f]{64}$'),
    receipt_id UUID NOT NULL UNIQUE REFERENCES ingress_receipts(receipt_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    admission_id TEXT NOT NULL UNIQUE REFERENCES response_admissions(admission_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    environment_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    world_generation_id TEXT NOT NULL,
    candidate_ref TEXT NOT NULL,
    candidate_version BIGINT NOT NULL,
    bound_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (environment_id, deployment_id, session_id, world_generation_id,
                 candidate_ref, candidate_version)
        REFERENCES protected_candidate_promotions(environment_id, deployment_id,
                    session_id, world_generation_id, candidate_ref, candidate_version)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);

-- Security Definer 只負責真實 Row Lock，不提供 DML／任意 SQL。
-- 低權限 Validator／Authorizer 可取鎖，但不需獲得 Session/Receipt/Policy 的 UPDATE。
-- Runtime 不能 EXECUTE；部署不得授予 Runtime 本函式或本 schema CREATE 權限。
CREATE OR REPLACE FUNCTION protected_lock_reference(kind TEXT, identity JSONB)
RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER VOLATILE PARALLEL UNSAFE
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF kind = 'candidate' THEN
        PERFORM 1 FROM candidate_records WHERE environment_id=identity->>'environment_id'
          AND deployment_id=identity->>'deployment_id' AND session_id=identity->>'session_id'
          AND world_generation_id=identity->>'world_generation_id'
          AND candidate_ref=identity->>'candidate_ref' FOR SHARE;
    ELSIF kind = 'read_admission' THEN
        PERFORM 1 FROM read_admissions WHERE read_admission_id=identity->>'read_admission_id'
          FOR SHARE;
    ELSIF kind = 'world_operation' THEN
        PERFORM 1 FROM world_operations WHERE environment_id=identity->>'environment_id'
          AND deployment_id=identity->>'deployment_id' AND session_id=identity->>'session_id'
          AND world_generation_id=identity->>'world_generation_id'
          AND result_digest=identity->>'result_digest'
          FOR SHARE;
    ELSIF kind = 'registry' THEN
        PERFORM 1 FROM projection_registry WHERE projection_contract_hash=identity->>'contract_hash'
          FOR SHARE;
    ELSIF kind = 'session_head' THEN
        PERFORM 1 FROM session_heads WHERE environment_id=identity->>'environment_id'
          AND deployment_id=identity->>'deployment_id' AND session_id=identity->>'session_id'
          FOR SHARE;
    ELSIF kind = 'session_binding' THEN
        PERFORM 1 FROM session_world_bindings WHERE environment_id=identity->>'environment_id'
          AND deployment_id=identity->>'deployment_id' AND session_id=identity->>'session_id'
          AND session_epoch=(identity->>'session_epoch')::bigint FOR SHARE;
    ELSIF kind = 'receipt' THEN
        PERFORM 1 FROM ingress_receipts WHERE receipt_id=(identity->>'receipt_id')::uuid FOR UPDATE;
    ELSIF kind = 'promotion' THEN
        PERFORM 1 FROM protected_candidate_promotions
          WHERE environment_id=identity->>'environment_id'
            AND deployment_id=identity->>'deployment_id' AND session_id=identity->>'session_id'
            AND world_generation_id=identity->>'world_generation_id'
            AND candidate_ref=identity->>'candidate_ref'
            AND candidate_version=(identity->>'candidate_version')::bigint FOR SHARE;
    ELSE
        RAISE EXCEPTION 'unsupported protected lock kind' USING ERRCODE = '22023';
    END IF;
    RETURN FOUND;
END;
$$;

-- 由 Migration 決定真正物件 schema，固定 pg_catalog first／pg_temp last。
-- 不能把呼叫者的 search_path 或 temp table 視作特權解析來源。
DO $$
DECLARE trusted_schema NAME := current_schema();
BEGIN
    EXECUTE format('ALTER FUNCTION %I.protected_lock_reference(text,jsonb) '
                   'SET search_path = pg_catalog, %I, pg_temp', trusted_schema, trusted_schema);
END;
$$;

-- 不可變證據不得被任何一般 DML 更新或刪除；實體 bytes 清理由後續獨立 Fence 管理。
CREATE OR REPLACE FUNCTION reject_protected_mutation()
RETURNS trigger
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'protected evidence is immutable' USING ERRCODE = '42501';
END;
$$;

DROP TRIGGER IF EXISTS candidate_promotion_immutable ON protected_candidate_promotions;
CREATE TRIGGER candidate_promotion_immutable BEFORE UPDATE OR DELETE
ON protected_candidate_promotions FOR EACH ROW
EXECUTE FUNCTION reject_protected_mutation();

DROP TRIGGER IF EXISTS grant_binding_immutable ON protected_grant_bindings;
CREATE TRIGGER grant_binding_immutable BEFORE UPDATE OR DELETE
ON protected_grant_bindings FOR EACH ROW
EXECUTE FUNCTION reject_protected_mutation();

REVOKE ALL ON TABLE protected_candidate_promotions, protected_grant_bindings FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_protected_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION protected_lock_reference(text,jsonb) FROM PUBLIC;
