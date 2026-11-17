-- 保留先前無摘要的紀錄，不在 migration 為歷史結果補造證據。
ALTER TABLE world_operations ADD COLUMN IF NOT EXISTS result_encoding_version SMALLINT;
ALTER TABLE world_operations ADD COLUMN IF NOT EXISTS result_digest CHAR(64);
-- 與既有可重複套用的 schema 安裝流程相容；同交易重建約束，避免半套 NULL 通過 CHECK。
ALTER TABLE world_operations DROP CONSTRAINT IF EXISTS world_operation_result_digest_valid;
ALTER TABLE world_operations ADD CONSTRAINT world_operation_result_digest_valid CHECK (
    (result_encoding_version IS NULL AND result_digest IS NULL)
    OR (result_encoding_version IS NOT NULL AND result_encoding_version = 1
        AND result_digest IS NOT NULL AND result_digest ~ '^[0-9a-f]{64}$')
);
