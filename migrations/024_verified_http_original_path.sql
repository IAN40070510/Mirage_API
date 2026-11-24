-- G3b：舊 Operation Proof 缺少原始路徑／Content-Type，不能補成可執行操作。
-- 新 Verifier 在 Replay/Receipt 同一交易寫入；舊列保留 NULL 並永遠 Fail-Closed。
ALTER TABLE protected_http_operation_bindings
    ADD COLUMN request_path TEXT
        CHECK (request_path IS NULL OR length(request_path) BETWEEN 1 AND 2048),
    ADD COLUMN request_content_type TEXT
        CHECK (request_content_type IS NULL OR length(request_content_type) BETWEEN 1 AND 256);
