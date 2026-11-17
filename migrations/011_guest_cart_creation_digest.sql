-- 原生請求的建立冪等鍵必須同時綁定內容，避免相同鍵換內容時重用另一張購物車。
ALTER TABLE guest_cart_creations ADD COLUMN IF NOT EXISTS operation_digest CHAR(64);

-- 原生回應的時間、地區與 catalog 投影上下文須與提交結果原子保存，重試不能混用更新後資料。
CREATE TABLE IF NOT EXISTS native_response_contexts (
    environment_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    world_generation_id TEXT NOT NULL,
    commit_attempt_id UUID NOT NULL,
    context JSONB NOT NULL,
    context_hash CHAR(64) NOT NULL,
    PRIMARY KEY(environment_id,deployment_id,session_id,world_generation_id,commit_attempt_id)
);
