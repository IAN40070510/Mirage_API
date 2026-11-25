-- G4 Authorizer 僅允許一個已驗證 Receipt 選定一份不可變 Promotion。
-- 不可只先 SELECT LIMIT 2：在查詢與 Grant 之間的新 Promotion 可能形成幻影列。
-- 以真正 PostgreSQL UNIQUE 索引在儲存層鎖定此單選性；舊版 NULL 身分
-- Promotion 不可由受保護 Authorizer 選用，故不妨礙既有不可變證據保留。
-- 如果舊資料存在同 Receipt 多筆，migration 必須 FAIL 而不能默默挑一筆。
CREATE UNIQUE INDEX protected_promotions_one_per_receipt
    ON protected_candidate_promotions (ingress_receipt_id)
    WHERE ingress_receipt_id IS NOT NULL;
