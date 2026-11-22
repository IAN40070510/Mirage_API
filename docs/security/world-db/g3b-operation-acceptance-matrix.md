# G3b 原始 HTTP／業務 RPC 逐項簽收矩陣

**判定基準：2026-11-23，隔離分支，正式部署與發送均封閉。**
本表把「能由 HTTP Proof 選到內部 Handler」與「完成原生 HTTP 成功／錯誤回應相容」
分開評分。`OPERATION_PROOF` 是原始 HTTP/JWS/Receipt 的可信來源；
`RPC_INTERNAL` 是 Executor 內部副作用或讀取，不代表 API 回應、Candidate
Promotion、Authorized Snapshot、Send Lease 已真正完成。以下沒有一條路由
取得正式 G3b 全操作端到端 PASS。

**傳輸子項實測**：固定程式 SHA `cb3e8a6a7d218e7f2144ba0d8ea641486e987898`，
[PostgreSQL 17.6 CI 45056622731](https://github.com/IAN40070510/Mirage_API/actions/runs/45056622731)
`65 passed`、實體 mTLS `4 passed`；
[容器 CI 45056622629](https://github.com/IAN40070510/Mirage_API/actions/runs/45056622629)
`success`。新增真三程序 Gateway→Verifier→Executor 及不同 CA 互相拒絕測試，
不等於獨立 DB Login 或正式部署 Secret／路由權威通過。

| 編號 | 實際方法／路由 | 來源 Proof | 固定 Executor | 2xx／4xx 完整相容簽收 |
| --- | --- | --- | --- | --- |
| I-01 | POST `/synthetic/inventory/reservations` | 隔離 PASS | 受保護 reserve；單一 Receipt Commit | OPEN：尚無可信原生回應 Payload／Validator |
| I-02 | POST `/synthetic/inventory/reservations/{reservation_id}/cancel` | 隔離 PASS | 受保護 cancel | OPEN：2xx／409、重試與錯誤封套整合 |
| I-03 | GET `/synthetic/operations/{attempt}` | 隔離 PASS | 尚未接入固定 Executor | OPEN：200／409 與結果來源 |
| I-04 | GET `/synthetic/inventory/{sku}` | 隔離 PASS | 尚未接入固定 Executor | OPEN：200／409 與讀取來源 |
| C-01 | POST `/synthetic/carts` | 隔離 PASS | 受保護 Creator→衍生 Cart | OPEN：200／409、原始成功封套 |
| C-02 | GET `/synthetic/carts/{cart_id}` | 隔離 PASS | 受保護讀取 Admission | OPEN：完整 cart JSON／錯誤 |
| C-03 | POST `/synthetic/carts/{cart_id}/line-items` | 隔離 PASS | 受保護 add | OPEN：200／409 原生封套 |
| C-04 | POST `/synthetic/carts/{cart_id}/line-items/{item_id}` | 隔離 PASS | 受保護 update | OPEN：200／409 原生封套 |
| C-05 | DELETE `/synthetic/carts/{cart_id}/line-items/{item_id}` | 隔離 PASS | 受保護 remove | OPEN：200／409 原生封套 |
| C-06 | POST `/synthetic/carts/{cart_id}/complete` | 隔離 PASS | 受保護 complete | OPEN：200／409 原生封套 |
| C-07 | GET `/synthetic/orders/{order_id}` | 隔離 PASS | 受保護讀取 Admission | OPEN：200／409 原生封套 |
| C-08 | POST `/synthetic/orders/{order_id}/cancel` | 隔離 PASS | 受保護 cancel_order | OPEN：200／409 原生封套 |
| C-09 | GET `/synthetic/carts/{cart_id}/operations/{attempt}` | 隔離 PASS | 受保護讀取 Admission | OPEN：200／409 原生封套 |
| M-01 | POST `/store/carts` | 隔離 PASS | 尚未執行 Native 建立 | OPEN：200／400／404／409 |
| M-02 | GET `/store/carts/{id}` | 隔離 PASS | 尚未執行 Native 讀取 | OPEN：200／400／404／409 |
| M-03 | POST `/store/carts/{id}/line-items` | 隔離 PASS | 特定 400／404 受保護拒絕來源 | OPEN：200／409、其餘 400／404 情形 |
| M-04 | POST `/store/carts/{id}/line-items/{line_id}` | 隔離 PASS | 尚未執行 Native update | OPEN：200／400／404／409 |
| M-05 | DELETE `/store/carts/{id}/line-items/{line_id}` | 隔離 PASS | 尚未執行 Native delete | OPEN：200／400／404／409 |
| M-06 | POST `/store/carts/{id}/complete` | 隔離 PASS | 尚未執行 Native complete | OPEN：200／400／404／409 |
| M-07 | GET `/store/orders/{id}` | 隔離 PASS | 尚未執行 Native order read | OPEN：200／400／404／409 |

## 安全簽收門檻

1. **入口拓樸**：Gateway 以獨立 CA／Client Certificate 直連 Verifier，
   Verifier 再以另一 CA／Client Certificate 直連 Executor；實際 ASGI
   Method／URL／Headers／Body 必須與 JWS Fingerprint／受保護 Operation Proof 相等。
   隔離三程序測試不等於正式容器 Secret、ACL、pg_hba／源網路已通過。
2. **每路由正常與拒絕結果**：對表中 20 條操作逐一提供官方／合成 Profile
   核准的實際 2xx／4xx Body、Header、Status、Contract Revision，
   用獨立 Validator 對照受保護 Commit／Read／Rejection Source；不能只比內部
   `result_digest` 或 `world_mutation` Metadata。
3. **拒絕與冪等**：缺 Header、重複 JSON Key、路由／編碼歧義、跨 Session／
   Resource／Epoch、負面 ACL、重送 JTI、同 Receipt 重試、DB COMMIT ACK 遺失、
   Executor 503、競態均不得鑄造第二次副作用或未核准的 200／400／404／409。
4. **發送獨立簽核**：在 G3b 全路由相容和實體角色／網路隔離簽核前不得移交
   G4 正式 Sender。不能把 mTLS readiness、200 internal RPC、PG test `passed`
   當成客戶端回應授權。

G3b 整體狀態 `OPEN`。`MIR-SEC-WORLD-001=OPEN`、`MSDSS P2=NO-GO`；
正式 Trusted Send `OFF`，不合併 main、不部署 staging 或 production。

技術來源：[受保護 RPC](../../protected-rpc.md)、[固定 Operation](../../ingress-receipt.md)、
[實作 CI 證據](grant-binding-implementation-status.md)、
[完整業務保護裁決](full-business-protected-executor-decision.md)。
