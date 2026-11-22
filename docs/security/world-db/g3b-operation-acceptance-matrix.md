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

**獨立登入增量實測**：固定程式 SHA `efd996d7cfea489f39d402f4392b29a89130644a`，
[PostgreSQL 17.6 CI 45057222355](https://github.com/IAN40070510/Mirage_API/actions/runs/45057222355)
`65 passed`、mTLS `4 passed`；
[容器 CI 45057222331](https://github.com/IAN40070510/Mirage_API/actions/runs/45057222331)
`success`。同一拋棄式 PG 的三程序測試另外建立三個互不繼承的 SCRAM-SHA-256
Verifier／Executor／Runtime Login：Verifier 能建來源而不得查 Commit Source，
Executor 能完成固定 Inventory Commit 而不能建立 Receipt，Runtime 不得建
Operation Proof 或 `SET ROLE` 成為 Executor。這是**實體登入及 ACL 的隔離測試**，
不是正式容器的 Secret 不可見、NetworkPolicy、Gateway 部署或全操作相容驗收。

**四角色服務／原生 Medusa 拒絕候選增量實測**：固定程式 SHA
`7987467a171bd7fdacda81b4484b0b9837770538`，
[PostgreSQL 17.6 CI 45062662638](https://github.com/IAN40070510/Mirage_API/actions/runs/45062662638)
`92 passed`、獨立 mTLS `4 passed`、文件檢查成功；
[容器示範 CI 45062662627](https://github.com/IAN40070510/Mirage_API/actions/runs/45062662627)
另行執行。驗證項含 Verifier/Executor 實體受限登入、固定路由、另一個
唯讀 Validator Login 重建 Medusa M-03 指定 400／404 來源與封套，及
Executor／Validator 不同 CA 的拒絕測試。這是**實驗室子項 PASS**，尚未完成
四個容器在正式網路／Secret／pg_hba 的部署級簽收，也未核准 Client HTTP Send。

| G3b 子門檻 | 獨立實測結果 | 正式簽收 |
| --- | --- | --- |
| 真 HTTPS Gateway→Verifier→Executor、互異 Client CA、拒絕重播／竄改 | 隔離 CI PASS | 僅實驗室傳輸子項 PASS |
| 三個實體 PostgreSQL SCRAM Login、無跨角色 DML／SET ROLE | 隔離 CI PASS | 僅實驗室 ACL 子項 PASS |
| 20 路由 Method／Path Template／Operation ID 與三份固定規格集合同步 | 逐路由 Parameterized Proof 單元測試 PASS | 僅靜態 Operation Mapping 子項 PASS；未證明每條真 JWS／mTLS／HTTP 結果 |
| 可配置的隔離 Verifier／雙 Executor／Native Validator、專用 DSN Secret、Role／Schema／ACL 啟動檢查 | 已實作四角色啟動工廠與無公開埠的 Compose 範本；待部署級真容器驗證 | OPEN：程式入口不等於部署隔離簽核 |
| Medusa M-03 特定 400／404 的原生 JSON 從獨立 Rejection Source 重建 | 真 PG、唯讀 Validator 來源投影、第二 mTLS CA PASS | 實驗室子項 PASS；正式 Client HTTP 回應與全操作兼容 OPEN |
| 正式獨立服務部署、Secret Mount／網路來源、無共享憑證可見性 | 未實測 | OPEN |
| 20 條正式原生 2xx／4xx Payload 與獨立來源／Validator | 20 條均未具全套證據 | OPEN |
| G3b 整體解封並移交 G4 Sender | 前述兩項未完成 | **NO-GO** |

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
| M-03 | POST `/store/carts/{id}/line-items` | 隔離 PASS | 特定 400／404 受保護拒絕來源／獨立 Validator mTLS 封套比對 | OPEN：正式 Client HTTP 400／404、200／409、其餘拒絕情形 |
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
