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

**四個真容器、獨立 Secret／Network／實體 ACL 增量實測**：隔離分支固定
程式 SHA `327743e8f1244515af961c9423db529c63db5499`，
[真容器 CI 45065339872](https://github.com/IAN40070510/Mirage_API/actions/runs/45065339872)
`success`；日誌記錄 `G3B_CI_PREPARED roles=5 ca_roots=3 services=4`、
`G3B_GATEWAY_PASS unsigned_routes=20/20 inventory_commit=1 medusa_400=1 medusa_404=1`
以及 `G3B_CONTAINER_AUDIT_PASS services=4 networks=3 distinct_mounts=verified runtime_acl=denied`。
這證明在一次性 PostgreSQL 17.6／Docker Compose 隔離環境中，四個實體容器均
通過不公開埠、專屬 Secret 可見性、三網路隔離、不同 SCRAM 物理角色／禁止
Runtime DML、實際 mTLS、可信 Inventory 一次 Commit、Medusa M-03 的
400／404 Executor+獨立 Validator 內部來源對帳及缺 JWS 的 20 條入口 403 拒絕。
**此為隔離 CI 的部署級子項 PASS，不是 staging／production ACL／Secret
實地簽核；20 個 403 不是 20 個原生業務 4xx，Medusa 的客戶端仍收到內部
對帳封套 200 而非原生 400／404。**

| G3b 子門檻 | 獨立實測結果 | 正式簽收 |
| --- | --- | --- |
| 真 HTTPS Gateway→Verifier→Executor、互異 Client CA、拒絕重播／竄改 | 隔離 CI PASS | 僅實驗室傳輸子項 PASS |
| 三個實體 PostgreSQL SCRAM Login、無跨角色 DML／SET ROLE | 隔離 CI PASS | 僅實驗室 ACL 子項 PASS |
| 20 路由 Method／Path Template／Operation ID 與三份固定規格集合同步 | 靜態 Mapping PASS，真容器 HTTPS 入口缺 JWS 的 20/20 逐路由 403 PASS | 隔離入口拒絕子項 PASS；每條合法 JWS、原生 2xx／業務 4xx 仍 OPEN |
| 可配置的隔離 Verifier／雙 Executor／Native Validator、專用 DSN Secret、Role／Schema／ACL 啟動檢查 | 真四容器啟動／實體角色／mTLS／密鑰用途 PASS | 隔離部署子項 PASS；正式環境另驗 |
| Medusa M-03 特定 400／404 的原生 JSON 從獨立 Rejection Source 重建 | 真 PG、唯讀 Validator 來源投影、第二 mTLS CA PASS | 實驗室子項 PASS；正式 Client HTTP 回應與全操作兼容 OPEN |
| Medusa M-03 Validator→Verifier 完整候選 Status／Headers／Body 交接 | 新增固定 400／404 bytes／Scope 綁定與篡改拒絕的本地測試；尚未取得本次真 PG CI | 候選交接局部 PASS；外層仍為內部 HTTP 200、正式 Client 400／404 OPEN |
| Synthetic 固定 mutation Handler rejected→可信 409 來源→獨立 Validator | I-01／I-02、C-03～C-06、C-08 的受保護 409 候選接線與負面測試待固定 SHA CI | 候選子項待驗；CAS conflict／其他 409、外層原生 HTTP 仍 OPEN |
| 正式獨立服務部署、Secret Mount／網路來源、無共享憑證可見性 | 一次性 Docker CI 真容器角色隔離 PASS | 隔離環境 PASS；staging／production 正式部署 OPEN |
| 20 條正式原生 2xx／4xx Payload 與獨立來源／Validator | 20 條均未具全套證據 | OPEN |
| G3b 整體解封並移交 G4 Sender | 前述兩項未完成 | **NO-GO** |

| 編號 | 實際方法／路由 | 來源 Proof | 固定 Executor | 2xx／4xx 完整相容簽收 |
| --- | --- | --- | --- | --- |
| I-01 | POST `/synthetic/inventory/reservations` | 隔離 PASS | 受保護 reserve；單一 Receipt Commit；真 Handler 409 候選待真 PG CI | OPEN：200、CAS conflict／其他 409、原生 HTTP |
| I-02 | POST `/synthetic/inventory/reservations/{reservation_id}/cancel` | 隔離 PASS | 受保護 cancel；真 Handler 409 候選待真 PG CI | OPEN：200、CAS conflict／其他 409、原生 HTTP |
| I-03 | GET `/synthetic/operations/{attempt}` | 隔離 PASS | 固定 UUID4／空 Body Proof → Executor 受保護 ReadAdmission；真 PG [45185402530](https://github.com/IAN40070510/Mirage_API/actions/runs/45185402530) PASS | OPEN：查詢結果、可信 200／409、獨立 Validator／外部 HTTP |
| I-04 | GET `/synthetic/inventory/{sku}` | 隔離 PASS | 固定 SKU／空 Body Proof → Executor 受保護 ReadAdmission；同上真 PG PASS | OPEN：庫存 Payload、可信 200／409、獨立 Validator／外部 HTTP |
| C-01 | POST `/synthetic/carts` | 隔離 PASS | 受保護 Creator→衍生 Cart | OPEN：200／409、原始成功封套 |
| C-02 | GET `/synthetic/carts/{cart_id}` | 隔離 PASS | 受保護讀取 Admission | OPEN：完整 cart JSON／錯誤 |
| C-03 | POST `/synthetic/carts/{cart_id}/line-items` | 隔離 PASS | 受保護 add；真 Handler 409 候選待真 PG CI | OPEN：200、其餘 409、原生 HTTP |
| C-04 | POST `/synthetic/carts/{cart_id}/line-items/{item_id}` | 隔離 PASS | 受保護 update；真 Handler 409 候選待真 PG CI | OPEN：200、其餘 409、原生 HTTP |
| C-05 | DELETE `/synthetic/carts/{cart_id}/line-items/{item_id}` | 隔離 PASS | 受保護 remove；真 Handler 409 候選待真 PG CI | OPEN：200、其餘 409、原生 HTTP |
| C-06 | POST `/synthetic/carts/{cart_id}/complete` | 隔離 PASS | 受保護 complete；真 Handler 409 候選待真 PG CI | OPEN：200、其餘 409、原生 HTTP |
| C-07 | GET `/synthetic/orders/{order_id}` | 隔離 PASS | 受保護讀取 Admission | OPEN：200／409 原生封套 |
| C-08 | POST `/synthetic/orders/{order_id}/cancel` | 隔離 PASS | 受保護 cancel_order；真 Handler 409 候選待真 PG CI | OPEN：200、其餘 409、原生 HTTP |
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

**I-03／I-04 ReadAdmission 增量（固定 SHA `49fc6ed8`，真 PG `114 passed`、mTLS `4 passed`）**：
`decode_verified_inventory_read()` 要求 Executor 自行查回 Verifier 寫入的
不可變 Proof，核對完整原始 GET Path／空 Body／Operation ID／UUID4，再以
Receipt 身分／Epoch／Key／Generation 建立 `protected_world_read_sources`。
固定 Executor RPC 對這兩個 GET 僅回傳 `inventory_read_admitted` 內部
Metadata，並拒絕額外 HTTP Status／Headers／Body 欄位；**沒有可信業務
Response，也沒有客戶端原生 200／409**。SKU 在字元路徑中可能使用 URL
百分比編碼，而現行 Verifier 會拒絕所有百分比編碼路徑；因此完整 SKU
URI 相容性與原生回應仍須獨立驗收，不能因 ReadAdmission 通過而勾選完成。

技術來源：[受保護 RPC](../../protected-rpc.md)、[固定 Operation](../../ingress-receipt.md)、
[實作 CI 證據](grant-binding-implementation-status.md)、
[完整業務保護裁決](full-business-protected-executor-decision.md)。
