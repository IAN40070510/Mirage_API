# G3b 原始 HTTP／業務 RPC 逐項簽收矩陣

**判定基準：2026-11-24，隔離分支，正式部署與發送均封閉。**
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

**I-03／I-04 唯讀候選增量已驗證**：固定 SHA
`808d07f63092596e534af550343eef2445be6209`，
[真 PostgreSQL 隔離合約 CI 45235439692](https://github.com/IAN40070510/Mirage_API/actions/runs/45235439692)
`125 passed`、mTLS `5 passed`；[Python CI 45235439732](https://github.com/IAN40070510/Mirage_API/actions/runs/45235439732)
`success`，[容器示範 CI 45235439667](https://github.com/IAN40070510/Mirage_API/actions/runs/45235439667)
`success`。I-03 真實 committed 操作 200 候選與 I-04 缺 SKU 409 候選的
唯讀來源/Validator 子項可登錄為**真 PG/mTLS 隔離 PASS**；G3b 特有
四服務 Push 工作流程仍需獨立確認。本 SHA 的外層是內部對帳 200，
**不是客戶端實收原生 HTTP**。

**2026-11-24 最新分支驗收補記（固定 SHA `88d286fc5012cf169107796723dab20e359cf17a`）**：
[PostgreSQL 17.6 合約 CI 45291573134](https://github.com/IAN40070510/Mirage_API/actions/runs/45291573134)
成功，受保護合約 `127 passed`、實體 mTLS `5 passed`；
[Python CI 45291574008](https://github.com/IAN40070510/Mirage_API/actions/runs/45291574008)
及[容器 CI 45291575025](https://github.com/IAN40070510/Mirage_API/actions/runs/45291575025)
均為 `success`。本地同 SHA 聚焦 Operation Binding／Protected Services／mTLS
`86 passed`，文件檢查成功。I-03 與 C-09「真正不存在的歷史操作」固定 409
來源及四服務子測試已包含在此 SHA 的隔離 CI，故其**候選子項**從「待 CI」
更新為「隔離 PASS」。這沒有測得原生 Client 409，亦未證明 20 路由全部成功／
拒絕相容、正式角色 Secret 隔離、G4 Sender 或 G5 Restore Fence。

**C-09 歷史結果跨 Cart 身分補強（固定 SHA `20be55ae309ab7f10a8056143c22cb6d0d991b37`）**：
獨立 Validator mTLS 候選在原本 Receipt／ReadAdmission／Scope／Schema／Hash 之外，
再將歷史 `cart.id` 或 `order.cart_id` 及實體 ID 型別與原始 GET `cart_id`
比對；重算合法 JSON、Envelope Hash 的錯 Cart 回應不能通過。修補前兩類
跨 Cart 攻擊回歸均失敗（成功重現），修補後同兩類及 ID 型別互換負面均拒絕，
正常 Cart／Order 候選仍通過。本地完整回歸 `1173 passed / 250 skipped`，
[真 PG17.6 合約 CI 45307470508](https://github.com/IAN40070510/Mirage_API/actions/runs/45307470508)
`129 passed`、真 mTLS `5 passed`；
[Python CI 45307470356](https://github.com/IAN40070510/Mirage_API/actions/runs/45307470356)
`1402 passed / 21 skipped`、
[容器 CI 45307470455](https://github.com/IAN40070510/Mirage_API/actions/runs/45307470455)
`success`。**C-09 候選交接跨 Cart 防護子項 PASS**；Client 原生 HTTP、並行
競態、未知 COMMIT 與 G4/G5/G6 仍 OPEN，不解封 Sender。

**I-04 原始 UTF-8 SKU 路徑跨服務一致性（固定 SHA `c1769b97f6e38e42d98b7c1ea6573cfe01bede74`）**：
Verifier 解碼、獨立 Read Source Projector、mTLS Validator Client 現在共用
`decode_verified_inventory_sku_path()`，保留未編碼 Unicode SKU 與合法標點的
一致性，拒絕 `%`／路徑分隔符／控制字元／`.`／`..`／無效 UTF-8 與長度歧義。
本地聚焦 `60 passed`，完整 `1173 passed / 251 skipped`；
[真 PG17.6 合約 CI 45309248796](https://github.com/IAN40070510/Mirage_API/actions/runs/45309248796)
`130 passed`、真 mTLS `5 passed`；
[Python CI 45309248824](https://github.com/IAN40070510/Mirage_API/actions/runs/45309248824)
`1403 passed / 21 skipped`、
[容器 CI 45309248903](https://github.com/IAN40070510/Mirage_API/actions/runs/45309248903)
`success`。**I-04 原始 UTF-8 候選相容子項 PASS**；此舊 SHA 尚未涵蓋
標準 Client percent URL，後續增量另見下段；原生 Client HTTP 200／409、
G4/G5/G6 仍 OPEN。

**I-04 正規 percent-encoded URL 候選（固定 SHA `4e2cecc8adbfed07d16adc95b354608d7077a0c2`，隔離 PASS）**：新增固定
RFC3986 編碼 SKU 解析（例如中文 `%E5...`、空格 `%20`），Verifier 將
原始 bytes 形式寫入不可變 Operation Proof，Executor 拒絕把同一 SKU
另一種 URL 表示重新綁回 Receipt；受保護 Projector 與獨立 Validator
仍按解碼後 SKU 比對來源。拒絕 `%2F`、ASCII 編碼別名、雙重編碼、
大小寫歧義、混合編碼與無效 UTF-8。
[真 PG17.6 CI 45311186073](https://github.com/IAN40070510/Mirage_API/actions/runs/45311186073)
`149 passed`、真 mTLS `5 passed`；
[Python CI 45311186120](https://github.com/IAN40070510/Mirage_API/actions/runs/45311186120)
`1422 passed / 21 skipped`；
[容器 CI 45311186163](https://github.com/IAN40070510/Mirage_API/actions/runs/45311186163)
`success`。**只有正規 URL 候選來源相容子項 PASS**，Client 原生 HTTP
成功／拒絕完整測試仍缺，**不能先簽 G3b**。

**C-06／C-07／C-08 真 Cart→Order 200 候選連續驗收（固定 SHA `eb118a7f8f68eda29f0fc44364d9ae7ca97a9499`，隔離 PASS）**：
受保護 Cart add 取得版本 2 後，新增同世代 `complete` 版本 3→衍生
`order_...`→原始 GET 訂單 ReadAdmission／獨立 Snapshot 投影 200→
`cancel` 版本 4 的連續真 DB 測試。三次獨立 Receipt 均由原始
Method／Path／Body 綁定，Mutation 200 需要 Commit Source／Receipt，
Order GET 200 需要 Creator Lineage／Read Source。
首輪真 PG 發現 C-08 Validator 誤用 complete 的 `cart_id` 規則，已修補成
按 `cart.complete`／`cart.cancel_order` 分別與原始 Cart／Order ID 比對，
再驗證結果確實存在同一 World Snapshot 且 Order→Cart 衍生關係一致；
跨 Cart、跨 Order、孤兒 Order 負面單元測試 PASS；
[真 PG17.6 CI 45312413649](https://github.com/IAN40070510/Mirage_API/actions/runs/45312413649)
`151 passed`、真 mTLS `5 passed`；
[Python CI 45312413568](https://github.com/IAN40070510/Mirage_API/actions/runs/45312413568)
`1424 passed / 21 skipped`；
[容器 CI 45312413632](https://github.com/IAN40070510/Mirage_API/actions/runs/45312413632)
`success`。**三條的獨立 DB 200 候選子項 PASS**，不是 Client HTTP 200。

**I-02 Cancel 200／409 連續候選（固定 SHA `6f42a511fcaacce0c4121ccc4175dd38da606250`，隔離 PASS）**：以已受保護的 I-01
成功預留結果取得 Reservation ID；新的固定 HTTP Receipt 取消並由
Validator 重建 200 `cancelled`，再以第三個 Receipt 重複取消該資源，
必須由真實 `rejected` WorldOperation 重建固定 409
`reservation_not_active`，世界版本不增加。
[真 PG17.6 CI 45313240326](https://github.com/IAN40070510/Mirage_API/actions/runs/45313240326)
`151 passed`、真 mTLS `5 passed`；
[Python CI 45313240332](https://github.com/IAN40070510/Mirage_API/actions/runs/45313240332)
`1424 passed / 21 skipped`；
[容器 CI 45313240348](https://github.com/IAN40070510/Mirage_API/actions/runs/45313240348)
`success`。I-02 200／特定 409 **受保護候選子項 PASS**，仍缺 CAS conflict／
其他 409 與原生 Client HTTP，整體 OPEN。

**C-04／C-05 真品項更新／刪除候選（待本次真 PG CI）**：延伸同一受保護
Cart→Order 測試，在 C-03 add 後以獨立 Receipt 綁定實際品項 ID，執行
C-04 update 200（數量與合成總額）、C-05 delete 200（空品項與總額歸零），
並分別重送同 Receipt 確認不雙寫。兩條均另取新 Receipt 驗證真正不存在的
品項 `cart_item_not_found` 409，由 `rejected` WorldOperation 與獨立 Validator
重建固定 JSON，失敗不推進 World 版本；惡意替換更新 Body／Path 或刪除
Body 不得重綁 Proof。最後再 add→complete→order GET→cancel，核對連續
世界版本。只有程式與測試準備好，**目前不得標記 CI PASS、正式 Client HTTP
或 G3b 解封**。

**Cart 成功候選與快照一致性補強（待本次真 PG CI）**：C-03～C-05
獨立 Validator 現在要求已提交 Result 的 Cart ID、全部品項 ID／數量／價格、
總額、狀態與已驗雜湊的當前 WorldSnapshot 逐欄相同；品項的原生陣列順序
不影響等值，但重複品項、跨 Cart、不同金額或缺少品項固定拒絕。這防止
一份結構合法且自行重算 Digest 的錯誤 Cart Result 冒充該次成功候選；
不等於已驗證 Client HTTP 或擁有 Send 授權。

| G3b 子門檻 | 獨立實測結果 | 正式簽收 |
| --- | --- | --- |
| 真 HTTPS Gateway→Verifier→Executor、互異 Client CA、拒絕重播／竄改 | 隔離 CI PASS | 僅實驗室傳輸子項 PASS |
| 三個實體 PostgreSQL SCRAM Login、無跨角色 DML／SET ROLE | 隔離 CI PASS | 僅實驗室 ACL 子項 PASS |
| 20 路由 Method／Path Template／Operation ID 與三份固定規格集合同步 | 靜態 Mapping PASS，真容器 HTTPS 入口缺 JWS 的 20/20 逐路由 403 PASS | 隔離入口拒絕子項 PASS；每條合法 JWS、原生 2xx／業務 4xx 仍 OPEN |
| 可配置的隔離 Verifier／雙 Executor／Native Validator、專用 DSN Secret、Role／Schema／ACL 啟動檢查 | 真四容器啟動／實體角色／mTLS／密鑰用途 PASS | 隔離部署子項 PASS；正式環境另驗 |
| Medusa M-03 特定 400／404 的原生 JSON 從獨立 Rejection Source 重建 | 真 PG、唯讀 Validator 來源投影、第二 mTLS CA PASS | 實驗室子項 PASS；正式 Client HTTP 回應與全操作兼容 OPEN |
| Medusa M-03 Validator→Verifier 完整候選 Status／Headers／Body 交接 | 固定 400／404 bytes／Scope 綁定及篡改拒絕；真四容器 CI [45211431898](https://github.com/IAN40070510/Mirage_API/actions/runs/45211431898) PASS | **候選交接隔離 PASS**；外層仍為內部 HTTP 200、正式 Client 400／404 OPEN |
| Synthetic 固定 mutation Handler rejected→可信 409 來源→獨立 Validator | I-01／I-02、C-03～C-06、C-08 固定 409 候選能力；隔離四服務實測 I-01 `unknown_synthetic_sku` 409，I-02 真 PG 重複取消 `reservation_not_active` 409 來源 PASS | **I-01／I-02 指定拒絕候選 PASS**；其餘 Handler 情境／CAS conflict／原生 HTTP 仍 OPEN |
| Inventory I-04 GET ReadAdmission→唯讀 WorldSnapshot→獨立 Validator 200／409 | 獨立 Validator 按 Receipt 重建精確 JSON／Scope／Hash，與 Executor ReadAdmission ID／Generation／Version／State Hash 逐欄相符；既有 SKU 200、真缺 SKU 409 與正規編碼 URI 均已真 PG/mTLS CI PASS | **I-04 200／409 與 SKU 編碼來源候選隔離 PASS**；客戶端原生 HTTP 與 G4 Send OPEN |
| 正式獨立服務部署、Secret Mount／網路來源、無共享憑證可見性 | 一次性 Docker CI 真容器角色隔離 PASS | 隔離環境 PASS；staging／production 正式部署 OPEN |
| 20 條正式原生 2xx／4xx Payload 與獨立來源／Validator | 20 條均未具全套證據 | OPEN |
| G3b 整體解封並移交 G4 Sender | 前述兩項未完成 | **NO-GO** |

| 編號 | 實際方法／路由 | 來源 Proof | 固定 Executor | 2xx／4xx 完整相容簽收 |
| --- | --- | --- | --- | --- |
| I-01 | POST `/synthetic/inventory/reservations` | 隔離 PASS | 受保護 reserve；單一 Receipt Commit；真 Handler `unknown_synthetic_sku` 409 候選四服務 PASS；200 成功 Commit／獨立 Validator 候選真 PG PASS | OPEN：其他 409、CAS conflict、原生 HTTP |
| I-02 | POST `/synthetic/inventory/reservations/{reservation_id}/cancel` | 隔離 PASS | 受保護 cancel；真 Reservation 200＋重複取消 `reservation_not_active` 409 候選，SHA `6f42a51` 真 PG PASS | OPEN：CAS conflict、其他 409、原生 HTTP |
| I-03 | GET `/synthetic/operations/{attempt}` | 隔離 PASS | 固定 UUID4／空 Body Proof → ReadAdmission；獨立 Validator 核對 WorldOperation、Commit Receipt、Snapshot／Epoch／Key，重建歷史 200 或確定不存在的 409 候選；固定 SHA `88d286f` 真 PG/mTLS CI PASS | OPEN：客戶端原生 200／409、競態與故障路徑 |
| I-04 | GET `/synthetic/inventory/{sku}` | 隔離 PASS | 固定 SKU／空 Body Proof → Executor ReadAdmission → 獨立 Validator 200 成功／真正缺 SKU 409 候選；SHA `c1769b9` 原始 UTF-8、SHA `4e2cecc` 正規 percent URL 候選真 PG/mTLS PASS | OPEN：Client 原生 200／409、全 URL 相容、G4 Send |
| C-01 | POST `/synthetic/carts` | 隔離 PASS | 受保護 Creator→衍生 Cart | OPEN：200／409、原始成功封套 |
| C-02 | GET `/synthetic/carts/{cart_id}` | 隔離 PASS | 受保護 ReadAdmission＋來源 ID；獨立 Validator 按派生 Cart、目前 Snapshot 重建 200 候選，真 PG 測試 PASS | OPEN：409 來源、客戶端原生 HTTP |
| C-03 | POST `/synthetic/carts/{cart_id}/line-items` | 隔離 PASS | 受保護 add 200 Commit／Validator 候選真 PG PASS；409 候選固定 Handler 存在 | OPEN：其餘 409、原生 HTTP |
| C-04 | POST `/synthetic/carts/{cart_id}/line-items/{item_id}` | 隔離 PASS | 受保護 update；新增真品項 200、缺品項 409、重送與 Proof 防替換測試，待真 PG CI | OPEN：其他 409／CAS、原生 HTTP、實體部署 |
| C-05 | DELETE `/synthetic/carts/{cart_id}/line-items/{item_id}` | 隔離 PASS | 受保護 remove；新增真品項 200、重複刪除 409、重送與 Proof 防替換測試，待真 PG CI | OPEN：其他 409／CAS、原生 HTTP、實體部署 |
| C-06 | POST `/synthetic/carts/{cart_id}/complete` | 隔離 PASS | 受保護 complete 版本 3／獨立 Validator 200 候選，SHA `eb118a7` 真 PG PASS；409 固定 Handler 存在 | OPEN：其餘 409、原生 HTTP |
| C-07 | GET `/synthetic/orders/{order_id}` | 隔離 PASS | 獨立 Validator 按受保護派生 Order、ReadAdmission 重建 200，SHA `eb118a7` 真 PG PASS | OPEN：409 來源、原生 HTTP |
| C-08 | POST `/synthetic/orders/{order_id}/cancel` | 隔離 PASS | 受保護 cancel_order 版本 4／獨立 Validator 按原始 Order ID 綁定 200，SHA `eb118a7` 真 PG PASS | OPEN：其餘 409、原生 HTTP |
| C-09 | GET `/synthetic/carts/{cart_id}/operations/{attempt}` | 隔離 PASS | 唯讀 Validator 核對歷史 WorldOperation、Protected Commit Source／Commit Receipt、ReadAdmission 與快照，重建 200 或確定不存在的 409 候選；固定 SHA `20be55a` 另修補歷史 Cart／Order 的跨 Cart ID 重綁，真 PG/mTLS CI PASS | OPEN：客戶端原生 200／409、競態與故障路徑 |
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

**I-03 增量（待真 PG／四服務 CI）**：新增 `/internal/v1/project-inventory-operation`
只接受 UUIDv4 Receipt，不提供 Handler／狀態／回應碼選擇。獨立只讀 Validator
驗證原始 `GET /synthetic/operations/{attempt}` Proof、ReadAdmission、完整 Scope、
WorldSnapshot、一致的 `committed` WorldOperation 及 Commit Receipt、原始 Result Digest、
Session Epoch／Generation／Key／到期時間，從真實結果重建固定 `200` JSON。
Verifier 再以 Executor ReadAdmission 元資料、已驗簽 Session、精確 Body／Hash、
UUID 與範本比對。未知／rejected／不確定操作不偽造 `409`；外層仍為內部對帳
`200`，沒有 Authorized Send 權，G3b 整體仍 OPEN。

**I-03／I-04 ReadAdmission 增量（固定 SHA `49fc6ed8`，真 PG `114 passed`、mTLS `4 passed`）**：
`decode_verified_inventory_read()` 要求 Executor 自行查回 Verifier 寫入的
不可變 Proof，核對完整原始 GET Path／空 Body／Operation ID／UUID4，再以
Receipt 身分／Epoch／Key／Generation 建立 `protected_world_read_sources`。
固定 Executor RPC 對這兩個 GET 僅回傳 `inventory_read_admitted` 內部
Metadata，並拒絕額外 HTTP Status／Headers／Body 欄位。I-03 仍無業務
Response；I-04 新增唯讀 Validator 可從獨立來源投影既有 SKU 的 200 候選，
且必須與 Executor ReadAdmission 四欄 metadata 完全一致；固定 SHA `faac8f5f`
隔離四服務及真 PostgreSQL CI PASS。**這不改變 Executor 的純 Metadata、
客戶端仍未收到原生 200／409**。SKU 在字元路徑中可能使用 URL
百分比編碼，而現行 Verifier 會拒絕所有百分比編碼路徑；因此完整 SKU
URI 相容性與原生回應仍須獨立驗收，不能因 ReadAdmission 通過而勾選完成。

技術來源：[受保護 RPC](../../protected-rpc.md)、[固定 Operation](../../ingress-receipt.md)、
[實作 CI 證據](grant-binding-implementation-status.md)、
[完整業務保護裁決](full-business-protected-executor-decision.md)。

**2026-11-24 Synthetic Mutation 200 候選增量（待真 PG CI）**：
新增專用 `project-synthetic-success` mTLS 入口，供 I-01／I-02、
C-03～C-06／C-08 七條已核准的 Synthetic Mutation 使用。
由獨立 Validator 唯讀核對相同 Receipt 的原始 HTTP、ReadAdmission、
真正 Commit Source、WorldOperation Result Digest、Commit Receipt、
最新快照與有效 Session／Key，驗證 OpenAPI 200 JSON Schema
及精確 Envelope。此路徑要求完整成功來源，不接受補造未知操作、
失敗結果或 Runtime 自稱成功；目前所有七條仍須個別真 PG
成功／業務拒絕／故障情境驗收，對外原生 HTTP 與 G4 Sender 保持封閉。

**I-03 未知操作 409 候選（固定 SHA `88d286f` 真 PG／mTLS 隔離 PASS）**：獨立 Validator 只有在受保護
GET Receipt／ReadAdmission 已通過，且指定 UUID4 在同世代
`world_operations` 確實不存在時，才按固定 Synthetic Inventory
OpenAPI 回傳 `operation_not_found` 409 候選。已有記錄卻不可信不可
降級成未知操作；對外仍禁止 Send。

**C-09 未知操作 409 候選（固定 SHA `88d286f` 真 PG／mTLS 隔離 PASS）**：只有受保護 Cart ReadAdmission
及相同資源、世代、原始 GET Proof 俱全，且 WorldOperation 依 UUID4
確實不存在時，獨立 Validator 才能產生固定 `operation_not_found`
409 候選；已有但不可信的結果仍固定拒絕。須再驗證拒絕競態／客戶端
原生 HTTP，不能在 G5 Fence 前解除 Sender 封鎖。
