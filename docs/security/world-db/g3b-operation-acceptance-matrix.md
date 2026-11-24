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

**C-04／C-05 真品項更新／刪除候選（固定 SHA `bcb0c68af9dc84693ead1b464be211d30354032a`，隔離 PASS）**：延伸同一受保護
Cart→Order 測試，在 C-03 add 後以獨立 Receipt 綁定實際品項 ID，執行
C-04 update 200（數量與合成總額）、C-05 delete 200（空品項與總額歸零），
並分別重送同 Receipt 確認不雙寫。兩條均另取新 Receipt 驗證真正不存在的
品項 `cart_item_not_found` 409，由 `rejected` WorldOperation 與獨立 Validator
重建固定 JSON，失敗不推進 World 版本；惡意替換更新 Body／Path 或刪除
Body 不得重綁 Proof。最後再 add→complete→order GET→cancel，核對連續
世界版本。[真 PostgreSQL 17.6 CI 45316183177](https://github.com/IAN40070510/Mirage_API/actions/runs/45316183177)
`152 passed`、實體 mTLS `5 passed`，
[Python CI 45316183239](https://github.com/IAN40070510/Mirage_API/actions/runs/45316183239)
`1425 passed / 21 skipped / 2 warnings`，
[容器 CI 45316183175](https://github.com/IAN40070510/Mirage_API/actions/runs/45316183175)
`success`。**只有受保護候選來源及隔離子項 PASS**，非 Client 原生 HTTP，
亦不得據此解封 G3b。

**Cart 成功候選與快照一致性補強（同 SHA `bcb0c68`，隔離 PASS）**：C-03～C-05
獨立 Validator 現在要求已提交 Result 的 Cart ID、全部品項 ID／數量／價格、
總額、狀態與已驗雜湊的當前 WorldSnapshot 逐欄相同；品項的原生陣列順序
不影響等值，但重複品項、跨 Cart、不同金額或缺少品項固定拒絕。這防止
一份結構合法且自行重算 Digest 的錯誤 Cart Result 冒充該次成功候選。
真 PG 合約 `152 passed` 包含這道檢查的正向路徑與負面單元測試，
不等於已驗證 Client HTTP 或擁有 Send 授權。

**C-03／C-06／C-08 真業務拒絕增量（固定 SHA `45b0285823e2dbc2fa2c8cc0558039475055682c`，隔離 PASS）**：從真實衍生
Cart 同世代、不同原始 HTTP Receipt 分別觸發 C-03 的
`unknown_synthetic_variant`／`insufficient_synthetic_inventory`、
C-06 的 `empty_synthetic_cart`／`cart_not_active`，以及 C-08 的
`order_not_cancellable`。每次均要求受保護 WorldOperation `rejected`、
獨立唯讀 Projector 固定 `409` JSON、原 Receipt 重送不另增 Rejection Source、
World 版本保持不變；本地純 Handler 五種拒絕碼重現通過。
[真 PostgreSQL 17.6 隔離 CI 45320201515](https://github.com/IAN40070510/Mirage_API/actions/runs/45320201515)
`152 passed`、獨立實體 mTLS `5 passed`，
[容器 CI 45320201553](https://github.com/IAN40070510/Mirage_API/actions/runs/45320201553)
`success`。**五種固定拒絕僅來源／Validator 隔離 PASS；不是 Client HTTP 409 PASS。**

**C-03 舊版本 CAS 拒絕增量（固定 SHA `c62c79cd0adaae7924ba6c757a8fdb2c41a20c6b`，隔離 PASS）**：
當另一有效且不同原始 Receipt 用過期 `expected_version` 發起 mutation，
要求真 DB `version_conflict` 使操作停止；同一 Receipt 再試不能創造
WorldOperation、Commit Source 或 Rejection Source，更不能把 CAS 競態偽裝成
Handler 的合法 409。
[真 PostgreSQL 17.6 CI 45320671028](https://github.com/IAN40070510/Mirage_API/actions/runs/45320671028)
`152 passed`、真 mTLS `5 passed`、文件檢查成功，
[容器 CI 45320671065](https://github.com/IAN40070510/Mirage_API/actions/runs/45320671065)
`success`。**只勾選單一舊版本 CAS fail-closed 子案例**；尚未覆蓋平行提交、
COMMIT ACK 不明或 Client HTTP，不能簽收全部 CAS。

**C-01 Creator→Derived 受保護授權鏈子項（隔離 PASS；整路由仍 OPEN）**：
原始 `createGuestCart` Receipt 屬於 Creator Session，而新 Cart 有不同的
Session／WorldGeneration。不能把衍生 Cart 快照直接當作 Creator Scope
的 SnapshotSource。固定程式 SHA
[`f4ef309`](https://github.com/IAN40070510/Mirage_API/commit/f4ef309019a8c0dbf85c5d9a549980ce4f189c9d)
新增獨立 `CartCreationSource`：唯讀 Validator 必須由原始 Creator Receipt、
不可變 `protected_cart_creations`、真 `createGuestCart` Proof、原始
`guest_cart_creations`、派生資源、已驗 Hash 的版本 1 WorldSnapshot、
Commit Receipt、雙方 Session Head／Generation、期限及 Key Revocation
重建固定 200 JSON；Projection／Promotion／Admission **全部保持 Creator
Scope**，只有 Source 指向 Derived Session。Promotion 必須重算精確
Envelope Hash；Grant 交易再驗來源是否仍有效，舊 Prototype Grant／Audit
不得接受這個特殊來源來繞過獨立 Authorizer。

[真 PostgreSQL 17.6 CI 45331338643](https://github.com/IAN40070510/Mirage_API/actions/runs/45331338643)
`155 passed`、真 mTLS `5 passed`、G5 密碼學回歸 `9 passed`；
[容器 CI 45331338690](https://github.com/IAN40070510/Mirage_API/actions/runs/45331338690)
`success`。真 DB 正向涵蓋 Creator→Derived 重試、200 Projector、Candidate
Promotion 及 Authorizer Admission；負面涵蓋錯 Scope、偽造派生來源、
竄改原始建立結果及 Grant 前證據漂移。中間 SHA `ec41463` 曾在 Grant
模型的同世代假設上 **CI FAIL**（`1 failed / 154 passed`），修正後以
`f4ef309` 重跑全數通過，沒有用早期 PASS 掩蓋失敗。

**不包含**：C-01 真實 Client 收到原生 200／409、所有非法建立情境、
授權後到 Sender 前派生世界的競態、未知 COMMIT／跨進程 ACK、
正式隔離角色與部署核對；上述和 G4/G5/G6 仍 OPEN。

**C-01 真四服務 Creator→Derived 正向路徑增量（2026-11-24，隔離候選 PASS）**：
固定提交 [`8f3aea4`](https://github.com/IAN40070510/Mirage_API/commit/8f3aea4472d7a4c2f6760583c591bec3aa69f1f0)
的 [G3b 四服務 CI #68](https://github.com/IAN40070510/Mirage_API/actions/runs/45334119506)
`success`；四個互異 Docker 服務、三個網路、三個 CA Root、隔離 Secret Mount
及五個 PostgreSQL 登入身分，在正式 mTLS／真 PostgreSQL 17.6 上送入
`POST /synthetic/carts` 的 JWS／原始 Creator Proof，得到
`G3B_ROUTE_PROTECTED_CART_CREATION_CANDIDATE`：
`operation_id=createGuestCart`、`source=protected_cart_creations`、
`authorization_scope=creator`、`validated_native_status=200`、
`outer_http_status=200`、`native_business_response=false`。
同批 `G3B_GATEWAY_PASS` 確認 20/20 未簽章路由拒絕、重播／匿名拒絕、
Executor 對外不可直連、Trusted Send `off`；`G3B_CONTAINER_AUDIT_PASS`
確認實體 ACL／網路／Mount 隔離。前一成功 [#67](https://github.com/IAN40070510/Mirage_API/actions/runs/45333854373)
亦驗證相同正向路徑；其後修正了虛擬 ACL 測試，使完整 CI 同版通過。

**最小權限修補與負面證據**：Cart 建立必須寫入 `native_response_contexts`，
而 `world_snapshots` 的 audit trigger 寫入 `world_initializations`；隔離
Cart Login 只獲得相關 `INSERT`，Validator 只有建立來源的 `SELECT`。
PostgreSQL 的 `SELECT ... FOR SHARE` 對 `synthetic_resources` 另要求
更新權限，因此僅允許 Cart Login 使用單一欄位 `UPDATE(resource_kind)`
供 row lock 檢查，不授予 table-wide `UPDATE`；migration
`028_immutable_synthetic_resource_lock.sql` 的 `BEFORE UPDATE OR DELETE`
Trigger 無條件阻止實際修改。真實 Cart Login 的 SQL 更新嘗試必須被拒，
CI 逐次核對列級權限與其他角色不能繞過不可變性。此為防止增權的隔離
技術子項，不代表任何 Production Role 已被核驗。

**失敗與重新驗證**：首次四服務 C-01 探針 [#60](https://github.com/IAN40070510/Mirage_API/actions/runs/45332128830)
因 Executor 503 FAIL；[#61～#66](https://github.com/IAN40070510/Mirage_API/actions/runs/45333527962)
依次定位並補齊真實角色／Trigger／Row-lock 權限，均未作 PASS。
修補 immutable lock 後 #67 PASS，但該 SHA 的 PG 模擬 ACL 測試有
`1 failed / 154 passed`；`8f3aea4` 修正測試後，
[真 PostgreSQL 契約 CI 45334128980](https://github.com/IAN40070510/Mirage_API/actions/runs/45334128980)
完整 `155 passed`、實體 mTLS `5 passed`、G5 密碼學 `9 passed`，
[容器示範 CI 45334128988](https://github.com/IAN40070510/Mirage_API/actions/runs/45334128988)
`success`。此增量仍**未提供客戶端原生 200／409、未知 ACK／COMMIT、
正式 Sender／Restore Fence，也未簽收 C-01 整路由**。

**C-01 跨 Receipt 重用 Cart 建立鍵負面增量（2026-11-24，隔離 PASS）**：
固定提交 [`43d11ba`](https://github.com/IAN40070510/Mirage_API/commit/43d11bab697f7a40cae59921a20b1dd0cda07f95)
的 [四服務 CI #71](https://github.com/IAN40070510/Mirage_API/actions/runs/45334890206)
`success`。先以明確 UUIDv4 `idempotency_key` 和 `commit_attempt_id`
完成一張有效 Creator Receipt 的 C-01 正向 200 候選，再使用**相同原始
JSON／建立鍵，但不同 x-request-id、有效 JWS／JTI／Receipt**再次呼叫。
第二張 Receipt 只能獲得不包含業務候選的內部 fail-closed `503`；
`G3B_ROUTE_CART_CREATION_CROSS_RECEIPT_DENIED` 表示拒絕，真資料庫稽核
同時要求 `protected_cart_creations` 和 `guest_cart_creations` 在相同
Creator Session 都只有兩筆（一次性 Owner fixture 一筆＋第一張 HTTP
Receipt 成功一筆），**不得因第二張 Receipt 多出第三筆**。既有
20/20 未簽章入口拒絕、Replay／ACL／Network／Trusted Send OFF 一併
回歸 PASS。[PG 契約 CI 45334895627](https://github.com/IAN40070510/Mirage_API/actions/runs/45334895627)
與 [容器 CI 45334895608](https://github.com/IAN40070510/Mirage_API/actions/runs/45334895608)
皆 `success`。第一版 [#70](https://github.com/IAN40070510/Mirage_API/actions/runs/45334706771)
實際 Gateway 拒絕成功，但誤將預置 Creator Cart 漏算為零，導致稽核
`FAIL`；#71 已修正預置基準並重跑。**只簽收跨 Receipt 重用鍵 fail-closed
這一個負面子案例**；同 Receipt 未知 COMMIT、所有 C-01 業務拒絕、
客戶端原生 HTTP 和 G4～G6 仍 OPEN。

**C-01 客戶端偽造建立 Body 負面增量（2026-11-24，隔離 PASS）**：
固定提交 [`2fe7fb0`](https://github.com/IAN40070510/Mirage_API/commit/2fe7fb0a422acbf139bfdd337af30723f03b7171)
的 [四服務 CI #73](https://github.com/IAN40070510/Mirage_API/actions/runs/45335393441)
`success`。兩次各有獨立有效 JWS／JTI／Receipt 的真 mTLS
`POST /synthetic/carts`，分別送入重複 `idempotency_key` JSON 欄位與
Client 自稱 `inventory={"sku-1":999}`，皆在原始 Body Proof／嚴格 Model
邊界被拒，對外控制面為 fail-closed `503` 而非業務 200／409；
`G3B_ROUTE_CART_CREATION_INVALID_BODY_DENIED cases=2`，同批真 PG
受保護 Cart 建立與原始建立表仍只各有預置一筆＋合法建立一筆，
未由無效輸入產生第三個 Cart。[PG 契約 CI 45335400708](https://github.com/IAN40070510/Mirage_API/actions/runs/45335400708)
與 [容器 CI 45335400698](https://github.com/IAN40070510/Mirage_API/actions/runs/45335400698)
皆 `success`。**僅簽收重複 JSON Key／額外 World 權威欄位這兩個
隔離負面子案例**；不能據此宣稱 C-01 所有非法 Body、原生 HTTP 或
G3b／G4～G6 已完成。

**C-02 新建 Derived Cart 即時讀取（2026-11-24，隔離候選 PASS）**：
固定程式提交 [`a79df7c`](https://github.com/IAN40070510/Mirage_API/commit/a79df7c472bfb9f305a527159706268963affc7d)
的 [G3b 真四服務 CI #75](https://github.com/IAN40070510/Mirage_API/actions/runs/45355053879)
`success`。直接沿用本次 C-01 成功建立的 Cart ID 與**新派生 Session**，
另簽新的 GET `/synthetic/carts/{cart_id}` JWS／JTI；正式 Gateway→
Cart Executor→唯讀 Native Validator mTLS 路徑取得 `getGuestCart`
`validated_native_status=200` 候選，獨立核對真 `ReadAdmission ID`、
來源 Snapshot、WorldGeneration、Derived Scope、初始 `state_version=1`
及與建立候選相同的 `cart`、`state_hash`、精確 Envelope Hash；
重播同張 JWS 得 403。既有 Owner fixture Cart 的 C-02 查詢仍一同通過，
`G3B_GATEWAY_PASS cart_created_then_read_200=1 cart_read_200=1`，
同批 `G3B_CONTAINER_AUDIT_PASS` 證明四個服務的網路、Secret 與 DB ACL
隔離，Trusted Send 仍 `off`。
[PG 契約 CI 45355063167](https://github.com/IAN40070510/Mirage_API/actions/runs/45355063167)
和 [容器 CI 45355062907](https://github.com/IAN40070510/Mirage_API/actions/runs/45355062907)
均 `success`。**只簽收 C-01→C-02 新派生身分的正向讀取候選**；
缺 Cart 的可信 409 來源、跨 Scope 全負面、客戶端原生 HTTP 與
G4 Sender／G5／G6 尚未完成。

**C-02 Creator 跨 Derived Cart Scope 讀取拒絕（2026-11-24，隔離負面 PASS）**：
固定程式提交 [`91ba701`](https://github.com/IAN40070510/Mirage_API/commit/91ba701f33b5179b84468ded3384aa7204894d83)
的 [G3b 真四服務 CI #77](https://github.com/IAN40070510/Mirage_API/actions/runs/45355731172)
`success`。同輪先由合法 Creator Receipt 建立 Derived Cart，再以獨立有效的
JWS／JTI／Receipt，用**原 Creator Session** 試圖 GET 新 Derived Cart ID；
Gateway→Executor 正式 mTLS 路徑回內部不透明 fail-closed `503`，不產生
`getGuestCart` 200 業務候選；同時要求真 PostgreSQL 的 Creator Session
**沒有** `protected_world_read_sources` 可供挪用。相對地，正確 Derived
Session 使用新 JWS 讀相同 Cart 仍取得 200 候選，舊 JWS Replay 仍遭 403。
CI 原始 `G3B_ROUTE_CART_CREATOR_CROSS_SCOPE_READ_DENIED` 與
`G3B_GATEWAY_PASS cart_creator_cross_scope_read=denied`、
`G3B_CONTAINER_AUDIT_PASS services=4 networks=3 distinct_mounts=verified
runtime_acl=denied trusted_send=off` 均成立；
[容器 CI 45355739624](https://github.com/IAN40070510/Mirage_API/actions/runs/45355739624)
`success`。**只簽收這個 Creator→Derived 跨 Scope 負面子案例**；
其他錯 Scope、可信 409、原生 Client HTTP、G4～G6 仍 OPEN。

**C-03～C-05 同一 Derived Cart 真四服務連續操作（2026-11-24，隔離候選 PASS）**：
固定提交 [`2cd34d1`](https://github.com/IAN40070510/Mirage_API/commit/2cd34d1c9aca6b804ad42b2550927f0a678d641a)
的 [四服務 CI #79](https://github.com/IAN40070510/Mirage_API/actions/runs/45356443474)
先證實 C-01 新建、C-02 原生候選讀取成功的 Derived Cart，以新 Receipt／
JWS／JTI／資源能力，真 POST C-03 加入 `known` Variant 兩件。
Executor 的真 Commit Source 及獨立唯讀 Validator 重建
`addGuestCartItem` 200 候選，`state_version=2`、數量 2、單價 100、
總額 200、Commit Attempt／Digest／State Hash／World Generation／
精確 Envelope Hash 均相符，JWS 重播 403。

固定提交 [`f414ecc`](https://github.com/IAN40070510/Mirage_API/commit/f414ecc9f7574ec6591cd94792da104913a625c9)
的 [四服務 CI #80](https://github.com/IAN40070510/Mirage_API/actions/runs/45356848007)
在相同 Derived Cart 版本 2，改送不存在的 `not-in-catalog` Variant，
真 Handler 回 `rejected`，獨立 `protected_world_rejection_sources`
還原固定 `unknown_synthetic_variant` 409 候選；內部控制面仍是 200，
**非客戶端收到業務 409**。

固定提交 [`2d75dfe`](https://github.com/IAN40070510/Mirage_API/commit/2d75dfe6bc49dbdfc18f91f087a40330c66f6df9)
的 [四服務 CI #81](https://github.com/IAN40070510/Mirage_API/actions/runs/45357206947)
`success` 再沿用上一張**已核對的加入候選**中的 Item ID，使用獨立有效
JWS／Receipt，依版本 2→3 執行 C-04 update 數量 3、金額 300，再依版本
3→4 執行 C-05 delete、Item 清空、金額 0。兩次真 mTLS／真 PostgreSQL
Commit／獨立 Validator 都逐欄核對受保護來源、Digest、版本、Hash、
Scope、精確封套，且兩次 Replay 都得到 403；
`G3B_GATEWAY_PASS cart_derived_add_200=1 cart_derived_unknown_variant_409=1
cart_derived_update_200=1 cart_derived_remove_200=1`，
`G3B_CONTAINER_AUDIT_PASS services=4 networks=3 ... trusted_send=off`。
真 PG 稽核要求 Commit Source 合計 4（庫存 1＋Cart 3）、
受保護 Rejection Source 合計 2（庫存 1＋Cart 1）；同版
[PG 契約 CI 45357214783](https://github.com/IAN40070510/Mirage_API/actions/runs/45357214783)
和 [容器 CI 45357214771](https://github.com/IAN40070510/Mirage_API/actions/runs/45357214771)
均 `success`。**只簽收這組 Derived Cart 加入／未知商品拒絕／更新／刪除的隔離子項**；
所有其他 CAS／缺 Item／競態／未知 COMMIT／客戶端原生 HTTP 仍 OPEN，
不能解除 G4～G6 Gate。

**C-06～C-08 同一 Derived Cart→Order 真四服務連續操作（2026-11-24，隔離候選 PASS）**：
在上段 C-05 真刪除後，Cart 版本 4 且 Items 為空。固定提交
[`301b784`](https://github.com/IAN40070510/Mirage_API/commit/301b784a294530999fc08359165383fe3d417237)
的 [四服務 #83](https://github.com/IAN40070510/Mirage_API/actions/runs/45357745752)
`success`：獨立有效 JWS／Receipt 呼叫 `completeGuestCart`，真 Handler
產生 `empty_synthetic_cart` 拒絕並由不可變 Rejection Source／獨立
Validator 重建固定 409 候選；同版
[PG 契約 #45357754506](https://github.com/IAN40070510/Mirage_API/actions/runs/45357754506)、
[Python #45357754478](https://github.com/IAN40070510/Mirage_API/actions/runs/45357754478)、
[容器 #45357754633](https://github.com/IAN40070510/Mirage_API/actions/runs/45357754633)
均 `success`。

固定提交 [`7b7c076`](https://github.com/IAN40070510/Mirage_API/commit/7b7c0761a43e1346299ca2a780309764daa4b647)
的 [四服務 #84](https://github.com/IAN40070510/Mirage_API/actions/runs/45358099395)
`success`：相同 Derived Cart 用有效新 Receipt 補入一件合法商品，版本
4→5、總額 100；緊接著依版本 5 真完成 C-06，受保護 Commit Source／
獨立 Validator 重建 **200 候選**，版本 6、`order_...`、Order→Cart
來源鏈、品項、價格及 State/Envelope Hash 均核對，兩次 JWS Replay 403。
同版 [PG #45358108384](https://github.com/IAN40070510/Mirage_API/actions/runs/45358108384)
與 [容器 #45358108417](https://github.com/IAN40070510/Mirage_API/actions/runs/45358108417)
均 `success`。

固定提交 [`5205e2a`](https://github.com/IAN40070510/Mirage_API/commit/5205e2a9491006e1d4b818a9e8167577c4ba73f9)
的 [四服務 #85](https://github.com/IAN40070510/Mirage_API/actions/runs/45358447382)
`success`：不是預置 Order，而是沿用 C-06 **已獨立驗證的 Order ID**，
以新 Order Resource Capability 和 JWS 經真 C-07 GET 建立 ReadAdmission，
Snapshot／獨立 Validator 重建 200 候選（版本 6）；接著以同一合法 Order
的另一張 Receipt 執行 C-08 `cancelSyntheticOrder`，真 Commit 後版本 7、
狀態 `cancelled`，獨立 Validator 重建 200 候選。逐筆核對
Scope／Generation／Digest／State/Envelope Hash 與 Replay 拒絕，
`G3B_GATEWAY_PASS derived_order_get_200=1 derived_order_cancel_200=1`。
同版 [PG #45358457179](https://github.com/IAN40070510/Mirage_API/actions/runs/45358457179)
與 [容器 #45358457245](https://github.com/IAN40070510/Mirage_API/actions/runs/45358457245)
均 `success`。**只簽收四服務中這組 Cart→Order 候選與空 Cart 拒絕**；
其餘 409、CAS 競態、未知 Commit、真客戶端原生 HTTP、正式 Sender／G5／G6
仍 OPEN。

**C-09 已取消 Order 後的 Cart 歷史操作與缺操作來源（2026-11-24，隔離候選 PASS）**：
固定提交 [`fcf7f81`](https://github.com/IAN40070510/Mirage_API/commit/fcf7f814aff40a4ee6912ec19a2943a0393158ef)
的 [真四服務 #86](https://github.com/IAN40070510/Mirage_API/actions/runs/45358750394)
`success`。沿用 C-03 成功加入商品時的原始 `commit_attempt_id`，在 C-06
結帳、C-07 查詢、C-08 取消後的**世界版本 7**，以合法 Derived Cart
Capability 與新 JWS／Receipt 呼叫 C-09 GET 歷史操作。
Executor 的新 ReadAdmission／獨立 Validator 必須以原始 WorldOperation、
受保護 Commit Source／Receipt 還原當年**版本 2** Cart／Hash／Attempt
200 候選，絕不以目前版本 7 狀態冒充；接著以另一張合法 Receipt 查詢
真正不存在的 UUIDv4 Attempt，獨立快照來源重建固定
`{"code":"operation_not_found"}` **409 候選**。兩次均核對最新
ReadAdmission 的來源 ID／Scope／Generation、精確 Envelope Hash、
Replay 403；`G3B_GATEWAY_PASS cart_historical_operation_200=1
cart_missing_operation_409=1`，Trusted Send 仍 `off`。
同版 [PG 契約 #45358760593](https://github.com/IAN40070510/Mirage_API/actions/runs/45358760593)
與 [容器 #45358760788](https://github.com/IAN40070510/Mirage_API/actions/runs/45358760788)
均 `success`。**只簽收同 Cart 歷史提交 200／真正缺 Attempt 409 的隔離候選**；
其他跨 Cart／並行／故障情況、客戶端原生 HTTP 仍 OPEN。

**I-02 真 Reservation 取消與重複取消（2026-11-24，隔離候選 PASS）**：
固定提交 [`deb0311`](https://github.com/IAN40070510/Mirage_API/commit/deb03115ee15e574e0de10c3c570ccfeccb680ef)
的 [真四服務 #88](https://github.com/IAN40070510/Mirage_API/actions/runs/45359511846)
`success`。沿用本輪 I-01 真實 Commit 的 Reservation ID 與合法 Inventory
Session，另簽兩張各自有效的 JWS／JTI／Receipt。第一次依 CAS 版本 2
呼叫 I-02 `cancelSyntheticInventory`，真 PostgreSQL Commit 版本 3，
獨立 Validator 核對 `protected_world_commit_sources` 產生取消狀態、
數量、State Hash／Result Digest／Envelope Hash 一致的 200 候選；
第二次依版本 3 對**同一 Reservation** 取消，真 Handler `rejected`，
`protected_world_rejection_sources` 固定 `reservation_not_active`
409 候選，沒有第二次庫存提交，JWS Replay 均為 403。
同版 [PG 契約 #45359521100](https://github.com/IAN40070510/Mirage_API/actions/runs/45359521100)
與 [容器 #45359521252](https://github.com/IAN40070510/Mirage_API/actions/runs/45359521252)
均 `success`；真 DB 稽核要求本輪 Cart／Inventory Commit Source 合計 8、
Rejection Source 合計 4。**僅這組 I-01→I-02 正向／重複取消候選隔離 PASS**；
其餘拒絕、CAS 競態、原生 Client HTTP 與 G4～G6 仍 OPEN。

| G3b 子門檻 | 獨立實測結果 | 正式簽收 |
| --- | --- | --- |
| 真 HTTPS Gateway→Verifier→Executor、互異 Client CA、拒絕重播／竄改 | 隔離 CI PASS | 僅實驗室傳輸子項 PASS |
| 三個實體 PostgreSQL SCRAM Login、無跨角色 DML／SET ROLE | 隔離 CI PASS | 僅實驗室 ACL 子項 PASS |
| 20 路由 Method／Path Template／Operation ID 與三份固定規格集合同步 | 靜態 Mapping PASS，真容器 HTTPS 入口缺 JWS 的 20/20 逐路由 403 PASS | 隔離入口拒絕子項 PASS；每條合法 JWS、原生 2xx／業務 4xx 仍 OPEN |
| 可配置的隔離 Verifier／雙 Executor／Native Validator、專用 DSN Secret、Role／Schema／ACL 啟動檢查 | 真四容器啟動／實體角色／mTLS／密鑰用途 PASS | 隔離部署子項 PASS；正式環境另驗 |
| Medusa M-03 特定 400／404 的原生 JSON 從獨立 Rejection Source 重建 | 真 PG、唯讀 Validator 來源投影、第二 mTLS CA PASS | 實驗室子項 PASS；正式 Client HTTP 回應與全操作兼容 OPEN |
| Medusa M-03 Validator→Verifier 完整候選 Status／Headers／Body 交接 | 固定 400／404 bytes／Scope 綁定及篡改拒絕；真四容器 CI [45211431898](https://github.com/IAN40070510/Mirage_API/actions/runs/45211431898) PASS | **候選交接隔離 PASS**；外層仍為內部 HTTP 200、正式 Client 400／404 OPEN |
| Synthetic 固定 mutation Handler rejected→可信 409 來源→獨立 Validator | I-01／I-02、C-03～C-06、C-08 固定 409 候選能力；隔離四服務實測 I-01 `unknown_synthetic_sku` 409，I-02 真 PG 重複取消 `reservation_not_active` 409，以及 C-03／C-06／C-08 五種真業務拒絕候選 SHA `45b0285` 真 PG PASS | **指定拒絕來源候選隔離 PASS**；其餘 Handler 情境／CAS conflict／原生 HTTP 仍 OPEN |
| Inventory I-04 GET ReadAdmission→唯讀 WorldSnapshot→獨立 Validator 200／409 | 獨立 Validator 按 Receipt 重建精確 JSON／Scope／Hash，與 Executor ReadAdmission ID／Generation／Version／State Hash 逐欄相符；既有 SKU 200、真缺 SKU 409 與正規編碼 URI 均已真 PG/mTLS CI PASS | **I-04 200／409 與 SKU 編碼來源候選隔離 PASS**；客戶端原生 HTTP 與 G4 Send OPEN |
| C-01 Creator→Derived 實體四服務候選 200、最小權限 Row Lock／不可變資源拒絕 | [四服務 #68](https://github.com/IAN40070510/Mirage_API/actions/runs/45334119506) PASS，`source=protected_cart_creations`、`authorization_scope=creator`、`native_business_response=false`；真 PG／mTLS／Trigger SQL 拒絕 PASS | **C-01 實體候選子項隔離 PASS**；客戶端原生 200／409、正式發送及未知 COMMIT OPEN |
| C-01 不同 Receipt 重用同一建立鍵 | [四服務 #71](https://github.com/IAN40070510/Mirage_API/actions/runs/45334890206) Gateway fail-closed `503`、兩個建立來源表均無第三筆，PG／Container 同版 PASS | **單一跨 Receipt 重用鍵負面子項隔離 PASS**；同 Receipt ACK 未知與業務 409 OPEN |
| C-01 不合法原始建立 Body／Client 偽造初始庫存 | [四服務 #73](https://github.com/IAN40070510/Mirage_API/actions/runs/45335393441) 真 JWS/mTLS 的重複 JSON Key／額外 Inventory 兩次 `503`，真 DB 無新增 Cart | **兩個輸入拒絕隔離子項 PASS**；完整 Body／業務 409／正式原生 HTTP OPEN |
| C-02 新建 Derived Cart 的 ReadAdmission／Validator 200 | [四服務 #75](https://github.com/IAN40070510/Mirage_API/actions/runs/45355053879) 新建真 Cart→新 Session GET→真 PG Read Source／精確 Hash 200 候選及 JWS Replay 拒絕 PASS | **C-02 即時派生讀取候選隔離 PASS**；可信缺 Cart 409、正式客戶端 HTTP OPEN |
| C-02 Creator 對 Derived Cart 跨 Scope 的讀取拒絕 | [四服務 #77](https://github.com/IAN40070510/Mirage_API/actions/runs/45355731172) 真 mTLS 有效 Creator JWS／新 Cart ID → 不透明 503；真 PG 無 Creator Read Source；Derived Scope 200 候選保持 PASS | **單一跨 Scope 負面子項隔離 PASS**；其他 Scope／409／原生 HTTP OPEN |
| C-03～C-05 真 Derived Cart 的連續更新與拒絕 | [四服務 #79](https://github.com/IAN40070510/Mirage_API/actions/runs/45356443474) C-03 200；[#80](https://github.com/IAN40070510/Mirage_API/actions/runs/45356848007) 未知 Variant 真來源 409 候選；[#81](https://github.com/IAN40070510/Mirage_API/actions/runs/45357206947) C-04/C-05 200，版本 1→2→3→4／精確 Hash／Replays PASS | **指定 200／409 候選四服務隔離 PASS**；其他錯誤／CAS 並行／原生 Client HTTP OPEN |
| C-06～C-08 新 Derived Cart 轉 Order／讀取／取消 | [四服務 #83](https://github.com/IAN40070510/Mirage_API/actions/runs/45357745752) 空 Cart 409；[#84](https://github.com/IAN40070510/Mirage_API/actions/runs/45358099395) 補品項後完成訂單 200；[#85](https://github.com/IAN40070510/Mirage_API/actions/runs/45358447382) 真 Order GET 200 與 cancel 200、版本 4→5→6→7、來源／Replay PASS | **特定 Cart→Order 連續候選四服務隔離 PASS**；其他情況／原生 HTTP／G4～G6 OPEN |
| C-09 已取消 Order 後仍可查合法 Cart 歷史操作／缺操作 | [四服務 #86](https://github.com/IAN40070510/Mirage_API/actions/runs/45358750394) 版本 7 的 ReadAdmission 重建版本 2 歷史 Cart／Commit 200 候選，同一 Cart 缺 UUIDv4 Attempt 409 候選，精確 Hash／Replay PASS | **指定 200／409 候選隔離 PASS**；其他故障、原生 HTTP OPEN |
| I-02 真實 I-01 Reservation 後續取消與重複取消 | [四服務 #88](https://github.com/IAN40070510/Mirage_API/actions/runs/45359511846) I-01 真 Reservation→I-02 CAS 版本 2→3 200 Commit；第二張有效 Receipt 真 Handler `reservation_not_active` 409 候選，來源／Replay PASS | **指定 I-02 200／409 候選隔離 PASS**；其他錯誤與原生 Client HTTP OPEN |
| Medusa M-02／M-07 原生 GET 受保護讀取來源 | 固定 SHA `eb2c6ce`；[G3b 四服務 #91](https://github.com/IAN40070510/Mirage_API/actions/runs/45362710702) PASS，真 PG17.6 [45362724404](https://github.com/IAN40070510/Mirage_API/actions/runs/45362724404) `159 passed`，真 mTLS `5 passed`，錯 Key／跨資源／重送 fail-closed | **Read Source 隔離子項 PASS**；正式 Client HTTP／完整 4xx 仍 OPEN |
| Medusa M-02／M-07 唯讀 Validator 固定契約 200 候選 | 固定 SHA [`3230ffa`](https://github.com/IAN40070510/Mirage_API/commit/3230ffad7b8f1b3409ee6d18fc76eeeb6e6ff05c)；[真四服務 #94](https://github.com/IAN40070510/Mirage_API/actions/runs/45370736606) `success`：M-02／M-07 原生 200 候選各一筆，真 JWS／mTLS、受保護 Read Source、SHA 固定官方契約、Scope／Hash 對帳；[PG17.6 #45370745118](https://github.com/IAN40070510/Mirage_API/actions/runs/45370745118) `162 passed`、真 mTLS `5 passed`、G5 模擬 `9 passed`；容器稽核四角色／三網路／Trusted Send OFF | **兩條原生 200 候選隔離子項 PASS**；Client HTTP 200／完整 4xx、G4～G6 OPEN |
| Medusa M-01 固定空 Cart 原生建立 200 候選及非空 items 拒絕 | 固定 SHA [`cbf6009`](https://github.com/IAN40070510/Mirage_API/commit/cbf600974c282df92daba324c4a459c9419e9cef)；[四服務 #97](https://github.com/IAN40070510/Mirage_API/actions/runs/45374946964) `success`：原始 M-01 JWS／mTLS、固定 Publishable Key、Creator→Derived `protected_cart_creations`、獨立 Medusa 200 Projector、Replay 403，非空 items 503 拒絕；真 DB 確認兩個 Creation Source 均僅有 fixture／synthetic／M-01 各一筆、20/20 未簽章拒絕、容器／網路／ACL 完整稽核 PASS；[PG17.6 #45374958565](https://github.com/IAN40070510/Mirage_API/actions/runs/45374958565) `165 passed`、真 mTLS `5 passed`、G5 模擬 `9 passed`；新增 SHA [`19a1a3d`](https://github.com/IAN40070510/Mirage_API/commit/19a1a3db83ed7ed60a3490049138312716f9f444) [四服務 #101](https://github.com/IAN40070510/Mirage_API/actions/runs/45377262900) `success`：7 組輸入、6 組 Executor 503／Query 前置 403、Cart Source 不增，真角色／ACL 稽核 PASS | **固定空 Cart 200 候選及八種指定輸入拒絕隔離子項 PASS**；客戶端原生 200／4xx、非空 items 成功與完整建立欄位／故障路徑仍 OPEN |
| 正式獨立服務部署、Secret Mount／網路來源、無共享憑證可見性 | 一次性 Docker CI 真容器角色隔離 PASS | 隔離環境 PASS；staging／production 正式部署 OPEN |
| 20 條正式原生 2xx／4xx Payload 與獨立來源／Validator | 20 條均未具全套證據 | OPEN |
| G3b 整體解封並移交 G4 Sender | 前述兩項未完成 | **NO-GO** |

| 編號 | 實際方法／路由 | 來源 Proof | 固定 Executor | 2xx／4xx 完整相容簽收 |
| --- | --- | --- | --- | --- |
| I-01 | POST `/synthetic/inventory/reservations` | 隔離 PASS | 受保護 reserve；單一 Receipt Commit；真 Handler `unknown_synthetic_sku` 409 候選四服務 PASS；200 成功 Commit／獨立 Validator 候選真 PG PASS | OPEN：其他 409、CAS conflict、原生 HTTP |
| I-02 | POST `/synthetic/inventory/reservations/{reservation_id}/cancel` | 隔離 PASS | 受保護 cancel；真 Reservation 200＋重複取消 `reservation_not_active` 409 候選，SHA `6f42a51` 真 PG PASS；**I-01 真建立→I-02 版本 2→3 取消 200／重複取消 409（`deb0311`、真四服務 #88）PASS** | OPEN：CAS conflict、其他 409、原生 HTTP |
| I-03 | GET `/synthetic/operations/{attempt}` | 隔離 PASS | 固定 UUID4／空 Body Proof → ReadAdmission；獨立 Validator 核對 WorldOperation、Commit Receipt、Snapshot／Epoch／Key，重建歷史 200 或確定不存在的 409 候選；固定 SHA `88d286f` 真 PG/mTLS CI PASS | OPEN：客戶端原生 200／409、競態與故障路徑 |
| I-04 | GET `/synthetic/inventory/{sku}` | 隔離 PASS | 固定 SKU／空 Body Proof → Executor ReadAdmission → 獨立 Validator 200 成功／真正缺 SKU 409 候選；SHA `c1769b9` 原始 UTF-8、SHA `4e2cecc` 正規 percent URL 候選真 PG/mTLS PASS | OPEN：Client 原生 200／409、全 URL 相容、G4 Send |
| C-01 | POST `/synthetic/carts` | 隔離 PASS | Creator→Derived `cart_creation` 200 候選、獨立 Validator／Promotion／Creator Admission 真 PG（`f4ef309`）；真四服務實際 JWS／mTLS／Cart-only DB Role 候選 200、越權更新拒絕（`8f3aea4`、CI #68），跨 Receipt 重用鍵 fail-closed（`43d11ba`、CI #71），雙重 JSON Key／Client 偽造 Inventory 拒絕（`2fe7fb0`、CI #73），來源漂移在 Grant 拒絕 | OPEN：Client 原生 200／409、未知 COMMIT、Grant→Sender 競態、正式部署 |
| C-02 | GET `/synthetic/carts/{cart_id}` | 隔離 PASS | 受保護 ReadAdmission＋來源 ID；獨立 Validator 按派生 Cart、目前 Snapshot 重建 200 候選，真 PG 測試 PASS；C-01 真建 Cart→新 Derived Session 立刻 GET（`a79df7c`、四服務 #75）PASS；原 Creator 對 Derived ID 跨 Scope 讀取 fail-closed（`91ba701`、四服務 #77）PASS | OPEN：409 來源、其餘跨 Scope 負面、客戶端原生 HTTP |
| C-03 | POST `/synthetic/carts/{cart_id}/line-items` | 隔離 PASS | 受保護 add 200 Commit／Validator 候選真 PG PASS；真未知 Variant／庫存不足 409 候選 SHA `45b0285` 真 PG PASS；舊版本 CAS fail-closed SHA `c62c79c` 真 PG PASS；**C-01→C-02 新 Derived Cart 的四服務實體 200（`2cd34d1`、#79）＋未知 Variant 409 候選（`f414ecc`、#80）PASS** | OPEN：其餘 409／CAS 並行、原生 HTTP |
| C-04 | POST `/synthetic/carts/{cart_id}/line-items/{item_id}` | 隔離 PASS | 受保護 update；真品項 200、缺品項 409、重送與 Proof 防替換，SHA `bcb0c68` 真 PG PASS；**新 Derived Cart 真四服務版本 2→3 200 候選（`2d75dfe`、#81）PASS** | OPEN：其他 409／CAS、原生 HTTP、正式部署 |
| C-05 | DELETE `/synthetic/carts/{cart_id}/line-items/{item_id}` | 隔離 PASS | 受保護 remove；真品項 200、重複刪除 409、重送與 Proof 防替換，SHA `bcb0c68` 真 PG PASS；**同 Derived Cart 真四服務版本 3→4 200 候選（`2d75dfe`、#81）PASS** | OPEN：其他 409／CAS、原生 HTTP、正式部署 |
| C-06 | POST `/synthetic/carts/{cart_id}/complete` | 隔離 PASS | 受保護 complete 200 候選真 PG PASS；真空 Cart／已完成 Cart 409 候選 SHA `45b0285` 真 PG PASS；**新 Derived Cart 空 Cart 409（`301b784`、四服務 #83）與補品項後真 Order 200（`7b7c076`、四服務 #84）隔離 PASS** | OPEN：其他 409／CAS、原生 HTTP |
| C-07 | GET `/synthetic/orders/{order_id}` | 隔離 PASS | 獨立 Validator 按受保護派生 Order、ReadAdmission 重建 200，SHA `eb118a7` 真 PG PASS；**C-06 真生成的 Order，獨立 Resource Capability／ReadAdmission 200（`5205e2a`、四服務 #85）PASS** | OPEN：409 來源、原生 HTTP |
| C-08 | POST `/synthetic/orders/{order_id}/cancel` | 隔離 PASS | 受保護 cancel_order 200 候選真 PG PASS；真重複取消 Order 409 候選 SHA `45b0285` 真 PG PASS；**同 Derived Order 真取消版本 6→7 200（`5205e2a`、四服務 #85）PASS** | OPEN：其他 409／CAS、原生 HTTP |
| C-09 | GET `/synthetic/carts/{cart_id}/operations/{attempt}` | 隔離 PASS | 唯讀 Validator 核對歷史 WorldOperation、Protected Commit Source／Commit Receipt、ReadAdmission 與快照，重建 200 或確定不存在的 409 候選；固定 SHA `20be55a` 另修補歷史 Cart／Order 的跨 Cart ID 重綁，真 PG/mTLS CI PASS；**新 Derived Cart 真四服務歷史版本 2 200＋缺 UUIDv4 409（`fcf7f81`、#86）隔離 PASS** | OPEN：客戶端原生 200／409、競態與故障路徑 |
| M-01 | POST `/store/carts` | 隔離 PASS | 僅部署固定 USD／Email、空 items 的原始 HTTP→Executor Creator→Derived Cart、獨立 Validator Medusa 200 候選與 Promotion／Grant 再驗；`cbf6009` 真 PG 165 tests／四服務 #97 PASS，新增 `19a1a3d` 四服務 #101 確認非法 Email／幣別／額外 Inventory／重複 JSON／Idempotency-Key／錯 Key 503，Query 在 Verifier 403，非空 items 503，真 DB 不增加 Cart | OPEN：Client 200／400／404／409，非空 items、其他建立欄位與所有故障 |
| M-02 | GET `/store/carts/{id}` | 隔離 PASS | 原生 GET→Receipt／Key／Capability→ReadAdmission，`eb2c6ce` 真 PG／四服務隔離 PASS；唯讀 Validator 固定契約 Cart 200 候選 `3230ffa`、真四服務 #94／PG17.6 隔離 PASS | OPEN：Client 200／400／404／409 |
| M-03 | POST `/store/carts/{id}/line-items` | 隔離 PASS | 特定 400／404 受保護拒絕來源／獨立 Validator mTLS 封套比對 | OPEN：正式 Client HTTP 400／404、200／409、其餘拒絕情形 |
| M-04 | POST `/store/carts/{id}/line-items/{line_id}` | 隔離 PASS | 尚未執行 Native update | OPEN：200／400／404／409 |
| M-05 | DELETE `/store/carts/{id}/line-items/{line_id}` | 隔離 PASS | 尚未執行 Native delete | OPEN：200／400／404／409 |
| M-06 | POST `/store/carts/{id}/complete` | 隔離 PASS | 尚未執行 Native complete | OPEN：200／400／404／409 |
| M-07 | GET `/store/orders/{id}` | 隔離 PASS | 原生 GET→Receipt／Key／Capability→ReadAdmission，`eb2c6ce` 真 PG／四服務隔離 PASS；唯讀 Validator 固定契約 Order 200 候選（匿名 `customer_id=null`）`3230ffa`、真四服務 #94／PG17.6 隔離 PASS | OPEN：Client 200／400／404／409 |

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
4. **發送技術簽收**：在 G3b 全路由相容、實體角色／網路隔離的**可重現技術證據**
   全 PASS 且 Owner 依 [Solo Developer Security Acceptance v1](solo-developer-security-acceptance-v1.md)
   核定本 Gate 前，不得移交 G4 正式 Sender。外部人工 Reviewer 非個人專案
   一般強制條件，但獨立 Validator／受保護來源不能省略。不能把 mTLS readiness、
   200 internal RPC、PG test `passed` 當成客戶端回應授權。

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

**Medusa M-01 固定空 Cart 建立候選（2026-11-24，隔離子項 PASS；原生 Client 回應 OPEN）**：
固定程式 SHA [`cbf6009`](https://github.com/IAN40070510/Mirage_API/commit/cbf600974c282df92daba324c4a459c9419e9cef)，
[G3b 四服務 #97](https://github.com/IAN40070510/Mirage_API/actions/runs/45374946964)
`success`，日誌 `G3B_ROUTE_MEDUSA_CREATE_CANDIDATE` 記錄真原始
`POST /store/carts`、JWS／mTLS、固定 Medusa Publishable Key、原始 HTTP Fingerprint、
Creator→Derived 真 Cart Lineage、獨立唯讀 Validator 對照官方固定契約重建
`StoreCartResponse` **200 候選**，Projection `authorization_scope=creator`、
`native_validator_200=true`、`native_business_response=false`。相同 JWS 重放
403；帶非空 `items` 的不同有效 JWS 固定拒絕 503，不創造 Cart。
`G3B_CONTAINER_AUDIT_PASS` 確認四容器／三網路、專用 Secret、實際 PostgreSQL ACL，
並要求同 Creator 的兩個不可變 Cart 建立來源表均**恰有三筆**（fixture、合成
C-01、原生 M-01），`PostCarts` Proof 恰有兩筆（合法與被拒），Trusted Send OFF。
[真 PostgreSQL 17.6 #45374958565](https://github.com/IAN40070510/Mirage_API/actions/runs/45374958565)
`165 passed`、實體 mTLS `5 passed`、G5 密碼學模擬 `9 passed`；
[容器示範 #45374958555](https://github.com/IAN40070510/Mirage_API/actions/runs/45374958555)
`success`。首次功能 SHA `4d5cec1` 的[四服務 #96](https://github.com/IAN40070510/Mirage_API/actions/runs/45374532981)
在 Gateway 測得 M-01 正負案例後，因 Host audit 仍假設舊的 Proof／Cart 筆數而
`FAIL`；`cbf6009` 修正為新的精確期望值並完整重跑 #97 `success`，未跳過
ACL 或關閉驗證。**只簽固定空 Cart 200 候選與指定拒絕隔離子項**；其他
M-01 Body、原生 Client HTTP 200／4xx、未知 Commit、故障、G4～G6 都仍 OPEN。

**M-01 七種輸入繞過拒絕補驗（固定 SHA `19a1a3d`，隔離 PASS）**：
[真四服務 G3b #101](https://github.com/IAN40070510/Mirage_API/actions/runs/45377262900)
`success`，`G3B_ROUTE_MEDUSA_CREATE_INPUT_DENIED cases=7
executor_denials=6 query_pre_receipt_status=403 new_cart_source=false`。
有 JWS 的 Client 變更 Email／currency、重複 JSON 欄位、注入初始 Inventory、
自訂 Idempotency-Key、錯 Publishable Key，六種必須由 Executor fail closed
`503`。非空 Query 由 Verifier 的 `derive_verified_operation()` 在 Receipt
與 Proof 寫入**之前**拒絕 `403`；不能將此案冒充 Executor 503。
真 DB 稽核要求 `PostCarts` 只有八筆 Proof（成功一筆、非法 items 一筆、
六組 Executor 拒絕）；Query 不得憑空多寫第九筆。兩個 Cart Creation
Source 表仍只有預設 fixture、合成 C-01、M-01 成功各一筆。
[#99](https://github.com/IAN40070510/Mirage_API/actions/runs/45376539501)
及 [#100](https://github.com/IAN40070510/Mirage_API/actions/runs/45376903639)
均因測試錯誤假設 Query 必須走 Executor 503 而 `FAIL`；#100 精確記錄
Query 實際 `status=403`，#101 依既有 Verifier 前置拒絕規則修正預期並
重跑四服務及 Container／ACL 全部 `success`。這**只補輸入拒絕子項**，
不等於 Client 正式業務錯誤或全部 Medusa 功能已通過。

**Medusa M-02／M-07 原生 GET 的受保護讀取來源（2026-11-24，隔離 PASS；原生 200 OPEN）**：
固定修正 SHA [`eb2c6ce`](https://github.com/IAN40070510/Mirage_API/commit/eb2c6ce71daeeb8e8352825b71acc6c2661c6ffb)
在[真四服務 G3b #91](https://github.com/IAN40070510/Mirage_API/actions/runs/45362710702)
`success`，依序測得真 Cart／Order ID 經原始 HTTPS、JWS、獨立 mTLS
Verifier→Executor、精確 Publishable Key、原始 Fingerprint 與派生 Capability
建立 `protected_world_read_sources`。日誌包含 `G3B_ROUTE_MEDUSA_CART_READ_SOURCE`
及 `G3B_ROUTE_MEDUSA_ORDER_READ_SOURCE` 各一筆，錯誤 Key 固定 503，JWS
Replay 403，`G3B_CONTAINER_AUDIT_PASS` 證明四服務／三網路／權限隔離。
[PG17.6 合約 CI 45362724404](https://github.com/IAN40070510/Mirage_API/actions/runs/45362724404)
`159 passed`、真 mTLS `5 passed`、G5 密碼學模擬 `9 passed`；
[容器示範 45362724685](https://github.com/IAN40070510/Mirage_API/actions/runs/45362724685)
`success`。首次 SHA `b9b0388` PG 測試曾 `1 failed / 158 passed`：把同
Receipt 再次 ReadAdmission 誤寫成必須回傳相同 Metadata；不變來源唯一約束
正確拒絕第二次寫入。修正測試要求第二次固定 503，沒有放寬資料庫唯一約束；
於上述新 SHA 全數驗證成功。此固定 SHA 的**既有證據只有 ReadAdmission Metadata**。
後續唯讀 Medusa 200 JSON Validator 已在固定 SHA
[`3230ffa`](https://github.com/IAN40070510/Mirage_API/commit/3230ffad7b8f1b3409ee6d18fc76eeeb6e6ff05c)
完成實驗室增量：[真四服務 #94](https://github.com/IAN40070510/Mirage_API/actions/runs/45370736606)
`success`，同一 Derived Cart／Order 的真原始 HTTP、JWS、mTLS、ReadAdmission
及唯讀 Validator 均取得正式 Medusa 契約 200 JSON 候選，`native_validator_200=true`，
來源 ID／Resource／Version／State Hash／Scope／Envelope Hash 逐欄對帳，
外層仍只有內部對帳 200，`native_business_response=false`；真 PG17.6
[45370745118](https://github.com/IAN40070510/Mirage_API/actions/runs/45370745118)
`162 passed`、實體 mTLS `5 passed`、G5 模擬 `9 passed`。獨立契約
SHA-256 錯誤、缺固定來源、跨資源／跨 Scope、RPC 偽造 `send_authorized`
均不得 Promotion。首次實作 SHA `6aad9b4` 的四服務 #93 在第一筆 Inventory
遇到內部 503，依啟動時間推定 Verifier Ready 早於其他角色準備完成；新 SHA 以全四角色 TLS
Listener 啟動屏障後，#94 從第一筆可信 Commit 到 M-02／M-07 候選全程通過，
且 `G3B_CONTAINER_AUDIT_PASS` 證明四服務／三網／角色 ACL 與 Trusted Send OFF。
**這只簽 M-02／M-07「200 候選隔離子項」，Client 原生 HTTP／完整 4xx／
ACK／CAS／G4～G6 仍 OPEN，不能當成全路由 Release 簽核。**

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
