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

| G3b 子門檻 | 獨立實測結果 | 正式簽收 |
| --- | --- | --- |
| 真 HTTPS Gateway→Verifier→Executor、互異 Client CA、拒絕重播／竄改 | 隔離 CI PASS | 僅實驗室傳輸子項 PASS |
| 三個實體 PostgreSQL SCRAM Login、無跨角色 DML／SET ROLE | 隔離 CI PASS | 僅實驗室 ACL 子項 PASS |
| 20 路由 Method／Path Template／Operation ID 與三份固定規格集合同步 | 靜態 Mapping PASS，真容器 HTTPS 入口缺 JWS 的 20/20 逐路由 403 PASS | 隔離入口拒絕子項 PASS；每條合法 JWS、原生 2xx／業務 4xx 仍 OPEN |
| 可配置的隔離 Verifier／雙 Executor／Native Validator、專用 DSN Secret、Role／Schema／ACL 啟動檢查 | 真四容器啟動／實體角色／mTLS／密鑰用途 PASS | 隔離部署子項 PASS；正式環境另驗 |
| Medusa M-03 特定 400／404 的原生 JSON 從獨立 Rejection Source 重建 | 真 PG、唯讀 Validator 來源投影、第二 mTLS CA PASS | 實驗室子項 PASS；正式 Client HTTP 回應與全操作兼容 OPEN |
| Medusa M-03 Validator→Verifier 完整候選 Status／Headers／Body 交接 | 固定 400／404 bytes／Scope 綁定及篡改拒絕；真四容器 CI [45211431898](https://github.com/IAN40070510/Mirage_API/actions/runs/45211431898) PASS | **候選交接隔離 PASS**；外層仍為內部 HTTP 200、正式 Client 400／404 OPEN |
| Synthetic 固定 mutation Handler rejected→可信 409 來源→獨立 Validator | I-01／I-02、C-03～C-06、C-08 固定 409 候選能力；隔離四服務實測 I-01 `unknown_synthetic_sku` 409 來源、Body 與重播拒絕 PASS | **I-01 指定拒絕候選 PASS**；其餘 Handler 情境／CAS conflict／原生 HTTP 仍 OPEN |
| Inventory I-04 GET Rea