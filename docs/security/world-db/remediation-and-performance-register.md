# MIR-SEC-WORLD-001 — 安全修復、整合阻礙與 HTTP 效能總表

> **文件性質**：跨輪討論的可追溯工作清單；不取代 [ADR](../../adr/MIR-SEC-WORLD-001-world-db-trust-boundary.md)、[決策紀錄](decisions-log.md)、[實作 Runbook](implementation-runbook.md) 或 [Verification Plan](verification-plan.md)。
>
> **整理日期**：2026-11-22（臺北時間）。**整合基準**：遠端文件分支 `docs/mir-sec-world-001-http-latency-baseline`、提交 `80eb37c6e2a13530cfd96bcfe89634450bc6ed5f`。本總表存於另一獨立文件分支；基準 SHA 不是 Mirage upstream main、MSDSS Protocol baseline，也不是本文件提交後的 SHA。
>
> **結論**：`MIR-SEC-WORLD-001 = OPEN`；`MSDSS P2 = NO-GO`；正式 Trusted Send／production DECEIVE **OFF**；未經安全驗收與核准不得啟用。獨立分支已有部分原生程式和隔離 Lab 測試，但**完整的受保護權限、真正的 HTTP 傳輸／Restore 閘門及端到端效能都未驗收**。

## 1. 範圍、優先次序及證據標記

- **使用者需求優先次序**：① 回應功能有效、資料與世界狀態正確；② 使用者感受到的速度與可用性；③ 在前兩者之上繼續強化安全性。**既定 Release Gate 不得因優化速度而跳過**，例如未授權發送、恢復未知 COMMIT 後盲目重試、Restore 隔離失效。
- **已採納架構**：資料庫強制關鍵狀態轉移（方案 B）；Mirage Owner 採納 **MSDSS Protocol Freeze v1**（D-68）；同一 Oracle 主機上獨立 Verifier／Authorizer 容器、OS 身分、SCRAM Role、Secret、DSN、Pool（D-69）；**Candidate Clean Cutover**，保留生成器，淘汰舊 Candidate 直接取得可信授權的入口（D-70）。另外 [Restore Anchor Option B](restore-anchor-option-b.md) 已核准獨立還原域；[BD-11](bd-11-deadline-semantics.md) 已選擇鎖後 DB 權威時間判定；[BD-05](bd-05-restore-quarantine-release.md) 已正式採納證據自動驗證解禁。
- **已明確要求的方向**：Fence 必須真正置於 World DB 備份／還原範圍之外；Send、Purge、Restore 走不能繞過的受保護閘門；全部證據正常時**自動解除 Quarantine，無需每次雙人或人工核准**；異常持續隔離，由人工修復後重跑驗證，**不得人工覆蓋失敗結果放行**。這是已採納的目標安全合約，不是現有部署完成證據。
- **威脅範圍**：R1（Runtime DB 憑證與全部該身分 SQL 能力）必須抵抗；R2（取得同等 SQL 能力的 SQLi）納入 R1；R3（合法 Verifier API 濫用／部分秘密）按能力負面測試。R4（完整 HTTP Runtime 程序控制並自行 ASGI send）、R5（主機 root／Docker daemon／PG superuser）**不宣稱本輪完整防護**。

| 標籤 | 精確意義 |
| --- | --- |
| **已重現** | 先前 MSDSS PR #23 的 PostgreSQL 缺口驗收報告有明確證據；本文件未重新執行。 |
| **已觀察** | 指定來源版本的程式／交易結構或本地檔案直接可見。 |
| **局部 PASS** | 特定隔離 PostgreSQL／CI 子案例通過；**不得擴寫成整體 Gate PASS**。 |
| **待實作** | ADR／修補方向已定，但關鍵接線、Migration、部署或閘門尚未完成。 |
| **NOT_RUN** | 無符合目前完整驗收條件的端到端或故障注入證據；文件檢查不算安全測試。 |
| **提議** | 需要量測或依 D-73 由 Owner 承擔 DBA／Security 責任完成定量裁決，不是已核准設定。 |

## 2. 原始已確認安全控制缺口

唯一沿用的正式問題編號為 **`MIR-SEC-WORLD-001`**（MSDSS `P2` 是另一專案的驗收代號，不得重複充當漏洞 ID）。MSDSS [Draft PR #23](https://github.com/IAN40070510/MSDSS/pull/23) 記錄 PostgreSQL 17.6 **13／13 符合測試預期**，其中三項是**成功重現缺口**，不是修復 PASS。

| 缺口 | 已觀察／報告能力 | 修復不變量 | 關閉前必有證據 |
| --- | --- | --- | --- |
| **SEC-01 發送授權** | Runtime DB 角色可直接把 Admission 改成 `SEND_AUTHORIZED` | Runtime 不能直寫授權結果；只能由受保護 Authorizer 在合法交易中轉移 | 真 SCRAM Runtime `42501` 或等價拒絕；正常 Grant／Authorize 流程完整 PASS |
| **SEC-02 Session epoch** | Runtime DB 角色可直接倒退 epoch | Epoch／Session Head 只能依可信意圖、Scope、版本及原子切換更新，不能只以 `new >= old` 判斷 | 不合法倒退／跳世代／錯誤 Session 更新遭拒；合法切換不回歸 |
| **SEC-03 Replay Tombstone** | Runtime DB 角色可提前刪除未過期 JTI | Replay 消費記錄不可在有效窗口內被清除，受限 GC 不得誤刪被 Receipt／對帳引用的證據 | 越權 `DELETE` 拒絕、保留窗口與 Restore／並行 GC 驗收 |

**風險分界**：目前已確認的是「持有 Runtime DB 權限者能繞過部分 DB 安全狀態機」；**尚無證據**證實匿名 HTTP 訪客能直接利用，也不能據此逕定 Critical 或宣稱 R4/R5 已受保護。

## 3. 延伸安全與整合問題：根因、解法、驗收

下表的 `SEC-04` 等是**工作項目**，不自動表示已找到另一個可獨立利用的漏洞。

| 項目／問題 | 目前風險或事實 | 已選或建議解法 | 最低驗收／狀態 |
| --- | --- | --- | --- |
| **SEC-04 可信 Ingress 來源** | Runtime 的 `domain_validation='passed'`、`contract_validation='passed'` 和單獨 Replay 記錄都不是獨立驗章證據 | 獨立 Verifier 自行驗 JWS、issuer/audience、環境、Session、fingerprint、時間與撤銷；受限 Role 寫不可偽造 Receipt | 假 claims、錯誤 JWS、Runtime 假 Receipt、Role 濫用拒絕；**部分 IngressTx Lab PASS，整體待實作** |
| **SEC-05 Request provenance 侷限** | Runtime 可構造自己提交的 request snapshot；JWS 與該快照吻合不等於快照來自實際 HTTP 入口 | 本輪採 **語意 A**：僅證明 JWS 與提交資料相符；若未來承諾真實入口來源，另採 Gateway 簽章／可信入口證據（語意 B） | `WORLD-FP-01A/01B` 分別檢查 mismatch 與來源冒稱；**不得過度聲稱 R4 防護** |
| **SEC-06 DB Role 與 Secret 隔離** | 既有 `trusted_http.create_app()` 共用 `postgres_dsn`；同池 `SET ROLE`、Secret 掛載、角色 membership 可摧毀信任邊界 | Runtime／Verifier／Authorizer／GC 分獨立容器、OS 使用者、SCRAM、DSN、Pool；禁止 Runtime 成為特權 Role 成員，受限函式撤銷 `PUBLIC EXECUTE` | 真實部署 Mount、`pg_hba.conf`、`pg_auth_members`、`SET ROLE`、有效 ACL／Function 權限；**隔離 Lab 子測 PASS，正式部署 NOT_RUN** |
| **SEC-07 `IngressTx` 原子性** | Key Guard、Replay 與 Receipt 若拆不同 physical connection，會產生部分提交 | 同一 PostgreSQL database／connection／transaction 內 guard、消費 JTI、建立 Receipt；僅協調器 commit/rollback | 明確 rollback 雙方不可見；ACK loss 進 `UNVERIFIABLE`；**隔離 Lab 局部 PASS，未知 COMMIT 對帳未完成** |
| **SEC-08 一次性 Evidence／Grant Binding** | JTI 消費可被誤當授權；Receipt 有被跨 Candidate／Session／Generation 挪用風險 | Ingress Receipt 固定 claims/request intent；之後 `GrantTx` **不重建 Receipt**，一次性綁定已 Promotion Candidate、完整 Scope／Version／Envelope Hash、Generation 及 Admission，DB FK／UNIQUE／行鎖強制 | 同 Receipt 並行兩 Candidate 最多一個成功；Binding＋Admission 原子、跨 Scope 拒絕；**待實作** |
| **SEC-09 Candidate 舊授權入口** | 舊 `candidate_records → grant()` 可繞過新可信 Promotion 合約 | **Clean Cutover**：保留商品、Cart/Inventory、Medusa 生成器；提交仍為低信任，Validator 核對內容和 Policy，短交易 Promotion；舊路徑不能作降級回退 | 嘗試偽造可信欄位、Promotion 中斷、版本替換與正常商城業務回歸；**待實作** |
| **SEC-10 Candidate／Snapshot 不可變性** | 只保留 Hash 或 FK 不足以防授權後替換 bytes；Candidate GC 若共用底層 Blob 可能誤刪 Snapshot | Authorized Snapshot 有獨立 id/version/storage object 與 Pin；`SEND_AUTHORIZED` 綁定的是真實 Snapshot；發送前核對 Envelope v1 的 status/headers/body | 修改 bytes、錯 Scope、Middleware 改寫、共用 Blob GC、Snapshot 不可用均安全拒絕；**待實作** |
| **SEC-11 Freeze v1 授權時間線** | 既有 Mirage `start_send()` 曾在授權後重新讀 Policy／Emergency；與 Freeze v1 的唯一授權線性化點有局部差異 | `SEND_AUTHORIZED` COMMIT 是最終授權；`StartSend` 只查 owner、deadline、single-use、Snapshot 的真實執行前置條件，**不創造第二次 Policy／Emergency 授權** | 既有原生調整回歸有 CI PASS；**完整 Freeze 矩陣符合性 NOT_RUN** |
| **SEC-12 Fence → HTTP 傳輸空窗** | **最嚴重的待整合風險之一**：`StartSend` 通過獨立 Fence，不表示隨後 ASGI 的 `response.start/body` 或實際 Socket 傳輸仍受 Fence 保護 | 所有 Send 路徑都只能取得受保護 `StartSend`／執行租約後發送；Purge／Restore 與該租約、活躍傳送、不可逆 Fence 共用**可驗證的並行協定**；不可假裝 HTTP 網路 I/O 能放進單一 PG 交易 | StartSend 與 Purge／Restore 並行、發送中 Quarantine、崩潰、未知 ACK、已送部分 bytes 的故障注入；**NOT_RUN** |
| **SEC-13 Purge 與 GC 混淆** | Candidate 原 payload Purged 不代表已授權 Snapshot 不可送；以 Purge 充當第二次撤銷會破壞 Freeze | `CandidatePayloadPurgeFence` 與 `AuthorizedSnapshotPurgeFence` 分開；後者不可逆地使 Snapshot **失去執行資格**，但不改寫既有 Admission 授權結果；GC 失敗只冪等重試 | Candidate 清理後完整 Snapshot 可用、Snapshot fence 後永久禁用、GC failure 不復活；**NOT_RUN** |
| **SEC-14 Restore／跨資料庫 Fence** | World DB 還原會回退 Replay、Binding、Tombstone；同一 DB 的 Fence／hash chain 也能一起倒退；Fence head 發布與 World commit 無原子性 | **已核准 Option B／BD-05**：獨立持久化 Fence authority／最高可信 Head；單調世代、涵蓋 digest、DB timeline／position 與 publication status。DB-first／Anchor-first／未知 ACK 一律對帳，不能證明就 Quarantine；證據全部 PASS 才能自動解禁 | 舊備份、Head 下降、Anchor 發布失敗、跨 DB COMMIT 未知、同時 Send/Purge、機器判定與無人工 bypass；**NOT_RUN／部署未完成** |
| **SEC-15 COMMIT 未知、外部副作用與 HTTP at-most-once** | 查無 Receipt 不是 rollback；World Mutation 已成功、Admission 失敗或已 `SEND_STARTED` 但程序失聯不能盲目重做 | 持久化 Operation ID＋input digest＋唯讀對帳；`UNVERIFIABLE` 不因等待超時自動改成功／失敗；World 成功但回應不可用屬 reconciliation classification；HTTP 不承諾 exactly-once delivery | pre/post-COMMIT fault、ACK loss、外部 effect 重試、`SEND_STARTED` 斷線；**對帳完整路徑 NOT_RUN** |
| **SEC-16 鎖序、配額與混合版本** | Profile advisory、Generation row lock、FK、GC、Emergency 可能有循環；新舊程式／鎖鍵共存可造成競態，Runtime 佔滿連線可阻礙 Emergency | 固定既有鎖鍵契約，產生含隱含 FK lock 的 DAG；交易級 advisory lock；角色連線上限、timeout、保留管理配額；不相容 Runtime 由 Preflight 拒絕，必要時停流升級 | `deadlock_detected`／`serialization_failure`、池角色不串用、鎖等待、混合版本和 Emergency 連線壓力；**未完整驗證** |

### `StartSend` 與實際 HTTP 傳輸的強制邊界

不得宣稱「取得一次 Fence PASS」即可保護之後任意長的傳輸。應依 D-73 由 Owner 承擔 DBA／Security 技術責任、取得可重現證據並審定以下短交易與傳輸契約（**待實作與驗收**）：

1. 受保護 `StartSendTx` 以同一個權威 Fence Head／Snapshot eligibility 證據、可信 Owner、不可延長的期限及 single-use 條件原子建立 `SEND_STARTED`，同時取得不可重複的**傳輸租約或等價 Pin**。
2. 交易結果確認後，ASGI 只能送出該租約綁定的 immutable Snapshot；**第一個 byte 送出前**發現中介層修改 bytes／status／headers 必須阻擋並稽核；**已部分送出後**則記錄 partial／unknown、按核准規則終止，不得假裝能撤回網路資料。**不能把持久化 `SEND_STARTED` 當成客戶端收到資料**。
3. Snapshot Purge 不得刪除仍有合法活躍 Sender 依賴的 bytes；Restore 必須先建立外部 durable Quarantine Fence，阻止**新的**起送，並等候、取消或按明確政策處置既有傳輸。已開始的網路傳輸無法靠 DB rollback 撤銷。
4. 任何異步／重啟／故障路徑均不可繞過取得租約。對已部分送出或未知結果，不自動建立新的 Admission、租約或重新發送。
5. 這只能證明**受控原生 Sender** 遵循協定；不能宣稱 R4「惡意控制整個 Runtime 並自行送出」也會被 DB ACL 阻止。

## 4. 速度、有效性與可用性問題

**產品風險**：使用者若經常等待數秒，可能放棄使用、排斥或把反常延遲當成環境異常。對 Mirage 而言，速度關係到**回應有效性與可信體驗**，不只是成本優化。

### 唯一已量測的速度證據

參見 [HTTP latency baseline](http-latency-baseline.md) 的 2026-11-22 隔離 PostgreSQL 17.6 微基準：單客戶端 `SELECT 1`、容器 Unix socket；重用連線平均 **0.162 ms**、每交易重連平均 **4.787 ms**，相差約 **29.5 倍**。這只說明連線開銷，**不代表完整 HTTP 速度或總體加速比例**。

**目前不存在**可信的完整 Trusted HTTP `P50/P95/P99`、TTFB、body complete、並行吞吐量，且正式發送 Release Fuse 仍禁用。模型生成上限範例可達 120 秒但範例設定 `enabled: false`，**不是目前實際回應時間**。

| 效能工作項目 | 現有問題／假設 | 解法與限制 | 驗收 |
| --- | --- | --- | --- |
| **PERF-01 缺少端到端基準** | 尚不能確定 AI、反覆連線、查庫、鎖競爭、ASGI 哪個真正最慢 | 先加入匿名分段 trace；記錄 Ingress、World、Generator、Grant、Fence、ASGI send、finish、pool wait、lock wait；分 cold/warm/cache hit | 隔離 1／10／50 concurrency；分別輸出 P50/P95/P99、TTFB、完整 body、錯誤率、有效回應率 |
| **PERF-02 DB 連線 churn／同步阻塞** | 多個 `psycopg.connect()` 可能每階段重連；同步 DB 在 async handler 中可能阻塞 event loop | 按 Role 隔離 **bounded pool**，不能共池 `SET ROLE`；短交易內重用 connection；必要時採受控 async／executor；量測而非預估加速 | 每 Role pool acquire/queue、conn 數、DB round trips、event-loop lag、P95/P99、Error/Deadlock |
| **PERF-03 每請求 AI 即時生成** | 冷模型、長生成、重試／repair 可能讓正常 HTTP 等數秒到數十秒 | 提前生成可重用的商品／Cart／Medusa 情境素材；Validation／Promotion 後儲存可信 Candidate；HTTP 快路徑只做 Scope 綁定、授權、Snapshot 與 Fence；真正 cache-miss 另外訂 SLO | cache hit/miss、品質／世界一致性、模型 cold/warm、token 數、拒絕率與延遲分布；不得跨 Session／Generation 重用授權 |
| **PERF-04 慢操作拖累快操作** | 模型推論與 DB／HTTP 共用阻塞執行資源，可能造成 head-of-line blocking | 將模型工作與 HTTP 熱路徑分流；有限度背景佇列／回壓／併發上限；資料庫控制面保留容量 | 50-concurrency 下常見請求的 P95/P99 不因長模型工作失控；Emergency／Quarantine 操作仍能登入 |
| **PERF-05 快速失敗的品質邊界** | 一味追求時限可能把有效請求變成 503，或採用錯 Scope／未授權的快取 | **SLO 不是安全截止期限**；內容與 Session 不可憑速度退化，無合法 Snapshot 時 Fail-Closed 而非回到舊 Candidate／跳過 Fence；同時計算錯誤與有效回應率 | 在 P95 達標時，正向業務結果、Scope、Envelope Hash、Replay、安全拒絕與 Audit 均通過 |

### 建議而非既定的效能 SLO

| 類別 | 目標（待實測／審查） | 說明 |
| --- | --- | --- |
| **預先生成／有效 Snapshot 的快路徑** | `P50 ≤ 150 ms`、`P95 ≤ 400 ms`、`P99 ≤ 1,000 ms` | 這是**討論中提出的產品目標**，不是現有實測或 Owner 已正式核准的 Release SLO；以同地區、相同網路與負載條件比較正常 API |
| **需要即時模型生成** | **PENDING BASELINE** | 不將即時推論耗時混入純快路徑 SLO；先實測模型與硬體，再決定可接受時間、回壓及業務處置 |
| **完整請求有效率** | **PENDING POLICY** | 除延遲外需單獨記成功、拒絕、未知結果、錯誤與正確 World 狀態，防止「全回錯誤但跑很快」取得假 PASS |

**效能優化不能暗中變更**：MSDSS Freeze v1、受保護 Admission、Replay single-use、Operation Recovery、真正獨立 Fence、Snapshot／Purge 資格、Restore Quarantine 或正式 Trusted Send 的禁用控制。

## 5. 修補順序與依賴（對照現行 G0～G6）

| 優先 | 工作與前置 | 完成判準／責任 | 本輪判定 |
| --- | --- | --- | --- |
| **P0 / G0** | 固定 affected SHA、確認三項 SQL 缺口與正常功能基準、建立隔離 DB；敏感 PoC 不公開擴散 | Mirage Owner／Security 保存固定版本與負面重現；未修補前保持 release fuse | **先前已重現；整體 G0 仍不應推定 PASS** |
| **P0 / G1–G2** | 正式 Verifier/Authorizer Role、Secret/來源隔離；可信 IngressTx Receipt、Replay 同交易 | 真實容器 Secret/Role/ACL，交易故障與跨 request 綁定測試 | **局部隔離 Lab PASS，正式接線未完** |
| **P0 / G3** | Candidate Clean Cutover、Validator/Promotion、Grant Binding、Session/Admission 受保護函式、禁止舊 Runtime DML | 三項原 SQL 越權必遭拒；新正常商城交易可用；未知 COMMIT 不重做 | **待實作／整體 NOT_RUN** |
| **P0 / G4** | 獨立 Snapshot 物件與 Pin、兩種 Purge Fence、所有發送路徑接強制 StartSend/Lease/ASGI 邊界 | Payload 替換、Purge/GC/Send 並行、Partial/Unknown HTTP fault 驗收 | **Audit INSERT 回滾／Lease non-retryable 真 PG 子項 PASS（SHA `4be3992`）；整體 NOT_RUN** |
| **P0 / G5** | 外部耐久 Fence/Highest Head、DB-first／Anchor-first 對帳、Restore Quarantine 與自動解禁證據 | 還原、故障、跨 DB commit 未知不得放行；人工修復不等於人工猜測已安全 | **簽章鏈 9 項 CI、Lab 真 pg_dump/restore 落後檢出子項 PASS；部署與完整故障注入未完** |
| **P1 / G6** | 全契約 Freeze v1、Mixed Binary、Migration rollback、真實 PostgreSQL 負面／正向及效能分段測試 | 固定 commit、DB/schema、SQLSTATE、JUnit、fault logs；依 [Solo Developer Security Acceptance v1](solo-developer-security-acceptance-v1.md) 由 Owner 逐項核對、最終核准，外部人工審查建議但非強制 | **完整安全驗收 NOT_RUN** |
| **P1 / PERF** | 計時 → 健康負載基準 → Role-bounded pool → 預先生成／推論分流 → 再測量 | 有效回應率與 P50/P95/P99 同時驗收；不影響 P0 Gate | **僅連線微基準 MEASURED，HTTP NOT_RUN** |

### 不得當作已完成的證據

- 原 SQL 13／13 PASS 內含三項**漏洞重現**；不代表安全弱點關閉。
- 既有 Freeze v1 原生修補曾有 [GitHub CI 1,260 passed／21 skipped](https://github.com/IAN40070510/Mirage_API/actions/runs/44847829807)，只涵蓋該提交的原生回歸。
- Oracle ARM64 隔離 Lab 已驗證 **SCRAM Runtime/Verifier Role 的部分 `42501` 拒絕**、Key/Replay/Ingress Receipt 在同交易的部分正／負案例；詳見 [Runbook 的固定 Job IDs](implementation-runbook.md)。**不能推論正式角色已部署、所有受限函式已完工或 R1 整體安全性已通過**。
- 文件 checker PASS、`WORLD-*` ID 唯一、Git diff 格式通過都**不是**安全或效能驗收 PASS。

## 6. 開放決策、阻斷條件與禁止捷徑

| 主題 | 已決定／預設 | 尚待驗證或核可 |
| --- | --- | --- |
| Freeze v1 | **Mirage Owner 已採納**；`SEND_AUTHORIZED` 不受授權後 Policy／Emergency 二次改判 | 完整 native conformance、競態及外部發送證明 |
| [BD-05 / Restore](bd-05-restore-quarantine-release.md) | **ADOPTED**：獨立 Anchor、缺證據隔離、全證據 PASS 自動解禁；人工只能修復並重新驗證，不能憑人為簽章繞過失敗 | 最高可信 Head／發布連續性、完整涵蓋、Retention、跨 DB unknown ACK、競態 release test 和正式部署 **NOT_RUN**；舊的雙人核准／單一 Operator Certificate 不再是放行條件 |
| [BD-11 / 時間](bd-11-deadline-semantics.md) | **DECIDED，未實作／未驗收**：拿到必要鎖後一次 PostgreSQL `clock_timestamp()` 判斷 eligibility；未到期可在期限後 COMMIT，成功 COMMIT 是授權線性化點；`StartSend` 另核對執行期限 | 含跨 Deadline commit、逾期判定及 ACK 遺失的 PG 交易測試；未知結果照 Operation ID 對帳，不重試、不開送 |
| Performance SLO | 快路徑建議 150/400/1,000 ms；速度與有效回應率同時評估 | 必須先量測完整安全路徑，Owner 才能採用量化門檻與負載模型 |
| R4/R5 | R1/R2 是本輪主要授權邊界，R4/R5 不得被冒稱已抵抗 | 若要抵抗遭完整接管的 HTTP Runtime 自行 send，需另議獨立 Sender／信任根 |

**嚴禁以這些捷徑收斂**：Runtime 自宣告 `verified=true`、`domain_validation=passed`；只見 Replay Tombstone 即承認已驗章；不知道 COMMIT 結果就逾時重試；用新的 JWS 重做未知的 World Mutation；新流程故障時改回舊 Candidate `grant()`；只憑 Fence 在 StartSend 當下通過就宣稱其後所有 bytes 安全；把任何單次 DB microbenchmark 說成全站 HTTP 性能；以 CI 全綠關閉 MIR-SEC-WORLD-001。

## 7. 結案條件及持續維護

`MIR-SEC-WORLD-001` 只能在下列條件全部達成後由授權審核者評估關閉：

1. **實作證據**：正式 Runtime 無關鍵直接 DML；Verifier → Receipt → Promotion → Binding → Admission → immutable Snapshot → StartSend 的真實受保護路徑可運作，並保留 World 合法交易功能。
2. **傳輸與還原**：Fence 不在 World DB 同一還原範圍；Send、Purge、Restore 全呼叫路徑無旁路；跨資料庫提交未知與真實 HTTP 部分傳輸均完成故障注入與對帳。
3. **安全測試證據**：PG 17 實體權限／SQLSTATE、角色與 Secret、並行鎖 DAG、policy race、rollback/unknown commit、Snapshot GC／Purge、Restore／舊備份、Mixed Binary、現有正常功能皆 PASS；每項 PASS 有版本、Migration、環境、測資、時間與脫敏 log。
4. **效能與品質**：拿到完整安全路徑的 HTTP P50/P95/P99／TTFB／錯誤率／有效回應率後優化並驗證；不能讓「降低檢查數量」成為性能改善手段。實際量化門檻需 Owner 採納。
5. **流程與發布**：採用 [Solo Developer Security Acceptance v1](solo-developer-security-acceptance-v1.md)：由 Owner 承擔 DBA／Security／Release 的審查責任，完成所有技術證據後對精確版本及環境單獨核准；外部人工 Reviewer 非個人專案一般強制門檻，但不得冒稱獨立第三方已審查。MSDSS P2 的獨立服務驗收不由本文件豁免。**在技術 Gate 全 PASS 且 Owner 另作特定 Release 核准之前，維持 Draft／獨立分支、production DECEIVE OFF，不合併 main 或擴張到共享 staging。**

本檔僅整合**目前可追溯的討論、固定來源與修補證據**；出現新問題須記錄日期、Work Item ID、affected source SHA、修復方案、實測結果及殘餘風險，並同步更新 [Decisions Log](decisions-log.md) 與 [Verification Plan](verification-plan.md)。不可因新增文字就把 `NOT_RUN` 改成 `PASS`。
