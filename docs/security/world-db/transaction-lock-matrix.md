# MIR-SEC-WORLD-001 — 交易、鎖與錯誤契約

**v0.1／Proposed／OPEN**。目的：避免把「單一安全狀態轉移交易」誤寫成「整個請求單一交易」，以及防止為了新增 Epoch／Key Freshness 而引入死鎖。本矩陣的**現有路徑**來自 Mirage `main` `88dc2008fd35a2d3873949a769653dc9f18e8980`；**目標交易**仍待實作及測試。

## 1. 現有鎖證據與循環風險

| 現有操作 | 已觀察主要資源順序 | 目前語意／待補事項 |
| --- | --- | --- |
| `PostgresSessionWorlds._resolve_in_transaction` | `session_heads FOR UPDATE` → 舊 `generation_controls UPDATE` → Session Binding／World Snapshot | Epoch cutover 會封存舊世代；有時新 Generation 初始化 |
| `PostgresSessionWorlds.admit_read` | `session_heads FOR SHARE` → `session_world_bindings FOR UPDATE` → `generation_controls FOR SHARE` → snapshot share | 檢查 Head／Generation／Snapshot 與 watermark |
| `PostgresAdmissionControl.grant` | `generation_controls FOR UPDATE` → Projection Registry 受保護操作 → 新 Admission INSERT | 已有單交易 Grant，但依賴 Runtime 提供的 observation，沒有擬議可信 Receipt+Binding |
| `claim`／`authorize_send`／`start_send` | `response_admissions FOR UPDATE` → `generation_controls FOR UPDATE` → Profile 受保護檢查／advisory guard | StartSend 有 owner／deadline／emergency；**沒有完整 Head／Key Receipt 鏈** |
| `KeyRevocationRegistry.guard/revoke` | 相同 `(environment,deployment,issuer,kid)` 的 transaction advisory lock → Tombstone read/write | 需與 StartSend 的 Key Lock 共同定義順序與 `READ COMMITTED` 查核 |
| Profile Revocation | Profile namespace 的 transaction advisory lock、受保護狀態讀寫 | 需與 Admission／Generation／Session 交互動態查核，沿用現有鍵演算法 |

**潛在循環示例（不是已重現的死鎖）**：

```text
Tx A (新增 Session 檢查若排在既有 StartSend 鎖後)：
  Admission → Generation ─等待→ Session Head

Tx B (Session epoch rollover)：
  Session Head ─等待→ Generation

=> Generation ↔ Session Head 形成可能循環。
```

不能只在既有 `_lock_admission()` 結尾加 `SELECT session_heads ... FOR SHARE`。**實作前必須產生涵蓋全部操作的鎖 DAG，且真實 PostgreSQL 以雙／多連線注入阻塞測試。** 鎖順序改變應同步檢查 Legacy／新版混跑；沿用現有 Profile／Key 64-bit extended-hash namespace，若變更鍵演算法須停流排空所有舊連線後切換。

## 2. 目標交易責任與失敗語意

| 目標操作 | 單一交易必須原子完成 | 鎖／時間義務 | 失敗結果 |
| --- | --- | --- | --- |
| **IngressTx** | Trusted Verifier 驗證後，JTI 唯一 INSERT＋Ingress Receipt INSERT | Key Revocation guard 與 JWS 核對必須有一致的線性化規則；同一 DB、同一 physical connection | 明確 rollback：兩者都不可見；未知 commit：保留 UNVERIFIABLE，不重新消費同 JTI |
| **GrantTx** | 鎖 Receipt、Candidate；核對 scope／完整 Envelope hash／Projection／session／generation／deadline；Binding UNIQUE＋Admission INSERT 同交易 | 必須定義 Receipt→Candidate→Head→Generation 等實際總鎖序，不可與舊交易相反 | 任一檢查失敗整筆 rollback；JTI 已消費事實不回復 |
| **AuthorizeTx** | 將同一 Admission 由 CLAIMED 升 SEND_AUTHORIZED；核對同一 Receipt／Binding、目前 Key／Profile／Epoch／Generation／期限 | 所有動態檢查與改寫在相容鎖及當前 DB Snapshot 內；使用 DB 實際檢查時間 | 業務拒絕不可用同 Operation 盲目重授權 |
| **StartSendTx** | owner、原 hash、Receipt／Key／Head／Profile／Generation、deadline 重查；唯一進入 SEND_STARTED 並記錄送出起點 | 與 Revocation／Epoch cutover 對同一 Scope 有可證明勝負順序 | 已撤銷／失配／逾時：拒絕；不能假設已開始的 bytes 可撤回 |
| **PreSendAbandonTx** | 尚未 Start 的 Admission 狀態從 SEND_AUTHORIZED → ABANDONED；不可改 hash；安全 Audit `CONTENT_MISMATCH` 同交易 | 受限函式核 owner／state；不得將假 send_started 記入普通 Response Audit | 已 SEND_STARTED 必須拒絕此「未開始」語意 |
| **ReplayGcTx** | 只刪除證明已超過所有安全保留／對帳窗口之舊墓碑 | 特權 GC 身分；與 Ingress／Restore 具有一致性界限 | 無法證明過期則保留／Fail-Closed，不因壓力提前刪除 |
| **Recovery** | 唯讀讀取 Operation Receipt 與業務 Commit Result；不改寫未知歷史 | 必須辨識 commit ack loss、still in-flight、DB unavailable | 無可驗證結論則 UNVERIFIABLE，停止重試／發送 |

## 3. Isolation 與鎖生命週期待證明事項

**建議起點**：評估 `READ COMMITTED` 搭配固定的 Row／Transaction Advisory Lock，並在取得全部必要鎖後才讀目前 Revocation／Epoch 與實際 DB 時間；不能單憑 Isolation 名稱宣稱可序列化。若採 `SERIALIZABLE`，要明確處理 SQLSTATE `40001` 與 read/write 故障重試；不得隱藏 `40P01` deadlock。

- `pg_advisory_xact_lock`／`pg_advisory_xact_lock_shared` 是 **transaction-level**，transaction rollback／commit 即釋放；連線池污染與 lock wait、long transaction 仍需測試。
- 每次 acquiring lock 前／後時間政策：`now()` 為 transaction start；等待鎖可能跨 deadline，因此安全判定在鎖後用 DB `clock_timestamp()` 或明確等價的實際時間來源，`current >= deadline` 拒絕。不得相信 Runtime 參數 `now` 作最終權威。
- 選擇相容 `SELECT FOR UPDATE`／`FOR SHARE` 模式，避免 share→upgrade 的雙向等待；對 Emergency Revoke、Key Revoke、Epoch Switch 與 StartSend 施加並行故障注入。
- `lock_timeout`、`statement_timeout`、`idle_in_transaction_session_timeout` 與角色 CONN LIMIT 是**可用性限制**，數值須由容量與延遲測試訂定；不是替代狀態機正確性的證據。

## 4. Error Classification（不可把所有 PostgreSQL 錯誤視為 rollback）

| 情況 | 可以重新執行原 Operation 嗎？ | 安全處置 |
| --- | --- | --- |
| 已明確 rollback，確認無外部副作用且 ID＋Digest 相同 | **可受限重試** | 同 ID、同 Input Digest、有限次數＋退避；不能擅自換新身分 |
| `40P01` Deadlock／`40001` Serialization Failure **且已確認 rollback** | **可受限重試** | 上限／退避／監控；若懷疑副作用先做對帳 |
| COMMIT ack 遺失或 Commit 中斷 | **不可直接重試** | Operation ID 唯讀查回、等待已知在途結束／人工對帳，不等同事務 rollback |
| DB 斷線／故障／結果查無 | **不可據此推定安全重試** | Fail-Closed、UNVERIFIABLE；缺 Receipt 不證明未提交 |
| 授權業務拒絕或 JTI 已消費 | **不得重用同一 JTI 授權** | 保留拒絕／消費原因；新嘗試需新的合法簽發者及 JTI |
| SEND_STARTED 後程序失聯 | **不得自動 HTTP 重送** | 保留 SEND_STARTED＋結果未知的 reconciliation record |

Operation ID 要在副作用前確定且能可靠關聯；**ID 是相關鍵而非授權憑證**，不能因 Runtime 可選 ID 就賦予特權。結果資料在執行交易內持久化並以同一 ID／input digest 避免混淆；原始認證／唯一性控制仍必須獨立強制。

## 5. Side-Effect 與 Admission 的分階段模型

| 狀態 | 可允許的後續行為 |
| --- | --- |
| World Commit 未確認 | 唯讀 reconciliation；不盲目重做 Mutation |
| `WORLD_COMMITTED_ADMISSION_UNAVAILABLE`（**擬議 API 語意**） | 可查回 World Operation Result；不得因 HTTP 重試再做業務交易／重新消費原 JTI |
| GRANTED／CLAIMED | 只可沿同一可信 Binding 進行下一步；期限／撤銷失效不可強制放行 |
| SEND_AUTHORIZED | 最後一刻重查最新安全狀態與 Envelope，才可 StartSend |
| ABANDONED＋CONTENT_MISMATCH | 永久不得重新開始；需新的合法 Candidate 與授權流程 |
| SEND_STARTED 且結果未知 | 不宣稱「未送出」、不自動重送；保留 Audit 與 reconciliation |
| SEND_COMPLETED／SEND_FAILED／SEND_PARTIAL_FAILURE | 現有終態；只能以真實可觀察的事件分類，不能把逾時當成 Client 已收到 |

## 6. 開放的實作證明

- 每個交易必須提交**實際**鎖相依矩陣及可由腳本讀取的 `lock_dependency.json`（可於實作 PR 新增），證明**所有**取得 Session Head／Generation／Admission／Profile／Key 的路徑沒有環。本文只是起始盤點，**不是現成 DAG 證明**。
- 要交付 schema：Binding FK/UNIQUE、Candidate Immutable／GC 協定、Operation Receipt UNIQUE＋Input Digest、Receipt 與 Replay 同交易約束；定義 migrations 與 rollback。
- 要用真實 PostgreSQL、**不同 DB Role**、多連線故障注入、clock crossing、未知 COMMIT、快照還原與安全禁用模式，才可宣稱保護成立。

參考 PostgreSQL 官方文件：[Explicit Locking](https://www.postgresql.org/docs/17/explicit-locking.html)、[Data Consistency Checks](https://www.postgresql.org/docs/17/applevel-consistency.html)、[Date/Time Functions](https://www.postgresql.org/docs/17/functions-datetime.html)。
