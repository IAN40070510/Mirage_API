# MIR-SEC-WORLD-001 — 交易、鎖與錯誤契約

**v0.2／Proposed／OPEN**。目的：避免把「單一安全狀態轉移交易」誤寫成「整個請求單一交易」，以及防止為了新增 Epoch／Key Freshness 而引入死鎖。本矩陣的**現有路徑**來自 Mirage `main` `88dc2008fd35a2d3873949a769653dc9f18e8980`；**目標交易**仍待實作及測試。

## 1. 現有鎖證據與循環風險

| 現有操作 | 已觀察主要資源順序 | 目前語意／待補事項 |
| --- | --- | --- |
| `PostgresSessionWorlds._resolve_in_transaction` | `session_heads FOR UPDATE` → 舊 `generation_controls UPDATE` → Session Binding／World Snapshot | Epoch cutover 會封存舊世代；有時新 Generation 初始化 |
| `PostgresSessionWorlds.admit_read` | `session_heads FOR SHARE` → `session_world_bindings FOR UPDATE` → `generation_controls FOR SHARE` → snapshot share | 檢查 Head／Generation／Snapshot 與 watermark |
| `PostgresAdmissionControl.grant` | `generation_controls FOR UPDATE` → Projection Registry 受保護操作 → 新 Admission INSERT | 已有單交易 Grant，但依賴 Runtime 提供的 observation，沒有擬議可信 Receipt+Binding |
| `claim`／`authorize_send`／`start_send` | `response_admissions FOR UPDATE` → `generation_controls FOR UPDATE` → Profile 受保護檢查／advisory guard | StartSend 有 owner／deadline／emergency；**沒有完整 Head／Key Receipt 鏈** |
| `KeyRevocationRegistry.guard/revoke` | 相同 `(environment,deployment,issuer,kid)` 的 transaction advisory lock → Tombstone read/write | 需與 StartSend 的 Key Lock 共同定義順序與 `READ COMMITTED` 查核 |
| Profile Revocation | Profile namespace 的 transaction advisory lock、受保護狀態讀寫 | 需與 Admission／Generation／Session 交互動態查核，沿用現有鍵演算法 |
| `TrustedSessionVerifier.verify`／`PostgresReplayStore.consume`／`KeyRevocationRegistry.guard` | Verifier 呼叫 Replay consume；Replay 與 Key Guard **各自開 DB connection** | **現有程式不滿足**「Key Guard＋Replay＋Receipt 同一 physical connection／transaction」；外層單加 BEGIN 無效 |
| `PostgresCandidateStore.put/gc` | `put` 由 body 算 SHA-256 保存完整 Scope＋`candidate_ref`；`gc` 依呼叫者傳入 `protected_refs` 刪除已過期紀錄 | 單靠呼叫者清單不是 Grant／GC 的 DB-level 原子性保證；需完整 Scope FK／鎖／受限 GC 與 Payload 保留策略 |

**潛在循環示例（不是已重現的死鎖）**：

```text
Tx A (新增 Session 檢查若排在既有 StartSend 鎖後)：
  Admission → Generation ─等待→ Session Head

Tx B (Session epoch rollover)：
  Session Head ─等待→ Generation

=> Generation ↔ Session Head 形成可能循環。
```

不能只在既有 `_lock_admission()` 結尾加 `SELECT session_heads ... FOR SHARE`。**實作前必須產生涵蓋全部操作的鎖 DAG，且真實 PostgreSQL 以雙／多連線注入阻塞測試。** 建議 GC 與 Grant 在涉及相同 Candidate 時遵循 `Candidate → Binding/Admission` 的**局部**順序，但全域路徑現有 Grant 先鎖 Generation、Session Resolve 先鎖 Head，且 FK 插入／刪除也可能取得 Row Lock；**不能把局部順序當作已證明無環**，必須共同排定全部鎖。鎖順序改變應同步檢查 Legacy／新版混跑；沿用現有 Profile／Key 64-bit extended-hash namespace，若變更鍵演算法須停流排空所有舊連線後切換。

## 2. 目標交易責任與失敗語意

| 目標操作 | 單一交易必須原子完成 | 鎖／時間義務 | 失敗結果 |
| --- | --- | --- | --- |
| **IngressTx** | Trusted Verifier 靜態驗簽後，單一 Coordinator 以**同 DB／同 Physical Connection／同 Transaction**取得 Key Guard、以 DB 時間重查權限、JTI 唯一 INSERT＋Ingress Receipt INSERT | 固定不可變內部驗證 Context；Store 不自行 connect/commit；例外 rollback／Pool reset；Key 與 Replay 線性化規則 | 明確 rollback：兩者都不可見；Commit ACK 未知：Client 初始 UNKNOWN，唯讀對帳，不重新消費同 JTI |
| **CandidatePromotionTx** | **短**受保護交易鎖定 DB 版本，核對 Validator Evidence（Envelope／Contract／Scope／Source／Revision／Identity／Algorithm／Time）並固定 Promoted Candidate，才讓 Grant 可見 | 昂貴 Validation 可先在鎖外對可信不可變快照完成；Promotion 重核相同 hash/version、當前政策允許狀態與 GC/Grant 全域鎖協定；禁止未授權自填 version／validated flag | Promotion 失敗不允許半可信 Candidate；Staging 留存僅供審計／受限 GC |
| **GrantTx** | 鎖**已提交的** Receipt、**已提升的** Candidate；核對 scope／完整 Envelope hash／Projection／session／generation／deadline／Policy Revision；**只建立** Binding UNIQUE＋Admission INSERT 同交易 | Receipt／Candidate／Head／Generation／Admission／Profile／Key 的**總鎖序待 DAG 核准**；不可無視既有 Grant 先 Generation 與 FK 自動鎖 | 任一檢查失敗整筆 rollback；已提交的 Ingress JTI 消費不回復 |
| **AuthorizeTx** | 將同一 Admission 由 CLAIMED 升 SEND_AUTHORIZED；核對同一 Receipt／Binding、目前 Key／Profile／Epoch／Generation／期限／**Policy Revision 是否仍可發送** | 所有動態檢查與改寫在相容鎖及當前 DB Snapshot 內；使用 DB 實際檢查時間 | 業務拒絕不可用同 Operation 盲目重授權 |
| **StartSendTx** | owner、原 hash、Receipt／Key／Head／Profile／Generation／Policy Revocation、deadline 重查；唯一進入 SEND_STARTED 並記錄送出起點 | 與 Revocation／Epoch cutover／Policy Change 對同一 Scope 有可證明勝負順序 | 已撤銷／失配／逾時：拒絕；不能假設已開始的 bytes 可撤回 |
| **PreSendAbandonTx** | 尚未 Start 的 Admission 狀態從 SEND_AUTHORIZED → ABANDONED；不可改 hash；安全 Audit `CONTENT_MISMATCH` 同交易 | 受限函式核 owner／state；不得將假 send_started 記入普通 Response Audit | 已 SEND_STARTED 必須拒絕此「未開始」語意 |
| **ReplayGcTx** | 只刪除證明已超過所有安全保留／對帳窗口之舊墓碑 | 特權 GC 身分；與 Ingress／Restore 具有一致性界限 | 無法證明過期則保留／Fail-Closed，不因壓力提前刪除 |
| **Recovery** | 唯讀讀取 Operation Receipt 與業務 Commit Result；不改寫未知歷史 | 必須辨識 commit ack loss、still in-flight、DB unavailable | 無可驗證結論則 UNVERIFIABLE，停止重試／發送 |

## 3. Isolation 與鎖生命週期待證明事項

**建議起點**：評估 `READ COMMITTED` 搭配固定的 Row／Transaction Advisory Lock，並在取得全部必要鎖後才讀目前 Revocation／Epoch 與實際 DB 時間；不能單憑 Isolation 名稱宣稱可序列化。若採 `SERIALIZABLE`，要明確處理 SQLSTATE `40001` 與 read/write 故障重試；不得隱藏 `40P01` deadlock。

- `pg_advisory_xact_lock`／`pg_advisory_xact_lock_shared` 是 **transaction-level**，transaction rollback／commit 即釋放；連線池污染與 lock wait、long transaction 仍需測試。
- **Verifier Context 不等於 DB 權限證明**：Verifier 內部固定 JWS 靜態驗證結果，不序列化給低信任服務；Receipt Writer 必須由實際受限 DB 連線身分執行，不接受自填 Verified JSON。所有 Key／Replay／Receipt API 使用受控 Transaction Context，且不得再開另一條 Connection 或中途 commit；連線池歸還前 rollback／session reset。
- **Candidate Validator／Promotion 交界**：昂貴 Validation 不宜因單一交易要求持有長時間 Key／Generation／Candidate 鎖；可在交易外依受保護不可變快照驗證，再由短 PromotionTx 重新鎖定並核對 DB 產生的 Version、bytes／Envelope hash、Scope、Contract／Source／Validator Evidence 和 Policy Authority 最新**允許狀態**。不能以普通 `validated=true` 作授權證據；Policy Version Upgrade 不應自動等同 Revocation。
- **Candidate FK／GC 的附帶鎖與留存**：FK 應參照實際完整 Scope 複合鍵，先確認 Index／鍵更新規則與插入所取得的 FK Row Lock；不能以單欄 `candidate_id` 虛構現在的資料模型。受限 GC 必須安全略過 Active／Bound／UNRESOLVED 且仍需要 Payload 的資料；若永久 Binding 保留，另行隔離可過期 Payload 與不可變稽核 Metadata，不得以無限保存 Raw Bytes 作唯一解。
- 每次 acquiring lock 前／後時間政策：`now()` 為 transaction start；等待鎖可能跨 deadline，因此安全判定在鎖後用 DB `clock_timestamp()` 或明確等價的實際時間來源，`current >= deadline` 拒絕。不得相信 Runtime 參數 `now` 作最終權威。
- 選擇相容 `SELECT FOR UPDATE`／`FOR SHARE` 模式，避免 share→upgrade 的雙向等待；對 Emergency Revoke、Key Revoke、Epoch Switch 與 StartSend 施加並行故障注入。
- `lock_timeout`、`statement_timeout`、`idle_in_transaction_session_timeout` 與角色 CONN LIMIT 是**可用性限制**，數值須由容量與延遲測試訂定；不是替代狀態機正確性的證據。

## 4. Error Classification（不可把所有 PostgreSQL 錯誤視為 rollback）

| 情況 | 可以重新執行原 Operation 嗎？ | 安全處置 |
| --- | --- | --- |
| 已明確 rollback，確認無外部副作用且 ID＋Digest 相同 | **可受限重試** | 同 ID、同 Input Digest、有限次數＋退避；不能擅自換新身分 |
| `40P01` Deadlock／`40001` Serialization Failure **且已確認 rollback** | **可受限重試** | 上限／退避／監控；若懷疑副作用先做對帳 |
| COMMIT ack 遺失或 Commit 中斷 | **不可直接重試** | Client 先標 `UNKNOWN`；依 Operation ID／digest 唯讀查回。可信同 ID 成功結果可改為 `CONFIRMED_COMMITTED`；仍不可驗證則保持 `UNVERIFIABLE`，不等同 rollback |
| DB 斷線／故障／結果查無 | **不可據此推定安全重試** | Fail-Closed、UNVERIFIABLE；缺 Receipt 不證明未提交 |
| **IngressTx 明確 rollback**，JTI 未消費，原 JWS 仍有效 | **同一 JWS 可否受限重試，依原 Operation ID/digest 與 Policy** | 先確定沒有未知 Commit／外部副作用；不可無條件要求簽發新 JWS |
| **IngressTx 已提交消費**，其後 Grant 業務拒絕 | **不得重新消費原 JTI** | 保留原因；若合法開始**新的意圖**，才由可信簽發者提供新 JWS/JTI，且不得重做已提交副作用 |
| 授權業務拒絕（無新合法輸入） | **不可盲目重試** | 停止該意圖；不能以換新 Token 當作規避拒絕的方法 |
| SEND_STARTED 後程序失聯 | **不得自動 HTTP 重送** | 保留 SEND_STARTED＋結果未知的 reconciliation record |

Operation ID 要在副作用前確定且能可靠關聯；**ID 是相關鍵而非授權憑證**，不能因 Runtime 可選 ID 就賦予特權。結果資料在執行交易內持久化並以同一 ID／input digest 避免混淆；原始認證／唯一性控制仍必須獨立強制。

## 5. Side-Effect 與 Admission 的分階段模型

| 狀態 | 可允許的後續行為 |
| --- | --- |
| World Commit 未確認 | 唯讀 reconciliation；不盲目重做 Mutation |
| `WORLD_COMMITTED_ADMISSION_UNAVAILABLE`（**擬議 Reconciliation Classification；不是正式 World／Admission State**） | 可查回 World Operation Result；不得因 HTTP 重試再做業務交易／重新消費原 JTI |
| GRANTED／CLAIMED | 只可沿同一可信 Binding 進行下一步；期限／撤銷失效不可強制放行 |
| SEND_AUTHORIZED | 最後一刻重查最新安全狀態與 Envelope，才可 StartSend |
| ABANDONED＋CONTENT_MISMATCH | 永久不得重新開始；需新的合法 Candidate 與授權流程 |
| SEND_STARTED 且結果未知 | 不宣稱「未送出」、不自動重送；保留 Audit 與 reconciliation |
| SEND_COMPLETED／SEND_FAILED／SEND_PARTIAL_FAILURE | 現有終態；只能以真實可觀察的事件分類，不能把逾時當成 Client 已收到 |

## 6. 開放的實作證明

- 每個交易必須提交**實際**鎖相依矩陣及可由腳本讀取的 `lock_dependency.json`（可於實作 PR 新增），證明**所有**取得 Session Head／Generation／Admission／Profile／Key 的路徑沒有環。本文只是起始盤點，**不是現成 DAG 證明**。
- 要交付 schema：Binding **完整 Scope** FK/UNIQUE、Candidate Submission／Validation／Promotion 與 GC 協定、Raw Payload／Evidence Retention、Operation Receipt UNIQUE＋Input Digest、Receipt 與 Replay 同 DB／Connection／IngressTx 約束；定義 migrations 與 rollback。Validator／Promotion 須防止內容或 Contract／Policy Revision TOCTOU，Policy Revocation 的時點也須能與 Grant／StartSend 線性排序。
- 要用真實 PostgreSQL、**不同 DB Role**、多連線故障注入、clock crossing、未知 COMMIT、快照還原與安全禁用模式，才可宣稱保護成立。

參考 PostgreSQL 官方文件：[Explicit Locking](https://www.postgresql.org/docs/17/explicit-locking.html)、[Data Consistency Checks](https://www.postgresql.org/docs/17/applevel-consistency.html)、[Date/Time Functions](https://www.postgresql.org/docs/17/functions-datetime.html)。
