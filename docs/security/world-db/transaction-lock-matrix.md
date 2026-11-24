# MIR-SEC-WORLD-001 — 交易、鎖與錯誤契約

**v0.2／Proposed／OPEN**。目的：避免把「單一安全狀態轉移交易」誤寫成「整個請求單一交易」，以及防止為了新增 Epoch／Key Freshness 而引入死鎖。本矩陣的**現有路徑**來自 Mirage `main` `88dc2008fd35a2d3873949a769653dc9f18e8980`；**目標交易**仍待實作及測試。

## 1. 現有鎖證據與循環風險

| 現有操作 | 已觀察主要資源順序 | 目前語意／待補事項 |
| --- | --- | --- |
| `PostgresSessionWorlds._resolve_in_transaction` | `session_heads FOR UPDATE` → 舊 `generation_controls UPDATE` → Session Binding／World Snapshot | Epoch cutover 會封存舊世代；有時新 Generation 初始化 |
| `PostgresSessionWorlds.admit_read` | `session_heads FOR SHARE` → `session_world_bindings FOR UPDATE` → `generation_controls FOR SHARE` → snapshot share | 檢查 Head／Generation／Snapshot 與 watermark |
| `PostgresAdmissionControl.grant` | `generation_controls FOR UPDATE` → Projection Registry 受保護操作 → 新 Admission INSERT | 已有單交易 Grant，但依賴 Runtime 提供的 observation，沒有擬議可信 Receipt+Binding |
| `claim`／`authorize_send`／`start_send`（**區分上游舊版與外部判定服務 Freeze v1**） | Mirage 上游 `main` 的原生實作仍須逐項核實；外部判定服務 Freeze v1 的 Authorize：Session Head FOR SHARE → Binding → Admission FOR UPDATE → Generation FOR UPDATE → Profile；StartSend：Admission FOR UPDATE，**不取 Head/Revocation 鎖** | 舊上游 Source 不能假裝已支援新 Freeze；新 v0.2 修補不得讓 StartSend 重新授權 |
| `KeyRevocationRegistry.guard/revoke` | Key namespace 的 transaction advisory lock → Tombstone read/write | 新 Ingress／Authorize 需納入 Key guard；**StartSend 不重新取 Key/Policy Revocation 鎖** |
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
| **AuthorizeTx** | 在同一受保護交易核對 Receipt／Candidate／OperationSnapshotBinding、Session Head、Generation、Key／Profile／Policy／Emergency、deadline；唯一 COMMIT SEND_AUTHORIZED | Head／Binding／Admission／Generation／Profile 鎖順序配合既有 Freeze v1；DB decision_time 在必要鎖後擷取一次 | COMMIT 未知不允許 StartSend；撤銷先提交則拒絕，授權先提交保留 |
| **StartSendTx** | 僅核已提交 SEND_AUTHORIZED、可信 owner、single-use、transmission_deadline、Snapshot version/hash、Purge Fence，原子記錄 SEND_STARTED 與安全必要 Audit | **只鎖 Admission／已綁 Snapshot 執行條件，不取 Policy/Emergency/Head/Key 動態授權鎖** | Snapshot unavailable → Fail-Closed；未知 COMMIT 不新建 HTTP／Admission／JWS；不代表 Client 已收到 |
| **PreSendAbandonTx** | 尚未 SEND_STARTED 時持久化不可重試 Execution Fence；可記錄 ABANDONED 執行終態，**但 SEND_AUTHORIZED revision/歷史授權事實必須保留**；安全 Audit 同交易 | 受限函式檢查 owner／state／Snapshot，不重讀 Policy；不得記假 send_started | 已 SEND_STARTED 或未知傳輸不能改稱未開始；不得抹除已提交授權證據 |
| **ReplayGcTx** | 只刪除證明已超過所有安全保留／對帳窗口之舊墓碑 | 特權 GC 身分；與 Ingress／Restore 具有一致性界限 | 無法證明過期則保留／Fail-Closed，不因壓力提前刪除 |
| **Recovery** | 唯讀核對 Operation Identity／Digest、World／Ingress／Grant Receipt、Transmission Audit、外部副作用、Object Storage 對帳 | DB 之間無共享 COMMIT；Restore 必須 Quarantine／Namespace Fence | 已證實 Rollback 無外部效果才可受限同 Operation 重試；未知／ACK loss／外部效果未確認不能重做 |

## 2A. Contract Freeze v0.2 交易／隱含鎖盤點（Proposed；非已驗證 DAG）

| Tx / 動作 | 權威資源／預期 Lock 類型 | Isolation／時間／副作用界線 |
| --- | --- | --- |
| IngressTx | Key advisory xact lock → Replay UNIQUE INSERT／FK → Receipt INSERT；實際依賴待 DBA 確認 | 提議 READ COMMITTED，同 physical connection／transaction；DB decision_time 鎖後一次；JTI＋Receipt 同提交 |
| OperationIdentityTx | Namespace/epoch 的 UNIQUE／row lock → immutable digest／external_effect_key | 副作用前必須提交；異 Digest 報 OPERATION_DIGEST_CONFLICT，Commit ACK 未知不得重建 |
| CandidatePromotionTx | 完整 Scope Candidate Evidence／Version row lock；FK Key Share／可能等待 GC DELETE | 外部昂貴驗證不能長期持有 Head/Generation；短交易重核 Proposal／Policy |
| PreparePinTx／SnapshotBindTx | Payload Evidence／Pin→ SnapshotProposal 唯一鍵；Binding UNIQUE(operation_identity_id) 和 Admission／Snapshot FK | 外部 materialize 不持 DB 核心鎖；Write-Once；AuthorizeTx 必須引用相同已提交且鎖定的 Binding |
| GrantTx | Head／Generation／Receipt／Promoted Candidate／Binding／Admission／Profile／Key；FK INSERT 對 Parent 隱含 KEY SHARE | **不能假定 Candidate 一定最先鎖**；必須交付完整多 Backend lock DAG |
| AuthorizeTx | Head FOR SHARE → Binding/Admission FOR UPDATE → Generation FOR UPDATE → Profile/Key/Policy Guard（實際順序需以 SQL 證實） | Freeze v1：**COMMIT SEND_AUTHORIZED 才是線性化點**；鎖後一次 decision_time |
| StartSendTx | Admission FOR UPDATE → 已綁 Snapshot/Pin/Purge Fence 的受保護執行檢查 | **無 Policy/Emergency/Epoch/Key 再授權**；SEND_STARTED＋必要 Audit 提交確認後才 ASGI |
| CandidatePayloadGcTx／AuthorizedSnapshotPurgeTx | Candidate Payload Object 與獨立 Snapshot Object identity/version、Binding、**實體 Blob Ref/Pin/Lease**、各自 Purge Fence、FK DELETE 隱含鎖 | Candidate GC 不能刪仍被 Snapshot Pin 的共享 Blob，Candidate Fence 不影響已授權 Snapshot。Snapshot GC 先受保護 COMMIT `AuthorizedSnapshotPurgeFence` 永久禁新 StartSend，後以固定 gc_operation_id 冪等刪實體 bytes；GC 失敗不得恢復資格；UNKNOWN 對帳；真正 Object 刪除與 DB COMMIT 非原子 |
| Restore/MixedFence | **還原範圍外**的 Quarantine/Namespace/Anti-Rollback Anchor/External Receipt；Old Role ACL／Connection Pool 徹底撤銷 | 先隔離才准 Runtime／Sender 恢復；外部單調 checkpoint 與 Tombstone/Operation 範圍不能驗證時持續禁送；新舊 Runtime 分 Role/credential，未知 COMMIT/HTTP 不新發送 |
| RestoreAnchorPublish（跨交易／跨信任域） | World DB 的 Operation/Tombstone Commit 與外部獨立 Head 的 durable publish／ACK 是**不同原子域**；Anchor 先行時必須標 PREPARED／UNUSED | DB first、Anchor missing／ACK unknown → Quarantine＋唯讀 Operation Digest／外部效果對帳；Anchor first、DB rollback → 不構成業務提交，Head 不回退；兩邊無法核對則持續 Quarantine，`WORLD-RESTORE-PUBLISH-01` NOT_RUN |

**MUST**：實作記錄每一 SQL 的**實際** Isolation Level、row/advisory/FK lock mode、等待依賴、lock_timeout、`40P01`／`40001` 時是否有外部副作用；並以不同 PostgreSQL Backend 鎖等待、順序競態、GC、撤銷、備份還原實證。**此圖是盤點，不是已證明全球無死鎖的 DAG。**

## 3. Isolation 與鎖生命週期待證明事項

**建議起點**：評估 `READ COMMITTED` 搭配固定的 Row／Transaction Advisory Lock，並在取得全部必要鎖後才讀目前 Revocation／Epoch 與實際 DB 時間；不能單憑 Isolation 名稱宣稱可序列化。若採 `SERIALIZABLE`，要明確處理 SQLSTATE `40001` 與 read/write 故障重試；不得隱藏 `40P01` deadlock。

- `pg_advisory_xact_lock`／`pg_advisory_xact_lock_shared` 是 **transaction-level**，transaction rollback／commit 即釋放；連線池污染與 lock wait、long transaction 仍需測試。
- **Verifier Context 不等於 DB 權限證明**：Verifier 內部固定 JWS 靜態驗證結果，不序列化給低信任服務；Receipt Writer 必須由實際受限 DB 連線身分執行，不接受自填 Verified JSON。所有 Key／Replay／Receipt API 使用受控 Transaction Context，且不得再開另一條 Connection 或中途 commit；連線池歸還前 rollback／session reset。
- **Candidate Validator／Promotion 交界**：昂貴 Validation 不宜因單一交易要求持有長時間 Key／Generation／Candidate 鎖；可在交易外依受保護不可變快照驗證，再由短 PromotionTx 重新鎖定並核對 DB 產生的 Version、bytes／Envelope hash、Scope、Contract／Source／Validator Evidence 和 Policy Authority 最新**允許狀態**。不能以普通 `validated=true` 作授權證據；Policy Version Upgrade 不應自動等同 Revocation。
- **Candidate FK／GC 的附帶鎖與留存**：FK 應參照實際完整 Scope 複合鍵，先確認 Index／鍵更新規則與插入所取得的 FK Row Lock；不能以單欄 `candidate_id` 虛構現在的資料模型。受限 GC 必須安全略過 Active／Bound／UNRESOLVED 且仍需要 Payload 的資料；若永久 Binding 保留，另行隔離可過期 Payload 與不可變稽核 Metadata，不得以無限保存 Raw Bytes 作唯一解。
- **權威決策時間**：每個 Protected Tx 先取得全部必要鎖，再只讀一次 DB `clock_timestamp()` 得 `decision_time` 並持久化；同交易所有期限／GC／Lease 均使用此值。Claim 判 `authorization_deadline`，Authorize/StartSend 判 `transmission_deadline`，`decision_time < deadline` 不代表 COMMIT 必須早於 deadline；COMMIT 未知一律拒絕猜測。Runtime now、時鐘回退／不可驗證 skew 均 Fail-Closed。
- **BD-11 OPEN 時的預設停用**：不能把 decision-time 合法冒稱 commit-before-deadline；如果產品需要後者，正式送出功能保持 DISABLED。未知 COMMIT 不得新起送／重試；但已實際完成的 `SEND_AUTHORIZED` 不因 ACK 遺失而回溯變成未授權。權威 DB 時間不可檢證時停止新的授權與 StartSend。
- **Purge Fence 不是 Policy Revocation**：僅受保護的 Snapshot 安全不可用／不可逆 GC 事實可封鎖已授權執行；Runtime 或控制介面不得在授權後藉自填 Fence 達成第二次政策否決（`WORLD-PROTOCOL-02` NOT_RUN）。
- **三軸資料一致性**：Admission 授權狀態、Candidate 原始 Payload retention、已綁 Authorized Snapshot 的 `AVAILABLE/PURGE_PENDING/PURGED/CORRUPT/UNAVAILABLE` 執行資格是不同狀態域。GC 清除 Candidate 原始 bytes 不能直接封鎖完整 Snapshot；Snapshot 真實 Purge/Integrity 失效則只封鎖新 StartSend，不回溯寫掉 SEND_AUTHORIZED；實際 Schema／轉移仍屬 Proposed，`WORLD-PURGE-BOUNDARY-01` NOT_RUN。
- **獨立儲存物件／雙 Fence／GC 重試**：CandidatePayloadObject 與 AuthorizedSnapshotObject 各有受保護 identity，底層共享 dedup Blob 時必須同鎖或等價 pin/refcount 保障，外部 Object Delete 與 DB Reference 轉移的競態須以故障注入測試。`CandidatePayloadPurgeFence` 不影響已授權 Snapshot，`AuthorizedSnapshotPurgeFence` 已提交則即使 Object GC 失敗也永久禁新起送；重試只能在相同冪等 GC Operation 下清理，不重開資格。`WORLD-SNAPSHOT-SEPARATION-01`、`WORLD-PURGE-RETRY-01` NOT_RUN。
- **Restore Fence**：只有還原範圍外的最高受信任 checkpoint head、單調世代、DB timeline/position 與 canonical digest 覆蓋清單能建立防重播／未倒退邊界；若缺 Candidate Tombstone/Binding/Operation/Replay/Revocation 涵蓋、或來源權威不可核對，必須持續 Quarantine（`WORLD-RESTORE-FENCE-01` NOT_RUN）。
- **Anchor 發布非原子**：DB-first 的 checkpoint ACK 未知與 Anchor-first 的 DB rollback 是兩個不同故障案例。先行的 PREPARED checkpoint 不等同 DB Commit，不能拿獨立 Anchor 當 World Result；DB-first 卻沒有相應最新 Head 時持續隔離並依 Operation Digest 對帳（`WORLD-RESTORE-PUBLISH-01` NOT_RUN）。
- `SELECT FOR UPDATE／FOR SHARE／FOR KEY SHARE`、FK INSERT/DELETE implicit row-lock／advisory lock 順序須列入同一 lock graph；Key／Profile／Emergency 與 **Authorize** 並行驗證，**不得**把本來已凍結的 Policy 又塞回 StartSend。
- `lock_timeout`、`statement_timeout`、`idle_in_transaction_session_timeout` 與角色 CONN LIMIT 是**可用性限制**，數值須由容量與延遲測試訂定；不是替代狀態機正確性的證據。

## 4. Error Classification（不可把所有 PostgreSQL 錯誤視為 rollback）

| 情況 | 可以重新執行原 Operation 嗎？ | 安全處置 |
| --- | --- | --- |
| **DB 明確證實 rollback**、有 World／External／HTTP 零不可逆副作用證據、同一 Operation Identity＋Digest 已確認未執行 | **才可考慮受限重試** | 同 ID、同 Digest、有限次數＋退避；重新查證 JWS `exp`、Session、Generation、Policy 仍有效；不可從單一 Receipt 查無推斷 rollback |
| `40P01` Deadlock／`40001` Serialization Failure **且已確認 rollback** | **可受限重試** | 上限／退避／監控；若懷疑副作用先做對帳 |
| COMMIT ack 遺失或 Commit 中斷 | **不可直接重試** | Client 先標 `UNKNOWN`；依 Operation ID／digest 唯讀查回。可信同 ID 成功結果可改為 `CONFIRMED_COMMITTED`；仍不可驗證則保持 `UNVERIFIABLE`，不等同 rollback |
| DB 斷線／故障／結果查無 | **不可據此推定安全重試** | Fail-Closed、UNVERIFIABLE；缺 Receipt 不證明未提交 |
| **IngressTx 明確 rollback**，JTI 未消費，原 JWS 仍有效 | **同一 JWS 可否受限重試，依原 Operation ID/digest 與 Policy** | 必須由 DB 明確證明 rollback，並對 World Commit／外部效果／HTTP 取得零副作用證據；原 Operation 不可另起一筆，授權／Epoch／時間仍有效；不可只靠 JTI 未消費 |
| **IngressTx 已提交消費**，其後 Grant 業務拒絕 | **不得重新消費原 JTI** | 保留原因；若合法開始**新的意圖**，才由可信簽發者提供新 JWS/JTI，且不得重做已提交副作用 |
| 授權業務拒絕（無新合法輸入） | **不可盲目重試** | 停止該意圖；不能以換新 Token 當作規避拒絕的方法 |
| SEND_STARTED COMMIT/ACK UNKNOWN | **不得新起 HTTP 傳輸或重試** | 查回 SEND_STARTED 只確認 DB 狀態；原 Sender 若尚有同一 TCP/ASGI 上下文可依期限完成；無批准續傳協定則 at-most-once，不得因對帳開新連線 |
| Snapshot Binding COMMIT/ACK UNKNOWN | **不得改選另一 Snapshot** | 按已持久化 Proposal、Operation Identity 只讀對帳，相同 Binding 只讀回、不同回 SNAPSHOT_BINDING_CONFLICT |
| SEND_STARTED 後程序失聯 | **不得自動 HTTP 重送** | 保留 SEND_STARTED＋結果未知的 reconciliation record |

Operation Identity 須在副作用前以 `UNIQUE(authority_namespace,namespace_epoch,operation_id)` 建立不可變 `input_digest`／演算法及外部 `external_effect_key`；不同 Digest 拒絕、相同 Digest 僅查原結果，未知 COMMIT／Restore 不能藉新 Epoch／JWS 改外部效果 Key。ID 不是授權憑證。

## 5. Side-Effect 與 Admission 的分階段模型

| 狀態 | 可允許的後續行為 |
| --- | --- |
| World Commit 未確認 | 唯讀 reconciliation；不盲目重做 Mutation |
| `WORLD_COMMITTED_ADMISSION_UNAVAILABLE`（**擬議 Reconciliation Classification；不是正式 World／Admission State**） | 可查回 World Operation Result；不得因 HTTP 重試再做業務交易／重新消費原 JTI |
| GRANTED／CLAIMED | 只可沿同一可信 Binding 進行下一步；期限／撤銷失效不可強制放行 |
| SEND_AUTHORIZED | **授權已凍結**；StartSend 只驗 owner／deadline／single-use／授權 Snapshot integrity／Purge Fence；不得二次核 Policy／Emergency／Epoch |
| ABANDONED＋CONTENT_MISMATCH | 永久不得重新開始；需新的合法 Candidate 與授權流程 |
| SEND_STARTED 且結果未知 | 不宣稱「未送出」、不自動重送；保留 Audit 與 reconciliation |
| SEND_COMPLETED／SEND_FAILED／SEND_PARTIAL_FAILURE | 現有終態；只能以真實可觀察的事件分類，不能把逾時當成 Client 已收到 |

## 6. 開放的實作證明

- 每個交易必須提交**實際**鎖相依矩陣及可由腳本讀取的 `lock_dependency.json`（可於實作 PR 新增），證明**所有**取得 Session Head／Generation／Admission／Profile／Key 的路徑沒有環。本文只是起始盤點，**不是現成 DAG 證明**。
- 要交付完整 Scope+Version Candidate Evidence／Payload／Snapshot／Binding FK/UNIQUE、Pin/Lease／Purge Tombstone、Snapshot Proposal 和 Write-Once Operation Binding、`UNIQUE(authority_namespace,namespace_epoch,operation_id)`、固定外部 effect key；新 schema/rollback 不得重開 Runtime DML 或產生重送資格。
- 要用真實 PostgreSQL、**不同 DB Role**、多連線故障注入、clock crossing、未知 COMMIT、快照還原與安全禁用模式，才可宣稱保護成立。

參考 PostgreSQL 官方文件：[Explicit Locking](https://www.postgresql.org/docs/17/explicit-locking.html)、[Data Consistency Checks](https://www.postgresql.org/docs/17/applevel-consistency.html)、[Date/Time Functions](https://www.postgresql.org/docs/17/functions-datetime.html)。
