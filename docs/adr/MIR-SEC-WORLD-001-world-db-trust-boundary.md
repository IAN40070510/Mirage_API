# MIR-SEC-WORLD-001 — World DB 信任邊界與受保護發送授權（Architecture Draft）

| 欄位 | 值 |
| --- | --- |
| ADR 版本 | **v0.2**（2026-11-21，Asia/Taipei；由 v0.1 追加審查結論） |
| Architecture | **Proposed；未經 Owner／DBA／Security 核准** |
| Security weakness | **MIR-SEC-WORLD-001 — OPEN／尚未修復** |
| 關聯驗收 | **MSDSS P2 — NO-GO**；P2 是 MSDSS 的驗收代號，不是 Mirage 的漏洞識別碼 |
| Mirage 原始碼基準 | `main` commit `88dc2008fd35a2d3873949a769653dc9f18e8980` |
| 來源 | 多輪架構審查結論及原始碼唯讀核對；**本文件本身不構成已通過的安全驗證** |
| 變更界線 | 文件提案；**不代表已修改 Runtime、資料庫 ACL、staging、金鑰或 production 開關** |
| 審核責任 | Mirage Owner、DBA、Security；發布仍須 Release Approver 與 MSDSS P2 個別驗收 |

> **一句話決策方向**：採方案 B，讓 PostgreSQL／獨立可信角色強制關鍵授權狀態轉移；每個不可分割的安全狀態轉移使用同一個 PostgreSQL 交易，但**不假裝整個 HTTP、World Mutation 與外部副作用能共用一個交易**。

## 1. 問題、實證與未實證主張

MSDSS 的 [Draft PR #23](https://github.com/IAN40070510/MSDSS/pull/23) 報告：在 PostgreSQL 17.6 的隔離環境中，持有既有 World Runtime DB 身分者可直接修改發送授權狀態、倒退 Session epoch，或提早刪除尚未過期的 JWS Replay 墓碑。**該 PR 的測試結果（13/13、回歸與 CI）來自先前驗收紀錄；撰寫本 ADR 時未重新執行該實驗。** 其 3 項重現案例是缺口的證據，**不是修復通過**。

上游原始碼所見的既有行為：

- `src/deception/world/postgres_admission.py` 的 `grant`、`claim`、`authorize_send`、`start_send` 直接 DML；`_lock_admission` 依序取得 Admission、Generation、Profile 安全控制鎖。`start_send` 目前檢查 Claim Owner、Generation／Profile emergency 與 Transmission Deadline，**尚無沿受保護 Receipt 重新查核 Key Revocation／Session Head 的完整路徑**。
- `src/deception/world/session.py` 使用 `session_heads` 保存 epoch，Session 切換會更新舊 Generation 的 seal；已有 `world_snapshots.expires_at`，**不能據此虛構另一個已存在的 Generation-expiry 欄位**。
- `src/deception/domains/ecommerce/trusted_http.py` 傳入 `domain_validation='passed'` 等觀察結果；該字串屬 Runtime 審計宣告，**不是獨立不可偽造的授權證據**。該檔目前設定 Grant 的 `authorization_deadline` 不超過原始 JWS `exp`，而 `transmission_deadline` 可取世界快照期限與短發送窗口的下限；Grant 後 Token 到期能否開始發送需正式裁決。
- `src/deception/world/postgres_replay.py` 的 `replay_entries` 是已消費 JTI 的防重放墓碑；它本身不證明驗章成功，也不是任意未消費 Token 的儲存清單。
- `src/deception/world/transmission.py` 在 `prepare` 核對 Envelope v1，但 `start` 呼叫持久化起送；最後一刻的 Payload／Middleware 完整性與失配稽核仍須形成受保護合約。
- `migrations/009_response_audit.sql` 的 `response_audit` 主要記錄傳輸事件，現行第一筆事件由 `start_send` 寫入；沒有現成的特權 `CONTENT_MISMATCH` 原子拒絕操作。

資料庫 ACL 風險不表示 HTTP 訪客已證實可利用，也**不能只因為 CI 全綠便關閉**。正式風險嚴重度、憑證暴露面與真實攻擊路徑尚待 Security 分級。

## 2. 威脅能力與保證界線

以**能力**而非攻擊方式命名：

| 能力 | 攻擊者實際能力 | 本 ADR 保證目標 |
| --- | --- | --- |
| R1 | 取得 HTTP Runtime DB 憑證，能用該角色執行任何獲准 SQL | **必須抵抗**繞過 Receipt、Binding、Admission、epoch、Replay、revocation 等保護 |
| R2 | SQL Injection 最終取得與 R1 等價的 Runtime SQL 能力 | **包含在 R1 的 DB 負面測試**；應用端仍需參數化與輸入驗證 |
| R3 | 可呼叫 Verifier 公開 API，或取得部分設定／秘密（按實際能力細分） | 無效 JWS／偽造 claims 必須被拒；部分秘密外洩須額外隔離與事件處置 |
| R4 | 完全控制 HTTP Runtime 程序／可自行呼叫 ASGI send | **不承諾端到端阻止自行發送**；需要獨立發送者才可擴大主張 |
| R5 | 控制主機 root、Docker daemon 或 PostgreSQL superuser | **不在本輪保證範圍內** |

T1／T1.5／T2 舊稱僅保留於 [決策歷史](../security/world-db/decisions-log.md) 的脈絡。`pg_hba.conf` 只是來源與認證規則，**不是單獨的服務身分證明**；同主機 root 無法由容器掛載權限抵抗。

各控制項的 R1–R5 覆蓋範圍與剩餘風險詳見 [威脅能力矩陣](../security/world-db/threat-capability-matrix.md)。

## 3. 方案比較與架構選擇

| 方案 | 邊界 | 代價／剩餘風險 |
| --- | --- | --- |
| A：信任 HTTP Runtime | DB 身分可用既有 DML；依賴程序檢查、憑證管理與稽核 | R1 被竊時無資料庫獨立強制，必須由 Security 正式接受此殘餘風險 |
| **B：受保護交易與獨立 Verifier／Authorizer（建議）** | Runtime 不具關鍵狀態 DML；可信角色只可執行窄介面，DB 強制來源／轉移／唯一性 | 需調整交易、部署、GC、故障對帳與 CI；**不等於 R4/R5 保障** |

**Architecture Proposed：選 B；尚未取得 Mirage Owner、DBA、Security 核准。** 本 ADR 不是直接套用原始 Assessment Ledger 的 EXECUTE-only 權限。World Runtime 仍有合法 SELECT／INSERT／UPDATE 與部分 DELETE 使用情境；應**按資料表、欄位與操作**逐項拆權限，不能整庫撤銷 DML 造成既有交易壞掉。

## 4. 權威證據與不可變綁定（強制合約）

受保護授權鏈是 `Admission → Grant Binding → Ingress Receipt → Replay Tombstone`。四者是**不同證據**，任一張表存在都不能單獨證明整條鏈有效。

1. **Ingress Verifier 的驗證責任／來源語意 A**：只收原始 JWS 與必要、可重新計算的請求資料；不得接受 Runtime 提供的 `verified=true`、issuer 覆寫、驗證結果、簽發時間、政策版本或已核准標記。自行驗證簽章、Claims、issuer、audience、deployment/environment、request fingerprint、時間、Session epoch、金鑰信任與撤銷。**本輪只承諾「JWS 與所提交的 Canonical Request Snapshot 相符」**，不宣稱 Runtime 提交的快照必然等於實際入口 HTTP 請求。獨立入口來源證明（Gateway 簽章、受控 IPC 或可信入口）是未來語意 B／R4 設計；不因此放寬後續 Grant／StartSend 的同一 Request Fingerprint Binding。
2. **Receipt 的信任根與 Verified Context**：可選獨立 Verifier 服務及受限 DB Role，或受保護 DB 驗證程序；必須證明 Runtime DB 角色無法建造／改寫 Receipt、登入 Verifier 身分、取得其 Secret，亦無法藉過度寬泛的 SECURITY DEFINER 函式偽造結果。Immutable Verified Context 只能在 Verifier 內部由實際驗證結果建立，**不是 PostgreSQL 能自行辨識的密碼學證明**；DB 信任仍由 Verifier 實際驗證、獨立 DB 身分、窄函式與存取隔離共同成立。
3. **同資料庫原子性與唯一交易協調器**：同一 PostgreSQL **database、physical connection、IngressTx** 內取得 Key Revocation Guard、依 DB 權威時間重新檢查期限／撤銷、原子插入 Replay Tombstone 與 Ingress Receipt；僅交易協調器可 commit/rollback。靜態 JWS 驗證的不可變結果不得由呼叫者任意注入 Claims／JSON／policy／時間；Replay Store、Key Revocation Store、Receipt Writer 的受保護交易介面不得自行開第二條連線或在中途 commit。例外須 rollback 並清理連線池 Session 狀態。**現行** `TrustedSessionVerifier.verify()`、`PostgresReplayStore.consume()` 與 `KeyRevocationRegistry.guard()` 分別管理連線／消費，尚未達成本合約。若未來拆分 DB，必須另立安全協定，不可沿用此原子性聲明。
4. **Ingress 與 Candidate 的時間順序**：Ingress 發生時 Candidate 通常**尚未生成**；Receipt 先綁定已驗證 Claims、request fingerprint 與候選意圖／允許的 Scope，**不得偽稱此時已驗證未來的 Candidate hash**。GrantTx 再將不可變的實際 Candidate、Envelope v1 hash、Session、Generation、Projection 與 Receipt **原子綁定**到 Admission。
5. **不可挪用／唯一性**：`(issuer,audience,jti)` 確保 Token 一次性消費；Receipt ID、Operation ID、Admission ID 與 Candidate ID 各有不同語意與完整 Scope。Receipt 最多有一筆有效 Grant Binding；同一 Receipt 不得換 Candidate／Generation；同一 Operation ID 配不同 `input_digest` 必須拒絕。使用 DB FK、UNIQUE、鎖與權限強制，而非只相信 Python。
6. **「已使用」定義**：StartSend 時 Receipt **原本就已綁定目前 Admission**。不得因 `used=true` 一律拒絕；必須拒絕的是**其他 Admission 的重綁、已撤銷或不符合當前授權窗口**。
7. **Candidate Submission／Validation／Promotion／Binding**：Runtime 可提出低信任 Candidate，但不能自行指定可信 owner、generation、validation、promotion、授權狀態；可採 staging、受限函式或**既有** `PostgresCandidateStore` 加權限隔離，**不預先指定新資料表**。Candidate Validator 對實際 bytes 及完整 Scope、request fingerprint、Projection／Contract、政策與來源版本獨立驗證；Promotion 以不可變 bytes／hash／policy revision 建立可供 Grant 使用的 Candidate，不得留下半可信狀態。若 Validation 與 Promotion 分交易，必須以受保護證據綁定完全相同的不可變內容版本，Promotion 重新核對且重查當前政策；Staging 不可直接供 Grant 使用。GC 必須與 Bound Candidate 的 FK／鎖保護相容。
8. **完整性、授權、傳輸是三個不同證明**：`SHA256(bytes)==candidate_hash` 只證明資料完整性；符合核准 Projection／Scope／Contract／來源才是政策授權；送入 ASGI 的 status／headers／body 不變快照才是傳輸邊界。任何後置 Middleware 變更使原 Admission 失效，不能以原 hash 重新授權，不能宣稱 TLS／Client exactly-once delivery。
9. `domain_validation='passed'`／`contract_validation='passed'` 僅可作為 Runtime 觀察與稽核；若 Authorizer 無法取得獨立可信的必要驗證結果，必須 Fail-Closed，**不得採取「限速臨時信任 Runtime」作為正式通路**。

來源、Writer、Reader、信任等級與 Source of Truth 細項見 [Evidence Authority Matrix](../security/world-db/evidence-authority-matrix.md)。

## 5. 角色、函式與部署限制

**擬議角色**（名稱與精確 GRANT 尚待 DBA 核准）：`mirage_http_runtime`、`mirage_ingress_verifier`、`mirage_authorizer`、`mirage_replay_gc`、`mirage_control_admin`、`mirage_schema_owner`（NOLOGIN）。

- Runtime／Verifier／Authorizer 以**獨立憑證、獨立 DSN、獨立連線池／執行身分**登入。禁止在共享 Runtime 連線池以 `SET ROLE` 切換特權；Runtime 不得是特權 Role 成員、不可透過角色繼承或 Pool 重用取得權限。
- 使用 Secret 掛載／OS 身分限制與 `pg_hba.conf`／網路 ACL 的組合；單機環境可採受限檔案與不同 Linux 帳號。這些能降低 R1／部分 R3，**不能聲稱抵抗 R5**。
- 逐項撤銷 Runtime 對 `response_admissions`、`generation_controls`、`session_heads`、受保護 Receipt／Binding／Replay／GC 等關鍵欄位的直接越權 DML；保留合理 World 原生交易所需的最低操作。沒有明確審核前不要執行破壞性 REVOKE。
- 角色權限必須以 [Role × Operation × Read／Write／Execute／SET ROLE 矩陣](../security/world-db/threat-capability-matrix.md) 作為可驗收合約；Verifier 不可建立 Binding，Authorizer 不可寫入 Receipt，Candidate Validator 不能取得 Key／Receipt Writer 身分。`SECURITY INVOKER` **不會憑空提升** Runtime 寫入受保護資料表的權限。
- 特權 `SECURITY DEFINER`：固定可信 `search_path`（例如 `pg_catalog, mirage_secure, pg_temp`，`pg_temp` 放最後），完整 schema-qualified 引用；可信 schema 無 Runtime `CREATE`；新函式在授權前撤銷 `PUBLIC EXECUTE`；函式 owner 不可供 Runtime 直接登入／切換；僅接受可驗證且窄化的狀態轉移輸入；DML 函式標註 `VOLATILE PARALLEL UNSAFE` 供審計。不要將函式預設 volatility／parallel safety 誤說成 PostgreSQL 會自動設為 IMMUTABLE。
- 檢查 Runtime 是否取得 `SUPERUSER`、`BYPASSRLS`、`CREATEROLE`、`pg_execute_server_program`、不當 Extension／Large Object 權限；`COPY ... FROM PROGRAM` **不是一般函式 EXECUTE 權限**，不能把它當成必然可利用路徑。
- 角色 CONNECTION LIMIT、`lock_timeout`、`idle_in_transaction_session_timeout`、控制面保留連線與緊急撤銷能力是**可用性／營運防線**，不是可以獨立阻止持有 Runtime 身分的攻擊者之完整安全邊界。PostgreSQL 17 `reserved_connections` 能否用、誰具 `pg_use_reserved_connections`、配額是否足夠須實際驗證。

## 6. 安全交易、鎖、狀態與截止時間

### 6.1 交易切割

| 交易 | 原子責任 | 明確不保證 |
| --- | --- | --- |
| **IngressTx** | 驗證 JWS 成功後，在同一 DB 交易消費 JTI、建立 Receipt；失敗兩者一起 rollback | 不包含尚未生成的 Candidate；沒有 Admission 不代表可恢復 JTI |
| **CandidatePromotionTx** | 原子固定經受保護驗證的 Candidate bytes／Scope／Contract／Policy Revision 與 Promotion 結果；驗證證據不能挪用於其他 bytes | Staging 提交不等於 Promotion；失敗不得留下可被 Grant 使用的資料 |
| **GrantTx** | 鎖可信 Receipt／Candidate，核對 Scope、摘要、當前 Generation／Session／Revocation，原子建立唯一 Binding 與 Admission | 不與已提交 World Mutation、外部 API 共用交易 |
| **AuthorizeTx** | 對同一 Admission 重新檢查動態狀態與期限，再進入 `SEND_AUTHORIZED` | 歷史 Receipt 不能取代現時查核 |
| **StartSendTx** | 同一受保護交易重新檢查 Session Head、Key、Profile、Generation、Receipt、owner、時間與 Envelope，記錄 `SEND_STARTED` | DB 記錄不等於 HTTP bytes 已送達客戶端 |
| **Pre-send block** | 原子地從尚未開始發送的 Admission 轉 `ABANDONED`，並保存安全拒絕原因 | 不能把 SEND_STARTED 的未知傳輸改成確定未發送 |

`AuthorizeTx`／`StartSendTx` 必須使用 Receipt／Binding 自己保存的 `issuer`、`kid`、Session scope/epoch、Generation 作**重新查核的索引**，不可使用 Runtime 傳來的替代識別；Receipt 歷史驗證成功**沒有永久授權效力**。

### 6.2 並行與線性化點

目前程式 `postgres_admission._lock_admission` 有 **Admission → Generation → Profile** 鎖序，`session._resolve_in_transaction` 有 **Session Head →（舊）Generation** 鎖序。若在 StartSend 的 Generation lock **之後**追加 Session Head lock，可能產生 `Session Head ↔ Generation` 循環等待，**不能盲目加一條 SQL 當作修復**。

新的鎖順序、Isolation、Revocation 與 StartSend 誰先成立、Snapshot 時機、超時及可重試錯誤，均依 [交易／鎖矩陣](../security/world-db/transaction-lock-matrix.md) 完成 Owner／DBA 審查及真實 PostgreSQL 並行測試後定稿。任何切換 `hashtextextended('mirage-profile:'...)`、Key namespace 或 Advisory Lock Key 的變更都要獨立審核，不能在新舊版本混用鍵值時滾動升級。

**建議政策**：較新 Session epoch 已提交後，舊 epoch 尚未 `SEND_STARTED` 的 Admission 不得開始發送；已 `SEND_STARTED` 的外部傳輸不可事後回收。撤銷與 StartSend 競爭時依正式鎖／提交順序定義勝負；無法確認目前安全狀態時禁止新的 `SEND_AUTHORIZED`、`SEND_STARTED`。

### 6.3 Token、Grant、Transmission Window

建議使用三個語意分離的期限：`token_expiry`、`grant_deadline`、`start_send_deadline`。其中 `WorldSnapshot.expires_at` **是既有世界快照期限**，不是未經證實的 Generation-expiry 欄位。

```text
grant_deadline <= token_expiry  （不以 Receipt 延長新 Grant）
start_send_deadline = min(
    token_expiry + approved_grace,
    grant_time + approved_transmission_window,
    authoritative_world_snapshot_expiry (若政策要求且有受保護資料)
)
```

`approved_grace`、window、clock skew、比較精度與是否准許 Token 到期後開始傳輸仍為 **Owner＋Security Blocking Policy Decision**；沒有核准即採 `approved_grace=0` 的保守政策。不得接受 Runtime 傳入的任意 world expiry。

DB 須在取得必要鎖後，以**實際檢查時間**評估（可用 `clock_timestamp()`，不要誤用交易開始固定的 `now()`），`current_time >= deadline` 拒絕；應明確區分 DB StartSend 判定時點與 ASGI 第一個 byte 交接時間，並限制兩者間的延遲。

### 6.4 Admission 與 HTTP 傳輸結果

沿用既有 Admission State：`GRANTED`、`CLAIMED`、`SEND_AUTHORIZED`、`SEND_STARTED`、`SEND_COMPLETED`、`SEND_FAILED`、`SEND_PARTIAL_FAILURE`、`ABANDONED`、`EXPIRED`；**不因 audit reason 增加新核心狀態**。

- `SEND_STARTED` 之前，Envelope 不符：窄化特權操作原子轉 `ABANDONED` 並寫入 `CONTENT_MISMATCH` 安全稽核；不可寫入假的 `send_started`。
- 已開始且確知失敗：依既有失敗終態記錄；已開始但無法確定結果：保留 `SEND_STARTED`／`UNRESOLVED` 對帳，不假設沒發送，不自動重送。
- `SEND_STARTED` 記錄的是 DB 許可／開始發送意圖；不能推導 ASGI 已嘗試、TCP/TLS 已送達或 Client 收到。這四種事件應分開。
- World Commit 成功但 Admission 失敗，**可以存在**且不能藉 HTTP 重試重做 Mutation；需以 `commit_attempt_id`、request fingerprint、Session／Generation 和既有 World Operation Result 對帳。`WORLD_COMMITTED_ADMISSION_UNAVAILABLE` 僅是提議的 **Reconciliation Classification（跨交易對帳分類）**，不是既有 World Commit／Admission enum。

## 7. Replay、未知 COMMIT、GC 與 Restore

- **Replay**：`replay_entries` 僅保存**已消費** JTI；未消費 JTI 無需建立 GC 條目。有效 Receipt 必須對應同交易提交的墓碑，只有墓碑／只有 Receipt 都必須拒絕並告警，不能自行補寫授權證據。
- **保留**：JTI、Receipt、Binding、Operation Receipt 應保留到 Token 最長可能可接受時間、skew、安全延遲、重試／對帳及備份還原安全界限全部結束；使用經核准公式與政策參數，例如驗證過的 `exp + skew + restore_margin` 與 `consume_time + max_lifetime + 2×skew + 2×uncertainty` 取保守上限。`UNRESOLVED` 不得僅以逾時自動視為 `ABORTED`。
- **未知 COMMIT**：Operation ID 必須在副作用前可重建或由受保護來源發給呼叫者；它是**相關鍵，不是授權憑證**。Receipt/Operation Result 在相同交易內持久化、唯一 `operation_id`＋輸入摘要綁定。查到同 ID 同 digest 的已提交結果可唯讀恢復；查無**不能證明交易未提交**，應保持 `UNVERIFIABLE`，不得盲目重授權／重消費 JTI／重發送。
- **外部副作用**：World Mutation、Medusa／Cart API 執行與 Admission 不保證跨交易 exactly-once；由 Owner 核准「業務提交、回應沒開始」語意。必要時以可查回 Result／Outbox／冪等業務操作；不可查回者必須記錄 at-most-once、人工對帳或補償限制。
- **Restore Quarantine**：單主機建議採 World DB 還原後強制隔離，正式發送關閉；只有在 Replay／Receipt／Key Revocation／Session／Generation 不倒退能被核實，或所有受影響舊 Token 都已確定超出可接受窗口後，才可解除。換公鑰**不能自動代替撤銷舊 Token**。備份／還原必須驗證隔離開關不可因快照回退而消失；無權威證明時持續 NO-GO。

## 8. 版本相容、部署與回滾

1. **Expand**：在隔離 DB 建立新受保護資料、角色、Receipt／Binding／Operation Receipt 與窄介面，原正式發送保持 OFF。`production trusted-send mode: DISABLED` 是**要求的安全政策**，在查明實際控制面／功能開關、可寫身分、還原後狀態與強制執行證據前，**不能宣稱它是已經存在、不可繞過的開關**。
2. **Dual-read／Observe-only**：比對新舊策略，但不得因新策略失敗降級成信任 Runtime 宣告的放行路徑。
3. **Preflight Gate**：部署前與 Runtime 啟動時檢查 Schema／Function Signature／Role ACL／Version／Credential 安置，任一不相容則不能進入正式發送模式；CI 與實例內真實非特權連線共同驗收。
4. **Cutover**：由 Mirage Owner、DBA、Security、Release Approver 明確簽核後才允許安排；若鎖鍵或不可兼容狀態機更動，不承諾零停機滾動，應停流排空再切換。
5. **Rollback**：可回復程式的 Observe-only／正式發送 OFF；**不可**自動撤銷 Receipt/Replay 墓碑、放鬆 ACL、恢復已撤銷金鑰或讓舊 Epoch 復活。回滾程序需在隔離 PG 與還原演練中驗證。

## 9. 驗收、證據與失效處置

完整測試 IDs、前置 DB Role／pg_hba／Connection Pool、預期 SQLSTATE、並行故障注入與證據責任見 [Verification Plan](../security/world-db/verification-plan.md)。最低 Release Gate：

- 以**真正 `SESSION_USER=mirage_http_runtime` 的獨立 SCRAM 連線**重跑原三項越權，全部須遭拒，並檢查 effective privileges／Role inheritance／`SET ROLE`／`BYPASSRLS`；單純使用 superuser fixture 的綠燈無效。
- Runtime 無法偽造 Receipt 或直接把 Admission 改 `SEND_AUTHORIZED`；Verifier 不能為無效 JWS、錯請求、舊 epoch、已撤銷 Token 發有效 Receipt。
- Replay+Receipt 必須同一 PostgreSQL database、同一 physical connection、同一 IngressTx；Grant 的 Binding+Admission 同交易；已綁 Receipt 不可重用於其他 Candidate。鎖循環檢查、Epoch/Key rotation/revocation 的並行勝負、期限跨鎖等待及 Envelope mismatch 實測。
- 未知 COMMIT、World 成功但 Admission 失敗、SEND_STARTED 之後失聯、GC／Restore Quarantine、Schema／ACL 不相容與故障恢復實測。
- 失效**可由系統偵測**者立即 Fail-Closed；Secret 外洩、容器掛載錯誤、主機權限遭侵害等**需監控／人工判定**者應停止正式發送、撤銷／輪替憑證、隔離、保留證據，不可謊稱應用能自動證明未外洩。

## 10. Blocking Open Decisions、關閉標準與審核

| ID | 必須裁決／確認 | 負責角色 | 狀態 |
| --- | --- | --- | --- |
| BD-01 | Verifier 獨立部署、密鑰、DB／網路存取與最小可用授權通路 | Mirage Owner＋Security＋DBA | OPEN |
| BD-02 | 各交易實際鎖順序／隔離級別，Session epoch & Revocation 勝負，受限函式介面 | Mirage Owner＋DBA | OPEN |
| BD-03 | Token 過期後是否允許短 Transmission Window、grace／skew／時間語意 | Mirage Owner＋Security | OPEN |
| BD-04 | World Commit 成功但 Admission 失敗的 API 與 Recovery；外部副作用是否可查回 | Mirage Owner＋API Owner | OPEN |
| BD-05 | JTI/Receipt/Binding 保留公式、Restore Quarantine 的外部安全錨點、實際恢復操作 | DBA＋Security＋Operations | OPEN |
| BD-06 | R3/R4/R5 風險接受界線、Credential Rotation、實際發送不可變 snapshot | Security＋Mirage Owner | OPEN |
| BD-07 | Candidate GC 與 Grant 的 FK／Row Lock／Advisory 具體方案、完整 Schema 相容 | DBA＋Mirage Owner | OPEN |
| BD-08 | 正式接受 Request Provenance 語意 A 的範圍與殘餘風險；語意 B 另案 | Security＋Mirage Owner | OPEN |
| BD-09 | Candidate Validator 的可信身分／政策來源及 Validation→Promotion 空窗處理 | Mirage Owner＋Security＋DBA | OPEN |
| BD-10 | 正式發送 DISABLED 的實際控制面、Runtime 權限、Restore 後不可倒退的隔離機制 | Release Approver＋Security＋Operations | OPEN |

**關閉條件**：上述政策決策經審查、部署／密鑰邊界經驗證、負面與正向真實 PG 測試及恢復證據完整、Owner/Security/Release 核准；之後才能考慮將 `MIR-SEC-WORLD-001` 由 OPEN 轉為已修復。PR 合併、CI 綠燈或沒有外部攻擊回報**均不足以關閉**。

**維持**：`Architecture: Proposed | MIR-SEC-WORLD-001: OPEN | MSDSS P2: NO-GO | production trusted-send mode: DISABLED (policy requirement; enforcement evidence pending)`。

## 11. 文件及版本追溯

- [決策歷史與被否決替代方案](../security/world-db/decisions-log.md)
- [權威證據矩陣](../security/world-db/evidence-authority-matrix.md)
- [交易、鎖、錯誤與一致性矩陣](../security/world-db/transaction-lock-matrix.md)
- [威脅能力與覆蓋矩陣](../security/world-db/threat-capability-matrix.md)
- [測試／驗收計畫](../security/world-db/verification-plan.md)
- [Mirage World Runtime 現有行為](../world-runtime.md)；[Trusted Session](../trusted-session.md)；[Key Revocation](../key-revocation.md)；[World Operation Result](../commit-results.md)
- [MSDSS P2 權限審查證據：PR #23](https://github.com/IAN40070510/MSDSS/pull/23)（跨服務驗收；不代表 Mirage 已修復）

### 版本歷史

| 版本 | 日期 | 內容 |
| --- | --- | --- |
| v0.1 | 2026-11-21 | 首次將前幾輪審查整理成可審查 Architecture Draft；所有 proposed 控制、未決政策與未執行測試均明確標示 |
| v0.2 | 2026-11-21 | 收斂 Trusted Request 語意 A、Verifier Context／單一連線協調、Candidate 驗證與 Promotion、Rollback／Unknown COMMIT、角色矩陣與正式發送停用控制；**仍為 Proposed** |
