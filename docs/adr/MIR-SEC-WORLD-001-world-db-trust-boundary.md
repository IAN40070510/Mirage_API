# MIR-SEC-WORLD-001 — World DB 信任邊界與受保護發送授權（Architecture Draft）

> 本文件以 Mirage 原生授權契約為維護範圍。歷史跨專案整合證據已移交保存，原生安全要求與驗收狀態維持原紀錄。

> **後續決策優先適用（2026-11-21）**：[獨立 Restore Anchor Option B](../security/world-db/restore-anchor-option-b.md) 已核准、[BD-05 自動驗證解禁](../security/world-db/bd-05-restore-quarantine-release.md) 已採納、[BD-11 鎖後 Deadline 語意](../security/world-db/bd-11-deadline-semantics.md) 已決定。本文後續若仍將 BD-05／BD-11 寫成 OPEN 或要求每次 Operator Release Certificate，視為歷史草稿未同步；**以上專用決策文件較新並優先**。完整修復與效能議題另見 [整合總表](../security/world-db/remediation-and-performance-register.md)。上述決策皆不代表已實作或已驗收。

> **2026-11-24 新人員驗收制度（D-73）**：Mirage Owner `IAN40070510` 已採納
> [Solo Developer Security Acceptance v1](../security/world-db/solo-developer-security-acceptance-v1.md)。
> 本文歷史上要求 DBA／Security／Release Approver **四方人工簽核**的敘述，
> 改由 Owner 在 G3b～G6 全部技術證據 PASS 後作可追溯最終核准；
> 外部獨立人工審查為建議項。**獨立 DB Role／Validator／Fence、全部技術 Gate、
> Mirage release 個別驗收仍必須遵守；採納制度不等於放行。

> **2026-11-25 D-74 新產品部署範圍（優先於本文歷史外部 Fence 必備敘述）**：
> Mirage 維持單主機完整功能；外部 Restore Fence 為選配的跨整機／跨復原域
> 防回滾強化 Profile。現行 Option B 與 BD-05 的外部最高 Head、跨庫對帳及
> 自動證據解禁 MUST，在 **啟用 external_fence** 時全部保留；單機標準模式
> 不宣稱能防止整台 VM 靜默回滾，仍需完整 G3b/G4/G6／單機 G5 安全驗收及
> Owner 風險揭露與最終 Release 核准。完整界線與未測案例見
> [D-74 Deployment Profiles](../security/world-db/single-node-restore-profiles.md)。
> **本輪是契約範圍變更，尚非原生程式實作／可信發送核准。****

| 欄位 | 值 |
| --- | --- |
| ADR 版本 | **v0.2 Contract Freeze candidate**（2026-11-21；Proposed、未核准） |
| ADR 所在分支 | `docs/mir-sec-world-001-adr-v0.1`（保留舊名稱與 v0.1→v0.2 歷史；Mirage `main` 尚未包含；本次 Draft PR HEAD 以 GitHub 為準） |
| Document commit | 以 GitHub Draft PR 的實際 HEAD／`git rev-parse HEAD` 取得**完整 SHA**；不可在同一追蹤檔案中內嵌「本次自身 Commit SHA」，否則修改檔案本身就會改變 SHA；前置 Commit 另列作溯源，不代表目前版本 |
| World DB authority remediation | **NOT_IMPLEMENTED**（實作狀態） |
| 新版安全驗收 | **NOT_RUN**（測試狀態；不得與既有缺口重現測試混算） |
| Production DECEIVE | **OFF**（政策要求；正式部署強制證據尚缺） |
| Architecture | **Proposed；尚未完成完整技術驗收及特定 Release 的 Owner 最終核准**（人員責任依 D-73） |
| Security weakness | **MIR-SEC-WORLD-001 — OPEN／尚未修復** |
| 關聯驗收 | Mirage release — NO-GO，等待原生安全矩陣與 Owner 對固定版本驗收 |
| Protocol baseline（Mirage Protocol Freeze v1） | 以本 ADR 的授權、Snapshot、deadline 與恢復契約為準，原生符合性依固定 SHA 獨立驗收 |
| Implementation baseline（Mirage source） | **固定原始碼分析 SHA**：Mirage upstream `main` `88dc2008fd35a2d3873949a769653dc9f18e8980`；正式 Owner 採納時須另外核准適用版本。文件前置 HEAD `003c918f142296588d2fe14b70fafe3cc5cf8458` 不是 Mirage source baseline |
| Mirage Owner adoption | **ACCEPTED（2026-11-21）**；使用者已正式選擇授權一致性優先及採納 Mirage Protocol Freeze v1，見 [D-68](../security/world-db/decisions-log.md)；**不代表**原生符合性或 DBA／Security 簽核 |
| G1 Verifier／Authorizer 部署隔離選擇 | **同機獨立容器／OS 身分（D-69，2026-11-21）**；每服務不同 SCRAM DB Role／Secret／DSN，禁止共池或 Runtime `SET ROLE`；仍須實測與部署簽核，R5 主機控制不涵蓋 |
| Candidate 授權遷移策略 | **Clean Cutover（D-70，2026-11-21）**；保留原生 Candidate 生成器，但舊的 `candidate_records → grant()` 不得作為正式可信發送的授權入口；新路徑尚未完成，**NOT_IMPLEMENTED** |
| Mirage native conformance | **NOT_RUN**（`WORLD-PROTOCOL-MATRIX-01`／`WORLD-PROTOCOL-01`）；固定 `start_send()` 有**已觀察到的局部差異**，不得以該單點推論完整合約測試已執行或已有全域符合性結論 |
| 來源 | 多輪安全審查及兩個不同 Repo/SHA 的唯讀核對；**非已實作／通過的安全驗證** |
| 變更界線 | 文件提案；**不代表已修改 Runtime、資料庫 ACL、staging、金鑰或 production 開關** |
| 審核責任 | **D-73 已採納**：Owner `IAN40070510` 承擔 DBA／Security／Release 技術責任並在全部技術 Gate PASS 後獨立作最終決議；外部人工 Reviewer 建議但非本個人專案一般阻擋條件。Mirage release 若有獨立服務／契約門檻仍須另驗。 |

> **一句話決策方向**：採方案 B，讓 PostgreSQL／獨立可信角色強制關鍵授權狀態轉移；每個不可分割的安全狀態轉移使用同一個 PostgreSQL 交易，但**不假裝整個 HTTP、World Mutation 與外部副作用能共用一個交易**。

## 1. 問題、實證與未實證主張


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

**Architecture Proposed：選 B；Owner 已採納方向，但尚未通過全部技術驗收與特定版本 Release 核准（D-73）。** 本 ADR 不是直接套用原始 Assessment Ledger 的 EXECUTE-only 權限。World Runtime 仍有合法 SELECT／INSERT／UPDATE 與部分 DELETE 使用情境；應**按資料表、欄位與操作**逐項拆權限，不能整庫撤銷 DML 造成既有交易壞掉。

## 4. 權威證據與不可變綁定（強制合約）

受保護授權鏈是 `Admission → Grant Binding → Ingress Receipt → Replay Tombstone`。四者是**不同證據**，任一張表存在都不能單獨證明整條鏈有效。

1. **Ingress Verifier 的驗證責任／來源語意 A**：只收原始 JWS 與必要、可重新計算的請求資料；不得接受 Runtime 提供的 `verified=true`、issuer 覆寫、驗證結果、簽發時間、政策版本或已核准標記。自行驗證簽章、Claims、issuer、audience、deployment/environment、request fingerprint、時間、Session epoch、金鑰信任與撤銷。**本輪只承諾「JWS 與所提交的 Canonical Request Snapshot 相符」**，不宣稱 Runtime 提交的快照必然等於實際入口 HTTP 請求。獨立入口來源證明（Gateway 簽章、受控 IPC 或可信入口）是未來語意 B／R4 設計；不因此放寬後續 Grant／StartSend 的同一 Request Fingerprint Binding。
2. **Receipt 的信任根與 Verified Context**：可選獨立 Verifier 服務及受限 DB Role，或受保護 DB 驗證程序；必須證明 Runtime DB 角色無法建造／改寫 Receipt、登入 Verifier 身分、取得其 Secret，亦無法藉過度寬泛的 SECURITY DEFINER 函式偽造結果。Immutable `VerifiedContext` **只約束同一可信 Verifier 程序內部的呼叫路徑**，不是 PostgreSQL 能自行辨識的密碼學證明；DB 的強制邊界是驗證工作負責的專用登入 Role、ACL、受限 Writer Function 與受控 Transaction Context。Receipt Writer **不能**因物件型別／JSON 欄位符合預期就信任來源，亦不得接受外部提供的 `verified=true`、完整「已驗證 claims」、政策版本或自訂時間。`VerifiedContext` 不可直接序列化穿過不可信程序／服務邊界，Runtime 也不得重建同名 Context。**若未來拆成跨服務寫入**，須另立經認證與防重放的協定（例如 mTLS、簽章、唯一 request ID、固定版本與接收端驗證）；本輪不假定該協定已存在。
3. **同資料庫原子性與唯一交易協調器**：同一 PostgreSQL **database、physical connection、IngressTx** 內取得 Key Revocation Guard、依 DB 權威時間重新檢查期限／撤銷、原子插入 Replay Tombstone 與 Ingress Receipt；僅交易協調器可 commit/rollback。靜態 JWS 驗證的不可變結果不得由呼叫者任意注入 Claims／JSON／policy／時間；Replay Store、Key Revocation Store、Receipt Writer 的受保護交易介面不得自行開第二條連線或在中途 commit。例外須 rollback 並清理連線池 Session 狀態。**現行** `TrustedSessionVerifier.verify()`、`PostgresReplayStore.consume()` 與 `KeyRevocationRegistry.guard()` 分別管理連線／消費，尚未達成本合約。若未來拆分 DB，必須另立安全協定，不可沿用此原子性聲明。
4. **Ingress 與 Candidate 的時間順序**：Ingress 發生時 Candidate 通常**尚未生成**；Receipt 先綁定已驗證 Claims、request fingerprint 與候選意圖／允許的 Scope，**不得偽稱此時已驗證未來的 Candidate hash**。GrantTx 再將不可變的實際 Candidate、Envelope v1 hash、Session、Generation、Projection 與 Receipt **原子綁定**到 Admission。
5. **不可挪用／唯一性**：`(issuer,audience,jti)` 確保 Token 一次性消費；Receipt ID、Operation ID、Admission ID 與 Candidate ID 各有不同語意與完整 Scope。Receipt 最多有一筆有效 Grant Binding；同一 Receipt 不得換 Candidate／Generation；同一 Operation ID 配不同 `input_digest` 必須拒絕。使用 DB FK、UNIQUE、鎖與權限強制，而非只相信 Python。
6. **「已使用」定義**：StartSend 時 Receipt **原本就已綁定目前 Admission**。不得因 `used=true` 一律拒絕；必須拒絕的是**其他 Admission 的重綁**，或**尚未獲 SEND_AUTHORIZED 前**已被撤銷的授權請求；授權已提交後的 Policy／Emergency 變化不可在 StartSend 二次否決。StartSend 仍會拒絕 owner／期限／single-use／Snapshot execution 失效。
7. **Candidate Submission／Validation／Promotion／Binding**：Runtime 可提出低信任 Candidate，但不能自行指定可信 owner、generation、validation、promotion、授權狀態；可採 staging、受限函式或**既有** `PostgresCandidateStore` 加權限隔離，**不預先指定新資料表**。Candidate Validator 對實際 bytes 及完整 Scope、request fingerprint、Projection／Contract、政策與來源版本獨立驗證。**首選短交易 Promotion**：先鎖定受 DB 保護的 Candidate 版本並讀取確定 bytes，依可信政策完成必要驗證，原子固定 Promotion；若昂貴的 Projection／Contract 檢查必須在鎖外完成，須由可信 Validator 產生綁定 DB 產生且不可變的 Candidate Version、Envelope hash、Scope、`projection_contract_hash`、`policy_revision`、`source_spec_sha256`、validator identity／algorithm version／驗證時間的證據；如跨信任邊界還需可驗的來源認證。Promotion 的**短**交易重新鎖定並核對版本、bytes hash、Scope 與政策可用性，再建立可信 Candidate。Runtime 提供的版本整數或 `validated=true` 不算安全證據。Staging 不可直接供 Grant 使用，失敗不留下半可信物件。
8. **完整性、授權、傳輸是三個不同證明**：`SHA256(bytes)==candidate_hash` 只證明資料完整性；符合核准 Projection／Scope／Contract／來源才是政策授權；送入 ASGI 的 status／headers／body 不變快照才是傳輸邊界。任何後置 Middleware 變更使原 Admission 失效，不能以原 hash 重新授權，不能宣稱 TLS／Client exactly-once delivery。
9. `domain_validation='passed'`／`contract_validation='passed'` 僅可作為 Runtime 觀察與稽核；若 Authorizer 無法取得獨立可信的必要驗證結果，必須 Fail-Closed，**不得採取「限速臨時信任 Runtime」作為正式通路**。
10. **政策狀態與時間語意**：版本升級／Key Rotation **不自動等於撤銷**。由受保護 Policy Authority 明定 Revision 的 ACTIVE／禁止新 Grant／REVOKED 狀態及過渡相容規則；Promotion／Grant 必須依當下核准政策，AuthorizeTx **在 SEND_AUTHORIZED COMMIT 前**重新確認 Revision／撤銷；StartSendTx **不得**二次查核 Policy／Emergency／Epoch／Generation 作授權。撤銷若晚於授權提交不可回溯撤銷；Payload／Snapshot 缺失屬執行條件，不是第二次授權。不能僅因數字上有「最新版」便擅自否定或放行既有 Candidate。
11. **Candidate GC、參照及資料保留**：優先以受保護 FK／UNIQUE 與相容 Row Lock 防 GC 刪除被有效 Binding 引用的 Candidate，但現行 `candidate_records` 使用完整 Scope＋`candidate_ref`，**不應憑空假設全域唯一 `candidate_id`**。FK 必須指向實際權威複合鍵；`ON DELETE RESTRICT`／等效約束不得被 Runtime 改寫。**FK 不等於完整 GC 策略**：若 Binding 永久保留，無限期保存原始 Payload 將造成資料保留／容量風險；可分離不可變審計 Metadata／Hash 與短期 Payload，或依經核准的終態與保留窗口安排受限清理，絕不清除仍可 StartSend／UNRESOLVED／對帳所需的 bytes 或證據。`protected_refs` 僅供效能優化，不能作唯一刪除依據。

來源、Writer、Reader、信任等級與 Source of Truth 細項見 [Evidence Authority Matrix](../security/world-db/evidence-authority-matrix.md)。

## 5. 角色、函式與部署限制

**擬議角色**（名稱與精確 GRANT 尚待 DBA 核准）：`mirage_http_runtime`、`mirage_ingress_verifier`、`mirage_authorizer`、`mirage_replay_gc`、`mirage_control_admin`、`mirage_schema_owner`（NOLOGIN）。

- Runtime／Verifier／Authorizer 以**獨立憑證、獨立 DSN、獨立連線池／執行身分**登入。禁止在共享 Runtime 連線池以 `SET ROLE` 切換特權；Runtime 不得是 Verifier／Authorizer Role 成員、不可透過角色繼承或 Pool 重用取得權限。**`NOINHERIT` 不代表不能 `SET ROLE`**：必須查核 `pg_auth_members` 的 `set_option`、`inherit_option`、`admin_option` 及**間接 membership 鏈**，並在真實 Runtime 登入連線實測 `SET ROLE`、`SET SESSION AUTHORIZATION`、`PUBLIC EXECUTE` 與 schema `USAGE`；不能只看 `rolinherit`。
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
| **AuthorizeTx** | 受保護交易查核當前 Policy／Emergency／Session／Generation／Receipt／Snapshot Binding 及期限；**COMMIT SEND_AUTHORIZED 是唯一授權線性化點** | 決策時間不是 COMMIT；未知提交不可推定授權 |
| **StartSendTx** | 只核對已提交授權、可信 owner、期限、single-use、精確 Snapshot Binding／完整性／Purge Fence；原子提交 `SEND_STARTED` 和安全必要 Audit | **不得重作 Policy／Emergency／Session／Key 授權**；提交確認後才可送出第一個 ASGI 訊息，DB 記錄不等於客戶端收到 |
| **Pre-send block** | 尚未 SEND_STARTED 時持久化不可重試 execution fence，可將執行狀態轉 ABANDONED，**但必須保留先前 SEND_AUTHORIZED 修訂與不可變授權歷史**；原子保存安全拒絕原因 | 不得把既有授權抹除、宣稱政策撤銷已回溯生效；未知 SEND_STARTED 不得偽造「未發送」 |

`AuthorizeTx` 用受保護 Receipt／Binding 取得可信 issuer、kid、Session scope/epoch、Generation 和 Snapshot Identity，不能信 Runtime 自填識別。`StartSendTx` 僅驗同一已授權 Snapshot 與執行條件；Receipt 歷史成功不授予**新的**發送權限，但已提交授權不因之後的撤銷回溯失效。

### 6.2 並行與線性化點

目前程式 `postgres_admission._lock_admission` 有 **Admission → Generation → Profile** 鎖序，`session._resolve_in_transaction` 有 **Session Head →（舊）Generation** 鎖序。若在 StartSend 的 Generation lock **之後**追加 Session Head lock，可能產生 `Session Head ↔ Generation` 循環等待，**不能盲目加一條 SQL 當作修復**。

新的鎖順序、Isolation、Revocation 與 **AuthorizeSend** 誰先提交、Snapshot 時機、超時及可重試錯誤，均依 [交易／鎖矩陣](../security/world-db/transaction-lock-matrix.md) 完成 Owner／DBA 審查及真實 PostgreSQL 並行測試後定稿。**`Candidate → Binding／Admission` 只能先視為 Grant／GC 的局部排序建議**；既有 Grant 先鎖 Generation、Session 切換先鎖 Session Head，若把 Candidate 鎖硬塞到它們前面，可能另造循環；須確認全路徑 DAG 與 FK 自動鎖後再訂全域順序。任何切換 `hashtextextended('mirage-profile:'...)`、Key namespace 或 Advisory Lock Key 的變更都要獨立審核，不能在新舊版本混用鍵值時滾動升級。

**Protocol Freeze v1**：較新 epoch／Emergency 先 COMMIT → 拒絕後續 SEND_AUTHORIZED；SEND_AUTHORIZED 先 COMMIT → 保留授權，StartSend 不重查 Head／Policy／Emergency。Snapshot 無法安全執行可以拒絕傳輸，但不可假裝是授權被撤銷。完整鎖圖／FK 隱含鎖仍待真 PG 驗證。

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

**Deadline Matrix**（Mirage Protocol Freeze v1 目標契約）：Claim 檢查 `authorization_deadline`；AuthorizeSend 及 StartSend 檢查 `transmission_deadline`；每段 ASGI 發送仍受 transmission deadline 限制。每個受保護交易取得必要鎖後**只從 DB 取得一次 decision_time**，同一交易全部期限／GC／Lease 使用同一值並持久化。`decision_time < deadline` 是判定時間有效，**不是** COMMIT 保證早於 deadline；SEND_AUTHORIZED 的 COMMIT 仍是唯一授權生效點。未知 COMMIT、DB 時鐘倒退／不可驗證、跨 DB skew 均 Fail-Closed；Runtime 提供的 now 僅可診斷。

### 6.4 Admission 與 HTTP 傳輸結果

沿用既有 Admission State：`GRANTED`、`CLAIMED`、`SEND_AUTHORIZED`、`SEND_STARTED`、`SEND_COMPLETED`、`SEND_FAILED`、`SEND_PARTIAL_FAILURE`、`ABANDONED`、`EXPIRED`；**不因 audit reason 增加新核心狀態**。

- `SEND_STARTED` 之前，Envelope 不符：窄化特權操作原子轉 `ABANDONED` 並寫入 `CONTENT_MISMATCH` 安全稽核；不可寫入假的 `send_started`。
- 已開始且確知失敗：依既有失敗終態記錄；已開始但無法確定結果：保留 `SEND_STARTED`／`UNRESOLVED` 對帳，不假設沒發送，不自動重送。
- `SEND_STARTED` 記錄的是 DB 許可／開始發送意圖；不能推導 ASGI 已嘗試、TCP/TLS 已送達或 Client 收到。這四種事件應分開。
- World Commit 成功但 Admission 失敗，**可以存在**且不能藉 HTTP 重試重做 Mutation；需以 `commit_attempt_id`、request fingerprint、Session／Generation 和既有 World Operation Result 對帳。`WORLD_COMMITTED_ADMISSION_UNAVAILABLE` 僅是提議的 **Reconciliation Classification（跨交易對帳分類）**，不是既有 World Commit／Admission enum。

## 6.5 v0.2 Contract Freeze：決定性受保護合約（其餘舊措辭不得抵觸）

本節是 v0.2 規範性授權契約。SEND_AUTHORIZED 的 COMMIT 是授權生效點，之後不再以 Policy／Emergency 作第二次授權。StartSend 仍須核對 owner、deadline、single-use、Snapshot 與不可逆 execution-ineligibility fence。Mirage Owner 採納見 D-68，原生符合性與安全修補以固定版本測試證明。

### 6.5.1 Policy、Revocation、Deadlines 和 Send Freeze

**採納更新（D-68，2026-11-21）**：上述「需 Mirage Owner 明確採納」的前提現已由使用者正式決定；原始 upstream 差異仍是歷史證據，獨立實作分支已開始修補。以下 MUST 為目標契約，**原生符合性與 DB 權限安全驗收仍未核准／尚未完成**。

1. **MUST**：`CLAIMED → SEND_AUTHORIZED` 的 **DB COMMIT** 是唯一授權線性化點；Policy／Emergency／Epoch／Generation／Key 撤銷先提交則拒絕之後的授權，授權先提交則**不得回溯撤銷**。如需授權後撤銷，須正式升版 **Protocol Freeze v2** 並另跑競態驗收。
2. **MUST**：Policy Authority 由獨立受保護控制者管理 `ACTIVE`、`NO_NEW_GRANTS`、`REVOKED`；NO_NEW_GRANTS 禁止**新** Grant，舊有效 Grant 在其他條件符合下仍可取得 Send Authorization；REVOKED 禁新 Grant 及尚未提交的 Authorize。`REVOKED` 不可改回 ACTIVE，恢復必須新 Revision；Candidate Validation 只記錄 Revision，不代表已授權。
3. **MUST**：`StartSend` **不**重查 Policy／Emergency／Session Head／Key／Generation 做第二次授權；它只核對已提交授權、可信 claim owner、`transmission_deadline`、single-use、已綁定 Snapshot 的 bytes/hash/version、Snapshot Purge Fence。若內容缺失則 `PAYLOAD_UNAVAILABLE`／`SNAPSHOT_UNAVAILABLE` Fail-Closed（執行條件失效，不是授權撤銷）。**Purge／Execution Fence 僅能由真實、受保護且不可逆的 Snapshot 可用性與 GC 轉移產生**，不得被用作任意改寫的「授權後政策撤銷」旁門；此區別須以 `WORLD-PROTOCOL-02` 驗收。
4. **MUST**：每個受保護交易於全部必要鎖到手後，從權威 DB **一次**取 `decision_time`，記錄並供該交易所有期限／Lease／GC 判斷；`decision_time < deadline` 是**邏輯判定時有效**，不保證 COMMIT 早於期限；`SEND_AUTHORIZED COMMIT` 才是線性化點。Claim 使用 `authorization_deadline`；AuthorizeSend 與 StartSend 使用 `transmission_deadline`；之後每個 ASGI 發送段也檢查後者。**BD-11 未核准前的保守政策**：只以全部必要鎖取得後的單一 DB `decision_time` 作判定；**不得**宣稱 COMMIT-before-deadline 已被滿足；若產品要求此嚴格語意，該正式發送能力維持 DISABLED。COMMIT ACK 不明時，對外**不可憑猜測啟動新 StartSend、重試或發送**，先按原 Operation 對帳；若實際已提交，不得把已發生的授權 COMMIT 假寫成 rollback 或回溯撤銷。時間倒退、權威時鐘不可用／無法判定有效性時禁止**新的**授權與起送；DB 時鐘異常的偵測需要獨立監控／保守下界，不能假設 `clock_timestamp()` 自動單調。**決策時間有效但 COMMIT 跨越 deadline** 的正式語意與可容忍延遲仍待 Owner＋Security＋DBA 裁決，不得暗中變更 Freeze v1。
5. **MUST**：`SEND_STARTED` 與安全必要傳輸 Audit／Snapshot 參照須在**確認 COMMIT** 後才可送第一個 ASGI 訊息。補充 Audit 可進 durable reconciliation queue，但**不得**補造 send_started。已開始輸出後 Audit 失敗 → 結果未知，不得假設傳輸未發生。

### 6.5.2 Operation Identity、外部效果、Restore Fence

6. **MUST**：Operation 在副作用前建立受保護 `OperationIdentity`：`authority_namespace`、`namespace_epoch`、`operation_id`、`input_digest NOT NULL`、`digest_algorithm`、`external_effect_key`、`created_at`、`retention_until`。`UNIQUE(authority_namespace,namespace_epoch,operation_id)`；同 ID 不同 Digest = `OPERATION_DIGEST_CONFLICT` 並無第二筆結果；同 Digest 只能取既有結果或進入對帳。禁止 UPDATE／UPSERT 改寫 Digest 或外部 Key。Namespace／Tenant 由可信 Receipt／權威映射取得，不採 HTTP body／Runtime 參數。
7. **MUST**：`operation_id`、`jti`、`admission_id`、`snapshot_id`、`external_effect_key` 分別表示不同身分。`external_effect_key` 首次 Operation Identity 持久化時固定，不能因 Epoch、Restore、重試或重新簽發 JWS 自動更換；一項 Operation 若有多個不同外部效果，須固定每項效果的 key。新 Namespace Epoch 不證明舊效果已 rollback。
8. **MUST**：Restore **先由 World DB 還原範圍之外的受保護控制面啟用 Quarantine，且須在 Runtime／Sender 接受正式發送前生效**；核對 Operation／World Result、Ingress／Grant Receipt、Transmission Audit、外部 effect status。釋放隔離須提出**不能跟著同一 World DB 備份倒退的安全錨點**（例如獨立受保護 Ledger／Restore Fence／單調世代及其防倒退檢查點），證明其身分、寫入權限、世代單調性，並核對被還原資料與錨點涵蓋的 Tombstone／Revocation／Operation 範圍；單靠「備份內資料彼此一致」或時間戳無法證明其後的墓碑沒有消失。**擬議最小 Fence 證據格式**：`restore_fence_id`、`authority_namespace`、`monotonic_generation`、`covered_database_position`（連同資料庫 timeline／incarnation，單純 LSN 不足以跨 Restore 比較）、`covered_object_operation_digest`、`previous_fence_hash`、`created_at`、`authenticated_checkpoint`。Digest 必須指定**確切涵蓋的表／namespace／事件種類**、canonical encoding、hash algorithm/version 與範圍邊界，至少納入被保護的 Candidate Tombstone、Binding、Operation Identity 與受影響的 Replay／Revocation；外部受保護權威**另保存不可倒退的最新已接受 head/generation**，防止整條 hash chain 連同 head 一起被回放成舊版本。Runtime 不可建立、改寫或降低錨點；獨立恢復權威只接受大於等於已承認狀態且具正確前序／範圍證據的新 checkpoint。**單一 checkpoint 不是未涵蓋資料列的完整性保證**；對帳無法證明的範圍不能據此解禁。錨點遺失、不可驗證或落後時**繼續 Quarantine**，不可用單純等待期限或 Runtime 自報 checkpoint 自動解禁；解除隔離必須留存簽核身分、對帳結果、head、涵蓋範圍與 release certificate。實際錨點型式與復原 release certificate 仍為 BD-05 OPEN。未知提交或外部服務無法對帳時採 at-most-once／持續拒絕或經 Owner 授權人工處置，**不能**自動換 Epoch／新 JWS 重做。`WORLD_COMMITTED_ADMISSION_UNAVAILABLE` 是 **reconciliation classification**，不是新增 AdmissionState。
9. **MUST**：未知 `SEND_STARTED` COMMIT → Sender 不得自行重試、建立新 JWS／Admission／Snapshot 或新 HTTP 傳輸；對帳查到 SEND_STARTED **只證明 DB 已提交**，不證明 ASGI／Proxy／Client 已收。沒有正式核准的 resumable transport，**不可因對帳而新開傳輸**；同一仍活著的 Sender 與原連線可依 Freeze v1 結束原本已開始的傳輸，不能描述為「恢復後重送」。

**Anchor 發布與失敗窗口（BD-05 尚未解決）**：World DB Commit 與外部最新可信 Fence Head 的持久化**不是同一個 PostgreSQL 交易**。若 Tombstone／Binding／Operation 已提交而外部 checkpoint 尚未發布即當機，單看舊 Head 仍無法排除漏記事件。正式實作必須定義「DB 事件提交 → 外部權威 durable checkpoint → 哪些操作可解禁／GC」的順序、在途紀錄／對帳介面與 checkpoint ACK 未知的恢復；**不得只因存在一個有效但落後的錨點就證明所有事件已涵蓋**。這是 Restore Anchor 的跨交易一致性阻擋條件，不以新增服務取代設計證明。

**雙向發布故障契約（`WORLD-RESTORE-PUBLISH-01`，NOT_RUN）**：Anchor 最小記錄 `fence_id`、`authority_namespace`、`monotonic_generation`、`covered_db_position`（含 timeline）、`covered_operation_digest`／覆蓋清單、`previous_fence_digest`、`publication_status`，並由還原範圍外的權威保存不可回退的最高可信 Head；Runtime 不得建立、下調或重設世代。

| 跨系統次序與故障 | 必須保留的安全語意 |
| --- | --- |
| **DB 先 COMMIT，Anchor 發布未完成／ACK 未知** | 不得把舊 checkpoint 當作涵蓋最新 DB 事件。先 Quarantine，依固定 Operation ID／Digest、資料庫提交結果及外部副作用唯讀對帳；無法證明涵蓋範圍不得恢復發送。 |
| **Anchor 先發布，DB 明確 ROLLBACK** | 預發布只能是 `PREPARED`／`UNUSED` 等非業務提交 checkpoint，不得標 `COMMITTED` 或據此創建不存在的 Operation；以受保護冪等 checkpoint 對帳，已發布的單調 Head 不得倒退。 |
| **Anchor 或 DB 結果未知、兩者不同步** | 記錄未知範圍與發佈狀態，持續 Quarantine；外部標記不能代替 DB Commit Receipt，DB 記錄也不能代替外部 durable ACK。 |

此表是待實作的**故障合約**，不是宣稱已解決跨 DB／Anchor 的原子性；可行發布協定與 release certificate 仍是 BD-05 OPEN。

### 6.5.3 Candidate／Snapshot Write-Once、合法狀態與 Purge

**Clean Cutover 決策（D-70，已由使用者選定實作方向；仍待原生驗收）**：

- **保留** `getProduct`、合成 Cart／Inventory、Medusa 的 Candidate 生成、Gate 與 Envelope v1 封裝；不讓新授權改造不必要地重寫業務生成器。
- **停止信任** `trusted_http.admitted()` 現有的 `PostgresCandidateStore.put()` 後直接呼叫 `PostgresAdmissionControl.grant()` 的兩次獨立交易組合。舊 `candidate_records` 只允許受控讀取、對帳或遷移，不得因 ref/hash 已存在就提供新的 `SEND_AUTHORIZED`；既有資料不自動升格為可信版本。
- **唯一新入口** 必須先取得由受保護 Validator／Promotion 固定的完整 Scope、不可變版本、Envelope bytes/hash、Projection/Policy 證據；`GrantTx` 在同一資料庫交易中核對可信 Ingress Receipt、一次性 Binding 與受保護 Candidate，再產生 Admission 並綁定**獨立 Authorized Snapshot**。`StartSend` 只能依受保護 Snapshot，而非舊 Candidate 原始 Payload 起送。
- **禁止降級**：Promotion／Receipt／Binding／Snapshot 任何一項不存在、衝突或不可驗時拒絕；不得設定 `legacy=true`、環境開關、重試舊 `grant()` 或修改 Runtime 的資料表來繞過。舊有記憶體 CandidateStore 測試不構成新可信路徑的授權證據。
- **切換原則**：不在沒有新路徑的狀態下刪除共用 Generator 介面；先實作新 schema、角色 ACL、交易狀態與 Transmission，再以真實低權限 PG、並行與故障注入證明舊路徑被拒且新流程正常。正式發送持續禁用；Snapshot／Restore 與 External Side Effect 的未決條件不可被 Cutover 遮蔽。

10. **MUST**：明確分離 `CandidateEvidence`（完整 Scope、candidate_ref/version、Envelope hash、Policy／Source／Validation）、`CandidatePayload`（BYTEA 或固定 object id/version/hash 與 purge state）、`GrantBinding`、`SnapshotProposal`、`OperationSnapshotBinding`、`AuthorizedSnapshot`、`PayloadPurgeTombstone`；允許等價受保護模型而不強制每個名稱都需獨立資料表。**擬議完整 Candidate Version Identity** 為 `(environment_id, deployment_id, session_id, world_generation_id, candidate_ref, candidate_version)`；`GrantBinding`／Snapshot／FK 必須保留這個完整識別，不得省略 version 或 Scope。**既有** migration `001_world_runtime.sql` 的 `candidate_records` 主鍵僅前五項、沒有 `candidate_version`；新增 DB 生成、不可變 Version 是**正式 Schema／ACL／升級前置條件（NOT_IMPLEMENTED）**，在 Migration 與舊版二進位的相容／負面測試完成之前**不得**把六欄 Identity 當成可執行的現有 DB 約束。前五項是不可重用的**邏輯識別保留鍵**：不能靠改 version 重用已綁／已清理的相同 `candidate_ref`；以受保護的 UNIQUE／Tombstone 強制。`SUBMITTED + VALID BINDING` 不合法；`PURGED → AVAILABLE` 永久禁止；同一完整 Identity 不能 INSERT 替代 Payload。
11. **MUST**：先以受保護交易記錄**首次不可變 Snapshot Proposal** 和完整 Scope Pin；固定 object ID／version／hash，交易外依固定版本 materialize 完整 bytes、驗 Envelope encoding v1／Hash，再建立不可變 Snapshot。不能在等待外部 Object Storage 時一直持有關鍵 DB row lock。首次 Proposal 未持久化，無法聲稱能阻止改選。外部物件不存在／hash 失配 → Fail-Closed，不可請 Runtime 重新提供相同 Hash 的「替代內容」。
12. **MUST**：`OperationSnapshotBinding` 受 `UNIQUE(operation_identity_id)` Write-Once 控制，綁 Snapshot id/version/hash/encoding、Operation、完整 Scope／Generation、Admission。不同值重綁 → `SNAPSHOT_BINDING_CONFLICT` 且原紀錄不變；相同值只能讀回（不得重新授權）。未知 COMMIT 先對帳；確定 Rollback 也只能沿最初**持久化** Proposal 重試；Restore 後缺 Binding 不得改選。Binding 與 Authorize 同受保護交易，或 Authorize 在同一交易鎖定並引用既有**已提交且不可變** Binding；未綁定不得 SEND_AUTHORIZED。
13. **MUST**：`SEND_AUTHORIZED` 持久化精確 `candidate_identity/version`、`operation_identity`、`snapshot_id/version/hash`、`envelope_encoding_version`、`payload_pin_id`、`admission_id`、Scope/Generation；StartSend 只讀取此 Snapshot，不重新解析 Candidate 或拉取 Object 的新 version。Snapshot 是應用層 Envelope（status、按序 headers、body）及現有編碼 v1 的 hash，**不是 TCP wire-byte hash**；允許的 HTTP framing 轉換須獨立驗證。
14. **MUST**：原 Candidate Payload Purged **不會**否定已完整驗證、獨立保存的合法 Snapshot；Snapshot Purged／corrupt 才使 StartSend 無資格。GC 必須依完整 Identity／Version／Binding／Pin／Lease／Purge Tombstone 的受保護資料庫權威決定；`protected_refs` 只能當最佳化提示。FK 保證參照，不足以保證 Promotion、Purge、StartSend 的合法狀態組合。
15. **MUST**：Snapshot 清理前先持久化**不可重試 Execution Fence**（不回溯抹除 SEND_AUTHORIZED）、阻擋新 StartSend；此 Fence 只能證明實際執行資源／安全清理不可用，不得作為未經 Freeze v2 的任意撤銷指令。已 SEND_STARTED 的活躍 Sender 必須持續取得原 Snapshot 至完成或受控中止；結果 UNKNOWN 依有界留存／對帳規則，不因到期假設傳輸失敗。保留 `operation_id,external_effect_key,admission_id,snapshot_id/hash,encoding_version,purge_time/reason,non_retryable` 及完整 Candidate 邏輯識別／Version，清理 bytes 後永不恢復原發送資格。**Tombstone 若只存在可還原到過去的 World DB，仍可能因 Restore 回退而消失；還原庫內 Tombstone 存在也不證明墓碑集合完整或世代未倒退。**須以 World DB 還原範圍外可驗證的防倒退錨點與恢復隔離比對；錨點來源／完整性／覆蓋範圍不明時持續禁止正式發送。Secure Purge 保證須限定實際儲存，不能聲稱立即追回 RAM／ASGI／WAL／Backup 內容。
16. **MUST**：Snapshot 原始 bytes 需定義可讀 Role、隔離／加密、最大大小、保留期限、備份／Restore、加密金鑰銷毀與安全刪除；一般 Audit／Debug log 不得儲存敏感全文；取回時重新計算 Hash，不能只相信 Metadata。

17. **MUST — 獨立物件身分（`WORLD-SNAPSHOT-SEPARATION-01`，NOT_RUN）**：`Candidate Payload Object` 與 `Authorized Snapshot Object` 在可信 Metadata 中具**不同受保護儲存身分**；Snapshot 固定 `snapshot_id`、不可變 `snapshot_version`、storage `object_id/version`、Envelope hash 及 Operation／Admission Binding，`SEND_AUTHORIZED` 指向 Snapshot，**不指向可清理的 Candidate 原始 Payload**。若兩個邏輯物件在底層去重儲存共用同一 Blob，必須由非 Runtime 可改的**實體引用計數／Pin／Lease 或等價防刪協定**保護，並用併發 GC／Object Storage 故障注入證明 Candidate 清理不會刪除被授權的實際 bytes。Snapshot 讀取時重算**實際 Snapshot bytes** 的 Envelope v1 hash，不能只比 Metadata。獨立 ID／兩張狀態表本身不構成實體隔離證明。

18. **MUST — 兩類不可混淆的清理 Fence**：`CandidatePayloadPurgeFence` 僅終止原始 Candidate 的 retention／未來使用或 Promotion，不得改寫 Admission 授權，也不得影響仍完整的 Authorized Snapshot；`AuthorizedSnapshotPurgeFence` 由受保護 Snapshot GC／Integrity 流程寫入，提交後永久禁止同 Snapshot 的**新** `StartSend`，但不可回溯修改 `SEND_AUTHORIZED` 或形成第二個 Policy／Emergency Revocation。共用 Blob 時 Candidate GC 先確認 Snapshot Pin／引用權威，不能因 Candidate Fence 便刪除仍受保護的物件。兩類 Fence 各有 Write-Once Scope、object identity/version、reason、DB time、GC operation identity 與獨立權限，Runtime 不可自填。

19. **MUST — Fence 先行、清理可重試（`WORLD-PURGE-RETRY-01`，NOT_RUN）**：`AuthorizedSnapshotPurgeFence` 已提交，但後續 Object GC 斷線／失敗時，執行失格**持續生效且不可撤銷**。受控 GC 可用固定冪等 `gc_operation_id` 與受保護的進度／對帳紀錄重試**實體刪除**或進行人工清理；不得恢復同 Snapshot `AVAILABLE`、不得替換原 bytes／建立新 Snapshot 或 Admission。刪除前仍依原 ACL／加密／留存政策保護殘存 bytes，保留 Audit／Tombstone 與故障證據。GC 失敗主要是清理／可用性故障，不可藉安全資格回退補救。

**狀態欄位不得混合（Proposed execution contract，非聲稱既有 Schema 已有此 enum）**：

| 獨立軸線 | 語意與狀態 | 強制規則 |
| --- | --- | --- |
| Admission／Authorization | 既有 `GRANTED`／`CLAIMED`／`SEND_AUTHORIZED`／`SEND_STARTED`／成功或失敗終態 | `SEND_AUTHORIZED` 的歷史授權 COMMIT 不因後續 Purge／Policy 回溯抹除；記錄 `ABANDONED` 執行終態仍須保留授權歷史 |
| Candidate 原始 Payload retention | 是否保留 Candidate 初始 bytes／Evidence；可已 Purged | 原 Candidate Purged **不代表**已授權 Snapshot 失去發送資格；不能拿 Candidate GC 取代 Snapshot 檢查 |
| **已綁 Authorized Snapshot execution eligibility** | 擬議 `AVAILABLE`、`PURGE_PENDING`、`PURGED`、`CORRUPT`、`UNAVAILABLE` | `StartSend` 查核的**只能是 Admission 綁定的同一 Snapshot**：`AVAILABLE` 且其他條件符合才可起送；`PURGE_PENDING` 只有在真實不可逆 Purge Fence 已受保護提交時封鎖；`PURGED` 同一 identity 永不得復活／掛替代 bytes；`CORRUPT` 必須有實際受保護 Hash/Integrity 失敗證據；`UNAVAILABLE` 代表不可證明可用、先 Fail-Closed，不可直接推定已永久刪除 |

**Fence 命名**：表中泛稱 Snapshot Purge Fence 的既有文字均指 `AuthorizedSnapshotPurgeFence`；Candidate 原始 Payload 的保留／GC 由 `CandidatePayloadPurgeFence` 管理。兩者不能以同一可覆寫旗標實作，也不能把 Candidate Payload 清理當作 Snapshot 失格理由。

**不可逆執行失格標記**（`irreversible execution-ineligibility marker`）是 Snapshot 的執行資格，不是 Policy／Emergency `REVOKED` 或新的 Authorization State。寫入必須由受限 Snapshot GC／Integrity 操作依可信 Object version、Hash、Pin／Lease、保留政策及已固定 Admission Scope 產生；**Runtime／Policy Caller 不得自填狀態、purge reason 或 timestamp**。一旦 irreversible fence 提交，不能藉回填 Payload、重設 enum 或改掛 object version 恢復相同 Snapshot 資格；Audit 保留 snapshot identity/version/hash、原 Admission 授權記錄、purge 原因、權威 DB 時間、Writer 身分及受保護 Evidence。`WORLD-PURGE-BOUNDARY-01` 要同時驗證合法 Candidate 原始資料清理不阻擋完整 Snapshot，以及真正 Snapshot Purge 僅改執行資格。

`PURGE_PENDING` 若已有不可逆 Fence，即使後台清理卡住也不得私自退回 `AVAILABLE`；須有可對帳的 GC Operation ID、上限／告警與人工介入的完成或安全隔離流程。此為**可用性與恢復風險**，不能用「解除 Fence 讓舊 Admission 重送」補救。

### 6.5.4 Privileged Caller、完整鎖圖、Mixed Runtime

17. **MUST**：獨立 `NOLOGIN` 函式 Owner、可信固定 `search_path`（`pg_temp` 末尾）、撤銷 `PUBLIC EXECUTE`；一般 Runtime 不可透過 `SET ROLE`／membership／直接 DML 或可繼承權限取得 Verifier／Authorizer。`SESSION_USER`／`CURRENT_USER`／`SET LOCAL app.tenant_id`／`app.claim_owner`／自填 `protocol_version` 皆不是可信業務主體或版本證明。特權操作沿受保護 Ingress Receipt → Operation Authority → Persisted Subject／Tenant → Grant Binding 推導權限並查核 input scope、owner、generation、revision；需測試跨 owner/admission 越權。
18. **MUST**：完整 Lock DAG 記錄每交易隔離級別、row `FOR UPDATE/FOR SHARE/FOR KEY SHARE`、FK INSERT／DELETE 隱含鎖、advisory lock 先後與 Session Head／Generation／Admission／Candidate／Binding／Policy／Key／Pin／GC 的順序；`40P01`／`40001` 只在確認 Rollback 且沒有任何外部不可逆效果後才可有界重試，`lock_timeout`／未知 COMMIT 不得猜測成功。真 PostgreSQL 多 Backend 實證完成前，不宣稱「全球無死鎖」。
19. **MUST**：新版 Runtime 使用**新 DB Role／Credential**；部署 Preflight 先撤銷舊 Role 的 protected DML／EXECUTE、終止舊連線／清空 Pool，才允許新版 Schema／函式／ACL 相容 Sender。Runtime 自填 protocol_version 只是診斷資料，不能作安全版本憑證；舊二進位／舊 Role、DB restore、migration rollback 不能重啟受保護寫入／發送。

### 6.5.5 規範性不變量與驗收映射

| ID | MUST（v0.2 新設計，尚未實作） |
| --- | --- |
| I-01–I-04 | Evidence immutable；Payload Purge 不可逆；Binding 不代表 bytes 可用；StartSend 不得回頭重取 Candidate |
| I-05–I-06 | 同 Namespace Operation ID 只綁單一 Digest；未知 COMMIT 不得自動重新 World Mutation |
| I-07–I-08 | Policy/Emergency 尊重 Freeze v1；一般 Runtime 不可改授權狀態／偽造可信 Subject |
| I-09–I-12 | Pin／GC 防刪；未知外部傳輸不自動重送；舊備份不能復活撤銷權限；NOT_RUN 不是 PASS |
| I-13 | 各受保護交易於取得必要鎖後只取一次 DB decision_time，明定判定時間 vs COMMIT |
| I-14 | 跨表狀態以受保護轉移＋完整 FK／鎖圖強制，不只相信 Trigger/precheck |
| I-15 | 傳輸只用已授權綁定的同一不可變 Snapshot，不取代、不重新抓 Candidate |
| I-16 | Namespace rotation 不改變首次固定的外部 idempotency key |
| I-17 | 未知 SEND_STARTED 不得自動重試／新授權／新傳輸；對帳也不直接授權開新連線 |
| I-18 | 授權綁 Envelope 編碼、完整 Scope、Snapshot identity/version/hash；不稱 TCP hash |
| I-19 | Snapshot bytes 有明確 Role、保留、加密、備份、Purge Fence 與不可重試規則 |

**驗收 ID**：`WORLD-OPERATION-01/02/03`、`WORLD-POLICY-01/02`、`WORLD-PAYLOAD-01/02/03`、`WORLD-SNAPSHOT-01`、`WORLD-SNAPSHOT-ACL-01`、`WORLD-LIFECYCLE-01/02/03`、`WORLD-PURGE-01`、`WORLD-TIME-01`、`WORLD-LOCK-01`、`WORLD-IDENTITY-01`、`WORLD-COMPAT-01`、`WORLD-RECOVERY-03/04`、`WORLD-RESTORE-OP-01`。**全部 NOT_RUN**；先前 13/13 World Role 測試中 3 項是漏洞重現，與新的修補驗收不可混算。


### 6.5.6 新增／修訂契約測試完整 ID 登錄（全數 NOT_RUN）

以下使用**完整 ID**，避免 `01/02/03` 縮寫被誤認為單一測試；與 Decision Log 及 Verification Plan 同步，文件檢查器必須逐項核對：

| Test ID | 狀態 |
| --- | --- |
| `WORLD-IDENTITY-01` | **NOT_RUN** |
| `WORLD-OPERATION-01` | **NOT_RUN** |
| `WORLD-OPERATION-02` | **NOT_RUN** |
| `WORLD-OPERATION-03` | **NOT_RUN** |
| `WORLD-POLICY-01` | **NOT_RUN** |
| `WORLD-POLICY-02` | **NOT_RUN** |
| `WORLD-PAYLOAD-01` | **NOT_RUN** |
| `WORLD-PAYLOAD-02` | **NOT_RUN** |
| `WORLD-PAYLOAD-03` | **NOT_RUN** |
| `WORLD-SNAPSHOT-01` | **NOT_RUN** |
| `WORLD-SNAPSHOT-ACL-01` | **NOT_RUN** |
| `WORLD-LIFECYCLE-01` | **NOT_RUN** |
| `WORLD-LIFECYCLE-02` | **NOT_RUN** |
| `WORLD-LIFECYCLE-03` | **NOT_RUN** |
| `WORLD-PURGE-01` | **NOT_RUN** |
| `WORLD-TIME-01` | **NOT_RUN** |
| `WORLD-LOCK-01` | **NOT_RUN** |
| `WORLD-COMPAT-01` | **NOT_RUN** |
| `WORLD-RECOVERY-03` | **NOT_RUN** |
| `WORLD-RECOVERY-04` | **NOT_RUN** |
| `WORLD-RESTORE-OP-01` | **NOT_RUN** |
| `WORLD-AUDIT-02` | **NOT_RUN** |
| `WORLD-PROTOCOL-01` | **NOT_RUN** |
| `WORLD-PROTOCOL-02` | **NOT_RUN** |
| `WORLD-RESTORE-TOMBSTONE-01` | **NOT_RUN** |
| `WORLD-RECOVERY-03A` | **NOT_RUN** |
| `WORLD-RECOVERY-03B` | **NOT_RUN** |
| `WORLD-RECOVERY-03C` | **NOT_RUN** |
| `WORLD-RECOVERY-03D` | **NOT_RUN** |
| `WORLD-RECOVERY-03E` | **NOT_RUN** |
| `WORLD-RECOVERY-03F` | **NOT_RUN** |
| `WORLD-RESTORE-FENCE-01` | **NOT_RUN** |
| `WORLD-PURGE-BOUNDARY-01` | **NOT_RUN** |
| `WORLD-PROTOCOL-MATRIX-01` | **NOT_RUN** |
| `WORLD-SNAPSHOT-SEPARATION-01` | **NOT_RUN** |
| `WORLD-RESTORE-PUBLISH-01` | **NOT_RUN** |
| `WORLD-PURGE-RETRY-01` | **NOT_RUN** |

既有其餘 `WORLD-*` 測試維持 [Verification Plan](../security/world-db/verification-plan.md) 的原 ID；本清單為**本輪 v0.2 合約精確化所新增／修改的 37 項必檢 ID**（其中 `WORLD-RECOVERY-03` 是群組索引，03A～03F 是六個**各自具 Given／Action／Expected** 的可執行子案），不是所有歷史測試 ID。全部仍 NOT_RUN；群組索引不能單獨報 PASS。

## 7. Replay、未知 COMMIT、GC 與 Restore

- **Replay**：`replay_entries` 僅保存**已消費** JTI；未消費 JTI 無需建立 GC 條目。有效 Receipt 必須對應同交易提交的墓碑，只有墓碑／只有 Receipt 都必須拒絕並告警，不能自行補寫授權證據。
- **可用性與重試界線**：語意 A 下 Runtime 可提前提交一份與合法 JWS 相符的資料並消費 JTI；Verifier Caller 必須經服務認證，對 Caller／Session／Scope 設流量與消費異常監控並留存稽核，不能以單獨「每 JTI 限速」取代總量防護。**已提交消費**後的 Grant 失敗，不得復活同 JTI；若政策允許重新發起新業務意圖，須由合法簽發者產生新 JWS／JTI，並確保不重複執行既有副作用。**只有 DB 明確證明 IngressTx 已 Rollback（不是 Receipt 查無）、沒有任何 World／外部 API／HTTP 不可逆副作用，且同一不可變 Operation Identity＋Digest 可證實未執行**，才可在 JWS `exp`、Session、Policy、Generation 仍有效及簽發／冪等政策允許時，沿**原 ID 與原 digest** 受限重試；**JTI 未消費不等於 World Mutation 未執行**。**未知 COMMIT** 時舊／新 JWS 都不得繞過對帳或另建外部 Effect Key。
- **保留**：JTI、Receipt、Binding、Operation Receipt 應保留到 Token 最長可能可接受時間、skew、安全延遲、重試／對帳及備份還原安全界限全部結束；使用經核准公式與政策參數，例如驗證過的 `exp + skew + restore_margin` 與 `consume_time + max_lifetime + 2×skew + 2×uncertainty` 取保守上限。`UNRESOLVED` 不得僅以逾時自動視為 `ABORTED`。
- **未知 COMMIT**：Operation ID 必須在副作用前可重建或由受保護來源發給呼叫者；它是**相關鍵，不是授權憑證**。Operation Identity 在副作用前受保護建立 `UNIQUE(authority_namespace,namespace_epoch,operation_id)`，不可變 `input_digest`／演算法／`external_effect_key`；不同 Digest 必須 `OPERATION_DIGEST_CONFLICT`，不得 UPSERT 改寫。同 ID 同 Digest 只可唯讀查回／對帳；多 DB／外部效果沒有共同原子交易。查到同 ID 同 digest 的已提交結果可唯讀恢復；查無**不能證明交易未提交**，應保持 `UNVERIFIABLE`，不得盲目重授權／重消費 JTI／重發送。
- **外部副作用**：World Mutation、Medusa／Cart API、Admission、HTTP 不保證跨交易 exactly-once；首次 Operation 建立時固定外部 `external_effect_key`，**不因 Namespace Epoch、Retry、Restore 或新 JWS 自動旋轉**。外部不能對帳則 at-most-once／人工對帳或永久阻擋，不得自動重做。`WORLD_COMMITTED_ADMISSION_UNAVAILABLE` 僅是 reconciliation classification。
- **Restore Quarantine**：單主機建議採 World DB 還原後強制隔離，正式發送關閉；只有在 Replay／Receipt／Key Revocation／Session／Generation 不倒退能被核實，或所有受影響舊 Token 都已確定超出可接受窗口後，才可解除。換公鑰**不能自動代替撤銷舊 Token**。備份／還原必須驗證隔離開關不可因快照回退而消失；無權威證明時持續 NO-GO。

## 8. 版本相容、部署與回滾

1. **Expand**：在隔離 DB 建立新受保護資料、角色、Receipt／Binding／Operation Receipt 與窄介面，原正式發送保持 OFF。`production trusted-send mode: DISABLED` 是**要求的安全政策**，在查明實際控制面／功能開關、可寫身分、還原後狀態與強制執行證據前，**不能宣稱它是已經存在、不可繞過的開關**。
2. **Dual-read／Observe-only**：比對新舊策略，但不得因新策略失敗降級成信任 Runtime 宣告的放行路徑。
3. **Preflight Gate／Mixed Binary Fence**：舊／新 Runtime 必須有**不同 DB Role／Credential**；先撤銷舊 Role 的關鍵 DML／privileged EXECUTE、終止舊連線／清空 Pool，再允許新版 Writer。由部署控制器核對 Schema／Function／Role ACL／Credential 及恢復隔離，**Runtime 自填版本或 session variable 不算可信版本證明**；不相容／舊 Worker 重啟立即 Fail-Closed，Rollback 不得重開舊權限。
4. **Cutover**：依 [Solo Developer Security Acceptance v1](../security/world-db/solo-developer-security-acceptance-v1.md) 在 G3b～G6 必要證據全 PASS 後，由 Mirage Owner 以可追溯的特定 SHA／環境 Release 決議明確核准，並另授權實際部署；外部人工審查為建議但未取得不得冒稱已完成。若鎖鍵或不可兼容狀態機更動，不承諾零停機滾動，應停流排空再切換。
5. **Rollback**：可回復程式的 Observe-only／正式發送 OFF；**不可**自動撤銷 Receipt/Replay 墓碑、放鬆 ACL、恢復已撤銷金鑰或讓舊 Epoch 復活。回滾程序需在隔離 PG 與還原演練中驗證。

## 9. 驗收、證據與失效處置

完整測試 IDs、前置 DB Role／pg_hba／Connection Pool、預期 SQLSTATE、並行故障注入與證據責任見 [Verification Plan](../security/world-db/verification-plan.md)。最低 Release Gate：

- 以**真正 `SESSION_USER=mirage_http_runtime` 的獨立 SCRAM 連線**重跑原三項越權，全部須遭拒，並檢查 effective privileges／Role inheritance／`SET ROLE`／`BYPASSRLS`；單純使用 superuser fixture 的綠燈無效。
- Runtime 無法偽造 Receipt 或直接把 Admission 改 `SEND_AUTHORIZED`；Verifier 不能為無效 JWS、錯請求、舊 epoch、已撤銷 Token 發有效 Receipt。
- 驗收 Python Context 與資料庫授權**分層**：Context 不穿越低信任邊界；Runtime 不能以 SQL／特權函式參數偽造來源。測試 `pg_auth_members` `SET/INHERIT/ADMIN` 路徑、`SET SESSION AUTHORIZATION` 與 schema／function 有效權限，不只查 `NOINHERIT`。
- Replay+Receipt 必須同一 PostgreSQL database、同一 physical connection、同一 IngressTx；Grant 的 Binding+Admission 同交易；已綁 Receipt 不可重用於其他 Candidate。鎖循環檢查、Epoch/Key rotation/revocation 的並行勝負、期限跨鎖等待及 Envelope mismatch 實測。
- 未知 COMMIT、World 成功但 Admission 失敗、SEND_STARTED 之後失聯、GC／Restore Quarantine、Schema／ACL 不相容與故障恢復實測。
- Mirage 固定來源 `start_send()` 與 Mirage Protocol Freeze v1 的**差異分析**、Mirage Owner 正式採納紀錄及 `WORLD-PROTOCOL-01/02`；未修改 Mirage 原生實作前不得宣稱 conformant。
- `WORLD-PROTOCOL-MATRIX-01` 分三份證據測試：**Mirage Protocol baseline ACCEPTED／Mirage Owner adoption ACCEPTED（2026-11-21，D-68）／Mirage native conformance NOT_RUN**。Native 符合性須逐項查 `SEND_AUTHORIZED` COMMIT 線性化、前後 Policy/Emergency、owner、deadline、single-use、Snapshot/ASGI bytes、未知 COMMIT 與 HTTP 結果分類；`start_send()` 修補只是一個切面，不是整套測試的判決。
- World DB 舊備份不含後續 Candidate Tombstone 時，以**還原範圍外**之受保護錨點攔截舊身分復活；Anchor 不可讀／不可驗時持續 Quarantine（`WORLD-RESTORE-TOMBSTONE-01`）。
- `WORLD-RESTORE-FENCE-01` 使用過期／重播／未涵蓋後續 Candidate Tombstone、Binding、Operation 的錨點；`WORLD-RESTORE-PUBLISH-01` 獨立測 DB-first／Anchor-first 故障；`WORLD-PURGE-BOUNDARY-01` 驗證 Snapshot eligibility 與 Admission authorization 互不覆寫；`WORLD-SNAPSHOT-SEPARATION-01` 測底層共用 Blob 的 Pin/GC；`WORLD-PURGE-RETRY-01` 測 Fence 已提交但 GC 失敗。全部未實作前維持 NOT_RUN。
- 失效**可由系統偵測**者立即 Fail-Closed；Secret 外洩、容器掛載錯誤、主機權限遭侵害等**需監控／人工判定**者應停止正式發送、撤銷／輪替憑證、隔離、保留證據，不可謊稱應用能自動證明未外洩。

**驗證結果分層**（執行期間實際 PASS/FAIL 須另以固定 HEAD SHA、命令、產出保存；文件內不預先宣稱本次檢查結果）：

| 類型 | 可證明的範圍 | 此 ADR 安全驗收狀態 |
| --- | --- | --- |
| `python tools/check_documentation.py` | 文件連結、索引、指定契約 ID 的靜態規則；實際執行結果另存 Git/PR 紀錄 | **不等於安全驗收** |
| 所有 `WORLD-*` ID 唯一性檢查 | ID 及表格登錄不重複；**不證明測試內容正確** | **不等於安全驗收** |
| Git diff／遠端檔案一致性 | 文字差異與檔案內容一致，**不證明程式遵守 ADR** | **不等於安全驗收** |
| Mirage native Freeze v1 conformance | 需 Mirage 原生交易實作與 `WORLD-PROTOCOL-01/02` | **NOT_RUN** |
| 真實 PostgreSQL ACL／交易／並行 GC | 非特權角色、有效權限、真實多 Backend 測試 | **NOT_RUN** |
| Restore／Tombstone／獨立錨點 | 以舊備份和有／無錨點做 Quarantine／釋放演練 | **NOT_RUN** |

**驗收狀態轉移規則（未來安全測試報告，不是本輪文件檢查器的 PASS 權限）**：`NOT_RUN → RUNNING → PASS／FAIL／BLOCKED`；若環境／依賴阻塞而無法開跑，可由 `NOT_RUN → BLOCKED`，須記 Owner、原因及解除條件。`BLOCKED` 解除後**只能重新進入 RUNNING**，不能直接人工改 PASS；`FAIL` 需修補並**重新進入 RUNNING** 才可產生新 PASS。每次 PASS 均須綁定**Mirage 精確 source SHA、migration/schema hash／版本、PostgreSQL 版本、實際測試 Role/環境、資料集／故障注入配置、UTC 開始與結束時間、JUnit／已脫敏日誌／SQLSTATE 等不可變證據位置與執行者**；若環境、Policy、Migration 或 Expected 改變，先標 `STALE` 並重新執行，不沿用舊 PASS。必要證據缺失或只有文件靜態檢查仍是 `NOT_RUN`／`BLOCKED`，不能直接設成 PASS。現行 `tools/check_documentation.py` 在尚未實作期間**刻意只接受 NOT_RUN**；未來啟用 PASS/BLOCKED 機制須另經審核引入受證據約束的結果來源及狀態轉移稽核，不能只把靜態字串白名單改寬。

## 10. Blocking Open Decisions、關閉標準與審核

| ID | 必須裁決／確認 | 負責角色 | 狀態 |
| --- | --- | --- | --- |
| BD-01 | Verifier 獨立部署、密鑰、DB／網路存取與最小可用授權通路 | Mirage Owner＋Security＋DBA | OPEN |
| BD-02 | 各交易實際鎖順序／隔離級別，Session epoch & Revocation 勝負，受限函式介面 | Mirage Owner＋DBA | OPEN |
| BD-03 | 現行 Claim／Authorize／StartSend deadline **保持 Freeze v1**；Token grace／skew 參數、DB clock 最大偏差及外部 IO 限制仍須 Owner 批准，不得自行更改 Freeze | Mirage Owner＋Security | OPEN（不可在 StartSend 加第二授權） |
| BD-04 | World Commit 成功但 Admission 失敗的 API 與 Recovery；外部副作用是否可查回 | Mirage Owner＋API Owner | OPEN |
| BD-05 | JTI/Receipt/Binding 保留公式、**World DB 還原範圍外防倒退錨點**的權威來源／不可重播最新 head／單調世代／資料庫 timeline＋覆蓋位置／canonical digest manifest 規格（涵蓋 Candidate Tombstone、Binding、Operation／Replay／Revocation）／Quarantine release 證據與操作；錨點未定或不可驗則禁止正式發送 | DBA＋Security＋Operations | OPEN（預設持續 Quarantine） |
| BD-06 | R3/R4/R5 風險接受界線、Credential Rotation、實際發送不可變 snapshot | Security＋Mirage Owner | OPEN |
| BD-07 | Candidate GC 與 Grant 的完整 Scope FK／Row Lock／全域 DAG、原始 Payload 與稽核證據分級保留／清理方案 | DBA＋Mirage Owner＋Security | OPEN |
| BD-08 | 正式接受 Request Provenance 語意 A 的範圍與殘餘風險；語意 B 另案 | Security＋Mirage Owner | OPEN |
| BD-09 | Candidate Validator 的可信身分／政策來源、長耗時驗證的交易外證據、短 PromotionTx 與 Revision 撤銷／升級規則 | Mirage Owner＋Security＋DBA | OPEN |
| BD-10 | 正式發送 DISABLED 的實際控制面、Runtime 權限、Restore 後不可倒退的隔離機制 | 依 D-73 由 Owner 承擔 Release／Security／Operations 的實測責任與最終核准 | OPEN |
| BD-11 | `decision_time` 有效但 `SEND_AUTHORIZED` COMMIT 晚於 deadline 的政策；可驗證 DB 時鐘下界、可接受交易延遲與判斷點，**不得默默改 Freeze v1**。未定案：僅允許鎖後單一 DB `decision_time` 邏輯判定，**不宣稱** COMMIT-before-deadline；若產品必須保證後者，正式發送保持禁用；未知 Commit 不得開始新傳輸，已實際提交的授權不回溯改寫 | Mirage Owner＋Security＋DBA | **OPEN — 預設 Fail-Closed／no production send** |
| BD-12 | Mirage Owner 是否正式採納 Mirage Protocol Freeze v1 以及對應原生 `start_send()` 相容修正／回歸；現行差異不能只靠改 ADR 消除 | Mirage Owner＋Security＋Mirage Contract Owner | **Owner 採納已決（D-68）；原生修正、Security 相容審查與完整驗收仍 OPEN／NOT_RUN** |

**關閉條件**：上述政策決策經審查、部署／密鑰邊界經驗證、負面與正向真實 PG 測試及恢復證據完整、Owner/Security/Release 核准；之後才能考慮將 `MIR-SEC-WORLD-001` 由 OPEN 轉為已修復。PR 合併、CI 綠燈或沒有外部攻擊回報**均不足以關閉**。

**維持** Architecture Proposed、Mirage Owner adoption ACCEPTED（D-68）、Mirage native conformance NOT_RUN、MIR-SEC-WORLD-001 OPEN、Mirage release NO-GO。以各 Gate 的固定版本證據更新個別狀態，正式 Trusted Send 保持 OFF。

## 11. 文件及版本追溯

- [決策歷史與被否決替代方案](../security/world-db/decisions-log.md)
- [權威證據矩陣](../security/world-db/evidence-authority-matrix.md)
- [交易、鎖、錯誤與一致性矩陣](../security/world-db/transaction-lock-matrix.md)
- [威脅能力與覆蓋矩陣](../security/world-db/threat-capability-matrix.md)
- [測試／驗收計畫](../security/world-db/verification-plan.md)
- [Mirage World Runtime 現有行為](../world-runtime.md)；[Trusted Session](../trusted-session.md)；[Key Revocation](../key-revocation.md)；[World Operation Result](../commit-results.md)

### 版本歷史

**版本證據**。契約版本、原生程式 SHA、Owner 採納及 native conformance 分別記錄。當前 SHA 由 Git／PR Metadata 取得，新增安全驗收維持原有 NOT_RUN 狀態，歷史證據不能直接升格為新版本通過。

| 版本 | 日期 | 內容 |
| --- | --- | --- |
| v0.1 | 2026-11-21 | 首次將前幾輪審查整理成可審查 Architecture Draft；所有 proposed 控制、未決政策與未執行測試均明確標示 |
| v0.2 | 2026-11-21 | 收斂 Trusted Request 語意 A、Verifier Context／單一連線協調、Candidate 驗證與 Promotion、Rollback／Unknown COMMIT、角色矩陣與正式發送停用控制；**仍為 Proposed** |
| v0.2 審查增補 | 2026-11-21 | VerifiedContext 程序／DB 分界、Role SET membership、受限 Promotion 證據與政策撤銷、完整 Scope FK／原始 Payload 保留、全域鎖 DAG、Ingress rollback／已消費／未知 Commit 重試分類；無新實作或測試結果 |
| **v0.2 Contract Freeze candidate** | 2026-11-21 | 與 Mirage Protocol Freeze v1 對齊、Operation/Snapshot Write-Once、時間、兩種 Purge、完整鎖圖、外部效果、Mixed Runtime；**僅文件，全部新驗收 NOT_RUN** |
| v0.2 收斂補遺 | 2026-11-21 | 核對 Mirage upstream 與 原生目標協定 差異、完整 Candidate Version Identity／不可重用邏輯鍵、Restore 後 Tombstone 不復活、明確 Rollback＋零外部效果重試前提、Deadline COMMIT 時點與 Git 自引用追溯限制；**仍未實作或驗收** |
| v0.2 審查補錄 | 2026-11-21 | 明列 Mirage Freeze v1 採納狀態、外部防倒退錨點必要性、BD-11 未定前保守停用、Purge Fence 不作任意二次授權、文件靜態檢查與真實安全驗收分流、Recovery A～F 獨立驗收；**仍為 Proposed／NOT_RUN** |
| v0.2 三軸狀態與恢復錨點補錄 | 2026-11-21 | 分離 契約版本基準／Mirage Owner 採納／Mirage native conform；Anchor 增不可重播外部 head＋digest 覆蓋規格；拆 Candidate retention／Authorized Snapshot eligibility／Admission state；加入 3 項測試與 NOT_RUN→BLOCKED→PASS/FAIL/STALE 的證據閘門；**未實作、未安全驗收** |
| v0.2 儲存物件及故障次序補錄 | 2026-11-21 | Snapshot／Candidate 物件與 Pin 分離；雙 Purge Fence；DB-first／Anchor-first 發布不一致 Quarantine；Fence 後 GC 冪等重試；實測證據狀態機；新增 3 案，**全部 NOT_RUN** |
