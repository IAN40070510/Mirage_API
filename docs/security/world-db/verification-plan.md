# MIR-SEC-WORLD-001 — 真實 PostgreSQL 驗收與安全負面測試計畫

**v0.2 — Test Plan Only；全部新案例狀態 `NOT_RUN`，不能因本文件被提交而改為 PASS。**

## 1. 測試環境、身份與證據

- 基準原始碼：Mirage `main` `88dc2008fd35a2d3873949a769653dc9f18e8980`；針對修復 PR 再記錄 branch SHA、Migration Hash、PostgreSQL 版本、Role ACL 與 feature flags。
- 使用**真實 PostgreSQL 17 系列隔離實例**與 SCRAM 身分。建立真正 `mirage_http_runtime`、`mirage_ingress_verifier`、`mirage_authorizer`、`mirage_replay_gc`、`mirage_control_admin`；Schema Owner NOLOGIN。不可用 postgres／owner 登入執行 Runtime 權限負面測試。
- 每個 fixture 建立**物理上的獨立連線與 DSN**，先查 `SELECT session_user, current_user;`；同時查 effective grants、Role inheritance、`rolbypassrls`／`rolsuper`／`rolcreaterole`、`pg_auth_members`（`set_option`／`inherit_option`／`admin_option`，包含間接成員鏈）、`has_table_privilege`／`has_schema_privilege`／`has_function_privilege`／`pg_has_role`、`pg_hba.conf` 實際登入來源與 Pool role reuse。**NOINHERIT 不能代替 SET ROLE 的拒絕實測**。
- DML／函式越權應明確斷言 PostgreSQL `SQLSTATE 42501`（或在受限函式中的固定**業務拒絕**碼）；**兩者不可混用**。若操作本應因狀態機拒絕，不可要求必然是 42501。
- 驗證 `SECURITY DEFINER` 的 owner、`search_path`、PUBLIC EXECUTE、Schema CREATE、pg_temp shadowing、函式多載、Extension、Large Object、`SET ROLE`／Role membership、`COPY FROM PROGRAM` **實際權限**；不可僅查 role 名稱。
- Fault injection 要能控制 PostgreSQL Transaction 的「before commit」「after commit but before ACK」「read-only lookup fail」、Executor restart、Network timeout、clock skew、restore 及 concurrency/barrier。測試 Harness 知道的真實 COMMIT 結果不得被假設為 Verifier Client 當時也能知道。測試日誌必須脫敏，不外洩 DB Secret／JWS 私鑰。
- Verifier／Key Guard／Replay／Receipt 在**同一 DB、同一 Physical Connection、同一受控 IngressTx** 驗收。Runtime 不得傳入可偽造的 Verified Context／Claims／Signature Validation Result，內部 Context 不得直接序列化交給不可信服務；`SECURITY DEFINER`／函式 Writer 必須按 Role 與 Scope 做負面測試。Candidate Submission／Validation／Promotion／Binding 的 hash、**DB 生成版本**、Policy Revision、Source/Validator Evidence、Scope、GC 不變量需分開驗證。
- 每項結果保留 JUnit／命令／SQLSTATE／出錯注入點／原始碼 commit／DB migration／角色有效權限／實際輸出；未執行以 `NOT_RUN`，錯誤拒絕也不算正常 PASS。

## 2. ACL、Verifier 與 Evidence Binding

| ID | 測試情境 | 預期（新設計完成後） | 狀態 |
| --- | --- | --- | --- |
| `WORLD-ACL-01` | Runtime 直接將 Admission 改 SEND_AUTHORIZED | DML denied，SQLSTATE 42501；資料不變 | NOT_RUN |
| `WORLD-ACL-02` | Runtime 將 Session Head epoch 倒退或任意跳躍 | DML denied；受限切換只接受合法狀態 | NOT_RUN |
| `WORLD-ACL-03` | Runtime 提早 DELETE 未過期 Replay Tombstone | DML denied；受限 GC 不清理 | NOT_RUN |
| `WORLD-ACL-04` | Runtime 直接修改 Generation／Key Revocation／已核准 Candidate | DML denied；重要內容無變化 | NOT_RUN |
| `WORLD-ACL-05` | Runtime 經 Role 繼承、間接 membership `SET`、`SET ROLE`、`SET SESSION AUTHORIZATION`、Pool 重用、SECURITY DEFINER 假輸入取權 | 全部 denied；`pg_auth_members` grant option／函式 `PUBLIC EXECUTE`／schema `USAGE` 不可使其任意提升 | NOT_RUN |
| `WORLD-ACL-06` | Runtime 真實 SCRAM 連線並掃 effective permissions | 符合審核角色矩陣，非 superuser／BYPASSRLS | NOT_RUN |
| `WORLD-VERIFIER-01` | Runtime 提交無效 JWS、錯 signature、錯 audience／scope | Verifier 不寫 Receipt／有效 Replay Binding | NOT_RUN |
| `WORLD-VERIFIER-02` | Runtime 覆寫 verified、issuer、kid、policy version、issued/expires | Verifier 不採信自填值；無有效 Receipt | NOT_RUN |
| `WORLD-VERIFIER-03` | Runtime 讀 Verifier Secret／連線 Verifier Role／取其 DB Role | Permission denied；無替代憑證或來源通道 | NOT_RUN |
| `WORLD-VERIFIER-04` | Runtime 通過合法 API 送已撤銷、錯 fingerprint、舊 epoch Token | Fail-Closed；不建立有效 Receipt | NOT_RUN |
| `WORLD-FP-01A` | JWS fingerprint=F1，提交原始 Request R2 算得 F2 | 驗證器自行 Canonicalize 後拒絕；不得直接採信 Runtime 傳來的 F1 | NOT_RUN |
| `WORLD-FP-01B` | 提交請求可由 Runtime 製造，但**與有效 JWS 所簽 fingerprint 一致** | 語意 A 只可證明提交資料一致；不宣稱真實 HTTP 來源已證明，也不能對不同 Request 的 Admission 放行 | NOT_RUN |
| `WORLD-FP-01C` | 已有 Receipt，後續 Grant／StartSend 替換 Request Fingerprint | Binding／授權拒絕，不能挪用至其他請求 | NOT_RUN |
| `WORLD-CONTEXT-01` | Runtime 自造 Python Verified Context、跨序列化「驗證 JSON」、直接呼叫 Receipt Writer、向窄 `SECURITY DEFINER` 注入 claims、繞過 ACL INSERT／UPDATE／DELETE 或 `SET ROLE` | 不信任形狀／欄位；按真實 Runtime DB Role／函式 ACL 拒絕，沒有有效 Receipt；`SESSION_USER`／`CURRENT_USER` 差異可證明 | NOT_RUN |
| `WORLD-ROLE-01` | Verifier 嘗試建立 Binding；Authorizer 嘗試建立 Receipt；Runtime 嘗試 SET ROLE | 依角色矩陣拒絕，不得繼承其他特權 | NOT_RUN |
| `WORLD-RECEIPT-01` | Replay Tombstone 存在但 Receipt 缺失 | Grant denied 並告警，不能補寫授權 | NOT_RUN |
| `WORLD-RECEIPT-02` | Receipt 存在但 Replay 墓碑不存在 | Grant denied 並告警；不接受孤兒 Receipt | NOT_RUN |
| `WORLD-RECEIPT-03A` | Replay INSERT 後、Receipt INSERT 前的**同一 IngressTx** 發生錯誤且**已證實 rollback** | 兩者對其他交易均不可見；本 Operation 無已提交 Receipt。新嘗試仍須遵守 JWS／JTI 有效性政策 | NOT_RUN |
| `WORLD-RECEIPT-03B` | PostgreSQL COMMIT 可能完成，但 Client 的 ACK 遺失 | Client 初始 UNKNOWN；不得重消費 JTI、重建 Receipt 或重試副作用；對帳查到可信同 ID／digest 才確認已提交，查回仍失敗則 UNVERIFIABLE | NOT_RUN |
| `WORLD-TX-01` | Key Guard／Replay Store／Receipt Writer 在 IngressTx 中嘗試自開第二連線或自行 Commit | 交易介面拒絕；單一 Coordinator 控制 commit/rollback；Pool reset／錯誤 cleanup 有證據 | NOT_RUN |
| `WORLD-BIND-01` | 同一 Receipt 並行綁兩個不同 Candidate | 最多一個合法 Binding／Admission 提交 | NOT_RUN |
| `WORLD-BIND-02` | 同一 Receipt 被重綁不同 Candidate／Generation | 永久 denied，未更改原 Binding | NOT_RUN |
| `WORLD-BIND-03` | Binding 成功而 Admission INSERT 故障 | 同交易整筆 rollback，無部分有效 Binding | NOT_RUN |
| `WORLD-BIND-04` | Receipt 已綁定**當前** Admission，Authorize／StartSend 重查 | 正常流程允許；不得把 used=true 誤判成重放 | NOT_RUN |
| `WORLD-CAND-03` | Runtime INSERT Candidate 時自填 trusted hash／owner／generation／authorization 欄 | 不接受為可信結果，僅允許低信任 submission 或由受保護程序核算 | NOT_RUN |
| `WORLD-CAND-04` | Candidate bytes/hash 一致，但違反核准 Projection／Source／Scope／Policy | 拒絕 Validation／Promotion 或 Grant；Hash 不能替代政策授權 | NOT_RUN |
| `WORLD-CAND-05` | Submission 成功，Validation 失敗或 Promotion 中斷 | 不存在可供 Grant 使用的半可信 Candidate；Staging 只供隔離／稽核／GC | NOT_RUN |
| `WORLD-CAND-06` | Validator 通過後分別替換 bytes、DB Candidate Version、完整 Scope、Validator Evidence、Policy Revision；包含**同 hash、不同 Revision** | 短 PromotionTx 逐項重新核對可信證據與現行政策；拒絕變更，不能使用 Runtime 自填 version/validated | NOT_RUN |
| `WORLD-CUTOVER-01` | 舊 Runtime 使用 `PostgresCandidateStore.put()` 建立 ref/hash，然後嘗試走舊 `PostgresAdmissionControl.grant()`、直接 SQL 或舊二進位提交可信授權；包含新路徑不可用時的降級回退 | 舊 Candidate 不具受保護 Promotion／Receipt／Binding／Snapshot 時，不能建立有效 `SEND_AUTHORIZED`，不能以環境開關或舊權限繞過；原有資料可唯讀對帳但不自動升格 | NOT_RUN |
| `WORLD-CUTOVER-02` | 新的商品、Cart／Inventory、Medusa Candidate 依序進行 Submission、可信 Validation/Promotion、一次性 Grant Binding、獨立 Snapshot；注入 Promotion 中斷、Binding race 與 Candidate GC | 三種來源都只使用新授權邊界；正常路徑仍能準確執行 Envelope v1，部分失敗無半可信 Candidate／重授權；已授權 Snapshot 不因原 Candidate 被清理而遺失 | NOT_RUN |
| `WORLD-POLICY-01` | (A) Validation→Promotion 前撤銷；(B) Policy v1→v2 但 v1 ACTIVE；(C) REVOKED 在 SEND_AUTHORIZED 前先 COMMIT；(D) REVOKED 在 SEND_AUTHORIZED 後 COMMIT；(E) Candidate Payload 已清、授權 Snapshot 完整 | A 拒絕新 Promotion/Grant；B 不自動撤舊 Revision；C 拒絕最終授權；D 授權保留、StartSend 不重新查政策；E 依原 Snapshot 可安全起送，仍遵守 owner／deadline／single-use | NOT_RUN |
| `WORLD-SCOPE-01` | 使用別的 Session／Generation／Operation 的 Candidate、Snapshot、Admission 或 WorldSnapshot expiry | Grant／Authorize 拒絕替代 Scope；StartSend 對**已授權綁定的** Snapshot／owner/Scope identity 做執行一致性檢查，不能由 Runtime 注入替代值 | NOT_RUN |
| `WORLD-PAYLOAD-01` | Runtime 修改 Candidate 原 bytes、或 ASGI middleware 在 Snapshot 後改寫 status/headers/body | 綁定 Envelope v1 與 immutable Snapshot；未授權變更拒絕，不得重新取 Candidate 以相同 Hash 替換；必要 Audit 寫失敗時禁止首個 ASGI | NOT_RUN |
| `WORLD-PAYLOAD-02` | DB Pin 有效但外部 Object Storage 指定版本已刪、替換、讀取失敗或 Hash 不符；同 body 不同 Scope/headers/status/encoding | Fail-Closed；只能讀首次固定 object id/version，驗完整 Envelope Hash、Scope，不能偷換內容 | NOT_RUN |

### Snapshot、Operation、生命週期與 Caller 受保護合約（新 v0.2 測試）

| ID | 測試情境 | 預期 | 狀態 |
| --- | --- | --- | --- |
| `WORLD-IDENTITY-01` | 共用合法 DB LOGIN 下不同 Tenant／Claim Owner；Runtime 以 SESSION_USER、SET LOCAL app.tenant_id、function owner／admission/scope/generation/revision 交叉偽造 | 受限函式沿受保護 Receipt→Operation→Subject→Binding 查回身份；所有跨 owner/tenant 拒絕，無受保護狀態改變 | NOT_RUN |
| `WORLD-OPERATION-01` | 一個權威 Namespace/Epoch 下同 operation_id 首次 Digest=A，第二次 Digest=B；UPSERT/UPDATE 嘗試改寫 | OPERATION_DIGEST_CONFLICT；唯有一筆 immutable Operation Identity；A 重試只讀回或對帳 | NOT_RUN |
| `WORLD-OPERATION-02` | 第一次持久化 Snapshot Proposal A，Binding A 後嘗試 B、重試 A、COMMIT ACK unknown、Restore 缺 Binding | B→SNAPSHOT_BINDING_CONFLICT；A→讀回原 Binding 且不重新授權；UNKNOWN→唯讀對帳；缺 Binding 不得改選 | NOT_RUN |
| `WORLD-OPERATION-03` | 建新 Namespace Epoch、新 JWS 或重試時試圖重建 external_effect_key；Operation 多個副作用 | 原業務副作用 Key 不變且每個效果有獨立穩定鍵；不可藉新 Epoch 重做已提交外部效果 | NOT_RUN |
| `WORLD-LIFECYCLE-01` | SUBMITTED/VALIDATED/PROMOTED、Raw Payload、Binding、Snapshot、Policy 的合法／不合法組合 | SUBMITTED+VALID BINDING 禁止；PROMOTED+PURGED+ACTIVE BINDING 只保留證據、若快照完整可依原授權執行；Policy REVOKED 禁新 Grant/Authorize | NOT_RUN |
| `WORLD-LIFECYCLE-02` | Purged Candidate 以相同五欄 Logical Key＋原 version、新 version、跨 Session／Generation、Rollback Restore 遺失墓碑後重新 INSERT/Promotion／掛回 bytes | 六欄完整 Identity 與五欄不可重用邏輯鍵均由受保護約束拒絕替換；DB 還原無法證明墓碑未倒退時 Quarantine；先驗證**既有 Schema 無 version、必須 Migration** | NOT_RUN |
| `WORLD-LIFECYCLE-03` | Validation→Promotion、Binding→GC、FK INSERT/DELETE 相互競爭與次序變化 | 跨表約束由完整 FK/受限轉移/真 PostgreSQL row/advisory/FK 鎖強制，無 TOCTOU/可逃過的 precheck | NOT_RUN |
| `WORLD-PAYLOAD-03` | 原 Candidate 已 Purged 但已綁完整 Snapshot；Snapshot 本身 Purged／Corrupt；Sender 開始後 Pin 到期 | 前者在既有授權與期限內可 StartSend；後兩者不可新起送；原已在途 Sender 使用原 Snapshot 直到終態/受控中止，不回抓 Candidate/Object | NOT_RUN |
| `WORLD-SNAPSHOT-01` | Status／ordered headers／body bytes／encoding v1／Snapshot id/version/hash 與 Admission/Operation 變動，ASGI 訊息不同；合法 HTTP framing | 應用層 Envelope 任何未授權變更拒絕；合法 framing 轉換允許；不把 Hash 宣稱為 TCP wire hash | NOT_RUN |
| `WORLD-SNAPSHOT-ACL-01` | 不同 Role 讀 Snapshot、備份與 Debug Log 中敏感 bytes、保留期／密鑰刪除／取回 Hash | 未授權 Role 無全文權限，Audit 無敏感 bytes，有限 retention/backup/secure purge 及真 bytes hash 驗證必須留下證據 | NOT_RUN |
| `WORLD-SNAPSHOT-SEPARATION-01` | **Given**：Candidate Payload Object 與已 `SEND_AUTHORIZED` 的 Snapshot Object 有獨立 immutable id/version，測試獨立實體儲存與去重共用 Blob＋受保護 Pin 兩種配置。**Action**：Candidate GC／外部 Object Delete 與 StartSend 併發；攻擊者竄改快照 Metadata Hash 或實際 bytes。 | **Expected**：Candidate 刪除後仍能按合法 owner/deadline/single-use 從原 Snapshot 實際 bytes 成功 StartSend；共享 Blob 不能在 Snapshot Pin 有效時遭刪；Hash 不符必拒絕，SEND_AUTHORIZED 不指回原 Candidate Payload；不可只靠不同邏輯 ID 判 PASS。 | NOT_RUN |
| `WORLD-POLICY-02` | Emergency 在 SEND_AUTHORIZED 前／後提交，另 NO_NEW_GRANTS 與既有 Grant、REVOKED 後再 ACTIVE | 前者拒絕 Authorize；後者已授權保留、Start 不再重查；NO_NEW_GRANTS 禁新 Grant，REVOKED 不可直接復活 | NOT_RUN |
| `WORLD-PROTOCOL-01` | **Given**：固定 Mirage upstream `88dc2008…` `start_send()` 含 Generation/Profile Emergency 二次查核，外部判定服務 `5a1ee26…` Freeze v1 以 SEND_AUTHORIZED COMMIT 為最終授權點。**Action**：比較行為，再以正式修補後 Mirage 原生交易、並行撤銷與 owner/deadline/single-use/Snapshot 測試實測 | **Expected**：舊 upstream 明確標為已知差異、非 compliant；**新版未實作前 NOT_RUN，不能宣稱已 PASS**。正式採納版不二次 Policy/Emergency 授權，仍攔截 owner、期限、single-use、Snapshot 不符 | NOT_RUN |
| `WORLD-PROTOCOL-02` | **Given**：SEND_AUTHORIZED 已提交且 Snapshot 完整，後續 Policy/Emergency 改變。**Action**：Runtime 或控制面嘗試自填／任意覆寫 Purge/Execution Fence；另觸發真實受保護 Snapshot purge/corruption | **Expected**：前者不得藉偽造 Fence 否決已提交授權；後者按執行不可用性 Fail-Closed，保留授權歷史與不可重送證據；兩者皆不得引入第二個政策授權點 | NOT_RUN |
| `WORLD-PROTOCOL-MATRIX-01` | **Given**：外部判定服務 Freeze v1 固定 `5a1ee26...`，Mirage source 固定 `88dc2008...`，Owner 已於 2026-11-21 明確採納（D-68）；只有 `start_send()` 局部差異已被觀察。**Action**：獨立取出 外部判定服務 Protocol baseline 狀態、Mirage Owner 決策紀錄、Mirage native 端到端合約測試（SEND_AUTHORIZED COMMIT、授權前後 Policy/Emergency、owner、deadline、single-use、Snapshot/ASGI、未知 COMMIT、傳輸分類） | **Expected**：三欄只能分別填 `ACCEPTED`（外部判定服務 baseline）／`ACCEPTED`（Mirage Owner）／`NOT_RUN`（Mirage native），不可互代；局部差異須列修正項但不能冒稱完整 conformance PASS/FAIL 已實測 | NOT_RUN |

## 3. Freshness、鎖、時間與輪替

| ID | 測試情境 | 預期 | 狀態 |
| --- | --- | --- | --- |
| `WORLD-EPOCH-01` | 同一 Session：Epoch advance 先提交與 SEND_AUTHORIZED 先提交的兩種排序（Grant 已存在） | 前者拒絕舊授權；後者保留已提交授權，即使 epoch 後變更也不在 StartSend 二次查 | NOT_RUN |
| `WORLD-EPOCH-02` | Session Head／Generation／Admission／Policy 與 AuthorizeSend 多 Backend 競態 | 按 Freeze v1 已證實的鎖與 COMMIT 排序；StartSend 不新增 Head／Generation lock／第二授權 | NOT_RUN |
| `WORLD-LOCK-01` | 真 PG 多 Backend: Candidate/Binding/Admission/Generation/Session Head/Key/Policy/Snapshot/GC；列出 READ COMMITTED 或實際 Isolation、FOR UPDATE/SHARE/KEY SHARE、FK INSERT/DELETE 隱含鎖、advisory lock 及 40P01/40001/timeout | 必須提供無循環 lock graph、真阻塞證據與 retry safety；任何未知 commit／已外部副作用不重試；**NOT_RUN 時不能宣稱全域無死鎖** | NOT_RUN |
| `WORLD-FRESH-01` | Profile／Key Revocation 分別在 SEND_AUTHORIZED 前／後 COMMIT | 前者拒絕 Authorize；後者不回溯已完成授權，StartSend 只檢執行條件 | NOT_RUN |
| `WORLD-FRESH-02` | Profile／Key Emergency 與 AuthorizeSend 多 Backend barrier | 以 Freeze v1 最終 COMMIT 線性化；後提交的撤銷不可改寫已提交授權 | NOT_RUN |
| `WORLD-TIME-01` | (A) Runtime 偽造過去 now；(B) Claim／Authorize／StartSend 各交易獨立 DB decision_time；(C) 同交易多期限只用一筆 decision_time；(D) 鎖等待跨過 deadline；(E) 判定後 COMMIT 延遲跨 deadline；(F) DB 時鐘倒退／skew／無法驗證時間 | 使用鎖後單次 DB 權威時間判定；Claim 用 authorization_deadline，Authorize/Start 用 transmission_deadline；E 必須保留 decision_time、**實際 COMMIT 時點／未知結果及後續起送是否拒絕**，依 BD-11 核准政策判定，**未定案不能宣稱 PASS**；F 需驗證時鐘下界／偏差監控，失去權威則 Fail-Closed | NOT_RUN |
| `WORLD-TIME-02` | Grant 後 JWS exp 已過、但 AuthorizeSend／StartSend 仍有 transmission_deadline | **不得**在 StartSend 加新 Token/Policy 撤銷檢查；依 Freeze v1 既有 transmission_deadline 及已核准的 Grant/Token window，未核准 grace 不啟用 | NOT_RUN |
| `WORLD-TIME-03` | StartSend Tx 開始時尚有效，等待 Admission/Pin 鎖跨 deadline | DB 鎖後 decision_time >= transmission_deadline → 拒絕，不得使用 transaction_timestamp() 或 Runtime now 當權威 | NOT_RUN |
| `WORLD-ROTATE-01` | 新增 K2、K1 仍可信且未撤銷 | 按明訂輪替政策，不由 Runtime 自選 key | NOT_RUN |
| `WORLD-ROTATE-02` | K1 被撤銷或相同 issuer/kid 被換不同 key material | 不得不經重新驗證繼續授權 | NOT_RUN |
| `WORLD-AUDIT-01` | SEND_STARTED 前 Snapshot Hash mismatch 或必要稽核 INSERT 失敗 | DB 安全必要 Evidence 無法 COMMIT 則第一個 ASGI bytes=0；狀態保留失敗與可對帳原因，不偽寫 send_started；不得用 Runtime 舊 Candidate 替代 | NOT_RUN |

### Snapshot 清理、Audit 與 Mixed Runtime 併行（新增）

| ID | 測試情境 | 預期 | 狀態 |
| --- | --- | --- | --- |
| `WORLD-PURGE-01` | Snapshot 清理與 SEND_AUTHORIZED、StartSend、活躍 Sender、UNKNOWN 結果同時競爭 | 先原子 non_retryable fence、禁止新 Start；活躍 Sender 保留同一 Snapshot 至終態／受控中止，Unknown 有界保留／對帳；Purge 永不復活資格 | NOT_RUN |
| `WORLD-PURGE-BOUNDARY-01` | **Given**：同一 Admission 已 SEND_AUTHORIZED；(A) Candidate 原始 Payload 已 Purged，但 Authorized Snapshot 仍完整；(B) Authorized Snapshot 進入受保護不可逆 `PURGE_PENDING/PURGED`，或可信 Hash 證明 `CORRUPT`；(C) Runtime 嘗試直接改 eligibility／purge reason；(D) Purge worker 在寫入不可逆 Fence 後卡住。**Action**：競爭 StartSend、GC 與 Policy/Emergency 變動並注入 worker crash | **Expected**：A 不因 Candidate GC 被誤判不可發送，仍遵守 owner/deadline/single-use；B 只能改 Snapshot execution eligibility、保留原授權歷史、Snapshot id/hash 與 Audit；C 依 ACL/窄函式拒絕；D 保留不可逆 Fence 並對帳／告警，不回復 AVAILABLE、不重送，也不創造 Policy Revocation | NOT_RUN |
| `WORLD-PURGE-RETRY-01` | **Given**：`AuthorizedSnapshotPurgeFence` 的 DB Commit 已確認、Snapshot 實體 bytes 尚在，Object GC 第一次 delete 失敗。**Action**：注入 GC crash／timeout，再由受限 GC 以相同 `gc_operation_id` 重試或受控人工清理；Runtime 嘗試恢復 AVAILABLE 或新建 Snapshot/Admission。 | **Expected**：Fence 提交即永久禁止該 Snapshot 新 StartSend；重試只影響物件清理，不撤回 Fence、不改寫 SEND_AUTHORIZED、無替代 Snapshot/Admission；殘存 bytes 遵守 ACL/retention，Audit/Tombstone/GC 進度可查。 | NOT_RUN |
| `WORLD-COMPAT-01` | 舊 DB Role／Credential／Connection Pool、舊二進位與新 schema/function/ACL，Runtime 自填新 protocol_version，Restore 舊 ACL | 舊 Role 直接受保護 DML／EXECUTE 被 DB 拒絕；身份／版本不信自填值；混版/回滾 Fail-Closed，不重授權 | NOT_RUN |
| `WORLD-AUDIT-02` | 已發出部分 ASGI bytes 後寫 Supplementary Audit 失敗、Unknown Transmission | 不宣稱未傳輸；不得重送、不能用補充事件偽造 SEND_STARTED；對帳與有限保留 | NOT_RUN |

## 4. 部分完成、COMMIT、GC 與 Restore

| ID | 測試情境 | 預期 | 狀態 |
| --- | --- | --- | --- |
| `WORLD-FAIL-01` | Receipt 已建立／JTI 已消費，但 Grant 失敗 | 不得再次消費原 JTI；沒有有效 Admission | NOT_RUN |
| `WORLD-FAIL-02` | World Commit 成功、Admission 建立失敗 | 既有 World Operation Result 可查回；不重做 Mutation | NOT_RUN |
| `WORLD-FAIL-03` | Grant 後 Policy/Emergency 在 SEND_AUTHORIZED 前撤銷；另測撤銷在 SEND_AUTHORIZED 後發生 | 前者無新授權、拒絕；後者授權保留，StartSend 不二次政策授權，Snapshot/owner/deadline 仍須通過 | NOT_RUN |
| `WORLD-FAIL-04` | SEND_STARTED 之後 Runtime Crash／TCP 失聯 | 結果 UNKNOWN／UNRESOLVED；無自動重送 | NOT_RUN |
| `WORLD-RECOVERY-01` | 未知 COMMIT（before／after ACK loss） | 有相同 ID／digest 可信結果才唯讀查回；不能盲目重試 | NOT_RUN |
| `WORLD-RECOVERY-02` | Operation ID 相同但 input digest 改變／ID 碰撞 | 明確拒絕而不轉移別的 Operation 結果 | NOT_RUN |
| `WORLD-RECOVERY-03` | **群組索引，不得產生 JUnit PASS**：各以 A～F 獨立 Fault Injection 實測；不可把「查不到 Receipt」當 rollback，亦不得把測試 Harness 知道的 COMMIT 真值當 Client 所知 | **Expected**：`03A`～`03F` 每案獨立 Given／Action／Expected、各有 JUnit 與 commit/DB 角色/副作用證據；本列只保留索引、不代表六案通過 | NOT_RUN |
| `WORLD-RECOVERY-03A` | **Given**：IngressTx 經 PostgreSQL 明確證實 rollback，可信查核顯示 World／外部 API／HTTP 均無效果，原 Operation Identity/Digest 未執行且 JWS／Session／Generation／Policy 仍有效。**Action**：以**同 ID、同 Digest** 發起受限重試 | **Expected**：僅在所有前提成立時可依政策重新驗證並受限執行；任一前提缺失則拒絕，不得以單純 JTI 未消費推定安全 | NOT_RUN |
| `WORLD-RECOVERY-03B` | **Given**：Ingress Replay＋Receipt 已提交，後續 Grant 失敗，JTI 已永久消費。**Action**：Runtime 用相同或換 Operation ID 重用同 JTI | **Expected**：拒絕重消費；原消費墓碑與失敗證據保留，沒有有效的新 Admission／Binding | NOT_RUN |
| `WORLD-RECOVERY-03C` | **Given**：IngressTx 的 COMMIT ACK 遺失，Client 無從得知實際提交，唯讀對帳暫不可用。**Action**：Runtime 嘗試用舊 JWS、新 JWS 或新 Epoch 直接重試 | **Expected**：全部停止重新執行；標 `UNVERIFIABLE` 並以原 Operation ID/Digest 對帳，查無結果不得解作 rollback | NOT_RUN |
| `WORLD-RECOVERY-03D` | **Given**：World Mutation/Commit 已由可信結果證實提交，Admission 狀態失敗或不可確認。**Action**：HTTP 重試或簽發新 JWS 以求再次執行相同意圖 | **Expected**：不重做 World／外部副作用；以固定 Effect Key／World Operation Result 對帳，不以新 JWS 消除原不確定性 | NOT_RUN |
| `WORLD-RECOVERY-03E` | **Given**：`SEND_STARTED` 已可能提交，Sender 已輸出首個 ASGI bytes，但補充 Audit ACK 遺失。**Action**：Runtime Crash 後重開連線、要求重送 | **Expected**：不新建 HTTP 傳輸、不宣稱 bytes=0；保留 UNKNOWN／UNRESOLVED，只有原本仍存活的傳輸可依已核准政策完成 | NOT_RUN |
| `WORLD-RECOVERY-03F` | **Given**：外部 Snapshot Object 已被刪除，但 World DB 的 Purge/Fence 記錄因 COMMIT/ACK 或 Restore 不確定而欠缺。**Action**：從舊 DB 備份恢復已授權 Snapshot 後要求 StartSend | **Expected**：沒有外部可信刪除／恢復錨點與可用 bytes 證據即 Quarantine、不得重新發送；DB 舊紀錄不能復活已失效 Snapshot | NOT_RUN |
| `WORLD-GC-01` | GC 對未過期 JTI／在途 Binding／UNRESOLVED 操作嘗試清理 | 全部保留；超過所有保留窗口才有權 GC | NOT_RUN |
| `WORLD-GC-02` | 多 Backend GC 對同 Candidate Full Scope/Version 的 FK/Binding/Grant/SnapshotPin 競爭；protected_refs 提示過時；deadlock/lock timeout | 真 DB 的 FK 隱含鎖＋受保護轉移防止 orphan／TOCTOU；GC 不以 Runtime protected_refs 為權威，未知 COMMIT 不猜測 | NOT_RUN |
| `WORLD-GC-03` | 長期保留 Evidence／Binding，原 Candidate Raw Payload 已到期；比較 Active Snapshot、未解傳輸／Unknown 結果與有限保留窗口 | 原 Candidate 已 Purged，但合法 Snapshot 可用時不影響已提交授權；Snapshot 欄位／Purge Tombstone 不被刪成可重送；Active/Unknown 需有安全保留／有界中止 | NOT_RUN |
| `WORLD-RESTORE-OP-01` | 舊 DB 回滾至 Operation Identity 建立前，但外部已執行 OP-100；新 Namespace/Epoch 下再次發起同一意圖 | 先 Quarantine 並向外部 Effect/World Receipt 對帳；未知不可重新發送或產生新外部 Key，沒有穩定證據就永久阻擋或人工處置 | NOT_RUN |
| `WORLD-RECOVERY-04` | SEND_STARTED commit ACK 遺失：A 原 Sender 仍持原連線；B 對帳查得 SEND_STARTED；C 查無／仍未知 | A 只允許原本已開始的傳輸按期限結束；B 只證明 DB 狀態，不得新建 HTTP；C at-most-once 禁自動重試／新 JWS／Snapshot | NOT_RUN |
| `WORLD-RESTORE-01` | World DB 還原到舊 Replay／Revocation／Epoch 快照 | 發送 Quarantine；舊 Receipt／Token 不重新有效 | NOT_RUN |
| `WORLD-RESTORE-02` | 還原後清理計算、Clock Skew、Key Rotation 不確定 | 不自動提前解除隔離；有可驗證的完整恢復證據 | NOT_RUN |
| `WORLD-RESTORE-TOMBSTONE-01` | **Given**：在備份後建立並清理 Candidate，寫入不可復活 Tombstone 與後續 Operation/Purge 事件；舊 World DB 備份**不含該 Tombstone**。**Action**：還原舊備份，嘗試重建原五欄 Logical Key／不同 version，再分別令外部錨點可用、不可用／被倒退 | **Expected**：還原前在受保護控制面啟用 Quarantine；無法核對**不隨 World DB 回退**的錨點完整性／單調性／事件涵蓋範圍時始終禁用正式發送與 Identity 復活；只有可信 reconciliation、Owner 批准與正式放行流程才能解除；此案 NOT_RUN 不代表錨點已實作 | NOT_RUN |
| `WORLD-RESTORE-PUBLISH-01` | **Given**：World DB 與外部 Restore Anchor 是不同提交域。**Action A**：DB Tombstone/Operation 已 COMMIT，但 Anchor publish 斷線／ACK 未知；**Action B**：外部 Anchor `PREPARED` 先發布，DB 明確 ROLLBACK；**Action C**：舊錨點 head 被重播／降低 generation。 | **Expected**：A 不宣稱最新事件已涵蓋，維持 Quarantine 直到 Operation ID/Digest/外部 effect 與 durable Head 完整對帳；B 不能把 PREPARED/UNUSED 當業務提交或執行不存在操作，單調 Head 不回退；C 受獨立權威拒絕。任何未知結果都不可恢復正式發送。 | NOT_RUN |
| `WORLD-RESTORE-FENCE-01` | **Given**：外部控制面已接受最新 Fence Head H2，另備 H1/H2 checkpoint；H1 有合法簽章但 generation 較低，H2 的 digest manifest 涵蓋 Candidate Tombstone、Binding、Operation／Replay／Revocation；(B) Tombstone DB COMMIT 成功但 H2 checkpoint 發布前當機／ACK 未知。**Action**：還原只對得上 H1 的舊 World DB，嘗試重播 H1、降低 generation、以 Runtime 憑證寫入 Fence、使用錯 digest／timeline 或落後的有效 H1 冒稱涵蓋後續 Tombstone | **Expected**：獨立最高可信 head/世代拒絕可判定的降版與改寫；B 的跨交易 checkpoint 缺口**不會**因 H1 簽章有效而通過，不可證明完整時持續 Quarantine；無可信 reconciliation／獨立 Owner/DBA/Security 放行證據不得恢復發送 | NOT_RUN |
| `WORLD-MIGRATION-01` | Schema／ACL／函式版本不匹配 | Startup/Release Preflight Fail-Closed；正式發送不能開始 | NOT_RUN |
| `WORLD-MIGRATION-02` | 舊 Runtime 仍持舊 Role/Pool、舊 Advisory Key 或 schema rollback | 撤銷舊 Role protected DML/EXECUTE 並清空 Pool；Runtime 自填 version 不具權威；舊版本不能重開發送／權限 | NOT_RUN |
| `WORLD-DISABLE-01` | 實際 Trusted-send 控制面無法確認、Runtime 可自行啟用、或 Restore 使禁用狀態倒退 | Release Preflight 失敗、正式發送停止；不得以未經證實的 `DECEIVE OFF` 字樣代替控制證據 | NOT_RUN |
| `WORLD-AVAIL-01` | Runtime 佔滿自身連線、持鎖／慢交易 | Control／Revoke 仍可連線或明確停用服務；記錄延遲與不符項 | NOT_RUN |
| `WORLD-AVAIL-02` | R3-A Caller 搶先提交合法且與 JWS 一致的資料、批量消耗不同 JTI；Verifier Caller 身分／Session／Scope 限流 | 不得宣稱已驗證真實入口；依受保護 Caller 認證及總量防護拒絕／告警；已消費 JTI 不復活，未知 Commit 不重試 | NOT_RUN |

**測試 ID 精度**：`WORLD-RECOVERY-03` 是**不具可執行 PASS 的父索引**；上方 `03A`～`03F` 已各自寫明 Given／Action／Expected 並維持 NOT_RUN，未來 JUnit 只准以各子案產生實際結果，不得把父索引或跨文件重述當作同一測試。文件檢查器的 ID 唯一性只是**靜態保護**，不證明真實回歸已執行。

## 5. 已有回歸與本輪證據不可混淆

| 類別 | 現有證據的正確說法 |
| --- | --- |
| 外部判定服務消費端歷史問題紀錄（已另行封存） | 先前報告的 13/13 PostgreSQL 與 3 種**成功重現權限缺口**；不是 ACL 修復 PASS |
| Mirage `main` 既有測試 | 可當作功能／契約 regression baseline；未曾以新角色證明本 ADR 的安全強制 |
| 此 ADR v0.2 的新 `WORLD-*` | **全部 NOT_RUN**；只有設計好的 scenario／expected result，無執行結果 |
| 未來 Draft PR 與 CI 綠燈 | 需分別保留 DB 角色測試、並行、Unknown Commit、Restore、Transport/ASGI snapshot、版本相容和 Owner Signoff |

## 6. 關閉與部署限制

測試報告、ACL Dump、容器秘密掛載、真實 Postgres 版本、Key Trust Registry、Restore 手冊與 Owner／DBA／Security／Release Approver 簽核缺一不可。未完成時：`MIR-SEC-WORLD-001: OPEN`、`外部端權限驗收: NO-GO`、`production trusted-send mode: DISABLED`（**政策要求；真實強制控制尚待查核**）。沒有 HTTP 攻擊回報或 PR 合併不能取代證據。

## 7. v0.2 契約完成／狀態交付規則

- 本計畫所有新增或改寫之 `WORLD-*` case 均為 **NOT_RUN**；Mirage API `main` `88dc2008fd35a2d3873949a769653dc9f18e8980` 的 Native baseline 與外部判定服務 `main` `5a1ee26dcf79f04cf29345a0403e3f3f8082358b` 的 Freeze v1 **不可混同**，也不能推論新保護已採納。
- 真 PG 測試需使用獨立角色與多 Backend；驗證 `FOR UPDATE/SHARE/KEY SHARE`、FK implicit locks、lock_timeout、40P01、40001、真正的 role membership／SET ROLE、DB-derived decision_time、外部 Snapshot/Object Storage version、quarantine/mixed binary、各層 ACK lost。
- `WORLD_COMMITTED_ADMISSION_UNAVAILABLE` 仍只是 reconciliation classification，**不是 Admission／World 狀態**。所有測試報告必須固定 commit SHA／schema／DB 角色／容器與 source hash，且分開記錄實際 PASS／FAIL／SKIP／NOT_RUN。
- Mirage Owner／DBA／Security／Release Approver 未簽核、真實 ACL／Policy race／Payload Purge／Restore／Mixed Runtime 尚未通過時：`Architecture: Proposed | MIR-SEC-WORLD-001: OPEN | 外部端權限驗收: NO-GO | Production DECEIVE: OFF`。
