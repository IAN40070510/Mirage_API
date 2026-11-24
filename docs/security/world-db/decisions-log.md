# MIR-SEC-WORLD-001 — 架構決策歷史與審查修正

> 本文件以 Mirage 原生授權契約為維護範圍。歷史跨專案整合證據已移交保存，原生安全要求與驗收狀態維持原紀錄。

**Consolidated v0.2 — 2026-11-21；Architecture Proposed／Weakness OPEN／Mirage release NO-GO。** 本表於同一文件分支依次 Commit，保留 v0.1 歷史。

本紀錄把先前多輪對話中的**結論、假設、已否決方向、仍待 Owner 核准的決策**整理為可版本控制的狀態；不是把每則聊天當作已正式簽核的會議紀錄。現行人員簽核優先遵循 [Solo Developer Security Acceptance v1](solo-developer-security-acceptance-v1.md)，以前草稿所列 DBA／Security／Release Approver 為技術責任領域，不再是四位獨立人工審核者的強制配置。

## 已固定為 ADR 提案的方向（不等於已實作）

| ID | 設計結論 | 原因／邊界 |
| --- | --- | --- |
| D-01 | 缺口正式識別 `MIR-SEC-WORLD-001`，發布驗收與漏洞識別分開記錄 | 維持原生漏洞、修補與發布證據的可追溯性 |
| D-02 | 選方案 B：DB／窄特權角色強制關鍵狀態轉移 | R1 Runtime DB 身分能繞過應用程式狀態機，不能以程式自行守規矩當成 DB ACL 保證 |
| D-03 | 依 R1–R5 能力矩陣定義攻擊者；等價 SQL Injection 歸 R1 能力 | 不用攻擊名稱重複計算相同 DB 能力；R4/R5 另案 |
| D-04 | Runtime、Verifier、Authorizer 用分離 DB 身分、DSN／連線池、秘密與來源 | 不在低信任 Pool 使用 `SET ROLE`；同容器／同 Module 不自動代表可信隔離 |
| D-05 | `domain_validation='passed'` 與 `contract_validation='passed'` 是 Runtime 輸入／稽核資訊 | 不能從一個 DB 字串推得密碼學驗證來源 |
| D-06 | Verifier 必須自己驗原始 JWS、Claims、部署綁定、Session、Revocation、Replay | Runtime 不得自填 `verified`、issuer、policy、時間或 Receipt 核准結果 |
| D-07 | `replay_entries` 防重放，Receipt 證明驗證、Binding 控制一次使用、Operation Receipt 控制對帳 | 四者證明不同主張，不能互相代替 |
| D-08 | 同一 PostgreSQL IngressTx 原子消費 JTI 並建立可信 Receipt | 不承諾跨 DB 原子性；已消費 JTI 不因後續 Grant 失敗而重新開放 |
| D-09 | **IngressTx** 先建立 Replay Tombstone＋Receipt；**GrantTx** 僅鎖定並檢查既有 Receipt／Candidate／Generation／撤銷，原子建立唯一 Binding＋Admission，**不重新建立 Receipt** | 修正 v0.1 不精確措辭；兩階段在不同交易提交，不能假裝同一建立交易 |
| D-10 | 授權使用 Envelope v1 的實際應用層 bytes，Candidate 受保護不可改 | Hash 不證明 ASGI／TLS 客戶端實際收到；任何後置內容變動使 Admission 失效 |
| D-11 | **已由 D-32／Freeze v1 取代**：只在 AuthorizeTx 以受保護 Receipt／Binding 做最新 Epoch／Key／Policy 查核；StartSendTx 不二次授權 | 原敘述要求 StartSend 重查 Policy／Epoch，與 Mirage Protocol Freeze v1 衝突，故明確廢止 |
| D-12 | 不要求「整個 HTTP 請求單一交易」；僅要求「每個安全狀態轉移單一交易」 | World Commit／外部 side effect 與 Admission 分階段，有故障不一致，需對帳 |
| D-13 | Operation ID＋Input Digest 供唯讀 reconciliation；COMMIT 未知不得盲目重試 | 查無 Receipt 無法排除仍在途或未知提交；不得用逾時推定失敗 |
| D-14 | 不擴張 Admission State 表達稽核原因；失配前使用 `ABANDONED`＋原子 audit | SEND_STARTED 之後不能假設沒發送，不自動重送 |
| D-15 | 既有 `pg_advisory_xact_lock` 是交易級；重構需保留鎖鍵相容 | 不把它當 Session-level；不得在鎖鍵不相容時混跑新舊版 |
| D-16 | Restore 時 Fail-Closed Quarantine，不靠單純還原 DB 取得安全性 | Replay／Revocation／Epoch 舊狀態可能倒退；須核實舊 Token 全部無效才解禁 |
| D-17 | DB ACL 與 SECURITY DEFINER 都要真實 PG 負面測試 | 不能以 superuser fixture 或 13 項「成功重現」測試宣稱缺口修復 |
| D-18 | Request Provenance 本輪採**語意 A**：JWS 與 Runtime 提交 Canonical Request 相符；不證明實際 HTTP 入口來源 | 語意 B 需可信 Gateway／入口證據，另案；後續 Binding 仍須同 Request Fingerprint |
| D-19 | Verifier 的 Verified Context 僅是內部不可變資料，**不是 DB 可獨立驗證的證明** | 來源可信性依真實驗章、受限 Writer Role、窄介面與秘密／網路隔離，不接受 Runtime 自填 verified JSON |
| D-20 | Ingress Key Revocation Guard、Replay Tombstone、Receipt 共用**同一 PostgreSQL DB／Physical Connection／Transaction Coordinator** | 現有 `trusted_session.py`、`postgres_replay.py`、`key_revocation.py` 各自連線，需要重構內部交易介面與 cleanup；禁止 Store 自行 commit |
| D-21 | Candidate Submission、Validation、Promotion、Binding 為**不同授權語意**；不強制新增 staging table | Authorizer 不信任 Runtime 自填 hash／Scope／驗證旗標；Promotion 對 bytes＋Policy Revision 原子固定，避免 Validation→Promotion TOCTOU |
| D-22 | Candidate Promotion 失敗不得留下半可信物件；GC 不能刪除受保護 Bound Candidate | 需檢查真正 FK／Row Lock／GC，不能只憑 Runtime 提交的 protected_refs 清單 |
| D-23 | `WORLD_COMMITTED_ADMISSION_UNAVAILABLE` 是跨交易 **Reconciliation Classification** | 禁止擅自加入既有 AdmissionState／World Commit Enum |
| D-24 | 正式發送 OFF 須有獨立強制、可驗證且 Restore 後不倒退的控制面 | `production DECEIVE OFF` 目前作為政策要求，不宣稱存在已驗證的全域功能開關 |
| D-25 | `VerifiedContext` 只作同一可信 Verifier 程序內部資料；Receipt DB 信任由實際驗章、專用 Role、ACL、受限 Writer 與受控交易建立 | 不以 Python 型別／序列化 claims JSON 作 PostgreSQL 安全證明；跨服務 Context 傳送需獨立認證與防重放協定 |
| D-26 | `NOINHERIT` 不能取代 Role Membership／`SET ROLE` 驗收 | PG17 `pg_auth_members` 的 `set_option`／`inherit_option`／`admin_option`、間接角色鏈、`PUBLIC EXECUTE`、schema `USAGE` 都須從真實 Runtime 身分檢查 |
| D-27 | 長耗時 Candidate Validation 可在交易外，但 Promotion 必須短交易、鎖版本並重核不可變 Evidence／目前政策 | 版本須由 DB 受保護生成，Evidence 綁 Scope／Envelope／Contract／Policy／Source／Validator；避免長交易持鎖阻礙 Emergency Revoke |
| D-28 | **已由 D-32／D-34 取代**：升版不等於撤銷；Policy Revocation 只在最終 SEND_AUTHORIZED COMMIT 前限制新授權 | StartSend 在授權後只檢查執行條件，不再因 Policy 改變拒絕已授權快照 |
| D-29 | Candidate Evidence／原始 Payload／Snapshot／Binding／Pin 分離；GC 按完整 Scope／Version 與不可重試 Fence 決策 | 原 Candidate Purge 不自動否定已授權 Snapshot；Snapshot Purge 永遠取消起送資格，GC 不可只信 protected_refs |
| D-30 | Ingress 明確 rollback、JTI 已提交、未知 COMMIT／外部副作用／SEND_STARTED 分階段對帳 | 查到 SEND_STARTED 只代表 DB 提交，不授權新的 HTTP 傳輸；未知結果不能換新 JWS／Admission |
| D-31 | Candidate→Binding／Admission 只是局部依存順序，不能在未盤點 Session Head／Generation／Admission／Key／FK 鎖前宣告全域安全 | 目前 Grant 先取 Generation，Session Resolve 先取 Head；要交付無循環 DAG 與對抗測試後才能訂總序 |

## v0.2 Contract Freeze 決策補充（均為 Proposed，未經 Owner 批准）

以下 D-32～D-47 是**取代前述矛盾條文**的文件提案，不是已執行的 DB 改造；保留 D-11、D-28 的歷史記錄但不可據此要求 StartSend 二次授權。

| ID | 規範性選擇 | 拒絕的捷徑／驗收 |
| --- | --- | --- |
| D-32 | `SEND_AUTHORIZED` COMMIT 為唯一授權線性化；Policy、Emergency、Epoch、Key 只在 Commit 前否決，授權後 StartSend 不二次查 | 需要更晚撤銷須 Freeze v2；依 `WORLD-POLICY-01`、`WORLD-POLICY-02`（NOT_RUN） |
| D-33 | 各交易鎖定後一次 DB-derived `decision_time`；Claim → authorization_deadline，Authorize/Start → transmission_deadline；decision_time 非 commit 時刻 | Runtime 自填 now、lock wait 跨期限／clock skew；`WORLD-TIME-01`（NOT_RUN） |
| D-34 | Policy `ACTIVE／NO_NEW_GRANTS／REVOKED` 的不可逆 Revision；歷史 Grant 不等於可新授權 | Policy 後撤銷不回溯 SEND_AUTHORIZED；`WORLD-POLICY-01`、`WORLD-POLICY-02`（NOT_RUN） |
| D-35 | Operation Identity `UNIQUE(authority_namespace,namespace_epoch,operation_id)`，單一不可變 Digest／External Effect Key | 禁 UPDATE／UPSERT 更改 Digest，衝突拒絕；`WORLD-OPERATION-01`、`WORLD-OPERATION-03`（NOT_RUN） |
| D-36 | 首次**持久化 Snapshot Proposal**、Materialize／Hash 驗證、`OperationSnapshotBinding` Write-Once 且與 Admission／Scope／Generation 綁定 | 不同 Snapshot 衝突，相同只能讀回；Commit ACK 未知先對帳；`WORLD-OPERATION-02`（NOT_RUN） |
| D-37 | `CandidateEvidence`、`CandidatePayload`、`AuthorizedSnapshot`、`GrantBinding`、`PurgeTombstone` 分離 | 不用 FK 代替狀態機／清理政策；`WORLD-LIFECYCLE-01`、`WORLD-LIFECYCLE-02`、`WORLD-LIFECYCLE-03`（NOT_RUN） |
| D-38 | Candidate 原 Payload Purged 但 Snapshot 有效時可依已授權執行；Snapshot Purged／Corrupt 則永久不可起送 | 不回 Candidate 取內容；`WORLD-PAYLOAD-01`、`WORLD-PAYLOAD-02`、`WORLD-PAYLOAD-03`（NOT_RUN） |
| D-39 | Snapshot 對應既有 Envelope v1（status/headers/body），不把 Hash 說成 TCP wire bytes | ASGI／HTTP framing 分層、測試非法重寫；`WORLD-SNAPSHOT-01`（NOT_RUN） |
| D-40 | Snapshot 安全保留、Role ACL、加密／備份、Purge 前 non-retryable fence，活躍 Sender 不可被 GC 非預期移除 | 敏感 raw Payload 不進 Debug/Audit；`WORLD-SNAPSHOT-ACL-01`、`WORLD-PURGE-01`（NOT_RUN） |
| D-41 | 完整 FK 隱含鎖／advisory／row lock 與 Isolation、deadlock/timeout/外部效果一起驗收 | 不能單靠 Candidate→Binding 宣告全域無死鎖；`WORLD-LOCK-01`（NOT_RUN） |
| D-42 | `SECURITY DEFINER` 以受保護 Receipt→Operation→Subject/Scope 導出權限；DB LOGIN／SESSION_USER 不是業務主體 | Role、owner、scope、generation 輸入偽造負面測試；`WORLD-IDENTITY-01`（NOT_RUN） |
| D-43 | Operation Epoch 不代表外部副作用已 Rollback；Restore Quarantine 與 External Effect Key 先對帳 | 不得用新 Epoch／JWS 偷偷重做；`WORLD-RESTORE-OP-01`（NOT_RUN） |
| D-44 | `SEND_STARTED` COMMIT ACK 未知不自動 Retry／新 HTTP／新 Snapshot；查到 DB 狀態不等於 Client 收到 | 沒有經核准續傳協定時 at-most-once；`WORLD-RECOVERY-03`、`WORLD-RECOVERY-04`（NOT_RUN） |
| D-45 | Mixed Runtime 需不同 Credential／DB Role，舊 Role ACL 撤銷、舊 Pool 回收、Schema/Function Preflight | Runtime 自報 protocol_version 非安全憑證；`WORLD-COMPAT-01`（NOT_RUN） |
| D-46 | 一切新控制先 NOT_IMPLEMENTED／NOT_RUN，原 PG 13/13 有 3 個漏洞重現案例 | 不以歷史測試或文件審查替代原生修補 |
| D-47 | `WORLD_COMMITTED_ADMISSION_UNAVAILABLE` 永遠僅為 reconciliation classification | 不新增 Admission enum，不將回復條件變成重試權限 |

### v0.2 精確化補遺（D-48～D-52；仍為 Proposed）

| ID | 具體修正 | 證據／限制 |
| --- | --- | --- |
| D-48 | Protocol Freeze v1 的目標協定由本 ADR 定義，原生 start_send 的符合性以實測判定 | SEND_AUTHORIZED 提交後只執行 owner、deadline、single-use 與 Snapshot 檢查，保留完整符合性測試 |
| D-49 | Candidate 使用完整六欄 Version Identity，另永久保留不允許重用的五欄 Logical Key；Payload Purge Tombstone 必須受 Restore Quarantine 保護 | `migrations/001_world_runtime.sql` 現有五欄主鍵**沒有** `candidate_version`；新增版本／不可逆鍵保留是擬議 Migration，不能虛稱現有 ACL 已保證 |
| D-50 | Rollback 重試須具 DB **明確 rollback 證明**、World/External/HTTP **零不可逆效果證明**、原 Operation Identity/Digest 未執行及全部權威期限／Scope 仍有效 | 查無 Receipt、JTI 尚未消費或換新 JWS 單獨都不夠；未知 COMMIT 維持 UNVERIFIABLE，不得自動重試 |
| D-51 | ADR 版本、歷史分支名、兩份 Source SHA、當前文件 Commit、實作與新驗收狀態**分欄追溯** | 同一追蹤 Markdown 無法可靠內嵌自己的 HEAD SHA（寫入會改變 Commit）；實際 Document Commit／文件檢查結果由 Git/PR 外部證據提供 |
| D-52 | 區分鎖後 DB `decision_time` 與最後 `SEND_AUTHORIZED` COMMIT，並保留跨 Deadline 延遲與 DB 時鐘回撥的 Owner 決策 | `decision_time < deadline` 只證明判定當下合法；不能推出 COMMIT 必然在期限前。StartSend 仍按 Freeze v1 的 transmission deadline，不能自行引入第二授權 |

### v0.2 協定與證據狀態補錄（D-53～D-57；仍為 Proposed）

| ID | 具體修正 | 證據／限制 |
| --- | --- | --- |
| D-53 | 原生授權契約採納與實作符合性分別記錄，後續採納決議見 D-68 | WORLD-PROTOCOL-01／02 需要原生實作與並行測試，文件採納不產生通過證據 |
| D-54 | Restore／Purge 的非復活證明必須錨定於 World DB **還原範圍外**、不可由 Runtime 改寫或同時倒退的控制面／Ledger／單調 checkpoint | 只驗還原庫內 Tombstone 存在、備份內表一致或自填 timestamp 不足；錨點缺失／不可驗持續 Quarantine；`WORLD-RESTORE-TOMBSTONE-01` NOT_RUN；實際選型 BD-05 OPEN |
| D-55 | BD-11 未核准前固定鎖後單一 DB decision_time／未知 Commit 停止新起送／無法判定權威時間即 Fail-Closed | 不宣稱 commit-before-deadline；產品若要求 Commit 先於期限則保持正式發送關閉。已 COMMIT 的授權不回溯改成 rollback；Policy Race 仍須採納 Freeze v1 |
| D-56 | 文件／ID／遠端檔案一致性可 PASS 但安全驗收仍 NOT_RUN；`WORLD-RECOVERY-03` 為群組，A～F 需每一子案具 Given／Action／Expected | 靜態檢查不能代替 native conformance、PG ACL、GC、Restore、Commit Loss 的 runtime／DB 證明 |
| D-57 | Snapshot Purge Fence 僅限事實上不可安全執行／清理的受保護狀態，禁止將其變成 Freeze v1 授權後的任意 Policy Revocation 入口 | `WORLD-PROTOCOL-02` 驗證已授權但 Snapshot 完整時，不因新 Policy／Emergency 或偽造 Fence 而作第二授權 |

### v0.2 三軸審核／Anchor 防回滾／執行資格補錄（D-58～D-62）

| ID | 具體修正 | 證據／限制 |
| --- | --- | --- |
| D-58 | 審核拆三軸：`Mirage Protocol Freeze v1 Protocol baseline=DEFINED IN ADR`、`Mirage Owner adoption=PENDING`、`Mirage native conformance=NOT_RUN` | 固定 Mirage SHA 已有局部 `start_send()` 差異，但不能以單點推得完整合約實測結果；`WORLD-PROTOCOL-MATRIX-01` 覆蓋全部授權／傳輸項 |
| D-59 | Restore Anchor 至少記 `restore_fence_id`、Namespace、monotonic generation、資料庫 timeline/position、涵蓋資料 canonical digest、前序 hash、時間與來源認證；外部權威需保存**防重播的最新 head**，並定義 DB COMMIT 與外部 Head durable ACK 之間的發布／對帳窗口 | 僅有 hash chain 而沒有外部可信最高 head，可整條重播舊版；**DB 已提交但 Anchor 更新落後也是缺口**，digest 未明確涵蓋 Tombstone/Binding/Operation/Replay/Revocation 不代表它們完整；`WORLD-RESTORE-FENCE-01` NOT_RUN |
| D-60 | Admission 授權狀態、Candidate 原始 Payload retention、**已綁 Authorized Snapshot execution eligibility** 是不同軸線 | Candidate 原始 bytes Purged 且 Snapshot 完整仍可合法起送；Snapshot 不可用才拒絕，Purge 不改寫歷史 SEND_AUTHORIZED；已提交不可逆 `PURGE_PENDING` 即使 GC 卡住也不能重開資格；`WORLD-PURGE-BOUNDARY-01` NOT_RUN |
| D-61 | 安全測試結果應有 `NOT_RUN`／`BLOCKED`／`PASS`／`FAIL`／`STALE` 與固定 evidence refs 的狀態轉移；文件靜態檢查不能出具安全 PASS | 現行 checker 尚未接真實測試 evidence，因此強制新增案例仍為 NOT_RUN；未來引入 PASS/BLOCKED 需另審核證據來源與版本失效條件 |
| D-62 | Protocol Freeze v1 與原生程式版本各自記錄，BD-11 約束仍維持 | decision_time 不證明 COMMIT 早於 deadline，未知 COMMIT 必須對帳，已提交授權不可回溯否認 |
| D-63 | Candidate Payload 與 Authorized Snapshot 必須有獨立受保護的**邏輯及儲存物件身分**；共享底層去重 Blob 時由實體 Pin／引用權威防 Candidate GC 刪 Snapshot | SEND_AUTHORIZED 僅綁 immutable Snapshot id/version/storage object version，取回真實 bytes 重算 Hash；`WORLD-SNAPSHOT-SEPARATION-01` NOT_RUN |
| D-64 | 拆成 `CandidatePayloadPurgeFence` 與 `AuthorizedSnapshotPurgeFence`，各獨立 Write-Once、Scope 與受限寫入 | 前者只禁止原 Candidate 再使用；後者不可逆禁止 Snapshot 新起送但不改 SEND_AUTHORIZED，Runtime 不可自填；`WORLD-SNAPSHOT-SEPARATION-01`、`WORLD-PURGE-RETRY-01` NOT_RUN |
| D-65 | Restore Anchor 與 World DB 不具天然原子提交，必須覆蓋 **DB-first／Anchor-first** 兩種錯誤次序及未知 ACK | DB committed／Anchor missing → Quarantine；Anchor PREPARED／DB rollback 不構成業務提交；獨立最高可信 Head 不回退，Operation Digest 對帳；BD-05 OPEN，`WORLD-RESTORE-PUBLISH-01` NOT_RUN |
| D-66 | `AuthorizedSnapshotPurgeFence` 已提交但 Object GC 失敗時只重試 cleanup，**永不恢復 eligibility** | 用固定 `gc_operation_id` 冪等清除／受控介入，保留原 ACL、Audit、Tombstone；不得產生替代 Snapshot／Admission；`WORLD-PURGE-RETRY-01` NOT_RUN |
| D-67 | 安全測試結果必須經 `NOT_RUN → RUNNING → PASS/FAIL/BLOCKED`，阻塞解除／修復失敗後只能重跑；PASS 綁定不可變實測證據 | 固定 Mirage SHA、Migration/Schema、PG 版、Role、資料集、時間、Fault Injection 與脫敏日誌；文件檢查 PASS 不轉成 `WORLD-*` PASS；`WORLD-SNAPSHOT-SEPARATION-01`、`WORLD-RESTORE-PUBLISH-01`、`WORLD-PURGE-RETRY-01` 全部 NOT_RUN |
| D-68 | **2026-11-21 使用者正式決定：Mirage 採納 Mirage Protocol Freeze v1，授權一致性優先。** `SEND_AUTHORIZED` COMMIT 是唯一授權線性化點；`StartSend` 不以後續 Policy／Emergency 變動作第二次授權，但必須核對可信 owner、期限、single-use 與 Snapshot 執行前置條件 | 只更新 **Mirage Owner adoption=ACCEPTED**；Mirage native conformance 與 World DB authority remediation 仍分別為 **NOT_RUN／NOT_IMPLEMENTED**。本次只在獨立修補分支改原生行為與回歸，不修改 Mirage `main`、staging 或 production send 設定 |
| D-69 | **2026-11-21 使用者決定同一 Oracle 主機上以不同獨立容器／OS 身分部署 Verifier 與 Authorizer。** 不增設第二台主機；Runtime、Verifier、Authorizer 的 SCRAM DB Login、DSN、Secret Mount 與連線池完全隔離，禁止透過 `SET ROLE` 共享高權限連線 | R1 Runtime 憑證竊取須無法讀／執行受保護 Receipt、Binding 與 Admission。部署級 `pg_hba.conf`、`pg_auth_members`、Secret 與 Connection Pool 重用須有實測證據；同機 root／Docker daemon 被控制不涵蓋。實作與 acceptance **NOT_RUN** |
| D-70 | **2026-11-21 使用者同意 Candidate 採 Clean Cutover：保留商品、Cart／Inventory、Medusa 的 Candidate 生成能力；淘汰舊 `candidate_records → PostgresAdmissionControl.grant()` 作為正式發送的可信授權入口。** 新流程必須經獨立可信 Validation／Promotion、Ingress Receipt、一次性 Grant Binding 與獨立 Authorized Snapshot；舊流程不得成為降級回退。 | 不承諾舊 `put()`／`load()`／`gc()` 取得可信授權的向後相容性；未經對帳的既有 Candidate／Admission 不自動升格或重新授權。待新安全路徑與角色 ACL 原生驗證完成後才切換；目前 `from_environment()` Release Fuse 保持不可旁路，正式發送 **DISABLED**。本決策不是實作完成或 Owner／DBA／Security 全面簽核。 |

### HTTP 效能與傳輸安全補錄（2026-11-22；非新安全驗收）

| ID | 討論結論 | 狀態／不得過度宣稱 |
| --- | --- | --- |
| D-71 | **效能目標提議**：預先生成內容的合法快路徑暫以 `P50 ≤ 150 ms`、`P95 ≤ 400 ms`、`P99 ≤ 1,000 ms` 規劃，品質／有效回應率與錯誤率需共同驗收；即時 AI 生成另訂基準。先量測再優化 Role-bounded pool 與預生成內容。 | **PROPOSED／HTTP END-TO-END NOT_RUN**；隔離 PG 單次 `SELECT 1` 連線重用 0.162 ms、重連 4.787 ms 不代表全 HTTP 速度或實際加速倍數；效能 SLO 不是授權截止期限。見 [延遲紀錄](http-latency-baseline.md) 與 [整合總表](remediation-and-performance-register.md)。 |
| D-72 | **傳輸閘門待實作約束**：只在 `StartSend` 通過外部 Fence 不足以保障後續 ASGI bytes；Send／Snapshot Purge／Restore 需要統一的受保護起送／租約／Pin 與並行隔離協定，外部 Fence Head 必須真正在 World DB 還原域外，證據異常持續 Quarantine。 | **REQUIRED DESIGN BOUNDARY／IMPLEMENTATION NOT_COMPLETE／SECURITY NOT_RUN**；不可宣稱 HTTP 網路傳輸在 PostgreSQL 單一交易內，亦不可將 R1 控制誇大為受控 Runtime 遭完整接管時的 R4 保證。具體實作與故障注入見 [整合總表](remediation-and-performance-register.md)。 |
| D-73 | **2026-11-24 Owner `IAN40070510` 採納 [Solo Developer Security Acceptance v1](solo-developer-security-acceptance-v1.md)**：用 Owner 最終簽核＋全矩陣真實證據取代四位不同人工角色各自簽核；外部 Reviewer 建議但非本個人專案的一般阻擋條件，未取得不得冒稱第三方審核 | **GOVERNANCE ADOPTED / RELEASE NOT APPROVED**。獨立 Validator／DB 角色及全部 G3b～G6 技術驗收**不減少**，`NOT_RUN` 不可改 PASS；Mirage release 或其他外部強制規則不受影響，Trusted Send OFF、Draft／NO-GO 不變。 |

**跨文件最新決策優先權**：先前 D-54／D-55 等仍提及 `BD-05`／`BD-11` OPEN，屬歷史審查文字；2026-11-21 的 [Restore Anchor Option B](restore-anchor-option-b.md)、[BD-05 自動驗證解禁](bd-05-restore-quarantine-release.md)、[BD-11 鎖後 Deadline](bd-11-deadline-semantics.md) 已分別 OWNER APPROVED／ADOPTED／DECIDED，應按最新決策執行。全部仍未完成原生部署及安全驗收；BD-05 不允許以人工／雙人簽核繞過失敗證據。

**版本證據**。契約版本、原生程式 SHA、Owner 採納及 native conformance 分別記錄。當前 SHA 由 Git／PR Metadata 取得，新增安全驗收維持原有 NOT_RUN 狀態，歷史證據不能直接升格為新版本通過。

### v0.2 新增／修訂測試 ID 交接清單（37 項，其中 1 項為群組索引；全部 NOT_RUN）

`WORLD-IDENTITY-01`、`WORLD-OPERATION-01`、`WORLD-OPERATION-02`、`WORLD-OPERATION-03`、`WORLD-POLICY-01`、`WORLD-POLICY-02`、`WORLD-PAYLOAD-01`、`WORLD-PAYLOAD-02`、`WORLD-PAYLOAD-03`、`WORLD-SNAPSHOT-01`、`WORLD-SNAPSHOT-ACL-01`、`WORLD-LIFECYCLE-01`、`WORLD-LIFECYCLE-02`、`WORLD-LIFECYCLE-03`、`WORLD-PURGE-01`、`WORLD-TIME-01`、`WORLD-LOCK-01`、`WORLD-COMPAT-01`、`WORLD-RECOVERY-03`、`WORLD-RECOVERY-04`、`WORLD-RESTORE-OP-01`、`WORLD-AUDIT-02`。

本輪追加 `WORLD-PROTOCOL-01`、`WORLD-PROTOCOL-02`、`WORLD-RESTORE-TOMBSTONE-01`，以及 `WORLD-RECOVERY-03A`、`WORLD-RECOVERY-03B`、`WORLD-RECOVERY-03C`、`WORLD-RECOVERY-03D`、`WORLD-RECOVERY-03E`、`WORLD-RECOVERY-03F`。**父 ID `WORLD-RECOVERY-03` 不可作獨立 JUnit PASS**；子案必須各自滿足 Verification Plan 的 Given／Action／Expected。

本輪再加入 `WORLD-RESTORE-FENCE-01`、`WORLD-PURGE-BOUNDARY-01`、`WORLD-PROTOCOL-MATRIX-01`；所有案例仍 NOT_RUN，不能用文件檢查器通過宣稱安全驗收。

本次再補 `WORLD-SNAPSHOT-SEPARATION-01`（獨立物件／共用 Blob Pin）、`WORLD-RESTORE-PUBLISH-01`（兩方向發布失敗）、`WORLD-PURGE-RETRY-01`（Fence 後 GC 故障）。完整 Given／Action／Expected 留在 Verification Plan；均尚未執行。

完整預期與 Scenario 以 [Verification Plan](verification-plan.md) 各唯一 ID 為準；ADR／Decision Log／Plan 的 ID 與狀態必須同步，這裡沒有 PASS 證據。`WORLD_COMMITTED_ADMISSION_UNAVAILABLE` 仍是 reconciliation classification，非 State enum。

## 曾討論但明確拒絕的捷徑

| 提議／誤解 | 處理 | 理由 |
| --- | --- | --- |
| 將 World DB 直接改成原始 Assessment Ledger 的 EXECUTE-only | **拒絕照搬** | World Native 仍需正當 SELECT／INSERT／UPDATE／部分 DELETE，須分操作改造 |
| 獨立 Python Module 或多一張 Receipt 表就算新的信任根 | **拒絕** | 沒有隔離 Role、秘密、Verifier 的真實輸入驗證，Runtime 仍可偽造 |
| Runtime 的 `domain_validation=passed` 或 Replay Tombstone 即代表 Token 已可信驗章 | **拒絕** | 稽核／防重放不是來源認證 |
| IngressTx 一開始就強制 Receipt 包含未生成的 Candidate Hash | **修正為兩階段綁定** | Ingress 綁 request＋intent；Grant 以單交易綁真正 Candidate hash |
| 查無 Operation Receipt 五分鐘就改 `EXPIRED` 並直接重試 | **拒絕** | 時間經過不證明未知 COMMIT 已 rollback，可能造成重複副作用 |
| 暫時允許部分 Runtime 自宣告授權，靠限速或人工標記 | **拒絕** | 對 R1 的授權根仍不可信，不能當正式發送最小通路 |
| 還原後直接上傳新的公鑰就解除隔離 | **拒絕自動解禁** | 舊 Token／舊金鑰撤銷與全域身分切換尚未獲證 |
| 一律在 SECURITY DEFINER 中移除 `pg_temp` 就一定安全 | **校正** | 官方安全例示將 `pg_temp` 放末尾；搭配 schema-qualified 名稱、可信 schema、撤銷 PUBLIC CREATE/EXECUTE 與負面測試 |
| COPY FROM PROGRAM 只靠一般 EXECUTE 就能執行 | **校正** | 另須 superuser 或 `pg_execute_server_program` 類權限，須審核真實有效權限 |
| PostgreSQL 不寫 volatility 就預設 IMMUTABLE／parallel safe | **校正** | DML 函式宜顯式標示 `VOLATILE PARALLEL UNSAFE` 方便審計，但不應錯稱預設為 IMMUTABLE |
| Runtime 原地改 Admission Hash 後重新授權同 Receipt | **拒絕** | 破壞 Envelope 不可變與一次性 Binding；需新 Candidate＋合法新授權流程 |
| 讓 Runtime 直接提供 `request_fingerprint` 或「原始快照」便宣稱已證明實際 HTTP 入口 | **拒絕過度承諾** | 只能證明 JWS 與提交資料相符；外部來源需另有可信入口證據 |
| 在外層增加 `BEGIN`，但 Replay／Key Guard Store 仍自行開連線 | **拒絕** | 不同 Physical Connection 無法因外層 Python 區塊產生同一 PostgreSQL 原子交易 |
| 以 Python `VerifiedContext` 類別作為資料庫身分認證 | **拒絕** | Class／JSON 不是 DB 可信來源證明，需受保護 DB 身分與寫入介面 |
| 強制 Candidate 新增 staging table 作為唯一設計 | **不預先指定** | 可沿用既有儲存並加權限、Validator／Promotion 或受限函式；以安全驗收證據裁決 |
| Validation 已 PASS 就不再核對 bytes／Policy Revision，直接 Promotion | **拒絕** | 內容或政策可能在兩階段之間改變，需不可變證據及重新驗證 |
| `NOINHERIT` 等於沒有 `SET ROLE` 權限 | **校正** | `SET ROLE` 由 Role Membership 的 SET 選項與間接鏈決定，需實際 ACL／登入測試 |
| 規定所有 Candidate Validation 必須持鎖做完 | **拒絕一刀切** | 昂貴驗證若長期占鎖會影響安全撤銷可用性；應先驗不可變快照、在短 PromotionTx 查核證據與當前政策 |
| 只要有 FK RESTRICT，就能永久保留全部 Candidate 原始 bytes 而無需 GC | **拒絕** | FK 是參照完整性；需對 Raw Payload／稽核 Metadata 設分層保留，Active／UNRESOLVED 不能誤刪 |
| 任何失敗一律必須簽發新 JWS 再試 | **拒絕** | 明確 rollback 可在原 ID/digest 與政策下受限重試；已消費不復活、未知 Commit 不得以新 Token 規避對帳 |
| `SEND_STARTED` 表示 Client 收到，或網路失聯等於沒送 | **拒絕** | DB 起送、ASGI 嘗試、Socket 寫入與客戶端接收是不同事件 |

## 仍須正式裁決（不得隱藏成既定事實）

| 決策 | 提議／待評估選項 | 目前 |
| --- | --- | --- |
| Verifier 位置與信任根 | 獨立服務＋獨立 DB Role；若不同 DB 必須重做 Ingress 原子協定 | **OPEN** |
| Authorize／StartSend／Epoch／Revocation 的總鎖序 | 先盤點全部路徑並產生無循環圖，再定量測試 | **OPEN** |
| StartSend 期限政策 | `G=0` 嚴格 Token 未過期；或短、不可延長的已核准 Grace Window | **OPEN** |
| Candidate GC 與 Grant 互斥方式 | 完整 Scope FK＋Row Lock／受限 GC；須含保留分層、全域鎖 DAG 與並行測試 | **OPEN** |
| World Commit 成功但 Admission 無法取得 | API 可查回／at-most-once／可補償與對外回應 | **OPEN** |
| Replay／Receipt 保留、還原隔離與釋放條件 | 單機 Quarantine 與外部安全錨點／保守到期窗口 | **OPEN** |
| R4/R5 額外安全需求 | 分開威脅模型或正式殘餘風險接受 | **OPEN** |
| Request Provenance 語意 A 風險接受 | 若未來要求實際入口來源驗證，採語意 B 並另行威脅分析 | **OPEN（提案採 A）** |
| Candidate Validator 身分與 Promotion 具體交易 | 受控交易外 Validation／短交易 Promotion，DB 不可變版本、可信政策撤銷與版本相容規則 | **OPEN** |
| 正式發送禁用控制面 | 查明開關與 Credential／Restore／Runtime 權限，驗證 fail-closed | **OPEN** |

## 紀錄原則

每個後續決策需有：ID、日期、決策人、選項、來源 commit／PR、威脅能力、測試結果、殘餘風險與可回滾方式。**實作完成**、**測試通過**、**Owner 核准**與**安全弱點關閉**是四個獨立狀態。

**持續紀錄工作約定（本輪已獲使用者同意）**：每次與此 ADR 有關的討論形成新結論時，將可核對內容整合到**同一文件分支**，以新的 Git Commit／版本歷史保留修改理由；不重複建構平行文件，不以「合併討論紀錄」解讀為可合併 `main`、修改 staging 或啟用正式發送。尚未核准的選項必須標為 Proposed／OPEN，測試未執行仍是 NOT_RUN；未來新對話需由取得 Repo 權限的執行者實際提交，**不宣稱已有無人值守的跨會話自動化**。

目前無正式 Owner 簽核紀錄，請勿把本檔的「已固定提案方向」解讀成已核准進入 production。
