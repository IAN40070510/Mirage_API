# MIR-SEC-WORLD-001 — 安全修補執行與驗收順序

**狀態：IMPLEMENTATION IN PROGRESS／World DB 權限修補尚未完成／正式發送不得開啟**。此文件供獨立修補分支追蹤，不是 PostgreSQL ACL、原生符合性或正式部署的 PASS 證據。

## 固定起點及證據

- Mirage 原生基準：`88dc2008fd35a2d3873949a769653dc9f18e8980`；ADR 文件前置：`ff2afb6a2bde45e79093d54004f036a8df0ce3a6`。
- `trusted_http.create_app()` 對 Trusted Session Provider、Candidate、Admission、Registry、Audit／World 共用 `postgres_dsn`。
- `TrustedSessionVerifier.verify()` 在簽章驗證後透過 `PostgresTrustedKeyRevocations.guard()` 與 `PostgresReplayStore.consume()` 操作**兩條獨立交易連線**；現況不具備 Replay＋Receipt 同交易。
- `PostgresAdmissionControl.grant/claim/authorize_send/start_send/emergency_revoke` 直接對 `response_admissions`、`generation_controls` DML；`PostgresReplayStore.gc()` 直接 `DELETE replay_entries`。
- Mirage 固定上游版 `start_send()` 經 `_lock_admission(..., for_send=True)` 再讀 Generation/Profile Emergency；與 MSDSS Freeze v1 有局部差異。**2026-11-21 使用者已正式選定 Mirage 採納 Freeze v1**；獨立實作分支開始修正該差異，完整原生協定與安全驗收仍未通過。
- 本工作使用獨立分支，不得合併 `main` 或變更 staging／production；文件紀錄、程式修補和真實資料庫驗收必須各自標示。

## 實作順序（每一步前後保留負面與正常路徑證據）

| Gate | 實作目標 | 最低安全／功能驗收 | 狀態 |
| --- | --- | --- | --- |
| G0 | 固定受影響 SHA、非特權 Runtime 角色、隔離 PG 17 測試 DSN；重現三個已知直接 SQL 越權 | 原缺口重現歸類為預期風險，不能寫成修復 PASS；正常世界操作基準不退化 | NOT_RUN |
| G1 | Verifier／Authorizer 與 Runtime 分離 OS/容器身分、Secret、DB Role、DSN；明確關閉角色繼承及 `SET ROLE` 路徑 | 從 Runtime 的真實 SCRAM 連線無法讀／取得特權 DSN 或執行受保護函式 | NOT_RUN |
| G2 | 受保護 IngressTx：可信 Verifier 驗章、Key Revocation、Replay Tombstone、Ingress Receipt **同一 PostgreSQL DB／Connection／Tx** | 偽造來源／重放／Rollback／COMMIT ACK unknown；已消費 JTI 不得跨 Scope/Receipt 重綁 | NOT_RUN |
| G3 | 受保護 Candidate Promotion、Grant Binding、Admission／Generation／Session／Replay GC 轉移；撤銷 Runtime 直接受保護 DML | 原三個 SQL 越權被 DB 拒絕，正向 Grant／Claim／Authorize／Cutover／Revocation／Replay GC 保持正常；完整 Lock DAG | NOT_RUN |
| G4 | Snapshot 真實物件身分／immutable version、physical Pin／Key lifetime、兩種 Purge Fence、StartSend／Purge 競態 | 真實 bytes/Hash、Owner/Deadline/Single-use、異步 Object GC／Pin／Shared Blob 及未知 send 結果；不得偷偷二次授權 | NOT_RUN |
| G5 | Restore Quarantine、外部 Anchor 連續涵蓋、雙方向發布未知及 Operator Release Certificate | 舊備份及事件缺口無法復活 Tombstone／JTI／Snapshot；未知涵蓋不得解禁 | NOT_RUN |
| G6 | 混合版本／Rollback／CI／正式簽核 | 非特權 PG Integration、失敗注入、既有 Mirage 全套回歸、Owner／DBA／Security／Release Approver 簽核 | NOT_RUN |

**G1 子切面（待獨立驗證）**：獨立分支新增 `deception.security.world_acl`，以正式 Runtime 實體 DSN 唯讀檢查 Session Login、有效權限、特權 Role Membership 與關鍵表。現有 `trusted_http.from_environment()` 在服務／權限重構未完成前有不可由環境開關跳過的 **Release Fuse**：即使 ACL 檢查通過仍拒絕正式 Trusted Send 啟動。`create_app()` 仍供隔離 Python 正向測試使用，**不能以此推論正式入口可啟用**。新增 `WORLD-ACL-06` 子案例在一次性 PostgreSQL CI service 建立真實 SCRAM LOGIN，驗證無法改寫 Admission、Session epoch、Replay 或 `SET ROLE`；一般開發環境未設 `MIRAGE_WORLD_ROLE_TEST_ISOLATED=true` 不准修改 PostgreSQL cluster roles。這只驗證**隔離 ACL fixture**，並非正式 Oracle 部署角色、Secret、來源或 IPC 的證據，G1 保持 `NOT_RUN`。

## 不得由工程師自行猜測的決策

1. **Mirage Owner adoption／Protocol Freeze v1：ACCEPTED（2026-11-21 使用者明確決策）。** `SEND_AUTHORIZED` 提交後不以 Policy／Emergency 做第二次授權；`StartSend` 保留 owner、deadline、single-use 與真實 Snapshot 執行前置條件。這只解除協定選擇阻塞，**不代表** DB 角色分離、Snapshot 完整性、未知 COMMIT 或原生端到端符合性已經驗證。
2. **受信任 Verifier／Authorizer：2026-11-21 使用者選定同一 Oracle 主機、不同容器及 OS 身分（D-69）。** 每服務獨立 PostgreSQL Login／SCRAM Secret／DSN 與網路 ACL，Runtime 無法掛載或讀取高權限 Secrets；禁止共池與動態 `SET ROLE`。此選擇涵蓋 R1，但不宣稱抵抗主機 root／Docker daemon（R5）；尚須真實檢查部署 Mount、`pg_hba.conf`、Membership 與有效 ACL。
3. **BD-05 Restore Anchor 發布協定／Retention／Quarantine release、BD-11 Deadline COMMIT 語意：OPEN。** 未核准前正式發送維持禁用。

## 驗收證據規則

### 2026-11-21 第一批 Freeze v1 相容修補（僅原生回歸）

- 修補 Commit：`0f1493f0ef6e2765b3ca4b56efeae4129695e3db`（獨立分支，未合併 main）。
- [Python tests GitHub Actions run 44847829807](https://github.com/IAN40070510/Mirage_API/actions/runs/44847829807)：PostgreSQL `17.6-alpine` service、Python 3.12，**1,260 passed／21 skipped／2 warnings**，結論 `success`；完整 JUnit artifact `14683717240`，摘要 `sha256:126b71ea8f917f5792584fad5fbae4eb080f2a0525759f256f14ac5af0a9a5d1`。
- [Container demonstration verification run 44847829826](https://github.com/IAN40070510/Mirage_API/actions/runs/44847829826)：`success`。
- 本地 `python tools/check_documentation.py`、Python `compileall`、`git diff --check`：通過。
- **證明範圍**：本次記憶體／PostgreSQL `StartSend` 的 Freeze v1 行為調整與既有完整測試回歸；21 個 skip 不能當成通過。這些結果**不等於**新受保護 DB Role 實體連線、IngressTx Receipt 原子性、R1 負面 SQL、Snapshot／Restore 或完整協定逐條符合性已完成。上述 G0–G6 仍依既有表列狀態。

- 只以隔離專用 PostgreSQL 測試 DB 執行會修改角色或資料表的整合測試，不能指向共享 staging 或 production。
- 結果變更須循 `NOT_RUN → RUNNING → PASS/FAIL/BLOCKED`，留下固定 Mirage SHA、Schema/Migration hash、PG 版本、實體 DB Login、資料集與 Fault Injection、UTC 時間及脫敏日誌。
- `python tools/check_documentation.py` 成功只代表文件品質，不代表 G0–G6 或 `WORLD-*` 安全驗收通過。
- 在所有 Gate 未通過且簽核未完成前：`Architecture=Proposed`、`MIR-SEC-WORLD-001=OPEN`、`MSDSS P2=NO-GO`、`production trusted-send=DISABLED`。
