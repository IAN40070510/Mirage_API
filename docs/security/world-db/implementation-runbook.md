# MIR-SEC-WORLD-001 — 安全修補執行與驗收順序

> 本文件以 Mirage 原生授權契約為維護範圍。歷史跨專案整合證據已移交保存，原生安全要求與驗收狀態維持原紀錄。

**狀態：IMPLEMENTATION IN PROGRESS／World DB 權限修補尚未完成／正式發送不得開啟**。此文件供獨立修補分支追蹤，不是 PostgreSQL ACL、原生符合性或正式部署的 PASS 證據。

> **D-74 2026-11-25 更新：**Mirage 必須支援單主機、未安裝外部 Fence 的完整正常功能；G5 分成標準單機和選配外部強化兩個不同驗收集。歷史 G5 的域外 Head／BD-05 要求不再是一般安裝依賴，仍是 external_fence 的不可免除條件；詳見 [雙 Profile 規範](single-node-restore-profiles.md)。程式尚未接線，兩組均不得簽 PASS，Trusted Send OFF。

## 固定起點及證據

- Mirage 原生基準：`88dc2008fd35a2d3873949a769653dc9f18e8980`；ADR 文件前置：`ff2afb6a2bde45e79093d54004f036a8df0ce3a6`。
- `trusted_http.create_app()` 對 Trusted Session Provider、Candidate、Admission、Registry、Audit／World 共用 `postgres_dsn`。
- `TrustedSessionVerifier.verify()` 在簽章驗證後透過 `PostgresTrustedKeyRevocations.guard()` 與 `PostgresReplayStore.consume()` 操作**兩條獨立交易連線**；現況不具備 Replay＋Receipt 同交易。
- `PostgresAdmissionControl.grant/claim/authorize_send/start_send/emergency_revoke` 直接對 `response_admissions`、`generation_controls` DML；`PostgresReplayStore.gc()` 直接 `DELETE replay_entries`。
- Mirage 固定上游版 `start_send()` 經 `_lock_admission(..., for_send=True)` 再讀 Generation/Profile Emergency；與 Mirage Protocol Freeze v1 有局部差異。**2026-11-21 使用者已正式選定 Mirage 採納 Freeze v1**；獨立實作分支開始修正該差異，完整原生協定與安全驗收仍未通過。
- 本工作使用獨立分支，不得合併 `main` 或變更 staging／production；文件紀錄、程式修補和真實資料庫驗收必須各自標示。

## 實作順序（每一步前後保留負面與正常路徑證據）

| Gate | 實作目標 | 最低安全／功能驗收 | 狀態 |
| --- | --- | --- | --- |
| G0 | 固定受影響 SHA、非特權 Runtime 角色、隔離 PG 17 測試 DSN；重現三個已知直接 SQL 越權 | 原缺口重現歸類為預期風險，不能寫成修復 PASS；正常世界操作基準不退化 | NOT_RUN |
| G1 | Verifier／Authorizer 與 Runtime 分離 OS/容器身分、Secret、DB Role、DSN；明確關閉角色繼承及 `SET ROLE` 路徑 | 從 Runtime 的真實 SCRAM 連線無法讀／取得特權 DSN 或執行受保護函式 | NOT_RUN |
| G2 | 受保護 IngressTx：可信 Verifier 驗章、Key Revocation、Replay Tombstone、Ingress Receipt **同一 PostgreSQL DB／Connection／Tx** | 偽造來源／重放／Rollback／COMMIT ACK unknown；已消費 JTI 不得跨 Scope/Receipt 重綁 | NOT_RUN |
| G3 | 受保護 Candidate Promotion、Grant Binding、Admission／Generation／Session／Replay GC 轉移；撤銷 Runtime 直接受保護 DML | 原三個 SQL 越權被 DB 拒絕，正向 Grant／Claim／Authorize／Cutover／Revocation／Replay GC 保持正常；完整 Lock DAG | NOT_RUN |
| G4 | Snapshot 真實物件身分／immutable version、physical Pin／Key lifetime、兩種 Purge Fence、StartSend／Purge 競態 | 真實 bytes/Hash、Owner/Deadline/Single-use、異步 Object GC／Pin／Shared Blob 及未知 send 結果；不得偷偷二次授權 | NOT_RUN |
| G5 standard_single_node | 無外部 Fence 仍有完整 World/Grant/StartSend/HTTP、已知 Restore／Unknown Fail-Closed；不宣稱整機靜默回滾偵測 | 無外部 DSN/Key 的真單機 2xx/4xx、GC/Send/Purge/Crash、Profile 防降級與權限證據 | NOT_RUN |
| G5 external_fence（選配） | Restore Quarantine、域外 Anchor 連續涵蓋、雙向未知發布、**BD-05 證據全 PASS 自動解禁** | 真跨復原域舊備份、Head 單調、防 Tombstone 復活；未知 ACK、並行 Send/Purge、外部服務故障拒絕降級 | NOT_RUN |
| G6 | 混合版本／Rollback／CI／正式簽核 | 非特權 PG Integration、失敗注入、既有 Mirage 全套回歸；按 [Solo Developer Security Acceptance v1](solo-developer-security-acceptance-v1.md) 保存證據並由 Owner 最終核准，外部人工審查非強制 | NOT_RUN |

**G1 子切面（待獨立驗證）**：獨立分支新增 `deception.security.world_acl`，以正式 Runtime 實體 DSN 唯讀檢查 Session Login、有效權限、特權 Role Membership 與關鍵表。現有 `trusted_http.from_environment()` 在服務／權限重構未完成前有不可由環境開關跳過的 **Release Fuse**：即使 ACL 檢查通過仍拒絕正式 Trusted Send 啟動。`create_app()` 仍供隔離 Python 正向測試使用，**不能以此推論正式入口可啟用**。新增 `WORLD-ACL-06` 子案例在一次性 PostgreSQL CI service 建立真實 SCRAM LOGIN，驗證無法改寫 Admission、Session epoch、Replay 或 `SET ROLE`；一般開發環境未設 `MIRAGE_WORLD_ROLE_TEST_ISOLATED=true` 不准修改 PostgreSQL cluster roles。這只驗證**隔離 ACL fixture**，並非正式 Oracle 部署角色、Secret、來源或 IPC 的證據，G1 保持 `NOT_RUN`。

**G2 子切面（本輪待 CI 驗證）**：`TrustedSessionVerifier` 配合 `PostgresTrustedKeyRevocations.consume_guarded_replay` 與 `PostgresReplayStore._consume_on_cursor`，使**現有 Key Revocation Guard＋Replay JTI INSERT** 在同一 PostgreSQL connection／READ COMMITTED transaction 執行。不同 DSN 或非 PostgreSQL Replay Store 拒絕；新增真實 PostgreSQL 的單連線、INSERT 後 rollback、COMMIT ACK loss 負面案例。這**尚未涵蓋 Ingress Receipt、由可信 Verifier 獨立寫入的證據、Operation ID 對帳或正式 Role ACL**。G2 仍為 `NOT_RUN`；正式入口 Release Fuse 不變。

**2026-11-21 G2 Ingress Receipt 原子性子驗收（獨立 Candidate Clean Cutover 分支）**：新增 `migrations/017_trusted_ingress_receipts.sql`、`PostgresIngressReceiptWriter` 及 `TrustedSessionVerifier.verify_with_receipt()`；在同一 Key Guard／Replay 交易中寫入 Receipt，任何 Receipt Writer 失敗必須連同 Replay 回滾。這不是對舊 `verify()` 的可信度升級；舊路徑僅保留測試相容，正式發送 Release Fuse 不變。

- 真實 PostgreSQL `17.6-alpine`：專用 Oracle `mir-sec-world001-lab`、一次性新 Schema、無 published ports；單次探針來源為獨立工作區，不改原三個 Compose 或七個 staging 容器。
- 正向／負向交易：首次 Job `job_01M7Y53Q2Z00JEZQGMRNGM0JFM` 因測試容器不可讀 `0600` 密碼檔而失敗；僅限一次性受控測試容器加入原 Lab Bootstrap 同樣的 `CAP_DAC_READ_SEARCH` 後，**成功 Job `job_01M7Y557CH005E073KWZAZKYZV`** 實際輸出 `LAB_RECEIPT_TX_PROBE_OK normal=atomic replay=denied explicit_rollback=atomic`。成功測試於一次性新 schema 執行，測後只刪除此 schema；不觸及其他資料庫或容器。
- 實體 Role／DB ACL 子測試：**Verifier SCRAM Job `job_01M7Y55P9K00HH03PJ2PY6PPKJ`** 輸出 `LAB_RECEIPT_SCHEMA_PROBE_OK orphan=23503 role_denial=42501 pair_rollback=atomic`；**Runtime SCRAM Job `job_01M7Y566SY00CRARMGPRDJX3D6`** 輸出 `LAB_RECEIPT_SCHEMA_PROBE_OK role=runtime direct_dml=42501`。它們驗證專用 Lab ACL 與 FK，不是正式產品角色已部署的證據。
- **追加資料庫時間負面驗收**：對 Key Lock 後重新讀取 `clock_timestamp()` 的版本，隔離 PG 17.6 Job `job_01M7Y5BR5R00F2165DB6PQEG3R` 輸出 `LAB_RECEIPT_TX_PROBE_OK normal=atomic replay=denied explicit_rollback=atomic db_time=denied`；故意將 Python 驗證時間倒退 120 秒、送出過期簽章，資料庫拒絕且無消費 JTI。測試來源封存 SHA-256 `a4b690403ce02c470a338db670b7cf7b6b95c8da1d6af89b58799f10323a332a`，測完只移除獨立探針 Schema。
- **新增真實受限 Verifier 正向／負向整合**：以 `mir_sec_verifier` 的獨立 SCRAM Secret 在專用拋棄式 Schema 僅授予 Replay／Receipt 所需 `SELECT/INSERT`；Job `job_01M7Y5F5QP00RTD093B4WMH7N4` 回報 `LAB_VERIFIER_RECEIPT_ROLE_OK scram=verifier receipt=inserted replay=inserted protected_dml=42501 set_role=42501`。同一角色可成功驗章後消費並存 Receipt，不能 `UPDATE response_admissions`、`DELETE ingress_receipts`、`UPDATE generation_controls` 或 `SET ROLE mir_sec_authorizer`。來源封存 SHA-256 `efb24a9503c2282249f6cc322bc5e9598fe8f1e0253c6c54ac69a64faa6b679c`。
- **Replay GC 保留引用與可用性回歸**：加入 `NOT EXISTS` 保護，使 GC 對已過期但仍被 Receipt FK 引用的 JTI 不刪除，同時可刪其他過期 Tombstone；隔離 PG Job `job_01M7Y5P9S200Z7ATGMC68PTG8B` 輸出 `LAB_RECEIPT_TX_PROBE_OK normal=atomic replay=denied explicit_rollback=atomic db_time=denied gc=protected_receipt_retained`。測試封存 SHA-256 `f3544addaad4c6395e4f29930da4f16fb098a05ee40cf4aff403b41b91057e3e`。此測試只說明暫時保守留存，不等於正式 GC/Restore retention 已核准。
- **範圍限制**：交易探針使用隔離 Lab schema owner 進行正向功能測試，實體 Verifier/Runtime ACL 負面測試另以 SCRAM 角色分別執行。尚未證明正式 Verifier 程序不可由 Runtime 取得憑證、跨服務 IPC、Receipt 與 Grant 的一次性 Binding、Unknown COMMIT 對帳、Snapshot／Restore 或傳輸；G2 整體 `NOT_RUN`，G3–G6 仍 `NOT_RUN`。

**G3 Candidate Clean Cutover（D-70）**：使用者已選定淘汰舊的可信 `candidate_records → grant()` 路徑，保留三類業務 Candidate 生成器。切換時必須先提供可信 Submission／Validation／Promotion、一次性 Receipt→Candidate→Admission Binding 及獨立 Authorized Snapshot，再撤銷舊 Runtime DML／Grant 能力；不存在「新流程故障改用舊 `put()`／`grant()`」的回退選項。驗收必須同時證明 **(a)** 舊路徑與 Runtime 直接 SQL 不能建立有效 `SEND_AUTHORIZED`，**(b)** 新角色及正常商品／Cart／Medusa 路徑不退化，**(c)** Candidate GC 不刪已授權 Snapshot，**(d)** unknown COMMIT 與 Restore fail-closed。G3/G4/G5 仍 **NOT_RUN**；在完整證據前只允許獨立分支與隔離 DB，正式發送仍禁用。

## 不得由工程師自行猜測的決策

1. **Mirage Owner adoption／Protocol Freeze v1：ACCEPTED（2026-11-21 使用者明確決策）。** `SEND_AUTHORIZED` 提交後不以 Policy／Emergency 做第二次授權；`StartSend` 保留 owner、deadline、single-use 與真實 Snapshot 執行前置條件。這只解除協定選擇阻塞，**不代表** DB 角色分離、Snapshot 完整性、未知 COMMIT 或原生端到端符合性已經驗證。
2. **受信任 Verifier／Authorizer：2026-11-21 使用者選定同一 Oracle 主機、不同容器及 OS 身分（D-69）。** 每服務獨立 PostgreSQL Login／SCRAM Secret／DSN 與網路 ACL，Runtime 無法掛載或讀取高權限 Secrets；禁止共池與動態 `SET ROLE`。此選擇涵蓋 R1，但不宣稱抵抗主機 root／Docker daemon（R5）；尚須真實檢查部署 Mount、`pg_hba.conf`、Membership 與有效 ACL。
3. **最新遠端裁決已取代早期 OPEN 記錄**：[獨立 Restore Anchor Option B](restore-anchor-option-b.md) **OWNER APPROVED**；[BD-05](bd-05-restore-quarantine-release.md) **ADOPTED**「證據自動驗證解禁、異常隔離、人工只負責修復」；[BD-11](bd-11-deadline-semantics.md) **DECIDED**「鎖後 `clock_timestamp()` 決定 eligibility、成功 COMMIT 是生效點」。三者皆**IMPLEMENTATION NOT COMPLETE／ACCEPTANCE NOT_RUN**；Head 發布/Retention/未知 ACK 的實際協定與正式角色仍須驗證，不得因決策已定就開啟正式發送。

## 驗收證據規則

### 2026-11-21 第一批 Freeze v1 相容修補（僅原生回歸）

- 修補 Commit：`0f1493f0ef6e2765b3ca4b56efeae4129695e3db`（獨立分支，未合併 main）。
- [Python tests GitHub Actions run 44847829807](https://github.com/IAN40070510/Mirage_API/actions/runs/44847829807)：PostgreSQL `17.6-alpine` service、Python 3.12，**1,260 passed／21 skipped／2 warnings**，結論 `success`；完整 JUnit artifact `14683717240`，摘要 `sha256:126b71ea8f917f5792584fad5fbae4eb080f2a0525759f256f14ac5af0a9a5d1`。
- [Container demonstration verification run 44847829826](https://github.com/IAN40070510/Mirage_API/actions/runs/44847829826)：`success`。
- 本地 `python tools/check_documentation.py`、Python `compileall`、`git diff --check`：通過。
- **證明範圍**：本次記憶體／PostgreSQL `StartSend` 的 Freeze v1 行為調整與既有完整測試回歸；21 個 skip 不能當成通過。這些結果**不等於**新受保護 DB Role 實體連線、IngressTx Receipt 原子性、R1 負面 SQL、Snapshot／Restore 或完整協定逐條符合性已完成。上述 G0–G6 仍依既有表列狀態。

### 2026-11-21 G1 預檢／隔離 SCRAM 角色子案例

- 原生測試 Commit：`04d29a2d99c57590793a726398ddc967ae4a2b8a`。
- [Python tests GitHub Actions run 44849685972](https://github.com/IAN40070510/Mirage_API/actions/runs/44849685972)：PostgreSQL `17.6-alpine` service，**1,265 passed／21 skipped／2 warnings**；JUnit artifact `14684238578`，摘要 `sha256:1da77caacb06672b8a89a3c589cebc380dabcbf201f673f1e708997828874ba7`。
- [Container verification run 44849686038](https://github.com/IAN40070510/Mirage_API/actions/runs/44849686038)：`success`。
- 測試包含 `test_world_acl_real_scram_login_denies_protected_dml`：在**專用拋棄式 CI PostgreSQL** 以實際非特權 SCRAM LOGIN 執行 Admission／Session／Replay 負面 SQL 與 `SET ROLE`；此子案例及共用高權限 DSN 啟動阻擋均已納入 pytest suite。
- **驗證限制**：角色是 CI 為測試建立的受限 fixture，不是正式 Oracle 容器中已部署的 Runtime Role；新的受保護授權函式、Ingress Receipt、Authorizer 及 Restore 仍未完成。**G1 完整驗收與 `MIR-SEC-WORLD-001` 仍 OPEN**，不能因 CI PASS 解除正式發送禁令。

### 2026-11-21 Oracle ARM64 實機隔離 PostgreSQL 角色子驗收

- **驗收切面**：新增專用 `mir-sec-world001-lab-net`（Docker internal bridge）、`mir-sec-world001-pgdata`、`mir-sec-world001-pg`、`mir-sec-world001-verifier-probe`、`mir-sec-world001-authorizer-probe`；Runtime 為單次測試容器。所有容器只加入 Lab 網路，沒有 host-published ports，與原有三組 Compose 網路無交集；原有七容器在驗收後仍維持 Running，原健康狀態未退化。未變更 staging、正式金鑰與 Trusted Send 開關。
- **資料庫與來源**：專用 `mir_sec_world_lab`、PostgreSQL `17.6`／arm64 image ID `sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94`；探針 image ID `sha256:05fa0bab9b32b2898d5e39cb3c647fcd454d30d7af157284816dd6654b976509`。原始 Probe／Provision 程式固定於 `317a913d2d8f6ae6503abfaa7653d9a561da60cc`，後續僅調整 Compose 的探針 Healthcheck，未改探針程式或 DB ACL。
- **初始化**：`job_01M7Y13MRV00H4W49TVSBJJCYF`，`LAB_PROVISION_OK migrations=16 roles=3 secrets=redacted`；三個獨立 SCRAM Login（`mir_sec_verifier`、`mir_sec_authorizer`、`mir_sec_http_runtime`）為 `NOSUPERUSER`／`NOINHERIT`／`NOBYPASSRLS`，沒有互相 Membership。Secret 本地產生且沒有進入輸出或 Git；`bootstrap` 僅作一次性權限建置。
- **正／負面結果**：`job_01M7Y1408600RPS895K5K0HZVQ`：Verifier 允許 Replay INSERT 再 rollback、越權 DML／`SET ROLE` 均 `42501`；`job_01M7Y13Z8R00MZY9GZ0AR69ZH5`：Authorizer 允許讀取 Admission、直寫及 `SET ROLE` 均 `42501`；`job_01M7Y14EVX009RTY1Y3QH6ECPC`：Runtime 無法修改 Admission、Session epoch、Replay 或 `SET ROLE`，均 `42501`。三者輸出 `LAB_ROLE_PROBE_OK`，Job Exit Code 成功。
- **已排除的環境誤報**：首次 Bootstrap 因 root 容器移除全部 capabilities 而無法讀取其他 UID `0600` 密碼檔，已只對一次性 Bootstrap 加 `CAP_DAC_READ_SEARCH` 後成功；Probe 映像預設 HTTP healthcheck 因沒有 HTTP 服務而誤報 unhealthy，後續 Compose 明確停用探針的該檢查，PG `pg_isready` 不受影響。
- **證據基準**：首次成功部署 Compose hash `70364025d12332d6bed9a27fe1e127005fdf8c76435172c6e4b978ac1a49931f`（後續 Healthcheck 調整會產生新 hash）；核對紀錄 `job_01M7Y15K62001XG803ZB6956R8`、`job_01M7Y15VV500HP0K6VJQMG6JSH`、`job_01M7Y15HH900CRPQG617NR3QNK`、`job_01M7Y15J2K00809JZ93DQ8W32K`。
- **安全驗收判定：Lab ACL 子切面 PASS；G1 完整 Gate NOT_RUN；G2–G6 NOT_RUN**。目前 `mir_sec_*` 是專用測試角色而非正式 `mirage_*` 身分；尚無正式 Verifier／Authorizer 執行邏輯、Receipt／Binding／Grant 受限函式、來源鎖定 `pg_hba.conf`、Restore Fence 或端到端正常世界交易。本 Lab 不構成 production 安全證明。
- **額外原生交易子測試（2026-11-21）**：`deploy/security-lab/atomic_ingress_probe.py` 固定來源 Commit `e55c668a18e05a7764da792d04d683c70c53046b`，透過 `mir-sec-world001-verifier-probe` 的真實 SCRAM 登入執行 `PostgresTrustedKeyRevocations.consume_guarded_replay`；Gateway `job_01M7Y1H93000AFB7W25KG9VCXQ` 為 `succeeded`，輸出 `LAB_INGRESS_TX_PROBE_OK guarded_replay=accepted replay=denied explicit_rollback=atomic`。注入在同一交易、Key Lock 與 Replay INSERT 之後／COMMIT 之前；後續新連線確認 Rollback JTI 不存在。**這不是 Ingress Receipt 的原子性或 Unknown COMMIT 對帳測試；G2 整體仍 NOT_RUN**。
- **實機最終盤點**：完成 Probe HTTP healthcheck 修正後 Compose SHA-256 `8c70c5ac7469f6a1325a298a18ba1406d1d15d3132ded41c885b86767052c592`、Docker 內部網路 `Internal=true` 且只包含三個 Lab 常駐容器；`job_01M7Y1BVCH00T450D2Q3GTZP3T` 列出 Lab PostgreSQL `healthy`、Verifier／Authorizer `running`，原有七容器原狀。已精確移除三個停止中的 Lab 診斷／一次性探針容器（Gateway `job_01M7Y1BBSS00THNS1MAP70Z0XV`、`job_01M7Y1BCZC00SB2NDDRP4DEREZ`、`job_01M7Y1BCDC00S90TXY93GPMNGS`），無刪除 Volume、證據檔或既有容器。
- **CI 前一固定版本**：提交 `f7f10e5e91c635fa34d00f5afedb748bf15a80a2` 的 [Python／PG17.6 run 44859596779](https://github.com/IAN40070510/Mirage_API/actions/runs/44859596779) 成功，**1,267 passed／21 skipped／2 warnings**；[Container run 44859596809](https://github.com/IAN40070510/Mirage_API/actions/runs/44859596809) 成功。新增 Ingress 原生實機探針提交 `e55c668a18e05a7764da792d04d683c70c53046b` 的 CI 結果需獨立核對，不沿用舊版 PASS。

- 只以隔離專用 PostgreSQL 測試 DB 執行會修改角色或資料表的整合測試，不能指向共享 staging 或 production。
- 結果變更須循 `NOT_RUN → RUNNING → PASS/FAIL/BLOCKED`，留下固定 Mirage SHA、Schema/Migration hash、PG 版本、實體 DB Login、資料集與 Fault Injection、UTC 時間及脫敏日誌。
- `python tools/check_documentation.py` 成功只代表文件品質，不代表 G0–G6 或 `WORLD-*` 安全驗收通過。
- 在所有 Gate 未通過且簽核未完成前：`Architecture=Proposed`、`MIR-SEC-WORLD-001=OPEN`、`Mirage release=NO-GO`、`production trusted-send=DISABLED`。
