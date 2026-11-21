# MIR-SEC-WORLD-001 — G3 Grant Binding 實作紀錄

**修補分支**：`fix/mir-sec-world-001-protected-grant`（與 `main` 隔離）。

**2026-11-22 狀態**：`IMPLEMENTATION IN PROGRESS / NOT ACCEPTED`。這份文件保留本輪實作選擇及阻礙，**不是 G3 PASS**。`MIR-SEC-WORLD-001=OPEN`、`MSDSS P2=NO-GO`、正式 Trusted Send／Production DECEIVE **OFF**；原有 `from_environment()` 的 Release Fuse 不移除。

## 本輪已寫入獨立分支的變更（部分獨立 PostgreSQL 驗證已通過）

| 實作檔案 | 安全作用與限制 |
| --- | --- |
| `migrations/018_protected_grant_bindings.sql` | 新增完整 Scope＋不可變版本的 `protected_candidate_promotions`、一對一 Receipt/Admission 的 `protected_grant_bindings` 與不可變觸發器。新增固定 Schema `search_path` 的受限 `SECURITY DEFINER` Row Lock Helper；未授予 Runtime 執行權。Migration 不建立 LOGIN 或開啟發送。 |
| `src/deception/world/protected_grant.py` | 分離 Candidate Validator 與 Authorizer 的預期 PostgreSQL Login／DSN；Promotion 複製並重新驗證 v1 Envelope 三種 SHA-256；Grant 在單一交易鎖定 Session／Receipt／Candidate／Generation／Key／Profile，檢查 Registry／DB 期限並寫入 Binding＋Admission；Claim／Authorize 只接受已有 Binding，使用 DB 時間；Operation ID＋input digest 只讀查回。未核准 token expiry grace 前，保守要求 `transmission_deadline <= token_expires_at`。 |
| `src/deception/world/postgres_candidate.py` | Candidate GC 不使用呼叫者提供的 `protected_refs` 當唯一判據；已 Promotion 的來源候選不得被刪除。此為暫時偏向安全的保留策略，日後需分離可清理 Bytes 與永久 Metadata。 |
| `src/deception/security/world_acl.py` | 增加 Runtime 對兩張新表及受保護 Read Admission 來源的有效 DML 拒絕查核；正式 Runtime 的原生 ReadAdmission 寫入需改走可信 Executor，不能共用舊 DB Role。 |
| `tests/test_protected_grant.py` | 擬定真實 PostgreSQL 正向 Grant、Receipt 重綁／交易回滾、偽造 Fingerprint、未 Promotion、錯誤 Login、Candidate GC 與不可變資料負面測試；使用一次性真 SCRAM Login 及欄位級最低權限驗證。 |
| `.github/workflows/world-security-contract.yml` | 獨立、無正式憑證的 PostgreSQL 17.6 快速驗收；只針對 Protected Grant / SCRAM 角色，保留 JUnit，不取代全套 CI。 |

## 本輪發現並保持阻擋的關鍵事項

1. **ACL 與資料庫 Row Lock**：PostgreSQL 17 `SELECT ... FOR SHARE` 也需要受查表至少一欄 `UPDATE` 權限。不可直接向 Authorizer／Validator 授予 Key／Receipt／Session 等整表 `UPDATE`。目前新增只接受預先定義 `kind`／完整 Scope 的 `SECURITY DEFINER protected_lock_reference`，函式固定 Migration 對應的可信 Schema `search_path`，並撤銷 `PUBLIC EXECUTE`；一次性真 SCRAM 最小權限 Role 測試在隔離 CI 已通過，但正式部署的函式 owner NOLOGIN／無 Runtime 繼承／可信 Schema CREATE 撤銷仍未驗收。
2. **Validator 的政策權威**：Hash 一致只證明 bytes 完整，不能單獨證明 Contract／真實 HTTP 來源。獨立 Validator 尚未接進正式服務，沒有可量測的業務投影審核證據；目前 Promotion 只在專用受信任呼叫者假設下成立。不能讓 Runtime 以同一 DB 身分呼叫 Promotion。
   - `committed_operation` 的既有 `world_operations` 暫非獨立不可偽造來源；**受保護 World Executor 未完成前，Promotion 固定拒絕此來源**，不能把 Runtime SQL 寫入的結果列升級為可信業務提交證明。
3. **Transition/Send 接線**：新 Authorizer 尚未取代 `trusted_http.create_app()` 舊 `grant` 路徑；`StartSend`／Snapshot／Send Lease、跨 DB Fence／Restore 還沒連接。在此之前 `from_environment()` 必須繼續硬拒絕。
4. **真資料庫驗證權限**：本機沒有 PostgreSQL／pytest 服務；嘗試唯讀盤點既有 Oracle 隔離 Lab 時，Gateway 使用者對 `/var/run/docker.sock` 得到 `permission denied`（Job `job_01M8022EJE00NNKXPMDAK1YAT3`）。不得在未授權狀態下提權操作 Lab。**隔離 GitHub PostgreSQL 17.6 G3 子測試已 PASS，Oracle 既有 Lab／真實部署 G3–G5 整體驗收尚未執行**。

## 驗證證據分類

| 類別 | 狀態 | 證據 |
| --- | --- | --- |
| Python 語法與模組匯入 | PASS | `compileall`；`PYTHONPATH=src python -c ...` |
| 函式中文註解／文件檢查 | PASS | `python tools/check_documentation.py` |
| Git Patch whitespace | PASS | `git diff --check` |
| PostgreSQL 17 管理登入下的 Grant / 回滾子驗收 | PASS（初版 SHA `cb1369e0da408bf5c3114657099432201fad4b7d`） | GitHub Python tests [run 44955152598](https://github.com/IAN40070510/Mirage_API/actions/runs/44955152598)：`1278 passed / 21 skipped`；容器 [run 44955152642](https://github.com/IAN40070510/Mirage_API/actions/runs/44955152642) PASS。這只覆蓋該 SHA 的原子性子測試，不能沿用為後續 Row Lock／SCRAM PASS。 |
| Row Lock 函式／實體 SCRAM Role／Grant 狀態轉移子測試 | PASS（限 SHA `a54065f2c1cf4a6b13dc34b3c7d7a2bf08e42f34`） | GitHub 隔離 PostgreSQL 17.6 [run 44955902350](https://github.com/IAN40070510/Mirage_API/actions/runs/44955902350)：`8 passed`。不代表本輪最新修改、全套並行安全或正式部署通過。 |
| 本次新增的 `committed_operation` 不可信來源阻擋 | NOT_RUN | 待新 Commit 的獨立 PostgreSQL CI；僅由 Python 靜態檢查無法驗證資料庫權限。 |
| Snapshot、Send Lease、Restoration Fence | NOT_IMPLEMENTED | G4／G5 未接線 |
| 全套 Python／HTTP 效能回歸 | NOT_RUN | 不可將 Static PASS 當成 P95 測試 |

## 接續順序

1. 以獨立 Lab 或 GitHub CI PostgreSQL 17 修正 ACL／受限鎖定程序，完成 Candidate Validator、Authorizer、Grant Binding 的正反面驗收。
2. 建立實體 Authorized Snapshot／Pin 與一次性 Send Lease，讓 ASGI 起送前的 Snapshot 與 Fence 檢查具同一安全協定；不在 `SEND_AUTHORIZED` 後重判政策。
3. 完成 World DB 還原範圍外的持久化 Quarantine Fence 與不同 DB Commit 失敗對帳，並封住 Send／Purge／Restore 並行放行競態。
4. Owner／DBA／Security 審核、G0–G6 真實安全驗收與量測通過前，不解除 Release Fuse。
