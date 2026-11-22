# MIR-SEC-WORLD-001 — G3 Grant Binding 實作紀錄

**修補分支**：`fix/mir-sec-world-001-protected-grant`（與 `main` 隔離）。

**2026-11-22 狀態**：`IMPLEMENTATION IN PROGRESS / NOT ACCEPTED`。這份文件保留本輪實作選擇及阻礙，**不是 G3 PASS**。`MIR-SEC-WORLD-001=OPEN`、`MSDSS P2=NO-GO`、正式 Trusted Send／Production DECEIVE **OFF**；原有 `from_environment()` 的 Release Fuse 不移除。

## 本輪已寫入獨立分支的變更（部分獨立 PostgreSQL 驗證已通過）

| 實作檔案 | 安全作用與限制 |
| --- | --- |
| `migrations/018_protected_grant_bindings.sql` | 新增完整 Scope＋不可變版本的 `protected_candidate_promotions`、一對一 Receipt/Admission 的 `protected_grant_bindings` 與不可變觸發器。新增固定 Schema `search_path` 的受限 `SECURITY DEFINER` Row Lock Helper；未授予 Runtime 執行權。Migration 不建立 LOGIN 或開啟發送。 |
| `migrations/019_protected_world_sources.sql` | 將 Verifier Receipt 的 `access_mode`／`resource_id` 保存為已驗證 Claims；新增獨立的受保護 ReadAdmission／World Commit 來源證據。既有缺少能力欄位的 Receipt 不作可信 World Executor 憑據，舊來源列不得因 schema 更新而補簽。 |
| `src/deception/world/protected_grant.py` | 分離 Candidate Validator 與 Authorizer 的預期 PostgreSQL Login／DSN；Promotion 複製並重新驗證 v1 Envelope 三種 SHA-256；Grant 在單一交易鎖定 Session／Receipt／Candidate／Generation／Key／Profile，檢查 Registry／DB 期限並寫入 Binding＋Admission；Claim／Authorize 只接受已有 Binding，使用 DB 時間；Operation ID＋input digest 只讀查回。未核准 token expiry grace 前，保守要求 `transmission_deadline <= token_expires_at`。 |
| `src/deception/world/protected_world.py` | 新增僅供隔離特權執行程序使用的 `PostgresProtectedWorldExecutor`，檢查登入者、Receipt 的已簽 Session／Mode／Resource／Fingerprint、現時 Epoch／Generation／Key Revocation；ReadAdmission、業務 World Mutation 與各自受保護來源證據於同一實體連線及交易提交。不採信 Runtime 自稱能力或舊業務結果。正式服務通訊／容器 Secret 尚未接線。 |
| `src/deception/world/session.py`、`src/deception/world/event_store.py` | 原生 ReadAdmission、固定 Handler World Commit 可使用外層 Executor 的受控交易連線，不另開交易或自行 commit；既有 API 未指定交易連線時保留原方法行為，但舊 Runtime DML 不具可信發送資格。 |
| `src/deception/security/ingress_receipt.py` | 可信 Verifier 於原本 Replay／Receipt 同交易寫入簽名 Claims 中的 `access_mode`／`resource_id`；DB 不從 Runtime 參數補填該能力。 |
| `src/deception/world/postgres_candidate.py` | Candidate GC 不使用呼叫者提供的 `protected_refs` 當唯一判據；已 Promotion 的來源候選不得被刪除。此為暫時偏向安全的保留策略，日後需分離可清理 Bytes 與永久 Metadata。 |
| `src/deception/security/world_acl.py` | 擴大 Runtime 對 World State／Operation／ReadAdmission／Protected Sources 的有效 DML 拒絕查核，並驗證無 Executor membership 或 Row Lock 特權執行權。正式 Runtime 的原生 Write／ReadAdmission 必須改走可信 Executor，不能共用舊 DB Role。 |
| `tests/test_protected_grant.py` | 擬定真實 PostgreSQL 正向 Grant、Receipt 重綁／交易回滾、偽造 Fingerprint、未 Promotion、錯誤 Login、Candidate GC 與不可變資料負面測試；使用一次性真 SCRAM Login 及欄位級最低權限驗證。 |
| `tests/test_protected_world_executor.py` | 新增 Read＋Commit 正向、錯誤 Mode／Fingerprint、Commit 來源寫入故障的原子 rollback、舊業務列不得自動受信任、真 SCRAM Executor／Runtime 權限分離等測試；**本新增批次尚未經 PG CI 執行**。 |
| `.github/workflows/world-security-contract.yml` | 獨立、無正式憑證的 PostgreSQL 17.6 快速驗收；只針對 Protected Grant / SCRAM 角色，保留 JUnit，不取代全套 CI。 |

## 本輪發現並保持阻擋的關鍵事項

1. **ACL 與資料庫 Row Lock**：PostgreSQL 17 `SELECT ... FOR SHARE` 也需要受查表至少一欄 `UPDATE` 權限。不可直接向 Authorizer／Validator 授予 Key／Receipt／Session 等整表 `UPDATE`。目前新增只接受預先定義 `kind`／完整 Scope 的 `SECURITY DEFINER protected_lock_reference`，函式固定 Migration 對應的可信 Schema `search_path`，並撤銷 `PUBLIC EXECUTE`；一次性真 SCRAM 最小權限 Role 測試在隔離 CI 已通過，但正式部署的函式 owner NOLOGIN／無 Runtime 繼承／可信 Schema CREATE 撤銷仍未驗收。
2. **Validator 的政策權威**：Hash 一致只證明 bytes 完整，不能單獨證明 Contract／真實 HTTP 來源。獨立 Validator 尚未接進正式服務，沒有可量測的業務投影審核證據；目前 Promotion 只在專用受信任呼叫者假設下成立。不能讓 Runtime 以同一 DB 身分呼叫 Promotion。
   - `committed_operation` 的舊 `world_operations` 暫非獨立不可偽造來源；新路徑只接受同一可信 Executor 交易建立且綁定同 Receipt 的 `protected_world_commit_sources`，舊列永久不因查詢成功而自動提升為權威。
   - ReadAdmission 同理只採信 `protected_world_read_sources`；Runtime 能指定 `request_fingerprint` 不等於真實入口來源證明（Fingerprint 語意 A）。需另由可信入口保證原始請求，這不屬於單一 DB R1 防護。
3. **Transition/Send 接線**：新 World Executor／Authorizer 尚未取代 `trusted_http.create_app()` 的舊共用 DSN、`grant`／直接業務呼叫路徑；獨立服務認證、驗證器請求快照、`StartSend`／Snapshot／Send Lease、跨 DB Fence／Restore 也還沒接線。在此之前 `from_environment()` 必須繼續硬拒絕。
   - **完整電商流程差異（阻擋）**：`CartHTTP.createGuestCart` 與 Medusa `PostCarts` 由原始 creator Session 建立**衍生的新 Cart Session／World**，不能套用一般 mutation 的「Receipt Session 必須等於目標 Session」；需正式的 `creator receipt → protected cart creation → derived scope` 單次來源鏈及同交易權威產生者。`SyntheticCarts.create_cart()`、原生資源映射與 World `resolve()` 初始寫入也必須從舊 Runtime 搬到可信 Executor，不是只移交 `world_operations`。
   - **正常錯誤回應差異（阻擋）**：`CartHTTP`、`MedusaCartHTTP` 的合法 400／409 走 `SecurityErrorSource`，目前 Candidate Promotion 保守拒絕無受保護來源的錯誤模板；若不新增獨立可信模板／拒絕結果的權威證據，無法宣稱保留完整 API 契約，也不得把這些拒絕降級成任意成功回應。
4. **真資料庫驗證權限**：本機沒有 PostgreSQL／pytest 服務；嘗試唯讀盤點既有 Oracle 隔離 Lab 時，Gateway 使用者對 `/var/run/docker.sock` 得到 `permission denied`（Job `job_01M8022EJE00NNKXPMDAK1YAT3`）。不得在未授權狀態下提權操作 Lab。**隔離 GitHub PostgreSQL 17.6 G3 子測試已 PASS，Oracle 既有 Lab／真實部署 G3–G5 整體驗收尚未執行**。

## 驗證證據分類

| 類別 | 狀態 | 證據 |
| --- | --- | --- |
| Python 語法與模組匯入 | PASS | `compileall`；`PYTHONPATH=src python -c ...` |
| 函式中文註解／文件檢查 | PASS | `python tools/check_documentation.py` |
| Git Patch whitespace | PASS | `git diff --check` |
| PostgreSQL 17 管理登入下的 Grant / 回滾子驗收 | PASS（初版 SHA `cb1369e0da408bf5c3114657099432201fad4b7d`） | GitHub Python tests [run 44955152598](https://github.com/IAN40070510/Mirage_API/actions/runs/44955152598)：`1278 passed / 21 skipped`；容器 [run 44955152642](https://github.com/IAN40070510/Mirage_API/actions/runs/44955152642) PASS。這只覆蓋該 SHA 的原子性子測試，不能沿用為後續 Row Lock／SCRAM PASS。 |
| Row Lock 函式／實體 SCRAM Role／Grant 狀態轉移子測試 | PASS（限 SHA `a54065f2c1cf4a6b13dc34b3c7d7a2bf08e42f34`） | GitHub 隔離 PostgreSQL 17.6 [run 44955902350](https://github.com/IAN40070510/Mirage_API/actions/runs/44955902350)：`8 passed`。不代表本輪最新修改、全套並行安全或正式部署通過。 |
| 不可信 `committed_operation` 來源阻擋、ReadAdmission Runtime 權限拒絕 | PASS（限 SHA `0b1650583f794d1c47c0646bcb0ef7c2197ae966`） | GitHub 隔離 PostgreSQL 17.6 [run 44956251385](https://github.com/IAN40070510/Mirage_API/actions/runs/44956251385)：`9 passed in 3.46s`；仍未證明正式 World Executor／ReadAdmission provenance 或部署隔離。 |
| 可信 World Executor／兩種受保護來源及 Rollback | PASS（限 SHA `9c0cf210f82c5958256da5c85869b60d43c3505e`） | GitHub 隔離 PostgreSQL 17.6 [run 44979074395](https://github.com/IAN40070510/Mirage_API/actions/runs/44979074395)：`14 passed in 6.62s`；容器 [run 44979074359](https://github.com/IAN40070510/Mirage_API/actions/runs/44979074359) PASS。新加「不同 Receipt 同 Fingerprint」與「沒有 Proof 的 ReadAdmission」案例待下次 CI；正式業務入口與 Oracle 部署仍未驗收。 |
| 相同 Fingerprint、不同 Receipt 與無 Provenance 的 ReadAdmission | PASS（限 SHA `92be17aa0b756aba048904a65b47c99394612a11`） | GitHub 隔離 PostgreSQL 17.6 [run 44979254933](https://github.com/IAN40070510/Mirage_API/actions/runs/44979254933)：`16 passed in 7.01s`；容器 [run 44979255001](https://github.com/IAN40070510/Mirage_API/actions/runs/44979255001) PASS。僅為新增原子性與來源完整性子合約。 |
| Snapshot、Send Lease、Restoration Fence | NOT_IMPLEMENTED | G4／G5 未接線 |
| 全套 Python／HTTP 效能回歸 | NOT_RUN | 不可將 Static PASS 當成 P95 測試 |

## 接續順序

### 2026-11-22 接續分支 G3b 增量（尚未驗收）

下一批增量新增 `021_protected_business_rejections.sql`：只允許固定 World
Handler 實際保存 `rejected` 操作時，Executor 同交易生成受保護 409 錯誤來源。
Validator 必須比對來源 Receipt／完整 Scope／Fingerprint、固定錯誤模板、
Contract Revision、持久化 Operation Result Digest 與精確 Envelope Hash。
Runtime 單獨提交 `SecurityErrorSource` 仍然不能 Promotion。初期僅覆蓋
合成 Inventory／Cart 的固定 `{"code":...}` 409，Medusa 400／404、
未持久化的輸入驗證錯誤尚需各自權威證據，不能把此批視為完整 400／409 PASS。

`fix/mir-sec-world-001-resume-20261122` 新增 `020_protected_cart_lineage.sql` 與
`PostgresProtectedWorldExecutor.create_cart()`，把 creator Receipt 與新建 cart
Session／World／resource 的 lineage 原子寫入；新增一次性 Receipt／Cart 唯一約束，
在首次受保護呼叫發現舊 `guest_cart_creations` 時拒絕補簽。
`SyntheticCarts.create_cart()` 另支援 Executor 專用的共交易連線，不改公開呼叫預設行為。
Runtime ACL preflight 同步列入新 lineage 表；獨立 PostgreSQL 測試新增同 Receipt
重試、錯 idempotency key 重綁阻擋。

此增量**僅限合成 Cart 的專用 Executor 業務 primitive**。HTTP Runtime 尚未接到
獨立驗證的服務入口；Medusa native_context、初始品項、合法 400／409 受保護
拒絕證據、G4 Snapshot／Lease、G5 外部 Fence 均未完成。不能宣稱 G3b PASS。
本機 `compileall`／文件檢查及非 PostgreSQL 回歸通過；因本機沒有隔離 PG DSN，
本輪 PostgreSQL 新增測試為 SKIP，須以固定 SHA 的 CI 真 PG 結果補驗。

1. 以獨立 Lab 或 GitHub CI PostgreSQL 17 修正 ACL／受限鎖定程序，完成 Candidate Validator、Authorizer、Grant Binding 的正反面驗收。
2. 將 `World.resolve()`／`SyntheticCarts.create_cart()` 的衍生 Scope 與合法拒絕模板納入受保護 Executor 來源合約，連接 `trusted_http.create_app()` 原生 Cart／Inventory／Medusa 業務；驗證所有既有 2xx／4xx 結果與冪等／未知 COMMIT。原生 HTTP 入口尚未接線時不得將 G3 視為完整。
3. 建立實體 Authorized Snapshot／Pin 與一次性 Send Lease，讓 ASGI 起送前的 Snapshot 與 Fence 檢查具同一安全協定；不在 `SEND_AUTHORIZED` 後重判政策。
4. 完成 World DB 還原範圍外的持久化 Quarantine Fence 與不同 DB Commit 失敗對帳，並封住 Send／Purge／Restore 並行放行競態。
5. Owner／DBA／Security 審核、G0–G6 真實安全驗收與量測通過前，不解除 Release Fuse。
