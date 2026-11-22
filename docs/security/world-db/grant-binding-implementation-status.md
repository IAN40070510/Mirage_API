# MIR-SEC-WORLD-001 — G3 Grant Binding 實作紀錄

**修補分支**：前置 `fix/mir-sec-world-001-protected-grant`；續作 `fix/mir-sec-world-001-resume-20261122`（皆與 `main` 隔離）。

**2026-11-22 狀態**：`IMPLEMENTATION IN PROGRESS / NOT ACCEPTED`。這份文件保留本輪實作選擇及阻礙，**不是 G3 PASS**。`MIR-SEC-WORLD-001=OPEN`、`MSDSS P2=NO-GO`、正式 Trusted Send／Production DECEIVE **OFF**；原有 `from_environment()` 的 Release Fuse 不移除。

## 2026-11-22 G3b HTTP 邊界最新補充（下方舊紀錄按當時 SHA 保留）

隔離分支已補上 `create_direct_verifier_app()` 原始 ASGI HTTP 接收、真正 JWS
驗章後單交易 Replay／Receipt／固定 Operation Proof；Verifier 可使用獨立
`FixedExecutorMTLSClient` 以受信任 TLS Server CA、專用 Client Certificate
呼叫另一程序的 `create_fixed_executor_app()`。RPC 僅收 Receipt ID、原始
Path／Body，Medusa 額外要求 Fingerprint 綁定的 `request_id`、`raw_url`、
核准原始 Headers。Executor 從受保護資料庫取回固定 Handler／Scope，絕不
接受 Runtime 自選 Operation；重放只重用同 Receipt 已存在的 Read Source，
未知 COMMIT 不盲目重試。

`migrations/027_protected_medusa_rejections.sql`、`PostgresProtectedWorldExecutor`
與 `PostgresCandidatePromoter._source_matches()` 把以下原生拒絕接入獨立來源：
限定 `POST /store/carts/{id}/line-items`，核對原始金鑰或 Body 模型的 400，
以及已受保護 Cart catalog 沒有 variant 的 404。均需同 Receipt ReadAdmission、
原始 Operation Proof、Scope／Fingerprint、固定原生 JSON Envelope Hash，
再寫入不可更新／不可刪除的來源表；Runtime 自填安全錯誤模板不具權威。
其它 Medusa 操作／成功回應仍 503，**不等於完整 Medusa API 相容通過**。

| 固定來源與 CI | 實測結果 | 不可推論的事項 |
| --- | --- | --- |
| Commit `138beba79e59f9955f8c1e50a9454c60732a16fb`，隔離 [PostgreSQL CI 45055022497](https://github.com/IAN40070510/Mirage_API/actions/runs/45055022497) | `63 passed`、mTLS `4 passed`，含 Medusa 400／404 DB 來源、偽造回應無法 Promotion；容器 [45055022535](https://github.com/IAN40070510/Mirage_API/actions/runs/45055022535) PASS | 不是全 Medusa 路由、部署級角色或 G4/G5 完成證明 |
| Commit `14e3fd2cfba0935b27e44abadefa4746776e77cd`，隔離 [PostgreSQL CI 45055331170](https://github.com/IAN40070510/Mirage_API/actions/runs/45055331170) | `64 passed`、mTLS `4 passed`，追加真正 Verifier→Executor mTLS 雙程序 Medusa 400 與簽後 Key 篡改拒絕；容器 [45055331220](https://github.com/IAN40070510/Mirage_API/actions/runs/45055331220) PASS | Verifier 測試側使用 ASGI TestClient、兩個服務沿用隔離 DB 同一 Login；未證明真 Gateway→Verifier→Executor 三程序部署 |
| 本輪新增雙程序案例前的本機全套（無 PostgreSQL） | `1112 passed / 243 skipped / 2 warnings`，文件與 Patch 檢查 PASS；雙程序新增測試另由上列真 PG CI 執行 | SKIP 不算 PG PASS，缺 G3b 全操作結果與 G6 P95／故障注入 |

G3b 仍 `OPEN`：正式 HTTP Runtime／Ingress Gateway 實體路由、獨立
Verifier/Executor SCRAM 身分與 TLS 根信任隔離、完整 Inventory／Cart／Order／
Medusa 成功與錯誤回應相容、Validator／Sender 鏈與未知 COMMIT 對帳均待驗收。
G4 Sender mTLS、G5 獨立 Restore Fence、G6 故障注入與正式簽核均未完成。
`MIR-SEC-WORLD-001=OPEN`、`MSDSS P2=NO-GO`，Trusted Send **OFF**。

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
| `tests/test_protected_world_executor.py` | 新增 Read＋Commit 正向、錯誤 Mode／Fingerprint、Commit 來源寫入故障的原子 rollback、舊業務列不得自動受信任、真 SCRAM Executor／Runtime 權限分離等測試；續作 G3b 的 Cart Creator／GET 證據另見下方固定 SHA 的 PG CI。 |
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
| G3b Inventory／Cart／Order 固定 HTTP 命令與 Creator Lineage | PARTIAL PASS（限隔離分支 commit `dbf96706ba9852c6499284eae15ecf7cedf85f6b`） | GitHub 隔離 PostgreSQL 17.6 [run 45050313704](https://github.com/IAN40070510/Mirage_API/actions/runs/45050313704)：`52 passed`；獨立 sealed mTLS `2 passed`；容器 [run 45050313673](https://github.com/IAN40070510/Mirage_API/actions/runs/45050313673) PASS。不能視為 HTTP 接線。 |
| G3b 可信 createGuestCart、穩定衍生世界／重試 | PARTIAL PASS（限隔離分支 commit `5cd1d551e5bf313526a919a071b3264739f91a4b`） | GitHub 隔離 PostgreSQL 17.6 [run 45050573588](https://github.com/IAN40070510/Mirage_API/actions/runs/45050573588)：`55 passed`；mTLS `2 passed`；容器 [run 45050573766](https://github.com/IAN40070510/Mirage_API/actions/runs/45050573766) PASS。不能視為 Medusa 400／404 驗收。 |
| G3b Cart／Order／Operation 原始 GET 與來源鏈 | PARTIAL PASS（限隔離分支 commit `cdf5ecd95b6b22f2b91e57878ef5e25a0a4a5ee3`） | GitHub 隔離 PostgreSQL 17.6 [run 45050921787](https://github.com/IAN40070510/Mirage_API/actions/runs/45050921787)：`60 passed`；sealed mTLS `2 passed`；容器 [run 45050921824](https://github.com/IAN40070510/Mirage_API/actions/runs/45050921824) PASS。實際 mTLS 業務 RPC 仍固定 503，HTTP E2E 未驗收。 |
| G4 Snapshot Pin／一次性 Lease／ASGI 守衛 | PARTIAL / NOT WIRED | 內部隔離 Primitive 已實作；獨立 Sender RPC／真實 G5 Fence／正式端到端仍未驗收 |
| G5 Restoration／Purge Fence | NOT_IMPLEMENTED | 跨資料庫隔離權威／還原競態未接線 |
| 本地全套 Python 相容回歸 | PASS / PG SKIPPED | 續作分支本地 `python -m pytest -q`：`1110 passed / 240 skipped / 2 deprecation warnings`，`147.31s`；PG 類別靠上述 CI，**HTTP P95／真部署級故障注入仍 NOT_RUN**。 |
| 隔離 Fence 實體盤點 | OBSERVED / G5 NOT_RUN | Gateway 唯讀 Docker 檢視找到獨立 `postgres:17.6-alpine` Fence 容器與專屬資料 Volume；未驗證最高可信 Head、跨 DB Protocol、Root 隔離、發送守衛或 Purge/Restore 競態，不能當作 G5 PASS。 |

## 接續順序

### 獨立 mTLS 服務決策及 sealed 入口（2026-11-22）

**G3b Operation Binding 新增增量**：`023_verified_http_operations.sql` 與
`operation_binding.py` 讓獨立 Verifier 在同一 IngressTx 把實際 HTTP method、
唯一 OpenAPI Operation、路由模板、body hash、JWS 請求摘要綁定 Receipt。
不修改 Freeze v1 JWS 的 Signed Claims；需 Verifier 真正收到完整原始請求，
不接受 Runtime 自填「verified」或另選 Handler。Medusa／固定 RPC 消費端
尚未驗收，不能將表結構存在視為 G3b 整體 PASS。

**下一增量：固定 Inventory Executor primitive**：`024_verified_http_original_path.sql`
保留 Verifier 精確原始路徑／Content-Type，不對舊 Proof 補綁操作；
`commit_verified_inventory_http()` 只從已鎖定 Receipt 對應的不可變
Operation Proof 決定 Inventory reserve/cancel 的命令、資料與提交鍵，RPC
呼叫端不能自填 Handler。新負面測試涵蓋替換 body、path、JSON key、舊 Receipt
和真 PostgreSQL World 無副作用回滾。此方法**尚未接入 mTLS 服務端**，且
Cart／Order／Medusa、完整合法拒絕回應與 Verifier 物理隔離均未驗收。

**再下一增量：Cart／Order 固定命令及 Medusa 來源綁定**：
`operation_binding.py` 以確切 raw HTTP Proof 推導合成 Cart／Order 五種 mutation；
省略可選提交 UUID 時按 Receipt 確定性生成，同 Receipt 重放不能改變事件。
`PostgresProtectedWorldExecutor.commit_verified_cart_http()` 只容許
受保護 Creator Lineage 派生的 Cart／Order Scope；
`_verify_receipt()` 對可信 Read Source 也要求資源映射與衍生鏈。
`create_verified_cart_http()` 從原始 POST /synthetic/carts Receipt 綁定
穩定建立鍵與內容摘要，使用受保護 `create_cart()` 同交易產生衍生世界，
且不接受 Runtime 任意初始庫存或價格。
`read_verified_cart_http()` 將 Cart／Order／Operation 三種 GET 路徑固定綁回
受保護 Receipt 的原始 Resource ID 與 Creator Lineage；這仍是內部 primitive，
非 HTTP 接線或最終傳輸證據。
另將 Medusa Operation 來源綁到既有 SHA-256 固定的 OpenAPI 檔案，
**僅是 Request Identity，尚無 Native Executor／400／404 證據**。
這個增量也沒有對外啟用 mTLS execute，保留 503 和正式 Send Release Fuse。

Owner 已核准獨立 mTLS Trusted Service；`src/deception/security/protected_rpc.py`
建立只允許 Client Certificate、預設 loopback 的封閉傳輸服務。
未具證書拒絕 TLS 握手，具證書仍只能獲得 `sealed` 健康狀態，不能觸發業務；
短期測試 CA／EKU 握手驗收見 `tests/test_protected_rpc_mtls.py`。
此批不把 mTLS 當成 Operation 來源證明，也不讓 HTTP Runtime 藉 RPC 執行
自選 Handler。原始 HTTP Operation／Request Snapshot 仍需由獨立可信入口建立
不可偽造的 Receipt 綁定，G3b／G4／G5／G6 仍 OPEN，正式 Send OFF。

### 2026-11-22 接續分支 G3b 增量（尚未驗收）

下一批增量新增 `021_protected_business_rejections.sql`：只允許固定 World
Handler 實際保存 `rejected` 操作時，Executor 同交易生成受保護 409 錯誤來源。
Validator 必須比對來源 Receipt／完整 Scope／Fingerprint、固定錯誤模板、
Contract Revision、持久化 Operation Result Digest 與精確 Envelope Hash。
Runtime 單獨提交 `SecurityErrorSource` 仍然不能 Promotion。初期僅覆蓋
合成 Inventory／Cart 的固定 `{"code":...}` 409，Medusa 400／404、
未持久化的輸入驗證錯誤尚需各自權威證據，不能把此批視為完整 400／409 PASS。

G4 第一個隔離實作：`022_authorized_http_snapshots.sql` 以 immutable 表保留完整
Envelope Bytes、Candidate／Receipt／Operation／Scope、Send Owner 和 Deadline。
`PostgresProtectedAuthorizer.authorize_send()` 在相同 DB Transaction 將
`SEND_AUTHORIZED` 與受保護 Snapshot Pin 一起提交；若 Pin 寫入失敗，狀態
轉移必須回滾。後續新增 `025_protected_send_leases.sql`、
`PostgresProtectedSender` 及 `ProtectedLeaseTransmission`，以獨立 Sender DB Login
在 ASGI 首訊息前核對原 Pin、持久化唯一 Lease 與 SEND_STARTED，
成功／失敗回寫唯一終態，並保持 Freeze v1 不重判政策。其原子性、同時起送與
Renderer 首 byte 順序在隔離測試內驗證；仍需真 PostgreSQL CI 及
跨 DB G5 Restore/Purge Fence、實際 mTLS Sender 路徑與 G6 故障注入證明。
所以 **G4 只算部分實作，不是正式 PASS**。

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
