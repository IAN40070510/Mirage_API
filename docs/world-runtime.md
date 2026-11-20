# Synthetic World Runtime

## 用途與邊界

這份工具以完整 `WorldScope` 隔離 Session，用不可變 `WorldSnapshot` 保存狀態，並用 CAS 防止舊版本覆寫新版本。它不包含 Medusa 商品欄位，也不讀取真實商店。領域交易由[購物車](carts.md)與[庫存](inventory.md)實作；單次 HTTP 傳輸由[Renderer](renderer.md)整合。

`AdmissionControl` 負責 ResponseAdmission 的控制邊界：Grant、Cutover、Claim 與 Send Authorization 使用同一個單調控制序列。Grant 會先向 `ProjectionRegistry` 驗證契約、來源規格與 Compatibility Profile，只有取得 `AUTHORIZED` 及 Registry revision 才會建立准入。`PostgresAdmissionControl` 將同一狀態機放入 Generation row lock 與資料庫交易，可供多個 Mirage Instance 共用；合成 WorldEvent 需要可信業務服務明確啟用。

`ProjectionEvidence` 將官方規格雜湊、相容 Profile、Effective Projection 與差異核准綁在同一份證據中；官方 Schema 不符時，沒有對應 `DeviationApproval` 就不能建立有效投影。

`ProjectionRegistry` 再確認這份證據的契約、來源規格與 Profile 仍是目前核准版本；撤銷後即使呼叫者持有舊 Evidence，也不能取得新的輸出准入。`PostgresProjectionRegistry` 以同一資料庫交易保存這個決策，讓兩個 Instance 不會各自採用不同撤銷狀態。

整體停用 Profile 使用[Profile 撤銷介面](profile-revocation.md)及 migration 012。墓碑獨立於契約，阻止未來契約與啟動登錄復活同一 Profile；一般模式保留既有准入 lease，明確緊急模式才在 Claim／Send Authorization／起送邊界停止未起送回應。

## 輸入與輸出

跨程序控制驗收使用 `python -m pytest tests/test_control_processes.py -q`，需專用 MIRAGE_POSTGRES_TEST_DSN。每個排序案先確認兩個不同 OS PID／PostgreSQL backend PID，再以 pg_blocking_pids 確認第二交易真的等待第一交易，才允許依序提交；worker 全部退出後由新控制器查回結果。涵蓋 Grant／Cutover、契約及整體 Profile 撤銷／Grant、緊急撤銷與 Send Authorization／起送，以及獨立 reader 的 Watermark、Lease、epoch 拒絕。這是跨程序控制面證據；測試呼叫 finish_send 只驗證終態保存，不假稱有網路送達，真正 TLS／ASGI 證據另見[驗收矩陣](conformance-evidence.md)。

稽核分開保存四種事實：migration 010 的 `world_initializations` 記錄新快照的初始化版本與 hash；`read_admissions` 記錄已驗證請求的 scope、請求摘要與讀取來源；`world_events` 記錄成功業務事件；migration 009 的 `response_audit` 記錄開始、實際嘗試與終止結果。初始化 trigger 與快照同交易提交，重試不重複插入；稽核寫入失敗時建立回滾。安裝前的世界不補造歷史初始化事件。查閱時需由管理層按完整 scope 授權，這些內部資料表不是公開日誌 API，沒有原始 token、IP／UA、本文或模型提示。可信讀取前的 handler 拒絕另由 migration 013 的固定分類[入口稽核](ingress-audit.md)保存；它使用獨立交易，故障時仍拒絕並告警，不宣稱與 Replay 原子提交，尚無統一管理匯出。

- `WorldScope`：`environment_id`、`deployment_id`、`session_id`、`world_generation_id`。
- `WorldSnapshot.create()`：輸入 JSON 狀態，輸出帶 SHA-256 `state_hash` 的版本快照。
- `WorldCompatibility`：由部署提供世界引擎／來源與精確投影集合，產生不可變政策；`WorldSnapshot.compatibility` 讀取該快照保存的政策。
- `InMemoryWorldStore.create_if_absent()`：初始化同一 scope 的唯一快照。
- `PostgresWorldStore`：以 PostgreSQL 唯一鍵、交易與 row lock 提供共享快照及 CAS。
- `InMemoryWorldStore.load_result()`：區分 `world_found`、`session_not_found`、`expired`、`corrupted` 與 `storage_unavailable`。
- `PostgresAdmissionControl`：持久化 Grant、Cutover、Claim 與 Send Authorization 的狀態及共同 revision。
- `InMemoryWorldStore.compare_and_swap()`：輸入期望版本，輸出下一版本或明確衝突錯誤。
- `ResponseSource`：只能是 `SnapshotSource`、`CommitSource` 或 `SecurityErrorSource` 之一。
- `ProjectionEvidence`：輸入核准來源與投影驗證結果，輸出可供 ResponseAdmission 引用的證據。
- `ProjectionRegistry`：在 Grant 前確認投影仍核准且未撤銷，並提供可稽核的 Registry revision。
- `ProjectionRegistry`：登錄、授權與撤銷 Projection Contract，revision 必須單調遞增。
- `PostgresProjectionRegistry`：以 PostgreSQL row lock 保存共享 Registry 授權與撤銷。
- `CandidateStore`：保存不可變候選 bytes，依完整 WorldScope、candidate hash 與期限驗證讀取。
- `CandidateStore.gc()`：只清理已過期且未列在有效 Admission 保護集合中的 Candidate。
- `PostgresCandidateStore`：以共享資料庫保存 Candidate，並以 PostgreSQL 交易執行跨 Instance GC。
- `ReplayStore`：以 issuer／audience／jti 保存一次性授權消費狀態。
- `PostgresReplayStore`：以 PostgreSQL primary key 和交易提供跨 Instance Replay 防護。
- `TrustedSessionAssessmentProvider`：從唯一 `X-Trusted-Session` header 驗證請求綁定，並轉成既有 malicious assessment。
- `tests/fixtures/golden_vectors/world_runtime.json`：固定 canonical state hash、ResponseSource 與 Admission 順序。
- `tests/fixtures/golden_vectors/admission_projection.json`：16 組固定互通向量，涵蓋 Snapshot／Commit／SecurityError 三種來源、有效投影核准鏈，以及缺少／不符核准、跨世代、無效期限、未知編碼等拒絕案例。Python 驗證完整 ResponseAdmission 型別與 JSON 往返；Node 獨立核對此向量集合的不變量，不是正式授權 SDK，也不宣稱涵蓋全部 Pydantic 欄位規則。

該互通 fixture 另含固定世界政策與快照；Python 與 Node 分別重算政策及完整 state hash，核對允許集合與版本資料未在傳遞時遺失。Node 此向量只涵蓋物件、字串與安全整數，不推定為任意 JSON 數值的通用 canonicalization SDK。

## 使用範例

```python
from deception.world import InMemoryWorldStore, WorldScope

scope = WorldScope(
    environment_id="env-1",
    deployment_id="deploy-1",
    session_id="session-1",
    world_generation_id="generation-1",
)
store = InMemoryWorldStore()
snapshot = store.create_if_absent(scope, {"product_id": "prod_synthetic_001"})
same = store.load(scope)
assert same == snapshot
```

PostgreSQL 服務由 `compose.yaml` 提供，第一次建立資料表時套用
[`001_world_runtime.sql`](../migrations/001_world_runtime.sql)。設定
`MIRAGE_POSTGRES_DSN` 後，兩個獨立的 `PostgresWorldStore` 或
`PostgresAdmissionControl` 或 `PostgresCandidateStore` 物件即可共用同一資料庫。GC 前先從
`PostgresAdmissionControl.active_candidate_refs()` 取得仍可能被 Claim／發送使用的引用，再傳給
`PostgresCandidateStore.gc()`；這個查詢是保守保護，寧可延後清理也不能提前刪除。

## 失敗處理

- Snapshot 雜湊不符：拒絕建立或載入，並回報 `corrupted`。
- scope 不同：以不同保存鍵隔離，不得讀到其他 Session。
- World 不存在：`load_result()` 回報 `session_not_found`。
- Snapshot 到期：`load_result()` 回報 `expired`。
- Store 不可用：回報 `storage_unavailable`，不得自動建立替代 World。
- CAS 版本落後：`WorldStoreError("version_conflict")`。
- 未知 Admission：只回傳拒絕，不自動重建。
- Candidate 不存在、跨 scope、過期或 hash 不符：拒絕使用，不重新生成替代 bytes。
- Candidate GC：有效准入引用的 Candidate 必須列入 `protected` 集合，否則不得清理。
- `UNVERIFIABLE` 是操作結果，不是持久化狀態；PostgreSQL 已提供提交收據查詢與事件結果恢復，記憶體原型不提供持久化恢復，不能據查無紀錄盲目重寫。
- PostgreSQL 連線失敗會回報 `storage_unavailable` 或 `WorldStoreError`，不得建立替代 World。
- Replay JTI 重複消費：回報 `replay`，不得重新執行請求；Replay Store 不可用時必須 Fail-Closed。

## 驗證方式

事件寫入的五類 `CommitResult`、共用原子交易、結果摘要與唯讀恢復見[共用事件提交](commit-results.md)。低階 compare_and_swap 仍回 Snapshot／例外，不把它與事件介面混用。庫存與購物車事件使用 PostgreSQL 共用核心，記憶體事件後端尚未提供。

PostgreSQL 的初始化、CAS、Session 首次建立及事件寫入會先用同交易 SELECT 固定 JSONB 實際表示，再依原演算法計算 state_hash。如此指數數值與負零不會在保存後改變表示而生成不可讀快照；不重寫舊世界或替毀損快照補 hash。JSON 型別與數值限制見共用事件說明。

執行：

```powershell
pytest tests/test_world_runtime.py
MIRAGE_POSTGRES_TEST_DSN=postgresql://mirage:mirage@localhost:5432/mirage pytest tests/test_postgres_conformance.py
python tools/check_documentation.py
```

PostgreSQL Conformance 沒有設定 DSN 時會明確 skip；Golden Vector 與 Fault Matrix 測試可離線執行，但即使通過，也仍未通過完整多 Instance Conformance，本工具不能據此宣稱 Runtime 已符合 Protocol v1.1。

### 真正獨立程序的競爭驗收

設定專用 `MIRAGE_POSTGRES_TEST_DSN` 後執行 `python -m pytest tests/test_process_conformance.py -q`。每個案例使用獨立 schema，啟動兩個 spawn worker；父程序收到不同 PID 且確認兩者存活後才同時釋放。worker 各自建立 PostgreSQL 控制器與連線，競爭同一 JTI、同一 Claim 或同一 Session 首次初始化；結果必須分別為一次接受、一次 Claim 或同一份世界快照。

兩個 worker 正常退出後，父程序另建第三個控制器驗證重放仍拒絕、Claim 不可再領取、世界不被新提案覆蓋。這驗證程序退出後的共享資料持久性，不是 PostgreSQL 重啟或多主機分區測試。90 秒觀察期限只用於測試等待，超時不算成功，也不自動重做操作。測試只終止自己建立的 worker，結束會刪除自身 schema；不得指向正式資料庫。

AUTH-10 另外使用 `tests/test_ingress_processes.py` 啟動兩個不同 PID 的 HTTPS 驗章入口，使用真正 ingress 正規化、TrustedSession provider 及共享 PostgreSQL Replay。父程序確認兩個 TLS healthz 已回應後並行送同一固定 JWS；網路目的 socket 不同，但簽章涵蓋的 authority、path、query、原始 headers 及 JWS 相同。必須一個成功、一個固定 503；後續兩者都拒絕，worker 退出後重建 provider 仍拒絕。這是驗章邊界的端到端測試，不啟動模型或執行業務；完整 Gateway→業務流程由 test_msdss_wire 另驗。需要 OpenSSL 與專用 DSN，TLS 測試 key 只在本機 pytest 暫存目錄，不上傳 SSH。

`tests/test_http_world_isolation.py` 則啟動兩個完整可信電商服務程序，包含資源接收端核對、交易、Gate、Renderer 及傳輸紀錄。SEC-05 的 72 組負例使用有效測試簽章，分別變異環境、部署、Session、epoch、mode、世代 claims 或路徑資源，核對已存在／不存在資源在 `/store`／`/synthetic` 都有相同拒絕 bytes。世代不屬於 Client 可指定的 JWS 欄位，加入該欄位即拒絕。服務先重查完整資源 binding，拒絕不初始化替代世界；這項檢查獨立於 Gateway 身份適配器。

WORLD-02 透過兩個 TLS 服務交錯增加不同數量，再跨程序完成兩個 Session 的訂單、取消 A 並查詢 B，檢查 B 的完整快照保持一致。測試只用固定合成資料與本機短期 key，不接 Medusa、庫存或付款系統；需要專用 PostgreSQL DSN、OpenSSL 及本機 MSDSS request fingerprint 原始碼供比對。失敗不改走其他 Backend，也不自動重試操作。

## 授權與限制

專案程式採 Apache-2.0。此實作使用 Pydantic 進行嚴格型別驗證與 psycopg PostgreSQL 交易。`InMemoryWorldStore` 只適合測試與單程序原型；PostgreSQL Store 仍需可信時鐘、Crash recovery、Replay、Candidate retention 與完整跨 Instance Fault Matrix。

## 初始化提交回覆遺失

PostgresWorldStore.create_if_absent 在寫入交易的 COMMIT 發生連線或介面錯誤後，關閉原連線並依原始 WorldScope 讀取一次目前的快照。成功時回傳通過完整性與期限檢查的快照；查無資料、過期、損毀或儲存不可用時回報 world_initialization_unverifiable 與查詢分類。這個唯讀恢復僅確認目前的世界，無法證明是哪個請求建立它。上游須先取得可信且穩定的 WorldScope。

設定 MIRAGE_POSTGRES_TEST_DSN 指向可建立測試 schema 的隔離資料庫，執行：

    python -m pytest tests/test_postgres_conformance.py -k unknown_world_initialization -q

本機測試對實際交易分別注入「已提交」與「未提交」的相同連線錯誤。第二條連線由資料庫限制為唯讀，第三條連線獨立核對資料列與版本。此項驗收注入的是呼叫端收不到結果的狀態，沒有切斷實際 SSH 或資料庫網路。

## CAS 提交後 HTTP 中斷的恢復

管理者先依序套用 migrations/001_world_runtime.sql 和 migrations/002_world_commit_receipts.sql。服務端在寫入前產生並保存 uuid4()，傳入 PostgresWorldStore.compare_and_swap 的 commit_attempt_id。舊呼叫可省略參數，該次更新不產生收據。此 ID 僅用於查回一次提交；跨 attempt 的業務冪等仍需由後續 WorldEvent 協定實作。

傳輸中斷後，可信呼叫端重新確認原 scope 的查詢權限，再呼叫 get_commit_result(scope, attempt, authorized_scope=verified_scope)。committed 攜帶該次 state_version、state_hash；同一 attempt 的交易鎖仍被寫入者持有時回 pending，已保存的業務拒絕回 rejected。not_found 只表示原範圍沒有此收據；unverifiable 表示身份、輸入或儲存結果無法確認。不能把查無收據當成未提交而盲目重寫。合成購物車另有受資源能力保護的操作查詢路由，見[購物車文件](carts.md)；歷史 Capability 與收據清理政策尚未提供。

本機設定 MIRAGE_POSTGRES_TEST_DSN 指向可建 schema 的隔離 PostgreSQL，執行：

    python -m pytest tests/test_postgres_conformance.py -k committed_cas_survives -q

HTTP 測試服務與 client 在本機，資料庫位於 SSH 伺服器。SQL 遷移與測試資料透過 loopback SSH 隧道傳送。測試對端收到 HTTP 200 及部分本文後讀取失敗，接著檢查跨連線查詢、scope 限制與重複收據的交易回滾。

## Registry 撤銷與 Grant 的交易順序

PostgresAdmissionControl 與 PostgresProjectionRegistry 須傳入相同 DSN 字串（包含 schema 選項）。未符合此條件時 grant 回傳 None。Grant 交易先鎖定世代，再以 SELECT FOR SHARE 核對 Registry 列，鎖一直保留至准入與 revision 提交。撤銷在相同契約列取得 FOR UPDATE 鎖。撤銷提交後，等待中的 Grant 重新讀到 revoked 狀態並拒絕。正常撤銷只阻止新 Grant；已建立的准入仍依原授權期限等規則處理。

設定 MIRAGE_POSTGRES_TEST_DSN 指向可建立 schema 的隔離 PostgreSQL，執行：

    python -m pytest tests/test_postgres_conformance.py -k registry_revoke_orders -q

測試由本機兩條 PostgreSQL 連線執行，透過 pg_blocking_pids 確認等待對象，再控制先行交易提交。SSH 伺服器只保存合成測試資料並執行交易鎖。此測試涵蓋同一契約的兩種提交順序，跨世代 Cutover 與發送階段的緊急撤銷另行驗證。

## 同一世代的 Grant、Cutover 與 Claim

在本機設定 MIRAGE_POSTGRES_TEST_DSN 指向可建立隔離 schema 的 PostgreSQL，執行：

    python -m pytest tests/test_postgres_conformance.py -k generation_cutover_orders_grant_and_claim -q

兩個案例各從一個已有准入的世代開始。測試用 pg_blocking_pids 確認競爭者正在等先行交易，才允許提交。先 Grant 時，兩個控制器在封存後、期限前爭取同一張准入；檢查單次成功、最終狀態與 Grant、Cutover、Claim 的 revision。先 Cutover 時，等待中的 Grant 不產生資料列。兩種順序都檢查重複 Cutover、封存後新申請與期限相等。此項驗收覆蓋 Mirage 控制器與 PostgreSQL 交易，無需啟動 Gateway 或模型。

## 緊急撤銷的共享狀態

先依序套用 migrations 下 001、002、003 SQL。003 在 generation_controls 加入 emergency_revision。部署需完成 migration 才啟動新版本控制器。內部管理者可呼叫 emergency_revoke(generation_id)，重複呼叫回傳第一次撤銷的 revision。一般 Registry 撤銷與世代緊急撤銷各有獨立用途。

PostgresAdmissionControl 在取得 Generation 鎖後讀取共享 emergency_revision。撤銷後拒絕新的 Grant；尚未 Claim 或尚未取得發送授權者在下次操作轉為 ABANDONED。已有 SEND_AUTHORIZED 的授權保留其狀態，表示跨過強一致性邊界；start_send 不二次檢查世代／Profile 墓碑，只檢查 owner、唯一狀態與 transmission_deadline。此結果不證明已送出任何 bytes，也不提供 HTTP 在途取消保證。呼叫端傳入 revoked=False 無法覆蓋資料庫撤銷。既有 revoked=True 仍可用於單一授權的拒絕。

本機設定 MIRAGE_POSTGRES_TEST_DSN 指向隔離資料庫，執行：

    python -m pytest tests/test_postgres_conformance.py -k "emergency_revocation_orders or send_uses_transmission" -q

本機兩個控制器透過 SSH 隧道操作 Ubuntu PostgreSQL 16，以實際資料庫鎖等待驗證兩種順序、不同世代隔離與重建物件後的撤銷持久性。程序內 AdmissionControl 提供對應原型語意。事件 revision 可用 emergency_revocation 查詢。新增功能沿用現有 PostgreSQL／psycopg 授權，無額外依賴。

## Session 映射、epoch 與 ReadAdmission

migration 004 建立 session_heads、session_world_bindings 與 read_admissions。PostgresSessionWorlds.resolve 以 SessionBinding 的環境、部署、session、epoch 原子建立唯一世界。相同 epoch 的並行建立或程序重啟沿用既有世界；較新 epoch 在同一交易封存舊世代並建立新世代，較舊 epoch 拒絕。TTL 由部署者傳入，過期不會自動重設。

inspect_binding 是初始化結果未知時的唯讀恢復入口。admit_read 在同一交易檢查當前 epoch、未封存／未撤銷世代、snapshot hash／期限與 Watermark，再登記 ReadAdmission。Watermark 只向前，禁止傳入任意 Client header 來提高讀取版本。ReadAdmission 只提供來源證據，發送仍需 ResponseAdmission。

本機執行 tests/test_session_worlds.py，測試透過隔離 PostgreSQL 查核共享映射、較新 epoch、舊身份拒絕、版本倒退及交易結果遺失。正式 Gateway 提供可信 binding 的部署接線與匿名識別政策須另外設定。此模組沿用現有 PostgreSQL、Pydantic 與 psycopg 授權。

## 世界政策與契約切換

世界在 state 的保留鍵 `_mirage_world_compatibility` 保存 `world_schema_version`、`domain_adapter_version`、`source_spec_sha256`、`compatibility_profile_hash` 及精確的 `projection_profiles`。政策摘要涵蓋引擎版本、主要資料來源與全部投影集合；快照的 state_hash 再涵蓋整份政策，不另存未受 hash 保護的側邊設定。主要來源是合成資料規格；各輸出 Profile 另外保存自己的官方來源、平台及適配器版本，不能只因名字相同便視為相容。

可信 HTTP 組裝器將目前已審查的商品、購物車、庫存及可選 Medusa 原生投影列入同一世界政策。這是明列的領域映射，不是任意跨平台相容；例如 Medusa 回應適配器與共用電商引擎的版本不同，仍須精確列入這份政策。同一 Profile 下多個已核准 operation 不改變世界政策；新契約仍必須通過 Registry，撤銷也不因世界保存舊政策而失效。

`PostgresSessionWorlds(dsn, compatibility=policy)` 在新世界提案加入政策，讀取、准入、結果查詢及事件路徑重新核對。可信 HTTP 所有領域服務使用相同 policy；輸出發送前另核對選定 Profile 是否在世界集合。啟用不同的 API 組合會改變政策摘要，既有世界不自動擴充權限。CAS 與業務事件禁止新增、移除或替換政策；沒有自動遷移、續期、重建或改變可信 epoch 的行為。

舊快照若沒有政策，`compatibility` 明確為 None；配置政策的服務會拒絕，不會補寫版本或建立替代世代。底層 Store 與未配置政策的 Session 物件保留原型／唯讀定位相容性，不能據此宣稱完整符合性。正式啟用前須由部署者安排舊世界停用或另行審查遷移；本功能沒有替部署者批准資料遷移。

驗證使用 `python -m pytest tests/test_world_compatibility.py -q`；PostgreSQL 案例需專用 `MIRAGE_POSTGRES_TEST_DSN`。測試涵蓋政策摘要、契約切換、Profile 未登錄、舊世界拒絕、CAS 不可變與拒絕時不新增世界／收據。資料保存在既有 JSONB state 中，不需要新的 SQL migration；原有 migration checksum 不變。沿用既有 Pydantic、Python 及 PostgreSQL 授權，不加入模型或外部套件。


## P2 Session epoch 與 Send Authorization 原子一致性

原生可信 HTTP 以 PostgresAdmissionControl(require_session_binding=True) 啟動。
authorize_send 以 Admission 已落盤的 Generation 查詢 Session 綁定，
先對 session_heads FOR SHARE（和 resolve(epoch+1) 的 FOR UPDATE 互斥），
再檢查 binding，接續 Admission → Generation → Profile guard。
全部在同一個 PostgreSQL 交易提交 SEND_AUTHORIZED revision；
epoch+1 先提交時，舊世代不能取得新授權；授權已提交後，epoch 切換不追溯取消。
沒有 Session 映射／Head 消失時，正式可信 HTTP 拒絕，不降級為單機原型。

原始判定 ledger 使用獨立 schema 生命週期（參考 p2-original-assessment-store.md），
不得把它混入一般 World migration；隔離證據不是正式部署核准。
