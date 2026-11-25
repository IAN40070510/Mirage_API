# G4：受保護 Send Lease／ASGI Pin（增量，正式傳送仍封閉）

## 用途與安全邊界

`migrations/025_protected_send_leases.sql` 加入永久一對一 Lease 表與不可變
觸發器。成功的 `start_send()` 在同一資料庫交易把 Admission 從
`SEND_AUTHORIZED` 改為 `SEND_STARTED`，並寫入唯一 `lease_id`、Scope
關聯的 Receipt、精確 Candidate Hash、Fingerprint、Owner、Deadline 及
`send_started` Audit。Lease 寫入／Audit 失敗會回滾狀態轉移。

`ProtectedLeaseTransmission` 可以透過 `ResponseRenderer(...,
transmission_factory=...)` 接到既有 `ValidatedHTTPResponse`：在真正發出
`http.response.start` 之前先核對原請求、最終 Header／Body Hash，取得
一次性 Lease 並比對**真正保存**的 Envelope bytes。ASGI 完成／失敗時
以同一 Lease ID 原子寫入唯一終態及必要 Audit；任何不明結果不重新起送。
傳輸層另外要求回傳的 `lease_id` 是 UUIDv4，且 Lease 的
`transmission_deadline` 與已授權 Admission 完全一致；即使內部 Sender
回傳了匹配的 Payload，錯誤期限或無效 Lease ID 仍須在第一個 ASGI bytes 前拒絕。

**這些仍是隔離測試中的內部 primitive，不是正式 HTTP 入口。**
`protected_rpc.create_sealed_app()` 仍對業務 RPC 回 503；
`trusted_http.from_environment()` 繼續硬拒絕。正式 Sender OS 身分／Secret／
網路 ACL／mTLS 呼叫綁定、G5 Restore/Purge Fence、跨資料庫線性化及 G6
驗收尚未完成。D-74 的標準單機模式不強制安裝外部 Fence，但上述正式
Sender、已知 Restore 恢復與 G6 Gate 未通過前，這個 Primitive 不得對外解封。

## 輸入與輸出

- 輸入：Sender 專用 PostgreSQL DSN、精確的 `expected_login`、已授權
  Admission ID、不可猜測的既有 Owner、原 Request Fingerprint、預期
  Envelope v1 bytes；全部必須由受保護服務內部可信綁定提供。
- 成功：回傳 `ProtectedSendLease(lease_id, admission_id, receipt_id,
  send_owner, request_fingerprint, candidate_hash, envelope_bytes,
  transmission_deadline)`；原始 payload 取自不可變 Snapshot，不從
  Candidate 原本的可清理暫存位元組重新抓取。
- 拒絕：錯誤 Owner、期限、未授權狀態、不同 HTTP bytes、已起送、舊 Admission
  或缺 Snapshot 回傳 `None`；資料庫／Hash／Snapshot 完整性無法驗證時
  拋錯且不放行。
- 終態：`finish_send` 只接受同一次 Lease ID、Owner 與目前
  `SEND_STARTED`，可記錄 `SEND_COMPLETED`、`SEND_FAILED` 或
  `SEND_PARTIAL_FAILURE`；無權者與重覆呼叫固定拒絕。
- 唯讀故障對帳：`reconcile_send(admission_id, receipt_id, owner,
  request_fingerprint)` 用 Sender 專屬物理連線同時核對 Admission、
  Authorized Snapshot 及 Lease 的不可變綁定。傳回 `NO_LEASE_OBSERVED`、
  `STARTED_DELIVERY_UNKNOWN`、`TERMINAL_RECORDED` 或 `UNVERIFIABLE`，
  終態另附實際 DB State 與 `lease_observed`，但不回傳可被拿來偽造
  `finish_send()` 的原始 Lease UUID。**所有結果的 `retry_permitted=False`**；
  `NO_LEASE_OBSERVED` 不能證明其他復原域、失聯的 COMMIT 或實際網路
  發送不存在，`TERMINAL_RECORDED` 也不能證明 Client 全部收到。

### 隔離測試用例（不得移植到 Runtime）

```python
from deception.world import PostgresProtectedSender

# 只限隔離的獨立 Sender 程序；請勿傳入 Runtime 的 DSN 或可控 owner。
sender = PostgresProtectedSender(sender_dsn, expected_login="mirage_sender")
lease = sender.start_send(
    admission_id=authorized_admission_id,
    receipt_id=verified_receipt_id,
    owner=authorized_sender_owner,
    request_fingerprint=original_request_fingerprint,
    expected_envelope=validated_final_envelope,
)
if lease is None:
    raise RuntimeError("trusted_send_denied")
# 只有獨立 sender 的真 ASGI 範圍才可消費此 lease；不做未知 COMMIT 重試。
```

## 故障、驗證與限制

`python -m pytest -q tests/test_protected_send.py` 包含正式
`ValidatedHTTPResponse` ASGI 順序測試，證明 Lease 先於第一個 start/body，
錯 Pin 時零 ASGI 訊息；使用 `MIRAGE_POSTGRES_TEST_DSN` 的真 PostgreSQL
隔離測試驗證重複／併發起送只有一把 Lease、不同 Owner／Fingerprint／
bytes 拒絕、不可改寫 Lease、Lease INSERT 故障時 transaction rollback。
另有隔離 ASGI 負面測試故意回傳錯誤 Deadline 或非 UUIDv4 Lease ID，
均必須拒絕且不送出 `http.response.start`；這不代表 G5 已接線。

隔離測試的 Sender 登入者為專用 schema 管理者，不等於真實
`mirage_sender` 的最小權限 SCRAM／pg_hba／Secret 分離驗收。這裡的
Snapshot 是同一 PostgreSQL 內的不可變 BYTEA，未證明任何外部
Object Store 的 GC／共享 Blob Pin、跨資料庫 Restore quarantine 或
網路 ACK 不明情境。真正的異步送出即使已寫入 `SEND_STARTED`，也不
能保證客戶端收到全部 bytes；失敗必須保留不確定性，不能重送。

**G4 未知 ACK 對帳增量（隔離 PASS；正式 Sender 仍封閉）**：新增只用 Sender 既有 SELECT
權限的 `reconcile_send()`，不新增 SQL Migration、寫入權限或 HTTP RPC。
真 PostgreSQL 測試在同一 Admission 的尚無 Lease、已提交 Lease、已提交
終態及終態 Audit 插入失敗回滾後逐一查核，還驗證錯 Owner／Receipt／
Fingerprint 只得到 `UNVERIFIABLE`；即使觀察不到 Lease 也不可重起送。
對帳結果只回報 `lease_observed`，不暴露可用於 `finish_send` 的 Lease ID。
另強制核對原 Grant Binding、Admission JSON 的 ID／Fingerprint／Hash／世代／
Candidate Ref／期限與受保護 Snapshot；任何不一致回 `UNVERIFIABLE`。
這只改善故障診斷，不處理跨庫權威、客戶端 ACK、正式服務接線與 Restore。

### D-74 已知 Restore 本機隔離事件（新隔離子項，待本版 CI）

`030_local_known_restore_quarantine.sql` 建立不可更新、不可刪除的
`protected_local_restore_events`；受信任部署 Recorder 以實體獨立 PostgreSQL
登入 `mark_known_restore(uuid4)` 寫入事件，同 UUID 可安全重查，不產生第二
事件。Sender 在原 Admission Row Lock 之後取得本機共享 advisory transaction
lock、檢查此表；Recorder 取得同一鎖的排他型態才能插入事件。**事件已提交後**
的新 Lease 一律拒絕，已存在的原授權與 Snapshot 不更改。若表缺失、無 SELECT
權或 Lock/DB 無法查證則 fail closed。Sender 角色的啟動前 ACL 明確需要
`SELECT` 且禁止 `INSERT`／`UPDATE`／`DELETE`；Recorder 的獨立 Login
只需 `INSERT`，同 ID 使用 `ON CONFLICT DO NOTHING` 查核結果，不需要
`SELECT`／`UPDATE`／`DELETE`。新增真 PostgreSQL `NOINHERIT` SCRAM 兩角色
最小權限與禁止 `SET ROLE` 的隔離測試；正式部署 Secret/ACL 尚未驗收。
首輪測試發現 PostgreSQL 對**指定 Conflict Arbiter** 的寫法還要求額外
讀取權，實體 Recorder 因而 `permission denied`（不是 PASS）；已改為
不指定 Arbiter 的 `ON CONFLICT DO NOTHING`，僅以受保護表唯一主鍵
處理重複事件。此差異必須由下一版真 SCRAM CI 確認，不以純單元測試替代。

**G6 舊版 Sender 混跑隔離（待本版 CI）**：新增
`031_known_restore_lease_db_fence.sql`，不修改既有已套用 Migration。
`protected_send_leases` 的 `BEFORE INSERT` Trigger 在固定資料庫 schema
與相同 advisory transaction lock 下，再查不可變 Restore 事件；存在時
即以 `42501` 拒絕。這讓不認識新 Python 檢查的舊 Sender SQL 也無法在
已知 Restore 後提交新 Lease，前面的 Admission 狀態變更須整筆回滾。
Trigger 缺表時一樣拒絕，不能以 runtime flags 解除。後續追加
`032_known_restore_trigger_privilege_isolation.sql`：將無參數 Trigger 函式
改為 `SECURITY DEFINER`，同時維持 `pg_catalog, trusted_schema, pg_temp`
的固定搜尋路徑與 PUBLIC EXECUTE 撤銷。這讓舊 Sender 即使沒有新事件表
的 SELECT 權，**無 Restore 時仍能通過原本的 Lease INSERT**；已標記
之後仍由 DB 拒絕，且舊程序建立的同名 TEMP 表不能遮蔽真正的隔離事件。
新增真 SCRAM 舊版 SQL 正負與 TEMP Shadow 測試，**待確切 SHA CI 驗收**。
首次混版擴充 CI 在建立第二個 Admission 時，因測試 Helper 重複登記同一
Contract 的 revision=1 而正確報 `registry_revision_not_monotonic`；已讓
連續案例使用不同正式 Contract Hash，沒有放寬 Registry 單調性規則。
此項只涵蓋同一資料庫的**新 Lease**，不攔截先前已起送的網路 bytes、
已知事件遭 DB 還原覆寫、舊程序直接使用未受保護的外部發送通道，
亦不等於 G6 全部混版／正式網路部署已驗收。

此方法**只能偵測由部署控制面明確告知、且事件在目前 World DB 中仍可見的
已知 Restore**。部署流程須先停止受信任入口，完成還原後、任何 Sender
重啟前落盤事件；單靠資料庫內事件無法保證停機時程、不會被後續資料庫還原
覆寫，亦不能識別整台 VM 回滾或阻止已起送的網路 bytes 繼續傳輸。
目前只提供**單向持久隔離**，沒有放行 API、沒有繞過旗標，需另完成本機
驗證與原子 Release、部署 orchestration、角色/競態/故障驗收後才可簽
`SINGLE-NODE-03`。標準單機不宣稱整機快照抗回滾；外部 Fence 仍為選配。

初始唯讀對帳程式 [SHA `8bd5586`](https://github.com/IAN40070510/Mirage_API/commit/8bd5586f7ee7db4e25417ab20dc4b75ff811e566)
在 [隔離 PostgreSQL CI #45541214196](https://github.com/IAN40070510/Mirage_API/actions/runs/45541214196)
通過 `180 passed`，另有真實 mTLS `6 passed`、Anchor 模擬 `9 passed`、
第二套隔離 Fence PostgreSQL `12 passed`；兩組容器 CI `success`。
Admission 完整交叉綁定與故障注入為其後增量，須另看該版 SHA 的 CI，
不將前一版的 PASS 挪用為新測試證據。

下一輪 G6 最小權限增量另在一次性 PostgreSQL cluster 建立獨立
`NOINHERIT`／`NOBYPASSRLS` 的 SCRAM 登入，只授予四個對帳來源表的
`SELECT`，驗證 `reconcile_send()` 正向運作、`StartSend`／Admission `UPDATE`
及 `SET ROLE` 權限提升全部失敗；測試結束 `DROP OWNED`／`DROP ROLE`。
此子項在該版 CI 通過前保持 **PENDING**，亦不代替實際部署最小權限簽收。

另外補強 `start_send()` 的授權前不可變 Admission 交叉檢查：除了 Snapshot
的 Fingerprint／Hash／Candidate Ref／世代與 bytes，還必須確認原始
Admission ID、授權期限、傳輸期限及 Admission 世代與資料庫實體欄位完全
一致。隔離負面測試刻意保留正常 Pin，僅改 Admission JSON 的這些欄位；
任何差異都必須在建立 Lease／`SEND_STARTED` 前拒絕。**須另以包含該修補的
確切 SHA CI 驗收**，不可沿用舊版 Sender 證據。

套件與授權：僅使用專案既有 `psycopg`、Starlette／ASGI、Python 標準庫與
PostgreSQL 17；未加入新模型／商用外部服務。依賴授權沿用專案既有清單。

## 2026-11-24 Lease 回傳綁定補強：固定版本證據

修補程式 SHA [`1eee81ed4648e6ceee4d61b40aa5db15cd0d14cd`](https://github.com/IAN40070510/Mirage_API/commit/1eee81ed4648e6ceee4d61b40aa5db15cd0d14cd)。
先新增 ASGI 負面測試，實測「回傳 Deadline 較短」在修補前未被拒絕；
加入回傳 Lease UUIDv4／Deadline 精確比對後，同一案例與非法 UUID 均拒絕，
首筆 `http.response.start`／body 未輸出。正常 Lease、原有錯 Receipt／
Payload 與未知 ACK 單次毒化測試仍通過。

- 本地：G4／Protected Services／Operation Binding／Anchor／mTLS 聚焦
  `130 passed / 5 skipped`；五項未設 `MIRAGE_POSTGRES_TEST_DSN`，不是 PASS。
  `tools/check_documentation.py` PASS（1951 functions、71 guides），`git diff --check` PASS。
- [真 PostgreSQL 17.6 受保護合約 CI 45402191600](https://github.com/IAN40070510/Mirage_API/actions/runs/45402191600)：
  `166 passed`，另跑實體 mTLS `5 passed`、G5 Anchor 密碼學模擬 `9 passed`。
- [Python CI 45402191237](https://github.com/IAN40070510/Mirage_API/actions/runs/45402191237)：
  `1449 passed / 21 skipped / 2 warnings`。
- [容器示範 CI 45402191268](https://github.com/IAN40070510/Mirage_API/actions/runs/45402191268)：`success`。

上述證據只能簽收「G4 Lease 回傳欄位的 ASGI 前置完整性防護」子項。
CI 中的 PostgreSQL 不是部署環境的獨立 Sender 登入驗收；G5 獨立 Restore
Fence、真實 Sender 對外 ASGI、跨 DB 故障注入、G6 及最終 Owner Release
仍 **OPEN／NO-GO**，Trusted Send 保持 **OFF**。

## 2026-11-25 Snapshot Purge Fence 隔離子項證據（同 DB 邊界 PASS）

`029_protected_snapshot_purge_fences.sql` 為同一不可變 Snapshot 建立**獨立
不可逆執行資格 Fence**，不改 `SEND_AUTHORIZED` 原授權歷史、保留原始
Envelope bytes 與 Hash。`PostgresProtectedSnapshotPurger` 僅用專用 GC
Login 及 UUIDv4 `gc_operation_id` 插入；原操作 ID 可查既有記錄，其他
ID／Reason 不可重綁。資料庫 Trigger 先鎖同一 Admission，再核對活躍／未知
Send Lease；活躍 Sender 不得被 GC 切斷所需的 Pin。

Sender 必須先取得 `response_admissions FOR UPDATE`，**在另一條 SQL**
讀取是否已有 Purge Fence，才可起送。這個 Read Committed 邊界用來防止
「原本 SELECT 的 MVCC Snapshot 早於競爭 GC Commit」，不是在授權後
重新判斷 Policy／Emergency。Fence 及 Lease 的競爭須保證只允許一方先
提交；原 Snapshot、授權 Audit 及不可重送歷史皆留存。所有正式 Sender
入口和 Runtime 對 GC Fence 的 DML 必須保持拒絕。

此增量只覆蓋同一 PG 的執行資格 Fence，**不**負責已物理刪除的外部 Blob、
GC 故障／跨 DB 恢復、Purge Retention、G5 外部 Quarantine／Head、真實
低權限 GC 角色與正式 Sender 網路隔離。資料庫原 BYTEA 尚在；不能把
Fence INSERT 當作 Object GC 完成或 G4／G5 Release PASS。

- 固定修補 Commit [`f626f45`](https://github.com/IAN40070510/Mirage_API/commit/f626f45f7c191026a7088c2319ff3027c8ae845f)、[PG17.6 #45488811957](https://github.com/IAN40070510/Mirage_API/actions/runs/45488811957) `success`：真 PG `172 passed`，包含先 Fence 阻止 Start、Active/Unknown Lease 禁止清理、終態後保留 Lease 可 Fence、兩方並行只能一方提交、不可改寫 Fence；獨立 mTLS `5 passed`、G5 模擬 `9 passed`、隔離 Fence `7 passed`。
- [容器示範 #45488812056](https://github.com/IAN40070510/Mirage_API/actions/runs/45488812056) `success`；文件檢查 `1961 functions／69 guides` PASS。
- 以上只簽收**同一 PostgreSQL 的 Purge Fence／StartSend 競態指定子項**；正式 Role／GC／Object Pin／Restore／混版未通過，Trusted Send 繼續 **OFF**。
