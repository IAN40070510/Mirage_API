# G4：受保護 Send Lease／ASGI Pin（增量，正式傳送仍封閉）

## 用途與安全邊界

`src/deception/world/protected_send.py` 建立獨立 Sender 才可使用的原子
`StartSendTx`。`PostgresProtectedAuthorizer` 必須事先在同一 PostgreSQL 交易
完成 `SEND_AUTHORIZED` 與 `protected_authorized_http_snapshots` 不可變 HTTP
Envelope Pin。後續 Sender 使用**另一個實體資料庫 Login**，只檢查原 Pin 的
Receipt、完整 scope／candidate、Owner、Request Fingerprint、實際 Envelope
bytes、DB Deadline 與一次性狀態。依 MSDSS Freeze v1，不重查事後發生的
Policy／Key／Emergency 撤銷；它們的最終授權判定點是較早的
`SEND_AUTHORIZED COMMIT`。

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
驗收尚未完成；沒有外部權威 Fence 時，此 Primitive 不得啟用到外界。

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
