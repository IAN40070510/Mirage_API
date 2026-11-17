# 合成庫存預留與取消

## 用途與邊界

`SyntheticInventory` 只操作 Mirage PostgreSQL 中的合成 World。預留與取消依當前 SessionBinding、epoch、世代與版本提交，並在同一交易保存結果及 WorldEvent。它不呼叫 Medusa 庫存或付款介面。

內部服務及明確啟用的合成 HTTP 入口均已提供；商品 HTTP 展示仍為唯讀。事件交易使用[共用提交核心](commit-results.md)，既有 reserve／cancel 的 InventoryResult 與例外介面保留相容性；需要五類標準結果時使用 commit_event。

## 輸入輸出與範例

依序套用 migrations 下的 001 到 015 SQL，使用部署者提供的隔離 DSN：

```python
from uuid import uuid4
from deception.domains.ecommerce.inventory import SyntheticInventory
from deception.world.session import SessionBinding

# binding 必須來自可信身份驗證，不能直接使用訪客 header。
binding = SessionBinding(environment_id="lab", deployment_id="test", session_id="trusted-session", session_epoch=1,
                         access_mode="inventory")
inventory = SyntheticInventory(deployment_dsn)
snapshot = inventory.resolve(binding, {"inventory": {"SYN-SKU": 2}, "reservations": {}}, now=100, ttl=3600)
attempt = uuid4()  # 呼叫端在送出前保存，失去回應後用來查詢。
result = inventory.reserve(binding, sku="SYN-SKU", quantity=1, expected_version=1,
                           idempotency_key="reserve-001", commit_attempt_id=attempt, now=101)
cancelled = inventory.cancel(binding, reservation_id=result.result["reservation_id"], expected_version=2,
                             idempotency_key="cancel-001", commit_attempt_id=uuid4(), now=102)
```

`InventoryResult` 包含 committed／rejected、業務結果、狀態版本、hash 與原提交 ID。重用相同業務鍵及內容時，`replayed=True` 並回傳原提交結果。expected_version 與新的 attempt ID 不納入業務內容摘要，因此重試可沿用原業務鍵而不重複執行。業務鍵的範圍包含 WorldScope 與 operation。

## 失敗與恢復

未知 SKU、庫存不足及非有效預留會保存 rejected 結果，版本與庫存保持原值。相同業務鍵對應不同內容時拒絕。並行操作持有快照與 Session 映射鎖，版本落後回報 version_conflict。

舊 epoch、封存、緊急撤銷或世界過期時停止。提交結果未知時不能推定操作未發生。重新確認可信 binding 後呼叫 `operation_result(binding, attempt, now=...)`，唯讀查詢該當前世界的結果；找不到回傳 None，不能據此盲目提交。舊世代歷史查詢尚需獨立 Capability，不由此介面提供。

每次成功預留／取消同時保存快照、world_operations、world_events、world_commit_receipts 與 Watermark。拒絕的業務結果不產生庫存事件。WorldEvent 僅保存摘要，不保存原始憑證或請求內容。

## 驗證方式

本機設定 MIRAGE_POSTGRES_TEST_DSN 指向專用資料庫，再執行：

```powershell
python -m pytest tests/test_inventory_events.py -q
python tools/check_documentation.py
```

測試在本機執行；遠端模式由 SSH 主機的隔離 PostgreSQL 執行交易。驗證冪等預留、取消、雙 Instance CAS、不超賣、epoch／撤銷／到期，以及提交後失去回覆的查詢與單次事件。

## 授權與限制

自有模組採 Apache-2.0，沿用 psycopg 與 PostgreSQL，授權詳見 [共用授權文件](licensing.md)。未採用其他開源庫存系統的程式碼、模型或真實資料。`inventory_http.py` 已提供明確合成路由，由 `trusted_http.create_app(enable_business=True)` 啟用，仍須可信簽章與寫入權限；匿名 IP／UA 唯讀分組不能直接預留。訪客購物車與下單見[購物車文件](carts.md)。尚未提供預留自動逾時釋放、真實付款或跨世界移轉；正式部署核准另由整合層設定。

新版可信 HTTP 另需 migration 016 保存[請求 Audit](request-audit.md)；前面的 001–015 是直接庫存事件服務的需求，不能當作目前 HTTP 入口的完整 schema。
