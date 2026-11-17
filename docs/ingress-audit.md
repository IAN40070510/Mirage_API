# 可信 HTTP 入口拒絕稽核

## 用途與邊界

`PostgresIngressAudit` 保存已到達 Mirage trusted HTTP handler 的拒絕事件，涵蓋驗章、資源綁定、世界解析、讀取准入與回應 pipeline。它不要求先建立世界或 Admission，解決先前驗章及 scope 錯配只有固定 503、沒有共用持久紀錄的缺口。

這份紀錄不是 `response_audit` 的替代品；後者保存已有發送准入的傳輸事實。框架在 handler 前拒絕的格式／大小錯誤、健康與展示管理路由、ASGI 起送後故障不屬於本工具範圍。尚無集中日誌平台、管理 HTTP 匯出、保留排程或完整防竄改儲存。

## 輸入與輸出

建構子只接受部署設定的 DSN、environment_id、deployment_id。`record_refusal(stage=..., reason=...)` 只接受下列固定分類；無效分類在連線前拋出 ValueError。成功提交回傳新的伺服器 UUID，資料庫自動保存時間。不存在接收 request、Token 或例外文字的參數。

| 欄位 | 允許內容 |
| --- | --- |
| stage | trusted_ingress、resource_binding、world_resolve、read_admission、response_pipeline |
| reason | unavailable、read_only_policy、authorization_expired、resource_scope_mismatch |
| event_id | 伺服器每次新產生的 UUID v4，不採 Client request_id。 |
| environment_id／deployment_id | 啟動時已驗證的固定部署範圍，不採未驗證 claims。 |
| recorded_at | PostgreSQL 寫入時的時間，不採請求時間。 |

`unavailable` 是該階段無法安全完成的固定分類，不代表已判定某個特定攻擊。未保存 Token、kid、JTI、Session／cart／order ID、Client request_id、指紋、IP、UA、Cookie、路徑、query、本文或底層錯誤。好處是降低憑證與攻擊內容外洩；代價是不能用這張表還原原始請求或直接對照客戶提供的 request_id，只能依時間、部署與階段觀察。

## 設定與使用範例

稽核資料表由 migration 013 建立；目前完整可信入口另須套用至 014 的 key 墓碑，再啟動服務。此服務使用同一 Mirage 專用 DSN 自動建立 sink，不修改外部 Gateway。不是所有 HTTP 流量都導入這張表；只有上述 handler 的拒絕才寫入。

```python
from deception.security.ingress_audit import PostgresIngressAudit

audit = PostgresIngressAudit(dsn, environment_id="isolated-demo", deployment_id="isolated-demo")
event_id = audit.record_refusal(stage="trusted_ingress", reason="unavailable")
```

管理者可在 Mirage 專用 DB 唯讀統計，不需要對外公開查詢介面：

```sql
SELECT environment_id, deployment_id, stage, reason, count(*)
FROM ingress_refusal_audit
GROUP BY environment_id, deployment_id, stage, reason;
```

## 各節點白話功能

| 節點 | 功能 |
| --- | --- |
| trusted HTTP handler | 追蹤目前安全邊界；拒絕時呼叫一次固定分類，不傳訪客資料。 |
| PostgresIngressAudit | 開獨立交易寫入事件，只有提交成功才回傳 UUID，不重試未知結果。 |
| ingress_refusal_audit | 跨程序保存事件，不依賴世界或發送 Admission 存在。 |
| 固定故障告警 | 稽核無法保存時輸出 mirage_ingress_audit_unavailable 與固定階段，不輸出例外堆疊或 DSN。 |

## 失敗處理

連線期限為 5 秒、statement_timeout 為 5 秒；不是整個 HTTP 請求的總期限。缺少 migration、寫入失敗或 COMMIT 回覆未知都向呼叫端拋錯，不自動重試。入口即使無法稽核仍維持拒絕，不回退真實商店，不建立替代世界。只輸出固定告警；告警代表持久紀錄可能缺失，不能算完整稽核已成功。已提交但回覆遺失時可能已有一筆事件，因此不能假稱沒有寫入。

事件不參與 WorldEvent、Replay 或業務交易，不宣稱兩者原子提交。每次拒絕各有新事件；重放請求會新增拒絕紀錄，但不重放業務。Client 回應維持既有固定安全錯誤，不加入事件 ID 或內部分類。回應 pipeline 回傳的固定 503 也會記錄；已起送後的失敗由原傳輸稽核處理。

## 驗證方式

```powershell
python -m pytest tests/test_ingress_audit.py -q
python tools/check_documentation.py
```

PostgreSQL 與雙 TLS 程序案例須設定專用 MIRAGE_POSTGRES_TEST_DSN，並具備現有本機 MSDSS checkout 與 openssl。未設定造成的 skip 不算通過。測試包含新連線讀回、正常請求零拒絕事件、不同程序的驗章與資源錯配事件、回應 bytes 一致、世界及准入筆數不變，以及機密 canary 不出現在 DB／故障告警。

另以真正簽章並消費 Replay 的請求，在世界解析與讀取准入注入故障，核對實際階段；內層 pipeline 不拋錯而直接回固定 503 時也須保存。這些故障是隔離測試注入，不是生產故障的證明。

## 授權與限制

自有程式採 Apache-2.0，沿用 psycopg、PostgreSQL 與 Python logging，沒有新模型或第三方實作，詳見[授權表](licensing.md)。目前是應用程式只新增的紀錄，DB owner 仍可改寫資料，不能宣稱防竄改。大量拒絕會增加資料庫連線、儲存及延遲；正式部署仍需限流、保留政策、容量與告警接收設定。這些部署措施未由本工具自動啟用，也不修改 MSDSS 其他模組。
