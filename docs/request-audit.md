# 請求觀察與回應驗證 Audit

## 用途與邊界

`PostgresRequestAudit` 將已驗證請求的摘要、讀取基底與最終回應准入連成持久證據。`request_observations` 保存 `request_observed`，`request_observation_results` 保存已准入或無法確認；正向結果與 ResponseAdmission 在同一 PostgreSQL 交易。後續發送嘗試／完成仍由 `response_audit` 關聯相同 admission_id，完成不代表 Client 已收到。

這些是觀察事件，不是商品或庫存 WorldEvent。GET 不改業務狀態，但可新增觀察與發送稽核。元件不暴露 WorldStore 的世界寫入方法，不讀取 Medusa 身份服務、真實資料或模型。

## 輸入與輸出

`RequestObservation.from_snapshot()` 只擷取重新核對過 hash 的快照 scope、版本與 hash，另需三個 SHA-256：request_id_digest、trusted_context_digest、request_binding_digest。observation_id 為伺服器 UUIDv4。模型不可變、拒絕額外欄位，複製更新也重驗；DTO 本身不是授權證明。

可信 HTTP 在驗章、Replay、資源綁定、世界解析及 ReadAdmission 後，從本次已驗證 claims 及 request ID 計算摘要。Context 摘要涵蓋 claims 的固定排序緊湊 UTF-8 JSON；request ID 使用 UTF-8 SHA-256。資料表不接受原始 Token、Authorization、Cookie、路徑、請求本文、模型上下文或任意文字理由。前置拒絕維持[入口拒絕稽核](ingress-audit.md)的最小分類，不為未驗證資料建立可查的私人世界紀錄。

`RequestAuditLink` 由可信最終 Renderer 提供：包含已保存觀察、最終來源 scope，以及明確的 Domain／Contract `passed`。基底與目標可為不同 Session／世代，但環境與部署必須相同；建立訪客購物車會由匿名 catalog 世界進入新 cart 世界，不能把兩者混成同一基底。初始化具有自己的版本 1 收據時，可正確記錄 committed version=1，不等同產生庫存變更事件。

| 保存節點 | 白話功能 |
| --- | --- |
| request_observed | 記錄哪筆已驗證請求、哪份可信上下文與哪個基底版本開始處理；不宣稱業務成功。 |
| 最終驗證與 Grant | 兩項檢查通過後，將契約、候選 hash、來源世界與可選 committed version／hash 原子連到一次性准入。 |
| 無法確認的後段停止 | 保存固定 `unverifiable`，不猜測哪個內部步驟已提交，不覆寫可能已提交的正向 Grant 關聯。 |
| response_audit | 以 admission_id 關聯精確 final hash、起送、嘗試與 ASGI 終態，不複製候選本文。 |

通過回應驗證不等於業務提交成功。合法的合成 400／409 可引用 SecurityErrorSource，仍保存驗證與准入關聯，但 committed version／hash 必須為空；這與驗章、DB 等必要來源故障時不建立 Synthetic Grant 的固定安全錯誤路徑不同，不能把業務拒絕改成 503 或捏造快照證據。

## 設定與使用

先依序套用 migrations 至 `016_request_observations.sql`。新版可信 HTTP 自動接線，不另新增放寬開關，也不改 staging。直接使用的內部範例：

```python
from deception.world.request_audit import PostgresRequestAudit, RequestObservation

# 三個摘要及 snapshot 都來自已驗證的本次請求，不能轉抄 Client 自填欄位。
audit = PostgresRequestAudit(deployment_dsn)
observation = RequestObservation.from_snapshot(
    verified_snapshot,
    request_id_digest=request_id_sha256,
    trusted_context_digest=verified_claims_sha256,
    request_binding_digest=verified_request_fingerprint,
)
audit.begin(observation)
```

可信 HTTP 的 Renderer 在最後核對完成後，將 `RequestAuditLink` 傳給 `PostgresAdmissionControl.grant(request_audit=...)`。Grant 使用同一 cursor，重新核對完整已保存觀察及 request fingerprint／世代，再保存正向結果。舊控制面原型呼叫可省略此參數；不能由此推論該原型已有完整請求 Audit，正式可信 HTTP 一律提供。

查核使用受控 SQL，依 request ID 摘要找到 observation_id，再經結果與 admission_id 連到 response_admissions／response_audit。不可把完整 CandidateStore bytes 當作公開稽核匯出；摘要不是授權，知道 request ID 或 observation ID 不授予任何世界或歷史結果讀取權。

## 失敗與恢復

觀察寫入只嘗試一次，失敗立即停止，尚不進入業務。最終 Grant 的 Audit 保存失敗會回滾該張准入及控制 revision，拒絕發送；**此時業務事件可能早已提交**，不能把 HTTP 503 當作庫存已回滾，應依原業務鍵／attempt 做[唯讀恢復](commit-results.md)。

Grant 的 COMMIT 回覆遺失時不重新核發。若正向 Audit 與准入已提交，後段的 `close_unverifiable()` 不覆寫它；若未知分類先提交，後來使用相同觀察的 Grant 會回滾。任何其他摘要搭配已知 observation ID 都不能關閉或挪用另一請求。稽核來源也故障時仍拒絕，只輸出固定告警，不回顯例外或私人內容。

只見 request_observed 而無結果表示處理結果尚無完整證據，不能推定業務未提交或已完成。一般未知停止記錄 Domain／Contract `unverifiable`，不捏造 `passed`；正向兩項通過只在可信 Renderer 路徑成立。傳輸結果以既有 ASGI Audit 為準，沒有發送事件不等於對端收到與否的證明。

## 驗證方式

```powershell
python -m pytest tests/test_request_audit.py tests/test_request_audit_http.py -q
python tools/check_documentation.py
```

需設定專用 `MIRAGE_POSTGRES_TEST_DSN`；舊版跨倉 HTTP 驗收依賴已移交外部消費端；本倉庫原生 HTTP 驗收無需外部檢出。未配置 skip 不算通過。Windows 執行 pytest、JWS、ASGI 與 TCP 故障代理；SSH Ubuntu 只執行隔離 PostgreSQL。測試包括真實 SQL 約束故障、整張 Grant 回滾、COMMIT 回覆遺失、跨世界初始化、原始內容 canary 與業務可能已提交的拒絕路徑。試作與實際套回的證據需分開記錄於[進度](implementation-progress.md)。

停止與 Grant 的並行案例使用不同 PostgreSQL backend，先以 pg_blocking_pids 確認第二交易真的等待第一個結果鍵，再提交第一交易。Grant 先提交則未知停止不覆寫；停止先提交則等待中的 Grant 回滾。這是實際交易排序，不是兩個 OS 程序或 HTTP 傳輸證明。

## 授權與限制

自有程式與 migration 採 Apache-2.0，沿用 Pydantic、psycopg 與 PostgreSQL，不引入模型或新套件。依賴詳見[授權表](licensing.md)。目前沒有公開 Audit 查詢 API、跨系統匯出、保留／清理管理器、MAC 防惡意 DBA、既有歷史回補或前置拒絕的完整私人關聯。固定摘要也不是去識別的絕對保證，須限制資料庫與鑑識存取。未提供集中監控不會將未保存稽核當作成功。
