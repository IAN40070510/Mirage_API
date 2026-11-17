# 固定安全錯誤 Renderer

## 用途與邊界

`SecurityErrorRenderer` 為 pipeline 的固定 503／409 錯誤提供獨立、可在 World／Registry／Replay 不可用時運作的最終驗證。它只建立 `SecurityErrorSource`，不讀取私人世界、不查 DB、不呼叫模型，也不核准商品或任意候選回應。

商品回應仍使用原本的 OfficialResponseGate、ResponseRenderer 與 ResponseAdmission。固定安全錯誤使用內建、版本固定的兩個模板，核對 status、headers、精確 body bytes、來源及原請求，並在 ASGI 送出前重驗；不把 503 偽裝成權威 Medusa 404。框架在 handler 前產生的格式／大小限制錯誤，以及一般未接線展示 handler，不屬於此工具的 503／409 模板。

## 輸入與輸出

`render(request, not_applicable=False)` 接受入口已正規化的 NormalizedRequest 與真正 bool 的模板選項。回傳封存的 SecurityErrorResponse；無法驗證時拋出只含固定碼的 SecurityErrorRenderingError。

| 模板 | status／body | SecurityErrorSource |
| --- | --- | --- |
| 一般不可用 | 503；code=pipeline_unavailable、request_id | safe-unavailable，revision=1 |
| 不適用 | 409；code=pipeline_not_applicable、request_id | safe-not-applicable，revision=1 |

標頭固定為本次 x-request-id、精確表示 bytes 的 content-length 與 application/json。GET 等方法的 bytes／headers 保持原 JSONResponse 的固定格式；HEAD 不發 body，但保留對應表示的 Content-Length。TRACE 只回固定錯誤，不反射請求本文。沒有自訂 status、模板本文、cookie、私人欄位或 background callback 的輸入介面。

## 設定與範例

不需環境變數或 migration。`api.pipeline._unavailable` 自動呼叫這個 Renderer；`api.app` 直接接受已驗證封套，不能再補改 header。

```python
from deception.core.security_error import SecurityErrorRenderer

response = SecurityErrorRenderer().render(normalized_request)
response.assert_request(normalized_request)
```

`normalized_request` 必須由入口產生，request_id 只接受原既有 ASCII 格式。此介面不能把 Client 提供的任意 JSON 當模板。

## 各節點白話功能

| 節點 | 功能 |
| --- | --- |
| 內建固定模板 | 決定唯一允許的 status、欄位與來源版本，沒有商品資料。 |
| 完整原請求綁定 | 將原始 URL、path、query、headers、body 摘要與 request ID 一起綁住；不能借用另一請求的錯誤回應。 |
| SecurityErrorResponse | 封存實際傳輸 bytes／headers，起送前檢查改寫、背景工作及期限。 |
| API 入口 | 核對回應屬於本次請求後原樣交回，不在最後偷偷加欄位。 |

此綁定是本機安全錯誤的內部摘要，不改變 Gateway／JWS 的 fingerprint v1。它保留重複標頭，因此重複 Authorization 導致一般 fingerprint 拒絕時，仍可對原請求產生綁定的安全錯誤。原請求會短暫保留於記憶體供送出前核對；Token、本文、摘要及底層例外不加入回覆、日誌或資料庫。

## 失敗處理

status、headers、body、SecurityErrorSource、背景工作、封存 payload 或期限被改寫時，ASGI start 前拒絕。實際 scope 的 method、authority、path、raw path、query 與原始 headers 也須一致。原請求資料改變後不能通過 assert_request。

每份回應有五秒同程序 monotonic 發送期限，相等即拒絕；send 受到剩餘期限限制，逾時或取消原樣向上傳遞。若已起送後才出錯，不重新生成、不發第二份候選，也不回退真實 Backend。故障停止發送不代表已追回送出的 bytes。這個獨立錯誤路徑不建立 World／Synthetic Admission，也不偽造成功的 World 或傳輸稽核；可信 handler 的拒絕紀錄仍由[入口稽核](ingress-audit.md)另行處理。

## 驗證方式

```powershell
python -m pytest tests/test_security_error_renderer.py tests/test_renderer.py tests/test_generic_pipeline.py tests/test_golden_vectors.py -q
python tools/check_documentation.py
```

案例直接收集 ASGI 訊息，確認改寫／錯配時 start 前零輸出，固定模板與舊 bytes 完全相同，資料庫全部拒絕連線時仍能回覆。另驗 HEAD、TRACE、重複憑證標頭、期限相等及實際 API 入口。可信 HTTP／Gateway、scope 一致性與隔離映像需各自設定專用環境重驗；結果見[進度](implementation-progress.md)，不把隔離副本結果當原工作樹已通過。

## 授權與限制

自有程式 Apache-2.0，沿用 Python、Starlette、Pydantic 與既有來源型別，沒有新套件、模型或第三方實作，詳見[授權表](licensing.md)。目前只接受內建 503／409 與列明方法，不提供管理者自訂模板、跨程序重用回應、獨立發送稽核平台或框架所有 4xx／5xx 的統一模板。不能由固定安全錯誤通過推論商品契約或 Protocol v1.1 已全面符合。
