# 已驗證候選的 HTTP 回送

## 功能與邊界

`src/deception/core/renderer.py` 把任務協調器的已驗證內部候選轉為真正的 FastAPI／Starlette Response。HTTP 回送器先完成本次 `X-Request-ID` 與精確 UTF-8 `Content-Length`，再將最終 status、headers、body 連同實際請求 URL 交給契約驗證器；只回送本次通過驗證的 bytes。

這完成「內部候選 → 應用程式 HTTP 回應」的邊界，不會替部署核准來源，也不會把合成測試規格當成官方平台相容性證明。未審來源、錯誤網站／query、錯誤 operation 及未通過契約驗證器的內容仍無法回送。

## 現成專案評估與選擇

| 專案／介面 | 能力 | 本次採用方式 |
| --- | --- | --- |
| [FastAPI 直接回傳 Response](https://fastapi.tiangolo.com/advanced/response-directly/) | 直接使用明確 Response，不再套用 JSON 序列化 | 沿用既有依賴，回送回應組合器的 UTF-8 bytes |
| [Starlette Response](https://www.starlette.io/responses/) | 提供 ASGI response 與 raw headers | 沿用既有依賴；將傳輸標頭納入驗證，送出前檢查內容未改 |
| [既有契約驗證器 gate](gate.md) | 依實際 URL 與固定網站契約驗證候選 | 對最終候選重新驗證，不只信任舊的 `GateResult` |

Starlette 一般建構流程會自動補 `Content-Length`，並可能依 media type 補 `Content-Type`。HTTP 回送器明確處理最終 headers 與 bytes，避免在契約驗證器檢查後出現應用程式額外改寫；沒有新增回送框架或第三方依賴。

## 輸入與輸出

`ResponseRenderer(gate).render(result, request)` 接收：

| 輸入 | 必須滿足的條件 |
| --- | --- |
| `result` | 任務協調器的 `PipelineResult`，判定為 `validated`，且含本次候選、契約驗證器結果及有效發布期限 |
| `request` | HTTP 請求入口的原始 `NormalizedRequest`，與 trace 中的 request ID、請求指紋及候選關聯一致 |
| `gate` | 管理者建立的契約驗證器工具，使用核對後的固定部署契約 |

HTTP 回送器另核對候選摘要及 method。即使先前的 `gate_result` 顯示通過，仍須以最終候選和本次 `request.raw_url` 重跑 `verify_candidate()`；相同 schema 的其他 operation 不能代替。`trace.release_deadline_monotonic` 是任務協調器提供的必要欄位，表示同一程序單調時鐘上的最晚發布時間，取本次情境選擇工具判定與任務協調器總預算較早到期者。HTTP 回送器在最終契約驗證器驗證前後與送出 ASGI start 前再次核對；不能因最後驗證耗時或延後傳送而使用過期判定。

此期限僅適用於同一執行程序的即時交接。`PipelineResult` 或 trace 不可持久化後重放、跨程序或跨主機重用作為回送許可；保存的報告只供追溯，重新請求必須重新執行任務協調器/情境選擇工具/契約驗證器。

成功回傳 `ValidatedHTTPResponse`。它保存完整 body bytes 與 raw headers，發出 ASGI `http.response.start` 前檢查 status、body、headers 及背景工作沒有被更動，並核對 ASGI 請求的 method、URL、path、query 與 headers。這是應用程式的完整性檢查，不是供不受信任 Python 程式使用的簽章或權限系統。

```python
from deception.core.renderer import ResponseRenderer

renderer = ResponseRenderer(gate)
# result 由任務協調器產生，request 是 HTTP 請求入口傳入同一 handler 的原始快照。
response = renderer.render(result, request)
```

| API | 功能與失敗方式 |
| --- | --- |
| `ResponseRenderer(gate)` | 使用伺服器注入的契約驗證器，不依訪客或候選選驗證器 |
| `render(result, request)` | 核對內部結果、完成最終 headers、重新執行契約驗證；失敗拋 `RenderingError` |
| `response.assert_request(request)` | 供 HTTP 請求入口回傳前核對原請求與封存狀態 |
| `await response(scope, receive, send)` | 核對封存內容及 ASGI 請求後，只發出原樣 start/body 訊息 |
| `RenderingError.code` | 固定診斷碼，不包含原請求、body、憑證或底層例外內容 |

## HTTP 標頭與支援範圍

HTTP 回送器以本次 HTTP 請求入口追蹤 ID 完成 `X-Request-ID`，以 `len(candidate.body_bytes)` 決定 `Content-Length`，保留已核對的 JSON `Content-Type`。候選若已提供 ID 或長度，必須與本次值相同，不能靜默覆寫錯誤值。body 不重新解析、補值或序列化，因此中文等非 ASCII 字元的長度按 UTF-8 bytes 計算。

重複 header 名稱、無效名稱、控制字元、無法編碼的 header、錯誤 length、`Transfer-Encoding`、壓縮或 hop-by-hop 設定都不能成為可回送候選。目前支援與回應組合與契約驗證一致的 JSON body 及單值 headers；不支援多值 `Set-Cookie`、streaming、壓縮、HEAD、204／205／304 等無 body 情境。

HTTP 請求入口對 `ValidatedHTTPResponse` 不再於驗證後附加追蹤 header；一般診斷 Response 仍沿用 HTTP 請求入口的追蹤處理。HTTP 回送器的失敗是固定診斷，不回送原始內部候選、trace、例外或模型提示。

## 可選的 HTTP 請求入口 → 任務協調器 → HTTP 回送器接入

`src/deception/api/pipeline.py` 提供 `make_pipeline_handler()` 與 `create_app()`。管理者明確注入已建立的協調器、runtime、合成資料工具設定／快照，以及可信的 `assessment_provider`。provider 可以是同步或非同步 callable，負責取得接收層已完成來源認證的判定；工具不會從訪客 header 或 JSON 自行取得可信 verdict。

```python
from deception.api.pipeline import create_app

# 這些物件由部署程式依已審查設定建立。
# assessment_provider 必須是伺服器自己的認證整合，不能直接回傳訪客輸入。
app = create_app(
    orchestrator=pipeline,
    runtime=trusted_runtime,
    generation_config=checked_e_config,
    dataset=checked_e_dataset,
    assessment_provider=assessment_provider,
)
```

上述程式放在自己的 `deployment.py` 後，可從專案根目錄啟動：

```powershell
$env:PYTHONPATH = "$PWD/src"
.\.venv\Scripts\python.exe -m uvicorn deployment:app --host 127.0.0.1 --port 8001 --no-proxy-headers --no-server-header --no-date-header
```

範例中的工具、政策、部署身份及 provider 都須由呼叫端提供；repo 沒有自動信任任意遠端判定的公開接收 API。預設 `deception.api.app:app` 仍回 501，僅平台識別 handler 也維持診斷用途；只有明確使用完整接入才會執行生成與回送。

`not_applicable` 回 409，不能當成自動代理轉送；handler 內取得判定、生成或 `renderer.render()` 失敗時回固定 503 診斷。這些服務診斷不是模擬平台的商品回應，也不宣稱通過平台契約。取消仍向外傳遞，不繼續生成或備援。

handler 交還框架後，`ValidatedHTTPResponse.__call__()` 若發現驗證後變更、請求不符或回送期限已過，會在發出 ASGI start 之前拋出 `RenderingError`，不送出候選。此時錯誤回應由框架／伺服器處理，不能保證一定是上述 503。

`create_app()` 與 `make_pipeline_handler()` 另可注入 `renderer`、`now` 及 `allow_unreviewed`；後兩者供明確管理的離線預覽／測試使用，正式預設為即時時鐘與 `False`，訪客不能用 HTTP 欄位啟用。自訂 renderer 是受信任部署程式的擴充點；要維持本工具的最後驗證保證，應保留 `ResponseRenderer`。`create_app(max_body_bytes=...)` 沿用 HTTP 請求入口的實際 body bytes 大小限制。

`assessment_timeout_seconds` 限制取得可信判定的等待時間，預設 15 秒，只接受有限數值 `0 < value <= 120`，不接受布林值。非同步 provider 等待逾期回固定 503，沒有可信判定就不執行任務協調器。

## 生命週期與部署界線

模型 backend、內容快取及其他工具由建立它們的部署程式管理關閉；HTTP 回送器不另外啟動模型、連線原商店或建立背景工作。修正與備援工具備援成功也必須走相同的 HTTP 回送器最終驗證流程。判定 provider 在任務協調器的 `RunBudget` 建立前執行，使用獨立的 `assessment_timeout_seconds`。同步 provider 必須避免阻塞事件迴圈；非同步 timeout 無法在任意同步函式中途強制中斷，外部服務整合仍應設定自己的連線與讀取期限。

HTTP 回送器保證的是應用程式交給 ASGI server 的 status、body bytes 與應用 headers。啟用會改寫回應的 GZip、CORS、安全標頭 middleware 或代理之後，線上封包可能另有 header／編碼變更；須把這些處理移到最終驗證之前或另設明確驗證邊界。範例停用 Uvicorn 自動 `Server`／`Date` headers；HTTP/2 framing、連線管理與代理的傳輸行為仍由實際部署負責。

## 有效性驗證

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_renderer.py tests/test_pipeline_api.py tests/test_nm_integration.py tests/test_ingress.py -q
.\.venv\Scripts\python.exe tools/check_documentation.py
```

測試應比對真正送出的 status、body bytes 與全部應用 headers 和最後送契約驗證器的內容，並涵蓋 UTF-8 長度、驗證後變更、另一請求／URL／query／operation、舊 gate pass、非法傳輸設定、可信 provider 接入與不洩漏內部錯誤。TestClient 的合成規格結果確認模組邊界，不代表已完成 OCI 部署、真實網路代理或官方服務對照。

2026-11-09 完整回歸已取得 **546 項通過**。`test_nm_integration.py` 實際經 FastAPI 接入，比對中文備援回應的 status、完整 UTF-8 bytes 與全部應用 headers，確認與 HTTP 回送器最後送給契約驗證器的封套一致；provider 逾期與 HTTP 回送器回送期限亦有失敗分支驗證。詳見 [修正與備援工具的本次驗證](recovery.md#驗證方式)。

## 使用的套件與授權

| 使用元件 | 授權 | 用途 |
| --- | --- | --- |
| [FastAPI](https://github.com/fastapi/fastapi/blob/master/LICENSE) | MIT | HTTP app 及直接 Response 回傳 |
| [Starlette](https://github.com/Kludex/starlette/blob/main/LICENSE.md) | BSD-3-Clause | Response、ASGI 回送與 raw headers |
| [Pydantic](https://github.com/pydantic/pydantic/blob/main/LICENSE) | MIT | 沿用任務協調器/契約驗證器的型別化輸入與結果 |
| [openapi-core 0.19.5](https://github.com/python-openapi/openapi-core/blob/0.19.5/LICENSE) | BSD-3-Clause | 透過既有契約驗證器核對最終候選 |
| Python 標準庫 | PSF 及隨附聲明 | 不可變資料、摘要、編碼與函式整合等支援 |

啟動命令沿用既有 Uvicorn（BSD-3-Clause）；測試沿用 pytest（MIT）、HTTPX（BSD-3-Clause）及 Starlette TestClient。HTTP 回送器沒有新增套件，主要間接依賴及分發聲明見 [回應組合器套件表](composer.md#使用的套件與授權) 與 [任務協調與內容生成授權表](orchestration.md#套件模型與資料授權)。模型權重、來源規格與資料權利各自管理，回送工具不變更其授權或部署審查狀態。
