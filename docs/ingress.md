# A：FastAPI HTTP 請求入口

`mirage_api.api:app` 直接接收 HTTP 請求，把標準化的 `NormalizedRequest` 交給下一階段 handler。沒有另包一層 JSON 請求描述，也不會向 URL 發送網路請求。既有 `mirage_validator.api:app` 繼續提供獨立的驗證 API。

在專案根目錄啟動：

```powershell
.\.venv\Scripts\python.exe -m uvicorn mirage_api.api:app --host 127.0.0.1 --port 8001 --no-proxy-headers
curl.exe -i "http://127.0.0.1:8001/store/products/prod_synthetic_001?fields=id&fields=title" -H "X-Request-ID: demo-001"
```

B 平台識別器與 C 生成協調器尚未實作，預設回 **501**，不是商品回應或契約驗證通過：

```json
{
  "code": "pipeline_not_implemented",
  "message": "HTTP request captured; platform identification and generation are not implemented.",
  "request_id": "demo-001"
}
```

回應的 `X-Request-ID` 與 body 一致。入口不回顯原請求 headers、URL 或 body，不會將它們寫入應用程式紀錄；伺服器 access log 仍可能記錄 path／query。HEAD 的追蹤 ID 從 header 取得。

## 標準化介面

| 欄位 | 保留方式 |
| --- | --- |
| `request_id` | 使用單一合法的 `X-Request-ID`；缺少時產生 UUID。只接受 1–128 個 ASCII 字元，首字元為英數，其餘限英數、`.`、`_`、`-`；無效或重複回 400，附新的追蹤 ID |
| `method` | 收到的 HTTP method；支援 GET、HEAD、POST、PUT、PATCH、DELETE、OPTIONS、TRACE |
| `raw_url` | ASGI 可見的 scheme／authority 加原始 path／query，保留 percent encoding、query 順序與重複值 |
| `path`／`raw_path` | ASGI 解碼後 path（字串）及原始 path（bytes） |
| `query_string`／`query` | 原始 query bytes 及解碼後的有序 `(name, value)` tuple，保留重複參數與空值 |
| `headers` | 有序 `(name, value)` tuple，保留 ASGI 提供的重複 headers，以 Latin-1 解碼；header 名稱大小寫取決於 HTTP server |
| `body` | 原始 bytes，不解析 JSON、不重新序列化；空 body 為 `b""`，二進位與無效 JSON 也會保留 |

資料物件為不可變 dataclass，不包含自動推測的平台、operation 或情境。後續若需檢查 JSON，可從原始 bytes 另行解析，不能覆寫原始資料。預設 body 上限 1 MiB，以實際串流位元組計數，超過回 413，不會送進 handler；`create_app(max_body_bytes=...)` 可調整。

此 app 的所有 path 都是目標 API 路徑，包括 `/`、`/docs`、`/openapi.json`；不保留文件端點，也不自動補斜線。CONNECT 與 WebSocket 不在目前範圍。

`raw_url` 代表到達本服務的 URL，不會自動變成原商店 URL。上述本機測試 origin 是 `http://127.0.0.1:8001`。未來 B 須以已核准 manifest 與部署的 host／origin 配置匹配；不能把任意 Host 或 forwarded header 當作平台審查依據。若 HTTP server／代理已重寫 scheme、host、path，A 無法還原重寫前的 URL。範例停用 proxy headers，使本機觀察結果直接來自連線與 Host。

## 接上後續處理

`create_app(handler=...)` 接受 `async (NormalizedRequest) -> Response`，入口先完成標準化，再呼叫 handler，並附上同一追蹤 ID。預設 handler 只回報 501。正式 handler 尚待 B/C/H/I/M 完成後串接，必須在候選回應通過 gate 後才渲染；此介面本身不構成驗證或放行。

實作使用 [FastAPI Request 介面](https://fastapi.tiangolo.com/advanced/using-request-directly/) 讀取 HTTP 資料；這些原始輸入不會自動進行 Pydantic body 驗證。
