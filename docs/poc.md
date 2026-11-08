# Mirage_API：Response Contract Validator PoC

本頁是獨立、可重用的電商示意契約驗證工具，使用 Python 3.11+、FastAPI、Pydantic 2、jsonschema 4 與 JSON Schema Draft 2020-12。PoC 工具本身不調用 LLM、組合回應或修正重試；整個專案另有 C/G/H 模組，見 [工具文件索引](README.md)。

**所有 WooCommerce／Medusa 契約皆為 PoC 示意，不宣稱與任何官方 API 版本完全一致。** `poc-v1` 是本專案契約版本，不是平台版本。`get_product` 僅為示範操作 ID；200 為簡化商品，404 為本專案統一錯誤格式。`X-Request-ID` 亦為 PoC 自訂要求。

## 安裝與啟動（PowerShell）

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\python.exe -m uvicorn mirage_validator.api:app --reload
```

開啟 http://127.0.0.1:8000/docs 可試用。執行測試：

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

## 呼叫驗證 API

```powershell
curl.exe -X POST http://127.0.0.1:8000/v1/poc/validate -H "Content-Type: application/json" --data-binary "@fixtures/woocommerce_200_valid.json"
curl.exe -X POST http://127.0.0.1:8000/v1/poc/validate -H "Content-Type: application/json" --data-binary "@fixtures/medusa_invalid.json"
```

請求範例：

```json
{
  "platform_id": "woocommerce",
  "operation_id": "get_product",
  "contract_version": "poc-v1",
  "status_code": 200,
  "headers": {"Content-Type": "application/json", "X-Request-ID": "demo-001"},
  "body": {"id": 101, "name": "PoC 商品", "type": "simple", "status": "publish", "price": "19.90"}
}
```

`headers`、`status_code` 與 `body` 描述的是**待驗證回應**。驗證 API 本身的 HTTP headers 不會拿來替代。`body_encoding` 預設為 `json`，直接驗證 JSON 值且不轉型；要驗證未解析的 body，請設為 `raw` 並把 body 放成字串。raw 模式拒絕無效 JSON、非有限數值及重複 key。json 模式的字串仍是字串，不會被二次解析。body 必須提供，明確傳入 null 則交由 schema 判定。

有效結果：

```json
{"valid": true, "contract_id": "woocommerce:get_product:poc-v1:200", "errors": []}
```

例如把 `id` 改成字串，錯誤包含：

```json
{"location":"body","path":"/id","code":"type","reason":"'101' is not of type 'integer'","schema_path":"/properties/id/type"}
```

`path` 是相對於 location 的 RFC 6901 JSON Pointer；空字串代表根節點。required 與 additionalProperties 錯誤定位到所屬物件，reason 會列出缺少或多出的欄位。`schema_path` 指向造成錯誤的 schema 規則；非 schema 錯誤為 null。原因文字由 jsonschema 提供，通常為英文。

契約驗證通過或失敗，驗證 API 都回 HTTP 200，以 `valid` 判定；驗證請求本身不符輸入規格則回 HTTP 422。沒有契約的狀態碼回 `unsupported_status`；未知平台、操作或版本回 `contract_not_found`，不會猜測或改用其他版本。200 與 404 分別有自己的 schema。

## 結構與擴充

| 路徑 | 用途 |
| --- | --- |
| `mirage_validator/validator.py` | 可獨立呼叫的驗證邏輯 |
| `mirage_validator/registry.py` | 載入本地契約並檢查 schema、重複索引 |
| `mirage_validator/contracts/*.json` | 平台／操作／版本／狀態碼契約 |
| `mirage_validator/models.py` | 嚴格 Pydantic 輸入與結果模型 |
| `mirage_validator/api.py` | POST /v1/poc/validate |
| `fixtures/` | 兩平台的有效 200／404 與無效回應 |
| `tests/` | API 與獨立驗證器測試 |

新增 JSON 契約檔後重啟服務；索引來自檔案內容的四個欄位，不依賴檔名。`content_types` 使用小寫 MIME type；header 名稱不分大小寫，Content-Type 忽略參數（例如 charset），必要 headers 以各自的 JSON Schema 驗證。重複的大小寫 header 名稱會判定失敗。此 PoC 的 headers 是單值字典，未涵蓋多值 header 與原始 HTTP 封包解析。

WooCommerce 商品 schema 禁止額外欄位；Medusa 的巢狀 product 允許額外欄位，展示 `additionalProperties` 由契約決定。型別、required、enum、pattern 等規則都必須通過，JSON 能解析不代表符合契約。schema 僅接受受信任的本地設定，範例使用內嵌 schema，不會依使用者輸入路徑載入檔案或自動抓取遠端 `$ref`。

不啟動 API 也能使用：

```python
import json
from pathlib import Path
from mirage_validator import ResponseContractValidator, ValidationRequest

payload = json.loads(Path("fixtures/woocommerce_200_valid.json").read_text(encoding="utf-8"))
result = ResponseContractValidator().validate(ValidationRequest.model_validate(payload))
print(result.model_dump_json(indent=2))
```

後續 Composer／LLM 只需提交候選回應並讀取結果；本驗證器不修改候選內容、不產生備援回應、不重試。這是結構與 HTTP metadata 驗證，不驗證商品事實、商業規則或完整官方相容性。

## 套件授權

PoC 直接使用 [jsonschema（MIT）](https://github.com/python-jsonschema/jsonschema/blob/main/COPYING) 與 [Pydantic（MIT）](https://github.com/pydantic/pydantic/blob/main/LICENSE)，HTTP 介面使用 FastAPI（MIT）；Python 標準庫隨 PSF 授權及聲明管理。測試使用 pytest（MIT）與 HTTPX（BSD-3-Clause）。共用版本與分發要求見 [專案授權清單](../README.md#開源軟體模型與資料授權)；示意契約不能替代正式 I 的來源及部署審查。

依賴設計參考：[FastAPI 的 Pydantic 2 說明](https://fastapi.tiangolo.com/how-to/migrate-from-pydantic-v1-to-pydantic-v2/)、[jsonschema 驗證與 iter_errors](https://python-jsonschema.readthedocs.io/en/v4.21.1/validate/)。實際測試版本以執行環境及 pyproject.toml 為準。

已在 Python 3.13.5、FastAPI 0.135.1、Pydantic 2.13.5、jsonschema 4.23.0、pytest 8.3.4、httpx 0.28.1 環境完成 35 項測試。測試工具的 Starlette／AnyIO 組合有一則棄用提醒，不影響測試結果。
