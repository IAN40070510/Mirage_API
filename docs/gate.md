# 網站契約守門員

`POST /v1/validate` 改用網站綁定的 OpenAPI 驗證。原示意契約只供 `/v1/poc/validate` 使用，不能作正式放行依據。這是輸入格式的破壞性變更。

**目前沒有完成部署審查的 WooCommerce／Medusa 契約，也沒有實際官方服務的對照測試；預設不放行任何網站。** Medusa Store／Auth 子集已固定官方來源 commit，平台規格工具/契約驗證器使用相同 bytes，但部署、origin 與行為對照尚未核實，仍維持未審查；詳見 [來源狀態](../inputs/platforms/medusa/README.md)。合成規格測試與固定來源離線回歸均不等於真實部署的官方相容性證據。

`pass` 只證明符合已載入契約描述的規則。要聲稱與官方實際回應完全一致，仍須有精確版本、部署環境、可重現測試資料及官方服務對照測試。若官方規格缺少動態欄位、外掛、授權、headers 或業務規則，單靠 OpenAPI 套件不能補足保證。

## 執行

Python 3.11+，在專案根目錄以 PowerShell 執行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
$env:MIRAGE_PLATFORMS_DIR = "$PWD/inputs/platforms"
.\.venv\Scripts\python.exe -m uvicorn mirage_validator.api:app --reload
```

另開終端機測試：

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

平台根目錄預設為工作目錄下的 `inputs/platforms`；正式使用建議指定絕對路徑。`.env.example` 僅記錄設定名稱，不自動載入 `.env`。更新套件後需重啟。無效規格或雜湊不符使啟動失敗，不會略過後放行。

## 平台入口

```text
inputs/platforms/<網站與版本套件>/
  manifest.yaml         # 來源、版本、部署綁定、SHA-256、審查聲明
  openapi.yaml          # 固定版本的官方契約，使用內部 $ref
  samples/              # 可選；不推導契約、不當作驗證依據
```

WooCommerce 與 Medusa 目錄內的 `manifest.yaml.example` 不會被載入。取得實際規格並審查後才改成 `manifest.yaml`；同平台不同網站／版本可以建立多個套件。

1. 從指定官方版本取得規格，記錄 `source_url`、不可變 tag／commit 的 `source_revision`、精確 `platform_version`。不能把官方 JSON 範例直接轉成完整規格。
2. 官方來源缺少完整 OpenAPI 時，須依固定版本的官方原始碼與參考服務補齊有來源的契約與對照證據；完成前維持未支援。
3. 外部 `$ref` 須先打包為內部引用。程式拒絕外部引用，不自動下載規格。
4. 計算檔案 SHA-256，填入 `spec_sha256`。雜湊只證明檔案未變動，不能證明來源官方性。
5. `base_urls` 綁定完整 origin 與 API 前綴，例如 `https://shop.example/wp-json/wc/v3`；OpenAPI paths 必須相對於這個前綴。原 paths 已含前綴時應綁定 origin，避免重複。server 部署替換不改回應 schema；path／operation server override 暫不支援。
6. `query_contexts` 預設只允許無 query。其他情境須逐一審查，參數值為字串陣列，例如 `[{fields: [id,title]}]`。清單只限制適用情境，不會自動推導動態 schema；規格無法涵蓋時維持不支援。
7. 完成來源、部署與規則覆蓋審查後，維護者才設定 `approved: true`。這是受信任設定維護者的聲明，不是程式完成的官方認證。規格或部署變更必須重審。

```powershell
(Get-FileHash inputs/platforms/your-site/openapi.yaml -Algorithm SHA256).Hash.ToLowerInvariant()
```

`profile.yaml`、samples 或補充 schema 目前不載入，也不能偷偷放寬官方規則。不要將未指定的 `additionalProperties` 自行改為 false，然後宣稱更接近官方。

Medusa 的 [Store API 文件](https://docs.medusajs.com/api/store) 提供 OpenAPI 下載，且 `fields` 會影響回應內容。WooCommerce 的 [wc/v3 商品文件](https://developer.woocommerce.com/docs/apis/rest-api/v3/products/) 不應與舊 `/wc-api/v3` 混用。latest 文件可能變動，實際契約須固定到部署版本。

## 呼叫與結果

```json
{
  "request_url": "https://shop.example/wp-json/wc/v3/products/101",
  "request_method": "GET",
  "status_code": 200,
  "headers": {"Content-Type": "application/json"},
  "body": "{\"id\":101}"
}
```

此為呼叫格式示例，不是有效官方商品回應。`body` 是最終序列化的 UTF-8 JSON 字串。驗證器不修改字串、不修補、不重試，也不代送 HTTP 回應。

| decision | 意義 |
| --- | --- |
| pass | 已支援契約檢查全部通過，valid=true |
| reject | 回應違反契約，valid=false |
| unverifiable | 未涵蓋、未審查、匹配有歧義或驗證器失敗，valid=false |

預設無有效平台套件，因此回 `unverifiable` 與 `site_not_unique`。匹配後會附平台版本、operation ID、規格 SHA-256。錯誤帶 `location`、JSON Pointer `path`、`code`、`reason` 與可用時的 `schema_path`；required／額外欄位定位所屬物件，原因列出相關欄位。部分 HTTP 套件錯誤只提供 location 根節點。

只有 `decision == "pass"` 且 `valid == true` 才能放行，Composer 必須送出同一份已驗證的 body／status／headers，不能之後再修改。驗證 API 本身回 HTTP 200 不代表被測回應有效；輸入格式錯誤回 422。

## 實作範圍

- `mirage_validator/gate.py`：平台套件載入、網站綁定、方法／端點識別、OpenAPI 回應驗證。
- `mirage_validator/api.py`：正式契約入口與隔離的原 PoC 入口。
- `tests/test_gate.py`：自建測試規格，涵蓋 3.0／3.1、內部引用、型別／enum／required／additionalProperties、headers、status、缺少規格與歧義。

正式契約驗證統一使用 `openapi-core==0.19.5`，目前支援 OpenAPI 3.0／3.1，未支援 3.2。透過指定 response validator 停用 JSON body 型別轉換，讓 openapi-core 直接驗證原始型別，避免字串／布林值通過 integer 驗證；HTTP header 仍按字串傳輸與規格解析。這使用鎖定版本的內部擴充點，升級時必須跑過兩版 OpenAPI 的型別回歸測試。

不另外直接呼叫 `openapi-schema-validator`；該套件仍可能作為 openapi-core 的間接依賴安裝。`jsonschema` 僅用於原 PoC 的自訂 JSON Schema，不加入正式 OpenAPI 的第二輪驗證。

目前只支援 JSON body 與單值 headers 字典；無 body schema 的回應（包括尚未實作的 204／HEAD 情境）、非 JSON、未審查 query 組合、未知或重複網站匹配都不放行。不支援自動爬站推導規格、完整業務語意、多值 HTTP headers 或官方執行環境對照。

契約驗證器可獨立作為驗證工具，也已由任務協調器/回應組合器內部流程調用；生成及情境工具各有獨立模組，見 [工具文件索引](README.md)。契約驗證器本身不生成內容、修改候選或更新互動狀態。

## 套件授權

契約驗證器重用 [openapi-core 0.19.5（BSD-3-Clause）](https://github.com/python-openapi/openapi-core/blob/0.19.5/LICENSE)、[Pydantic（MIT）](https://github.com/pydantic/pydantic/blob/main/LICENSE)、[PyYAML（MIT）](https://github.com/yaml/pyyaml/blob/6.0.3/LICENSE) 與 [Werkzeug（BSD-3-Clause）](https://github.com/pallets/werkzeug/blob/3.1.1/LICENSE.txt)；HTTP API 使用 FastAPI（MIT）。標準庫隨 Python 的 PSF 授權及聲明管理。主要 schema／OpenAPI 間接依賴、測試套件及分發要求見 [回應組合器套件表](composer.md#使用的套件與授權) 與 [專案授權清單](../README.md#開源軟體模型與資料授權)。來源規格的權利與實際部署核准另行管理。
