# 平台 Profile 工具

## 本次確認的功能

平台規格工具把使用者提供的固定 OpenAPI 來源轉為可追溯的 Profile，供任務協調器取得生成上下文。輸入是 `inputs/sources/<platform>/source.yaml` 與同目錄的規格；輸出是 `generated/profiles/` 與 `generated/schemas/`。

| 功能 | 本次行為 |
| --- | --- |
| 來源識別 | 保留平台、宣告版本、來源 URL／revision、原始檔 SHA-256 與來源審查狀態 |
| 規格檢查 | 使用已鎖版的 openapi-core 0.19.5 檢查 OpenAPI 3.0／3.1；先拒絕外部或不存在的 `$ref`，不會自動連網 |
| 操作摘要 | 擷取 method、path template、operationId、tags、summary 與原始操作的 JSON Pointer |
| 參數與授權 | 合併 path／operation 參數，同名時由 operation 覆寫；保留 security 繼承與顯式清空 |
| 請求與回應 | 保留 requestBody、各狀態鍵（包括 `2XX`／`default`）、response headers、media type 與 schema |
| Schema 與欄位 | 原始 schema 保存在完整規格快照中；保留 required、enum、組合 schema、布林 schema 及遞迴引用 |
| 缺口 | 無 response content、media 未提供 schema 或版本文字不同時記入 warnings，不自行補欄位 |
| 查詢 | 以明確的 platform/version/hash/method/path template 取得 operation 與完整規格 |
| 可重現性 | 相同來源重建產物一致；不同來源、版本、雜湊或審查狀態禁止在同一平台檔案上靜默覆寫 |

`approved` 由維護者完成來源審查後設定，雜湊只確認 bytes 一致。`spec_info_version` 與 `platform_version` 分開記錄；兩者文字相同也不代表官方來源或部署已核實。平台規格工具不執行網站識別（平台識別器）、LLM 推論（任務協調與內容生成）、情境選擇（情境選擇工具）或回應驗證（契約驗證器）。平台慣例只有規格明示部分會被保留，不依描述推導價格型別、庫存邏輯或缺少的 404 schema。

## 現成專案評估與選擇

先查閱上游專案與文件，再選定本次整合方式：

| 專案 | 可重用功能 | 本次決定 |
| --- | --- | --- |
| [openapi-core 0.19.5](https://openapi-core.readthedocs.io/en/0.19.5/) | OpenAPI 3.0／3.1 規格、請求與回應驗證 | **重用現有依賴**；用 `OpenAPI.from_dict` 驗證，另實作本專案的來源識別、摘要與查詢 |
| [Prance](https://github.com/RonnyPfannschmidt/prance) | 解析規格、解析內外部引用 | 可作未來 discovery 的離線打包工具；這次只接受已打包內部引用，故不新增依賴 |
| [openapi-pydantic](https://github.com/mike-oakley/openapi-pydantic) | OpenAPI 3.0／3.1 的 Pydantic 型別模型 | 可用於型別化操作；這次保留原始 schema 與引用，用現有 Pydantic 定義 Profile 格式 |
| [openapi-python-client](https://github.com/openapi-generators/openapi-python-client) | 從 OpenAPI 產生 Python client SDK | 其輸出用途是 SDK；平台規格工具需要來源與生成契約上下文，這次沒有引入 |

這些專案提供解析、型別或 SDK 生成能力；本次評估選擇在既有驗證元件上增加專案需要的 Profile 層，未複製上游程式碼，也未新增依賴。

## 來源設定與執行

```yaml
schema_version: 1
platform_id: medusa
platform_version: '2.22.4'
source_url: https://github.com/medusajs/medusa/blob/81edb06c323812773c9c0dcc4da2d9784f3b3319/www/apps/api-reference/specs/store/openapi.full.yaml
source_revision: 81edb06c323812773c9c0dcc4da2d9784f3b3319
spec_sha256: ced300a2de92b9829e6e600964588e894b760f07f8d79c1df657e1abe0529058
approved: false
openapi_file: openapi.yaml
```

`platform_id` 僅接受小寫英數、`_`、`-`，首字元限英數。`openapi_file` 必須在 source.yaml 的資料夾內；YAML key 必須為不重複的字串，回應狀態應寫為 `'200'`。本版拒絕外部 `$ref`、`$dynamicRef` 與帶結構覆寫 sibling 的 Reference Object；schema 內的 3.1 `$ref` sibling、遞迴模型與布林值會原樣保存。未支援的規格會報錯，不會產生猜測的 Profile。

在專案根目錄執行，不必啟動 FastAPI 或 Ollama：

```powershell
$env:PYTHONPATH = "$PWD/src"
.\.venv\Scripts\python.exe -m deception.profile_builder --source domains/ecommerce/inputs/sources/medusa/source.yaml --output generated
```

目前 Medusa 輸入已依官方 `v2.22.4` 固定 commit 的完整 OpenAPI 修補子集：補上 `BaseRefund.idempotency_key`、51 個 operation 的 `x-allowed`，平台規格工具與契約驗證器規格檔 bytes 一致。目標平台版本 `2.22.4` 與官方規格 `info.version: 2.22.3` 分別記錄；來源仍維持 `approved: false`，尚未驗證實際部署。輸出有 77 個 operations。WooCommerce 只有 `source.yaml.example`，必須先提供固定規格才能執行，不能用現有 PoC schema 替代。

輸出如下，兩類產物均可由來源重建：

```text
generated/
├── profiles/medusa.yaml
└── schemas/medusa/<spec_sha256>.yaml
```

schema 快照保留原始 bytes，Profile 內的 `schema_file` 指向它；operation 的 `schema_pointer` 是該快照內的操作位置。`$ref` 仍相對於完整 OpenAPI 文件，不能把單一 schema 當成沒有引用的獨立 JSON Schema。

CLI 為單次離線建置用途，不支援多個程序同時發布同一平台。寫入時先發布規格快照再原子替換 Profile。更新版本或審查設定後使用新的輸出目錄，例如 `--output generated/releases/medusa-reviewed`，以保留舊 run 的身份；若 build 失敗不會改寫既有有效 Profile。

## 給任務協調器使用的查詢介面

```python
from pathlib import Path
from deception.profile_builder import ProfileTool

context = ProfileTool(Path("generated")).get_operation(
    platform_id="medusa",
    platform_version="2.22.4",
    spec_sha256="<與來源及本次run相同的SHA256>",
    method="GET",
    path="/store/products/{id}",
    allow_unreviewed=True,  # 僅用於目前未審來源的離線預覽
)
print(context.operation.responses.keys())
```

`allow_unreviewed` 預設為 `False`。查詢時會檢查版本／雜湊、原始規格快照與重新擷取的 Profile 是否一致，再回傳 `source`、`operation`、`specification`。path 必須是精確 template；將實際 URL 對應 template 屬於平台識別器，平台規格工具不自行猜測。未知操作、不符身份、遭改動的快照或摘要都拋出 `ProfileError`。

這個工具以 Python 與 CLI 提供，任務協調器已依精確身份讀取 Profile；可選的 [HTTP 請求入口→任務協調與修正備援→HTTP 回送器 HTTP app](renderer.md) 使用同一查詢流程。取得 Profile 不等於正式回應 gate 放行；契約驗證器仍依另一份已審查的部署 manifest、網站與 query 上下文驗證，HTTP 回送器對最終傳輸候選再執行契約驗證。現有 Medusa 部署審查狀態不變。

## 驗證與套件授權

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_profiles.py tests/test_medusa_pinned_contract.py -q
```

驗證來源 bytes／SHA-256、Profile 重建、操作查詢、內部引用與未審來源預覽；固定 Medusa 子集的回歸不表示實際部署已核准。

平台規格工具重用 [Pydantic（MIT）](https://github.com/pydantic/pydantic/blob/main/LICENSE)、[PyYAML（MIT）](https://github.com/yaml/pyyaml/blob/6.0.3/LICENSE) 及 [openapi-core 0.19.5（BSD-3-Clause）](https://github.com/python-openapi/openapi-core/blob/0.19.5/LICENSE)。標準庫 `hashlib`、`json`、`pathlib`、`tempfile` 等隨 Python 的 PSF 授權及聲明管理；測試使用 pytest（MIT）。主要共用驗證依賴與分發要求見 [回應組合器套件表](composer.md#使用的套件與授權)，來源 OpenAPI／文件權利與程式套件授權分開管理。
