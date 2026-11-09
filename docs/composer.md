# 回應組合工具

## 確認的功能與界線

回應組合器接收任務協調器的明確組合指令、平台規格工具的固定契約，以及可選的合成資料工具合成資料，建立同一份 `status_code`、單值 headers 與最終 JSON body 字串。程式位於 `src/deception/core/`，所有主要函式均附功能註解。

| 功能 | 本次行為 |
| --- | --- |
| 契約定位 | 依 platform／version／SHA-256／method／path template 從平台規格工具取得唯一操作 |
| 明確組合 | 使用呼叫者提供的 body 模板，不自動依 schema 填入猜測值、刪除欄位或轉型 |
| 合成資料映射 | 透過 JSON Pointer 從領域供應器的 `CompositionData.payload` 複製值到已存在的模板位置，不限定商品根節點 |
| 隔離 | 供應器先驗證領域資料，組合器重驗 DTO，且 site、platform、version、hash、scenario、run 必須與指令相同 |
| HTTP metadata | 狀態碼須有契約；拒絕重複 header、控制字元、傳輸 framing 與不符的 Content-Type |
| JSON | 僅支援 UTF-8 `application/json` 或 `application/*+json` 的明確媒體名稱；固定排序，保留 JSON 原始型別 |
| 契約 preflight | 對最終序列化 triple 檢查 schema 與 headers；失敗直接拒絕，不修正或重試 |
| 候選輸出 | 不可變 dataclass、tuple headers、body 字串與來源／run 身份；可原樣轉為契約驗證器的 GateRequest |
| 契約驗證器身份交接 | `verify_candidate` 交給契約驗證器後，核對 platform／version／hash／operation；其他契約的結果不能代替原候選通過 |

preflight 只表示符合載入的回應契約，不檢查原網站綁定、已審查 query 或真實平台行為。回應組合器的輸出仍是待契約驗證器驗證的候選，不包含 `valid=true` 或正式放行狀態。任務協調器已串接回應組合與契約驗證，[修正與備援工具](recovery.md) 的修正及備援也重新經過回應組合與契約驗證；可選 [HTTP 回送與完整 HTTP 接入](renderer.md) 會完成最終傳輸標頭，再依部署 manifest 對同一份 triple 重新執行契約驗證才回送。

資料輸入可直接提供 `CompositionData`，或由可信領域物件的 `to_composition_data()` 回傳該型別。裸字典或回傳其他型別的 adapter 都會拒絕；DTO 並不代替領域事實驗證。電商 adapter 仍依生成設定重建檢查商品，工單等其他領域可使用不同 payload，詳見 [共用資料交換](common-data.md)。

本版只處理有 JSON body 的回應。HEAD、204／205／304、非 JSON、缺少 media schema 或多值 headers 尚不支援。schema 是否允許額外欄位、nullable、組合 schema 等，沿用來源契約；不額外猜測或放寬。

對 OpenAPI 3.1 的根層 literal schema，`false` 明確拒絕任何 body，`true` 透過鎖版相容 adapter 允許任意 JSON、保留 headers 驗證，`{}` 也不是缺少 schema。adapter 不修改來源，也不將 `$ref`／sibling 自動當成 literal true；底層套件無法確認的其他 3.1 特性會拒絕組合。

`true` adapter 只覆寫 response body 的上層檢查入口，保留複合 header（`header.content.schema`）的正常驗證路徑。測試包含要求整數的複合 header，確認 JSON 字串與布林值都不能被誤當成有效整數。

## 現成專案評估

| 專案 | 能力 | 上游授權 | 本次決定 |
| --- | --- | --- | --- |
| [openapi-sampler](https://github.com/Redocly/openapi-sampler) | 從 OpenAPI／JSON Schema 產生範例 | MIT | 可供後續研究 schema sample；本版需要明確模板與合成資料工具關聯，未引入 |
| [json-schema-faker](https://github.com/json-schema-faker/json-schema-faker) | 從 schema 產生假資料 | MIT | 與既有合成資料工具有部分用途重疊，未引入其 TypeScript 執行環境 |
| [Prism](https://github.com/stoplightio/prism) | mock server、validation proxy | Apache-2.0 | 可作後續獨立對照服務；本版回應組合器是 Python 內部工具，未引入 |
| [openapi-core 0.19.5](https://openapi-core.readthedocs.io/en/0.19.5/validation/) | OpenAPI 請求／回應驗證 | BSD-3-Clause | **重用既有依賴**，與契約驗證器共用保留 JSON 原始型別的 response validator |

本次先比較上述方案，再採用 Python 內部組合器。沒有新增依賴，也沒有複製上游 sampler／mock server 的程式碼。preflight 使用鎖版 openapi-core 0.19.5 的 `_iter_errors` extension point，直接定位平台規格工具的 operation pointer；它不需要虛構網站或執行路由識別。升級這個版本時，必須重跑回應組合與契約驗證的原始型別與相同候選 triple 回歸測試。

## 使用的套件與授權

下表依本次環境的已安裝 distribution metadata 與隨附授權檔核對。除 openapi-core、Faker 外，其餘版本是本次驗證環境快照，實際安裝仍依 `pyproject.toml` 的範圍解析。

| 套件 | 本次版本 | 授權 | 在回應組合器路徑的用途 |
| --- | --- | --- | --- |
| [Pydantic](https://github.com/pydantic/pydantic/blob/main/LICENSE) | 2.14.3 | MIT | 嚴格組合指令與合成資料工具／平台規格工具模型 |
| [openapi-core](https://github.com/python-openapi/openapi-core/blob/0.19.5/LICENSE) | 0.19.5 | BSD-3-Clause | 契約與最終回應 preflight |
| [Werkzeug](https://github.com/pallets/werkzeug/blob/3.1.1/LICENSE.txt) | 3.1.1 | BSD-3-Clause | 單值 HTTP headers adapter |
| [PyYAML](https://github.com/yaml/pyyaml/blob/6.0.3/LICENSE) | 6.0.3 | MIT | 讀取平台 Profile 與 CLI 指令 |
| [Faker](https://faker.readthedocs.io/en/stable/#license) | 40.44.0 | MIT | 電商 adapter 重建並檢查商品；共用組合器不直接呼叫 Faker |
| [jsonschema](https://github.com/python-jsonschema/jsonschema/blob/main/COPYING) | 4.26.0 | MIT | 既有驗證鏈的 schema 驗證 |
| [jsonschema-path](https://github.com/python-openapi/jsonschema-path) | 0.3.4 | Apache-2.0 | openapi-core 的 schema 路徑與引用解析依賴 |
| [openapi-schema-validator](https://github.com/python-openapi/openapi-schema-validator) | 0.6.3 | BSD-3-Clause | OpenAPI schema 驗證依賴 |
| [openapi-spec-validator](https://github.com/python-openapi/openapi-spec-validator) | 0.7.2 | Apache-2.0 | OpenAPI 規格驗證依賴 |

Python 標準庫的 `json`、`dataclasses`、`pathlib` 等隨 Python 提供，依其 PSF 授權及隨附聲明分發。本表涵蓋回應組合器直接使用及主要共用依賴，不是完整間接依賴 SBOM；Faker 的 `tzdata` 等仍依 [合成資料工具授權說明](synthetic.md) 及實際安裝版本管理。打包第三方套件時保存其原始 LICENSE、版權、免責聲明，以及實際存在的 NOTICE。本工具呼叫公開 API／既有鎖版擴充點，未修改第三方原始碼；自有程式的 Apache-2.0 與第三方材料邊界見 [授權總覽](licensing.md)。

## 指令格式與執行

`domains/ecommerce/configs/composition.yaml` 提供明確的 Medusa 404 範例。它是呼叫者選定的錯誤情境，不代表回應組合器已判斷商品不存在；存在與否的情境選擇屬於情境選擇工具。

```powershell
$env:PYTHONPATH = "$PWD/src"
.\.venv\Scripts\python.exe -m deception.core --plan domains/ecommerce/configs/composition.yaml --profiles generated --output generated --allow-unreviewed
```

若平台規格工具尚未產生 Profile，先執行 [平台規格工具建立指令](profiles.md)。目前 Medusa 來源尚未審查，因此上面明確開啟離線預覽；預設不加 `--allow-unreviewed` 就會拒絕該來源。回應組合器不修改平台規格工具 source 或契約驗證器 manifest 的 `approved`。

成功會保存 `generated/responses/<platform>/<候選封套SHA256>.json`，並顯示契約預檢已通過、尚待部署契約驗證的訊息。檔案 body 欄位本身已是最終 JSON 字串；整份檔案是本地候選封套，不能直接把封套當成商品 HTTP body。

需映射電商資料時，同時提供 `--domain ecommerce`、`--dataset <合成資料產物>` 與 `--generation-config domains/ecommerce/configs/generation.yaml`。共用 CLI 由所選領域的 `provider.from_files` 載入及驗證資料，不自行解析商品。plan 的 scope 必須與資料相同；404 範例的 scenario/run 與預設成功情境不同，不能直接混用。

```yaml
# 指令的局部示例；其他身份與 status 仍須明確提供。
body:
  product:
    id: ''
    title: ''
bindings:
  - source_pointer: /products/0/id
    target_pointer: /product/id
  - source_pointer: /products/0/title
    target_pointer: /product/title
```

這個精簡 body 只適用相應的合成測試契約，無法滿足目前 Medusa 的全部必填欄位。target 必須存在，重複或父子重疊的 target 拒絕；陣列 index 不接受負值、前導零或 `-` append。沒有文字插值、檔案讀取表達式或任意程式執行。source 只能讀供應器明確投影的 payload；電商投影不包含生成設定與 provenance，其他領域也須自行選擇可暴露的資料。

## 交給契約驗證器的介面

```python
from pathlib import Path
from deception.core import ResponseComposer, verify_candidate

candidate = ResponseComposer(Path("generated")).compose(
    plan, dataset=dataset, allow_unreviewed=True,  # 僅供未審來源離線預覽
)
gate_request = candidate.to_gate_request(original_request_url)
assert gate_request.body == candidate.body
assert gate_request.headers == dict(candidate.headers)
assert gate_request.status_code == candidate.status_code
result = verify_candidate(candidate, official_gate, original_request_url)
```

呼叫者仍須確認結果的 `decision == 'pass'`、`valid is True`，才能把相同 triple 送給 HTTP 回送器。`verify_candidate` 使用現有契約驗證器，不重組 body；它另核對契約驗證器回報的平台、版本、雜湊及 operation，若不符就回 `unverifiable` 與 `candidate_identity_mismatch`，保留契約驗證器實際匹配的身份供追溯。這可防止兩個 operation 共用 schema 時，把另一個 URL 的 `pass` 用於原候選。契約驗證器本身的 `reject`、未知網站及未核准判定會保留。

`to_gate_request` 是低層轉換介面，不含上述身份核對，也不聲稱任何網站已受核准。預設工作目錄沒有核准的 Medusa manifest，因此現有 Medusa 候選仍不能正式放行。

## 有效性驗證與目前規格缺口

測試用固定雜湊的合成契約建立平台規格工具、合成資料工具、回應組合器，再讓契約驗證器讀取相同 bytes 與僅限臨時測試網站的核准 manifest，驗證 200／404 候選通過；同時驗證錯誤型別、缺欄位、header 注入、未知狀態、錯誤映射及 scope 不符會失敗。這些臨時測試不會核准 repo 的 Medusa 來源。

另以 repo 真實輸入的 Medusa 200／404 作 preflight，並確認未審查部署仍被契約驗證器拒絕。200 使用手寫的完整合成測試模板，將合成資料工具的商品與變體 ID／文字明確映射進去；固定 timestamps（包括 deleted_at）只驗證本地 schema，不證明實際平台的商品或刪除語意。當前 Medusa 商品與變體 schema 分別有多個合成資料工具尚未提供的必要欄位，特別是 `deleted_at`、`thumbnail`、尺寸等沒有 nullable；回應組合器不會將缺值補成 `null` 或自行修正來源。空 query 也不會自動帶入描述限定需 `fields=+variants.inventory_quantity` 的庫存，合成資料工具的 Price 不能直接塞成 calculated_price。

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_composer.py tests/test_candidate_handoff.py -q
```

回應組合器的有效性指的是明確組合、序列化、契約 preflight 與契約驗證器交接正確；正式平台語意、來源審查與部署對照仍是獨立條件。
