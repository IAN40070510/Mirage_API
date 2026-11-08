# F：情境選擇工具

## 功能與模組邊界

F 位於 `src/deception/scenarios/`，先依政策選定情境領域，再依管理者規則、B 的操作身份、D 的固定契約及外部判定選擇情境。共用引擎負責身份、判定、規則優先序及封存交接；領域處理器負責該領域的規則驗證與結果選擇。目前內建領域為 `ecommerce`（電商），商品規則與處理器位於 `domains/ecommerce.py`。本版採明確欄位與白名單規則，不執行文字表達式、`eval`、LLM 或網路請求。主要函式與資料模型附有功能註解。

| 功能 | 本版行為 |
| --- | --- |
| 領域選擇 | 政策必須明寫 `domain: ecommerce`；呼叫端可再指定領域核對，不接受未知領域或不符的政策 |
| 情境準備 | 核對請求、B／D 身份、判定關聯與政策，選定唯一情境 family |
| 電商結果選擇 | GET 商品明細：E 有相同商品 ID 選 `found`／200，沒有則選 `missing`／404 |
| 固定隔離範圍 | `scenario_id` 表示 family，例如 `product-lookup`；結果分支使用獨立 `outcome_id`，不重新標記 E 資料集 |
| 政策限制 | 明列部署、平台版本、規格 SHA-256、操作、query 組合、商品 ID 取得方式及允許模板；優先序最高者須唯一 |
| H 交接 | 輸出明確 `CompositionPlan` 與 E 欄位映射，由 H 組合、序列化並作契約 preflight |
| 可追溯性 | 保留領域、政策、規則、判定、請求與資料身份，區分情境選定與 I 的最終放行 |

F 的兩個階段解決 E 隔離範圍的先後關係：先準備固定 family，呼叫端才能以該 scope 建立或取得 E；然後 F 讀取同一 scope 的資料，選出存在或不存在的結果。`found` 與 `missing` 不會變成兩個不同 E namespace，也不會為了配合分支修改 `scope.scenario_id`。

F 只選擇管理者允許的結果，不偵測攻擊、不核准 D 來源或 I 部署、不替 H 猜測缺少的欄位，也不產生正式對外回應。H 的候選仍須把完全相同的 status、headers、body 交給 I；只有 I 的 `decision == "pass"` 且 `valid is True` 才能供後續 renderer 使用。目前沒有公開接收 verdict 的 HTTP API，也沒有自動轉送真實服務的流程。

## 選擇電商領域與擴充其他領域

領域、平台、情境與結果分別表示不同層次：

| 欄位 | 意義 | 電商例子 |
| --- | --- | --- |
| `domain` | 一組業務領域的政策模型與處理器 | `ecommerce` |
| `platform_id` | 目標服務及其固定契約 | `medusa`、`woocommerce` |
| `scenario_id` | 同一份資料所屬的情境 family | `product-lookup` |
| `outcome_id` | 依該次事實選出的結果分支 | `found`、`missing` |

選電商不等於選 Medusa，也不表示已核准任何平台。政策仍須精確綁定平台、版本、契約 SHA-256、部署及操作。現在可在政策中明確選擇：

```yaml
schema_version: 1
domain: ecommerce
policy_id: product-lookup-policy
policy_version: '1'
enabled: false
# 其他部署、規則與模板欄位見 inputs/policies/deception.yaml。
```

`load_policy(path, domain="ecommerce")` 與 `ScenarioEngine(policy, domain="ecommerce")` 會同時核對呼叫端選擇及政策領域。省略呼叫參數時使用政策明寫的 `domain`；政策本身不能省略。未知、未註冊或與政策不符的領域會拒絕，不從 URL、平台名稱或訪客 header 猜測，也不自動回退電商。

`DomainRegistry` 是新增領域的註冊介面。共用的 `DomainPolicy`、`ScenarioRuleBase`、`ResponseTemplateBase` 與 `DomainOutcome` 提供政策及結果基礎；每個新領域須定義自己的嚴格政策模型與 `prepare`／`resolve` 處理器，再註冊該領域。商品 ID 解碼、200／404 選擇、商品欄位限制與 E 商品查詢都由電商處理器負責，共用引擎不依 `products` 決定結果。

既有公開名稱 `ScenarioPolicy`、`ScenarioRule`、`ResponseTemplate` 與 `TemplateBinding` 保留為電商模型介面；新領域應使用各自的型別模型。`PreparedScenario.domain_context` 保存處理器產生的領域資料，取代共用封套的 `product_id` 欄位；準備封套及 trace 都包含 `domain`，不能把某個領域的封套交給另一個領域解析。舊政策需補上 `domain: ecommerce` 後重新載入；舊 prepared 封套應重新準備。

目前可用的正式領域只有電商。測試用非商品處理器只用來驗證分派與擴充介面，不代表已提供其他領域的業務規則、資料生成或 H 欄位映射。E/H 現有資料與映射仍以商品／變體為主；新增完整領域時，也須提供相應的資料供應及回應映射。這次不改寫既有 E scope 或 namespace；跨領域資料隔離須由新領域的資料介面一併設計。

## 外部判定的信任與失敗結果

呼叫 F 的整合層必須先確認判定來自可信服務，例如在接收層完成來源驗證、驗簽或受控服務間通道。`trusted_sources` 只是本地政策白名單，不能證明傳入 JSON 的來源身分；使用者可控制的 header 或 `trusted: true` 不能充當認證。

F 核對已提供判定的來源 ID、request ID、請求指紋、環境／部署／服務／站點、觀察時間、到期時間及政策允許的最長時效。預設讀取 UTC 時鐘，也可由呼叫端注入帶時區的時間；期限採不含截止點的區間，剛好到期就拒絕。請求指紋用於把判定綁定到同一請求，不取代外部判定的來源認證。

| 結果 | 意義 |
| --- | --- |
| `prepared` | 已選定 family，尚未根據 E 決定結果 |
| `selected` | 已根據驗證後的 E 快照選定結果並產生 H 指令，尚未通過 I |
| `not_applicable` | 有效判定為 benign，或沒有符合政策的情境；不代表可直接轉送真實服務 |
| `unverifiable` | 缺少、過期、未知、關聯不符、身份不一致、規則歧義或資料無法驗證；不產生可交給 H 的指令 |

未審的 D 來源只能由呼叫端明確開啟離線預覽；這個選項不會改動任何 `approved`，也不會使 I 接受未審部署。

## Python 內部工具介面

先建立明確綁定部署及固定契約的政策，再由整合層提供 A 的 `NormalizedRequest`、B 的 `IdentificationResult`、D 的 `OperationContext` 及已驗證來源的 `AttackAssessment`。以下以已完成審查並啟用的政策為前提，變數 `verified_assessment` 表示接收層已完成認證的判定，不是直接讀取訪客提供的 JSON。

```python
from datetime import datetime, timezone
from pathlib import Path

from deception.core import ResponseComposer, verify_candidate
from deception.scenarios import ScenarioEngine, fingerprint_request, load_policy
from deception.synthetic import generate_dataset
from deception.synthetic.models import SyntheticConfig

policy = load_policy(Path("reviewed-deception.yaml"), domain="ecommerce")
engine = ScenarioEngine(policy, domain="ecommerce")
preparation = engine.prepare(
    request, identification, profile, verified_assessment,
    run_id="run-a", now=datetime.now(timezone.utc),
)
if preparation.decision == "prepared":
    prepared = preparation.prepared
    config = SyntheticConfig(scope=prepared.scope, seed=42, product_count=2)
    dataset = generate_dataset(config)
    decision = engine.resolve(prepared, dataset, now=datetime.now(timezone.utc))
    if decision.decision == "selected":
        # C 必須保留這次請求與 F 決策的配對，不可把計畫套到其他商品 URL。
        assert decision.trace["request_fingerprint"] == fingerprint_request(request)
        candidate = ResponseComposer(Path("generated")).compose(
            decision.composition_plan, dataset=dataset,
        )
        result = verify_candidate(candidate, official_gate, request.raw_url)
        # 後續只有在 result.decision == "pass" 且 result.valid is True 時使用相同候選。
```

`fingerprint_request(request)` 提供與 F 相同的請求關聯計算；判定服務或受信任整合層應使用一致的正規化規則。呼叫端應保存或取回相同 run 的 E 快照；範例中的生成呼叫只是展示 E 必須使用 `prepared.scope`。路徑的商品 ID 指向生成資料中的商品時選 200，其他 ID 選 404；F 不會因查詢陌生 ID 而新增商品。

`inputs/policies/deception.yaml` 是明寫 `domain: ecommerce`、可由 `load_policy` 讀取的停用範本。部署、版本、SHA-256、operation、path 及完整回應 body 都須依 B/D 審查後替換；精簡的 `product.id/title` body 僅適用對應的測試契約，無法直接滿足 Medusa 的全部必填欄位。電商處理器檢查分支 schema 存在，實際模板值及 headers 仍由 H preflight 與 I 驗證。

`PreparedScenario` 的 seal 用於同一個 `ScenarioEngine` 實例的兩階段交接，防止領域及準備結果被改動；它不是外部判定的數位簽章，也不是跨程序可攜的認證 token。換引擎實例後應重新準備。領域、政策版本／內容、規則、模板、資料 namespace 與資料摘要可由結果追溯，不以敏感請求 body 或認證 header 作診斷輸出。

C 持有同一份 A 請求、F 決策與 H 候選，並在生成與發布前後核對指紋、期限及資料事實。H/I 目前核對 operation 與 path template，不能單靠 schema 發現「A 商品 body 被拿去回 B 商品 URL」；其他整合層也必須維持這個請求關聯，並把原始 URL 交給 I。E 快照仍須依已核對的完整設定載入；F 重建檢查內容與 scope，追溯 namespace 及快照摘要，不替整合層選擇 run 的種子設定。完整 C 流程見 [協調器說明](orchestration.md)。

## 邏輯一致性與後續交易擴充

本版驗證的是「同一資料集查詢同一商品得到相同結果」與「回應中的商品 ID／文字來自選定 E 實體」。E 目前是可重建的唯讀快照，因此 F 尚未實作購買、扣款、扣庫存、退款或訂單狀態變更。

要達成「購買一件商品後，再查餘額會減少」，需要 E 增加同一互動範圍的交易狀態，將餘額、庫存及訂單一起原子更新，並處理重複請求、併發、失敗回滾與狀態版本。F 再依該版本的交易結果選 `success`、`insufficient_funds` 等分支；H／I 檢查各分支的回應。不能只選成功模板，就宣稱扣款已完成，也不能改寫目前 E 的生成產物後繼續使用其可重建性標記。

目前 E scope 尚未包含獨立的 environment／deployment／service／session 欄位。F 會核對政策與判定中的部署身份；資料隔離仍由現有 E 的 site／platform／version／hash／scenario／run 組合負責。整合層須為需要隔離的部署／互動配置不同 site 或 run，不能讓不同部署重用同一份 scope/config 並期待資料自動隔離。多環境或使用者互動正式擴充時，應一併擴充 E 的狀態身份與交易介面。

## 現成專案評估

| 專案 | 可用能力 | 上游授權 | 本版決定 |
| --- | --- | --- | --- |
| [rule-engine](https://github.com/zeroSteiner/rule-engine) | Python 型別化條件表達式與規則比對 | [BSD-3-Clause](https://github.com/zeroSteiner/rule-engine/blob/master/LICENSE) | 後續條件種類增加時可評估；本版明確相等比對即可，未引入 |
| [python-jsonlogic](https://github.com/Viicos/jsonlogic) | JSON 規則、型別檢查與運算子 | [MIT](https://github.com/Viicos/jsonlogic/blob/main/LICENSE) | 可用於政策工具化；本版沒有通用運算式需求，未引入 |
| [Open Policy Agent](https://github.com/open-policy-agent/opa) | 以 Rego 管理政策及集中決策 | [Apache-2.0](https://github.com/open-policy-agent/opa/blob/main/LICENSE) | 可供未來多服務共用政策；本版不增加獨立服務與 Rego 執行環境，未引入 |

本版及領域選擇擴充重用既有 Pydantic 與 PyYAML，沒有新增依賴或複製上述專案的程式碼。規則的可表達範圍由嚴格資料模型限制，無法透過政策執行任意 Python。領域處理器由受控程式碼註冊，政策不能指定任意模組動態載入。若未來採用外部規則引擎，仍須維持 B／D／E 身份核對、同優先序歧義拒絕及 H／I 驗證邊界。

## 使用套件與授權

下表依本次環境的 distribution metadata、隨附授權檔及上游資料核對。版本表示本次驗證快照，只有 `pyproject.toml` 已鎖定的版本才是安裝限制。

| 套件 | 本次版本 | 授權 | 用途 |
| --- | --- | --- | --- |
| [Pydantic](https://github.com/pydantic/pydantic/blob/main/LICENSE) | 2.14.3 | MIT | F 的嚴格政策、判定、準備結果及決策模型 |
| [PyYAML](https://github.com/yaml/pyyaml/blob/6.0.3/LICENSE) | 6.0.3 | MIT | 透過既有安全讀取器載入本地政策 |
| [Faker](https://faker.readthedocs.io/en/stable/#license) | 40.44.0 | MIT | E 生成及重新驗證合成資料 |
| [openapi-core](https://github.com/python-openapi/openapi-core/blob/0.19.5/LICENSE) | 0.19.5 | BSD-3-Clause | D／H／I 的規格與候選回應驗證 |
| [Werkzeug](https://github.com/pallets/werkzeug/blob/3.1.1/LICENSE.txt) | 3.1.1 | BSD-3-Clause | H／I 的 HTTP metadata adapter |
| [jsonschema](https://github.com/python-jsonschema/jsonschema/blob/main/COPYING) | 4.26.0 | MIT | 既有契約驗證依賴鏈 |
| [jsonschema-path](https://github.com/python-openapi/jsonschema-path) | 0.3.4 | Apache-2.0 | OpenAPI 引用與路徑解析依賴 |
| [openapi-schema-validator](https://github.com/python-openapi/openapi-schema-validator) | 0.6.3 | BSD-3-Clause | OpenAPI schema 驗證依賴 |
| [openapi-spec-validator](https://github.com/python-openapi/openapi-spec-validator) | 0.7.2 | Apache-2.0 | OpenAPI 文件驗證依賴 |
| [pytest](https://github.com/pytest-dev/pytest/blob/8.4.2/LICENSE) | 8.4.2 | MIT | 模組與整合測試，非 F 執行期依賴 |
| [HTTPX](https://github.com/encode/httpx/blob/0.28.1/LICENSE.md) | 0.28.1 | BSD-3-Clause | 現有 FastAPI 測試工具，非 F 執行期依賴 |

Python 標準庫的 `hashlib`、`hmac`、`json`、`datetime`、`secrets` 等隨 Python 提供，按 Python 的 PSF 授權及隨附聲明分發。此表涵蓋 F 直接使用與主要共用依賴，不是完整 SBOM；例如 Pydantic 的 `pydantic-core`、Faker 的 `tzdata` 仍須依實際安裝與打包版本管理。共用鏈的細節可參閱 [E 說明](synthetic.md)、[H 說明](composer.md) 及 [README 授權清單](../README.md#開源軟體模型與資料授權)。

分發包含第三方元件的程式、容器或安裝包時，保存相應 LICENSE、版權與免責聲明；Apache-2.0 元件若帶 NOTICE，按條款保留適用內容及修改標示。未採用的候選不構成本版本的套件依賴。此清單沒有替 Mirage_API 原始碼選定授權，也不代表已核准 API 規格、文件或模型權重的再散布。

## 有效性驗證

可先列出已註冊的領域，再明確選擇電商執行離線展示，不必啟動伺服器或提供外部判定：

```powershell
$env:PYTHONPATH = "$PWD/src"
.\.venv\Scripts\python.exe -m deception.scenarios --list-domains
.\.venv\Scripts\python.exe -m deception.scenarios --demo --domain ecommerce --output generated
```

目前 `--list-domains` 只列出 `ecommerce`。展示必須明確提供 `--demo --domain ecommerce`；省略領域或指定未知領域都不會默認電商。展示會在臨時目錄建立專用合成契約，串接真正的 B／D／E／F／H／I，驗證 `200 → 404 → 200`、E 未被改動以及兩次相同商品的 body 完全一致。完成後原子保存 `generated/scenarios/<報告SHA256>.json`，內含 `test_only: true`、領域、契約、政策、資料身份、三次決策、候選與 gate 結果。臨時來源的核准只供這個合成展示使用，不讀寫 repo 的 Medusa／WooCommerce 來源或審查狀態。展示不包含網路請求或正式 HTTP 主流程。

模組測試以臨時固定契約建立 B／D／E，檢查領域選擇、未知或不符領域拒絕、跨領域封套、判定來源、時效、請求關聯、身份、規則優先序與歧義，並檢查商品存在性、scope、資料完整性及準備結果被改動時的拒絕行為。測試用非商品處理器驗證共用引擎會依註冊領域分派；電商整合測試把 F 的同一份 `CompositionPlan` 交給 H，再以完全相同的候選 triple 交給 I，覆蓋 200／404 分支。

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_scenarios.py -q
```

臨時測試契約的核准只存在於測試目錄，不會改動 repo 的 Medusa 來源或部署審查狀態。測試通過證明本版選擇規則與交接有效；完整 Medusa body、真實平台行為、外部判定的接收認證與交易狀態仍須各自驗證。
