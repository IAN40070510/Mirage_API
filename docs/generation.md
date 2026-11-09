# 內容生成工具

內容生成器的程式位於 `src/deception/generation/`。它依管理者明列的生成欄位、平台規格工具的局部回應 schema、合成資料工具的資料事實及情境選擇工具的結果，呼叫本機模型產生 JSON 片段。完整任務協調、內容生成與生成上下文流程見 [任務協調器說明](orchestration.md)，模型連線、選擇及預算見 [模型連線與 LLM 工具說明](llm.md)。

## 功能與責任

| 功能 | 實際行為 |
| --- | --- |
| 政策選擇 | 依領域、平台、版本、契約 SHA-256、operation、method、path、outcome、status 及 media 精確選一條規則 |
| 欄位生成 | 模型只回傳 `field_id` 對應的 JSON 值；目標 Pointer 由政策提供 |
| 事實保護 | 拒絕與政策 `protected_pointers` 或情境選擇工具的合成資料工具映射重複、父子重疊的目標 |
| schema 投影 | 從平台規格工具的精確回應擷取允許欄位的 schema，供解碼器及本地驗證使用 |
| 有限合併 | 僅替換既有模板位置，依 schema 驗證 JSON 值且不做隱含轉型；不改 scope、HTTP metadata 或合成資料工具映射 |
| 內容重用 | 使用獨立 SQLite 快取保存已驗證的衍生內容，不修改合成資料工具的 Faker 產物 |

內容生成器的結果是尚未發布的內容。任務協調器必須再交給回應組合器組合、契約驗證器驗證原樣候選，才能發布內容快取；`GeneratedContent` 本身不表示契約驗證器已放行。可選 [HTTP 回送器／完整 HTTP 接入](renderer.md) 已能回送最終重新驗證的候選；[修正與備援工具](recovery.md) 的同分支備援使用相同內容生成器欄位白名單，但不發布到模型內容快取。購買扣款、庫存更新及訂單交易仍屬後續合成資料工具狀態介面的工作。

## 輸入與輸出

| 輸入 | 內容與來源 |
| --- | --- |
| `CompositionPlan` | 情境選擇工具選定的 scope、操作、status、media、headers、body 骨架及合成資料工具映射 |
| `GenerationContext` | 任務協調器與生成上下文核對後的領域、請求指紋、部署、契約、資料摘要、情境與模型身份 |
| `OperationContext` | 平台規格工具的同平台／版本／契約／操作上下文 |
| `facts` | 資料供應器明確投影的唯讀事實，不是原始請求或完整合成資料工具 dump |
| `GenerationIntent` | 任務協調器模型提出的欄位 ID 與生成指示，仍須通過內容生成器白名單檢查 |
| `RunBudget` | 任務協調器建立、規劃與生成共同消耗的期限及用量預算 |

`generate()` 回傳 `GeneratedContent`：

| 欄位 | 意義 |
| --- | --- |
| `plan` | 只替換允許位置後的獨立回應組合器計畫 |
| `values` | 通過欄位 schema 檢查的 `field_id → JSON value` |
| `cache_key` | 綁定資料、契約、政策及生成設定的內容身份 |
| `cache_hit` | 這次內容生成器是否重用已發布內容 |
| `trace` | 規則、內容摘要、模型身份及本次 context ID |

## 設定

`domains/ecommerce/inputs/policies/generation.yaml` 是可解析但預設停用的任務協調與內容生成政策範本；它與合成資料工具使用的 `domains/ecommerce/configs/generation.yaml` 分開。啟用前須替換實際平台識別與規格工具身份、情境選擇工具 outcome、生成位置與完整回應模板。範本的精簡商品欄位不代表完整 Medusa body。

```yaml
schema_version: 1
domain: ecommerce
policy_id: product-content-generation
policy_version: '1'
prompt_version: '1'
enabled: false
# limits 與 rules 的完整格式見 domains/ecommerce/inputs/policies/generation.yaml。
```

每個 `GenerationRule` 必須明確配置契約身份、分支、保護位置與 `fields`。欄位設定如下：

| 欄位 | 用途與限制 |
| --- | --- |
| `field_id` | 模型可使用的欄位 ID；同規則唯一 |
| `target_pointer` | 非根層 RFC 6901 Pointer，必須指向 body 中已存在的位置 |
| `instruction` | 管理者提供的生成指示，1–1000 字元 |
| `cache_scope` | `entity` 或 `request`，預設 `request` |
| `entity_pointer` | `entity` 時必填，指向情境選擇工具封存的 `domain_context`；`request` 時不可提供 |

同一條規則的欄位一起原子發布，因此必須使用相同 `cache_scope` 及 `entity_pointer`。目前拒絕混合 request/entity 或不同實體引用。首版要求 `GenerationIntent.field_ids` 與規則的完整欄位集合一致，不能只生成其中一部分。

## 公開 API

| 函式／方法 | 功能、輸入與輸出 |
| --- | --- |
| `ContentGenerator(policy, backend, cache=...)` | 嚴格重驗政策並保存獨立快照；未提供 cache 時使用記憶體 SQLite |
| `generator.policy` | 回傳政策副本，外部修改不會改動已建立的生成器 |
| `generator.policy_sha256` | 唯讀的實際政策摘要 |
| `select_rule(plan, context)` | 核對政策啟用狀態、唯一操作／結果、scope、模板目標及合成資料工具映射，回傳一條規則 |
| `await generate(plan, context, profile, facts=..., budget=..., intent=..., feedback=None)` | 從已發布內容重用值，或呼叫 backend 生成，再驗證及合併；回傳暫存 `GeneratedContent` |
| `apply(plan, rule, schemas, values)` | 要求完整且無額外的欄位集合，依 schema 檢查各值，再替換允許的既有位置 |
| `ContentCache(path=None)` | 建立記憶體或指定檔案的 SQLite 內容快取 |
| `cache.get(key)` | 回傳內容副本或 `None`；摘要不符會拒絕讀取 |
| `cache.publish(key, values)` | 僅供完成回應組合與契約驗證檢查的任務協調器發布；同鍵競爭採先成功發布值 |
| `cache.close()` | 關閉自有資料庫連線；指定檔案路徑時保留已保存內容，預設記憶體快取的內容隨關閉消失 |
| `field_schema(profile, plan, pointer)` | 從同一平台規格工具契約的回應取得局部生成 schema |
| `digest(value)` | 固定 JSON 序列化後計算 SHA-256，拒絕 NaN 等不可重現值 |

`pointers.py` 的 `tokens()`、`overlap()`、`get()`、`replace()` 支援上述受限 Pointer 操作。陣列索引須是標準非負整數；不接受負值、前導零或 append，也不新增不存在的模板欄位。

一般整合建議交由任務協調器管理驗證及發布：

```python
from pathlib import Path

from deception.generation import ContentCache, ContentGenerator, GenerationPolicy
from deception.profile_builder.builder import read_yaml

policy = GenerationPolicy.model_validate(
    read_yaml(Path("reviewed-generation.yaml").read_bytes())
)
cache = ContentCache(Path("generated/generation/content.sqlite3"))
generator = ContentGenerator(policy, backend, cache=cache)
# 將 generator 注入 DeceptionOrchestrator；backend、cache 由應用程式關閉。
```

若獨立呼叫內容生成器，須先由任務協調器/平台規格工具/合成資料工具/情境選擇工具準備同一份 `base_plan`、`context`、`profile`、`facts` 及 `budget`：

```python
from deception.generation import GenerationIntent

rule = generator.select_rule(base_plan, context)
intent = GenerationIntent(field_ids=[field.field_id for field in rule.fields])
generated = await generator.generate(
    base_plan, context, profile, facts=facts, budget=budget, intent=intent,
)
# generated 尚未發布。由任務協調器執行回應組合與契約驗證、期限與請求關聯檢查後才處理快取。
```

## schema、快取與失敗處理

生成 schema 僅接受可明確處理的子集：基本型別、物件屬性、陣列項目、required、additionalProperties、enum/const、字串／數值／容器範圍及 format 等。內部引用有深度限制；不支援的複合 schema、循環、布林 schema 或引用鏈中的結構覆寫會拒絕。OpenAPI 的 nullable 會在局部生成視圖中轉為 JSON Schema 的可為 null 分支；原平台規格工具契約保持不變。

解碼器欄位使用 `WithJsonSchema` 完整替換局部 schema，避免通用 `JsonValue` 引用讓部分解碼器忽略 sibling 限制。模型輸出仍由 `Draft202012Validator`／`FormatChecker` 檢查原始 JSON 值，再由回應組合與契約驗證檢查完整候選。

內容鍵包含領域、環境／部署／服務、完整 scope、資料 namespace／摘要、實體或請求引用、規則、欄位 schema、情境選擇工具/內容生成器政策、body 骨架、事實投影、提示及模型身份。相同實體在相同規則與設定下可跨 request ID 重用；不同 operation／骨架不保證共用同一生成內容。

SQLite 唯一鍵讓競爭者取得先成功發布者的值。任務協調器會用勝出內容重新組合並經契約驗證器驗證；快取不保存可讓其他請求直接使用的 gate 通行結果，也不代替交易狀態。

修正與備援工具提供非空 `feedback` 要求修正時，內容生成器會略過既有快取讀取並重新呼叫模型，避免反覆讀到剛被部署 gate 拒絕的舊內容。新值仍須經完整回應組合與契約驗證及發布競爭核對；若既有勝出內容無法通過重驗，流程停止，不刪改舊快取或以備援掩蓋儲存／競爭問題。

直接 API 可能拋出 `ValueError`、schema 驗證錯誤、共用 `BudgetExceeded` 或模型／儲存錯誤。內容生成器不會自行刪欄位、轉型、補值或發布失敗內容。任務協調器/修正與備援工具對允許的欄位／組合錯誤及契約驗證器明確僅有 body 錯誤的 reject，依共用上限重新生成；耗盡後只可嘗試管理者配置、經相同回應組合與契約驗證重驗的同分支備援。其他契約驗證器不明結果、身份或 metadata 錯誤直接停止；完整條件見 [修正與備援工具失敗處理](recovery.md#進入備援及失敗處理)。

## 使用及驗證

真本機展示同時涵蓋任務協調、內容生成、回應組合及契約驗證：

```powershell
$env:PYTHONPATH = "$PWD/src"
.\.venv\Scripts\python.exe -m deception.generation --demo --domain ecommerce
```

共用入口依註冊領域派送展示；目前電商實作依預設 Foundation Reasoning 模型執行合成契約的 `200 → 404 → 200`，檢查資料不變、相同商品 body 一致、前兩次真生成及第三次內容快取。預設報告與 SQLite 位於 `generated/domains/ecommerce/generation/`，可用 `--output` 覆寫領域輸出根目錄。模型不存在、摘要不符或生成失敗時，命令回非零結束碼；歷史實測證據及適用範圍見 [任務協調與內容生成實測紀錄](orchestration.md#本次真本機模型展示證據2026-11-08)。

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_generation.py tests/test_orchestrator.py -q
```

上述測試主要使用可控模型驗證欄位、型別、引用、快取及交接邊界，與真模型展示分開判讀。通過合成契約不代表已完成真實 Medusa 部署審查。

## 套件與授權

| 使用元件 | 授權 | 用途 |
| --- | --- | --- |
| [Pydantic](https://github.com/pydantic/pydantic/blob/main/LICENSE) | MIT | 政策、上下文、生成值及解碼 schema 模型 |
| [jsonschema](https://github.com/python-jsonschema/jsonschema/blob/main/COPYING) | MIT | 局部 schema 及原始 JSON 值驗證 |
| [PyYAML](https://github.com/yaml/pyyaml/blob/6.0.3/LICENSE) | MIT | CLI 透過既有安全 loader 載入設定 |
| [SQLite](https://www.sqlite.org/copyright.html) | Public Domain | 保存已驗證衍生內容；Python `sqlite3` wrapper 另隨 Python 授權管理 |
| Python 標準庫 | PSF 及隨附聲明 | JSON、摘要、複製、路徑與鎖等支援 |

內容生成器透過既有 backend 使用 Pydantic AI（MIT）、相容 SDK（Apache-2.0）及 Ollama runtime（MIT）；精確版本與間接依賴見 [任務協調與內容生成授權表](orchestration.md#套件模型與資料授權)。模型權重另依所選模型的 LICENSE／NOTICE 管理。Galah（Apache-2.0）僅為設計參考，未引入其 Go runtime 或複製其程式碼；本次沒有因新增此文件而增加依賴。
