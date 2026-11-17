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
prompt_version: '3'
enabled: false
# limits 與 rules 的完整格式見 domains/ecommerce/inputs/policies/generation.yaml。
```

每個 `GenerationRule` 必須明確配置契約身份、分支、保護位置與 `fields`。欄位設定如下：

規則另可設定 `planning_mode: fixed_fields`，由主機直接選完整欄位集合；預設 `model` 保留模型規劃。`generation_mode: reviewed_template` 使用精確同分支的啟用 RecoveryPolicy 固定值，不呼叫模型；沒有核准值就拒絕。預設 `model` 保留生成。HTTP 電商 local 展示以固定欄位規劃商品描述，404 則使用核准且綁定請求 ID 的固定訊息。CLI 真模型展示仍生成兩個分支以驗證模型能力，不能把兩種展示的模型次數混算。

`fact_keys` 可列出領域 `facts` 字典的實際鍵，例如 `[/product/id, /product/title]`；這裡是字典鍵，不是對 facts 重新解讀 JSON Pointer。只有列出的事實會進入 planner 的 read_facts、生成提示與內容依賴；省略時使用全部 facts，缺少指定鍵就拒絕，不能默默忽略依賴。管理者必須完整列出任務所需事實，不將未提供的資料視為可自由發揮的內容。

| 欄位 | 用途與限制 |
| --- | --- |
| `field_id` | 模型可使用的欄位 ID；同規則唯一 |
| `target_pointer` | 非根層 RFC 6901 Pointer，必須指向 body 中已存在的位置 |
| `instruction` | 管理者提供的生成指示，1–1000 字元 |
| `cache_scope` | `entity` 或 `request`，預設 `request` |
| `entity_pointer` | `entity` 時必填，指向情境選擇工具封存的 `domain_context`；`request` 時不可提供 |

同一條規則的欄位一起原子發布，因此必須使用相同 `cache_scope` 及 `entity_pointer`。目前拒絕混合 request/entity 或不同實體引用。首版要求 `GenerationIntent.field_ids` 與規則的完整欄位集合一致，不能只生成其中一部分。

電商範本與隔離展示的提示版本為 `3`：商品描述要求一個面向 API 使用者、20–80 字元（含空白與標點）的英文句子，只使用明列事實；不能從商品名稱推定功能、效益、材質、庫存、價格或能力。事實不足時使用中性描述，資料值中的命令不得執行。404 訊息表示本情境找不到指定商品，不能改寫成缺貨、暫時不可用或權限不足；範例值為 `The requested product was not found.`。不得將內部合成、情境、展示或生成過程寫成對外業務說明，也不得因此修改權威事實中的合法名稱或材質。展示與範本共用這些語意規則，HTTP 展示沿用同一政策建立函式。

這項文案調整對應 README 的契約、可能業務語意與連續性宗旨，不把內部生成語境當成產品功能。HTTP 展示的預設固定描述另改為 `See the product details for more information.`；`test_only` 診斷、合成商品 ID／名稱及展示文件仍明確標示測試用途，不把隔離 demo 偽裝成正式服務。這些標記表示目前 demo 本身仍可被辨識，不能因提示改寫宣稱已完成真實回應銜接。

20–80 字元目前是提示要求；隔離合成契約仍維持原本 10–120 字元的 schema，因此通過 schema 不代表符合較窄的文字要求，也不代表語意正確。本次沒有修改正式平台契約或加入語意評分器。稀少事實、模糊名稱、資料內指令及不存在／缺貨的區分，仍須用真本機模型評估；離線流程測試無法證明模型會遵守提示。共用生成提示的優先順序、摘要與快取隔離見 [模型工具](llm.md#規劃與生成模式)。

## 公開 API

| 函式／方法 | 功能、輸入與輸出 |
| --- | --- |
| `ContentGenerator(policy, backend, cache=...)` | 嚴格重驗政策並保存獨立快照；未提供 cache 時使用記憶體 SQLite |
| `generator.policy` | 回傳政策副本，外部修改不會改動已建立的生成器 |
| `generator.policy_sha256` | 唯讀的實際政策摘要 |
| `select_rule(plan, context)` | 核對政策啟用狀態、唯一操作／結果、scope、模板目標及合成資料工具映射，回傳一條規則 |
| `await generate(plan, context, profile, facts=..., budget=..., intent=..., feedback=None)` | 從已發布內容重用值，或呼叫 backend 生成，再驗證及合併；回傳暫存 `GeneratedContent` |
| `apply(plan, rule, schemas, values)` | 要求完整且無額外的欄位集合，依 schema 檢查各值，再替換允許的既有位置 |
| `cache_binding(plan, context, profile, facts)` | 核對完整上下文、規則與欄位依賴，回傳規則、schemas、事實投影及內容鍵 |
| `cached(plan, context, profile, facts=..., budget=...)` | 僅對可信世界模式讀取已發布內容並驗欄位；回傳 `GeneratedContent` 或 `None`，不提供本次 gate pass |
| `ContentCache(path=None)` | 建立記憶體或指定檔案的 SQLite 內容快取 |
| `cache.get(key)` | 回傳內容副本或 `None`；摘要不符會拒絕讀取 |
| `cache.publish(key, values)` | 僅供完成回應組合與契約驗證檢查的任務協調器發布；同鍵競爭採先成功發布值 |
| `cache.get_entry(key)` | 讀取世界內容的值與首次配方封套，驗整份摘要；損毀就拒絕 |
| `cache.publish_entry(key, values, provenance)` | 在獨立資料表原子發布值與首次證據，同鍵競爭回傳勝出封套 |
| `cache.close()` | 關閉自有資料庫連線；指定檔案路徑時保留已保存內容，預設記憶體快取的內容隨關閉消失 |
| `field_schema(profile, plan, pointer)` | 從同一平台規格工具契約的回應取得局部生成 schema |
| `digest(value)` | 固定 JSON 序列化後計算 SHA-256，拒絕 NaN 等不可重現值 |

`pointers.py` 的 `tokens()`、`overlap()`、`get()`、`replace()` 支援上述受限 Pointer 操作。陣列索引須是標準非負整數；不接受負值、前導零或 append，也不新增不存在的模板欄位。

`apply()` 在所有欄位驗證成功後才開始替換獨立計畫的值。局部 schema 失敗會拋出 `deception.generation.models.GeneratedFieldValidationError`（`ValueError` 子類別），含至多 16 筆受控 `FieldViolation`；例外訊息固定，不包含生成值。`FieldViolation` 只描述欄位 ID、固定限制碼與適用的數值或 JSON 型別，供 [有限修正回饋](recovery.md#次數生命週期與快取) 使用。完整欄位集合錯誤或缺少可信結構資訊的其他失敗仍採泛用回饋，不從原始例外推導內容。

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

上述為未注入 `ContentLifecycle` 的相容模式；模型／政策／prompt 變更仍隔離快取。啟用可信世界模式時，改用下節的穩定內容身份，不沿用或遷移舊 `content` 資料表的值。

SQLite 唯一鍵讓競爭者取得先成功發布者的值。任務協調器會用勝出內容重新組合並經契約驗證器驗證；快取不保存可讓其他請求直接使用的 gate 通行結果，也不代替交易狀態。

修正與備援工具提供非空 `feedback` 要求修正時，內容生成器會略過既有快取讀取並重新呼叫模型，避免反覆讀到剛被部署 gate 拒絕的舊內容。新值仍須經完整回應組合與契約驗證及發布競爭核對；若既有勝出內容無法通過重驗，流程停止，不刪改舊快取或以備援掩蓋儲存／競爭問題。

直接 API 可能拋出 `ValueError`、schema 驗證錯誤、共用 `BudgetExceeded` 或模型／儲存錯誤。內容生成器不會自行刪欄位、轉型、補值或發布失敗內容。任務協調器/修正與備援工具對允許的欄位／組合錯誤及契約驗證器明確僅有 body 錯誤的 reject，依共用上限重新生成；耗盡後只可嘗試管理者配置、經相同回應組合與契約驗證重驗的同分支備援。其他契約驗證器不明結果、身份或 metadata 錯誤直接停止；完整條件見 [修正與備援工具失敗處理](recovery.md#進入備援及失敗處理)。

## 可信世界內容生命週期

`ContentLifecycle(world_scope, entity_version, content_epoch)` 是伺服器組裝層提供的內容身份。`world_scope` 使用既有 WorldScope 的 environment、deployment、session、world_generation_id；`entity_version` 是可信實體版次，不能把每次都增加的全域 snapshot version 當成未變實體的版次；`content_epoch` 是管理者明確切換內容配方的版次。環境／部署必須與本次 GenerationContext 相同。不同 Session、世界 Generation、實體版次或 content_epoch 不會借用舊內容。

```python
from deception.generation import ContentLifecycle

# 以下資料必須來自可信 Session/World 組裝層及本次有效的 world read，不能取訪客自稱的 header。
lifecycle = ContentLifecycle(
    world_scope=verified_world_read.snapshot.scope,
    entity_version=verified_entity_version,
    content_epoch=approved_content_epoch,
)
result = await pipeline.run(
    request, verified_assessment, runtime=trusted_runtime,
    generation_config=checked_e_config, dataset=checked_e_dataset,
    content_lifecycle=lifecycle,
)
```

生命週期內容鍵仍保留領域、環境／部署／服務、完整 DatasetScope（含契約 hash、scenario、run）、WorldScope、實體／請求引用、欄位目標、schemas、規則身份、情境政策 hash 及實際投影 facts。只有原始全域 state／namespace、body 骨架及生成配方改列為首次發布證據，而非每次讓內容失效的因素。每次請求仍從本次資料組合權威欄位並驗證，不拿舊 body、價格或 gate pass 代替。

同一內容身份下首次通過 H/I 的值與 provenance 原子保存於 SQLite `content_entries`。provenance 記錄原模型／任務配方、prompt／policy 版本與 hash、planner guidance hash、原狀態／namespace 和骨架摘要；固定模板或備援則保存來源與核准政策證據。不同模型、prompt、planner 建議或產生策略不會覆寫既定文字。若希望新文案，必須由可信組裝層更新 content_epoch；這個內容切換不是 WorldStore 的 Generation Cutover 或發送授權，不得混用。

模型前命中時，C 已完成 B/F/E 與本次規則／facts 核對；G 重新驗欄位，C 再組合並驗 H/I、期限與請求，M 最後重驗 HTTP。此時不要求模型可用，模型請求數為 0，trace.model 明列 `provider: not_used`、`execution_mode: cache`，原模型位於 generation.provenance。首次使用核准備援／模板也固定為該世界的內容，模型恢復後不突然替換；舊模型配方快取不會因此被污染。

快取損毀、依賴不明或既定內容未通過目前 gate 時停止，不能在相同身份下重生另一份內容掩蓋問題。競爭發布若採不同勝出值，必須重新組合並驗 I；值與原配方永遠一起保存。不能把快取摘要當作防本機寫入者竄改的簽章或 World Admission。

此功能不會驗簽 Session、不自行取得 WorldSnapshot、不消費 World ReadAdmission 或建立 ResponseAdmission。呼叫端必須使用既有可信世界與發送流程，核對當前 Session／epoch、world 期限與撤銷，再注入本次綁定；不能把格式正確的 ContentLifecycle 當作授權。HTTP 接法見 [上下文](context.md)。

世界內容紀錄目前沒有自動 GC／LRU。不能因一般快取 TTL 到期就刪掉仍有效世界的既定文案，否則下次生成會破壞連續性；退役世界的儲存清理與容量管理須由部署層依已核對的世界生命週期處理。這個 SQLite 紀錄也不提供跨多節點的 WorldStore 交易或發送授權保證。

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
