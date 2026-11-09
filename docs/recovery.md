# 有限修正與同契約備援

## 功能與責任

`src/deception/core/recovery.py` 提供主機控制的修正與備援工具，與 [任務協調器](orchestration.md)、[內容生成器欄位生成](generation.md) 共用同一次執行的身份、資料及預算。修正與備援工具的修正範圍是內容生成器已允許的欄位；明確備援則用管理者提供的欄位值替代失敗的模型內容，再重新通過回應組合與契約驗證。

| 路徑 | 實際責任 |
| --- | --- |
| 有限重新生成 | 對允許修正的內容失敗提供受限回饋，請內容生成器重新生成同一組欄位 |
| 明確備援 | 依精確契約與結果分支選一條 `FallbackRule`，使用其 `field_id → JSON value` |
| 最終核對 | 由任務協調器重新組合並驗證同一份候選，核對情境選擇工具決策、原請求與期限仍有效 |

修正與備援工具不改情境選擇工具的 outcome、status、method、path、media、scope 或合成資料工具權威映射，不放寬 schema，也不將 404 改成 200。管理者仍須明確選 `ecommerce` 等領域；工具不從商品名稱或模型文字猜測領域。

來源未核准、部署或契約身份不明、請求關聯不符、情境選擇工具判定到期、資料改變、總期限／預算耗盡及取消，都不能靠備援取得已驗證候選。備援本身不是預先簽發的 gate pass；每一次使用仍須重新經回應組合與契約驗證。

## 現成專案評估

| 專案 | 可重用能力 | 本次選擇 |
| --- | --- | --- |
| [既有 Pydantic AI](https://github.com/pydantic/pydantic-ai/tree/v2.66.0) | 型別化模型輸出及工具驗證，可要求模型重試 | 沿用模型介面，維持既有零隱藏重試設定；修正與備援工具的次數與總額度由主機程式控制 |
| [Tenacity](https://tenacity.readthedocs.io/en/stable/) | 依例外、結果、次數及時間條件重試 | 僅評估，未加入依賴。通用重試本身不核對本專案情境選擇工具 outcome、合成資料工具映射或回應組合與契約驗證同候選關係 |
| [既有回應組合與契約驗證](composer.md) | 明確映射、嚴格序列化與固定 OpenAPI 契約驗證 | 直接重用，每個修正與備援候選都重新驗證 |

因此本次在既有任務協調與內容生成上增加小型的政策與控制工具，沒有另外疊加模型重試框架，也沒有複製上游程式碼。

## 輸入、輸出與政策

修正與備援工具使用管理者載入的 `RecoveryPolicy`、本次 `CompositionPlan`、生成上下文的固定上下文、已選定的內容生成器規則及平台規格工具欄位 schema。`FallbackRule` 的身份必須對應本次領域、平台、版本、契約 SHA-256、operation、method、path、outcome、status、media，以及固定的內容生成器規則 ID、情境選擇工具/內容生成器政策摘要；不能只以相同 schema 或相似路徑替代。

備援值必須完整對應本次內容生成器規則的欄位集合，經 `generator.apply()` 檢查原始 JSON 值及 schema，再放入既有模板位置。額外欄位、缺欄位、錯誤型別、與合成資料工具映射重疊的目標及不存在的模板位置都不能使用。

`RecoveryPolicy` 預設停用備援。正式使用前，管理者需為自己的固定契約及每個允許結果建立政策；repo 的示意模板不能當成已核准的 Medusa／WooCommerce 商品契約。政策載入時的格式檢查也不代替本次回應組合與契約驗證。

修正與備援工具不回傳 HTTP Response。成功結果仍是任務協調器的 `PipelineResult(decision="validated")`；失敗時沒有可對外使用的候選。由 [HTTP 回送工具](renderer.md) 決定最終傳輸標頭，再以實際請求重新驗證。

## 設定與公開 API

`domains/ecommerce/inputs/policies/recovery.yaml` 提供可解析但預設 `enabled: false` 的範本。頂層欄位如下：

| 欄位 | 用途 |
| --- | --- |
| `schema_version` | 固定為 `1` |
| `domain` | 明確領域 ID，須與情境選擇工具/內容生成器相同 |
| `policy_id`、`policy_version` | 管理者維護的政策識別及版本 |
| `enabled` | 預設 `false`，只控制明確備援；未啟用時仍沿用既有有限修正 |
| `rules` | 最多 256 條備援規則；重複 ID 或完全相同選擇條件會拒絕 |

每條 `FallbackRule` 需提供：

| 欄位 | 用途 |
| --- | --- |
| `rule_id` | 修正與備援工具規則的唯一 ID |
| `generation_rule_id` | 對應目前內容生成器規則的 ID |
| `generation_policy_sha256`、`scenario_policy_sha256` | 實際內容生成與情境選擇工具的完整政策摘要 |
| `platform_id`、`platform_version`、`spec_sha256` | 與本次平台規格工具契約完全相同的身份 |
| `operation_id`、`method`、`path` | 精確 operation 與 path template |
| `outcome_id`、`status_code`、`media_type` | 情境選擇工具已選的結果、狀態與媒體；目前媒體只支援 `application/json` |
| `values` | 1–16 個 `field_id → JSON value`；使用時須恰好等於本次內容生成器欄位集合 |

政策不接受額外欄位或任意 JSON Patch。SHA-256 須為完整 64 字元小寫十六進位字串；不能使用模型短 ID、任意檔名或全零範例值代替實際政策摘要。`scenario_policy_sha256` 取自 `scenarios.policy_sha256`，`generation_policy_sha256` 取自 `generator.policy_sha256`；情境選擇工具/內容生成器政策變更後須同步審查修正與備援工具。

```python
from pathlib import Path

from deception.core.orchestrator import DeceptionOrchestrator
from deception.core.recovery import RecoveryPolicy, RecoveryTool
from deception.profile_builder.builder import read_yaml

policy = RecoveryPolicy.model_validate(
    read_yaml(Path("reviewed-recovery.yaml").read_bytes())
)
recovery = RecoveryTool(policy)
pipeline = DeceptionOrchestrator(
    identifier=identifier, profiles=profiles, scenarios=scenarios,
    generator=generator, composer=composer, gate=gate, recovery=recovery,
)
```

上述工具實例須由同一部署已核對的設定建立。省略 `recovery` 時，任務協調器使用不含備援政策的 `RecoveryTool()`，不會自動啟用 repo 範本。

| API | 功能與結果 |
| --- | --- |
| `RecoveryTool(policy=None)` | 重驗並封存獨立政策快照；沒有政策時只保留有限修正 |
| `recovery.policy` | 回傳政策副本或 `None`，外部修改不影響已封存規則 |
| `recovery.policy_sha256` | 回傳實際修正與備援工具政策摘要或 `None` |
| `select_fallback(plan, context, generation_rule_id)` | 精確選一條規則；停用或無匹配回 `None`，領域／scope 不符或歧義拋錯 |
| `apply_fallback(generator, plan, context, rule, schemas)` | 經內容生成器的同一 `apply()` 驗證固定值；回傳 `(plan, trace)` 或 `None`，不發布快取 |
| `can_repair_gate(result)` | 僅允許 `reject`／`valid: false` 且所有明確錯誤都位於 body 的契約驗證器結果 |
| `repair_feedback(field_ids)` | 只以固定錯誤碼、指示及已核准欄位 ID 產生回饋 |

這些修正與備援工具方法提供政策選取與內容檢查；完整流程仍應由任務協調器管理，獨立呼叫 `apply_fallback()` 不代表已完成回應組合與契約驗證或請求期限核對。

## 進入備援及失敗處理

任務協調器須先完成平台識別、規格及情境工具/合成資料工具、內容生成器白名單與局部 schema 檢查，才存在可使用的固定備援上下文：

| 失敗情況 | 處理 |
| --- | --- |
| 模型 `check_ready()` 或規劃失敗 | 總期限／預算與取消以外的失敗可直接嘗試已配置的同分支備援 |
| 內容生成器內容或回應組合器組合失敗 | 依 `max_repairs` 重新生成；耗盡後嘗試同分支備援 |
| 契約驗證器明確僅有 body 錯誤的 reject | 依同一修正上限重新生成；耗盡後嘗試同分支備援 |
| 契約驗證器 `unverifiable`、身份或 headers 等其他錯誤 | 直接停止，不使用備援掩蓋 |
| 請求／情境選擇工具決策／資料改變、快取發布或競爭候選驗證失敗 | 直接停止，不以備援代替 |
| 總期限／預算耗盡或取消 | 停止；取消向外傳遞 |

沒有適用備援時回 `generation_rejected`；備援欄位或回應組合器組合失敗回 `fallback_rejected`，備援未通過契約驗證器回 `fallback_not_passed`。這些是任務協調器內部結果碼；可選 HTTP 接入只回固定服務診斷，不公開底層例外。

成功備援 trace 明列 `source: fallback`、修正與備援工具政策摘要、備援規則 ID、內容摘要、欄位 ID 及 `cache_hit: false`，任務協調器另記錄失敗階段、使用量及 `release_deadline_monotonic`。該期限取情境選擇工具判定和共用總預算較早到期者，HTTP 回送器回送前仍須核對；修正與備援工具不延長有效期限。模型尚未可用時，模型身份明列 `provider: not_used`／`execution_mode: fallback`，不把純確定性備援記為真模型生成。

## 次數、生命週期與快取

修正次數沿用 `GenerationPolicy.limits.max_repairs`：預設 1，可設 0–2；首次生成不計入「修正」，所以最多有 `1 + max_repairs` 次生成嘗試。每次都沿用原 `RunBudget`，不能因重新生成、切換 Agent 或進入備援重新計算期限、模型請求、工具及 token 額度。

錯誤回饋只提供受控的驗證資訊，不將完整例外、原始請求 body、Cookie 或 Authorization 拼入模型提示。修正與備援工具不允許模型自行決定擴大欄位、換契約或宣告契約驗證器通過。

內容生成器收到非空修正回饋時略過既有快取讀取，確實重新生成；不會為了修正重複使用剛失敗的值。生成內容的發布競爭仍依原流程核對，儲存或競爭候選不可信時直接停止。

備援內容不發布到內容生成器的模型內容快取，避免一次模型故障讓管理者預設文字成為後續正常生成的永久勝出值。修正與備援工具不建立交易狀態、不修改合成資料工具快照，也不聲稱已完成扣款、退款或庫存變更。backend 與內容生成器快取的關閉仍由建立它們的應用程式負責。

## 驗證方式

在專案根目錄執行對應測試：

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_recovery.py tests/test_nm_integration.py tests/test_orchestrator.py -q
.\.venv\Scripts\python.exe tools/check_documentation.py
```

驗證重點包括無效生成後成功修正、次數耗盡後同分支備援、錯誤或歧義政策拒絕、404 維持 404、合成資料工具值不變、備援不污染模型快取，以及身份、到期、預算與取消不能繞過。可控模型測試用來確認控制流程；不代表所有真實模型、官方平台部署或業務交易已相容。

2026-11-09 已執行完整 `python -m pytest -q`：**546 項通過**，其中本次修正與備援工具/HTTP 回送器與 HTTP 接入新增 97 項測試案例。另已驗證停用的政策範本可解析，文件／函式註解檢查及 Python 語法編譯均通過。排程延遲不延長發布期限的回歸案例也包含於完整測試。

## 套件授權

| 使用元件 | 授權 | 用途 |
| --- | --- | --- |
| [Pydantic](https://github.com/pydantic/pydantic/blob/main/LICENSE) | MIT | 嚴格政策與欄位型別 |
| [jsonschema](https://github.com/python-jsonschema/jsonschema/blob/main/COPYING) | MIT | 重用內容生成器的 JSON 值及局部 schema 驗證 |
| [Pydantic AI slim 2.66.0](https://github.com/pydantic/pydantic-ai/blob/v2.66.0/LICENSE) | MIT | 重用既有模型介面；沒有新增另一套模型 SDK |
| [openapi-core 0.19.5](https://github.com/python-openapi/openapi-core/blob/0.19.5/LICENSE) | BSD-3-Clause | 透過既有回應組合與契約驗證完整候選 |
| Python 標準庫 | PSF 及隨附聲明 | 複製、摘要、JSON 與時間等支援 |

Tenacity 的 [Apache-2.0 授權](https://github.com/jd/tenacity/blob/main/LICENSE) 僅記錄評估對象；未安裝或採用該元件。共用直接及主要間接依賴、模型權重條款與發布聲明見 [任務協調與內容生成授權表](orchestration.md#套件模型與資料授權) 及 [回應組合器套件表](composer.md#使用的套件與授權)。此次修正與備援工具沒有新增第三方套件；模型、來源規格及合成資料的權利分開管理。
