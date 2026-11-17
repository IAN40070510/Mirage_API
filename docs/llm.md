# 本機模型連線、選擇與共用預算工具

`src/deception/llm/` 提供任務協調器的受控規劃、內容生成器的結構輸出、本機模型選擇與整體用量限制。它透過 Pydantic AI 連到受信任的 Ollama 端點；任務協調器流程見 [協調器說明](orchestration.md)，內容生成器的欄位政策與快取見 [內容生成工具](generation.md)。

## 工具分工與輸入輸出

| 工具 | 輸入 | 功能與輸出 |
| --- | --- | --- |
| `LLMConfig` | 管理者模型設定 | 嚴格核對執行模式、loopback URL、模型名稱、完整摘要、解碼及規劃模式 |
| `PydanticAIBackend` | `LLMConfig`、本次提示、註冊工具或輸出模型、`RunBudget` | 呼叫規劃或生成模型，回傳通過型別核對的 Pydantic 模型 |
| 模型選擇函式 | 已核對設定、明確模型名稱及可選摘要要求 | 只讀本機清單、選唯一已安裝模型，回傳固定摘要的設定副本 |
| `RunBudget` | `RunLimits` | 在同一 run 追蹤期限、模型請求、工具嘗試與回報 token |

模型工具選擇與輸出都受主機程式核對。模型不提供來源核准、不修改部署／契約身份，也不能自行宣告回應組合與契約驗證已通過。backend 只提供模型結果，正式 HTTP 輸出仍由後續 HTTP 回送器處理。

## 設定與預設模型

`configs/llm.yaml` 預設為本機已安裝的 **Foundation-Sec-8B-Reasoning Q4_K_M GGUF** 變體：

```yaml
schema_version: 1
execution_mode: local
base_url: http://127.0.0.1:11434/v1
model_name: hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF:Q4_K_M
model_digest: '77a78066847b2002fd602955667bd26857eb2cb751c6ed2e975c21b4a826b0a5'
planner_mode: structured_actions
temperature: 0.0
max_output_tokens: 1024
tasks:
  planner:
    max_output_tokens: 256
  generation:
    max_output_tokens: 256
  repair:
    max_output_tokens: 512
```

這是明確的 Reasoning 量化版本，不等同於基礎 Foundation-Sec-8B 或全部 Foundation 系列。digest 是完整權重身份，不能用 `ollama list` 顯示的短 ID 代替。Python 模型的 `max_output_tokens` 預設為 512，上面的基準設定為 1024；短欄位的 planner／generation／repair 實際分別為 256／256／512。這些是可驗證的請求設定，沒有宣稱較低額度已量測出品質或延遲改善。

`tasks` 只接受 `planner`、`generation`、`repair`。每個 `TaskModelConfig` 可覆寫 `temperature`、`max_output_tokens`，或同時提供 `model_name` 與 `model_digest` 選用另一個已核准本機模型；省略的值繼承基準設定，repair 不會自動繼承 generation 的覆寫。`config.for_task(name)` 回傳解析後副本。任務不能改 endpoint，也不能提供只有名稱或只有摘要的半份身份；cloud／空白模型名稱仍拒絕。`check_ready()` 在同一份 metadata 中核對所有任務的名稱、摘要及 remote 標記，不自動下載或任選模型。

尚未另行量測或核准較小／較強的模型，因此交付設定仍使用原 Foundation；有證據後可只替換所需任務的固定名稱與完整摘要。沒有加入未核對支援的 reasoning effort 或 verbosity 參數，也沒有以 prompt 假裝能停用 thinking。

| 設定 | 限制 |
| --- | --- |
| `execution_mode` | `local` 或 `test`；真本機模式不接受注入測試模型 |
| `base_url` | 僅支援明確 HTTP loopback `/v1`，拒絕帳密、query、fragment 及非本機位址 |
| `model_name` | 非空且無空白／控制字元；拒絕含 cloud 的名稱 |
| `model_digest` | 64 字元小寫十六進位 SHA-256 |
| `planner_mode` | `native_tools` 或 `structured_actions`；類別預設為前者，Foundation 設定明列為後者 |
| `temperature` | 0–1，預設 0.0 |
| `max_output_tokens` | 單次輸出上限 32–8192，與整個 run 的 token 額度分開 |
| `tasks` | 三種任務的本機模型／解碼覆寫；未設定時沿用原行為 |

程式依管理者設定選端點，不從訪客 header 或請求內容改選供應者。若採 SSH 反向通道讓雲端存取自架模型，程式端仍須連到其可見的 loopback 轉送埠；連線拓樸與維運需另行設定，這份模型設定不會自動建立通道。

## 規劃與生成模式

`native_tools` 使用 Pydantic AI 的原生函式工具與型別化輸出工具。名稱、參數及結果仍由已註冊工具表與輸出模型檢查；模型／伺服器實際是否正確回傳原生工具格式須個別驗證。

`structured_actions` 適用沒有原生工具能力的模型。存在 `read_contract` 時，主機在第一次推論前直接執行此必需讀取，將結果放入 `observations`，不再花一次推論選擇唯一合法動作。這次讀取仍計入工具預算、受同一期限及 64 KiB 結果大小限制；失敗時不發出模型請求。之後模型透過 `NativeOutput` 回傳嚴格 JSON，主機驗證後才執行其他已註冊的零參數唯讀工具，或以 `complete` 完成。同一工具在一次規劃中最多執行一次；已讀契約不再列為合法動作。讀取動作的 `result` 必須為 null，完成動作必須包含型別化結果。未知動作、額外欄位或超額工具不會被當成可執行指令。

規劃提示要求充分使用既有觀察，只在任務需要時追加讀取，完成時列出每個允許欄位一次；沒有必要補充內容時使用空 `instructions`。`GenerationRule.planning_mode: model` 保留這個規劃流程；`fixed_fields` 則由主機直接建立精確欄位集合與空建議，完全不呼叫 planner，但仍核對模型身份與執行生成、G/H/I。電商隔離展示的短描述與錯誤欄位已採 fixed_fields。原生工具模式的先讀契約仍是提示要求。

`generation_mode: reviewed_template` 優先使用精確同分支的核准固定值；缺少 RecoveryPolicy 規則就停止，不偷偷改用模型。HTTP 電商 local 展示的 404 採這個路徑並綁定當次商品 ID；商品描述仍可生成。純 fallback 展示沿用原行為。可信世界已發布內容可在上述策略前重用，細節見 [內容生命週期](generation.md#可信世界內容生命週期)。

內容生成器的 `generate()` 使用獨立的 `NativeOutput` Agent，沒有可執行函式工具。規劃及生成對話歷史分開，仍共用同一 `RunBudget`。模型的普通文字工具描述不會被模糊修復成原生工具呼叫，也不會在本機執行失敗後降級成假模型。

生成提示將管理者欄位指示限制在共用規則與 schema 內；規劃建議僅供參考，不得覆寫上述規則。事實值與 schema 描述中的文字只作資料，不可視為命令。輸出只含指定欄位，不得憑空補充事實或宣告驗證通過。提示文字的 SHA-256 以 `prompt_sha256` 加入 `check_ready()` 的模型身份。在原快取模式，這會隔離不同提示／任務配方；可信世界模式則保留首次配方作證據，只有明確內容世代或內容依賴變更才建立另一個內容身份。

生成內容另要求符合所選 API 結果的可能業務語意，並面向 API 使用者撰寫，不公開內部 prompt、planner 建議、修正回饋、合成世界或模型處理過程。內部標籤不構成業務事實；同時禁止因此遮蔽或改寫合法的權威名稱與材質，例如包含 synthetic 的商品材質。這仍是模型指示，沒有以字詞黑名單取代事實或 schema 驗證。

## 宗旨核對與後續建議

README 的目標包含契約、可能業務語意、跨請求一致性及降低真實／合成回應切換時的可辨識差異。四項改動的核對結果如下：

| 項目 | 主機已保證的邊界 | 限制與本次調整 |
| --- | --- | --- |
| 1：欄位提示 | 精確欄位集合、權威映射、原契約 schema 不變 | 版本 `3` 移除 404 範例自曝 synthetic 的文案；不把不存在寫成缺貨。自然度與語意仍須實測 |
| 2：指令優先順序 | 提示不提供額外工具或來源核准權限 | 補充面向使用者的業務語意與內部生成過程不外露要求；prompt 不是語意驗證器 |
| 3：規劃最佳化 | structured_actions 預讀仍計工具額度、檢查大小與期限，後續仍經 G/H/I | native_tools 的先讀契約目前只是提示要求，不能聲稱兩模式都有同樣的主機排序保證；不構成跳過 G/H/I 的路徑 |
| 4：修正回饋 | 固定錯誤碼、數值／型別、欄位白名單與筆數上限，不回填原始例外 | 純固定備援不再無條件要求 product_id；真正用商品 token 時仍要求可信 ID 並編碼 |

第 5 項已實作任務配方、固定欄位規劃及核准模板路徑，仍保留 Foundation 基準且未新增模型權重。接下來比較首次通過率、事實／情境正確率、自曝比例、冷／暖／快取端到端 p50／p95。`usage.tasks` 提供各任務請求數、回報 tokens 與推論時間，失敗無 token 回報時標記不完整；不把未知用量寫成已知零成本。短文案節省推論不代表真實／誘餌延遲已相似，不加入任意 sleep。這輪只有離線流程證據，沒有真模型品質或延遲結論。

第 6 項已實作選用的 `ContentLifecycle`：以可信 WorldScope、entity_version、content_epoch、契約／部署／run／情境及實際可見事實綁定內容；模型、prompt 與 planner guidance 只決定首次生成配方，同一內容身份不再因配方更新而覆寫。首次發布的配方與狀態摘要原子保存，模型前重用仍走本次 B/F/E、G/H/I 與最終 M 驗證。沒有可信生命週期時保持舊隔離鍵，不猜 session 或放寬 scope。這不自動整合 SessionWorld Store、World ReadAdmission 或 ResponseAdmission，部署者仍須使用其既有可信世界接法；見 [上下文](context.md)。

本次只做離線源碼／差異審查與可控模型／HTTP client 回歸；未執行真模型、正式 PostgreSQL、真實後端或 L3 銜接測試。隔離 demo 的 test_only、合成 ID／名稱與診斷端點仍會揭示測試環境，不能稱為正式部署隱蔽性驗證。現有 schema 通過也不能證明任意生成文字的業務語意或抗 prompt injection 能力。新增回歸位於 `tests/test_content_lifecycle.py`，涵蓋世界／實體／內容版次隔離、模型恢復、配方更新、固定模板、競爭發布、損毀拒絕與 HTTP provider；設定與實際請求額度另由 `tests/test_llm_backend.py` 驗證。

## 模型 API 與生命週期

| 函式／方法 | 功能、回傳及主要限制 |
| --- | --- |
| `LLMConfig.identity_fields()` | 回傳 provider、執行模式、完整模型身份、temperature、輸出額度及 planner mode，供追溯與快取使用 |
| `PydanticAIBackend(config, planner_model=None, generator_model=None)` | 本機模式建立無環境代理、無 redirect、無 SDK 自動重試的 client；test 模式要求兩個注入模型 |
| `await backend.check_ready(budget)` | 讀 `/api/tags` 與 `/api/version`，核對唯一模型、完整 digest、remote 標記及 runtime 版本，回傳模型身份 |
| `await backend.plan(prompt, tools, output_type, budget)` | 依選定模式規劃，回傳 `output_type`；工具只使用本次呼叫明確註冊的集合 |
| `await backend.generate(prompt, output_type, budget)` | 以 JSON Schema 原生輸出生成並重驗 `output_type`，不執行函式工具 |
| `await backend.generate_repair(prompt, output_type, budget)` | 使用 repair 任務配方生成，沿用同一 run 與修正上限 |
| `await backend.aclose()` | 冪等關閉自有 client；測試注入模型的其他資源由測試呼叫端管理 |

本機每次推論前後都重新核對權重摘要；任務協調器在發布前還會確認模型身份未變。若 tag 換權重或 metadata 含 remote model／host 標記，結果會被拒絕。metadata 每次讀取最多 1 MiB，backend 提示最多 128 KiB；內容生成器另有更小的提示限制。結構動作工具結果最多 64 KiB。

```python
from pathlib import Path

from deception.llm import LLMConfig, PydanticAIBackend
from deception.profile_builder.builder import read_yaml

config = LLMConfig.model_validate(read_yaml(Path("configs/llm.yaml").read_bytes()))
backend = PydanticAIBackend(config)
# 將 backend 注入 ContentGenerator，再交由任務協調器管理同一個 RunBudget。
# 應用程式結束時：await backend.aclose()
```

## 列出及選擇模型

CLI 使用 `deception.generation` 入口：

```powershell
$env:PYTHONPATH = "$PWD/src"
.\.venv\Scripts\python.exe -m deception.generation --list-models
.\.venv\Scripts\python.exe -m deception.generation --demo --domain ecommerce
.\.venv\Scripts\python.exe -m deception.generation --demo --domain ecommerce --model "qwen2.5-coder:7b"
```

第一個命令只列已安裝、未標示 cloud／remote 的模型與完整摘要，不需要 `--demo` 或 `--domain`。後兩個命令分別使用固定預設模型、明確選另一個完整名稱；也可加 `--model-digest <完整SHA256>` 核對指定摘要。模型選擇保留設定的 `planner_mode`；要用另一種規劃方式時，提供對應的 `--llm-config`。

| 選模 API | 行為 |
| --- | --- |
| `parse_local_models(metadata, config)` | 純解析：重驗設定、清單格式、完整摘要與名稱唯一性，過濾 cloud／remote，回傳排序的 `InstalledModel` tuple |
| `await list_local_models(config, transport=None)` | 只 GET 本機 `/api/tags`，總期限 15 秒、內容上限 1 MiB、無環境代理及 redirect；transport 僅供測試注入 |
| `await select_local_model(config, model_name=None, expected_digest=None, transport=None)` | 選唯一已安裝名稱並回傳設定副本；省略名稱時仍要求原設定 digest 不變 |

明確提供 `model_name` 時，選到的 metadata digest 會固定於該次設定；提供 `expected_digest` 則另核對呼叫端要求。操作只有 metadata GET，不下載模型、不選第一個相似名稱，也不自動接受預設 tag 的內容變更。可列出不等於該模型已通過生成品質驗證。

## 共用預算工具

`RunBudget` 由任務協調器建立，再傳給規劃與生成。切換 Agent、工具或有限修正不會重新起算。

| `RunLimits` | 預設 | 意義 |
| --- | --- | --- |
| `timeout_seconds` | 120 | 整個 run 的單調時鐘期限，允許 1–600 秒 |
| `max_model_requests` | 8 | 模型呼叫前計數，失敗呼叫也消耗額度 |
| `max_tool_calls` | 8 | 原生函式工具嘗試或主機執行的結構動作工具額度 |
| `max_input_tokens` | 32000 | 累積服務回報的輸入 token |
| `max_output_tokens` | 4096 | 累積服務回報的輸出 token |
| `max_repairs` | 1 | 任務協調器對允許生成／組合錯誤的重新生成上限 |

| 方法 | 功能 |
| --- | --- |
| `remaining()` | 回傳剩餘秒數，逾期拋 `BudgetExceeded("deadline_exceeded")` |
| `check()` | 檢查同一期限，供各主要階段前後使用 |
| `consume_request()` | 發出推論前計數；超限拋 `model_request_limit` |
| `consume_tools(count=1)` | 在工具執行前計入嘗試；超限拋 `tool_call_limit` |
| `consume_tokens(input_tokens, output_tokens)` | 累積非負整數用量；超限拋 `input_token_limit` 或 `output_token_limit` |
| `audit()` | 回傳用量及經過毫秒，不保存原始請求、提示或模型推理文字 |

`audit().tasks` 按 planner／generation／repair 保存 `requests`、`input_tokens`、`output_tokens`、`elapsed_ms` 與 `token_usage_complete`。任務時間只涵蓋模型 request 等待，不含 metadata、工具、H/I 或最終回送，不能直接當端到端延遲；最外層 `elapsed_ms` 才是 C run 經過時間。若 request 失敗、usage 缺失／無效或只得到零值，回報的 tokens 僅是已知部分，`token_usage_complete` 為 false，不能據此宣稱沒有花費。測試模式的 FunctionModel 用量仍是測試框架估算，不能當真模型或帳單資料。這些摘要不含原始 prompt 或例外文字。

原生工具回應中的未知名稱／無效參數也會先計工具嘗試；型別化輸出工具受模型請求額度約束。結構動作在 schema 或工具預算失敗時不執行工具。token 依服務回報核對，不承諾能在生成前精確預知 token 數。同步工作在主要階段前後核對期限；不能保證在任意同步函式中途強制中斷，但逾期結果不能取得已驗證候選。

## 錯誤與驗證

直接呼叫可能遇到設定／metadata 的 `ValueError`、`BudgetExceeded`、框架輸出錯誤、HTTP 錯誤或取消。任務協調器會轉為固定且不回顯憑證的失敗結果；它不把模型錯誤當成空模板或已驗證回應。明確配置的 [修正與備援工具備援](recovery.md) 可在已完成平台識別、規格及情境工具/合成資料工具/內容生成器核對後，以同分支固定欄位值重新經回應組合與契約驗證；這類結果標示 `source: fallback`，不冒充模型輸出，也不寫入模型內容快取。總預算、到期或取消不會觸發備援。`test` 模式明確標示測試模型，不會記為真本機模型。

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_llm_backend.py tests/test_model_selection.py tests/test_orchestrator.py -q
```

測試覆蓋工具／JSON 動作、輸出別名、未知工具、預算、metadata、摘要變更、cloud／remote 拒絕及模型選擇。真本機生成另用上方 `--demo` 命令，依報告的 `success`、`real_model`、checks、模型身份及各次契約驗證器結果判讀。Foundation 與 Qwen 的既有合成展示紀錄見 [任務協調與內容生成實測證據](orchestration.md#本次真本機模型展示證據2026-11-08)；它不代表所有列出模型或真實平台都已相容。

契約預讀的離線回歸另核對首次推論已收到契約、一次推論即可完成、契約不能重讀，以及工具超額、過大結果、逾期與讀取例外會在推論前停止。這些測試使用 `FunctionModel`，不構成真模型文案品質、tokens 或延遲改善的實測證據。

## 程式與模型授權

| 直接使用元件 | 授權 | 用途 |
| --- | --- | --- |
| [Pydantic AI slim](https://github.com/pydantic/pydantic-ai/blob/v2.66.0/LICENSE) | MIT | 受控 Agent、模型 wrapper、工具及結構輸出；目前鎖定 2.66.0 |
| [Pydantic](https://github.com/pydantic/pydantic/blob/main/LICENSE) | MIT | 嚴格設定及輸出模型 |
| [OpenAI Python SDK](https://github.com/openai/openai-python) | Apache-2.0 | 本機 Ollama 相容協定 client，不表示使用雲端推論 |
| [HTTPX2](https://github.com/pydantic/httpx2) | BSD-3-Clause | 有期限、無代理及 redirect 的 HTTP 傳輸 |
| [Ollama runtime](https://github.com/ollama/ollama/blob/main/LICENSE) | MIT | 獨立安裝的模型服務；本次未安裝 Ollama Python SDK |
| Python 標準庫 | PSF 及隨附聲明 | 非同步、時間、JSON、URL、簽章檢查等支援 |

完整版本、主要間接依賴及發布聲明見 [任務協調與內容生成授權表](orchestration.md#套件模型與資料授權)。Galah（Apache-2.0）僅作設計參考，未引入其執行環境或複製原碼；新增本文件沒有增加套件依賴。

預設 Foundation Reasoning 量化模型的權重條款須另外保存：官方 [NOTICE](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning/blob/main/NOTICE.md) 區分底層 **Llama 3.1 Community License** 與 Cisco 修改部分 **Apache-2.0**。不能把整份權重或其他 Foundation 變體簡化成程式套件的 MIT／Apache 授權。每次改選模型時，按該精確權重與 tokenizer 的 LICENSE／NOTICE 記錄；模型選擇工具不會替權重授權作自動核准。
