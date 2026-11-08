# P／LLM：模型連線、選擇與共用預算工具

`src/deception/llm/` 提供 C 的受控規劃、G 的結構輸出、本機模型選擇與整體用量限制。它透過 Pydantic AI 連到受信任的 Ollama 端點；C 流程見 [協調器說明](orchestration.md)，G 的欄位政策與快取見 [內容生成工具](generation.md)。

## 工具分工與輸入輸出

| 工具 | 輸入 | 功能與輸出 |
| --- | --- | --- |
| `LLMConfig` | 管理者模型設定 | 嚴格核對執行模式、loopback URL、模型名稱、完整摘要、解碼及規劃模式 |
| `PydanticAIBackend` | `LLMConfig`、本次提示、註冊工具或輸出模型、`RunBudget` | 呼叫規劃或生成模型，回傳通過型別核對的 Pydantic 模型 |
| 模型選擇函式 | 已核對設定、明確模型名稱及可選摘要要求 | 只讀本機清單、選唯一已安裝模型，回傳固定摘要的設定副本 |
| `RunBudget` | `RunLimits` | 在同一 run 追蹤期限、模型請求、工具嘗試與回報 token |

模型工具選擇與輸出都受主機程式核對。模型不提供來源核准、不修改部署／契約身份，也不能自行宣告 H/I 已通過。backend 只提供模型結果，正式 HTTP 輸出仍由後續 M 處理。

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
```

這是明確的 Reasoning 量化版本，不等同於基礎 Foundation-Sec-8B 或全部 Foundation 系列。digest 是完整權重身份，不能用 `ollama list` 顯示的短 ID 代替。Python 模型的 `max_output_tokens` 預設為 512，上面的交付設定另明列為 1024。

| 設定 | 限制 |
| --- | --- |
| `execution_mode` | `local` 或 `test`；真本機模式不接受注入測試模型 |
| `base_url` | 僅支援明確 HTTP loopback `/v1`，拒絕帳密、query、fragment 及非本機位址 |
| `model_name` | 非空且無空白／控制字元；拒絕含 cloud 的名稱 |
| `model_digest` | 64 字元小寫十六進位 SHA-256 |
| `planner_mode` | `native_tools` 或 `structured_actions`；類別預設為前者，Foundation 設定明列為後者 |
| `temperature` | 0–1，預設 0.0 |
| `max_output_tokens` | 單次輸出上限 32–8192，與整個 run 的 token 額度分開 |

程式依管理者設定選端點，不從訪客 header 或請求內容改選供應者。若採 SSH 反向通道讓雲端存取自架模型，程式端仍須連到其可見的 loopback 轉送埠；連線拓樸與維運需另行設定，這份模型設定不會自動建立通道。

## 規劃與生成模式

`native_tools` 使用 Pydantic AI 的原生函式工具與型別化輸出工具。名稱、參數及結果仍由已註冊工具表與輸出模型檢查；模型／伺服器實際是否正確回傳原生工具格式須個別驗證。

`structured_actions` 適用沒有原生工具能力的模型。模型透過 `NativeOutput` 回傳嚴格 JSON 動作，主機驗證後才呼叫已註冊的零參數唯讀工具。存在 `read_contract` 時先讀契約，之後讓模型選其他可用讀取或 `complete`；同一工具在一次規劃中最多執行一次。讀取動作的 `result` 必須為 null，完成動作必須包含型別化結果。未知動作、額外欄位或超額工具不會被當成可執行指令。

G 的 `generate()` 使用獨立的 `NativeOutput` Agent，沒有可執行函式工具。規劃及生成對話歷史分開，仍共用同一 `RunBudget`。模型的普通文字工具描述不會被模糊修復成原生工具呼叫，也不會在本機執行失敗後降級成假模型。

## 模型 API 與生命週期

| 函式／方法 | 功能、回傳及主要限制 |
| --- | --- |
| `LLMConfig.identity_fields()` | 回傳 provider、執行模式、完整模型身份、temperature、輸出額度及 planner mode，供追溯與快取使用 |
| `PydanticAIBackend(config, planner_model=None, generator_model=None)` | 本機模式建立無環境代理、無 redirect、無 SDK 自動重試的 client；test 模式要求兩個注入模型 |
| `await backend.check_ready(budget)` | 讀 `/api/tags` 與 `/api/version`，核對唯一模型、完整 digest、remote 標記及 runtime 版本，回傳模型身份 |
| `await backend.plan(prompt, tools, output_type, budget)` | 依選定模式規劃，回傳 `output_type`；工具只使用本次呼叫明確註冊的集合 |
| `await backend.generate(prompt, output_type, budget)` | 以 JSON Schema 原生輸出生成並重驗 `output_type`，不執行函式工具 |
| `await backend.aclose()` | 冪等關閉自有 client；測試注入模型的其他資源由測試呼叫端管理 |

本機每次推論前後都重新核對權重摘要；C 在發布前還會確認模型身份未變。若 tag 換權重或 metadata 含 remote model／host 標記，結果會被拒絕。metadata 每次讀取最多 1 MiB，backend 提示最多 128 KiB；G 另有更小的提示限制。結構動作工具結果最多 64 KiB。

```python
from pathlib import Path

from deception.llm import LLMConfig, PydanticAIBackend
from deception.profile_builder.builder import read_yaml

config = LLMConfig.model_validate(read_yaml(Path("configs/llm.yaml").read_bytes()))
backend = PydanticAIBackend(config)
# 將 backend 注入 ContentGenerator，再交由 C 管理同一個 RunBudget。
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

`RunBudget` 由 C 建立，再傳給規劃與生成。切換 Agent、工具或有限修正不會重新起算。

| `RunLimits` | 預設 | 意義 |
| --- | --- | --- |
| `timeout_seconds` | 120 | 整個 run 的單調時鐘期限，允許 1–600 秒 |
| `max_model_requests` | 8 | 模型呼叫前計數，失敗呼叫也消耗額度 |
| `max_tool_calls` | 8 | 原生函式工具嘗試或主機執行的結構動作工具額度 |
| `max_input_tokens` | 32000 | 累積服務回報的輸入 token |
| `max_output_tokens` | 4096 | 累積服務回報的輸出 token |
| `max_repairs` | 1 | C 對允許生成／組合錯誤的重新生成上限 |

| 方法 | 功能 |
| --- | --- |
| `remaining()` | 回傳剩餘秒數，逾期拋 `BudgetExceeded("deadline_exceeded")` |
| `check()` | 檢查同一期限，供各主要階段前後使用 |
| `consume_request()` | 發出推論前計數；超限拋 `model_request_limit` |
| `consume_tools(count=1)` | 在工具執行前計入嘗試；超限拋 `tool_call_limit` |
| `consume_tokens(input_tokens, output_tokens)` | 累積非負整數用量；超限拋 `input_token_limit` 或 `output_token_limit` |
| `audit()` | 回傳用量及經過毫秒，不保存原始請求、提示或模型推理文字 |

原生工具回應中的未知名稱／無效參數也會先計工具嘗試；型別化輸出工具受模型請求額度約束。結構動作在 schema 或工具預算失敗時不執行工具。token 依服務回報核對，不承諾能在生成前精確預知 token 數。同步工作在主要階段前後核對期限；不能保證在任意同步函式中途強制中斷，但逾期結果不能取得已驗證候選。

## 錯誤與驗證

直接呼叫可能遇到設定／metadata 的 `ValueError`、`BudgetExceeded`、框架輸出錯誤、HTTP 錯誤或取消。C 會轉為固定且不回顯憑證的失敗結果；它不把模型錯誤當成空模板或已驗證回應。明確配置的 [N 備援](recovery.md) 可在已完成 B/D/F/E/G 核對後，以同分支固定欄位值重新經 H/I；這類結果標示 `source: fallback`，不冒充模型輸出，也不寫入模型內容快取。總預算、到期或取消不會觸發備援。`test` 模式明確標示測試模型，不會記為真本機模型。

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_llm_backend.py tests/test_model_selection.py tests/test_orchestrator.py -q
```

測試覆蓋工具／JSON 動作、輸出別名、未知工具、預算、metadata、摘要變更、cloud／remote 拒絕及模型選擇。真本機生成另用上方 `--demo` 命令，依報告的 `success`、`real_model`、checks、模型身份及各次 I 結果判讀。Foundation 與 Qwen 的既有合成展示紀錄見 [C/G 實測證據](orchestration.md#本次真本機模型展示證據2026-11-08)；它不代表所有列出模型或真實平台都已相容。

## 程式與模型授權

| 直接使用元件 | 授權 | 用途 |
| --- | --- | --- |
| [Pydantic AI slim](https://github.com/pydantic/pydantic-ai/blob/v2.66.0/LICENSE) | MIT | 受控 Agent、模型 wrapper、工具及結構輸出；目前鎖定 2.66.0 |
| [Pydantic](https://github.com/pydantic/pydantic/blob/main/LICENSE) | MIT | 嚴格設定及輸出模型 |
| [OpenAI Python SDK](https://github.com/openai/openai-python) | Apache-2.0 | 本機 Ollama 相容協定 client，不表示使用雲端推論 |
| [HTTPX2](https://github.com/pydantic/httpx2) | BSD-3-Clause | 有期限、無代理及 redirect 的 HTTP 傳輸 |
| [Ollama runtime](https://github.com/ollama/ollama/blob/main/LICENSE) | MIT | 獨立安裝的模型服務；本次未安裝 Ollama Python SDK |
| Python 標準庫 | PSF 及隨附聲明 | 非同步、時間、JSON、URL、簽章檢查等支援 |

完整版本、主要間接依賴及發布聲明見 [C/G 授權表](orchestration.md#套件模型與資料授權)。Galah（Apache-2.0）僅作設計參考，未引入其執行環境或複製原碼；新增本文件沒有增加套件依賴。

預設 Foundation Reasoning 量化模型的權重條款須另外保存：官方 [NOTICE](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning/blob/main/NOTICE.md) 區分底層 **Llama 3.1 Community License** 與 Cisco 修改部分 **Apache-2.0**。不能把整份權重或其他 Foundation 變體簡化成程式套件的 MIT／Apache 授權。每次改選模型時，按該精確權重與 tokenizer 的 LICENSE／NOTICE 記錄；模型選擇工具不會替權重授權作自動核准。
