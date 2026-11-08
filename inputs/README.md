# Mirage_API 輸入資料

這些檔案是生成器各階段的輸入邊界。平台規格工具透過明確指定的 `sources/<platform>/source.yaml` 讀取固定規格並產生 Profile；`mirage_validator` 另外讀取 `platforms/*/manifest.yaml` 供正式 gate 使用。情境選擇工具與任務協調與內容生成政策由伺服器明確載入，下表標示的舊草稿不會自動載入。

| 類型 | 位置 | 目前用途 | 狀態 |
| --- | --- | --- | --- |
| 平台規格工具 Source | `sources/<platform>/source.yaml` 與規格 | 建立及查詢可追溯 Profile | 已實作；輸出在根目錄 `generated/`，詳見 [平台規格工具用法](../docs/profiles.md) |
| HTTP Request | `http-requests/` | 描述要模擬的請求 | 草稿，尚未被 Orchestrator 讀取 |
| API Specification | `platforms/<platform>/openapi.yaml` | 回應契約與 operation | 已有固定官方 commit 的 Medusa 子集，平台規格工具/契約驗證器 bytes 一致；實際部署仍未審查 |
| Platform Profile | `platforms/<platform>/profile.yaml` | 平台版本、來源與生成限制 | 草稿，未載入 |
| Scenario Configuration | `scenarios/<platform>/` | 測試情境與預期狀態 | 草稿，未載入 |
| 情境選擇工具 Scenario Policy | `policies/deception.yaml` | 明確領域、部署／操作白名單、可信判定來源 ID 及領域模板 | 已實作；範本選 `domain: ecommerce` 並停用，須替換實際身份並審查，詳見 [情境選擇工具用法與授權](../docs/scenarios.md) |
| 任務協調與內容生成 Generation Policy | `policies/generation.yaml` | 明確領域／契約分支、可生成欄位、保護位置及共用預算 | 已實作；範本停用，經審查後由 `GenerationPolicy` 載入，詳見 [任務協調與內容生成用法與授權](../docs/orchestration.md) |
| Synthetic State 草稿 | `synthetic/<platform>/` | 舊手寫示例 | 不載入；合成資料工具改讀根目錄 `configs/generation.yaml` 並生成 `generated/synthetic_data/`，詳見 [合成資料工具用法](../docs/synthetic.md) |
| 舊 Generation Policy | `policies/<platform>/` | 早期 LLM 與工具生成限制 | 草稿，未載入；現行任務協調與內容生成使用 `policies/generation.yaml` 格式 |

測試版本統一為 Medusa `v2.22.4`。API Specification、Platform Profile、Scenario Configuration、Synthetic State 與 Generation Policy 均以 `v2.22.4` 為基準。

模型位址、名稱及完整 digest 另位於根目錄 `configs/llm.yaml`，與合成資料工具的種子設定 `configs/generation.yaml` 分開。任務協調與內容生成真本機展示採隔離的合成契約與臨時政策，不讀寫 Medusa 的核准狀態；`FunctionModel` 測試與本機 Ollama 實際生成須分別記錄。
