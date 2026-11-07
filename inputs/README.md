# Mirage_API 輸入資料

這些檔案是生成器各階段的輸入邊界。D 透過明確指定的 `sources/<platform>/source.yaml` 讀取固定規格並產生 Profile；`mirage_validator` 另外讀取 `platforms/*/manifest.yaml` 供正式 gate 使用。其餘生成流程草稿尚未自動載入。

| 類型 | 位置 | 目前用途 | 狀態 |
| --- | --- | --- | --- |
| D Source | `sources/<platform>/source.yaml` 與規格 | 建立及查詢可追溯 Profile | 已實作；輸出在根目錄 `generated/`，詳見 [D 用法](../docs/profiles.md) |
| HTTP Request | `http-requests/` | 描述要模擬的請求 | 草稿，尚未被 Orchestrator 讀取 |
| API Specification | `platforms/<platform>/openapi.yaml` | 回應契約與 operation | 已有 Medusa 子集；目前檔案仍是舊匯入資料 |
| Platform Profile | `platforms/<platform>/profile.yaml` | 平台版本、來源與生成限制 | 草稿，未載入 |
| Scenario Configuration | `scenarios/<platform>/` | 測試情境與預期狀態 | 草稿，未載入 |
| Synthetic State | `synthetic/<platform>/` | 可重現的合成資料狀態 | 草稿，未載入 |
| Generation Policy | `policies/<platform>/` | LLM 與工具生成限制 | 草稿，未載入 |

測試版本統一為 Medusa `v2.22.4`。API Specification、Platform Profile、Scenario Configuration、Synthetic State 與 Generation Policy 均以 `v2.22.4` 為基準。
