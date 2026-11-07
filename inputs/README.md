# Mirage_API 輸入資料

這些檔案是生成器各階段的輸入邊界。只有 `mirage_validator` 目前會讀取已核准的 `inputs/platforms/*/manifest.yaml`；其餘檔案是生成流程的資料草稿，現階段不會被程式自動載入。

| 類型 | 位置 | 目前用途 | 狀態 |
| --- | --- | --- | --- |
| HTTP Request | `http-requests/` | 描述要模擬的請求 | 草稿，尚未被 Orchestrator 讀取 |
| API Specification | `platforms/<platform>/openapi.yaml` | 回應契約與 operation | 已有 Medusa 子集；目前檔案仍是舊匯入資料 |
| Platform Profile | `platforms/<platform>/profile.yaml` | 平台版本、來源與生成限制 | 草稿，未載入 |
| Scenario Configuration | `scenarios/<platform>/` | 測試情境與預期狀態 | 草稿，未載入 |
| Synthetic State | `synthetic/<platform>/` | 可重現的合成資料狀態 | 草稿，未載入 |
| Generation Policy | `policies/<platform>/` | LLM 與工具生成限制 | 草稿，未載入 |

`v2.22.4` 是來源 repository tag；官方 Store OpenAPI 入口檔的 `info.version` 為 `2.22.3`。兩者必須分開保存，直到完整規格、commit、hash 與目標部署完成核對。
