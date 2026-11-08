# 工具說明文件索引

此索引按目前實作提供獨立入口。每份說明記錄功能、輸入輸出、設定與使用方式、驗證及授權；共用細節可交叉參閱，不能把規劃中的功能當成可用 API。

| 工具／介面 | 程式位置 | 說明文件 |
| --- | --- | --- |
| A：HTTP 請求入口 | `src/deception/api/` | [入口、標準化與 handler](ingress.md) |
| B：平台識別 | `src/deception/discovery/` | [部署綁定與操作識別](identifier.md) |
| C：任務協調器 | `src/deception/core/orchestrator.py` | [控制流程、受控工具及內部結果](orchestration.md) |
| D：Profile 工具 | `src/deception/profile_builder/` | [固定來源建置與查詢](profiles.md) |
| E：合成資料工具 | `src/deception/synthetic/` | [生成、保存、驗證與唯讀查詢](synthetic.md) |
| F：情境工具 | `src/deception/scenarios/` | [領域選擇、規則及結果分支](scenarios.md) |
| G：內容生成工具 | `src/deception/generation/` | [欄位生成、schema、映射保護與快取](generation.md) |
| H：回應組合工具 | `src/deception/core/composer.py`、`handoff.py` | [組合、序列化與 I 交接](composer.md) |
| I：OpenAPI 契約驗證 | `mirage_validator/gate.py`、`api.py` | [部署契約、驗證結果與 HTTP API](gate.md) |
| J：生成上下文 | `src/deception/generation/models.py` | [身份、資料及版本的關聯](context.md) |
| P：本機模型與共用工具 | `src/deception/llm/` | [Ollama backend、選模、預算與生命週期](llm.md) |
| PoC：示意契約驗證 | `mirage_validator/validator.py`、`registry.py` | [與正式 gate 隔離的驗證介面](poc.md) |
| 文件維護工具 | `tools/check_documentation.py` | [文件標準與檢查方法](documentation.md) |

推薦閱讀順序為 A／B → D／E／F → C／J／G／P → H／I。模型設定與真實展示證據見 [C/G 整合說明](orchestration.md)，整體進度及架構見 [專案 README](../README.md)。

目前 M 正式 HTTP renderer、外部判定接收認證、集中設定服務與 E 的交易更新尚未實作；通用 N 備援也尚未完成。C/G 的有限重新生成不等於完整 N。這些能力的狀態列於專案 README，沒有可直接啟用的工具介面。

新增或修改工具時，依 [文件與函式註解標準](documentation.md) 更新本索引，並執行文件檢查。模型權重授權、執行套件授權及來源規格權利分開記錄。
