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
| M：HTTP 回送 | `src/deception/core/renderer.py`、`src/deception/api/pipeline.py` | [最終候選驗證與完整 HTTP 接入](renderer.md) |
| N：有限修正與備援 | `src/deception/core/recovery.py` | [同契約欄位修正、確定性備援與政策](recovery.md) |
| P：本機模型與共用工具 | `src/deception/llm/` | [Ollama backend、選模、預算與生命週期](llm.md) |
| PoC：示意契約驗證 | `mirage_validator/validator.py`、`registry.py` | [與正式 gate 隔離的驗證介面](poc.md) |
| 文件維護工具 | `tools/check_documentation.py` | [文件標準與檢查方法](documentation.md) |

推薦閱讀順序為 A／B → D／E／F → C／J／G／P → H／I → N／M。模型設定與真實展示證據見 [C/G 整合說明](orchestration.md)，整體進度及架構見 [專案 README](../README.md)。

M 已提供最終 HTTP 回送，N 已提供有限重新生成與精確同分支的確定性欄位備援；`deception.api.pipeline.create_app` 可由管理者注入可信判定 provider，串接 A→C/N→M。預設 A 及 B-only 入口維持診斷用途。外部判定來源認證接收器、集中設定服務及 E 交易更新尚未實作；也尚無 OCI 或真實 Medusa 部署對照。這些狀態列於專案 README。

新增或修改工具時，依 [文件與函式註解標準](documentation.md) 更新本索引，並執行文件檢查。模型權重授權、執行套件授權及來源規格權利分開記錄。
