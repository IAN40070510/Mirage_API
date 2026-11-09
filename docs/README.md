# 工具說明文件索引

此索引按目前實作提供獨立入口。每份說明記錄功能、輸入輸出、設定與使用方式、驗證及授權；共用細節可交叉參閱，不能把規劃中的功能當成可用 API。

首次閱讀可先看 [README 架構總覽](../README.md#系統架構)；部署組裝、快取及錯誤分支詳見 [詳細架構與執行邊界](architecture.md)。

| 工具／介面 | 程式位置 | 說明文件 |
| --- | --- | --- |
| 共用模型與資料交換 | `src/deception/common/` | [嚴格型別、隔離範圍與通用資料投影](common-data.md) |
| 領域載入與註冊 | `src/deception/domains/assets.py`、`registry.py` | [領域選擇、資產與擴充介面](domains.md) |
| OWASP 分類與弱點目錄 | `src/deception/security/` | [版本化分類、領域映射與模擬邊界](owasp-design.md) |
| HTTP 請求入口 | `src/deception/api/` | [入口、標準化與 handler](ingress.md) |
| 平台識別 | `src/deception/discovery/` | [部署綁定與操作識別](identifier.md) |
| 任務協調器 | `src/deception/core/orchestrator.py` | [控制流程、受控工具及內部結果](orchestration.md) |
| Profile 工具 | `src/deception/profile_builder/` | [固定來源建置與查詢](profiles.md) |
| 領域資料供應介面 | 共用資料投影與 `src/deception/synthetic/` 相容入口 | [領域資料供應與舊介面](synthetic.md) |
| 電商合成資料工具 | `src/deception/domains/ecommerce/synthetic/` | [商品／變體生成、保存、驗證與查詢](../domains/ecommerce/docs/synthetic.md) |
| 情境工具 | `src/deception/scenarios/` | [領域選擇、規則及結果分支](scenarios.md) |
| 電商情境處理器 | `src/deception/domains/ecommerce/scenarios.py` | [商品查詢、模板及結果規則](../domains/ecommerce/docs/scenarios.md) |
| 內容生成工具 | `src/deception/generation/` | [欄位生成、schema、映射保護與快取](generation.md) |
| 回應組合工具 | `src/deception/core/composer.py`、`handoff.py` | [組合、序列化與契約驗證器交接](composer.md) |
| OpenAPI 契約驗證 | `mirage_validator/gate.py`、`api.py` | [部署契約、驗證結果與 HTTP API](gate.md) |
| 生成上下文 | `src/deception/generation/models.py` | [身份、資料及版本的關聯](context.md) |
| HTTP 回送 | `src/deception/core/renderer.py`、`src/deception/api/pipeline.py` | [最終候選驗證與完整 HTTP 接入](renderer.md) |
| 有限修正與備援 | `src/deception/core/recovery.py` | [同契約欄位修正、確定性備援與政策](recovery.md) |
| 本機模型與共用工具 | `src/deception/llm/` | [Ollama backend、選模、預算與生命週期](llm.md) |
| 隔離展示服務 | `src/deception/api/demo.py` | [展示輸入、模型選擇與呼叫方式](docker.md) |
| HTTP 一致性驗證工具 | `tools/verify_domain_api.py` | [領域 verifier 派送、檢查內容與報告](verification.md) |
| Docker 封裝 | `Dockerfile`、`compose.yaml` | [建置、啟動、持久化與部署限制](docker.md) |
| PoC：示意契約驗證 | `mirage_validator/validator.py`、`registry.py` | [與正式 gate 隔離的驗證介面](poc.md) |
| 文件維護工具 | `tools/check_documentation.py` | [文件標準與檢查方法](documentation.md) |

推薦先讀領域選擇、共用資料交換及 OWASP 目錄，再按 HTTP 請求入口／平台識別 → Profile／領域資料與情境 → 任務協調／生成／模型 → 組合與驗證 → 修正備援／HTTP 回送閱讀。電商的具體 input、規則與驗證均在 [電商領域包](../domains/ecommerce/README.md)；模型設定見 [任務協調與內容生成整合說明](orchestration.md)，整體架構見 [專案 README](../README.md)。

HTTP 回送器已提供最終 HTTP 回送，修正與備援工具已提供有限重新生成與精確同分支的確定性欄位備援；`deception.api.pipeline.create_app` 可由管理者注入可信判定 provider，串接 HTTP 請求入口→任務協調與修正備援→HTTP 回送器。預設 HTTP 請求入口及僅平台識別入口維持診斷用途。外部判定來源認證接收器、集中設定服務及合成資料工具交易更新尚未實作；也尚無 OCI 或真實 Medusa 部署對照。這些狀態列於專案 README。

新增或修改工具時，依 [文件與函式註解標準](documentation.md) 更新本索引，並執行文件檢查。模型權重授權、執行套件授權及來源規格權利分開記錄。
