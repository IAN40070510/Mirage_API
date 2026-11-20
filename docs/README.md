# 工具說明文件索引

想知道某個工具做什麼、需要哪些資料、怎麼使用，可以從下面的表格找到說明。各份文件也會交代設定方式、檢查方法、授權，以及哪些部分還沒有實作。

首次使用請先看[安裝與第一次使用](getting-started.md)；各節點分工見 [README 架構總覽](../README.md#系統架構)，部署組裝、快取及錯誤分支詳見 [詳細架構與執行邊界](architecture.md)。

專案自有程式採 Apache-2.0；Medusa 規格、OWASP 分類資料、套件及模型的個別授權與封裝聲明見 [專案授權與第三方材料](licensing.md)。

安全架構提案（**尚未實作／尚未驗收**）：[MIR-SEC-WORLD-001 World DB 信任邊界 ADR v0.2](adr/MIR-SEC-WORLD-001-world-db-trust-boundary.md)；[決策歷史、權威證據、交易鎖與負面測試索引](security/world-db/README.md)。狀態：Architecture Proposed／Weakness OPEN／MSDSS P2 NO-GO。

| 工具／介面 | 程式位置 | 說明文件 |
| --- | --- | --- |
| 獨立 HTTPX 請求摘要 | `src/deception/api/fingerprint.py` | [不依賴外部 Gateway 的客戶端摘要](trusted-session.md#獨立客戶端的請求摘要) |
| 請求與驗證結果 Audit | `src/deception/world/request_audit.py`、`migrations/016_request_observations.sql` | [假名化觀察、原子 Grant 關聯與故障處理](request-audit.md) |
| 共用事件提交與標準結果 | `src/deception/world/commit.py`、`event_store.py`、`migrations/015_world_operation_result_digests.sql` | [五類結果、原子事件與唯讀恢復](commit-results.md) |
| 提交結果固定互通向量 | `tests/fixtures/golden_vectors/commit_results.json`、`verify_commit_results.mjs` | [公開 JSON、Unicode 與摘要核對](commit-results.md) |
| JWS 固定拒絕碼與簽發向量 | `tests/fixtures/golden_vectors/trusted_session_errors.json`、`sign_trusted_errors.mjs` | [格式、clock、撤銷及 Replay 邊界](trusted-session.md) |
| 固定安全錯誤 Renderer | `src/deception/core/security_error.py` | [獨立模板、精確封套與請求綁定](security-errors.md) |
| 可信簽章金鑰撤銷 | `src/deception/security/key_revocation.py`、`migrations/014_trusted_key_revocations.sql` | [永久墓碑、Replay 排序與輪替](key-revocation.md) |
| 可信入口拒絕稽核 | `src/deception/security/ingress_audit.py`、`migrations/013_ingress_refusal_audit.sql` | [固定分類、資料最小化與故障處理](ingress-audit.md) |
| Profile 整體撤銷 | `src/deception/world/projection_registry.py`、`admission.py`、`postgres_admission.py` | [一般／緊急墓碑、控制邊界與驗證](profile-revocation.md) |
| Medusa 原生購物車映射 | `src/deception/domains/ecommerce/medusa_cart_http.py`、`medusa_cart_projection.py` | [原生路由、金額、匿名投影與隔離驗收](medusa-carts.md) |
| 原生資源時間 | `src/deception/domains/ecommerce/native_time.py` | [UTC 格式、單調時間與歷史拒絕](medusa-carts.md) |
| Gateway 部署組裝與已核准注入點 | `integrations/msdss/gateway_bootstrap.py` | [預設觀察政策、秘密檔與外部變更](gateway-bootstrap.md) |
| Gateway 原版框架相容性環境 | `integrations/msdss/requirements.compatibility-test.txt` | [隔離版本清單與驗收邊界](gateway-bootstrap.md) |
| 脫敏封裝與版本化資料庫更新 | `tools/package_runtime.py`、`tools/apply_migrations.py` | [操作邊界、輸入與驗證](runtime-operations.md) |
| 匿名合成購物車與訂單 | `src/deception/domains/ecommerce/carts.py`、`cart_http.py` | [cart.id、訪客狀態、下單與取消](carts.md) |
| 原生 Medusa 購物車範圍審查 | 固定來源與獨立 scoped Profile | [合成契約與原生接線的差異](medusa-cart-integration-review.md) |
| 合成庫存預留與取消 | `src/deception/domains/ecommerce/inventory.py` | [交易、冪等與結果恢復](inventory.md) |
| Session 世界映射與讀取准入 | `src/deception/world/session.py` | [Session、epoch 與 Watermark](world-runtime.md) |
| Medusa 身份與匿名唯讀分組 | `src/deception/security/medusa_identity.py`、`anonymous_identity.py` | [驗證介面與啟用範圍](trusted-session.md) |
| Trusted Session 部署與 Gateway | `src/deception/security/trusted_deployment.py`、`integrations/msdss/` | [JWS 接線、Replay 與限制](trusted-session.md) |
| 共用模型與資料交換 | `src/deception/common/` | [嚴格型別、隔離範圍與通用資料投影](common-data.md) |
| Synthetic World Runtime | `src/deception/world/` | [WorldScope、Snapshot、CAS 與 ResponseAdmission](world-runtime.md) |
| 實作進度追蹤 | `docs/implementation-progress.md` | [目前完成項目、驗證紀錄與下一步](implementation-progress.md) |
| Protocol 驗收證據 | README v1.1 與測試案例 | [已覆蓋範圍與尚未完成的 Gate](conformance-evidence.md) |
| 領域載入與註冊 | `src/deception/domains/assets.py`、`registry.py` | [領域選擇、資產與擴充介面](domains.md) |
| OWASP 分類與弱點目錄 | `src/deception/security/` | [版本化分類、領域映射與模擬邊界](owasp-design.md) |
| HTTP 請求入口 | `src/deception/api/` | [入口、標準化與 handler](ingress.md) |
| 安全檢查結果（可信攻擊判定）與接收程式 | `src/deception/scenarios/models.py`、`src/deception/api/pipeline.py` | [欄位意思、由誰提供、怎麼接收與出錯處理](attack-assessment.md) |
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

HTTP 回送器提供最終候選驗證及可選的一次發送准入，修正與備援工具提供有限重新生成與同分支確定性備援。`deception.api.pipeline.create_app` 可注入可信判定 provider；可信獨立服務另接 JWS、共享 Replay、Session 世界及可明確啟用的合成交易。預設診斷入口不自動開啟這些能力。隔離 Ubuntu Medusa、七項原生 Store 映射與 ARM64 映像已有驗收；正式 Gateway 部署、完整 Store 能力、集中設定服務及 L3 真實資料映射仍有獨立邊界，詳見[證據對照](conformance-evidence.md)。

新增或修改工具時，依 [文件與函式註解標準](documentation.md) 更新本索引，並執行文件檢查。模型權重授權、執行套件授權及來源規格權利分開記錄。
