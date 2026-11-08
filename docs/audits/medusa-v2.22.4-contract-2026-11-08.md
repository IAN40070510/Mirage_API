# Medusa v2.22.4 契約核實紀錄（2026-11-08）

## 第三輪：已完成靜態契約修補（最新狀態，2026-11-08）

> 本節覆蓋本文前述「尚未修補」的歷史記錄；**靜態規格已修補、執行期與部署驗證尚未完成**。

- 將 `inputs/platforms/medusa/openapi.yaml` 及 `inputs/sources/medusa/openapi.yaml` 更新為相同的 UTF-8 LF bytes；`info.version` 改回官方 `v2.22.4` tag 所含文件的原始值 **`2.22.3`**，`platform_version`（目標套件）保持 **`2.22.4`**。
- 依上游 `openapi.full.yaml` 逐操作補回 **51 個 `x-allowed` 區塊**；修補後比對：**51/51 與上游相同操作的區塊文字完全一致**。
- 依官方 `BaseRefund` 定義補回可選的 `idempotency_key: string`。
- 更新 D 來源與 I 未啟用 manifest 範本的 `source_revision` 為固定 commit `81edb06c323812773c9c0dcc4da2d9784f3b3319`，`source_url` 指向固定 commit 的官方 `openapi.full.yaml`。
- 本地修補後契約 SHA-256：`ced300a2de92b9829e6e600964588e894b760f07f8d79c1df657e1abe0529058`。D/I 規格 bytes 完全相同，`source.yaml` 與 `manifest.yaml.example` 記錄相同雜湊。
- 更新 `.gitattributes`，防止 Git 在 Windows 對 D 或 I 的 `openapi.yaml` 重新改寫換行。
- 新增 `tests/test_medusa_pinned_contract.py`（離線回歸測試）。該測試**已提交但尚未在 Python pytest 執行**；不可標示為已通過 CI。
- 本次對修補後內容執行額外靜態檢查：67 paths、77 operations、51/51 `x-allowed` 官方文字一致、710 個 `#/components/...` 引用均有本地定義，兩份規格內容完全一致。這是直接比對及引用存在性檢查，不等同完整 OpenAPI runtime validator 測試。
- `api-scope.json` 原始 `source_sha256` 是歷史 metadata，仍與官方完整 `openapi.full.yaml` 不同；沒有覆寫，以避免偽造其原始來源。

### 維持阻擋的事項

1. 重新執行 `pytest`、Profile Builder，以及正式 Validator 對目前契約的離線載入測試。
2. `x-allowed` 已保留於 OAS，但 Mirage_API 的執行時欄位／`fields` 策略仍需驗證；這不是單靠 OAS schema 就能保證的能力。
3. 實際 Medusa v2.22.4 測試部署、可信 origin、query 上下文與真實 HTTP 對照回應尚未核實。
4. 沒有正式核准的 `manifest.yaml`；D 的 `approved` 和 I 的 `approved` 均保持 `false`。不可將這份修補直接當成站點放行依據。
5. 為長期可重現維護，仍建議加入固定官方來源 → 篩選 operation → 依賴 schema closure → 規格檢查的自動化子集生成腳本；本輪已完成一次性修補，**沒有宣稱生成腳本已建立**。


> 審查結論：**尚不可啟用正式契約（BLOCKED）**。本文件只記錄已取得的證據與差異，不代表官方相容性認證。請勿將 `approved` 改為 `true` 或建立正式 `manifest.yaml`，直到下列條件均完成。

## 固定來源

- 上游專案：`medusajs/medusa`
- 目標 tag：`v2.22.4`
- tag 指向的 commit：`81edb06c323812773c9c0dcc4da2d9784f3b3319`（GitHub tags API）
- Release：2026-11-06 09:19:10 UTC；[官方 release](https://github.com/medusajs/medusa/releases/tag/v2.22.4)
- 上游 API Reference base：[store/openapi.yaml（固定 tag）](https://github.com/medusajs/medusa/blob/v2.22.4/www/apps/api-reference/specs/store/openapi.yaml)，blob SHA-1：`430bfa28072ed986c8d656512ee3c54f0bd76bdb`
- 上游逐操作規格：[specs/store/paths/（固定 tag）](https://github.com/medusajs/medusa/tree/v2.22.4/www/apps/api-reference/specs/store/paths)
- 目標部署版本、部署 origin、publishable API key、參考服務回應：**尚未提供**。

重要：上述上游 `openapi.yaml` 的 `info.version` **仍為 `2.22.3`**，本地子集兩份規格的 `info.version` 為 `2.22.4`。tag 與 API 文件版本文字不一致，不能直接把本地版本文字視為官方來源驗證證據。

## 已執行的比對

1. 本地 `inputs/platforms/medusa/openapi.yaml`：67 paths、77 method/path operations。
2. 上游固定 tag 的 `specs/store/paths/`：69 個路徑檔；本地 67 條路徑的對應檔案均存在。
3. 逐一讀取上述 67 個上游路徑檔，抽取各 operation 的 **method、operationId、已宣告 response status keys**，與本地 77 個 operation 比較：**77/77 一致；未發現缺少或多餘的本地 operation**。
4. 官方另有兩條路徑不在本地子集：`/store/search`、`/store/payment-collections/{id}/payment-sessions/{session_id}`。本地是 XGBoost inference 範圍選擇的子集，**不應據此推論完整 API 覆蓋**。
5. 上游逐操作檔中，**51 個 Store operations 存在 `x-allowed` 擴充欄位，但本地子集相同操作沒有保留**；包含 `GET /store/products`、`GET /store/products/{id}`、購物車及多個其他 Store 操作。
6. 抽樣檢視 `StoreProductResponse`、`StoreProduct`、`StoreCartResponse`、`StoreProductVariant` 的 schema 開頭／required：所見欄位相符；**未完成全部 schema、型別、`$ref`、response header、query 動態選欄及實際服務行為的逐位元／語意比較**。
7. 本地兩個 `openapi.yaml` 經 CRLF → LF 正規化後內容相同，但原始 bytes 與 SHA-256 不同：
   - `inputs/sources/medusa/openapi.yaml`：CRLF，SHA-256 `65b6917fb04c52d3a2394cabe8c391db8ebfa74e5aec336eb88069ed5e14ba0b`
   - `inputs/platforms/medusa/openapi.yaml`：LF，SHA-256 `69d267893f845e79c22cc9a235d3e98e34730a70a74885217de4a4ec8186a4ad`
   - `inputs/sources/medusa/source.yaml` 的 `spec_sha256` 對應 CRLF 檔。這是 D、I 契約身份需要先處理的問題，不能將其中一個雜湊直接貼給另一個檔案。
8. 既有 `input-audit.json` 記載 10 個成功狀態回應缺少 `content`；本次沒有完成所有這些回應是否有回應本文的官方／實際服務核對，仍不可自動補 schema。

## 尚未通過的核實項目（阻擋正式放行）

- [ ] 從上述固定 commit 取得、保存、校驗可重現的官方完整 OpenAPI，建立可稽核的原始規格與子集產生關係；釐清官方 `info.version: 2.22.3` 與套件 tag `v2.22.4` 的差異。
- [ ] 對照完整的 schema、`$ref`、required、狀態回應內容、header、授權／欄位白名單；決定保留並執行 `x-allowed` 的策略。**單靠 openapi-core 的基本契約檢查，不可當成動態 `fields` 選欄的完整行為保證**。
- [ ] 統一 D 與 I 所使用的規格原始 bytes／雜湊（或明確使用兩份可分別驗證的身份），並執行重建、載入與跨元件一致性測試。
- [ ] 指定實際 Medusa 部署的精確版本、origin、path 前綴、適用 `query_contexts`，完成可信部署綁定。
- [ ] 用固定版本參考服務及相同測試資料，收集正常、404、`fields`／locale、授權缺失等可重現樣本，比對實際 JSON 與 HTTP 行為。
- [ ] 維護者人工審查來源、版本、操作範圍及安全策略後，再建立正式 `manifest.yaml` 並決定 `approved: true`。

## 判定與下一次驗收

目前維持 `source.yaml: approved=false`、`manifest.yaml.example: approved=false`，不啟用正式 gate；預期未核准契約時應回 `unverifiable`，而非 `pass`。

完成上列阻擋項目後，測試最少應涵蓋：真實部署綁定 + 受支援操作的有效 200 → `pass`；故意變更型別 → `reject`；未知站點／來源未核准／未審查 query → `unverifiable`。此處是**驗收規劃，不是已執行的整合測試結果**。

## 範圍說明

本次透過 GitHub 連接器讀取本地 repo 和官方固定 tag 的原始文本，並執行結構摘要／雜湊比對；沒有部署或呼叫 Medusa 參考服務，沒有執行本專案 pytest，也未取得上游超大型 `openapi.full.yaml` 進行完整語意差異分析。**77/77 一致只適用 operation ID 和宣告 status keys，不代表整體 API 相容性。**

## 第二輪：官方完整 Store OpenAPI 結構比對（2026-11-08）

### 官方來源與版本身份

- 已由官方 `v2.22.4` Git tag（commit `81edb06c323812773c9c0dcc4da2d9784f3b3319`）取得 `www/apps/api-reference/specs/store/openapi.full.yaml`；Git blob SHA-1 `000dcd0fb6d124a9675e5168b49ef7b354ac8a19`。
- 讀取的上游完整檔案 UTF-8 內容 SHA-256：`ac76bf98207021e17455819ec9db5eee3742efa6172a76b4d83d67b06d97af4d`。
- `api-scope.json` 既有 `source_sha256` 為 `438ac1daa9b3d6e27944e05a553986dcc4a3f3dbde72dd4d3b978575d6eaf328`，**不等於**此固定 tag 的完整上游規格；在取得原始 `openapi.full.yaml` 與其產生流程前，不可聲稱此 metadata 已驗證官方來源。
- 官方 `packages/medusa/package.json` 在 `v2.22.4` 確實宣告版本 `2.22.4`；但同 tag Store API Reference `openapi.yaml`、`openapi.full.yaml` 的 `info.version` 是 `2.22.3`。交叉檢查 `v2.22.3` tag 的 Store API Reference `info.version` 為 `2.22.2`。這顯示文件版本文字存在一版落差，但**不因此推論部署相容性**。

### 核實方式與結果

讀入官方完整規格及本地 `inputs/platforms/medusa/openapi.yaml`，將 YAML 內容轉為結構樹後，依路徑／操作 ID 比對操作、參數、requestBody、response status、media type、Schema `$ref`、required、型別、限制、enum 等結構屬性。為避免文字與排版干擾，比對時排除 `description`、`summary`、`title`、`example(s)`、`externalDocs` 等說明性欄位與 `x-*` 擴充欄位；**`x-allowed` 另外逐一統計，不視為已通過**。比對器為此審查執行的離線結構檢查，非正式 Gate 的整合測試。

| 核實範圍 | 官方完整規格 | 本地子集 | 結果 |
| --- | ---: | ---: | --- |
| HTTP paths | 69 | 67 | 本地 67 條皆存在於官方 |
| HTTP operations | 79 | 77 | **77/77 核心結構一致** |
| `components/schemas` | 617 | 133 | **132/133 核心結構一致** |
| `components/responses` | 8 | 6 | **6/6 一致** |
| `components/securitySchemes` | 3 | 3 | **3/3 一致** |
| `components/examples` | 7 | 6 | **6/6 一致（排除說明性欄位）** |
| `x-allowed` | 52 個操作有此擴充（完整規格） | 0 | **子集對應的 51 個 Store operations 缺失** |

**唯一發現的核心 Schema 差異**：本地 `components/schemas/BaseRefund/properties/idempotency_key` 缺少官方定義 `type: string`。此欄位在官方 Schema 中並非 `required`；缺少宣告仍使子集不完整，不可聲稱全數一致。

**其他限制**：
- `x-allowed` 是實際限制 Store API `fields` 存取範圍的擴充資料（Medusa v2.21.0 起已有 strict allowed fields；詳見 [官方 release](https://github.com/medusajs/medusa/releases/tag/v2.21.0)）。現有 OpenAPI Schema gate **不會自動推導或執行此白名單**，必須由明確策略、已審查 query 情境與服務實測共同保證。不能僅把 `x-allowed` 放回 YAML 就宣稱安全檢查完整。
- 本地未收錄的 `/store/search` 和 `/store/payment-collections/{id}/payment-sessions/{session_id}` 是選擇性子集，應保持未支援，除非另行擴充且核實。
- 結構一致性不證明執行時的商品價格、外掛、授權、locale、`fields`、header、業務狀態與回應完全一致。

### 修復與核准前驗收（更新）

- [ ] 以官方固定 commit 的完整 `openapi.full.yaml` 為 **可重現的唯讀上游輸入**，建立子集生成工具；生成時保留 `x-allowed` 等必要行為擴充欄位，還原 `BaseRefund.idempotency_key`。
- [ ] 明確分離 `platform_version=2.22.4`（目標套件／部署版本）及上游文檔 `info.version=2.22.3`；不得篡改來源版本以假裝檔案是官方原始物。
- [ ] 對源規格與生成子集分別計算 SHA-256，保存固定 commit、來源 blob SHA、子集產物雜湊與產生程式版本；同步 D、I 用到的契約與更新快照。跨環境若需逐 byte 身份，先處理 CRLF/LF 差異。
- [ ] 新增自動回歸測試：77 個操作／133 個 schema 的核心映射、`x-allowed` 保留、`BaseRefund.idempotency_key`、無未知 `$ref`、格式 Gate 的 pass/reject/unverifiable 和非預期來源 fail-closed。
- [ ] 取得目標測試站點的已驗證部署身份與真實回應對照（包含正常、404、缺少 publishable key、`fields` 與其他已批准 query）。
- [ ] 維護者完成審查後才能批准來源與部署契約；目前 **維持 `approved=false`**。

本次已核對靜態規格，**沒有進行 Medusa 運行環境與正式 Gate 的動態測試、沒有修改現有 `openapi.yaml`／hash／批准設定，也沒有宣稱官方已完整相容**。

### CI 首輪失敗與結構位置修復（2026-11-08）

GitHub Actions 首輪 pytest 為 `179 passed, 1 failed`；失敗點為 `BaseRefund.properties.idempotency_key` 未找到。原因：上一輪文字修補誤將 `idempotency_key` 放到鄰近的 `BaseCartLineItem.properties`。已將欄位移回官方的 `BaseRefund.properties`，並同步更新 D/I 規格及 SHA-256。之前文件中的靜態文字存在性檢查不足以證明 YAML 結構正確；本次以 pytest YAML 解析回歸測試驗收。CI 重新執行結果須以最新 GitHub Actions run 為準。
