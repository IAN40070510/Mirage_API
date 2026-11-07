# Medusa v2.22.4 契約核實紀錄（2026-11-08）

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
