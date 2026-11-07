# Medusa 輸入檔案檢查

本資料夾的 `openapi.yaml` 由使用者提供的 `medusa-store-auth.openapi.yaml` 移入並改名，內容未修改；`api-scope.json` 原樣移入。

| 檔案 | 可用用途 | 檢查結果 |
| --- | --- | --- |
| openapi.yaml | OpenAPI 回應契約 | OpenAPI 3.0.0，可被 openapi-core 及本專案 PlatformRegistry 載入 |
| api-scope.json | 平台操作範圍與來源資訊 | 77 個 method／path／operation ID 與契約相符；目前執行程式不讀取此檔案 |
| manifest.yaml.example | 待完成的部署綁定範本 | 已填入實際規格雜湊，approved=false；不會自動載入 |
| input-audit.json | 本次檢查結果 | 記錄雜湊、覆蓋範圍及未確認事項 |

規格含 67 個路徑、77 個操作、133 個 components schemas；所有內部 `$ref` 均能解析，沒有外部 `$ref`。解析引用後有 529 個 response media schema 項目。規格檢查通過不代表已證明與官方服務完全一致。

## v2.22.4 測試版本與目前輸入的差異

本專案測試版本是 Medusa `v2.22.4`。輸入設定以 `source_revision: v2.22.4` 和 `test_target_version: 2.22.4` 表示本次測試版本。

## 尚不能啟用為官方完整一致性守門員的原因

- 現有 `openapi.yaml`、`api-scope.json` 與 `input-audit.json` 均已統一標示為 `v2.22.4`；完整官方規格與部署仍須完成核對。
- scope 的 `source_file` 指向 `openapi.full.yaml`，其中的 `source_sha256` 不等於目前子集規格的雜湊。它可能記錄上游完整檔案，不能拿來驗證目前子集；需提供原始完整檔案或官方不可變版本來源才能追溯。未改寫原始 scope metadata。
- `scope_meaning` 明確表示這是 XGBoost inference 選取的請求範圍，不是偵測準確率、訓練覆蓋或完整 API 相容性的證據。
- 10 個成功狀態回應沒有 `content`，詳見 audit 的 `responses_without_content`。這可能是空回應，也可能是規格未完整描述；本次未自行補寫。現有守門員對這些情況回 `unverifiable`。
- 尚未提供目標網站綁定與已核實的部署版本，也沒有官方參考服務的回應對照證據。此為 Medusa Store／Auth 子集，不涵蓋 Admin 或 WooCommerce。

## 下一步設定

核實官方來源與部署版本後，更新 manifest 範本的 `source_revision`、規格雜湊與 `base_urls`。`platform_version` 已設定為測試目標 `2.22.4`；`base_urls` 的 `https://shop.example` 是占位值，不是已知網站。

規格 paths 已包含 `/store` 與 `/auth`，部署 binding 應為網站 origin（或這兩者共同的實際部署前綴），不要再附加 `/store`。完成來源與適用範圍審查後才決定 approved 狀態並將檔名改成 `manifest.yaml`。查詢參數組合仍須獨立確認，不得靠 sample 推導完整契約。

本次檢查也確認：以未審查狀態暫存載入時，守門員會回 `contract_not_approved`，不放行。
