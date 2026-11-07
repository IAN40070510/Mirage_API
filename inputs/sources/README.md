# D 的來源輸入

每個 `source.yaml` 與它指定的 `openapi.yaml` 放在同一來源資料夾。D 僅讀取 CLI 明確指定的本地檔案，不會自動抓取 `source_url`。

`medusa/` 是從舊 `inputs/platforms/medusa/openapi.yaml` 複製的使用者提供快照。來源版本文字為 2.22.4，但尚未完成上游版本與部署比對，因此 `approved: false`。舊路徑暫供既有驗證器與文件使用；兩份檔案不自動同步。更新 D 輸入時，須在本目錄更新規格與 `spec_sha256`，並重新審查來源。

`woocommerce/` 目前只有來源設定範本，沒有真實固定版本規格；不會用 PoC 契約冒充官方輸入。

來源核准與網站部署綁定分別管理。D 不讀舊 `profile.yaml` 草稿，不寫入或核准驗證器的 `manifest.yaml`。詳見 [D 功能與用法](../../docs/profiles.md)。
