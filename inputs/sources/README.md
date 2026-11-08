# 平台規格工具的來源輸入

每個 `source.yaml` 與它指定的 `openapi.yaml` 放在同一來源資料夾。平台規格工具僅讀取 CLI 明確指定的本地檔案，不會自動抓取 `source_url`。

`medusa/` 已依官方 `v2.22.4` 固定 commit 的完整 OpenAPI 核對並修補 Store/Auth 子集。目標平台版本記為 `2.22.4`，官方規格的 `info.version` 另記為 `2.22.3`。此處規格與 `inputs/platforms/medusa/openapi.yaml` 的 bytes 相同，但尚未完成實際部署及行為對照，因此保留 `approved: false`。兩份檔案不會自動同步；更新來源時，須一併核對規格、完整 SHA-256 及部署契約身份，並重新審查。詳見 [固定來源狀態](../platforms/medusa/README.md)。

`woocommerce/` 目前只有來源設定範本，沒有真實固定版本規格；不會用 PoC 契約冒充官方輸入。

來源核准與網站部署綁定分別管理。平台規格工具不讀舊 `profile.yaml` 草稿，不寫入或核准驗證器的 `manifest.yaml`。詳見 [平台規格工具功能與用法](../../docs/profiles.md)。
