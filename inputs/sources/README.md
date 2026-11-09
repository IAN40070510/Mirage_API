# 各領域的固定來源輸入

此處保留共用來源規則；實際 `source.yaml` 與規格應放在 `domains/<domain>/inputs/sources/<platform>/`。平台規格工具只讀取明確指定的本地檔案，不會自動抓取 `source_url`。

每個來源包包含同一資料夾的 `source.yaml` 與它指定的固定 `openapi.yaml`，記錄版本、不可變 revision、完整 SHA-256 與審查狀態。來源追溯及部署核准分開管理；雜湊一致只表示 bytes 一致，不能證明實際服務已對照。

目前領域來源入口：

| 領域 | 來源 |
| --- | --- |
| 電商 | [領域包](../../domains/ecommerce/README.md)、[Medusa 固定來源狀態](../../domains/ecommerce/inputs/platforms/medusa/README.md) |

新增領域時，不把自己的來源放回共用根目錄，也不重用其他領域的 `approved` 或部署身份。規格讀取及產物位置見 [平台規格工具說明](../../docs/profiles.md)。
