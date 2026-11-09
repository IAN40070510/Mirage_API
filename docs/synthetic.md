# 領域資料供應介面

共用協調器透過領域資料供應器取得已驗證資料，不在核心內生成商品、工單或其他特定實體。

| 介面 | 責任 |
| --- | --- |
| `load(config, data, expected_scope)` | 依該領域型別與規則核對隔離身份，生成或載入資料 |
| `facts(data, plan)` | 只投影允許模型看到的權威事實，不送完整請求或憑證 |
| `composition_data(data)` | 回傳 `CompositionData(scope, payload)`，讓組合器套用通用 Pointer 映射 |
| `from_files(config_path, dataset_path)` | 選用的檔案讀取能力，先完成領域驗證再回投影 |

資料來源、重建規則、實體關聯、資料版本及交易更新由各領域管理。通用 DTO 的型別驗證不代替來源認證或業務事實驗證；詳見 [共用資料交換](common-data.md)。

目前內建供應器為 [電商合成資料工具](../domains/ecommerce/docs/synthetic.md)，商品模型、Faker、價格、庫存及查詢規則均位於該領域套件。既有 `deception.synthetic` CLI 與匯入保持相容，新程式建議使用領域明確的入口。

共用組合 CLI 若要讀取領域資料檔，需明確提供 `--domain`、`--generation-config` 及 `--dataset`；不能把某領域資料重新標記成另一領域。未知領域不會回退電商。新增領域的步驟見 [領域包說明](domains.md)。

## 驗證與授權

`tests/test_generic_pipeline.py` 使用非商品的工單資料完整驗證協調、生成、映射、契約與回送；`tests/test_synthetic.py` 驗證電商供應器的既有一致性。新的供應器需自行提供資料隔離、型別、錯誤與生命週期測試。

共用介面沿用 Pydantic（MIT）與 Python 標準庫（PSF 及隨附聲明）；Faker（MIT）及商品規則的詳細授權在電商文件，沒有因共用化新增套件。交易狀態尚未提供通用實作，不能用模型內容快取代替。
