# 共用情境選擇工具

共用引擎核對請求、可信判定關聯、部署與契約身份，依管理者規則選擇唯一情境，交由已註冊領域的 `prepare`／`resolve` 決定業務結果。核心不假設商品、GET 或 200／404。

## 輸入、輸出與分工

`DomainPolicy` 提供 domain、政策版本、可信來源 ID、有效期限、規則及模板；各領域以自己的 Pydantic 模型擴充。`ScenarioRuleBase` 的部署、操作、query 及優先序是通用約束，額外選擇條件由領域定義。

| 階段 | 功能與輸出 |
| --- | --- |
| `prepare(request, identity, profile, assessment, run_id=...)` | 核對同一請求與判定有效性，回傳固定 scope 與封存的領域上下文 |
| `provider.load(...)` | 由所選領域驗證資料，不自動改標其他 run |
| `resolve(prepared, data)` | 領域處理器決定結果，回傳通用組合計畫、資料摘要及可追溯決策 |
| 組合、驗證與回送 | 沿用同一候選及原請求，選情境本身不等於契約放行 |

`PreparedScenario` 與結果綁定 domain、政策、請求指紋、操作、資料身份及有效期限。缺少／未知／過期或關聯不符的判定會拒絕，不能由模型補出依據。來源白名單不是驗簽，外部判定來源仍須由接收層先認證。

`not_applicable` 表示判定或政策未選出誘餌情境，不會自動轉送真實服務；`unverifiable` 沒有可用候選。共用引擎不偵測攻擊，不提升來源核准，也不讀取任意訪客 URL 或執行規則中的程式碼。

## 選擇領域與安全情境

應用程式以明確的 domain ID 選註冊處理器，政策 domain 必須相同。未知領域或另一領域的封套均拒絕。領域資料與擴充步驟見 [領域包](domains.md)，共用安全分類與設計狀態見 [OWASP 情境設計](owasp-design.md)。

目前內建的 [電商處理器文件](../domains/ecommerce/docs/scenarios.md) 說明商品、模板及 200／404 規則。它們不是所有領域的限制。非電商工單測試使用不同方法、狀態、實體及映射，仍經相同共用引擎。

## 離線展示入口

```powershell
$env:PYTHONPATH = "$PWD/src"
.\.venv\Scripts\python.exe -m deception.scenarios --list-domains
.\.venv\Scripts\python.exe -m deception.scenarios --demo --domain ecommerce
```

命令列從 `DomainImplementations` 取得明確領域的可選 `scenario_demo(output_root, domain=...)` 入口，沒有指定領域、領域未知或該領域未註冊展示時均拒絕。清單表示已註冊插件，不代表每個插件都提供離線展示；未提供展示的既有插件仍可使用其他介面。

預設把 `generated/domains/<domain>/` 交給所選展示；`--output <path>` 可明確覆寫整個輸出根目錄。報告的欄位、案例及檢查由領域實作負責，共用入口只回報領域、完成狀態及報告路徑。目前內建電商報告保存於其輸出根目錄的 `scenarios/<報告SHA256>.json`，具體驗證條件見 [電商離線展示](../domains/ecommerce/docs/scenarios.md#有效性驗證)。

## 驗證與生命週期

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_scenario_demo_dispatch.py tests/test_scenario_domains.py tests/test_generic_pipeline.py tests/test_scenarios.py -q
```

引擎內的封存標記只用於同實例的一致性交接，不是對外來源認證或可跨程序持久重用的簽章。互動與交易狀態仍須由領域資料供應器管理，不能由結果模板推定已扣款或更新庫存。

展示回歸會實際執行電商離線契約管線，核對報告 bytes 摘要與一致性結果，並以不同業務的工單插件驗證派送、預設輸出及拒絕行為。這不代表已提供工單領域的完整功能。

## 使用的套件與授權

共用引擎使用既有 Pydantic（MIT）、安全 YAML loader 所用 PyYAML（MIT）及 Python 標準庫（PSF 與隨附聲明）。契約元件與領域供應器授權分別見 [組合器套件表](composer.md#使用的套件與授權) 與電商文件，未新增規則引擎或執行環境。
