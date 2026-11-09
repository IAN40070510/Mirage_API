# 共用模型與資料交換

`src/deception/common/` 提供所有領域可使用的嚴格模型、ID 格式與隔離範圍。`SyntheticModel` 禁止額外欄位、非有限數值與隱含型別轉換；`DatasetScope` 綁定站點、平台、版本、契約雜湊、情境與 run，沒有商品或工單欄位。

`CompositionData(scope, payload)` 是資料供應器完成領域驗證後，交給回應組合器的 JSON 投影。`payload` 可以是商品、工單或其他領域的結構；組合器只沿管理者明列的 JSON Pointer 取得既有值，核對 scope，再驗證完整回應。

```python
from deception.common import CompositionData

data = CompositionData(
    scope=checked_scope,
    payload={"tickets": [{"id": "ticket-001", "state": "open"}]},
)
```

上述 `checked_scope` 代表本次已核對的隔離範圍，不能以任意字串代替。資料供應器須先驗證內容與來源；DTO 格式本身不是來源認證、業務事實證明或防竄改簽章。HTTP 訪客不能提供任意 DTO 當作權威資料。

為保留舊呼叫端，資料物件可提供 `to_composition_data()`，由領域 adapter 完成核對後回傳 DTO。電商資料集會先依相同生成規則重建驗證，再投影商品／變體；此規則位於電商套件，組合器不匯入商品型別或硬編商品根節點。

錯誤 scope、缺少來源／目標 Pointer、重複映射、無效 JSON 型別或不符最終契約都會拒絕，不轉型、補欄位或放寬規格。模型仍只能生成政策允許的位置；權威映射和弱點模擬固定值各自受保護。

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_generic_pipeline.py tests/test_composer.py tests/test_synthetic.py -q
```

此模組只使用既有 Pydantic（MIT）與 Python 標準庫（PSF 及隨附聲明），沒有新套件或自有連線生命週期。各領域資料讀寫及來源條款由其資料供應器文件管理，完整框架分工見 [領域說明](domains.md)。
