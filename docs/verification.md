# 領域 HTTP 一致性驗證工具

## 功能與分工

`tools/verify_domain_api.py` 是共用驗證入口，依管理者明確選定的領域呼叫已註冊 verifier。共用工具不假設商品、訂單、帳戶或其他業務欄位；各領域保存自己的案例、固定資料、契約與判讀方式。

目前可用領域與詳細說明：

| 領域 | 實作與說明 |
| --- | --- |
| `ecommerce` | [領域包](../domains/ecommerce/README.md)、[電商呼叫方式](../domains/ecommerce/docs/usage.md)、[商品與攻擊特徵矩陣](../domains/ecommerce/docs/verification.md) |

新增資料夾或 YAML 不會自動執行程式碼。新領域須同時註冊業務處理器及 verifier；未知 ID 不回退其他領域。弱點分類與模擬狀態見 [OWASP 設計](owasp-design.md)，不能把 `designed` 當成可執行弱點。

## 輸入與呼叫

在專案根目錄執行：

```powershell
$env:PYTHONPATH = "$PWD/src"
.\.venv\Scripts\python.exe tools/verify_domain_api.py --list-domains
.\.venv\Scripts\python.exe tools/verify_domain_api.py --domain ecommerce --base-url http://127.0.0.1:8000 --output generated/domains/ecommerce/verification/http-api.json
```

| 輸入 | 用途 |
| --- | --- |
| `--domain` | 明確領域 ID；省略時讀共用 `configs/app.yaml` 及管理者環境覆寫 |
| `--list-domains` | 列出已註冊 verifier，不送出測試請求 |
| `--base-url` | 實際目標 origin，預設 `http://127.0.0.1:8000`；具體可接受範圍由領域 verifier 核對 |
| `--host-header` | 管理者指定的 Host；用途與限制由領域 verifier 定義 |
| `--timeout` | 每次請求期限，預設 60 秒；領域 verifier 仍須執行範圍檢查 |
| `--output` | JSON 報告位置，預設 `generated/domains/<domain>/verification/http-api.json`；同名檔案會覆寫 |

Docker 使用方式見 [共用部署說明](docker.md)。`tools/verify_ecommerce_api.py` 保留為電商相容入口；新呼叫應選擇共用工具及明確 `--domain`。

共用展示預設亦按 `generated/domains/<domain>/` 分隔產物。`MIRAGE_OUTPUT_ROOT` 選擇展示的共用輸出根目錄；verifier 報告使用自己的 `--output`，不會因展示目錄覆寫而自動改寫 CLI 報告位置。相容 `MIRAGE_DEMO_OUTPUT` 只對明確展示輸出覆寫有效。資產與輸出分工見 [領域說明](domains.md)。

## 結果與錯誤

工具保存 verifier 的報告及 `success`。失敗、連線或格式異常以非零結束碼結束，不把部分通過當成全部有效；未註冊領域在開始請求前拒絕。詳細業務檢查、來源觀察、模型使用量及可用性前提由各領域的驗證文件解釋。

結果須區分：契約符合、資料一致、受控弱點觸發、模型確實執行，以及實際容器執行。某一層通過不能取代其他層。各領域歷史報告保存在自己的文件資料夾，不能用某個領域或舊版本結果宣稱整個通用框架的所有情境皆已有效。

## 維護與授權

所有具名函式均須有功能 docstring，新增領域時同步增加自己的正反向測試與工具說明。共用文件檢查：

```powershell
.\.venv\Scripts\python.exe tools/check_documentation.py
```

入口使用既有 Pydantic（MIT）設定及 Python 標準庫 `argparse`、`json`、`pathlib` 等，隨 Python 的 PSF 授權及隨附聲明管理，沒有另加驗證框架。領域 verifier 使用的套件及模型權重須在各領域文件記錄。
