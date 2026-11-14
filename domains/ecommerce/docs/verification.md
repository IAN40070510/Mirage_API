# 電商 API 攻擊特徵與邏輯一致性驗證

## 功能、目的與界線

通用領域拆分後的最新驗證為 637 項完整測試與三組各 16 項真實 HTTP 請求通過；兩種弱點亦已加入固定值與必要標頭契約。完整範圍與限制見 [領域拆分驗證紀錄](audits/domain-pack-verification-2026-11-09.md)。下方既有模型實測數字保留原驗證時間與範圍。

共用 `tools/verify_domain_api.py --domain ecommerce` 呼叫 `deception.domains.ecommerce.verification`，對本機的 [隔離展示服務](../../../docs/docker.md) 發送實際 HTTP 請求，確認假回應符合已載入的合成契約，並在商品身份、名稱、存在性、重複查詢內容與資料快照間保持一致。電商 verifier 只接受 HTTP loopback origin、停用環境代理並拒絕 redirect；不向外部平台發送測試流量。

展示服務明確產生 `simulated_malicious` 判定，用來驗證判定後的處理流程。這不是 SQL 注入偵測器、真實攻擊來源認證、滲透測試結果或官方平台相容性證明。模型模式與固定備援模式分開記錄，固定備援不能當成真模型成功的證據。

## 輸入與呼叫方式

先依 [電商使用說明](usage.md) 及 [共用 Docker 說明](../../../docs/docker.md) 選擇領域，或在專案根目錄執行相同 app：

```powershell
$env:PYTHONPATH = "$PWD/src"
$env:MIRAGE_DOMAIN = 'ecommerce'
.\.venv\Scripts\python.exe -m uvicorn deception.api.demo:create_app --factory --host 127.0.0.1 --port 8000 --no-proxy-headers --no-server-header --no-date-header --no-access-log
```

另開終端機執行：

```powershell
$env:PYTHONPATH = "$PWD/src"
.\.venv\Scripts\python.exe tools/verify_domain_api.py --domain ecommerce --base-url http://127.0.0.1:8000
```

| 輸入 | 用途及預設 |
| --- | --- |
| `--base-url` | 真正網路連線的 loopback HTTP origin，預設 `http://127.0.0.1:8000`，不可包含帳密、路徑、query 或 fragment |
| `--host-header` | 選用的明確 loopback `Host`；容器內連線埠與對外綁定 origin 不同時使用，例如 `127.0.0.1:8001` |
| `--timeout` | 每個 HTTP 請求期限，預設 60 秒，須為有限正數且不超過 600 秒 |
| `--output` | JSON 報告位置，預設 `generated/domains/ecommerce/verification/http-api.json`；同名報告會被新一輪結果覆寫 |

測試前先讀 `/demo/info`，要求 `test_only: true`、`domain: ecommerce` 且至少有兩個合成商品。商品、備援文字與種子輸入來自 `domains/ecommerce/configs/demo.yaml`；工具不會把訪客 payload 當成管理設定。每輪使用不同追蹤 ID，避免把其他請求的觀察結果混入報告。

## 測試矩陣

| 請求或序列 | 預期行為 |
| --- | --- |
| 存在商品 → 不存在商品 → 再查原商品 | `200 → 404 → 200`；兩次成功 body bytes 一致，找不到的商品固定為 not_found 且 message 綁定當次商品 ID |
| 查詢不同商品 | ID、名稱對應各自資料，不能混用另一商品內容 |
| 商品 ID 含 SQL、腳本或命令注入字串 | 當作普通 ID 查詢，不執行指令；不存在時 404，回應只包含 URL-encoded ID |
| GET body 內提示注入、偽造環境／判定／forwarded 標頭 | 不改已綁定部署、商品事實或生成權限，不回顯測試憑證 |
| 未審查 query 或不符合綁定的 Host | 固定 503 診斷，沒有可放行的平台候選 |
| 下單、刪除商品等未支援寫入 | 503，不能假裝交易成功或修改快照 |
| TRACE | 503，不回顯 Authorization |
| 無效追蹤 ID／過大 body | 分別 400／413，不進入內容生成 |

工具目前包含 16 個實際 HTTP 案例，另比對資料快照、商品事實、內容穩定性及明確不支援交易的狀態。單元與整合測試另覆蓋過期判定、模型故障、備援政策、型別、快取隔離及驗證後變更，見各工具說明。

購買後扣款、退款與庫存寫入尚未實作。因此這次能確認的是查詢與拒絕行為的一致性，不能聲稱已驗證「買了商品後餘額減少」。這類需求需要交易狀態、去重及並行控制。

## 輸出、錯誤及生命週期

報告包含 `success`、`cases`、`logical_consistency`、`configured_mode`、`observations` 與 `real_model_requests`。每個案例保留預期／實際狀態、追蹤 ID 及長度／不洩漏檢查；不保存原始 Authorization 或模型提示。

`recent_results` 是展示服務最多 64 筆的結果摘要，區分 `generation_source: model`、`cache` 或 `fallback`。`real_model_requests` 只加總已核對為 local／ollama 的模型請求；模式設定為 `local` 不代表必然成功使用模型，故障後備援也會清楚列出。

任一案例或一致性檢查失敗，工具以非零結束碼結束；連線、格式或不符合展示前提等問題也會保存 `success: false` 報告，不把部分通過當成全部有效。回應限制 2 MiB；報告由呼叫端指定位置保存，工具不改來源、政策或部署核准，也不下載模型。

公開函式 `checked_origin()` 核對目標，`request_json()` 保留原始 HTTP bytes，`verify()` 回傳完整結果，`main()` 處理 CLI 與報告保存。各函式均有功能 docstring。

這些商品函式屬於電商實作；共用入口只派送已選領域，不直接假定商品欄位。舊 `tools/verify_ecommerce_api.py` 保留相容，不作新增領域的範本。

## 驗證方式及授權

2026-11-09 已分別在本機實際 Uvicorn 服務測試兩種模式：

| 模式 | HTTP 案例 | 通過契約的內容來源 | 真本機模型請求 |
| --- | --- | --- | --- |
| 固定備援 | 16 個全部通過 | 8 份固定備援，未冒充模型生成 | 0 |
| Foundation-Sec-8B-Reasoning Q4_K_M | 16 個全部通過 | 6 份真實生成、2 份快取重用，無備援 | 38 |

其餘案例是預期的 400、413 或 503 拒絕診斷，也包含在每組 16 個案例內。兩組的所有 `logical_consistency` 檢查均通過；完整回歸為 **586 項通過**。實測來源與限制見 [驗證紀錄](audits/ecommerce-verification-2026-11-09.md)，JSON 報告位於本機 `generated/verification/ecommerce-fallback.json` 與 `generated/verification/ecommerce-foundation.json`，可用上方 CLI 重建。

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe tools/check_documentation.py
```

驗證工具只使用 Python 標準庫 `urllib`、`json`、`argparse`、`datetime`、`pathlib` 及 `uuid`，隨 Python 的 PSF 授權及隨附聲明管理，未新增套件。展示服務沿用 FastAPI（MIT）、Pydantic（MIT）、PyYAML（MIT）、Faker（MIT）、Starlette（BSD-3-Clause）、openapi-core（BSD-3-Clause）等現有依賴；詳細版本及間接依賴見 [回應組合套件表](../../../docs/composer.md#使用的套件與授權)、[模型套件與權重授權](../../../docs/orchestration.md#套件模型與資料授權) 和 [Docker 授權說明](../../../docs/docker.md)。
