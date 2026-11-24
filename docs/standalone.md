# 獨立運作與驗收

## 用途與邊界

Mirage 提供合成世界與 API 回應，支援原生 Request Fingerprint、
JWS 驗章、JTI 防重放、Session／World、Grant、原生 Audit、受保護
Executor／Validator／Sender 與 Restore Fence。
偵測或導流政策由使用本服務的客戶端自行負責。

## 安裝與啟動

在新的 Python 3.11 以上環境安裝本倉庫即可。

```sh
python -m venv .venv
python -m pip install -e ".[test]"
python tools/check_documentation.py
python -m uvicorn deception.api.demo:create_app --factory --host 127.0.0.1 --port 8000
```

實際執行時使用該虛擬環境的 Python。
`/healthz` 應回 200，`/demo/info` 提供合成商品 ID。
`/api/products/{id}` 回覆合成商品，未知商品回 404。
此展示程序的健康不構成受保護交易的發布驗收。

## 可信客戶端契約

Mirage 的 `TrustedDeploymentSettings` 配置允許的 issuer、audience、
環境、部署、服務及公鑰。客戶端依 Mirage 的固定 wire vectors 計算
請求摘要，提交帶有 Session、epoch、期限與一次性 JTI 的 JWS。
私鑰由已核准的呼叫端保管，Mirage 驗證其簽章並使用自身 Replay 儲存。
Session／World 綁定與資源授權繼續由 Mirage 原生流程檢查。

`deception.api.fingerprint.fingerprint_httpx_request` 是公開的客戶端
摘要函式。協定資料模型定義在 Mirage 來源中，測試使用自有 fixtures。
可選 `original_lookup` 接受部署者提供的本地介面，預設無外部連線，
嚴格模式仍以同一份 Mirage AttackAssessment 模型核對摘要並拒絕失敗。
這個可選功能不要求任何固定外部服務。

## 故障與限制

驗章、Replay、世界綁定、Receipt、Grant、Lease 或必要的儲存檢查
失敗時沿用原生拒絕行為。未知 COMMIT 使用既有對帳契約處理。
本次去耦沒有更動原生安全演算法或 PostgreSQL schema，
G3b～G6 未完成的安全 Gate 仍維持原有狀態。

## 驗證與授權

```sh
python -m pytest -q
python tools/check_documentation.py
```

PostgreSQL、mTLS、容器、Medusa 與 restore 測試需要各自明確的隔離環境，
缺少環境的 skip 必須單獨報告。
原生原始碼與相依套件授權見[授權說明](licensing.md)。
發布前核對目前固定 SHA 的完整測試、建置與原生安全 Gate。
