# Mirage 獨立安裝、契約與驗收

## 用途與邊界

Mirage 自行維護合成世界、Session、Grant、Replay、JWS 驗證、
資源權限、稽核與受保護的回應流程。是否允許偵測、判定及簽發
JWS，由部署者的外部客戶端負責。Mirage 不要求特定 Gateway 或
其他專案的 Python 模組、SQL 函式及框架相容環境。

## 安裝與輸入輸出

需要 Python 3.11 以上，於獨立乾淨虛擬環境執行：

```sh
python -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python tools/check_documentation.py
.venv/bin/python -m pytest -q
.venv/bin/python -m uvicorn deception.api.demo:create_app --factory --host 127.0.0.1 --port 8000
```

展示服務 `/healthz` 回報程序存活，`/demo/info` 提供合成商品識別，
`/api/products/{id}` 回覆合成資料；未知商品回 404。

正式可信接收端由 `TrustedDeploymentSettings` 配置固定 issuer、
audience、服務範圍及驗章公鑰；已核准客戶端依公開 wire vectors
建構 HTTP 請求摘要與短期 JWS。Mirage 驗章、檢查 Replay、Session
與資源綁定。部署者可注入 `OriginalAssessmentLookup` 並啟用
`require_original_assessment=True`；查回失敗、摘要不符或不存在時
嚴格拒絕，未提供查回介面時不能啟用嚴格模式。

## 失敗處理與驗證限制

驗章、Replay、Grant、Receipt、資料庫或世界安全控制失效時，
由 Mirage 原生入口依契約拒絕，不回退到真實服務。測試依賴的
PostgreSQL、mTLS、Medusa、容器與還原實機測試必須另在隔離環境
執行；沒有相關環境而 skip 不算通過。獨立安裝與封裝驗證列於
`tests/test_standalone_runtime.py`，本次拆除外部組裝入口不構成
G3b～G6 的發布簽核，也沒有執行正式切換或資料庫 migration。

## 授權

本倉庫自有程式採 Apache-2.0；第三方套件和測試材料授權另見
[授權清單](licensing.md)。
