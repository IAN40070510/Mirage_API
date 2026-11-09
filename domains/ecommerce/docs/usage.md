# 電商領域的輸入、呼叫與受控弱點

## 選擇電商

共用入口只選領域，不在根設定宣告商品欄位。根 `configs/app.yaml` 可設定 `domain: ecommerce`，或由管理者環境明確選擇：

```powershell
$env:MIRAGE_DOMAIN = 'ecommerce'
docker compose up --build -d --wait --wait-timeout 180
curl.exe --fail http://127.0.0.1:8000/demo/info
```

以上命令在專案根目錄執行。完整映像、模型及輸出 volume 管理見 [共用 Docker 說明](../../../docs/docker.md)。未知領域或未註冊實作會拒絕，不猜測 URL 或由訪客 header 選領域。

## 電商 input

`domains/ecommerce/configs/demo.yaml` 是隔離展示設定：

```yaml
schema_version: 1
domain: ecommerce
origin: http://127.0.0.1:8000
mode: fallback
weakness_scenario: null
seed: 20261109
product_count: 2
run_id: isolated-demo
fallback_description: This is a reviewed synthetic demonstration product.
fallback_missing_message: The requested synthetic demonstration product does not exist.
```

| 欄位 | 用途與限制 |
| --- | --- |
| `domain` | 固定電商；包與實作 ID 必須一致 |
| `origin` | 綁定實際 HTTP origin，不接受帳密、query、fragment 或路徑前綴 |
| `mode` | `fallback` 刻意不啟動模型；`local` 使用共用 `configs/llm.yaml` 的本機模型及已配置備援 |
| `weakness_scenario` | `null` 表示一般商品查詢；非空時只接受此領域已實作情境 |
| `seed` | 0–4294967295 的固定種子 |
| `product_count` | 2–10 個合成商品，讓驗證可檢查不同商品隔離 |
| `run_id` | 資料隔離身份，不代表真實顧客或登入會話 |
| 備援文字 | 固定欄位內容，10–120 字元，仍須經契約與最終回送驗證 |

`MIRAGE_DEMO_MODE`、`MIRAGE_DEMO_ORIGIN` 可由管理者覆寫模式與 origin。`MIRAGE_DEMO_CONFIG` 是選用的明確檔案覆寫；未提供時由領域 `domain.yaml` 找到本檔。Docker 不再預設把這個環境變數硬指向電商。

展示產物預設放在 `generated/domains/ecommerce/`，每次啟動再建獨立子目錄，保持契約、Profile、資料及內容快取同屬已選領域。容器的 `MIRAGE_OUTPUT_ROOT=/app/generated` 是共用根目錄；相容 `MIRAGE_DEMO_OUTPUT` 若明確提供，則直接覆寫展示輸出位置，不自動附加領域路徑。停止容器保留命名 volume，需匯出時可用 `docker compose cp mirage:/app/generated/domains/ecommerce ./ecommerce-output`。

正式 Medusa 來源、部署契約、政策與其他草稿放在本包 `inputs/`。展示建立獨立合成契約及模擬惡意判定，不會讀寫正式來源的核准狀態；Medusa 仍是 `approved: false`，WooCommerce 沒有完整已核准來源。

## 一般商品與攻擊特徵請求

先取得本次合成商品 ID：

```powershell
$info = Invoke-RestMethod http://127.0.0.1:8000/demo/info
$productId = $info.product_ids[0]
curl.exe --fail-with-body -i "http://127.0.0.1:8000/api/products/$productId" -H 'X-Request-ID: product-001'
curl.exe --fail-with-body -i "http://127.0.0.1:8000/api/products/$productId" -H 'X-Request-ID: product-002'
curl.exe -i http://127.0.0.1:8000/api/products/prod-synthetic-missing -H 'X-Request-ID: missing-001'
curl.exe --path-as-is -i 'http://127.0.0.1:8000/api/products/%27%20OR%201%3D1--' -H 'X-Request-ID: sqli-path'
```

存在商品應為 200、不存在商品為 404。同一商品的 ID、名稱與完整 body 應穩定；不同 request ID 仍須各自重新驗證最後封套。攻擊文字只作普通輸入，不成為可執行工具。

未審查 query、未知操作或方法應停止，不臆造成功購買。交易寫入未支援，因此下單、扣款、退款、更新庫存等測試要求明確拒絕。服務診斷不是已通過商品契約的候選。

## 啟用受控弱點

先列出本領域的情境及狀態：

```powershell
$env:PYTHONPATH = "$PWD/src"
.\.venv\Scripts\python.exe -m deception.domains --domain ecommerce
```

在 `configs/demo.yaml`（相對本領域資料夾）明確選一個 `weakness_scenario`，重新啟動服務：

```yaml
weakness_scenario: api3-internal-product-properties
```

此情境在合成商品成功回應的 `/product/internal_note` 放入領域包的固定虛構註記。新增欄位先宣告在本次合成契約中，再建立來源摘要及 Profile；註記列入保護位置，不讓訪客或模型改寫。

另一個選項：

```yaml
weakness_scenario: api8-debug-header-disclosure
```

此情境在成功與找不到商品的模板加入固定 `X-Legacy-Store-Version`，值來自領域目錄的 `legacy_version`，不是實際主機版本。最後 headers 仍須重新通過契約驗證器。

兩個情境只能逐一明確選擇；其餘八項目前只有設計與驗證條件，不能啟用。這些模擬不會讓服務真的執行 SQL、shell、外部 URL、主機 metadata 存取或真實授權繞過；沒有宣稱已實作 honeytoken 使用告警。

若用唯讀設定掛載：

```yaml
services:
  mirage:
    volumes:
      - ./domains/ecommerce/configs/demo.yaml:/app/domains/ecommerce/configs/demo.yaml:ro
```

未掛載時，改主機檔案後須重建映像。來源、政策與分類在啟動時核對，不由訪客請求更新。

## 電商驗證與授權

```powershell
docker compose exec mirage python tools/verify_domain_api.py --domain ecommerce --base-url http://127.0.0.1:8000 --output /app/generated/domains/ecommerce/verification/http-api.json
```

預設驗證報告為 `generated/domains/ecommerce/verification/http-api.json`，`--output` 可明確覆寫。詳細案例、報告與歷史結果見 [電商驗證矩陣](verification.md)。共用驗證 CLI 不讀商品欄位；依領域註冊的 verifier 送出商品案例。商品／變體資料規則見 [電商合成資料工具](synthetic.md)，情境與模板規則見 [電商情境選擇](scenarios.md)。完整回歸可在專案根目錄執行 `python -m pytest -q`，不能把歷史結果當成新弱點全部已驗證的證據。

電商實作沿用 Faker、Pydantic、PyYAML、jsonschema（MIT），並經既有 openapi-core、Starlette、Uvicorn（BSD-3-Clause）流程回送。模型權重、固定 API 規格與 OWASP 文字各自管理；共用套件及權重條款見 [工具索引](../../../docs/README.md)、[模型整合授權](../../../docs/orchestration.md#套件模型與資料授權) 及 [OWASP 設計說明](../../../docs/owasp-design.md)。
