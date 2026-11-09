# 電商誘餌領域包

這個資料夾集中電商專用的設定、固定來源、政策、弱點情境、使用說明及驗證紀錄。共用引擎不在這裡；Python 電商實作位於 `src/deception/domains/ecommerce/`。其他領域應建立自己的同層資料夾與已註冊實作，不直接套用商品規則。

## 目錄與責任

```text
domains/ecommerce/
├── domain.yaml                 # 領域身份與包內相對資產位置
├── configs/                    # 電商展示、資料生成、組合與部署綁定範例
├── inputs/
│   ├── sources/                # Medusa 固定來源與 WooCommerce 來源範本
│   ├── platforms/              # 部署契約及未核准 manifest 範本
│   ├── policies/               # 情境、生成與備援政策
│   ├── http-requests/          # 歷史請求描述範例
│   ├── scenarios/              # 歷史情境草稿
│   └── synthetic/             # 歷史手寫資料草稿
├── security/owasp-scenarios.yaml
└── docs/
    ├── usage.md                # 電商 input、呼叫、弱點選擇與限制
    ├── synthetic.md            # 商品／變體生成、驗證與查詢規則
    ├── scenarios.md            # 商品操作、模板與分支規則
    ├── verification.md         # 商品邏輯與攻擊特徵矩陣
    └── audits/                 # 電商與 Medusa 的歷史驗證紀錄
```

`domain.yaml` 只宣告相對資產位置，不能要求任意 Python 匯入。共用載入器會確認包內路徑不存在逃逸、manifest 的領域 ID 正確，並由伺服器明確註冊實作。

## 明確選擇領域

在專案根目錄執行：

```powershell
$env:PYTHONPATH = "$PWD/src"
.\.venv\Scripts\python.exe -m deception.domains --list-domains
.\.venv\Scripts\python.exe -m deception.domains --domain ecommerce
$env:MIRAGE_DOMAIN = 'ecommerce'
.\.venv\Scripts\python.exe -m uvicorn deception.api.demo:create_app --factory --host 127.0.0.1 --port 8000 --no-proxy-headers --no-server-header --no-date-header --no-access-log
```

Docker 與其他領域共用相同映像及入口，依 [共用 Docker 說明](../../docs/docker.md) 設定 `MIRAGE_DOMAIN`。目前內建已註冊的業務領域只有電商；未知 ID 不會自動回退電商。

領域產物預設分隔在 `generated/domains/ecommerce/`，HTTP verifier 的預設報告為 `generated/domains/ecommerce/verification/http-api.json`。容器以共用 `MIRAGE_OUTPUT_ROOT` 設根目錄；只有明確使用相容 `MIRAGE_DEMO_OUTPUT` 時才直接覆寫展示路徑，避免把電商目錄當成通用框架的預設業務。

## 目前支援範圍

- 隔離合成商品 GET：存在 200、不存在 404、同商品內容及資料快照一致。
- 固定欄位備援與可選本機模型，兩者在結果摘要中分開記錄。
- 兩個可啟用的受控弱點回應：虛構內部商品屬性外露、虛構除錯版本標頭外露。
- Medusa Store/Auth 固定來源子集及 WooCommerce 設定範本；正式部署仍未核准，不代表示範契約可替代官方平台。

購買、扣款、退款、訂單狀態、庫存交易及完整誘捕告警仍未實作。弱點模擬不會執行 SQL、shell、任意 URL、反序列化程式碼或真實權限繞過。

## OWASP 情境狀態

這是本專案依通用分類建立的電商映射，不是 OWASP 官方電商專屬 Top 10。

| API Security 分類 | 電商情境 ID | 狀態 |
| --- | --- | --- |
| API1:2023 | `api1-cross-order-access` | 已設計，尚不可啟用 |
| API2:2023 | `api2-weak-synthetic-session` | 已設計，尚不可啟用 |
| API3:2023 | `api3-internal-product-properties` | 已實作，可明確選擇 |
| API4:2023 | `api4-resource-limit-illusion` | 已設計，尚不可啟用 |
| API5:2023 | `api5-synthetic-admin-function` | 已設計，尚不可啟用 |
| API6:2023 | `api6-coupon-reuse-flow` | 已設計，尚不可啟用 |
| API7:2023 | `api7-static-metadata-illusion` | 已設計，尚不可啟用 |
| API8:2023 | `api8-debug-header-disclosure` | 已實作，可明確選擇 |
| API9:2023 | `api9-legacy-api-inventory` | 已設計，尚不可啟用 |
| API10:2023 | `api10-untrusted-upstream-fixture` | 已設計，尚不可啟用 |

分類版本、來源及授權見 [OWASP 設計說明](../../docs/owasp-design.md)。實際參數及限制以 [情境目錄](security/owasp-scenarios.yaml) 與 [電商使用說明](docs/usage.md) 為準。

## 說明與驗證

使用方式見 [電商 input 與呼叫](docs/usage.md)、[電商合成資料](docs/synthetic.md)、[電商情境](docs/scenarios.md)、[HTTP 驗證矩陣](docs/verification.md) 及 [Medusa 來源狀態](inputs/platforms/medusa/README.md)。共用工具責任、套件授權與介面見 [工具索引](../../docs/README.md)，領域註冊與資料交換見 [通用領域包](../../docs/domains.md) 及 [共用資料](../../docs/common-data.md)。
