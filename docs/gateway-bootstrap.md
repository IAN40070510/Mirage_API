# 可選 Gateway 部署組裝

> **歷史歸檔，非目前 Mirage 安裝指引。** 本文件記錄舊版跨專案實作和當時的驗收證據，相關組裝器、相容性依賴與測試已移出 Mirage。下方路徑和命令不能用於目前分支；目前的運作入口見 [Mirage 獨立安裝與驗收](standalone.md)。外部消費者的部署與移轉驗證應在其自身倉庫執行。

## 用途與邊界

`integrations/msdss/gateway_bootstrap.py` 將已驗證的 Medusa 登入、匿名唯讀分組與合成資源能力組裝成 TrustedSessionDispatcher。它只在原 Gateway 建好 HTTP client 後執行，不載入或替換偵測模型，不改真實上游，不執行 migration，也不自動修改 MSDSS。

整合端須在自己的 HTTP client 生命週期內明確呼叫組裝器，並提供 MSDSS 型別與相依套件。Mirage 不自動修改其他 repo、不安裝外部 Gateway 依賴，也不啟用導流。一般 Mirage 展示與可信服務可獨立啟動；只有這個可選 Gateway adapter 需要 MSDSS。

兩個專案的完整依賴需分開管理；下方固定的相容性清單只驗證組裝子集，不代表可以把兩個完整環境合併安裝。外部服務的來源變更及部署紀錄由整合端自行維護，不隨 Mirage 公開發行。

Mirage runtime 封存與映像已包含 integrations 目錄，以供檢閱與受控整合；Mirage 服務不會自動啟動 Gateway。MSDSS 本身仍須另外提供 msdss 套件與原 Gateway 模型環境。

身份適配器與 dispatcher 使用 HTTPX 0.28 系列，已列為 runtime 依賴，不能只依靠開發環境的 test extras；pydantic-ai 所帶入的 httpx2 不會提供 `import httpx`。映像內匯入驗證包含這項差異。

## 輸入、輸出與設定

公開 JSON 使用 GatewayIntegrationSettings，包含 deployment（與 Mirage 端相同的 issuer、audience、環境、部署、來源、服務、站點、公開金鑰）、kid、固定 HTTPS mirage_origin 及 medusa_origin。enforcement_enabled 與 deception_approved 預設皆 false；兩者明確 true 才允許原政策進入已核准的誘餌決策，仍須符合實際偵測器與門檻條件。minimum_class_score 預設 0.90，無自動降門檻。

| 環境變數 | 內容 |
| --- | --- |
| MIRAGE_GATEWAY_SETTINGS_FILE | 公開設定 JSON 檔路徑 |
| MIRAGE_GATEWAY_SIGNING_KEY_FILE | Ed25519 raw 32-byte 私鑰檔路徑，必須匹配指定 kid |
| MIRAGE_IDENTITY_KEY_FILE | 至少 32-byte 身份 HMAC 秘密檔路徑 |
| MIRAGE_MEDUSA_PUBLISHABLE_KEY_FILE | 固定 Medusa 的 publishable key 檔路徑 |
| MIRAGE_POSTGRES_DSN | Mirage 專用儲存連線，不得指向 Medusa 業務資料庫 |

部署檔路徑不由訪客提供。DSN 與秘密不放公開 JSON；檔案權限及輪替由部署者管理。原 client 的 TLS 驗證及固定信任設定必須保留。allow_loopback_identity_http 預設 false，只在隔離 SSH loopback 身份測試明確開啟。

亦可從已核准部署程式呼叫 configure_gateway_state(state, settings=..., postgres_dsn=..., signing_key=..., identity_key=..., publishable_key=...)，避免使用環境讀檔入口。成功後只更新 state.deception_dispatcher 與 state.decision_policy；身份元件的 DB 存取延後至實際請求。這是可信整合端，訪客不能指定 WorldScope 或寫入政策。

## 失敗處理

金鑰不匹配、身份來源不安全、未知設定、缺少秘密／client 或已有 dispatcher 時停止，並在所有元件建好前保留原 state。不可吞掉啟動錯誤再默默切成真實後端。整個 Gateway client、模型與取消工作的生命週期仍由原 Gateway 維護。

## 驗證方式

### 與 MSDSS 原版框架隔離驗證

`integrations/msdss/requirements.compatibility-test.txt` 固定 FastAPI 0.115.6、Pydantic 2.10.4、HTTPX 0.28.1 以及測試用 cryptography、psycopg、pytest。這是可丟棄環境的驗收清單，不是整個 Mirage 的安裝清單，也不會更新 MSDSS 原 .venv：

```powershell
python -m venv generated/acceptance-gateway-compat
generated/acceptance-gateway-compat/Scripts/python.exe -m pip install -r integrations/msdss/requirements.compatibility-test.txt
generated/acceptance-gateway-compat/Scripts/python.exe -m pytest tests/test_gateway_bootstrap.py tests/test_trusted_session.py -q
```

2026-11-16 本機獨立環境驗證為 15 passed，沒有安裝 pydantic-ai、OpenAPI 驗證器或模型。結果證明從原始碼載入的 Gateway 組裝子集及 JWS 能在原版框架下運作，不表示可以用 pip 合併兩個完整專案的依賴，也不涵蓋資料庫連線、身份端點、正式 detector 或 staging 啟用。測試報告位於 generated/acceptance-gateway-compat.xml 與 .log；資料全為合成金鑰與請求，未讀取憑證或私人業務資料。

`python -m pytest tests/test_gateway_bootstrap.py -q` 使用本機實際 MSDSS 型別、隨機金鑰及 lazy DB 元件驗證預設 observe-only、錯誤不留下半套設定與分開秘密檔讀取，不啟動模型、不連資料庫。真正 JWS／HTTP／身份流程另見[部署驗收](trusted-session.md)。外部整合的實際啟動及依賴可用性須在整合環境驗證，不能由型別測試推定。

## 授權與限制

自有組裝器採 Apache-2.0，沿用既有 HTTPX、cryptography、Pydantic、PostgreSQL 與 MSDSS 型別；授權見[共用表](licensing.md)。沒有複製其他身份服務程式或引入模型。本發行不包含其他 repo 的修改補丁，不啟用正式 Gateway。新增 enable_medusa_store 開關預設 false，明確啟用才解析 `/store` 資源 ID；對應的獨立原生 Profile 與支援範圍見[映射說明](medusa-carts.md)。
