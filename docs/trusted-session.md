# Trusted Session 部署與 Gateway

## 用途與邊界

### 可選原始判定嚴格綁定（MSDSS 測試移交）

`TrustedSessionAssessmentProvider` 新增 `original_lookup: OriginalAssessmentLookup | None` 與 `require_original_assessment: bool = False`。預設維持原行為：驗章、請求 fingerprint、部署 scope 及共享 Replay 通過後，以簽章 claims 建立 malicious 判定；**預設並未查回或核對原始 AttackAssessment digest**。

只有可信部署者提供私有 `lookup(assessment_id) -> AttackAssessment | None` 並明確設定 `require_original_assessment=True`，才會在 JWS 驗證後查回原始判定，核對 assessment ID、request ID、fingerprint、環境／部署／來源／服務／站點、malicious verdict、時效，以及 `sha256(original.model_dump_json().encode("utf-8"))` 與簽章 `assessment_digest` 是否一致（固定時間摘要比較）。不得從訪客 URL、header 或未驗證 HTTP 回應提供 lookup。缺資料、錯誤型別、scope／摘要不符或私有儲存失效一律拒絕，不降級回 claims 重建；嚴格模式缺 lookup 或 lookup／模式搭配錯誤會在建構時拋出 `ValueError`。

此基礎 OriginalAssessmentLookup 介面只支援接收端核對；新增的獨立 PostgreSQL ledger 實作可在部署者明確啟用 strict、提供 Consumer DSN 並先由 DBA 套用專用 migration 後，執行跨 Instance 一次性領取。Gateway persist-before-sign 仍是 MSDSS 所有的整合流程；正式資料庫、CA/TLS、failover、entitlements 和 production DECEIVE 均未核准。私有儲存的交易、權限、版本與生命週期仍需獨立設計。測試：`python -m pytest -q tests/test_original_assessment_binding.py tests/test_trusted_ingress.py tests/test_trusted_error_vectors.py tests/test_trusted_session.py`；跨語言案例需 Node.js 22，skip 不應算通過。沿用現有 Python hashlib／hmac、cryptography、pytest，不新增外部執行服務；套件授權沿用[授權表](licensing.md)。


### 獨立客戶端的請求摘要

`deception.api.fingerprint.fingerprint_httpx_request(request, request_id)` 可供 Mirage 獨立客戶端使用，不需要 MSDSS。輸入為已固定 URL、標頭與 body bytes 的 HTTPX／httpx2 相容請求介面，輸出為 v1 SHA-256 摘要；不依具體 Request 類別身份判斷，不修改請求、不讀取串流，也不簽發或核准身份。空 request_id、未緩衝 body 或重複核准標頭皆 ValueError。請先建好相同 request，再簽發 JWS 並送出，簽後修改 body、URL 或受綁定標頭會被服務端拒絕。

```python
import httpx
from deception.api.fingerprint import fingerprint_httpx_request

request = httpx.Request("GET", "https://mirage.example.invalid/api/products/example",
    headers={"x-request-id": "example-001"})
digest = fingerprint_httpx_request(request, "example-001")
```

此範例只計算摘要，不發出網路請求。驗證為 `python -m pytest tests/test_client_fingerprint.py tests/test_golden_vectors.py -q`，使用與實際 Gateway 相同的公開固定 wire 向量，另確認串流不被消費、原請求不被改寫。沿用 HTTPX 與 Python 標準函式庫，自有實作採 Apache-2.0，未複製外部 Gateway 原始碼。它不能取代可信身份來源、Replay 或正式簽發器。

### 已驗證授權的時鐘偏差

接收端只取一次 Unix 時刻，先依部署的 `max_clock_skew` 驗證 JWS；驗章、scope、金鑰及 Replay 都成功後，提供判定層的起始時間取 signed `iat` 與接收時刻的較早者。這讓簽發端稍快但仍在核准範圍的授權能立即使用，避免入口接受卻在商品判定誤回 503。原始 claims／可信上下文摘要保留原值，截止時間仍是 signed `exp`，不延長到期；超出 skew 仍在 Replay 前拒絕，一般未簽章 assessment 的時間規則也不變。

`tests/test_trusted_clock.py` 核對 -5、0、+1、+30 秒、超界 +31 秒、已到期授權、單次時鐘取樣，以及真實 ASGI／PostgreSQL 的 +15 秒商品查詢與原始 Audit 摘要。此修正只調整 Mirage 驗證後的判定時間，不改 Gateway、主機時鐘或授權簽章格式。部署仍須維護時間同步；這不是無限容忍時差。

### 固定簽發、拒絕碼與 Replay 向量

`tests/fixtures/golden_vectors/trusted_session_errors.json` 固定保存 **61 組精確 wire**（4 接受、57 拒絕），覆蓋 15 種基本驗證器拒絕碼。輸入明列原始 Header／claims JSON、簽章變異、Unix 時間、外部 key 撤銷值及是否已消費；輸出是已驗證 claims 或精確 TrustedSessionError 代碼。JSON 重複欄位、非物件、錯誤演算法／key／受眾、scope、Unicode、clock 邊界、padding 與非 canonical Base64URL 均有固定案例。

| 類別 | 固定代碼 |
| --- | --- |
| 格式與資料 | token_not_text、invalid_compact_jws、invalid_trusted_session_claims、invalid_base64url |
| 信任與綁定 | invalid_trusted_session_signature、issuer_or_audience_mismatch、request_fingerprint_mismatch、trusted_key_not_found、trusted_key_revoked、trusted_session_context_mismatch |
| 時間 | trusted_session_expired、trusted_session_invalid_time_order、trusted_session_lifetime_exceeded、trusted_session_not_yet_valid |
| 一次性消費 | trusted_session_replay |

Node 的 `sign_trusted_errors.mjs` 只從公開測試 seed 重建原始 UTF-8 bytes 及 Ed25519 簽章，核對 wire 與公鑰；它不模擬 Mirage 政策或共享儲存。padding／非 canonical 負例仍保持有效簽章 bytes，用來證明 Mirage 因格式拒絕。Python 核對每個固定結果，另確認前置拒絕零次 Replay 呼叫，原 JTI 仍可由合法授權消費；已消費及 clock 邊界案例分開驗證。

```powershell
python -m pytest tests/test_trusted_error_vectors.py -q
python -m pytest tests/test_trusted_error_vectors.py tests/test_commit_vectors.py -q
```

這組向量離線執行，不讀部署私鑰、不啟動模型或連接真實身份服務。測試 seed 僅是公開材料，不能作部署秘密。沿用現有 cryptography、pytest 與 Node 內建 crypto／fs／assert；新增自有向量與簽發器採 Apache-2.0，未封裝 Node 執行檔或新增套件。缺少 Node 時只有獨立簽發案例 skip，不能當成通過；Python 明確以 UTF-8 解讀 Node 輸出，不依賴 Windows code page。這不取代 PostgreSQL 故障／共享 key guard、實際 Gateway HTTPS 或所有部署互通的驗收，原始 parser 詳細錯誤也不對外公開。

`tests/fixtures/golden_vectors/request_fingerprint.json` 另固定六組 canonicalization v1 請求：percent-encoded path、重複 query 與 Unicode 值、二進位 body、忽略標頭不改 hash、核准標頭順序有綁定，以及重複 Host／Authorization 拒絕。`verify_fingerprint.mjs` 以 Node 獨立重算標準化快照的精確摘要，Python 與實際 MSDSS dispatcher 的最終 HTTPX request 適配器也核對同一批資料。這補足「只把預先算好的 fingerprint 放入 JWS」的證據缺口；不代表所有語言 HTTP parser 或代理改寫都已驗證，真正 HTTPS 邊界仍由 test_msdss_wire 覆蓋。

`TrustedDeploymentSettings` 將部署者核准的 issuer、audience、環境、部署、服務與公鑰集合接到 PostgreSQL Replay。Gateway adapter 原始碼保存在 `integrations/msdss/trusted_session_dispatch.py`，供 MSDSS 的 `src/msdss/adapters/` 使用；必須由部署程式明確注入，不會自動切換 staging。

Gateway 僅對 `approved_attack` 的 DECEIVE 決策簽發授權。Session ID／epoch 必須由可信 resolver 提供，不能轉抄訪客 header。簽發器不存取鑑識庫；私鑰由部署程式注入，Mirage 只保存公鑰。使用 HTTPS，HTTPX 送出已簽章的同一個請求，不跟隨 redirect 或轉送真實後端。

## 輸入輸出與設定範例

```python
import os
from pathlib import Path
from deception.security.trusted_deployment import TrustedDeploymentSettings

settings = TrustedDeploymentSettings.model_validate_json(
    Path(os.environ["MIRAGE_TRUSTED_SETTINGS_FILE"]).read_text(encoding="utf-8")
)
provider = settings.build_provider(postgres_dsn=os.environ["MIRAGE_POSTGRES_DSN"])
# 在既有 pipeline.create_app(..., assessment_provider=provider) 注入。
```

設定欄位：`issuer`、`audience`、`environment_id`、`deployment_id`、`source_id`、`service_id`、`site_id`，以及 `public_keys`（kid → 32-byte 公鑰 hex）。`max_lifetime` 預設／上限 60 秒，`max_clock_skew` 預設／上限 30 秒。正式金鑰不能使用 fixture 金鑰。輪替期間可同時列入多個 kid；新公鑰仍需更新設定並重建 provider，單改磁碟檔不會熱載入。新版 provider 另查[共享 key 墓碑](key-revocation.md)，可不重啟就拒絕已撤銷 issuer／kid；舊版未接入的程序不具此能力。

`build_provider` 回傳可呼叫的 assessment provider；資料庫連線延至請求驗證。新版先依序套用 migrations 至 014；缺少共享撤銷表時拒絕，不降級。Gateway 另需 `cryptography>=43,<46`，與 Mirage 使用相同範圍。簽發器輸入是最後 HTTPX Request、核准 DecisionOutcome、可信 SessionBinding；輸出是 Mirage HTTP 回應。

## 失敗處理

無效公鑰、空身份及超出期限政策於建構時拒絕。錯誤環境／部署在消費 JTI 前拒絕；期限必須滿足 `iat <= nbf < exp`。Replay 保留至 `exp + max_clock_skew`，期限相等即拒絕，避免 GC 使寬限期授權重新有效。缺少／重複 JWS、簽章或 fingerprint 錯誤、資料庫不可用一律停止，不使用記憶體替代共享 Replay。

## 驗證方式

跨語言案例使用 Node.js 22 內建 crypto 與公開 fixture seed 重建測試簽章，再由 Python provider 驗證原始請求與修改 body 的負例。執行 `python -m pytest tests/test_trusted_ingress.py -k node_signature -q`。缺少 Node.js 會跳過該案例。雙入口 PostgreSQL 案例可經 SSH loopback 隧道連到隔離資料庫，只傳送 migration 與合成 Replay 紀錄。

執行 `python -m pytest tests/test_trusted_session.py tests/test_trusted_ingress.py tests/test_postgres_conformance.py -q`。PostgreSQL 測試需 `MIRAGE_POSTGRES_TEST_DSN` 指向隔離資料庫；缺少時 skip 不是通過。雙入口競爭測試使用固定 vector，因此同一資料庫不可同時執行多份該測試。執行 `python tools/check_documentation.py` 檢查函式與文件。

## 套件／模型授權與目前限制

自有 adapter 採 Apache-2.0；cryptography 採 Apache-2.0／BSD 雙授權，HTTPX 採 BSD-3-Clause，沿用套件而未複製上游實作；其餘見 [授權表](licensing.md)。無模型呼叫，未採用其他開源 Gateway 程式碼。

目前仍需正式 resolver、部署金鑰與 issuer／audience 配置。固定 JWS 向量不是跨語言互通完成的證據；Network／未知交易結果與完整 Registry／Admission Conformance 的最新範圍見[證據矩陣](conformance-evidence.md)。`assessment_digest` 綁定 Gateway 判定摘要；預設模式仍未查回原判定，僅從 claims 重建 malicious，attack types 由部署設定提供。可選的嚴格模式見上文；正式跨 Instance 查回仍未完成。`WorldEvent` 業務寫入預設停用，明確啟用合成業務時才開放。可信 handler 的拒絕另存[入口稽核](ingress-audit.md)，不包含原始憑證或攻擊本文。

## 實際 Gateway proxy 傳輸驗收

部署 middleware 在完成身份解析後，把同一個 adapter 模組定義的 `SessionBinding(environment_id, deployment_id, session_id, session_epoch)` 放入 `request.state.trusted_session_binding`，並把 dispatcher 注入 `app.state.deception_dispatcher`。綁定須由服務端建立。缺少綁定、型別或 scope 不符時，dispatcher 拒絕簽發。

設定 MSDSS_ROOT 指向 MSDSS checkout（預設為 Mirage 專案的同層 MSDSS 目錄），安裝專案測試依賴並確認 openssl 在 PATH，執行 `python -m pytest tests/test_msdss_wire.py -q`。測試使用實際 Sentinel proxy、決策政策、合成模型結果與測試 middleware。獨立 HTTPS 程序使用 Mirage 請求解析、驗章與程序內 ReplayStore；回傳已驗章的 session、epoch 及程序 ID 供驗收。正式身份提供者、完整業務 pipeline 與共享 PostgreSQL 的整體接線仍待部署驗證。

## 完整電商 pipeline 與共享 Replay

電商展示的 create_app 接受部署程式傳入的 assessment_provider。注入 TrustedDeploymentSettings.build_provider 所建立的 provider 後，商品路由使用該 provider，/demo/info 顯示 injected_provider。省略參數時仍可使用原本的模擬展示。

指定 MSDSS_ROOT 與 MIRAGE_POSTGRES_TEST_DSN（隔離測試資料庫，測試會套用 migration），執行：

    python -m pytest tests/test_msdss_wire.py -k postgres-pipeline -q

測試以短期憑證及合成身份查詢商品，在相同 HTTPS origin 重啟獨立服務後原樣重送，再以新簽章查詢。測試環境的模型與身份由 fixture 提供，正式身份來源待決定。測試使用既有 Python 套件、OpenSSL 與 PostgreSQL，未新增套件或模型。

## Replay 寫入故障驗收

在本機設定 MIRAGE_POSTGRES_TEST_DSN 指向可建立測試 schema 的隔離 PostgreSQL，再執行：

    python -m pytest tests/test_postgres_conformance.py -k replay_fault -q

兩個案例各自建立並清除獨立 schema。寫入逾時案例由另一個交易鎖住 replay_entries，寫入連線使用測試專用 1000 毫秒 statement_timeout。提交結果未知案例讓 PostgreSQL 完成寫入，再於本機消費介面拋出連線錯誤。兩者均檢查一次消費、固定 503 回應與零次協調器呼叫，並從另一連線核對 JTI 是否存在。此案例驗證應用層失去成功結果的處理；TCP 封包實際中斷與生產連線期限設定仍屬其他驗收範圍。

## Medusa 已登入顧客的身份適配

驗章的具名 SEC-06 負向驗收位於 `tests/test_trusted_session.py`：以測試 key 重新簽章後，仍拒絕 none／HMAC／RSA／EdDSA 別名、錯誤 typ／協定、未知 kid、遠端／內嵌 key、錯誤 issuer／audience、期限邊界及缺少必填 claims。每個拒絕案例再確認原合法 JTI 尚可首次使用，避免把前置拒絕誤作 Replay 消費；這些是離線測試，不會連線 header 提供的 URL。

資源請求在驗章之後、解析世界之前，另外比對當次 cart／order 路徑與伺服器重新查回的 SessionBinding。有效簽章不免除 Session、epoch、resource_id 及 access_mode 的一致性檢查；不符一律固定 503，不建立新世界或 ReadAdmission。Gateway 發出錯配授權也不能讓 Mirage 回覆該 Session 的另一張購物車。此接收端檢查完全位於 Mirage，不擴大 MSDSS 外部變更。

MedusaIdentityProvider 只對部署固定 origin 發送 GET /store/customers/me?fields=id，核對 Bearer 或 connect.sid。每次都驗證原服務，拒絕 redirect、非 200、回應超過 16 KiB 與無效 customer.id。client 的 CookieJar、訪客 path、query、body 與自填身份不參與查詢。只以固定 origin、已驗證 customer.id 和登入憑證的 HMAC 建立不透明 session ID，IdentitySessions 保存 epoch 與本地撤銷旗標。

正式 origin 使用 HTTPS。明確啟用 allow_loopback_http 的模式僅供 SSH loopback 隧道測試。部署注入 publishable key、至少 32 bytes 的 identity_key 及 DSN，憑證不放入文件或程式碼。先套用 migration 005。每份登入憑證有自己的合成 session；換 Token 可能建立新世界。Medusa Bearer 的客戶端登出不代表撤銷已簽發 JWT，因此 Mirage 另提供本地 revoke_identity；Cookie 登出則由原 Medusa 再次查核失敗。

Mirage 內的 MSDSS dispatcher adapter 可注入 identity_provider，使用驗證結果建立 JWS，無需改動 MSDSS 的 proxy 程式。需要在部署程式注入 adapter 才會啟用。本機測試包括 test_medusa_identity.py、test_medusa_live.py 與 test_msdss_wire.py 的 medusa-pipeline。實機驗收使用 SSH 主機的獨立 Medusa 2.22.4、PostgreSQL、Redis 容器，只有合成顧客及金鑰。參考 [Medusa 顧客身份查詢](https://docs.medusajs.com/resources/storefront-development/customers/retrieve) 與 [登入方法](https://docs.medusajs.com/resources/storefront-development/customers/login)。

重驗須明確設定 `MIRAGE_MEDUSA_TEST_ORIGIN`、`MIRAGE_MEDUSA_TEST_ADMIN_EMAIL`、`MIRAGE_MEDUSA_TEST_ADMIN_PASSWORD` 及 Mirage 專用 `MIRAGE_POSTGRES_TEST_DSN`，管理員只能屬於可丟棄的隔離 Medusa。測試會建立合成顧客與 publishable key；不能指向真實店鋪。先確認 Medusa `/health` 回 200，再執行 `python -m pytest tests/test_medusa_live.py "tests/test_msdss_wire.py::test_gateway_dispatch_to_independent_mirage[medusa-pipeline]" -q`。缺少環境的 skip 不是通過；另驗結果不可混進先前整套計數。

2026-11-16 以新版共享 key 墓碑 provider 重驗上述兩項通過。Windows 執行測試與 Mirage worker，Ubuntu 只提供隔離 Medusa／DB／Redis；internal Docker 網路不發布主機端口時，由 SSH 轉發其私有 IP 即可，無需增加對外網路。合成管理員秘密不貼入命令範例或報告，測後連同專用容器、network、隧道與本機暫存刪除。這不是正式 MSDSS 身份來源／部署設定已啟用的證明。

## 匿名查詢與 IP／UA 分組

依本次使用者決定，匿名查詢使用固定唯讀合成資料，再以 Gateway 實際來源 IP、User-Agent 和短期窗口輔助分組。AnonymousIdentityProvider 預設窗口為 300 秒，以部署 HMAC key 計算不透明 group ID。資料庫只保存摘要、窗口與限額，原始 IP／UA 不保存。需要 migration 006_anonymous_groups.sql。

HybridIdentityProvider 有 Medusa 憑證時驗證顧客，無憑證時才匿名分組，無效顧客憑證不會降級。Gateway adapter 將 access_mode 放入簽章 claims，未提供該欄位的舊 JWS 預設 read_only。純匿名分組只能查詢，不能取得庫存寫入能力。固定匿名資料使用 fallback 模式，不讓每次模型生成造成內容漂移。

| 影響 | 行為與取捨 |
| --- | --- |
| 無需 Client 配合 | 掃描器不用保存 Cookie 或額外 Token，也可取得一致合成查詢資料。 |
| NAT 與代理共用 | 相同來源 IP、UA 與窗口可能合併不同訪客；這不是個人身份證明。 |
| UA 偽造與變更 | UA 可由 Client 修改，因此分組會變動；它不授予顧客或寫入權限。 |
| IP 或窗口變更 | 會形成新組，查詢仍使用相同固定合成 catalog；不保證個別訪客跨窗口的狀態連續性。 |
| 來源可信邊界 | 只讀 Gateway 的 request.client，不採用訪客自填 X-Forwarded-For。若部署在代理後，需明確接入核准代理提供的來源；目前不猜測。 |
| 大量分組 | 每部署每窗口預設最多 1000 新組，既有組不重複計數；超額 fail-closed。 |
| Guest 商業操作 | Medusa 原本允許未登入者操作購物車。純分組的唯讀限制不是 Medusa 登入規則；合成 cart.id 可寫狀態由已登記資源能力授權，見[購物車](carts.md)。 |

本機執行 tests/test_anonymous_identity.py，以及 test_msdss_wire.py 的 anonymous-pipeline 案例。身份與分組元件皆採 Apache-2.0，使用既有 HTTPX、PostgreSQL 與 Python 標準庫，無新增模型。參考 [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)。

## 獨立可信服務啟動入口

`python -m uvicorn deception.domains.ecommerce.trusted_http:from_environment --factory --host 127.0.0.1 --port 8000 --no-proxy-headers` 使用部署環境建立服務。必要環境變數為 `MIRAGE_TRUSTED_SETTINGS_FILE`（只含受信公開金鑰與部署政策）、`MIRAGE_POSTGRES_DSN`（Mirage 專用 DB）及 `MIRAGE_DEMO_ORIGIN`（簽章路由的固定 origin）。`MIRAGE_ENABLE_BUSINESS=true` 才開啟合成交易，預設 false；`MIRAGE_AUTO_MIGRATE=true` 才於啟動時更新 schema，預設由部署流程另外執行，見[migration 操作](runtime-operations.md)。旗標只接受 true／false，設定錯誤會阻止啟動。

此入口不會注入 MSDSS dispatcher，也不會自動把真實流量送入 Mirage。Gateway 的簽章私鑰與身份設定須由其部署層安全提供，不能寫進此公開金鑰設定。對外需要 TLS 或可信 TLS 終結層；容器或 ASGI 健康檢查只表示程序存活，不表示正式身份、Projection 或符合性已核准。現有 Compose 預設仍是一般展示服務，不能直接視為可信交易部署。
