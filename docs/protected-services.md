# G3b 獨立服務啟動與正式 HTTP 隔離配置（未放行）

## 用途、可信邊界

`src/deception/security/protected_services.py` 把測試中使用的 Verifier 與固定
Executor 真 mTLS 入口提升為**可從受控環境配置的獨立進程啟動方式**。服務以
`MIRAGE_G3B_SERVICE_ROLE` 只選定 `verifier`、`executor` 或 `validator`；各自讀取
**不同的 Secret Mount**，嚴禁使用舊 `MIRAGE_POSTGRES_DSN` 或收到另一個
角色的 DSN。程序在綁定 Listener 前連到 PostgreSQL，檢查 `session_user`
等於 `current_user` 與指定 Login，且 Role 為 `NOINHERIT`、沒有超級使用者、
`BYPASSRLS` 或建立資料庫／角色權，最後逐表核對必要與禁止的 ACL。
此外核對**唯一 schema** 與禁止任何 PostgreSQL 角色成員資格，不能靠
`SET ROLE` 轉入另一個授權域。

Verifier 只從實際 HTTPS ASGI 的 URL、Method、Headers、Body 與 JWS／Receipt
推導 Operation，對 `synthetic-inventory` 固定路由到 Inventory Executor，
對 `synthetic-carts`／`medusa-native-cart` 固定路由到 Cart Executor。
缺乏平台目標時，在消費 JTI／Receipt 前拒絕；不能由 Runtime 藉由 RPC JSON
指定 Handler、Session、State、Scope 或改寫可信來源。兩個 Executor 分開執行
固定 SyntheticInventory 或 SyntheticCarts Handler，不傳原始 PostgreSQL DSN
給 Runtime。Verifier 與 Executor 的 mTLS Client CA 不同於 Gateway CA；只有
受保護的網路可到達這些內部入口。

**本階段已接獨立原生候選 Validator mTLS，尚未建立可信的客戶端原生 HTTP 回應，
更未啟用 G4 Sender。** Verifier 的 200 JSON 是控制面對帳資料，不得當作
Inventory／Cart／Medusa 的最終 HTTP 200。`GET /internal/ready` 只證明服務
存活；所有原生 2xx／4xx 仍須獨立來源、封套與規格驗證。舊
`trusted_http.from_environment()` 的 Release Fuse 仍硬拒絕啟動。

## 原生 HTTP 回應投影子切面

`src/deception/world/protected_native_http.py` 首先接入 Medusa
`POST /store/carts/{id}/line-items` **特定 400／404**：Executor 與獨立
候選投影端重用同一套固定 native JSON template，兩者精確計算 Canonical
Envelope Hash。`PostgresProtectedNativeProjector` 僅接受 Receipt UUIDv4，
使用獨立物理 Login 查 `protected_medusa_rejection_sources`，與
Ingress Receipt、不可變 Operation Proof、受保護 Read Source／Admission、
當前 Session Epoch／Generation／Key Revocation 逐欄一致後，才輸出
`ProtectedNativeProjection`（`status`、`headers`、不可變 `body_bytes`、
`envelope_hash`、來源、完整 Scope、Fingerprint）。錯配、過期、未知回應
或沒有來源一律拒絕，沒有從 Runtime 傳入的 Body／Status 模板可供補簽。

目前獨立 `native-validator` 以第三組 mTLS CA 對 Verifier 提供
`POST /internal/v1/project-medusa-rejection`；只接受 Receipt UUIDv4，
在獨立唯讀 PostgreSQL Login 上重建候選原生 400／404 bytes、Scope 與 Hash。
Verifier 會在比對 Executor 的 status／envelope hash／Operation／Fingerprint 後，
只輸出 `native_projection` 對帳摘要；來源缺漏時關閉並回 503。這不是原生
400／404 Client Response，不接受由 Runtime 自選的 Body、Status 或 Template。

候選投影結果可交既有 `PostgresCandidatePromoter` 的來源核對，
**並沒有新增可對 Client 送出 400／404 的 HTTP endpoint**；正式獨立
全 20 操作的原生 2xx／4xx、Contract Gate 和 G4 Sender
仍是 OPEN。投影使用 Read Committed 的當前資料庫檢查，尚不能取代
G5 Restore Fence 及 Send 前重新驗證。

## 輸入、輸出與設定

主程式：

```bash
python -m deception.security.protected_services
```

共同必要環境：

| 設定 | 用途 |
| --- | --- |
| `MIRAGE_G3B_SERVICE_ROLE` | 只允許 `verifier`、`executor` 或 `validator` |
| `MIRAGE_G3B_BIND_HOST`、`MIRAGE_G3B_BIND_PORT` | 明確的 Listener 位址與 TCP 埠，不提供公開 HTTP fallback |
| `MIRAGE_G3B_WORLD_SCHEMA` | 與 PG 連線 `current_schema()` 必須精確一致，避免查詢同名假表 |
| `MIRAGE_TRUSTED_SEND_ENABLE` | 若存在，只能是 `false`；所有正式發送依舊不可用 |

Verifier 專用：

| 設定 | 用途 |
| --- | --- |
| `MIRAGE_G3B_VERIFIER_DSN_FILE`／`MIRAGE_G3B_VERIFIER_LOGIN` | 唯一 Verifier SCRAM Secret 與物理 Login |
| `MIRAGE_G3B_VERIFIER_KEYS_FILE` | JSON `{ "kid": "canonical-base64-32-byte-Ed25519-public-key" }`，最多 16 個；禁止重複 Key |
| `MIRAGE_G3B_ENVIRONMENT_ID`、`MIRAGE_G3B_DEPLOYMENT_ID` | 不可空的 Receipt 範圍 |
| `MIRAGE_G3B_EXPECTED_ISSUER`、`MIRAGE_G3B_EXPECTED_AUDIENCE` | 唯一受信任 JWS 發行者與收件者 |
| `MIRAGE_G3B_INVENTORY_EXECUTOR_ORIGIN`、`MIRAGE_G3B_CART_EXECUTOR_ORIGIN` | 固定 HTTPS Executor 端點，必須有可驗證 DNS SAN |
| `MIRAGE_G3B_VERIFIER_SERVER_CERT_FILE`／`MIRAGE_G3B_VERIFIER_SERVER_KEY_FILE` | Gateway→Verifier mTLS Server 身份 |
| `MIRAGE_G3B_GATEWAY_CLIENT_CA_FILE` | 只允許專屬 Gateway Client CA |
| `MIRAGE_G3B_VERIFIER_CLIENT_CERT_FILE`／`MIRAGE_G3B_VERIFIER_CLIENT_KEY_FILE` | Verifier→Executor mTLS Caller 身份 |
| `MIRAGE_G3B_EXECUTOR_SERVER_CA_FILE` | 驗證 Executor Server CA／SAN |
| `MIRAGE_G3B_NATIVE_VALIDATOR_ORIGIN` | 固定獨立原生候選 Validator HTTPS 端點 |
| `MIRAGE_G3B_VERIFIER_VALIDATOR_CERT_FILE`／`MIRAGE_G3B_VERIFIER_VALIDATOR_KEY_FILE` | Verifier→Validator 專用 Client 身份，與 Executor 不共用 |
| `MIRAGE_G3B_NATIVE_VALIDATOR_SERVER_CA_FILE` | 獨立 Validator Server CA／SAN |

Executor 專用：

| 設定 | 用途 |
| --- | --- |
| `MIRAGE_G3B_EXECUTOR_DSN_FILE`／`MIRAGE_G3B_EXECUTOR_LOGIN` | 個別 Inventory／Cart Executor 的 SCRAM Secret 與物理 Login |
| `MIRAGE_G3B_EXECUTOR_PLATFORM` | 僅 `synthetic-inventory` 或 `synthetic-carts`，無自選 Handler RPC |
| `MIRAGE_G3B_CART_STATE_FILE` | 僅 Cart：固定 Catalog、Inventory 和可選 Native Context 的嚴格 JSON |
| `MIRAGE_G3B_MEDUSA_PUBLISHABLE_KEY_FILE` | Cart 的原生 Medusa 固定 Key；不由請求配置 |
| `MIRAGE_G3B_EXECUTOR_SERVER_CERT_FILE`／`MIRAGE_G3B_EXECUTOR_SERVER_KEY_FILE` | Executor mTLS Server 身份 |
| `MIRAGE_G3B_VERIFIER_CLIENT_CA_FILE` | 只允許專屬 Verifier Client CA |

Native Validator 專用：

| 設定 | 用途 |
| --- | --- |
| `MIRAGE_G3B_VALIDATOR_DSN_FILE`／`MIRAGE_G3B_VALIDATOR_LOGIN` | 專屬唯讀 PostgreSQL SCRAM Login，不使用 Verifier／Executor 密碼 |
| `MIRAGE_G3B_VALIDATOR_SERVER_CERT_FILE`／`MIRAGE_G3B_VALIDATOR_SERVER_KEY_FILE` | Validator mTLS Server 身份 |
| `MIRAGE_G3B_VALIDATOR_CLIENT_CA_FILE` | 只接受 Verifier→Validator 專用 Client CA |

DSN／Key／Cart State 都由私有檔案讀入，拒絕不存在、空值、超上限、重複
JSON Key 及異常數值。Runtime 與 Verifier 不應看到 Executor 的 DSN；
Executor 亦不得取得 Verifier 的 DSN 或 JWS 公鑰清單。Role 不可取得
`protected_candidate_promotions` 的 INSERT 權，因為它們不是 Validator。

## 服務拓樸範本

隔離規劃在 `deploy/security-lab/g3b-compose.yaml`，四個非 root 容器：

1. `verifier` 只接 Gateway 所在的 `g3b_gateway` 網路，另連執行及資料庫網路。
2. `inventory-executor`／`cart-executor` 只在 `g3b_execution` 與 `g3b_database`，無 host `ports`。
3. `native-validator` 只在執行與資料庫網路，以獨立只讀 Login 查固定 Medusa
   拒絕來源，只信任專用 Verifier Client CA，無公開埠。
4. 四者各有不同 DSN Secret；Verifier 才有 JWS 固定公鑰與 Gateway CA；
   Executor、Validator 只接對應的 Verifier Client CA，不掛 Runtime Secret。

範本預設置於 `g3b-isolated` profile，需要手動準備外部 Docker Networks、
非共用 PostgreSQL Role、專用 Certificate SAN、外部 Secret，且須把資料庫
容器接到 `g3b_database`。缺任何 Secret 或錯誤權限就啟動失敗，**不提供
自動建立高權限 Role、不發布 public port、不取代既有安全 Fuse**。
這仍是部署規格範本，不是已部署、已完成 pg_hba／NetworkPolicy 簽核的證據。

## 失敗處理與驗收

- 缺少設定、同時提供兩種 DSN、密碼與 Login 不符、危險 ACL 或超權限：
  `ProtectedRpcConfigurationError`，未開放執行入口。
- 未通過 Gateway Client Cert：TLS 握手拒絕；缺 JWS／Fingerprint 不符：403，
  不落 Receipt；缺固定平台 Executor：503，不允許 Runtime fallback。
- Executor 回應故障或 Commit ACK 未知：503／UNVERIFIABLE，不重新起送。
- 合法證明經固定 RPC 取得的 Commit、Read、Medusa 特定 400／404 來源只是
  **內部資料**；獨立 Validator 投影重建成功不代表 Grant，缺 Promotion／
  Authorized Snapshot 不得輸出客戶端 HTTP。

聚焦測試：`python -m pytest -q tests/test_protected_services.py
tests/test_protected_rpc_mtls.py tests/test_ingress_receipts.py`。真 PostgreSQL Role
測試須設於明確**可拋棄**的 `MIRAGE_WORLD_ROLE_TEST_ISOLATED=true` CI，
而非正式 DB。檢查 `python tools/check_documentation.py`。

尚待驗收：正式 Gateway 端原始網路連線、Secret 不可見性、pg_hba、兩個
Executor 都可用的真容器端到端正反面、20 條原生 HTTP 200／400／404／409
兼容、獨立 Validator 的真容器部署簽收、故障注入與正式簽核。上述任一欠缺，
`MIR-SEC-WORLD-001=OPEN`、`MSDSS P2=NO-GO`，Trusted Send `OFF`。

## 套件與授權

自有程式採 Apache-2.0；使用專案既有 FastAPI／Uvicorn／HTTPX、
psycopg／Pydantic／cryptography、PostgreSQL 和 Docker Compose。
依賴與第三方授權請參閱 [授權表](licensing.md)。
