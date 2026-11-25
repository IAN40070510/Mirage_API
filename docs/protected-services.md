# G3b 獨立服務啟動與正式 HTTP 隔離配置（未放行）

## 用途、可信邊界

`src/deception/security/protected_services.py` 把測試中使用的 Verifier 與固定
Executor 真 mTLS 入口提升為**可從受控環境配置的獨立進程啟動方式**。服務以
`MIRAGE_G3B_SERVICE_ROLE` 只選定 `verifier`、`executor` 或 `validator`；各自讀取
**不同的 Secret Mount**，嚴禁使用舊 `MIRAGE_POSTGRES_DSN` 或收到另一個
角色的 DSN。程序在綁定 Listener 前連到 PostgreSQL，檢查 `session_user`
等於 `current_user` 與指定 Login，且 Role 為 `NOINHERIT`、沒有超級使用者、
`BYPASSRLS`、`REPLICATION` 或建立資料庫／角色權，最後逐表核對必要與禁止的 ACL。
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

**本階段已接獨立原生候選 Validator mTLS，尚未建立可信的客戶端原生 HTTP 回應；
G4 Sender 只新增封閉的 mTLS 啟動骨架，未啟用任何 Send Lease HTTP 操作。**
Verifier 的 200 JSON 是控制面對帳資料，不得當作
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
再將 Validator 的完整 Scope 與本次**已驗簽** JWS 的 Environment／Deployment／
Session 逐欄比對，保留已驗證的 `native_projection.status_code`、
`headers`、`body_b64`、`envelope_hash`、`body_sha256`、`source` 和 `scope`。
`delivery=candidate_only_no_send_authorization` 明確表示這仍是**內部候選**；
來源、Scope、Body 或非正規 Base64 錯配均固定拒絕 503。外層 Verifier HTTP
仍為**內部對帳 `200`**，不是原生 `400／404` Client Response，也不接受
由 Runtime 自選 Body、Status 或 Template。不得把 `body_b64` 直接交給 Gateway
發送，須先建立合法 Promotion／Authorized Snapshot／獨立 Sender Lease 與 G5 Fence。

新增 `POST /internal/v1/project-receipt` 作為獨立 Validator 的統一投影入口：
外部請求只能提供單一 UUIDv4 `receipt_id`；專用唯讀 PostgreSQL Login
從不可變 `protected_http_operation_bindings` 與 `ingress_receipts` 的 Fingerprint
一致性，固定選擇 20 個 Synthetic／Medusa Operation 之一。寫入操作再查真
`protected_world_commit_sources`、`protected_world_rejection_sources` 與
`protected_medusa_rejection_sources` 的唯一互斥來源，分派已驗證的成功或拒絕
投影；來源缺失、混雜、Operation／Receipt／Fingerprint 重綁皆 fail closed。
此入口不接受 Caller 提供 Handler、成功／失敗狀態碼、Body、Scope、Template
或核准旗標；返回的仍是**候選**，不建立 Promotion／Grant／Sender Lease。
Verifier 的十條原生候選 mTLS Client 路徑都收斂到這個 Receipt-only URL，
各路徑仍獨立核對真實 Executor Operation／Envelope／來源、原始已驗簽 JWS
的 Scope 與該操作的固定原生 JSON 語意；固定分型投影 RPC 只保留向後相容。
此接線**未建立** Verifier→Authorizer→Sender 的完整授權傳輸通路，
不得視為 G4/G6 的 Client HTTP 發送驗收。

M-03 已知 Variant 的受保護 Executor Commit 已接線供隔離驗證：原始
`POST /store/carts/{id}/line-items` 必須有與 JWS Fingerprint 完全一致的
Publishable Key、JSON Body、Derived Cart Capability 和 Creator→Derived
不可變 Lineage；`variant_id` 與 `quantity` 僅從 NativeItemBody 取值，
預期世界版本只從受保護 ReadAdmission 快照取得，冪等鍵與 Attempt 由 Receipt
固定派生。一次 `cart.add` Commit 的內部結果只包含版本／Hash／Digest，不
包含可發送 Body；重送相同 Receipt 因唯一 Read Source 固定拒絕，不能重複
增加數量。後續在隔離分支接上獨立 Medusa 200 Validator 候選：只讀核對
`protected_world_commit_sources`、真 Handler Result／Commit Receipt、
ReadAdmission、目前 WorldSnapshot、`native_response_contexts` 的 Hash、
Creator→Derived Lineage 及 SHA 固定 `StoreCartResponse`。Verifier 要求
Validator 200 的 Body、Envelope、Scope 和 Commit 摘要精確符合本次執行來源。
**候選不等於 Client HTTP 200，也沒有 G4 Sender 授權**；CAS／結果不明
一律 fail closed。新增四服務流程及獨立驗證仍需真 CI 證據才可逐子項簽收。

M-03 四服務增量曾在 [CI #45381239098](https://github.com/IAN40070510/Mirage_API/actions/runs/45381239098)
遇到 `direct_verifier_medusa_add_unverifiable` 503。Validator 投影要按
`commit_attempt_id` 唯讀檢查 `native_response_contexts`，但隔離 CI 的獨立
SCRAM Validator 原先未取得該表 `SELECT`。修補只補 Validator `SELECT`，
並將它列入啟動前必要 ACL 與真 CI 權限稽核；Cart Executor 保留原有 INSERT，
Validator 仍禁止 INSERT／UPDATE／DELETE，Runtime 仍禁止 SELECT。這是
**針對可重現環境差異的最小權限修補，當時仍須真四服務 CI 重跑確認**，
不得因 PostgreSQL 管理員角色的單元測試通過就宣告 M-03 路由 PASS。

後續固定 SHA `a9eda2d` 的[真四服務 CI #45396264049](https://github.com/IAN40070510/Mirage_API/actions/runs/45396264049)
已 `success`，含 M-03 真 Commit／獨立 200 候選、角色 ACL 及 Secret 稽核；
SHA `3055a1d` 的[真 PostgreSQL 17.6 #45396777965](https://github.com/IAN40070510/Mirage_API/actions/runs/45396777965)
亦已 `166 passed`（另有真 mTLS 5 passed、模擬 G5 9 passed）。僅這些隔離
子項可判 PASS；正式 Client HTTP、G4～G6 與 Release 簽核仍未完成。

I-04 庫存 GET 新增另一個固定 mTLS 路徑
`POST /internal/v1/project-inventory-snapshot`；Validator 唯讀重建原始
`sku` 的 `200` JSON；若同一受保護快照**真正不存在此 SKU**，則新增固定
`409 {"code":"unknown_synthetic_sku"}` 候選，核對不可變 ReadAdmission 與完整 WorldSnapshot
版本、狀態雜湊、期限及 Epoch／Key。Verifier 重驗精確 JSON、SnapshotSource、
Scope／Hash；篡改與過期固定 503，不會回退 Runtime 自填庫存數量。
I-04 已有 200 與真正缺 SKU 409 的獨立候選：固定 SHA `808d07f`
的真 PG 隔離 CI `125 passed`、mTLS `5 passed`。快照毀損、過期、世代錯置
一律 503，不得冒充業務 409。原生 ASGI 傳輸與正式部署仍 OPEN；
G4 只有隔離 primitive，尚無可用的發送服務。

I-03 `GET /synthetic/operations/{attempt}` 新增固定
`POST /internal/v1/project-inventory-operation`：不同於 I-04 的庫存數量，
Validator 還必須從唯讀 `world_operations` 與 `world_commit_receipts` 證明同
World 世代的真正 `committed` 操作與完整 Result Digest，再以受保護
ReadAdmission／Snapshot／Epoch／Key 核對當前查詢。結果重建與合成 OpenAPI
一致的 `200 {commit_attempt_id,state_version,state_hash,reservation}` 候選，
拒絕由 RPC 選擇 Status 或 Body。若操作不存在、被拒或 Commit 不明，不會
自行補成 `409`。獨立 Validator 需要新增 `world_commit_receipts` 唯讀權，
仍不得 INSERT／UPDATE／DELETE；固定 SHA `808d07f` 的真 PostgreSQL
隔離 CI 已通過，新增四服務探針仍須逐版核對。
**外層仍只回內部對帳 200，不是客戶端原生成功回應。**

C-02 `getGuestCart` 與 C-07 `getSyntheticOrder` 新增獨立 Cart／Order GET
成功候選：Cart Executor 對 ReadAdmission 加上來源 ID，Validator 固定
`POST /internal/v1/project-cart-read` 只收 Receipt，再驗原始 GET 路由、
`synthetic_resources` 派生資源、快照完整性、Epoch／Generation／Key、
合成 OpenAPI Schema 及 200 精確 JSON；Verifier 與 Executor 的來源／Scope
逐欄比對，拒絕不明 409。Validator 唯讀角色新增 `synthetic_resources SELECT`；
此子項新增程式與測試，仍待本 SHA 的真 PG／四服務 CI，Sender 依舊封閉。

候選投影結果可交既有 `PostgresCandidatePromoter` 的來源核對，
**並沒有新增可對 Client 送出 400／404 的 HTTP endpoint**；正式獨立
全 20 操作的原生 2xx／4xx、Contract Gate 和 G4 Sender
仍是 OPEN。投影使用 Read Committed 的當前資料庫檢查，尚不能取代
G5 Restore Fence 及 Send 前重新驗證。

### Synthetic 真實 Handler 409 來源（新增候選子切面，待真 PG CI）

Inventory／Cart Executor 啟動時從本地固定合成契約配置拒絕碼與 Contract
Revision；僅在業務 Handler 真的以保存的 `rejected` 結果回傳，並且核對
Result Digest、Receipt／Read Source 後，才在**同一次受保護提交交易**寫入
不可更新的 `protected_world_rejection_sources`。獨立 Validator 的專用唯讀
SCRAM 身分增加對該來源及 `world_operations` 的 `SELECT`，不得
`INSERT`／`UPDATE`／`DELETE`；服務啟動時檢查 ACL，缺少權限直接拒絕。

`POST /internal/v1/project-synthetic-rejection` **僅接受 UUID4 Receipt**，由
獨立 Validator 重新核對 Handler↔Operation Proof、Result Digest、回應模板、
Scope／Epoch／Key／期限、ReadAdmission 與 409 Envelope Hash，最後生成
`{"code":"..."}` 原生合成 JSON 及不可發送的候選 Status／Headers／Body。
Verifier 再對照本次已驗簽 JWS Scope、Request Fingerprint 與完整候選 bytes。
這只適用 I-01／I-02、C-03～C-06、C-08 的**真業務 rejected**，不會把
無效 HTTP、未知 COMMIT、CAS conflict、任意 Runtime SecurityErrorSource
或無受保護 Result 的錯誤補簽為 409。原生 200、其他拒絕以及 G4 Sender
仍是 OPEN，包含 M-03 400／404 在內的外層 HTTP 繼續只回內部對帳 `200`。

本輪新增 `tests/test_protected_services.py` 的 400／404 精確候選交接正反測試：
包含錯 Session／Environment、Fingerprint、Status、Body、固定模板、Headers、
額外 Handler、Base64 與偽造的 Sender 啟用旗標。Verifier 的 Executor RPC
結果亦改用禁止重複 JSON Key／NaN 的嚴格解析，避免對帳欄位解析歧義；
`tests/test_ingress_receipts.py` 的真 PostgreSQL／mTLS 路徑也增加 bytes／Scope
比對（本地未配置 PG 時仍會 SKIP，不能算正式客戶端 HTTP PASS）。

## 輸入、輸出與設定

主程式：

```bash
python -m deception.security.protected_services
```

共同必要環境：

| 設定 | 用途 |
| --- | --- |
| `MIRAGE_G3B_SERVICE_ROLE` | `verifier`、`executor`、`validator`；G4 另有 `authorizer` 的 Receipt-only mTLS、`sender` 封閉入口 |
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

G4 獨立 Authorizer（新接線候選，未放行 Sender）專用：

| 設定 | 用途 |
| --- | --- |
| `MIRAGE_G4_AUTHORIZER_DSN_FILE`／`MIRAGE_G4_AUTHORIZER_LOGIN` | 獨立 SCRAM 實體 Login；不得共用其他角色 Secret |
| `MIRAGE_G4_AUTHORIZER_SERVER_CERT_FILE`／`MIRAGE_G4_AUTHORIZER_SERVER_KEY_FILE` | Authorizer mTLS Server 憑證與私鑰 |
| `MIRAGE_G4_AUTHORIZER_VERIFIER_CLIENT_CA_FILE` | 僅核准 Verifier Client CA，拒絕 Runtime／Executor 自行呼叫 |

Authorizer 服務新增 `POST /internal/v1/authorize-receipt`，只能接收
`{"receipt_id":"UUIDv4"}`，所有 Candidate／Scope／Policy／Deadline／Owner
都由保護資料庫的唯一 Promotion／Registry 導出；無 TLS、額外 JSON 欄位、
未知／重複 Receipt 或授權提交不明皆不得產生成功回應。
`FixedAuthorizerMTLSClient` 只送 Receipt，精確核對回覆的 Admission／Owner／
Fingerprint／Candidate Hash，不接受 `trusted_send=enabled` 或額外權限欄位。
Authorizer 啟動 preflight 驗證專屬物理 Login、固定 Schema、禁止跨角色 DML，
以及 `generation_controls.control_revision` 和 Admission 必需欄位的 column-only
UPDATE。此新增服務仍待真 SCRAM／網路隔離與正式 Client HTTP 端到端驗收；
它**只授權 Snapshot，不傳輸 HTTP bytes**，Sender Release Fuse 保持關閉。
隔離 G4 測試額外覆蓋一次性 SCRAM Login 以 `claim_revision` 等四個 Admission
欄位級 UPDATE 完成 Grant→Claim→Authorize；不得 SELECT 已授權 Snapshot bytes，
也有真 TLS 握手檢查無 Client Cert、不同 CA 及偽造 Candidate/Deadline 的拒絕。
這些測試僅證明 Authorizer 邊界，尚不是 Verifier→Authorizer→Sender 端到端。

G4 Sender（只准隔離部署；不屬於 G3b 四容器拓樸）專用：

| 設定 | 用途 |
| --- | --- |
| `MIRAGE_G4_SENDER_DSN_FILE`／`MIRAGE_G4_SENDER_LOGIN` | 獨立 Sender 物理 SCRAM 身分；嚴禁與 Runtime／Verifier／Executor／Validator 共用 |
| `MIRAGE_G4_SENDER_SERVER_CERT_FILE`／`MIRAGE_G4_SENDER_SERVER_KEY_FILE` | 封閉 Sender mTLS Server 憑證及私鑰 |
| `MIRAGE_G4_SENDER_CLIENT_CA_FILE` | Sender 專屬 Caller Client CA，禁止與既有三組 CA 共用 |

Sender 啟動前檢查物理 Login、`NOINHERIT`、無 Role 成員資格、固定 Schema、
無 Schema CREATE，另檢查三個授權／快照資料表 SELECT、單次 Lease INSERT／SELECT、
稽核 INSERT；`response_admissions` 只允許 `state` 欄位 UPDATE，不可取得
整表 UPDATE、其他 Admission 欄 UPDATE、World 變更、Receipt／Proof／Promotion
建立或改寫快照權。多個角色的 DSN 同時出現時直接拒絕啟動。這些是**啟動時
權限檢查合約**，不是已驗證的正式 ACL 授權清單。

`GET /internal/ready` 僅回報 `sender-sealed-pending-security-acceptance`，
`POST /internal/v1/send` 不論輸入或 mTLS Caller 身分一律 503，**不呼叫
StartSend、不建立 Lease、不輸出 HTTP Payload**。
Sender 啟動時還會解析 D-74 版本化部署宣告（`MIRAGE_RESTORE_PROFILE`、
`MIRAGE_RESTORE_PROFILE_VERSION=1`），標準單機不需要 Fence；選配外部模式
缺少權威設定或金鑰、或單機配置殘留 Fence 設定，一律 Fail-Closed。
此部分只是模式配置校驗，尚未完成持久模式釘選、正式 Sender 或 Restore
驗收。503 固定分類為 `fixed_sender_release_gates_not_met`，不再錯稱
「沒有外部 Fence」本身是標準單機的禁止原因。這不改變硬性 Release Fuse。
既有
`PostgresProtectedSender.start_send()` 增加必填 UUIDv4 Receipt，對照
Authorized Snapshot／Grant Binding 的同一 Receipt，阻止只有 Admission ID 的
交叉起送；`ProtectedLeaseTransmission` 在 ASGI 起送前也核對 Lease 的 Receipt。
傳輸物件在**呼叫 StartSend 之前**即標記「已嘗試」，即使 PostgreSQL COMMIT ACK
遺失、來源拒絕或 Lease 回傳錯配，也不可在同一物件再次起送；需要獨立對帳，
不允許把網路故障當成安全的自動重試。
獨立部署候選 `deploy/security-lab/g4-sender-sealed-compose.yaml` 只掛
`g4_sender_delivery`、`g3b_database` 兩個外部網路，沒有公開 Host Port、沒有
G3b Gateway／Executor 網路，使用獨立非 root UID 及四個專用 Secret；絕不改動
既有四容器 CI 拓樸。這份 Compose 只有結構性測試，**尚未做第五容器真實
部署的 Network／Secret／PG ACL 驗收**。正式 Sender 客戶端互通、
DB Commit 不明對帳及 G5 獨立 Restore Fence 均尚未完成。`Trusted Send=OFF`，
G4 不能簽核。

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

### 四容器真實隔離 CI（僅拋棄環境）

新增 `.github/workflows/g3b-four-service-isolated.yml`，使用真 Docker Engine
建置 `mirage-api:standalone`，另起 PostgreSQL 17.6，建立**三張獨立網路**與
四個固定非 root 服務。`g3b_ci_prepare.py` 必須取得
`MIRAGE_G3B_CI_EXPLICIT=ephemeral-four-services-only`，且只能對指定的
`mirage_g3b_ci`／`mirage_ci_owner` 新資料庫執行；否則拒絕任何 migration／
CREATE ROLE。建立五個獨立 SCRAM 身分（四服務加一個負面測試 Runtime），
檢查 NOINHERIT／NOREPLICATION／NOBYPASSRLS 並逐表 GRANT。

CI 每輪臨時簽發三組互異 CA：Gateway→Verifier、Verifier→雙 Executor、
Verifier→Native Validator。臨時原始檔保存在 0700 工作目錄，覆寫 Compose
`external` Secrets 成**本次 CI 的唯讀 file secrets**。不同容器有不同 DSN、
Secret 列表；不替使用者準備正式環境密碼，不呼叫 staging／production DB。
基礎映像的展示 `/healthz:8000` 不適用於專用 mTLS Listener；Compose
關閉該內建 healthcheck，真實 readiness 由 Gateway mTLS probe 檢查。
CI 建庫階段的 `pg_isready` 必須指定 `-h 127.0.0.1`，等待正式 TCP
Listener；PostgreSQL `initdb` 首次啟動的暫時 Unix socket 可能短暫回報
ready 後停止。限時 50 次、每次一秒，逾時明確紅燈，避免把初始化競態
誤判為應用程式 ACL／mTLS 失敗。
最新 Gateway Probe 另覆蓋一筆合法 JWS／固定 Inventory Handler 的
`unknown_synthetic_sku` **409 候選**：來源表寫入、獨立 Validator mTLS
重建 Status／Headers／Body、重播拒絕和 Runtime 無 INSERT 權限均逐項檢查。
此指定 409 候選在固定 SHA `faac8f5f` 的
[真四服務 CI 45211431898](https://github.com/IAN40070510/Mirage_API/actions/runs/45211431898)
獲得隔離 PASS，**仍不是客戶端原生 409**；其他業務拒絕情境尚未逐條簽收。

`g3b_ci_probe.py` 的 Gateway 模式只加入 `g3b_gateway` 網路：

- 真實 CA／Client Certificate 握手後連到 Verifier，匿名拒絕；直接指定 Handler
  RPC 固定 503；Gateway 不能解析 Executor／Validator／DB 的私網 DNS。
- 依三份固定 Registry 枚舉全部 20 路由的實際 HTTPS 無 JWS 請求，要求
  20/20 均固定拒絕 403；這只證明可信入口不能略過 Session 驗證，**不能**
  算作原生業務 200／400／404／409 相容證據。
- 固定 Inventory Request 先驗缺 JWS／篡改／重放都被拒，再送原始 HTTP、
  產生 Proof、固定 Inventory Executor Commit 且只提交一次。
- 對受保護衍生 Cart 發出 Medusa M-03 兩個固定 400／404 原因，必須由
  Executor 產生來源、獨立 Validator 重建相同 Envelope Hash；此 HTTP 200
  只是**內部對帳 RPC**，不是實際送出的客戶端原生 400／404。

Host Audit 模式逐容器比較 Docker Inspect 的**實際** Secret Mount、
Network、non-root UID、read-only rootfs、capability 與沒有 published port；
再用獨立 Runtime SCRAM 確認無權讀取可信 Receipt，且 PG 裡只有指定
Commit／Medusa Source／Operation Proof 數量。任何不符直接使 workflow 紅燈。

以上屬於**真實拋棄式容器與 DB 的 CI 故障／隔離驗證**，仍不等同正式部署
的 Docker/Swarm/Kubernetes NetworkPolicy、Secret ACL、pg_hba、TLS 輪替、
稽核環境權限或正式 Client HTTP Contract 簽核。沒通過實際 workflow 前
不得標記 CI PASS；更不可把這些控制面 200 作為 Trusted Send 證據。

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

隔離回歸證據：
[GitHub Actions 45062662638](https://github.com/IAN40070510/Mirage_API/actions/runs/45062662638)
在固定提交 `7987467a171bd7fdacda81b4484b0b9837770538` 的 PostgreSQL
17.6 CI 得到 `92 passed`，獨立 mTLS 子集 `4 passed`；這仍不是
正式 Compose 容器實體 Secret／Network Policy 的部署級 ACL 證據。

## 套件與授權

自有程式採 Apache-2.0；使用專案既有 FastAPI／Uvicorn／HTTPX、
psycopg／Pydantic／cryptography、PostgreSQL 和 Docker Compose。
依賴與第三方授權請參閱 [授權表](licensing.md)。

### C-09 歷史 Cart Operation 唯讀候選（待真 PG CI）

獨立 Validator 的 `project_cart_read` 現包含 `getCartOperation`：
從 Receipt／原始 GET Proof／派生 Cart 與當前 ReadAdmission 開始，
交叉驗證同世代 committed WorldOperation、不可變 Protected Commit Source
及 World Commit Receipt，重算 Result Digest，再依合成 OpenAPI 固定投影
歷史 Cart／Order 200 JSON。Validator 新增必要 `protected_world_commit_sources SELECT`
且不得具寫入權。未知或未提交操作固定拒絕，不可由 Runtime 捏造 409。
此為內部候選，不是客戶端實收 HTTP，也不具 G4 Send Lease 權限。

### I-01／I-02、C-03～C-06、C-08 成功 Mutation 候選（待真 PG CI）

獨立 Validator 的 `POST /internal/v1/project-synthetic-success` 只接受
受保護 Receipt UUID4，依固定 Synthetic Inventory／Cart Operation 映射，
交叉核對 Verifier 原始 HTTP Proof、Executor 同交易提交的
`protected_world_commit_sources`、`world_operations`、
`world_commit_receipts`、當次 ReadAdmission、目前 WorldSnapshot
以及 Session Epoch／Generation／Key Revocation／期限。只有真正
`committed`、摘要一致且當前快照仍處於相同版本時才從可信結果投影
OpenAPI 規定的成功 200 JSON。Verifier 另核對 Executor 所回報的
Commit Attempt UUID4、Result Digest、Version、Hash，所有 Header／Body
經獨立 Validator 重算；不接受 Runtime 自填 Handler、狀態或候選資料。
缺來源、漂移、錯誤 scope 或重送結果不明均拒絕，不提供 200 fallback。

這僅是內部 `native_projection`，不是公開客戶端的成功回應，
也不核發 Send Lease；不得以本功能替代 G4／G5 安全控制。

### I-03 未知歷史 Inventory Operation 的 409 候選（待真 PG CI）

同一 `getSyntheticOperation` GET Proof／ReadAdmission 中，如果在完整
環境、部署、Session、Generation 及 UUID4 條件下查無 `world_operations`，
獨立唯讀 Validator 才可產生固定 `{"code":"operation_not_found"}`
409 JSON。原始 Scope、目前快照 Hash、Epoch、Generation、Key 與期限照常
重新核對。若記錄存在但為 rejected、來源摘要損壞或 COMMIT 不明，必須
固定拒絕，不可偽裝成「查無」的 409。這仍是內部候選而非實際客戶端發送。

### C-09 未知歷史 Cart Operation 的 409 候選（待真 PG CI）

有效 Cart 衍生 Session／受保護 GET Receipt／ReadAdmission 下，當
`world_operations` 依 World Generation 與 UUID4 完全查無記錄時，
獨立唯讀 Validator 才按固定 Synthetic Cart 規格重建
`{"code":"operation_not_found"}` 409 JSON；如果有記錄但為 rejected、
未驗證 Commit 或摘要不一致，不能降級為 operation_not_found。
原始 GET Fingerprint、Cart Resource、Snapshot、Epoch／Key 與期限都
仍須一致。未知 Cart ID 不能用任意 Runtime 指令當作業務 409。
