# Protected World RPC — 獨立 mTLS 信任邊界（sealed 階段）

## 用途與安全邊界

`src/deception/security/protected_rpc.py` 是 **G3b 正式採用的獨立 mTLS 服務通道**的
首個隔離實作。只有持部署專用 Client CA 所核發有效憑證的客戶端，才能完成
TLS 握手；它不採信 HTTP header 所宣稱的「已驗證身分」。正式部署須使用
**僅供該內部 RPC Caller 使用的 CA／信任集**，不可把一般 Gateway 或公共
服務用戶端 CA 混入。

### G4 提前施工：封閉獨立 Sender（未放行）

`create_fixed_sender_app()`／`serve_fixed_sender_mtls()` 讓 Sender 使用另一組
Server Certificate 和專屬 Caller Client CA，Uvicorn 嚴格要求 Client Cert，
不採用 Proxy Header、不允許 HTTP fallback。由 `protected_services` 的
`MIRAGE_G3B_SERVICE_ROLE=sender` 組裝，實際 SCRAM Login 必須經過獨立
物理身分與最小 ACL 預檢。`GET /internal/ready` 僅代表封閉入口已啟動；
`POST /internal/v1/send` 永遠 503，不因 Payload、Admission、Receipt、
任何 Caller Header 或環境旗標開啟一次性 Send Lease。獨立 Restore Fence
與跨 DB Restore／Purge／Send 競態未過關前不接真實起送路徑。
真實 mTLS 握手／匿名 Client 拒絕的測試只驗傳輸，不等於部署級 ACL 簽核，
也不影響原先四容器 G3b 正式服務拓樸。

### G3b Direct Verifier HTTP 入口（隔離增量）

`create_direct_verifier_app()` 與 `serve_direct_verifier_mtls()` 為獨立 Verifier
程序提供**直接接收原始 HTTP** 的入口。TLS Client CA 必須只核發給可信原始
Ingress Gateway，不得簽發給 HTTP Runtime；原始 Request 必須由該 Gateway
直送 Verifier，不能由 Runtime 改寫後當作觀測的 HTTP。Verifier 從 ASGI
`raw_path`、原始 header、body、完整 URL 及實際 HTTP Method 推導唯一
Operation，計算 Fingerprint，再用固定 Key Registry 驗章及在同一 PostgreSQL
IngressTx 生成 Replay Tombstone／Receipt／`protected_http_operation_bindings`。

入口不接受 `operation`、claims、`verified=true` 或可由 Runtime 製造的
Header 身分旗標，也不接受代理 `X-Forwarded-Proto` 取代 TLS；Uvicorn
`proxy_headers=False`。真正的 mTLS Gateway 呼叫可取得 `receipt_id` 與固定
`operation_id` 供後續專用服務查回，**不是給一般 Client 的已授權回應**。
部署拓樸須保證 Gateway→Verifier 路徑沒有 Runtime 中介，並獨立驗證 Gateway
Client CA／DB SCRAM Role／網路來源。`FixedExecutorMTLSClient` 可由獨立
Verifier 持專用 mTLS 憑證使用：驗證成功後只傳 Receipt ID／原始 Path／Body
至已驗證主機名稱的 HTTPS Executor，完全不傳 Runtime 自選 Handler／Scope，
並禁止 HTTPX 自動使用環境 Proxy。ACK 不明只回固定 503，**不重試副作用**。
此模組的 `from_environment()` 仍只啟動 sealed listener；新增的
[`protected_services` 角色專用 CLI](protected-services.md) 才會依固定平台路由
與獨立 SCRAM／Secret 掛載 Verifier／Executor，但尚未完成正式部署與
可信客戶端 HTTP 回應驗收，不能視為 G3b 整體接線完成。

### G3b 固定 Executor HTTP（隔離增量）

`create_fixed_executor_app()`／`serve_fixed_executor_mtls()` 可使用與 Gateway
不同的 **Verifier→Executor 專用 Client CA** 啟動隔離業務 RPC。
`POST /internal/v1/execute` 的唯一輸入是 `receipt_id` 及原始
`raw_path_b64`、`raw_body_b64`；另可提供只含 Fingerprint 綁定欄位的
`original_http`（`request_id`／`raw_url`／核准 Headers），供 Medusa 核對
原始 `x-publishable-api-key`、Content-Type 與 Header 次序。此資料不轉送 JWS，
且完整 Fingerprint 必須與不可變 Proof 相符。服務不接受 Handler、Session Binding、Scope、
價格或預期版本等 RPC 欄位。服務先用專屬 Executor 實體 DB Login 查回
`ingress_receipts`／不可變 Operation Proof，再確定性選擇合成 Inventory
或 Cart／Order 的既定 Handler。錯 Body、路由／資源錯配時，禁止先建立
ReadAdmission；原始操作驗證通過後，Read 與受保護 World Commit 才可落地。

同一 Receipt 的精確重試只使用既有 Commit Key；Medusa 僅允許已固定
`POST /store/carts/{id}/line-items` 的合法拒絕：錯誤 publishable key／
NativeItemBody（400），或已受保護 Cart catalog 中確實沒有 variant（404）。
每種拒絕都必須從同 Receipt 的受保護 ReadAdmission 取得來源，寫入
`protected_medusa_rejection_sources` 不可變資料表，精確固定原生 JSON 封套
摘要；Candidate Promoter 核對原始 Operation、Scope、Fingerprint、
Read Source 和封套 hash。Runtime 自填 `SecurityErrorSource` 無受保護來源
不能 Promotion，未實作的原生成功操作和其他錯誤一律 503。
返回值屬於**受保護內部執行結果**，尚非
正式回給 Client 的業務回應，也不提供 Candidate Validation／Grant／Send。
Inventory I-03 `GET /synthetic/operations/{attempt}` 與 I-04
`GET /synthetic/inventory/{sku}` 另有固定 Handler 讀取子切面：Executor 從
受保護 Proof 核對原始空 Body／路徑、UUID4／SKU，再由 Receipt 建立
ReadAdmission；RPC 僅返回 `inventory_read_admitted`、來源 ID、世代及
版本／Hash。I-04 可再透過獨立 Validator 的
`POST /internal/v1/project-inventory-snapshot`，只按 Receipt 及唯讀 World
Snapshot 重建精確 `200 {sku,available,state_version}` 候選；Verifier 逐欄核對
Scope、Fingerprint、SnapshotSource、Body 與 Hash，**仍只回內部 200**。
此外 Validator 的來源 ID／Generation／Version／State Hash 必須與先前已驗證的
Executor ReadAdmission Metadata 完全一致；任何兩服務來源分歧固定 503。
I-03 原先只有 ReadAdmission 而沒有可信查詢 Payload；I-04 未知 SKU 的
業務 409 新增由獨立 WorldSnapshot 驗證「確實缺 SKU」的固定拒絕候選，
仍待真 PG／四容器 CI，外層仍只回內部對帳 200。
I-03 已增加另一條**待真 PG CI 的獨立候選**投影路徑：
`project-inventory-operation` 只接受 Receipt，核對同世代 `committed` 的
WorldOperation＋Commit Receipt＋ReadAdmission，重建固定 `200` 操作結果。
目前仍缺正式客戶端 HTTP、未知操作的可信 409 與完整 G4/G5，
不能因這項候選而把 I-03 當成正式完成。
包含百分比編碼 SKU 的 URI 相容測試仍
未解決；ReadAdmission 子切面已在固定 SHA `49fc6ed8` 的
[真 PostgreSQL CI](https://github.com/IAN40070510/Mirage_API/actions/runs/45185402530)
通過，但完整 GET 回應仍 OPEN。

**I-04 200 Candidate 待固定 SHA 真 CI**：Validator 對受保護的
`protected_world_read_sources`、`read_admissions`、原始 GET Proof 與
World 快照完整性雜湊做一致性核對；快照版本已移動、過期、缺 SKU、
Session Epoch／Key 撤銷時固定失敗而非合成業務 409。獨立 Validator
需要唯讀 `world_snapshots` SELECT，Runtime 無權持有該物理 Login。
新增 Synthetic 固定 mutation 真業務拒絕來源：Executor 將已保存
`rejected` 的結果與 409 固定 Envelope Hash 原子寫入受保護拒絕表，
獨立 Validator 從 Receipt 重建 JSON `{"code":"..."}`。Verifier 僅在
Executor 結果為真 `rejected` 時透過另一組 mTLS 取得 `native_projection`，
且會重驗完整 409 bytes、Scope、Fingerprint；此候選不可視為 Client HTTP
409，也不包含尚未取得來源的 CAS conflict／未知操作拒絕。新切面尚待真 PG CI。
已存在可信 Read Source 的重試只查回既有唯一來源的完整 Scope／Fingerprint／
State Version／Hash／期限，不能再 INSERT 第二個 ReadAdmission 來源；來源錯配
或到期拒絕。首次提交才建立新的受保護讀取來源。
既有 `create_sealed_app()` 與 `from_environment()` 依舊封閉；隔離測試現
已可經真 HTTPS/mTLS 完成 Verifier→Executor 兩程序固定 Inventory 提交，
但尚缺實際部署的 Gateway 網路路由、正式 SCRAM／CA 配置驗收、
合成 Session Bootstrap、全 Medusa 原生成功回應與 400／404 相容性、
實體部署角色隔離，不能切換到正式流量。

目前服務特意維持 `sealed`：沒有 Executor、Validator 或 Authorizer DB DSN；
`POST /internal/v1/execute` 永遠返回 503，不得執行業務。`GET /internal/ready`
只回報 `control_plane=sealed` 與 `trusted_send=disabled`，不是正式健康或放行證據。
此狀態可以測試傳輸隔離，不宣稱 G3b HTTP 業務接線或 G4 發送完成。

## 輸入／輸出與部署

由部署者透過獨立 Secret Mount 提供：

| 變數 | 意義 |
| --- | --- |
| `MIRAGE_PROTECTED_RPC_CERT_FILE` | mTLS Server certificate（須有 serverAuth EKU） |
| `MIRAGE_PROTECTED_RPC_KEY_FILE` | Server 私鑰，不能與 Client CA 共用 |
| `MIRAGE_PROTECTED_RPC_CLIENT_CA_FILE` | 專供已核准 Caller 的 Client CA PEM |
| `MIRAGE_PROTECTED_RPC_HOST` | 綁定位址，預設 `127.0.0.1`；跨容器必須搭配獨立網路隔離 |
| `MIRAGE_PROTECTED_RPC_PORT` | TCP port，預設 `8444` |

啟動命令（僅啟動 sealed transport）：

```bash
python -m deception.security.protected_rpc
```

Server 使用 Uvicorn TLS `ssl_cert_reqs=ssl.CERT_REQUIRED`，不提供忽略
Client Certificate 的參數。TLS 憑證須由實際部署控制面管理；不得在 repo
加入生產私鑰、共用 Runtime DSN 或 fallback 明文 HTTP。此階段僅限隔離
Lab，禁止將 `/internal/ready` 的成功當成開放 Trusted Send 的依據。

## 失敗處理

- 未提供／空白／重用 TLS 檔案：啟動前 `ProtectedRpcConfigurationError`。
- 無有效 Client Certificate：TLS 握手被拒，不落入 HTTP Handler。
- 使用有效 Client Certificate 呼叫業務：固定 503，沒有 World Side Effect。
- CA Rotation／RPC 服務失聯：Fail-Closed；上游不得退回舊共用 DSN。
- Direct Verifier 收到未知／有歧義的路由或錯 Fingerprint／JWS：HTTP 403，
  不得建立 Replay／Receipt／Operation。缺 TLS HTTPS Scope 固定 503；
  `x-trusted-session` 重複欄位亦拒絕。這些是**內部驗證錯誤**，不是
  Medusa 合法 400／404 的受保護業務來源證明。
- Fixed Executor 的 RPC JSON 有重複欄位、額外 Handler、非正規 Base64
  或超過上限：HTTP 400／413；TLS 不存在、Proof 缺失或來源不可核對：503。
  實際 COMMIT ACK 不明不得由上游自行重新起送。

## 驗證與未完成項目

執行 `python -m pytest -q tests/test_protected_rpc_mtls.py`；真實 OpenSSL
產生短期 Server/Client EKU 憑證，在獨立程序驗證成功、無 Client Cert 拒絕
及業務 RPC 固定 503，再執行 `python tools/check_documentation.py`。
Direct Verifier 的真實 mTLS listener 與 PostgreSQL Receipt/Proof 同交易測試
分別在 `tests/test_protected_rpc_mtls.py`、`tests/test_ingress_receipts.py`；
本地缺 PG 時後者 SKIP，須查固定 SHA 的真 PostgreSQL CI。
`test_direct_verifier_dispatches_inventory_over_real_executor_mtls_once` 在真
PostgreSQL CI 以不同程序、測試 CA 與 HTTPS 驗證單一 JWS→Proof→固定
Inventory Commit 一次，重送遭 Replay 拒絕。它只證明**測試用**隔離鏈路，
測試仍使用同一 DB Login，不能替代部署級獨立 SCRAM／Secret 負面測試。
`test_direct_verifier_medusa_400_over_real_executor_mtls` 另驗證原始
publishable key／Body 經 Fingerprint 在 Verifier→Executor 雙程序 mTLS 傳輸後，
才能建立 400 Read Source；簽發後改 key 為 403 且不得消耗 Replay／新建來源。
`test_three_process_gateway_verifier_executor_distinct_mtls_roots` 新增真 HTTPX
Gateway→Uvicorn Verifier→另一 Uvicorn Executor 三程序與相互獨立 CA：
含真 JWS、拒絕無憑證／錯誤 Client CA、未簽或簽後改 Body、Replay 單次副作用。
後續隔離 CI 把這三個程序改用不同 SCRAM-SHA-256 實體 Login，驗證
Verifier／Executor／Runtime 最低權限與 `SET ROLE` 跨角色拒絕。測試仍由同一
pytest 父程序啟動服務，不等於正式容器彼此不可見的 Secret／網路隔離；而且
尚無完整候選回應與正式 Gateway 路由，僅為跨程序傳輸與實體 DB 登入的
正反面子證據，不是 G3b 放行簽核。
固定 SHA `efd996d7cfea489f39d402f4392b29a89130644a` 的真 PostgreSQL
[CI 45057222355](https://github.com/IAN40070510/Mirage_API/actions/runs/45057222355)
為 `65 passed`、mTLS `4 passed`；
[容器 45057222331](https://github.com/IAN40070510/Mirage_API/actions/runs/45057222331)
成功，但不是正式服務拓樸驗收。
隔離資料庫的 404 另以可信 Cart catalog 缺失和 Candidate Promotion 驗證，
尚未涵蓋全部原生 Medusa 路由。

仍須獨立完成：部署級 Gateway→Verifier 原始 HTTP 來源證明、
Service Caller 認證政策、角色與憑證隔離、完整業務 RPC、未知 COMMIT 對帳、
Snapshot／Send Lease／外部 Restore Fence、真容器網路及故障注入。以上
未通過前 `MIR-SEC-WORLD-001=OPEN`、`MSDSS P2=NO-GO`。

## 套件與授權

本專案程式 Apache-2.0；使用既有 FastAPI、Uvicorn、HTTPX、Cryptography
及系統 OpenSSL。第三方套件授權詳見 [套件與授權表](licensing.md)。
