# Protected World RPC — 獨立 mTLS 信任邊界（sealed 階段）

## 用途與安全邊界

`src/deception/security/protected_rpc.py` 是 **G3b 正式採用的獨立 mTLS 服務通道**的
首個隔離實作。只有持部署專用 Client CA 所核發有效憑證的客戶端，才能完成
TLS 握手；它不採信 HTTP header 所宣稱的「已驗證身分」。正式部署須使用
**僅供該內部 RPC Caller 使用的 CA／信任集**，不可把一般 Gateway 或公共
服務用戶端 CA 混入。

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
Client CA／DB SCRAM Role／網路來源。此函式目前沒有正式部署環境入口，也
沒有直接呼叫 Executor 的 mTLS Service；不能視為 G3b 整體接線完成。

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

## 驗證與未完成項目

執行 `python -m pytest -q tests/test_protected_rpc_mtls.py`；真實 OpenSSL
產生短期 Server/Client EKU 憑證，在獨立程序驗證成功、無 Client Cert 拒絕
及業務 RPC 固定 503，再執行 `python tools/check_documentation.py`。
Direct Verifier 的真實 mTLS listener 與 PostgreSQL Receipt/Proof 同交易測試
分別在 `tests/test_protected_rpc_mtls.py`、`tests/test_ingress_receipts.py`；
本地缺 PG 時後者 SKIP，須查固定 SHA 的真 PostgreSQL CI。

仍須獨立完成：可信入口對原始 HTTP Request/Operation 的不可偽造綁定、
Service Caller 認證政策、角色與憑證隔離、固定業務 RPC、未知 COMMIT 對帳、
Snapshot／Send Lease／外部 Restore Fence、真容器網路及故障注入。以上
未通過前 `MIR-SEC-WORLD-001=OPEN`、`MSDSS P2=NO-GO`。

## 套件與授權

本專案程式 Apache-2.0；使用既有 FastAPI、Uvicorn、HTTPX、Cryptography
及系統 OpenSSL。第三方套件授權詳見 [套件與授權表](licensing.md)。
