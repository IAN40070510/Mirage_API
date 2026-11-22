# 可信 Ingress Receipt：受保護交易寫入（G2 子切面）

## 用途與邊界

`PostgresIngressReceiptWriter` 只供**獨立可信 Verifier 執行身分**於 Ed25519 JWS 實際驗章後建立 Receipt。`TrustedSessionVerifier.verify_with_receipt()` 先驗證簽章、issuer/audience、Request Fingerprint、部署 Scope 與期限，再透過 Key Revocation Guard 在**同一 PostgreSQL 資料庫、同一 physical connection、同一 IngressTx** 執行 Replay 唯一 INSERT 與 Receipt INSERT。

- `replay_entries` 防止已消費 JTI 再次使用；不單獨代表驗章證明。
- `ingress_receipts` 記錄可信驗證對象；其內容尚須由 GrantTx 一次性綁定 Candidate／Admission，才能成為授權依據。
- `VerifiedContext` 是 Verifier 程序內資料，不是 PostgreSQL 能辨識的 Python 型別。**正式可信性還必須依賴獨立容器／OS 身分、SCRAM Login／Secret／DSN、ACL、pg_hba 與窄 Writer。** 這些部署證據尚未完整驗收。
- `TrustedSessionVerifier.verify()` 保留舊測試相容介面，只消費 Replay，**不得作為新授權入口**。`trusted_http.from_environment()` 既有 Release Fuse 仍不可旁路；production trusted-send 維持 DISABLED。

## 輸入、輸出與使用範例

輸入為可信程序內的完整 Compact JWS、由服務端計算的 request fingerprint、部署固定 issuer/audience/environment/deployment、Verifier 專用 DSN 及同一 DSN 的 Key Guard／Replay Store／Receipt Writer。不可接受 Runtime 提供的 `verified=true`、已解析 claims、kid 覆寫或 policy version。

```python
from deception.security.ingress_receipt import PostgresIngressReceiptWriter

# verifier 需由可信部署程序以獨立角色及核准公鑰建置；示意不含密鑰配置。
writer = PostgresIngressReceiptWriter(verifier_dsn,
    environment_id="approved-env", deployment_id="approved-deploy")
claims, receipt_id = verifier.verify_with_receipt(
    compact_jws, expected_issuer="approved-issuer", expected_audience="mirage",
    request_fingerprint=trusted_fingerprint, environment_id="approved-env",
    deployment_id="approved-deploy", receipt_writer=writer)
```

成功後取得已驗證 claims 與 Receipt UUID；失敗可能是 JWS 不合法、Key 已撤銷、Replay 衝突、跨 DSN、Schema/ACL 不足、寫入失敗或 COMMIT 結果未知。不得在 COMMIT 未知時重消費 JTI、補建 Receipt 或重試業務副作用；須沿不可變 Operation ID 對帳（尚待 G2/G3 整合）。

## 驗證

### G3b：固定 HTTP Operation 證據（增量，未接線）

獨立 Verifier 可使用 `PostgresIngressReceiptWriter(..., verified_request=normalized)`；
`normalized` 必須是 Verifier 直接取得的 `NormalizedRequest`，不能由 Runtime
宣稱為「已驗證 JSON」。`derive_verified_operation()` 從固定的 synthetic
Inventory／Cart OpenAPI 路由與原始 request method/path 導出唯一 Operation，
要求 raw_path 與解碼後路徑一致、禁止 percent-encoding 路由別名與非空 query。
若 Signature 綁定的 Request Fingerprint 與這份原始快照不一致，Receipt Writer
在 Replay/Receipt 同一交易內拒絕，JTI 消費也回滾。

`migrations/023_verified_http_operations.sql` 新增受保護
`protected_http_operation_bindings`，保存 Receipt ID、固定 platform／operation、
method／path_template、完整 Request Fingerprint 與 Body SHA-256；資料不得更新
或刪除。舊 Receipt 即使 fingerprint 相同，也沒有新 Operation Binding，
不得以新服務 RPC 自動執行。此增量保留原本 `verified_request=None` 相容測試，
但這種舊入口不具可信 Operation 權威。

目前只支援 Synthetic Inventory/Cart，Medusa native mapping、URL/authority
部署政策、固定 handler 與 RPC 消費端的交叉驗證仍未完成。**獨立 mTLS sealed
服務不因本表存在就開放業務或 Trusted Send。**

驗證：`python -m pytest -q tests/test_operation_binding.py`；真實 PostgreSQL
則以 `MIRAGE_POSTGRES_TEST_DSN` 執行
`python -m pytest -q tests/test_ingress_receipts.py`。

- `tests/test_ingress_receipts.py`：完整 pytest／真實 PostgreSQL 隔離 Schema 測試（需 `MIRAGE_POSTGRES_TEST_DSN`）；未在本地執行，等待 CI。
- `deploy/security-lab/receipt_atomic_probe.py`：不依賴 pytest 的獨立 Oracle PostgreSQL 17.6 探針；只有 `MIRAGE_LAB_EXPLICIT=mir-sec-world001-lab` 且固定專用 DB 身分、一次性新 Schema 才可執行。
- `deploy/security-lab/verifier_receipt_role_probe.py`：在同一隔離 Lab 以實體 `mir_sec_verifier` SCRAM 登入驗證 Receipt／Replay 正向寫入；檢查 Admission、Generation、Receipt DELETE 及 `SET ROLE` 越權遭 SQLSTATE `42501` 拒絕。測試腳本只為一次性 Schema 授予最低需要的 DML，並由 Schema Owner 做建置與清除。不可外推為正式服務 Secret 或 IPC 隔離已通過。
- `migrations/017_trusted_ingress_receipts.sql`：FK 強制 Replay／Receipt 一致，`PUBLIC` 不具表 DML；實際 Verifier／Runtime ACL 由獨立部署腳本管理。
- `PostgresReplayStore.gc()` 對過期 JTI 只刪除**未**被 Receipt 參照者；FK 不允許清掉仍供 Grant／對帳使用的墓碑。這是保守保留政策，將來仍須由獨立 GC Role 執行正式 Retention 與 Restore 協定，不能由 Runtime 直接 `DELETE`。

**時鐘信任**：Receipt 寫入之前，Verifier 在 Key Lock 取得後使用 PostgreSQL `clock_timestamp()` 再檢查 JWS 的 `iat`、`nbf`、`exp` 與部署容許的 skew；呼叫端提供的 Python `now` 不得繞過資料庫權威時間。這是單一測試切面的保證，尚不涵蓋跨交易的 Grant／StartSend Deadline。

### 目前限制

此版本**未**實作正式遠端 Verifier 服務 IPC、受保護 Grant Binding／Authorized Snapshot、StartSend 的新信任鏈、未知 COMMIT 的操作對帳或 Restore Anchor。真實 DB 子測試成功不能關閉 `MIR-SEC-WORLD-001`，仍需 G1–G6 全部驗收與 Owner／DBA／Security 簽核。

套件與授權：使用專案既有 `cryptography`、Pydantic、`psycopg` 與 PostgreSQL 17；不新增模型、第三方遠端驗章服務或新資料集；授權遵循專案依賴文件。
