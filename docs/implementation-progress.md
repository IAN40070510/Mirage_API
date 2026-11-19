# Mirage_API 實作與驗收狀態

本文件記錄 Mirage 模組可使用的範圍與證據。正式 MSDSS 接線、部署秘密及 staging 導流屬整合階段，不是獨立 Mirage 啟動的先決條件。首次使用見[安裝指南](getting-started.md)。

## 已實作範圍

| 階段 | 可使用能力 | 驗收邊界 |
| --- | --- | --- |
| 唯讀世界 | 不可變 scope／snapshot、完整性摘要、唯讀准入 | 合成商品展示可獨立啟動，預設固定文字備援。 |
| 共享儲存 | PostgreSQL Session 映射、CAS、epoch、Lease、Watermark | migration 001–016；資料庫錯誤不建立替代世界。 |
| 投影與契約 | 固定來源、核准差異、Registry／Profile 撤銷 | 支援商品展示及七項原生 Store 映射，不批准完整 Medusa Store。 |
| 准入與傳輸 | Grant／Claim、Cutover、起送授權與緊急撤銷 | 精確最終 bytes 與單次發送；ASGI 完成不表示客戶端已收到。 |
| 互通及故障 | Python／Node 固定向量、未知提交、網路中斷及真正 PG 崩潰恢復 | 多程序及隔離實測，不宣稱任意生產組態符合性。 |
| 業務事件 | 訪客購物車、合成訂單、庫存預留／取消、冪等恢復 | 明確啟用可信入口才可寫入；不連真實庫存或付款。 |
| 請求 Audit | 假名化觀察、驗證結果及 Grant 原子關聯 | 不保存原始憑證、不回補歷史，也沒有公開稽核匯出。 |
| 原生時間 | UTC 格式及順序檢查、單調業務時間 | 回撥不延長 Lease；讀寫都拒絕不合法歷史。 |
| 獨立客戶端 | HTTPX 請求摘要介面 | 固定 wire 向量驗證，不需要外部 Gateway 原始碼。 |

## 驗收紀錄

2026-11-18 的模組基線為 **1221 passed、7 個明列 opt-in skipped，0 failed／errors**。四批共 1228 個 testcase 身份與原收集清單一致，來源 hash 在執行期間未變；這個數字是發布整理前的實測，不冒稱後續 GitHub commit 的 CI 結果。

七項 skip 分別是四個隔離容器案例、還原，以及 Medusa 身份／實際 Gateway 兩項。容器四項與原 pg_dump／pg_restore 測試已在該輪 ARM64 另通過，身份兩項另有 2026-11-17 的實際 Medusa 驗收。skip 與通過分開記錄。

### 2026-11-20 七項隔離整合驗收

2026-11-20 使用 Oracle Ubuntu ARM64 主機，針對上述七個**明確 opt-in** 的 testcase 另建一次性驗收環境，逐項執行後得到 **7 passed、0 failed、0 skipped**。這是獨立重驗的合計，不是把 2026-11-18 全套回歸的七個 skip 事後改成 pass，也不是新 commit 的 GitHub Actions 結果。當次測試使用未改動執行邏輯的 Mirage／MSDSS 來源；MSDSS Gateway 指測試載入的實際 Python dispatcher，不是用來登入主機的 Gateway SSH 服務。

| 具名測試 | 隔離驗證內容 | 最終結果 |
| --- | --- | --- |
| `tests/test_medusa_live.py::test_real_medusa_customer_identity_and_logout` | Medusa 2.22.4 合成管理員／顧客、Bearer／Cookie、登出及 Session 隔離 | PASS |
| `tests/test_msdss_wire.py::test_gateway_dispatch_to_independent_mirage[medusa-pipeline]` | 真實 MSDSS proxy 判定及 dispatcher、測試 CA 的 mTLS、獨立 HTTPS Mirage、跨程序 Replay | PASS（修正隔離 CA 設定後重跑） |
| `tests/test_container_runtime.py::test_packaged_trusted_service_guest_checkout` | 已封裝 Mirage 的訪客購物車、冪等下單與取消庫存回補 | PASS |
| `tests/test_container_runtime.py::test_packaged_native_store_mapping` | 原生 Store 路由、商品／訂單關聯、衝突拒絕及投影核准證據 | PASS |
| `tests/test_container_runtime.py::test_packaged_profile_revocation_requires_explicit_isolated_opt_in` | 僅在可丟棄 DB 永久撤銷 Profile，確認原生 API 拒絕且安全投影保留 | PASS |
| `tests/test_container_runtime.py::test_packaged_key_revocation_requires_explicit_isolated_opt_in` | 僅在可丟棄 DB 撤銷簽發 kid，確認舊授權無法增加世界／Replay／准入 | PASS |
| `tests/test_database_restore.py::test_restore_preserves_world_receipts_and_profile_tombstones` | `pg_dump -Fc`／`pg_restore` 到**另一個資料庫名稱**，比對整張表的內容摘要、世界與撤銷墓碑 | PASS |

**隔離拓樸與信任界線：** 專案專用、未公開任何主機連接埠的 Docker internal network；兩個全新 PostgreSQL 容器（Mirage 使用 PostgreSQL 17、Medusa 使用 PostgreSQL 16）、一個 Redis 7、一個 Medusa 2.22.4、一個只讀根檔案系統且以非 root 執行的 Mirage。合計五個長駐測試容器及三個具名資料卷，沒有掛接 `mirage-api`、`mirage-app` 或 `msdss-staging` 的資料卷。測試使用一次性 Ed25519 簽章私鑰、另行產生的 mTLS 憑證、合成管理員／顧客及專用 DB 密碼；私鑰未進入 Mirage 服務容器。pytest 在 ARM64 上的 Python 3.13.13／pytest 8.4.2 容器執行，Medusa 身份測試透過**同一隔離容器的 loopback** 存取，沒有對外開 port。各 PostgreSQL fixture 另建／刪除測試 schema；還原測試把獨立 Mirage 資料庫備份至不同命名的資料庫，沒有碰正式資料。

備份前在來源**合成**資料庫觀察到 `world_snapshots` 8、`world_events` 5、`world_commit_receipts` 9、`projection_profile_revocations` 1、`response_audit` 51、`ingress_refusal_audit` 5、`trusted_key_revocations` 1 筆；測試核對每張表的行數與排序後 SHA-256 摘要相等，並重新載入快照、驗證撤銷仍生效。這不是正式商店的備份驗證，也不代表 PITR／跨區復原通過。

**mTLS 首次失敗與重驗：** 原測試以 `openssl req -x509` 產生的短期 CA 缺少 X.509 `keyUsage`，Python 3.13／OpenSSL 嚴格驗證會報 `CA cert does not include key usage extension`，導致 HTTPS 探測逾時。這次只在測試容器使用獨立 `OPENSSL_CONF`，讓該自簽 CA 增加 `keyUsage = critical, keyCertSign, cRLSign`，不放寬 TLS 驗證、不修改測試執行邏輯或服務端憑證信任，隨後同一具名案例 **1 passed（10.06 秒）**。可重現的測試用 CA 設定重點如下；正式 CA 另依自己的 PKI 政策處理：

```ini
[req]
distinguished_name = req_dn
x509_extensions = v3_ca
prompt = no

[req_dn]
CN = Mirage acceptance CA

[v3_ca]
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
```

**重驗前置條件：** `MIRAGE_POSTGRES_TEST_DSN` 必須指向可建立／刪除 schema 的**專用測試資料庫**；身份／wire 測試另需 `MIRAGE_MEDUSA_TEST_ORIGIN`、`MIRAGE_MEDUSA_TEST_ADMIN_EMAIL`、`MIRAGE_MEDUSA_TEST_ADMIN_PASSWORD` 及 `MSDSS_ROOT`，Medusa origin 為測試網路命名空間內的 loopback；容器測試另需 `MIRAGE_CONTAINER_TEST_ORIGIN`、`MIRAGE_CONTAINER_TEST_KEY_FILE`、`MIRAGE_CONTAINER_NATIVE_PUBLISHABLE_KEY`。兩項破壞性隔離案例須各自明確設定 `MIRAGE_CONTAINER_PROFILE_REVOCATION_TEST=true`、`MIRAGE_CONTAINER_KEY_REVOCATION_TEST=true`，簽章金鑰撤銷安排在其他可信容器案例之後。還原測試需 `MIRAGE_BACKUP_RESTORE_TEST=true` 與**不同命名**的 `MIRAGE_BACKUP_SOURCE_TEST_DSN`／`MIRAGE_BACKUP_RESTORE_TEST_DSN`；必須先執行真實備份／還原並準備包含各類合成資料的來源 DB。缺少任何前置條件所產生的 skip 不能視為通過；不要將這些變數指向 staging 或正式資料。

**測後撤權與清理：** 測試用五個容器、三個具名卷、隔離網路、短期金鑰、合成帳號及秘密檔案均已刪除；原有七個 Mirage／Medusa staging 服務保持運行。連線工具 Gateway SSH 的專用 `ubuntu` 公鑰已從 `authorized_keys` 精確移除，只保留使用者原始的 Windows 公鑰；Gateway 伺服器登錄為零，執行中工作／排程為零，使用者再從 Windows 以原私鑰登入並確認原公鑰指紋。此撤權只針對此次 Gateway SSH 身分，不是對主機所有使用者／外部權限的完整稽核。

**仍未完成：** 正式 MSDSS 判定與導流啟用、staging 映像切換、GitHub Release／Tag 更新及完整 Protocol v1.1 Conformance。七項隔離測試成功不代表正式端到端流量已切換，也不替代未執行的部署安全檢查。

ARM64 映像驗證了 non-root 10001:10001、唯讀 root filesystem、健康、安裝模組 hash、原生／合成交易及撤銷。時間回撥探測確認下單／取消、原收據與上下文重播、庫存回補與 Lease 不變。另以獨立 PostgreSQL volume 在提交後 SIGKILL 再啟動，查回相同版本、state hash、結果摘要與原 attempt，重試不重複預留；這不是主機斷電或跨區災難恢復測試。

發布整理新增獨立 HTTPX adapter，改用 Mirage 自身介面執行核心 HTTP 測試，避免公開 clone 必須搭配私有 checkout。GitHub Actions 使用獨立 PostgreSQL、Node 固定向量、文件檢查與 Compose 的 16 請求驗證；各 commit 的實際結果以 Actions 及其 JUnit／HTTP 報告為準。

## 可重現檢查

```sh
python tools/check_documentation.py
python -m pytest -q
```

資料庫案例需專用 MIRAGE_POSTGRES_TEST_DSN，不能指向真實商店資料庫。沒有實際 MSDSS／Medusa 的整合案例會明確 skip，普通 Mirage 啟動與核心 HTTP 測試不要求那些服務。完整具名對照見[證據矩陣](conformance-evidence.md)。

```sh
docker compose up --build -d --wait --wait-timeout 180
docker compose exec -T mirage python tools/verify_domain_api.py --domain ecommerce --base-url http://127.0.0.1:8000
```

## 執行位置與交付

本機／CI 執行 pytest、客戶端及 Mirage 程序；SSH 隔離驗收由 Ubuntu 提供 PostgreSQL、Medusa／Redis 及 ARM64 映像。程式透過明確白名單、脫敏與 SHA-256 核對的封存建置，未將私鑰放入映像。測試容器、專用資料庫、volume、隧道及短期私鑰已清理，原報告與驗收映像保留。

公開版本排除 generated 產物、local-notes、秘密與外部專案變更補丁。私人環境的詳細歷史與外部變更說明保留本機，不上 GitHub。MSDSS 來源、既有服務及 staging 未由本模組自動修改或切換。

## 目前限制

預設展示服務是合成商品查詢；可信交易入口需要部署者配置 JWS 身份、公鑰與 PostgreSQL。正式攻擊判定器與導流由外部系統負責。L3 真實資料銜接維持停用；不提供完整 Medusa API、真實付款／配送／退款、產品刪除生命週期、集中稽核平台或生產秘密輪替管理。

自有程式與文件採 Apache-2.0。採用套件、固定來源與模型權利見[授權表](licensing.md)；通過本版具名測試不代表任意部署通過 Protocol v1.1 符合性。
