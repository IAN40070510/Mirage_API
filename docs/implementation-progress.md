# Mirage_API 實作與驗收狀態

## 2026-11-25 G3b～G6 安全 Gate 增量（未正式結案）

| 階段 | 隔離實測 | 尚未完成的放行條件 |
| --- | --- | --- |
| G3b | ARM64 四個獨立 non-root mTLS 服務與專用 SCRAM、20/20 無簽章路徑拒絕；I-01～I-04 的 8 組、C-01～C-09 的 16 組、M-01～M-07 的 10 組原生 Client 200／指定 400／404／409，均由真 Ed25519 JWS→Verifier→Executor→Validator→Publisher→Authorizer 跨七 TLS Listener、唯一 PG Lease 與 Replay 拒絕隔離驗收；Cart 跨衍生 Scope／舊 CAS 與 Medusa 錯 Key／跨資源額外 fail-closed | **20 路由尚未完成全部指定錯誤／CAS／故障／URL 矩陣**，Medusa 非空初始品項、完整官方契約變體、正式七服務獨立最小權限 Login／憑證輪替及安全審核 |
| G4 | Receipt-only Sender 綁定不可變 DB Pin，唯一 Lease；Gateway 原始 HTTP mTLS、授權 Envelope Hash 與 Client 原生 HTTP；隔離七 TLS／真 PG／JWS 重放測試已通過 | 正式服務仍封閉 503；正式 Sender／Gateway 部署、完整正式拓樸與 Client 端安全審核 |
| G5 | 已知 Restore／Purge、不可逆 Lease、密碼學 Anchor 模擬與獨立 PostgreSQL Fence 的隔離回歸；精確 `7ada6fd` ARM64 `53 passed` 額外覆蓋真 SCRAM、舊 Sender SQL DB Trigger、TEMP 偽裝、COMMIT ACK 不確定與標準單機 Profile fail-closed | 正式 Restore 控制面／故障域啟動、實際 DB Restore／GC／部署 Schema 和可選外部 Fence Acceptance；單機不得宣稱防整機快照倒退 |
| G6 | 真 JWS 全鏈經七 TLS／PG Lease／原生 200，JWS 重放阻擋；Sender TCP 停機、復原新 Receipt、COMMIT 後未知 ACK、Known Restore 與實際 Sender mTLS Read Timeout 五類隔離案例均 fail-closed；Gateway Client 下游斷線不重送 | Client 實體掉線／網路封包遺失／跨節點重啟與延遲綜合矩陣、可追溯放行與 Owner 簽核 |

隔離候選分支的 PR 為 [#32](https://github.com/IAN40070510/Mirage_API/pull/32)、[#33](https://github.com/IAN40070510/Mirage_API/pull/33)、[#34](https://github.com/IAN40070510/Mirage_API/pull/34)，全為 Draft／**NO-GO**，正式 `Trusted Send OFF`。#33 確切 SHA `5294d075` 的完整 Python CI **1541 passed／14 skipped**，ARM64 World／Role **258 passed／8 skipped**；#34 的確切 CI 應以該 PR 最新 SHA 與 Actions/JUnit 為準，不能沿用前一版的數字冒充。上述 ARM64 是獨立 `161.33.154.211` 測試區，未修改共用 Oracle 既有部署。

本輪 #34 ARM64 隔離驗收：G6 Sender 停機／新 Receipt 復原／已提交 Lease 回覆遺失／Known Restore **3/3**（其中停機與復原同一案例）；Gateway＋Sender 回歸 **26 passed**，工作 `job_01M891JFMM006JBZV10PKQHQVE`；新增同一 Client HTTP 真 Ed25519 JWS→Gateway→Verifier→Executor→Native Validator→Publisher→Authorizer→Sender 的七 TLS Listener 單案例 **1 passed**，工作 `job_01M891W4M600PCGRJD3A0RNZ1T`。該七 Listener 測試使用短期獨立測試 CA 與拋棄式同一 PG schema；各 mTLS Listener 真正獨立，資料庫角色最小權限的完整正式分離仍由別項 Role 驗收與部署 Gate 限制，**不可把此 Lab 視為正式可用性證明**。

較新提交 `1a9fe1f` 的 I-01～I-04 真 Client 七 TLS 完整回歸：ARM64 工作 `job_01M892PB7400PMHA4BNXD22W6A`、`28 passed`、JUnit `/tmp/mirage-g3b-g6-20261125.AsFBoE/g3b-i01-i04-exact-1a9fe1f.xml`；新 Cart／Order 測試 `tests/test_g6_cart_full_real_chain.py` 以 Creator→Derived Cart→Derived Order 的有效短期 JWS 經同樣七 Listener，逐筆精確核對 C-01～C-09 的 16 個指定 Client 原生 200／409 子案例及每張 Replay、Promotion、唯一 Lease，另對 Creator 跨 Scope、Cart 假冒 Order Capability 與舊版本 CAS 要求 503。這只是隔離 Sender 的證據，不是正式 production Sender 切換或 Owner 的 Gate 簽署。

`a53893af` 的 C-01～C-09 確切 ARM64 工作 `job_01M8932BYQ005T61RAE9NE927E`：`29 passed`、JUnit `/tmp/mirage-g3b-g6-20261125.AsFBoE/g3b-cart-exact-a53893a.xml`、文件 2182 functions／69 guides PASS。續新增 `tests/test_g6_medusa_full_real_chain.py`：M-01～M-07 共 10 個 Client 原生 200／400／404、10 筆真 PG Promotion／唯一 Send Lease、10 次即時重放拒絕，錯 Publishable Key／Creator 跨 Scope／缺 Item／空 Cart complete／Cart 假冒 Order 503。Medusa Projector 從 repo 固定的 OpenAPI 來源獨立重建 Payload；不允許 Gateway 虛構 Medusa 4xx。全路由均仍需按完整錯誤／故障表逐項簽收後才可放行。

`7ada6fd` 三平台固定 SHA ARM64 合併回歸：`job_01M8939FXM001KK15ZBTSGNCTK`、**30 passed**、JUnit `/tmp/mirage-g3b-g6-20261125.AsFBoE/g3b-all20-exact-7ada6fd.xml`；I/C/M 共 34 個指定原生回應、相互隔離的短期 JWS／PG Promotion／Send Lease 與逐筆 Replay 拒絕。G5 標準單機獨立回歸：`job_01M893DRJW00Z7GF0MPMZR6H75`、**53 passed**、JUnit `/tmp/mirage-g3b-g6-20261125.AsFBoE/g5-standard-roles-exact-7ada6fd.xml`。兩者均只在可拋棄 PostgreSQL／loopback TLS Lab 驗證，詳見[標準單機驗收表](security/world-db/single-node-restore-profiles.md)，所有全域 Release Gate 仍 NO-GO。

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

| 具名測試 | 隔離驗證內容 | 最終結果 |
| --- | --- | --- |
| `tests/test_medusa_live.py::test_real_medusa_customer_identity_and_logout` | Medusa 2.22.4 合成管理員／顧客、Bearer／Cookie、登出及 Session 隔離 | PASS |
| `tests/test_container_runtime.py::test_packaged_trusted_service_guest_checkout` | 已封裝 Mirage 的訪客購物車、冪等下單與取消庫存回補 | PASS |
| `tests/test_container_runtime.py::test_packaged_native_store_mapping` | 原生 Store 路由、商品／訂單關聯、衝突拒絕及投影核准證據 | PASS |
| `tests/test_container_runtime.py::test_packaged_profile_revocation_requires_explicit_isolated_opt_in` | 僅在可丟棄 DB 永久撤銷 Profile，確認原生 API 拒絕且安全投影保留 | PASS |
| `tests/test_container_runtime.py::test_packaged_key_revocation_requires_explicit_isolated_opt_in` | 僅在可丟棄 DB 撤銷簽發 kid，確認舊授權無法增加世界／Replay／准入 | PASS |
| `tests/test_database_restore.py::test_restore_preserves_world_receipts_and_profile_tombstones` | `pg_dump -Fc`／`pg_restore` 到**另一個資料庫名稱**，比對整張表的內容摘要、世界與撤銷墓碑 | PASS |

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

**測後撤權與清理：** 測試用五個容器、三個具名卷、隔離網路、短期金鑰、合成帳號及秘密檔案均已刪除；原有七個 Mirage／Medusa staging 服務保持運行。連線工具 Gateway SSH 的專用 `ubuntu` 公鑰已從 `authorized_keys` 精確移除，只保留使用者原始的 Windows 公鑰；Gateway 伺服器登錄為零，執行中工作／排程為零，使用者再從 Windows 以原私鑰登入並確認原公鑰指紋。此撤權只針對此次 Gateway SSH 身分，不是對主機所有使用者／外部權限的完整稽核。

ARM64 映像驗證了 non-root 10001:10001、唯讀 root filesystem、健康、安裝模組 hash、原生／合成交易及撤銷。時間回撥探測確認下單／取消、原收據與上下文重播、庫存回補與 Lease 不變。另以獨立 PostgreSQL volume 在提交後 SIGKILL 再啟動，查回相同版本、state hash、結果摘要與原 attempt，重試不重複預留；這不是主機斷電或跨區災難恢復測試。

發布整理新增獨立 HTTPX adapter，改用 Mirage 自身介面執行核心 HTTP 測試，避免公開 clone 必須搭配私有 checkout。GitHub Actions 使用獨立 PostgreSQL、Node 固定向量、文件檢查與 Compose 的 16 請求驗證；各 commit 的實際結果以 Actions 及其 JUnit／HTTP 報告為準。

## 可重現檢查

```sh
python tools/check_documentation.py
python -m pytest -q
```

```sh
docker compose up --build -d --wait --wait-timeout 180
docker compose exec -T mirage python tools/verify_domain_api.py --domain ecommerce --base-url http://127.0.0.1:8000
```

## 執行位置與交付

本機／CI 執行 pytest、客戶端及 Mirage 程序；SSH 隔離驗收由 Ubuntu 提供 PostgreSQL、Medusa／Redis 及 ARM64 映像。程式透過明確白名單、脫敏與 SHA-256 核對的封存建置，未將私鑰放入映像。測試容器、專用資料庫、volume、隧道及短期私鑰已清理，原報告與驗收映像保留。

## 目前限制

預設展示服務是合成商品查詢；可信交易入口需要部署者配置 JWS 身份、公鑰與 PostgreSQL。正式攻擊判定器與導流由外部系統負責。L3 真實資料銜接維持停用；不提供完整 Medusa API、真實付款／配送／退款、產品刪除生命週期、集中稽核平台或生產秘密輪替管理。

自有程式與文件採 Apache-2.0。採用套件、固定來源與模型權利見[授權表](licensing.md)；通過本版具名測試不代表任意部署通過 Protocol v1.1 符合性。
