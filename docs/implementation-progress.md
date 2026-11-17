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
