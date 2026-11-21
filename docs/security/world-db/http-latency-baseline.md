# Mirage Trusted HTTP 延遲初步診斷（隔離環境）

> 狀態：**PRELIMINARY / END-TO-END NOT_RUN**；`MIR-SEC-WORLD-001` **OPEN**。
> 此文件只記錄效能證據與後續量測條件；**不**是安全驗收或正式發送核准。
> Production trusted send / DECEIVE：**OFF**；未修改現有 staging。

## 1. 問題與測量範圍

問題是「接到 HTTP 請求至完成回應的端到端耗時」，不等於僅量測候選內容生成。
目前正式 Trusted HTTP 入口仍有硬性 Release Fuse，故**沒有**可信的真實完整請求 P50／P95／P99、TTFB 或並行吞吐量數據。

本輪唯讀原始碼檢查及 PostgreSQL 隔離微基準可建立兩個候選熱點，但尚無法斷言何者主導真實延遲。

## 2. 已量測：資料庫重建連線的固定成本

環境：Oracle 隔離 Lab `mir-sec-world001-pg`，PostgreSQL **17.6**；單一 `mir_sec_verifier` 客戶端，容器內 Unix socket，SQL 僅 `SELECT 1`。
使用 `pgbench -n -c 1 -j 1 -T 3 -R 100 -f /dev/stdin`，另一組加 `-C`（每交易重新連線）。
測試不寫入 World／Replay／Admission，無正式發送。

| 情境 | 交易數 | 失敗 | 平均延遲 | 說明 |
| --- | ---: | ---: | ---: | --- |
| 重用連線 | 315 | 0 | **0.162 ms** | 初始連線另計 4.133 ms |
| 每筆重連（`-C`） | 285 | 0 | **4.787 ms** | 平均重新連線 3.186 ms |

此微基準的端點連線策略相差約 **29.5 倍**，但不可視為 HTTP 整體加速比例；測量不含 Python、ASGI、網路往返、鎖競爭、模型生成、實際輸出。
此結果來自 2026-11-22（台北時間）隔離實驗，僅適用該測試條件。

## 3. 原始碼所見的候選瓶頸

1. `src/deception/domains/ecommerce/trusted_http.py` 的 `async handle()` 會同步執行多項 World／Audit／Admission 操作。`PostgresWorldStore`、`PostgresCandidateStore`、`PostgresAdmissionControl`、`PostgresReplayStore` 等多處 `psycopg.connect()` 以每操作開連線為主；`AdmissionTransmission.prepare/start/finish` 又產生數次獨立 DB 操作。可能造成連線成本與 ASGI event-loop 停頓。
2. `src/deception/api/pipeline.py` 的 assessment provider 預設 timeout 為 15 秒；`src/deception/llm/models.py` 的生成預算預設為 120 秒，且 `domains/ecommerce/inputs/policies/generation.yaml` 範本也填入 120 秒、最多 8 次模型請求及 1 次修正。**範本 `enabled: false`，不能宣稱目前部署實際使用該政策或耗到 120 秒。**
3. `src/deception/core/renderer.py` 在 `prepare()`、`start()`、兩次 ASGI `send()` 及 `finish()` 之間處理安全狀態；目前的 Fence 實驗性封裝只涵蓋 `start_send()`，沒有覆蓋完整傳輸。**不能為了效能跳過這些控制，或將現有實驗封裝宣稱為正式安全閘門。**

## 4. 下一步：完整 HTTP 分段驗證

必須在隔離 Lab、固定 Source SHA 與 Schema／Migration 版本進行；每個 span 僅記錄代碼、毫秒及不可反查的 request ID digest，不記錄 JWS、body、session 明文或 DSN。

| 分段 | 主要問題 | 必須輸出的資料 |
| --- | --- | --- |
| HTTP ingress → trusted verification | JWS、Key Revocation、Replay 與受保護 Receipt | P50／P95／P99、錯誤率 |
| World resolve → read → audit | 多次同步連線／鎖等待 | Connection acquire、SQL、lock wait 分開計時 |
| Generator／Cache／Gate | 本機模型 cold/warm、cache hit/miss | 模型使用次數、tokens、cache hit、P95 |
| Candidate → Grant → Authorize | 各階段交易與候選固化 | 每交易與總耗時、衝突率 |
| Fence → StartSend → ASGI send → finish | Restore 並行保護及輸出 | TTFB、body completion、unknown/partial 分類 |

量測須包含 cold/warm、1/10/50 concurrent（視隔離資源安全容量調整）、正常／拒絕／未知 COMMIT，並分開回報 P50／P95／P99 與錯誤率；不能在共享 staging 壓測。

## 5. 安全限制與暫定優化順序

1. 先加入**不含敏感欄位**的階段計時，建立真實瓶頸；不要先削弱 Policy 或交易合約。
2. 依 DB Role／信任邊界採用各自獨立的 **bounded pool**（禁止 `SET ROLE` 共池），量測新連線數、排隊與尾延遲；不能將必須分開的安全交易任意合併。
3. 若模型實際占主導，量測 cold start、Token 使用及可信內容 Cache 命中率；不得跨 Scope 取用不同授權結果。
4. 保持 DB ACL、未知 COMMIT 對帳、Restore Quarantine、single-use、Snapshot Hash 與 Protocol Freeze v1，不以縮短等待為理由放寬。

驗證狀態：PostgreSQL 微基準 **MEASURED**；完整 HTTP 分段 **NOT_RUN**；安全控制驗收 **NOT_RUN**；Production trusted send **OFF**。
