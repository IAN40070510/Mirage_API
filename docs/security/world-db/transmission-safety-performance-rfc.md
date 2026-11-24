# Mirage_API — Trusted HTTP 安全與效能整合改造 RFC v1

**狀態：DESIGN / NOT IMPLEMENTED / NOT ACCEPTED。** 基準分支：`fix/mir-sec-world-001-restore-anchor-lab`；`MIR-SEC-WORLD-001 OPEN`、`外部端權限驗收 NO-GO`、Production Trusted Send **OFF**。本文不授權合併、變更 staging、解除 Release Fuse 或降低既有驗證。

## 1. 問題與可證明的承諾

目前 `FencedAdmissionControl.start_send()` 在獨立 Fence DB 持鎖、執行 World DB StartSend 後釋放鎖；`ValidatedHTTPResponse.__call__()` 隨後才 `await send(http.response.start/body)`。因此 Restore 可在釋鎖後、實際 ASGI 發送前進入 Quarantine。另有 `__getattr__` 轉送 Claim／Authorize／Finish，及直接呼叫 `PostgresAdmissionControl.start_send` 的繞過路徑。PENDING intent 缺獨立證據對帳。

**必須區分三種事件**：(A) 世界狀態已授權 StartSend；(B) 應用程式把 HTTP 訊息交給 ASGI Server；(C) 遠端 Client 實際收到 bytes。B 不證明 C；TLS／Kernel／Proxy 緩衝可使 C 晚於 Quarantine。不能宣稱一般 ASGI 應用可撤回已交給傳輸層的 bytes。安全承諾限定為「Quarantine 生效後，不再**開始**新的、未獲准的 ASGI send；既有 in-flight 傳輸須依 drain／terminate 協定完成」，若業務要求「Quarantine 生效後 Client 不得收到任何舊 bytes」，必須擴大信任邊界至可確認排空的 egress proxy／transport，並承認無法回收先前已送出資料。

## 2. P0：Fence 與傳輸生命週期

### 2.1 狀態與線性化

Fence 權威至少有 `ACTIVE(epoch)`、`QUIESCING(epoch)`、`QUARANTINED(epoch)`、`VERIFYING(epoch)`；只允許經驗證的前向轉移。每個發送操作綁定 `(namespace, epoch, admission_id, owner, operation_id, snapshot_digest)`，且 operation_id 由可信呼叫者一次建立並持久化，**重試不可換新 ID**。

1. **Admission**：Receipt／Replay／Claim／Authorize 必須透過不可繞過的受限 DB 身分與 Fence epoch 協定，保留 BD-11 的 PostgreSQL authoritative clock 與 COMMIT 線性化要求。不可在獨立 DB 之間假裝有原子交易。
2. **Intent**：在獨立 Fence DB 提交唯一 PENDING 操作；持久化證據鍵與預期 World transition。未知提交結果不可重新生成操作 ID。
3. **StartSend**：取得 Fence 許可後，在 World DB 執行單次 StartSend；World DB 持久化 operation_id、epoch、admission、commit evidence。若 World COMMIT 或回應未知，停止新的輸出並交由獨立 reconciler。
4. **Emit**：所有 ASGI `send()` 必須在 transport gate 保護下執行，不能只在 send 前檢查 lease。採 **Drain-first** 模型：Restore 先原子進入 QUIESCING，禁止新 admission/emit 取得資格；已取得的 emit permit 可完成當前受控邊界；待所有 permit 完成或已被可證明終止後才轉 QUARANTINED。若要求立即阻止已取得 permit，須使用可取消且有確認回執的 egress 層，不能靠 TTL。
5. **Finish**：完成、失敗、取消或 unknown 的證據獨立記錄；部分發送不可當作 rollback。ASGI send 回傳只記為 application-handoff，不記為 client-delivered。
6. **Restore**：QUIESCING → drain/terminate verified → QUARANTINED → restore → independent epoch/head/operation reconciliation → conditional release。未知或無法排空時持續封鎖，**不得以 lease 過期或管理員手動 override 解禁**。

### 2.2 同步與故障

Transport gate 應由獨立 Fence Authority 協調跨 worker／跨 host 的 permit；單機 `asyncio.Lock` 不具足夠權威。若以 PostgreSQL row/advisory lock 直接涵蓋 `await send`，須證明連線保持、取消 cleanup、statement/lock timeout、慢速 Client、DB failover、Worker crash 與 Restore liveness；**不能**在 event loop 上持有同步阻塞呼叫。建議先在隔離 Lab 實作「受控單訊息 emit permit + QUIESCING drain barrier」驗證原理，再決定是資料庫持鎖方案或獨立 egress actor。對於不可確認的 Worker crash／socket buffer，Quarantine 保持不可解除，直到有可信終止證據。

Fence DB 不可用、epoch 不符、權限錯配、reconciler 不可用時 Fail-Closed。Release 不可由單一布林值 `committed=True` 決定，須獨立查核 World operation ID、audit／commit evidence、Anchor head、timeline／epoch、不可逆 tombstones 與完整 coverage。

### 2.3 防繞過

移除受信任執行路徑對裸 `PostgresAdmissionControl` 的直接依賴；限制 DB Runtime Role 不得直接更新 Admission/Send 欄位，僅授權最小權限的受控函式。不得依賴 Python wrapper 或 `__getattr__` 當安全邊界。檢查所有 HTTP／CLI／background／legacy callers，加入 negative ACL tests。不可將 Verifier、Authorizer、World Runtime、Fence 的 DSN／角色混用；以 DB identity、cluster system identifier、network ACL 與 restore domain 證明獨立性。

## 3. P1：可觀測性（先量測後改寫）

每個請求使用 `time.perf_counter_ns()` 的 monotonic span：ingress、JWS／Replay／Receipt、World resolve、Candidate load、Generator、Gate、Grant、Claim、Authorize、Fence acquire/wait、StartSend、ASGI first-send、body-send、Finish。分別報告 TTFB(application)、ASGI handoff completion、總耗時與 P50/P95/P99，並標示 warm/cold、成功/拒絕/unknown、1/10/50 concurrency。不得將 ASGI handoff 當 Client ACK。

Telemetry 只允許固定 stage／outcome、時間、不可反查 request digest、model identity digest、cache hit/miss、pool wait；不輸出 JWS、Session ID、原始 body、DSN、prompt、密鑰或 admission token。觀測工具故障不得改變授權結果；安全 audit 失敗仍遵守原有 fail-closed。

## 4. P2：DB pool + async

採 `psycopg_pool` bounded pools，依 **DB identity × DB role × process** 隔離；Verifier／Authorizer／World Runtime／Fence 不共享連線。Pool 具 max_size、acquire timeout、idle/max lifetime、健康檢查、shutdown cleanup、排隊與耗盡指標。每個交易單位明確 commit/rollback；不可透過 `SET ROLE` 共池，未知 COMMIT 不自動重試。Pool 的 queueing 必須納入 HTTP deadline；禁止在持有 Fence permit 時等待無界 pool。

先以完整 transaction function 在 bounded worker 執行隔離同步 psycopg，避免 event-loop blocking；**不可**逐 SQL 拆 thread 造成同一 connection 跨 thread。再針對熱路徑逐步轉 `AsyncConnectionPool`，保持相同 lock ordering、transaction boundary 與 authoritative clock。先測量同等 load 下的 P95/P99，再評估 pool 大小，避免 DB max_connections 過載。

## 5. P3：AI 生成與快取

區分即時可信授權和可離線準備的合成候選。背景生成 → schema/安全/來源驗證 → 存候選與版本 digest；HTTP 路徑依 Scope、world generation、policy revision、source/projection contract、model digest、input digest 選取候選，再**重新**執行現時 Receipt／Replay／Grant／Authorize／Fence／StartSend。不得快取 JWS verification outcome、Replay JTI、Grant、Admission authorization、Snapshot execution eligibility。Session-specific candidate 不跨 session 共用；World mutation 或 policy/version drift 必須失效。快取失效／miss 不可自動放行未驗證資料。

對模型做 cold/warm profiling、預熱、限制 token、縮減固定 schema 上下文、有限 repair、bounded queue 與 deadline budget；120 秒是配置上限而非實測延遲，且 generation policy 範本 `enabled: false`，不可宣稱正在生效。若即時生成超出授權 deadline，拒絕／返回固定安全 fallback，不以逾期快照發送。

## 6. P4：驗收矩陣與合併 Gate

| 測試 | 必須觀察的結果 |
| --- | --- |
| StartSend COMMIT 後、首個 ASGI send 前 Restore | 新 emit 被拒絕，或 Restore 等待已核准 permit 完成；不得交錯違反線性化 |
| 兩個 ASGI send 之間 Restore | QUIESCING 阻擋新 permit；已送出 bytes 不被宣稱回滾 |
| 慢速 Client／cancel／Worker crash／Fence outage | 有界操作、UNKNOWN 保留、無法證明排空時不解除 Quarantine |
| 多 Worker／多主機／DB failover | 單機 lock 不足以繞過；epoch／permit／reconcile 一致 |
| Unknown World COMMIT／duplicate operation ID | 同一 operation_id 對帳，不建立第二次 send |
| Restore stale backup／Anchor rollback／Purge race | Fail-Closed；舊 JTI／snapshot／grant 不復活 |
| 舊版 binary、直連 SQL／Role escalation | DB ACL 拒絕繞過；Release Fuse 保持 OFF |
| Pool exhaustion／transaction exception／cancellation | 無權限混用、無交易洩漏、無 event-loop stall |
| Cache scope/version drift／tamper／miss | 不跨 Scope、不重用授權、不跳過 Gate |
| HTTP 1/10/50 並行與冷／熱模型 | 記錄 P50/P95/P99、錯誤率、吞吐、CPU/RAM；與相同 workload 基線比較 |

**Gate**：設計審查 → isolated tests → 真雙 DB + HTTP + fault injection → independent evidence verification → security signoff → deployment approval。任何單元測試、`pgbench SELECT 1` 或文件 PASS 都不能升格成 G5／正式發送 PASS。

## 7. 建議的分段交付與修改範圍

- **A（安全先行）**：`security/fenced_admission_control.py`、`protected_operation_runner.py`、`fence_operation_journal.py`、`world/postgres_admission.py`、`world/transmission.py`、`core/renderer.py`、Fence/World migrations、ACL 與 race/fault tests。先確定 QUIESCING/Drain 的語意與不可回滾的傳輸邊界。
- **B（效能量測）**：新增 `performance/` 的無敏感資料 span helper、ASGI/DB/LLM 指標與 benchmark scripts。
- **C（資料庫）**：角色隔離的 pool registry、sync transaction executor／async store adapters、pool exhaustion tests。
- **D（生成）**：pre-generation worker、versioned candidate cache、validation/invalidation tests。
- **E（驗收）**：獨立 World/Fence DB、真 HTTP、故障注入、回歸與效能報告；Owner/Security 核准前不合併 main、不啟用 production。

## 8. 已有證據與限制

隔離 PostgreSQL 17.6 的 `SELECT 1`：重用連線平均 **0.162 ms**；每交易重新連線平均 **4.787 ms**（約 29.5 倍的微基準差距），**不是 HTTP 加速倍數**。目前缺真實完整 HTTP TTFB/P95/P99 與 AI 模型耗時資料。前述全部改造仍屬設計提案，必須在隔離分支逐步實作與驗收。
