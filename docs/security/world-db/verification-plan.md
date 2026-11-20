# MIR-SEC-WORLD-001 — 真實 PostgreSQL 驗收與安全負面測試計畫

**v0.1 — Test Plan Only；全部新案例狀態 `NOT_RUN`，不能因本文件被提交而改為 PASS。**

## 1. 測試環境、身份與證據

- 基準原始碼：Mirage `main` `88dc2008fd35a2d3873949a769653dc9f18e8980`；針對修復 PR 再記錄 branch SHA、Migration Hash、PostgreSQL 版本、Role ACL 與 feature flags。
- 使用**真實 PostgreSQL 17 系列隔離實例**與 SCRAM 身分。建立真正 `mirage_http_runtime`、`mirage_ingress_verifier`、`mirage_authorizer`、`mirage_replay_gc`、`mirage_control_admin`；Schema Owner NOLOGIN。不可用 postgres／owner 登入執行 Runtime 權限負面測試。
- 每個 fixture 建立**物理上的獨立連線與 DSN**，先查 `SELECT session_user, current_user;`；同時查 effective grants、Role inheritance、`rolbypassrls`／`rolsuper`／`rolcreaterole`、`has_table_privilege`、`has_function_privilege`、`pg_has_role`、`pg_hba.conf` 實際登入來源與 Pool role reuse。
- DML／函式越權應明確斷言 PostgreSQL `SQLSTATE 42501`（或在受限函式中的固定**業務拒絕**碼）；**兩者不可混用**。若操作本應因狀態機拒絕，不可要求必然是 42501。
- 驗證 `SECURITY DEFINER` 的 owner、`search_path`、PUBLIC EXECUTE、Schema CREATE、pg_temp shadowing、函式多載、Extension、Large Object、`SET ROLE`／Role membership、`COPY FROM PROGRAM` **實際權限**；不可僅查 role 名稱。
- Fault injection 要能控制 PostgreSQL Transaction 的「before commit」「after commit but before ACK」「read-only lookup fail」、Executor restart、Network timeout、clock skew、restore 及 concorrency/barrier。測試日誌必須脫敏，不外洩 DB Secret／JWS 私鑰。
- 每項結果保留 JUnit／命令／SQLSTATE／出錯注入點／原始碼 commit／DB migration／角色有效權限／實際輸出；未執行以 `NOT_RUN`，錯誤拒絕也不算正常 PASS。

## 2. ACL、Verifier 與 Evidence Binding

| ID | 測試情境 | 預期（新設計完成後） | 狀態 |
| --- | --- | --- | --- |
| `WORLD-ACL-01` | Runtime 直接將 Admission 改 SEND_AUTHORIZED | DML denied，SQLSTATE 42501；資料不變 | NOT_RUN |
| `WORLD-ACL-02` | Runtime 將 Session Head epoch 倒退或任意跳躍 | DML denied；受限切換只接受合法狀態 | NOT_RUN |
| `WORLD-ACL-03` | Runtime 提早 DELETE 未過期 Replay Tombstone | DML denied；受限 GC 不清理 | NOT_RUN |
| `WORLD-ACL-04` | Runtime 直接修改 Generation／Key Revocation／已核准 Candidate | DML denied；重要內容無變化 | NOT_RUN |
| `WORLD-ACL-05` | Runtime 經 Role 繼承、SET ROLE、Pool 重用、SECURITY DEFINER 假輸入取權 | 全部 denied；最小必要 EXECUTE 無任意提升 | NOT_RUN |
| `WORLD-ACL-06` | Runtime 真實 SCRAM 連線並掃 effective permissions | 符合審核角色矩陣，非 superuser／BYPASSRLS | NOT_RUN |
| `WORLD-VERIFIER-01` | Runtime 提交無效 JWS、錯 signature、錯 audience／scope | Verifier 不寫 Receipt／有效 Replay Binding | NOT_RUN |
| `WORLD-VERIFIER-02` | Runtime 覆寫 verified、issuer、kid、policy version、issued/expires | Verifier 不採信自填值；無有效 Receipt | NOT_RUN |
| `WORLD-VERIFIER-03` | Runtime 讀 Verifier Secret／連線 Verifier Role／取其 DB Role | Permission denied；無替代憑證或來源通道 | NOT_RUN |
| `WORLD-VERIFIER-04` | Runtime 通過合法 API 送已撤銷、錯 fingerprint、舊 epoch Token | Fail-Closed；不建立有效 Receipt | NOT_RUN |
| `WORLD-RECEIPT-01` | Replay Tombstone 存在但 Receipt 缺失 | Grant denied 並告警，不能補寫授權 | NOT_RUN |
| `WORLD-RECEIPT-02` | Receipt 存在但 Replay 墓碑不存在 | Grant denied 並告警；不接受孤兒 Receipt | NOT_RUN |
| `WORLD-RECEIPT-03` | Ingress 同交易 Receipt INSERT 故障／Rollback | Replay/Receipt 都不可見；未知 COMMIT 另行對帳 | NOT_RUN |
| `WORLD-BIND-01` | 同一 Receipt 並行綁兩個不同 Candidate | 最多一個合法 Binding／Admission 提交 | NOT_RUN |
| `WORLD-BIND-02` | 同一 Receipt 被重綁不同 Candidate／Generation | 永久 denied，未更改原 Binding | NOT_RUN |
| `WORLD-BIND-03` | Binding 成功而 Admission INSERT 故障 | 同交易整筆 rollback，無部分有效 Binding | NOT_RUN |
| `WORLD-BIND-04` | Receipt 已綁定**當前** Admission，Authorize／StartSend 重查 | 正常流程允許；不得把 used=true 誤判成重放 | NOT_RUN |
| `WORLD-PAYLOAD-01` | 受保護 Candidate Hash 通過後 Runtime 換 bytes／Middleware 修改 | 前送拒絕、原 hash 不修改、保護 audit | NOT_RUN |
| `WORLD-PAYLOAD-02` | Runtime 提交相同 body 不同 Scope/header/status/encoding | 不可跨 Candidate／Admission 挪用 | NOT_RUN |

## 3. Freshness、鎖、時間與輪替

| ID | 測試情境 | 預期 | 狀態 |
| --- | --- | --- | --- |
| `WORLD-EPOCH-01` | Grant 後 Session Head 提升 epoch，StartSend 尚未開始 | 舊 epoch 無法開始；不產生 send_started | NOT_RUN |
| `WORLD-EPOCH-02` | 同一 Session Head／Generation 的 Resolve 與 StartSend 並行 | 無鎖循環；結果符合提交順序與 Owner 政策 | NOT_RUN |
| `WORLD-LOCK-01` | Epoch Switch、Emergency Revoke、Grant、Authorize、StartSend 多線程 | 所有鎖順序符合 DAG；deadlock 可偵測且無越權 | NOT_RUN |
| `WORLD-FRESH-01` | Grant 後 Profile/Key Revocation 提交，StartSend 之前 | 拒絕新 SEND_STARTED；保留撤銷稽核 | NOT_RUN |
| `WORLD-FRESH-02` | 同時撤銷與 StartSend，固定 barrier 控制順序 | 明確提交前／後勝負；未確定時拒絕 | NOT_RUN |
| `WORLD-TIME-01` | Grant 前 JWS 到期 | 不可建立 Admission | NOT_RUN |
| `WORLD-TIME-02` | Grant 後 JWS 到期但 StartSend 未開始 | 依已核准 G/W Policy；預設 G=0 拒絕 | NOT_RUN |
| `WORLD-TIME-03` | StartSend Tx 開始時間合法、等待鎖跨過 deadline | 鎖後以 DB 實際時間拒絕，不用交易 now() 放行 | NOT_RUN |
| `WORLD-ROTATE-01` | 新增 K2、K1 仍可信且未撤銷 | 按明訂輪替政策，不由 Runtime 自選 key | NOT_RUN |
| `WORLD-ROTATE-02` | K1 被撤銷或相同 issuer/kid 被換不同 key material | 不得不經重新驗證繼續授權 | NOT_RUN |
| `WORLD-AUDIT-01` | SEND_AUTHORIZED 前送 Envelope mismatch | 原子 ABANDONED＋CONTENT_MISMATCH；無假的 send_started | NOT_RUN |

## 4. 部分完成、COMMIT、GC 與 Restore

| ID | 測試情境 | 預期 | 狀態 |
| --- | --- | --- | --- |
| `WORLD-FAIL-01` | Receipt 已建立／JTI 已消費，但 Grant 失敗 | 不得再次消費原 JTI；沒有有效 Admission | NOT_RUN |
| `WORLD-FAIL-02` | World Commit 成功、Admission 建立失敗 | 既有 World Operation Result 可查回；不重做 Mutation | NOT_RUN |
| `WORLD-FAIL-03` | Grant 成功、StartSend 因 Revocation 失敗 | Admission 不重新授權；明確拒絕 Audit | NOT_RUN |
| `WORLD-FAIL-04` | SEND_STARTED 之後 Runtime Crash／TCP 失聯 | 結果 UNKNOWN／UNRESOLVED；無自動重送 | NOT_RUN |
| `WORLD-RECOVERY-01` | 未知 COMMIT（before／after ACK loss） | 有相同 ID／digest 可信結果才唯讀查回；不能盲目重試 | NOT_RUN |
| `WORLD-RECOVERY-02` | Operation ID 相同但 input digest 改變／ID 碰撞 | 明確拒絕而不轉移別的 Operation 結果 | NOT_RUN |
| `WORLD-GC-01` | GC 對未過期 JTI／在途 Binding／UNRESOLVED 操作嘗試清理 | 全部保留；超過所有保留窗口才有權 GC | NOT_RUN |
| `WORLD-RESTORE-01` | World DB 還原到舊 Replay／Revocation／Epoch 快照 | 發送 Quarantine；舊 Receipt／Token 不重新有效 | NOT_RUN |
| `WORLD-RESTORE-02` | 還原後清理計算、Clock Skew、Key Rotation 不確定 | 不自動提前解除隔離；有可驗證的完整恢復證據 | NOT_RUN |
| `WORLD-MIGRATION-01` | Schema／ACL／函式版本不匹配 | Startup/Release Preflight Fail-Closed；正式發送不能開始 | NOT_RUN |
| `WORLD-MIGRATION-02` | 新舊版本混用不同 lock key 或 Rollback 權限較寬 | 阻止不安全混用；不能回復過寬 Runtime DML | NOT_RUN |
| `WORLD-AVAIL-01` | Runtime 佔滿自身連線、持鎖／慢交易 | Control／Revoke 仍可連線或明確停用服務；記錄延遲與不符項 | NOT_RUN |

## 5. 已有回歸與本輪證據不可混淆

| 類別 | 現有證據的正確說法 |
| --- | --- |
| MSDSS [Draft PR #23](https://github.com/IAN40070510/MSDSS/pull/23) | 先前報告的 13/13 PostgreSQL 與 3 種**成功重現權限缺口**；不是 ACL 修復 PASS |
| Mirage `main` 既有測試 | 可當作功能／契約 regression baseline；未曾以新角色證明本 ADR 的安全強制 |
| 此 ADR v0.1 的新 `WORLD-*` | **全部 NOT_RUN**；只有設計好的 scenario／expected result，無執行結果 |
| 未來 Draft PR 與 CI 綠燈 | 需分別保留 DB 角色測試、並行、Unknown Commit、Restore、Transport/ASGI snapshot、版本相容和 Owner Signoff |

## 6. 關閉與部署限制

測試報告、ACL Dump、容器秘密掛載、真實 Postgres 版本、Key Trust Registry、Restore 手冊與 Owner／DBA／Security／Release Approver 簽核缺一不可。未完成時：`MIR-SEC-WORLD-001: OPEN`、`MSDSS P2: NO-GO`、production `DECEIVE OFF`。沒有 HTTP 攻擊回報或 PR 合併不能取代證據。
