# P2 原始判定／發送授權原生安全增量（Mirage_API）

> 狀態：元件驗證與隔離 PostgreSQL opt-in 通過，**production DECEIVE 尚未核准**。
> 本文件描述上游 Mirage Native Owner 的可審查增量；MSDSS 保留 Gateway 真實 Ed25519 發送端與網路部署驗收。

## 威脅邊界

1. 可信請求必須先完成 Ed25519 JWS、請求 fingerprint、scope、Replay 驗證，再從獨立 PostgreSQL ledger 以一次性原子 UPDATE 取得原始 AttackAssessment。
2. 原始判定由 Gateway 先完成持久化並取得確認 ACK 才能簽章；若 publish 返回未知 COMMIT 或丟失 ACK，必須 fail-closed，**不能簽署或重試**。資料庫 UNIQUE request ID 防止繞過。
3. Consumer 只可 EXECUTE 原判定的 take 函式，Publisher 只可 EXECUTE publish 函式；兩者不能直接 SELECT／UPDATE 原始表或重置 consumed_at。函式須由獨立 NOLOGIN owner 持有，使用 SECURITY DEFINER 與固定 search_path。原判定資料庫不可對外開放。
4. Mirage HTTP 的最後發送授權須使用 require_session_binding=True，同一 PostgreSQL 交易依序 Session Head FOR SHARE → Admission FOR UPDATE → Generation FOR UPDATE → Profile；epoch rollover 的 Session Head FOR UPDATE 使兩者互斥。
5. Generation 或 Profile Emergency Revocation 只在 SEND_AUTHORIZED 前阻擋。先前成功 COMMIT 的 SEND_AUTHORIZED 不能追溯取消；SEND_STARTED 仍檢查 owner、單次起送、transmission_deadline，且不能追回已交給 ASGI 的 bytes。

## 原生部署配置

TrustedDeploymentSettings.require_original_assessment 預設 False，尚未取得正式批准時不得切換。
啟用 strict 時必須另外提供 MIRAGE_ORIGINAL_ASSESSMENT_CONSUMER_DSN；
不可與 World/Postgres 的管理員 DSN 共用，也不能由客戶請求覆蓋。
缺少 Consumer DSN 或設定與模式不符即拒絕啟動。

檔案 migrations/original_assessment/017_original_assessment_ledger.sql **不在一般 World migration 掃描範圍**，不可讓 MIRAGE_AUTO_MIGRATE 隱式套用。
在 DBA 核對的專用原判定 DB 中，以外部單一 transaction（psql --single-transaction，或等價部署工具）建立 ledger 及 SECURITY DEFINER 函式，原子撤銷 PUBLIC EXECUTE 與 CREATE。
隨後使用 DBA-owned 額外交易設置 NOLOGIN Owner 及不同的 Writer/Reader LOGIN EXECUTE-only 權限。
正式環境仍須核對 TLS CA、角色 grant 鎖定、DSN 輪替、WAL／備份／長期 tombstone、復原與 rollback。

## 原生測試所有權

- Mirage 預設 native CI：test_original_assessment_binding、test_trusted_deployment、test_profile_revocation、test_world_runtime、test_control_processes、test_postgres_conformance 及其受影響 HTTP conformance。
- Mirage opt-in：tests/opt_in/accept_original_assessment_postgres.py、accept_original_assessment_role_acl.py、accept_original_assessment_unknown_commit.py，必須使用明確的 p2_acceptance_ 隔離資料庫與真正不同 SCRAM 角色。不得指向 staging。
- MSDSS 仍擁有 Gateway 交易未知 COMMIT 時真實 Ed25519 呼叫次數、signed JWS／Request Binding、跨服務一次性取用與 P2-7 網路拓樸驗收。**不得把整套 MSDSS Gateway 測試移入 Mirage native CI。**

2026-11-20 Oracle ARM64 隔離結果：Mirage 原生無 DB 指定回歸 126 passed／22 skipped；獨立 PostgreSQL 最小權限與原判定 46 passed，World／撤銷／epoch 77 passed；另外 HTTP／packaging 無 DB 9 passed／3 skipped。
Skipped 的 PG 需求須由獨立資料庫測試補足，不能冒充 PASS；上述不是 Mirage 正式 release build 或 production CA 驗收。

來源：MSDSS PR #12–#16 的原生增量，基於 Mirage_API upstream main 88dc2008fd35a2d3873949a769653dc9f18e8980，先前 Mirage upstream PR #4、#5 已合併；不得覆蓋已審核的商品、Trusted Receiver 實作。

## 尚未簽收

**以下任何一項未通過，都不得啟用 production DECEIVE：**

- Mirage 上游正式 Code Review、canonical CI、完整 opt-in，指定 SHA 與 image digest。
- 真實跨主機 TCP fault injection、資料庫 failover／未知 COMMIT 端到端簽章／Replay。
- 正式 CA／mTLS、Gateway egress／VCN 隔離、原始資料 retention 與備份還原、回滾演練。
- Sentinel v6 模型成效與 Medusa vendor Schema／商品 source approved 政策核准。
