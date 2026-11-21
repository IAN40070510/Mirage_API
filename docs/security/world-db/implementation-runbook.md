# MIR-SEC-WORLD-001 — 安全修補執行與驗收順序

**狀態：IMPLEMENTATION PLANNING／尚未實作安全修補／正式發送不得開啟**。此文件供獨立修補分支追蹤，不是 PostgreSQL ACL、原生符合性或正式部署的 PASS 證據。

## 固定起點及證據

- Mirage 原生基準：`88dc2008fd35a2d3873949a769653dc9f18e8980`；ADR 文件前置：`ff2afb6a2bde45e79093d54004f036a8df0ce3a6`。
- `trusted_http.create_app()` 對 Trusted Session Provider、Candidate、Admission、Registry、Audit／World 共用 `postgres_dsn`。
- `TrustedSessionVerifier.verify()` 在簽章驗證後透過 `PostgresTrustedKeyRevocations.guard()` 與 `PostgresReplayStore.consume()` 操作**兩條獨立交易連線**；現況不具備 Replay＋Receipt 同交易。
- `PostgresAdmissionControl.grant/claim/authorize_send/start_send/emergency_revoke` 直接對 `response_admissions`、`generation_controls` DML；`PostgresReplayStore.gc()` 直接 `DELETE replay_entries`。
- 現有 `start_send()` 經 `_lock_admission(..., for_send=True)` 再讀 Generation/Profile Emergency；與 MSDSS Freeze v1 目標行為存在已觀察差異；**Owner 採納未經確認前不修改該語意**。
- 本工作使用獨立分支，不得合併 `main` 或變更 staging／production；文件紀錄、程式修補和真實資料庫驗收必須各自標示。

## 實作順序（每一步前後保留負面與正常路徑證據）

| Gate | 實作目標 | 最低安全／功能驗收 | 狀態 |
| --- | --- | --- | --- |
| G0 | 固定受影響 SHA、非特權 Runtime 角色、隔離 PG 17 測試 DSN；重現三個已知直接 SQL 越權 | 原缺口重現歸類為預期風險，不能寫成修復 PASS；正常世界操作基準不退化 | NOT_RUN |
| G1 | Verifier／Authorizer 與 Runtime 分離 OS/容器身分、Secret、DB Role、DSN；明確關閉角色繼承及 `SET ROLE` 路徑 | 從 Runtime 的真實 SCRAM 連線無法讀／取得特權 DSN 或執行受保護函式 | NOT_RUN |
| G2 | 受保護 IngressTx：可信 Verifier 驗章、Key Revocation、Replay Tombstone、Ingress Receipt **同一 PostgreSQL DB／Connection／Tx** | 偽造來源／重放／Rollback／COMMIT ACK unknown；已消費 JTI 不得跨 Scope/Receipt 重綁 | NOT_RUN |
| G3 | 受保護 Candidate Promotion、Grant Binding、Admission／Generation／Session／Replay GC 轉移；撤銷 Runtime 直接受保護 DML | 原三個 SQL 越權被 DB 拒絕，正向 Grant／Claim／Authorize／Cutover／Revocation／Replay GC 保持正常；完整 Lock DAG | NOT_RUN |
| G4 | Snapshot 真實物件身分／immutable version、physical Pin／Key lifetime、兩種 Purge Fence、StartSend／Purge 競態 | 真實 bytes/Hash、Owner/Deadline/Single-use、異步 Object GC／Pin／Shared Blob 及未知 send 結果；不得偷偷二次授權 | NOT_RUN |
| G5 | Restore Quarantine、外部 Anchor 連續涵蓋、雙方向發布未知及 Operator Release Certificate | 舊備份及事件缺口無法復活 Tombstone／JTI／Snapshot；未知涵蓋不得解禁 | NOT_RUN |
| G6 | 混合版本／Rollback／CI／正式簽核 | 非特權 PG Integration、失敗注入、既有 Mirage 全套回歸、Owner／DBA／Security／Release Approver 簽核 | NOT_RUN |

## 不得由工程師自行猜測的決策

1. **Mirage Owner adoption／Protocol Freeze v1：PENDING。** MSDSS 已接受的目標協定，不代表 Mirage 已簽核；不能先移除原生 StartSend 的 Emergency 再查。
2. **受信任 Verifier／Authorizer 的獨立身分與 DSN：使用者已同意方向。** 具體程序連線、介面 ACL 與部署服務來源仍需真實驗收；不得把兩個 Python 物件當成兩個信任域。
3. **BD-05 Restore Anchor 發布協定／Retention／Quarantine release、BD-11 Deadline COMMIT 語意：OPEN。** 未核准前正式發送維持禁用。

## 驗收證據規則

- 只以隔離專用 PostgreSQL 測試 DB 執行會修改角色或資料表的整合測試，不能指向共享 staging 或 production。
- 結果變更須循 `NOT_RUN → RUNNING → PASS/FAIL/BLOCKED`，留下固定 Mirage SHA、Schema/Migration hash、PG 版本、實體 DB Login、資料集與 Fault Injection、UTC 時間及脫敏日誌。
- `python tools/check_documentation.py` 成功只代表文件品質，不代表 G0–G6 或 `WORLD-*` 安全驗收通過。
- 在所有 Gate 未通過且簽核未完成前：`Architecture=Proposed`、`MIR-SEC-WORLD-001=OPEN`、`MSDSS P2=NO-GO`、`production trusted-send=DISABLED`。
