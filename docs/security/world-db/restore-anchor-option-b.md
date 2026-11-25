# Restore Anchor Option B — approved security contract (2026-11-21)

Status: **OWNER APPROVED / IMPLEMENTATION NOT COMPLETE / G5 NOT RUN**.

## Trust boundary

The Restore Anchor MUST be outside the World DB backup and restore domain. Its credentials, write authority, backup and retention policy MUST be independent from World DB Runtime, Verifier and Authorizer credentials. An isolated same-host laboratory store may validate the protocol but does not establish resistance to host-root compromise, host snapshot rollback, or a malicious Docker administrator.

## Required invariants

1. World DB rollback MUST NOT make a previously revoked key, consumed replay JTI, non-retryable operation or purged authorized Snapshot eligible again.
2. Anchor checkpoints MUST bind authority namespace, epoch, monotonically increasing sequence, previous checkpoint digest, World DB evidence digest, protocol version and publication identifier. Hashes alone do not establish freshness: the verifier MUST consult the independent authoritative latest checkpoint.
3. An anchor record MUST NOT be overwritten, deleted, or replaced by Runtime credentials. Only a dedicated checkpoint publisher may append; quarantine release requires a separately authorized operator certificate.
4. Checkpoint publication and World DB COMMIT are not one atomic transaction. Both crash windows MUST have explicit durable intent, reconciliation and fail-closed behavior; an ACK loss MUST NOT be treated as rollback.
5. Restore starts in quarantine. It remains quarantined on missing, stale, conflicting, unavailable or unverifiable anchor evidence, and on unknown commit/publication outcomes. Reconciliation alone MUST NOT authorize a new HTTP transport attempt.
6. Snapshot purge MUST persist the non-retryable fence before deleting bytes and must not race with an active sender without a retention or controlled-abort protocol.
7. Release requires proof of contiguous coverage from the restored checkpoint to the independent latest checkpoint, including revocations, replay tombstones, bindings, send attempts and purge fences. Missing evidence means NO-GO.
8. The Release Fuse and production trusted send remain OFF throughout this work.

## Mandatory acceptance cases (not yet passed)

- RESTORE-ANCHOR-01: rollback World DB while Anchor retains later revocation/JTI/purge checkpoint => quarantine.
- RESTORE-ANCHOR-02: missing, stale, tampered, overwritten or inaccessible Anchor => fail closed.
- RESTORE-ANCHOR-03: crash before/after World DB COMMIT and before/after Anchor publication, including lost ACK => deterministic reconciliation without duplicate authorization.
- RESTORE-ANCHOR-04: Runtime SCRAM identity cannot append, update, delete, truncate, switch role or read publisher secrets.
- RESTORE-ANCHOR-05: verified contiguous coverage and operator release certificate required to exit quarantine.
- RESTORE-ANCHOR-06: restore during concurrent StartSend, active sender and Snapshot purge => no second transport or resurrection.

## 2026-11-24 one-time Oracle Arm64 lab preflight — bounded PASS, G5 OPEN

On `isolated-arm64-lab`, authenticated Gateway sudo access inspected two **already
existing** `postgres:17.6-alpine` containers:
`mir-sec-world001-pg` (World Lab, separate `mir-sec-world001-pgdata` volume,
`mir_sec_owner` login) and `mir-sec-world001-fence-pg` (Fence Lab, separate
`mir-sec-world001-fence-data` volume, `fence_admin` login). Both use the dedicated
Lab Docker network, not a staging network. This proves distinct PostgreSQL
instances, physical data volumes and admin logins, **not** credential invisibility
to a malicious host root or a deployed independent checkpoint authority.

A temporary `mir_g5_oneoff_20261124` schema was created in each **Lab database
only**. Test records advanced World and independent Fence to sequence 2, with
SHA-256 digests and a previous-record hash. The test then removed sequence 2
**only from the temporary World probe table**, simulating a rollback to sequence 1.
Fence still reported sequence 2, its one-step hash chain verified, and an external
comparison failed closed:

```text
G5_ONEOFF WORLD_HEAD=1 FENCE_HEAD=2 QUARANTINE_REQUIRED=YES
```

Gateway evidence: cross-DB comparison job `job_01M85VFNS30025JTG3PT9CA5RQ`
(exit 0).
One-time schemas were then deleted from both Lab databases and verified absent:
Fence cleanup job `job_01M85VGH3S001KMJ813MW7NCYQ`, World cleanup job
`job_01M85VG8CP00DHMPWRFWD81SN9`. No existing app tables, containers,
Docker volumes or staging/production resources were modified or removed.

**Acceptance boundary:** this is a physical-isolation and rollback-*simulation*
preflight only, not `RESTORE-ANCHOR-01` through `06` acceptance. No actual World
DB backup/restore, durable publication protocol with external highest-head
anti-replay trust, independent publisher ACL, checkpoint coverage proof,
crash-window reconciliation, release certificate, active Sender or Purge race
was exercised. The lab comparison must not be treated as an implemented runtime
quarantine guard, a production Anchor, or authorization to lift the Release Fuse.

## 2026-11-24 cryptographic anchor verifier increment — local unit PASS, G5 OPEN

`src/deception/world/restore_anchor.py` adds a fail-closed, **verification-only**
Ed25519 contract with separate pinned Publisher and Head Authority public keys.
The Head Authority must sign fresh 32-byte challenges together with the
independent **latest** namespace/epoch/sequence/digest **before and after** chain
verification; an advancing Head invalidates the comparison. The verifier checks every
checkpoint signature, previous-checkpoint hash, exact event sequence coverage,
unique publication identity, COMMITTED-only state, and the restored World's
digest against its historical checkpoint. An older restored DB receives
`RESTORE_BEHIND`; matching the latest Head receives `HEAD_MATCHED`, but
**neither result permits release** (`release_authorized=False`). Read failure,
missing link, stale/tampered signature, nonce mismatch, PREPARED publication,
or untrusted Head fails closed.

`tests/test_restore_anchor.py` provides nine isolated cryptographic contract
tests (including mismatch, rollback, outage, tampering, replay and coverage
gaps). Local command `PYTHONPATH=src python -m unittest discover -s tests -p
test_restore_anchor.py -v`: **9 passed**, no physical DB/restore/container
involved; GitHub isolated contract CI is configured to retain JUnit separately.
This is **only a code-level subcomponent** and must not be counted as
`RESTORE-ANCHOR-01` through `06` or `RESTORE-RELEASE-01` through `07`.

At fixed code SHA `4be39923bbffb76ded388035cd250517ff732e57`,
[PostgreSQL contract CI 45325688577](https://github.com/IAN40070510/Mirage_API/actions/runs/45325688577)
reported 154 protected PG passes, 5 mTLS passes and **9 separate anchor
cryptography passes**. [Python CI 45325688529](https://github.com/IAN40070510/Mirage_API/actions/runs/45325688529)
reported `1436 passed / 21 skipped / 2 warnings`;
[container CI 45325688534](https://github.com/IAN40070510/Mirage_API/actions/runs/45325688534)
was successful. The skipped cases remain skipped.

To make this enforceable, a subsequent isolated implementation must supply
an independently credentialed durable Publisher and fresh monotonic Head Reader,
with an auditable append-only event ledger that proves completeness (not just
contiguous declared event numbers). It must bind exact restore-epoch/World DB
state, perform two-domain COMMIT/ACK reconciliation and atomic BD-05 quarantine
transitions, and serialize Sender/Purge. The Reader/Head expected epoch and
public keys cannot be supplied by the restored World DB or untrusted Runtime.
No production or staging service is connected to this helper.

## 2026-11-24 actual pg_dump/pg_restore against separate lab Fence — bounded PASS

An additional **host-only disposable test** on `isolated-arm64-lab`
used the existing `mir-sec-world001-pg` World Lab and the separate
`mir-sec-world001-fence-pg` PostgreSQL 17.6 Fence Lab (distinct containers,
data volumes, and administrator logins). It never touched a staging or
production database. Two uniquely named empty World test databases and a
single dedicated Fence schema were created after verifying none existed.

1. In World source test DB, commit event 1 (`REPLAY_CONSUMED`); persist an
   independently calculated SHA-256 state digest in Fence checkpoint 1.
   Jobs `job_01M85WR4RC0020QMDBAJ4GXN43` and
   `job_01M85WRHM700JQ4B44CEX43VW7`.
2. Take a **real PostgreSQL custom-format `pg_dump`** before event 2:
   `job_01M85WSAXP00YZAAVFZDWKA7QB` exited 0; archive SHA-256
   `979bada0cd18b7ec89d9c475c3c3bc9c1ab33f055b330257632812d5a77a68bb`
   from `job_01M85WSNVD00HDBF6WVA7RG75T`.
3. Commit event 2 (`SNAPSHOT_PURGE_FENCE`) **after backup** and append
   Fence checkpoint 2 linked to checkpoint 1. Jobs
   `job_01M85WT4NR00Q59E1H5JRAVVFW` and
   `job_01M85WTH6B009H9MN3PEDXSZ5V`.
4. Run actual `pg_restore --exit-on-error` into a **different empty World
   test database**, job `job_01M85WTW0D00D7K8B84YECRGP3` exit 0.
   Source was sequence 2 / digest `35002ada60aa676b...`, restored was
   sequence 1 / digest `451f92386c058839...`, independently stored
   Fence Head was sequence 2. Fence checkpoint count and SHA-256 previous
   links verified `2|2|t|t`: source/restore/Fence query jobs
   `job_01M85WWE3S00ECZGFH34KH702A`,
   `job_01M85WW3S300FG1FXBH5E1DRGT`,
   `job_01M85WVSDJ006Z2C75SW3G05WS`,
   `job_01M85WVF2Y00RM0V91H3YKV5QC`.
   Comparison result: **`G5_LAB_PGDUMP_RESTORE QUARANTINE_REQUIRED=YES`**.
5. Drop **only** the two one-off databases, one Fence schema, and its archive;
   jobs `job_01M85WX3HX00F3TH0N27RKWYM4`,
   `job_01M85WY0XX00664D6JR1SCBS72`,
   `job_01M85WXPW200G8AP6VMEAJE93W`,
   `job_01M85WXC9E00NPRH55G31WSH8A` all succeeded.
   Independent post-cleanup checks found `0` matching databases,
   `0` matching Fence schemas and no archive: jobs
   `job_01M85WYCYE00DG0P41GKCE1RWX`,
   `job_01M85WYXGG002MRYVMCS3FPRBV`,
   `job_01M85WYN6C00ZTFSE8D0DZFGBP`.

This is stronger than deleting a probe table to simulate rollback: the
restored World contents were actually produced by PostgreSQL backup/restore.
**It is nevertheless a disposable ledger probe**, not a full application
World DB restore or production Anchor. The host SQL probe uses hash chaining,
not the new signed-checkpoint Reader; it has no complete Publisher/Head
credential isolation proof, no signed monotonic freshness protocol, no
real business effects, no crash-window/unknown-ACK reconciliation, and no
BD-05 automated Quarantine transition or Sender/Purge concurrency test.
`RESTORE-ANCHOR-01` through `06` and G5 overall remain **OPEN/NOT_RUN**.

## Deployment guardrails

### 2026-11-24 第二 PostgreSQL Fence Ledger 隔離增量（固定 SHA 隔離 PASS）

`deploy/security-lab/g5-fence-schema.sql` 專供**不同於 World DB 的隔離 Fence
資料庫**，不納入 World DB 的 `migrations/`。Schema 有不可改寫 Checkpoint、
單調 Head、Namespace／Epoch／Sequence 與 Publication 唯一約束，禁止 SQL
直接 UPDATE／DELETE／TRUNCATE Checkpoint，拒絕 Head 倒退。
`src/deception/world/postgres_restore_anchor.py` 新增兩個獨立 DB 登入界面：

- `PostgresAnchorPublisher`：在 DB 交易內驗證 Publisher Ed25519 簽章、
  序號、前節 Hash、事件號連續，原子追加 COMMITTED Checkpoint 並前進 Head；
  拒絕同 Publication 重送與順序不明結果。跨 World DB 的 COMMIT/ACK
  對帳**尚未提供**，不可將此 append 視為已對帳完成。
- `PostgresAnchorHeadReader`：唯讀登入取得外部 Head，對 Verifier 當次
  隨機 nonce 簽署；另一個唯讀查詢返回完整原始 Checkpoint，交由既有
  `verify_restore_anchor` 驗證。Head 私鑰須由獨立 Head 服務的秘密通道提供，
  不能從 World DB、Runtime 或請求參數取用。

`tests/test_postgres_restore_anchor.py` 與
`.github/workflows/world-security-contract.yml` 新增**第二個全新 PostgreSQL
17.6 CI service**（獨立於 World PG），以三個隨機臨時 SCRAM Login 測試
Publisher／Reader／Runtime 的資料表 ACL、真正持久化 Head、舊世界回退、
重送／缺口／錯簽章、直接 DML 防護，另以兩條獨立連線競爭相同下一個
Checkpoint，核對唯一成功與 Ledger 不重複。只允許專用 CI／Lab 啟用
`MIRAGE_G5_FENCE_TEST_DSN`；沒有變數必須 SKIP，不可算 PASS。

**固定來源／CI 證據**：程式 SHA
[`e36d4bb7c498cd591d0ab7546a1e0f831f68209a`](https://github.com/IAN40070510/Mirage_API/commit/e36d4bb7c498cd591d0ab7546a1e0f831f68209a)。
[隔離 PostgreSQL 17.6 #45408339195](https://github.com/IAN40070510/Mirage_API/actions/runs/45408339195)
`success`：既有受保護合約 `166 passed`、真 mTLS `5 passed`、
G5 密碼學模擬 `9 passed`、**第二個 PostgreSQL 服務／真實三角色
SCRAM 與兩連線並行 Fence Ledger `4 passed`**。
[Python #45408339208](https://github.com/IAN40070510/Mirage_API/actions/runs/45408339208)
`success`：`1449 passed / 25 skipped / 2 warnings`；新增的四個
G5 實體 DB 案例在此流程因未設第二 DSN 而明確 SKIP，不能重複算為 PASS。
[Container #45408339359](https://github.com/IAN40070510/Mirage_API/actions/runs/45408339359)
`success`。本地曾執行同版聚焦 `9 passed / 4 skipped`、
`tools/check_documentation.py` PASS、`git diff --check` PASS。

這是**獨立測試資料庫的真實持久化表（測後清除）／角色／並行交易子項**，不是
實際生產環境、實際 World DB `pg_restore` 後的原子 Quarantine
或 `RESTORE-ANCHOR-01`～`06` 完整簽核；不得因子項成功解除 Sender。

### 2026-11-24 Fence COMMIT ACK 遺失增量（隔離紅綠驗證）

在最新獨立 Mirage 主線（已移除 consumer-owned 外部判定服務 integration）新增
`test_fence_lab_lost_commit_ack_fails_closed_and_does_not_republish`：
對全新、內部網路、SCRAM PostgreSQL 17.6 的 Publisher 真正完成第一筆
Checkpoint 與 Head 更新，卻在交易 context 返回前注入 `OSError` 模擬
COMMIT ACK 遺失。修補前 `job_01M872NHKW007H9CZSQW7Z1WFK` **1 failed**，
確認原始系統層例外直接逸出；修補後 `PostgresAnchorPublisher.append()`
與 `PostgresAnchorHeadReader._query()` 將 `OSError` 和 `psycopg.Error`
統一為固定的 `RestoreAnchorError`。`job_01M872QV9H00ERXYFVVFV1DKZ3`
真 PostgreSQL **6 passed**：Ledger/Head 僅有第一節、同一鏈節重送遭拒、
第二節正確前進，Head Reader Transport 錯誤亦固定 fail-closed。
`job_01M872S382003FFHANZ58PDX80` 另有密碼學與 standalone runtime
**12 passed**；第一次 `-I` 執行因臨時 Runner 未安裝原生 Python Package
而報錯，補齊一次性隔離 venv 中的本地封包連結後全過，未更動產品入口。

此增量只處理**單一 Fence DB 交易結果的不可驗證錯誤類型**與防盲重送；
World DB ↔ Fence DB 的跨庫 Commit Intent／ACK 對帳、完整事件語意、
BD-05 Quarantine 原子解禁及 Sender／Purge 競態仍未實作，G5 不得簽成 PASS。
本輪資料庫和網路均為拋棄式合成實驗，未觸及 staging/production。

### 2026-11-25 Fence authority namespace／epoch 強制釘選（局部修補）

在獨立 `PostgresAnchorPublisher` 與 `PostgresAnchorHeadReader` 的建構介面加入
必填 `trusted_namespace`、`trusted_epoch`。這些值必須來自**獨立 Fence
服務的部署設定**，不得從恢復後的 World DB、受信任 HTTP 請求或 Runtime
參數取得。Publisher 在驗章／DB 寫入前拒絕不同範圍的 Checkpoint；Head
Reader 在 DB 查詢／簽署 nonce 前拒絕不同 namespace 或 epoch，讀取原始鏈節
也使用相同限制。這防止部署已釘選新世代時，舊世界資料誘使同一獨立服務
替歷史世代簽署有效但過期的最新 Head。

新增不需要資料庫的負面測試，驗證跨 namespace／舊 epoch 的 Publisher／
Reader 請求在任何查詢前拒絕、未設定合法範圍不能啟動，並保留合法範圍的
Head nonce 驗章。現有實體 PostgreSQL 測試仍負責證明合法發布與歷史鏈節
讀取；未提供第二個專用 Fence DSN 的環境必須保留 SKIP，不可算成實體 PASS。

**此子項仍未解決**：單一 namespace 下最高 active epoch 登錄（後續增量見下）、完整事件
涵蓋、跨 World/Fence DB 未知 COMMIT／ACK 對帳、BD-05 原子自動解禁，以及
Restore↔Sender↔Purge 競態。此切面不提供釋放 Quarantine 的 API，
不修改正式發送封鎖，G5 仍 **OPEN／NO-GO**。

### 2026-11-25 獨立 Fence DB 最高 active epoch 登錄（待實體 CI 簽收）

第二個 Fence DB 隔離 schema 新增 `authority_epochs(namespace, generation, epoch)`
不可變追加表，權威世代必須從 1 開始連續遞增、同一 namespace 不得重用 epoch。
只有獨立 DBA 能追加；Publisher／Head Reader 只獲 `SELECT`，Runtime 無權讀寫。
Publisher 在發佈之前使用與 DBA 世代追加同一把 namespace advisory transaction
lock，再讀最高 generation 的 epoch；舊簽章與舊實體 DB login 不能在換代後
接續更新 Head。Reader 在每次 Head 觀測與鏈節讀取時，都在獨立 DB 查當前
最高 generation；舊 epoch 就算保有簽章有效的歷史 Head 也不可再次簽發。

新增真第二 PostgreSQL 測試：管理者建立初始權威、Publisher／Reader 正常使用、
DBA 追加第二世代、舊 Reader／Publisher 拒絕、新世代可進行獨立簽章鏈、
Publisher 不得自行追加權威世代、管理者不能修改歷史或跳號。隔離 CI 會驗證
這個新子項；在完成前不得把它登記為 PASS。

**嚴格限制**：這只建立單一獨立 Fence DB 的世代上限與不可回退稽核資料。
它不保證對抗該 Fence DB 管理者或儲存備份域自身的回退，也不驗證跨 epoch
的全部業務事件涵蓋或跨兩庫原子性。BD-05 機器解禁、同時 Send/Purge、
正式憑證與 Release Gate 仍未接線；正式 Trusted Send 保持 OFF。

**隔離主線 CI 補證**：固定提交
[`d35af3f`](https://github.com/IAN40070510/Mirage_API/commit/d35af3f62c9ab7bf667bfcae903540a3ec333f7d)
的 [World PG17.6 #45426410173](https://github.com/IAN40070510/Mirage_API/actions/runs/45426410173)
`166 passed`、真 mTLS `5 passed`、密碼學 `9 passed`、獨立 Fence PG `6 passed`；
[Python #45426410183](https://github.com/IAN40070510/Mirage_API/actions/runs/45426410183)
`1453 passed / 11 skipped / 2 warnings`，
[容器 #45426410092](https://github.com/IAN40070510/Mirage_API/actions/runs/45426410092)
成功。

**Fence Head 資料庫級前節綁定**：固定提交
[`e15c7f5`](https://github.com/IAN40070510/Mirage_API/commit/e15c7f5793de56e0238c3fc4f769d73cc901e7e2)
在第二個實體 PG 加上 Head INSERT／UPDATE Trigger：首次 Head 必須對應
已持久化序號 1／全零前節／事件 1 起點；後續 Head 必須參照同
Namespace／Epoch、序號恰好 +1、雜湊承接前一 Head、事件連續且已寫入的
Checkpoint。即使 Publisher Login 已有 Head 表的 UPDATE 權限，也不能
直接 SQL 推進至不存在或斷鏈節點。
[World PG17.6 #45427919546](https://github.com/IAN40070510/Mirage_API/actions/runs/45427919546)
`166 passed`、真 mTLS `5 passed`、密碼學 `9 passed`、**獨立 Fence 真 PG `7 passed`**；
[Python #45427919653](https://github.com/IAN40070510/Mirage_API/actions/runs/45427919653)
`1453 passed / 12 skipped / 2 warnings`；
[容器 #45427919657](https://github.com/IAN40070510/Mirage_API/actions/runs/45427919657)
與[四服務 #45427905221](https://github.com/IAN40070510/Mirage_API/actions/runs/45427905221)
均成功。新測試只在可拋棄 Schema 建立不存在 Head 與合法簽名但錯前節的
Checkpoint，再證明 SQL Head 推進遭拒；不宣稱這可阻止已取得合法 Publisher
簽章私鑰的人發布其他有效事件，也不能代替兩庫最高 Head 的持久化部署。

### 2026-11-25 Oracle 一次性完全隔離 PostgreSQL Lab — SQL／Restore PASS，已清理

使用者另行授權在既有 SSH 主機 `138.2.107.99` 執行**測完立即清理**的
Mirage 專用 Lab；不得借用或修改 MSDSS／正式 Mirage 容器、網路、資料卷與
Secret。部署前盤點為 41 個既有容器、30 個網路、30 個資料卷；另以
`mirage-g5-isotest-20261125-a71f` 全新命名空間建立兩個
`postgres:17.6-alpine`（World／Fence）、兩個各自 `internal: true` 的
Docker bridge、兩個獨立具名資料卷及一個同時接入兩個 Lab 網路的專用
PostgreSQL Probe。沒有公布主機 TCP 埠，憑證在新建 0700 目錄產生、
僅透過 Docker Secret 掛載，沒有讀取或複用 MSDSS Secret。

以目前 `deploy/security-lab/g5-fence-schema.sql` 在 Fence DB 建立真實
Trigger／表及最小權限角色；SQL 接受測試 **PASS**：拒絕 Authority 世代
跳號與更新、拒絕 Checkpoint 改寫、拒絕不存在鏈節的 Head 推進，並允許
連續有效鏈節前進至 Head 2、Authority Generation 2。World 在序號 1
做 PostgreSQL `pg_dump -Fc`，推進至 2，再用 `pg_restore --clean`
還原至 1；Probe 從專用雙網路以真實 SCRAM 登入讀得：

```text
PASS_FENCE_DDL_ACL_MONOTONIC_EPOCH_AND_HEAD | Head=2 | epoch-a
PASS_RESTORED_WORLD_SEQ=1
PASS_LIVE_SCRAM_ROLLBACK_QUARANTINE world=1 fence=2 auth_generation=2
PASS_DB_NETWORK_SEPARATE_world_cannot_resolve_fence
PASS_DB_NETWORK_SEPARATE_fence_cannot_resolve_world
```

這個 Quarantine 結論是隔離 Probe 比較兩庫序號所得的**驗收斷言**；不是
正式 Restore 控制器、G4 Sender 或 BD-05 解禁路徑的端到端運轉證據。
SQL Checkpoint 內容使用合成摘要與簽章占位資料，**不能**冒充 Publisher
Ed25519 驗章測試；真實 Python／SCRAM／簽章鏈驗證另外由固定提交
[`50b47a6`](https://github.com/IAN40070510/Mirage_API/commit/50b47a6696424e93692d31e06bb36cf23827c347)
的 [World PG CI #45498525815](https://github.com/IAN40070510/Mirage_API/actions/runs/45498525815)
（獨立 Fence PG `10 passed`）支援。

Gateway 稽核工作：Fence DDL `job_01M87YDWBX008XNDD5HRYE07RH`；
Fence SQL／ACL `job_01M87YG7MY00C46GC3BWX60W8M`；World
`pg_dump` `job_01M87YH0P1001WWGQRVPJF66R7`、前進
`job_01M87YH9AJ00EHA3W59DQPXQ8M`、`pg_restore`
`job_01M87YHHDZ00P5G7D2PW606MSE`、還原確認
`job_01M87YHVHT00XVTS3CXSBMAAAV`；跨網 SCRAM／Quarantine
`job_01M87YJCXV00VV1FJQFM25PBSP`；反向網路隔離
`job_01M87YKC8600SXBWY3XZ8B1RFW` 與
`job_01M87YJQTG00PXG3RNERDH45A4`。

清理 `compose.down` `job_01M87YNMDR00XKF9FNPYVT4WHC` 後，只針對
本次新建的兩個具名資料卷及 Probe 自動產生的一個匿名資料卷執行已預覽的
移除，並刪除新專案目錄及兩把一次性密鑰：
`job_01M87YRTQQ00AYF6JHWB92462M`、
`job_01M87YSHF2002CMM20ZVRYCZT6`、
`job_01M87YS5CY0052CHY5N9K3XJ3S`、
`job_01M87YTA7T00V9FFJJG8H5FMAF`。最後重新列舉為
**41／30／30**，三份資源名稱集合與測試前完全相同，原有容器的執行
狀態沒有變化，一次性工作目錄不存在。此測試對 MSDSS **零變更**。

**判定：同主機的獨立 PostgreSQL Lab PASS／CLEAN；跨主機、不同回復域的
正式 Restore Fence 未獲證明，G5 仍 OPEN／NO-GO，Trusted Send OFF。**

### 2026-11-25 第二台 Oracle 主機一次性真簽章 Restore Lab — PASS／已銷毀

使用者指定**不同於既有 `138.2.107.99` 共享主機**的獨立 SSH 主機
`161.33.154.211`（Ubuntu 24.04 ARM64），要求完成驗證後刪除測試檔。
先由使用者透過 PuTTY 在該主機核對 ED25519 SSH Host Key
`SHA256:ISzzPU/8h6Js7i4diXg/FIqp0ir59rI7wqeMKo6C3a8`；Gateway 固定指紋
並以專用臨時公鑰驗證登入成功。測試前盤點為 **0 容器／3 內建網路／0
資料卷／0 映像**，全新專案路徑不存在。不修改 MSDSS 主機、正式環境、
套件、系統核心、SSH 主機金鑰或防火牆。

以一次性 `mirage-g5-external-oneoff-20261125-b43e` 專案部署 World／Fence
兩個 `postgres:17.6-alpine`，各有獨立 `internal: true` Docker 網路、具名
資料卷、SCRAM 認證與不對外發布的 5432 埠；無權限的測試端只加入這兩個
Lab 網路。所有隨機資料庫密碼在主機新建 0700 目錄產生，以 Docker Secret
掛載，不採用 Windows `.ppk` 或 MSDSS Secret。部署源碼精確鎖定
[`5286138`](https://github.com/IAN40070510/Mirage_API/commit/528613877323fab158417cda065946f50098268f)。
該主機沒有 Docker Buildx 和 `docker compose` 外掛，因此在不安裝任何
主機套件的前提下，以既有 legacy Docker builder 和獨立
`docker-compose` v2.24.0 建置與管理；建置上下文只含四個必要原始檔、
空白 package init 和 Dockerfile，未包含密鑰。

- **原始 G5 Python + 獨立實體 PostgreSQL**：真 Publisher／Reader／Runtime
  SCRAM、Ed25519 簽章、世代切換、連續事件、SQL Trigger 與 ACL，共
  `10 passed in 0.99s`（`job_01M883HJP400X4AGC8Q4G6K64A`）。
- **額外端到端 signed restore Probe**：使用真正 `SignedAnchorCheckpoint`
  與 `PostgresAnchorPublisher` 發布序號 1，再 `pg_dump -Fc` World；World
  前進至 2 且已簽署 Fence Head 也到 2 後，實際執行 `pg_restore --clean`
  將 World 回退至 1。獨立 `verify_restore_anchor` 回傳
  `RESTORE_BEHIND` 且 `release_authorized=False`；Fence Head 保留 2。
  DBA 再追加權威世代 2，舊 Publisher 與 Reader 均拒絕。
  初始簽章 `job_01M883P4HG00005C12VNHRJ1F7`、
  `pg_dump` `job_01M883PGJP00NCE6QN57GZ8R8S`、
  發布第二鏈節 `job_01M883PZJF00WEJ6VSGPMZNH2Y`、
  `pg_restore` `job_01M883QCP100SKJXJSGJJGVQDR`、
  還原／世代拒絕驗證 `job_01M883QP9600DJCXQ8DFRMP8ZJ`。
- **網路及密碼負向測試**：World/Fence 容器互相無 DNS 解析，Host
  PostgreSQL 連線全面使用 SCRAM，錯誤密碼遭拒（
  `job_01M883R87100Z2JB5BCT4KPJJR`、
  `job_01M883S15V00TZE7RVYKCW6AMH`、
  `job_01M883RT7300DK2R7PC277XY4B`）。

```text
10 passed in 0.99s
PASS_SIGNED_HEAD_SEQ1_RELEASE_DENIED
PASS_SIGNED_HEAD_SEQ2_WORLD_SEQ2_RELEASE_DENIED
PASS_REAL_SIGNED_RESTORE_BEHIND_QUARANTINE world=1 fence=2 gen=2
PASS_RETIRED_EPOCH_PUBLISHER_READER_DENIED
PASS_WORLD_CANNOT_RESOLVE_FENCE
PASS_FENCE_CANNOT_RESOLVE_WORLD
PASS_SCRAM_REQUIRED_AND_WRONG_PASSWORD_REJECTED
```

清理以獨立 Compose `down` 作業 `job_01M883SSM500PNDZY2CW359RMC`
移除 3 個容器與 2 個網路；專用資料卷移除
`job_01M883V0QF00SYQZYN097519WK`、
`job_01M883VG1F00ZQNZTK89780XJE`；再按實際 parent chain，逐一
移除 **8 個**新建測試／中間 Docker 映像，未使用廣域 prune。最後移除含
Git clone、程式、一次性密碼、Compose 與 SQL 的整個專用目錄（dry-run
確認 528 entries，`job_01M88428S3009E9FR144HED03M`）。資源再次
盤點回到**0 容器／3 內建網路／0 資料卷／0 映像**，專案路徑不存在。

臨時 Gateway Ed25519 公鑰只對 `/home/ubuntu/.ssh/authorized_keys` 的
精確一行做原子移除（`job_01M8843S91008RDDVQ50FDCCTK`，保留原
owner／group／0600 權限），下一次連線在
`job_01M884424T00JR72ARW5FP5KB0` 得到
`unable to authenticate`，並已刪除 Gateway 臨時主機註冊。
Gateway 刪除主機時仍輸出 `manual_required`，因為公鑰先被撤銷使
Gateway 無法**再次**登入驗證；前述精確替換和 SSH 拒絕是已取得的
撤銷證據，使用者仍可由 PuTTY 自行補做 `authorized_keys` 最後確認。
Windows 原有 `private.ppk` **沒有讀取、傳送或刪除**。

**界線：**新主機與原有 MSDSS 主機確實分離，但本次合成 World 與 Fence
仍位於**同一台新的測試主機**，且測後全部銷毀；這不等於正式 World
Host ↔ 外部 Fence Authority 的跨主機連線、獨立備份域不可回退能力，
也未涵蓋雙 DB Unknown ACK、BD-05 自動解禁及 Send/Purge 競態。
**G5 仍 PARTIAL／NO-GO，Trusted Send OFF，非 Owner 簽核。**

**此項狀態仍是 G5 PARTIAL／NO-GO**：CI 與一次性隔離主機測試通過真實
密碼學與 PostgreSQL 合約，但尚未完成正式憑證隔離、不可回退的最高
Head Authority、
端到端事件語意覆蓋、World DB 發布意圖與雙向未知 ACK 對帳、BD-05
Quarantine 原子自動解禁、正式 Restore／Send／Purge 競態。任何符合簽章的
`HEAD_MATCHED` 仍固定 `release_authorized=False`，Sender 保持 Sealed。

The pre-existing `mir-sec-world001-lab` remains dedicated to its earlier tests.
The separately authorized one-time `mirage-g5-isotest-20261125-a71f` environment
was created outside those resources and completely removed after verification.
Do not attach existing staging/MSDSS networks, restart existing containers, reuse
production secrets, merge the Draft PR, or enable trusted send.

Decision: **Option B approved**. Implementation: **IN PROGRESS**. G5: **NOT RUN**. MIR-SEC-WORLD-001: **OPEN**. Mirage release: **NO-GO**.
