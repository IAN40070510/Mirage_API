# 唯讀 Synthetic World Runtime

## 用途與邊界

這份工具提供 Mirage_API 第一階段的共用唯讀世界基礎：用完整 `WorldScope` 隔離 Session，以不可變 `WorldSnapshot` 保存狀態，並用 CAS 防止舊版本覆寫新版本。它不包含 Medusa 商品欄位、不讀取真實商店，也不提供 WorldEvent 寫入或 HTTP 傳輸。

`AdmissionControl` 負責 ResponseAdmission 的最小控制邊界：Grant、Cutover、Claim 與 Send Authorization 使用同一個單調控制序列。Grant 會先向 `ProjectionRegistry` 驗證契約、來源規格與 Compatibility Profile，只有取得 `AUTHORIZED` 及 Registry revision 才會建立准入。`PostgresAdmissionControl` 將同一狀態機放入 Generation row lock 與資料庫交易，可供兩個 Mirage Instance 共用；WorldEvent 仍未啟用。

`ProjectionEvidence` 將官方規格雜湊、相容 Profile、Effective Projection 與差異核准綁在同一份證據中；官方 Schema 不符時，沒有對應 `DeviationApproval` 就不能建立有效投影。

`ProjectionRegistry` 再確認這份證據的契約、來源規格與 Profile 仍是目前核准版本；撤銷後即使呼叫者持有舊 Evidence，也不能取得新的輸出准入。`PostgresProjectionRegistry` 以同一資料庫交易保存這個決策，讓兩個 Instance 不會各自採用不同撤銷狀態。

## 輸入與輸出

- `WorldScope`：`environment_id`、`deployment_id`、`session_id`、`world_generation_id`。
- `WorldSnapshot.create()`：輸入 JSON 狀態，輸出帶 SHA-256 `state_hash` 的版本快照。
- `InMemoryWorldStore.create_if_absent()`：初始化同一 scope 的唯一快照。
- `PostgresWorldStore`：以 PostgreSQL 唯一鍵、交易與 row lock 提供共享快照及 CAS。
- `InMemoryWorldStore.load_result()`：區分 `world_found`、`session_not_found`、`expired`、`corrupted` 與 `storage_unavailable`。
- `PostgresAdmissionControl`：持久化 Grant、Cutover、Claim 與 Send Authorization 的狀態及共同 revision。
- `InMemoryWorldStore.compare_and_swap()`：輸入期望版本，輸出下一版本或明確衝突錯誤。
- `ResponseSource`：只能是 `SnapshotSource`、`CommitSource` 或 `SecurityErrorSource` 之一。
- `ProjectionEvidence`：輸入核准來源與投影驗證結果，輸出可供 ResponseAdmission 引用的證據。
- `ProjectionRegistry`：在 Grant 前確認投影仍核准且未撤銷，並提供可稽核的 Registry revision。
- `ProjectionRegistry`：登錄、授權與撤銷 Projection Contract，revision 必須單調遞增。
- `PostgresProjectionRegistry`：以 PostgreSQL row lock 保存共享 Registry 授權與撤銷。
- `CandidateStore`：保存不可變候選 bytes，依完整 WorldScope、candidate hash 與期限驗證讀取。
- `CandidateStore.gc()`：只清理已過期且未列在有效 Admission 保護集合中的 Candidate。
- `PostgresCandidateStore`：以共享資料庫保存 Candidate，並以 PostgreSQL 交易執行跨 Instance GC。
- `ReplayStore`：以 issuer／audience／jti 保存一次性授權消費狀態。
- `PostgresReplayStore`：以 PostgreSQL primary key 和交易提供跨 Instance Replay 防護。
- `TrustedSessionAssessmentProvider`：從唯一 `X-Trusted-Session` header 驗證請求綁定，並轉成既有 malicious assessment。
- `tests/fixtures/golden_vectors/world_runtime.json`：固定 canonical state hash、ResponseSource 與 Admission 順序。

## 使用範例

```python
from deception.world import InMemoryWorldStore, WorldScope

scope = WorldScope(
    environment_id="env-1",
    deployment_id="deploy-1",
    session_id="session-1",
    world_generation_id="generation-1",
)
store = InMemoryWorldStore()
snapshot = store.create_if_absent(scope, {"product_id": "prod_synthetic_001"})
same = store.load(scope)
assert same == snapshot
```

PostgreSQL 服務由 `compose.yaml` 提供，第一次建立資料表時套用
[`001_world_runtime.sql`](../migrations/001_world_runtime.sql)。設定
`MIRAGE_POSTGRES_DSN` 後，兩個獨立的 `PostgresWorldStore` 或
`PostgresAdmissionControl` 或 `PostgresCandidateStore` 物件即可共用同一資料庫。GC 前先從
`PostgresAdmissionControl.active_candidate_refs()` 取得仍可能被 Claim／發送使用的引用，再傳給
`PostgresCandidateStore.gc()`；這個查詢是保守保護，寧可延後清理也不能提前刪除。

## 失敗處理

- Snapshot 雜湊不符：拒絕建立或載入，並回報 `corrupted`。
- scope 不同：以不同保存鍵隔離，不得讀到其他 Session。
- World 不存在：`load_result()` 回報 `session_not_found`。
- Snapshot 到期：`load_result()` 回報 `expired`。
- Store 不可用：回報 `storage_unavailable`，不得自動建立替代 World。
- CAS 版本落後：`WorldStoreError("version_conflict")`。
- 未知 Admission：只回傳拒絕，不自動重建。
- Candidate 不存在、跨 scope、過期或 hash 不符：拒絕使用，不重新生成替代 bytes。
- Candidate GC：有效准入引用的 Candidate 必須列入 `protected` 集合，否則不得清理。
- `UNVERIFIABLE` 是操作結果，不是持久化狀態；目前原型尚未提供持久化故障恢復。
- PostgreSQL 連線失敗會回報 `storage_unavailable` 或 `WorldStoreError`，不得建立替代 World。
- Replay JTI 重複消費：回報 `replay`，不得重新執行請求；Replay Store 不可用時必須 Fail-Closed。

## 驗證方式

執行：

```powershell
pytest tests/test_world_runtime.py
MIRAGE_POSTGRES_TEST_DSN=postgresql://mirage:mirage@localhost:5432/mirage pytest tests/test_postgres_conformance.py
python tools/check_documentation.py
```

PostgreSQL Conformance 沒有設定 DSN 時會明確 skip；Golden Vector 與 Fault Matrix 測試可離線執行，但即使通過，也仍未通過完整多 Instance Conformance，本工具不能據此宣稱 Runtime 已符合 Protocol v1.1。

## 授權與限制

專案程式採 Apache-2.0。此實作使用 Pydantic 進行嚴格型別驗證與 psycopg PostgreSQL 交易。`InMemoryWorldStore` 只適合測試與單程序原型；PostgreSQL Store 仍需可信時鐘、Crash recovery、Replay、Candidate retention 與完整跨 Instance Fault Matrix。
