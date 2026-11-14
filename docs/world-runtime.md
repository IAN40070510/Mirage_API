# 唯讀 Synthetic World Runtime

## 用途與邊界

這份工具提供 Mirage_API 第一階段的共用唯讀世界基礎：用完整 `WorldScope` 隔離 Session，以不可變 `WorldSnapshot` 保存狀態，並用 CAS 防止舊版本覆寫新版本。它不包含 Medusa 商品欄位、不讀取真實商店，也不提供 WorldEvent 寫入或 HTTP 傳輸。

`AdmissionControl` 負責 ResponseAdmission 的最小控制邊界：Grant、Cutover、Claim 與 Send Authorization 使用同一個單調控制序列。它是單程序原型，不能直接當作多 Instance 的持久化 Store。

## 輸入與輸出

- `WorldScope`：`environment_id`、`deployment_id`、`session_id`、`world_generation_id`。
- `WorldSnapshot.create()`：輸入 JSON 狀態，輸出帶 SHA-256 `state_hash` 的版本快照。
- `InMemoryWorldStore.create_if_absent()`：初始化同一 scope 的唯一快照。
- `InMemoryWorldStore.compare_and_swap()`：輸入期望版本，輸出下一版本或明確衝突錯誤。
- `ResponseSource`：只能是 `SnapshotSource`、`CommitSource` 或 `SecurityErrorSource` 之一。

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

## 失敗處理

- Snapshot 雜湊不符：拒絕建立或載入。
- scope 不同：以不同保存鍵隔離，不得讀到其他 Session。
- World 不存在：`WorldStoreError("world_not_found")`。
- CAS 版本落後：`WorldStoreError("version_conflict")`。
- 未知 Admission：只回傳拒絕，不自動重建。
- `UNVERIFIABLE` 是操作結果，不是持久化狀態；目前原型尚未提供持久化故障恢復。

## 驗證方式

執行：

```powershell
pytest tests/test_world_runtime.py
python tools/check_documentation.py
```

目前尚未通過 Golden Vectors、Fault Matrix 或多 Instance Conformance；本工具不能據此宣稱 Runtime 已符合 Protocol v1.1。

## 授權與限制

專案程式採 Apache-2.0。此實作使用 Pydantic 進行嚴格型別驗證。`InMemoryWorldStore` 只適合測試與單程序原型；正式部署仍需共享持久化 Store、可信時鐘、Crash recovery、Replay 與跨 Instance 原子性。
