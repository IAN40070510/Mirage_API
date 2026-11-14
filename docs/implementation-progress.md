# Mirage_API 實作進度

> 本文件是工作進度追蹤，不是 Protocol v1.1 的符合性聲明。  
> 只有在 Golden Vectors、Fault Matrix 與多 Instance Conformance 全部通過後，才可以宣稱 Runtime 符合 Protocol v1.1。

## 目前總覽

更新日期：2026-11-14

| 工作區 | 狀態 | 說明 |
| --- | --- | --- |
| Architecture Baseline v1.1 | 已定義 | 已固定 Session、World、Projection、Admission、Fail-Closed 等責任邊界。 |
| Protocol v1.1 文件基線 | 已定義 | README 已記錄 Admission 狀態、ResponseSource、控制序列與 Conformance Gate。 |
| 唯讀 World Runtime 基礎 | 第一階段完成 | 已有嚴格 `WorldScope`、不可變 `WorldSnapshot`、CAS 與單程序 Admission 原型。 |
| Medusa 領域整合 | 既有流程 | 現有電商資料與 API 驗證流程仍可運作，尚未接入完整共用 World Runtime。 |
| 共享持久化 WorldStore | 未開始 | 目前只有單程序 `InMemoryWorldStore`，不能作為多 Instance 安全依據。 |
| Golden Vectors | 未通過 | 尚未建立並驗證跨元件 JWS、Admission、Projection 與錯誤碼向量。 |
| Fault Matrix | 未通過 | 尚未完成 Store、Registry、Clock、Network、Crash、Replay 與撤銷故障注入。 |
| 多 Instance Conformance | 未通過 | 尚未驗證跨 Instance 的 Claim、Cutover、Watermark 與 Fail-Closed 行為。 |
| WorldEvent 寫入 | 停用 | 在 Commit、Idempotency、Epoch／Lease 與 Rotation 驗收前保持停用。 |

## 已完成

### 文件與規格

- [README 架構基線](../README.md) 已補上各架構節點的白話功能說明。
- 已區分 `UNVERIFIABLE` 操作結果與持久化 Admission 狀態。
- 已區分 `SnapshotSource`、`CommitSource` 與 `SecurityErrorSource`。
- 已固定 Grant／Claim／Cutover／Send Authorization 使用同一 Generation 控制序列。
- 已要求 Projection 差異具備核准來源與 revision 證據。
- 已明確規定 Conformance 證據完成前不得宣稱 Runtime 符合 Protocol v1.1。

### 第一階段 Runtime

- [`WorldScope`](../src/deception/world/models.py) 綁定環境、部署、Session 與 World 世代。
- [`WorldSnapshot`](../src/deception/world/models.py) 使用固定 JSON 編碼與 SHA-256 驗證內容完整性。
- [`InMemoryWorldStore`](../src/deception/world/store.py) 提供 atomic create-if-absent、讀取與 CAS。
- [`AdmissionControl`](../src/deception/world/admission.py) 提供 Grant、Cutover、Claim、Send Authorization 與狀態查詢。
- 電商 404 已改為綁定當次請求商品 ID；攻擊樣式 ID 先 URL encode 再放入 message，避免原始字串直接回顯。
- Admission 未知或遺失時不會自動重建。
- 新增的功能與測試函式均附有功能 docstring。

## 驗證紀錄

### 本機

| 驗證 | 結果 |
| --- | --- |
| `pytest tests/test_world_runtime.py` | 6 passed |
| `python tools/check_documentation.py` | 通過，782 functions、25 tool guides |
| `python -m compileall -q src/deception/world tests/test_world_runtime.py` | 通過 |
| `git diff --check` | 通過 |
| 完整 pytest | 尚未完成；目前環境缺少既有 `openapi_core`、`pydantic_ai`、`httpx2` |

### 遠端 MSDSS Mirage

遠端測試使用現有 branch `feat/p2-trust-contract-hardening-20261110`、commit `1a9801e`，不是本地尚未提交的第一階段 World Runtime 變更。

| 驗證 | 結果 |
| --- | --- |
| Docker image build | 成功 |
| `/healthz` | 成功 |
| `/demo/info` | 成功 |
| `verify_domain_api.py --domain ecommerce` | 成功 |
| 同一商品連續兩次 GET | 兩次 `200`，body 完全一致 |
| 未知商品 404（原始遠端版本） | HTTP `404` 成功，但 body 未包含請求商品 ID |

遠端 404 body 目前為：

```json
{"message":"The requested synthetic demonstration product does not exist.","type":"not_found"}
```

原始遠端版本不符合目前 README 所定義的「404 回應必須綁定當次請求 ID」要求；該缺口已在本地修正並於隔離遠端副本驗證。原始遠端測試容器已清理，既有 staging 服務未停止。

本次修正已在隔離遠端測試副本重新建置驗證：未知商品回傳 HTTP `404`、`type=not_found`，message 包含請求商品 ID；測試容器已清理。

## 進度對照表

| 階段 | 目標 | 完成條件 | 狀態 |
| --- | --- | --- | --- |
| 1 | 唯讀 Synthetic World 基礎 | Scope、Snapshot hash、CAS、ResponseSource、Admission 原型與單元測試 | 已完成 |
| 2 | 共用持久化 WorldStore | 共享 Store、Session Binding、Snapshot Isolation、重啟策略與故障結果 | 未開始 |
| 3 | Projection 與領域回應整合 | Official／Effective Projection、核准差異、200／404 權威欄位與最終 HTTP 驗證 | 進行中 |
| 4 | Admission 多 Instance | 持久化 Grant／Claim、Cutover、Send Authorization、Emergency Revocation | 未開始 |
| 5 | Conformance | Golden Vectors、Fault Matrix、多 Instance Suite 全部通過 | 未開始 |
| 6 | WorldEvent | Commit、Idempotency、Epoch／Lease、Read Fence、Rotation 與復原 | 停用 |

## 下一步

1. 將 `InMemoryWorldStore` 抽象成共享持久化 Store 介面，補上 scope mismatch、corrupted 與 storage unavailable 結果。
2. 建立 Official OpenAPI／Reviewed Effective Projection／Deviation Approval 的可驗證資料模型。
3. 建立跨元件 Golden Vectors 與第一版 Fault Matrix。
4. 將 Admission 控制從單程序原型移到具線性化順序保證的共享 Store。
5. 在上述證據完成前，維持 `WorldEvent` 寫入停用。

## 授權與限制

本文件與專案程式採 Apache-2.0。進度狀態依目前本機測試與遠端驗證紀錄整理，不代表生產部署核准、正式多 Instance 符合性或真實 Medusa 資料隔離已完成。
