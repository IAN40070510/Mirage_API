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
| WorldStore 介面與結果分類 | 第一階段完成 | 已有 `WorldStore` Protocol、`WorldLoadResult` 與 found／expired／corrupted／unavailable 分類；目前仍是單程序實作。 |
| PostgreSQL 共享 WorldStore | 實作完成，待環境驗證 | 已有 migration、交易式 Store 與 CAS；需在 PostgreSQL 環境執行 Conformance。 |
| PostgreSQL Projection Registry | 已接入 Grant，待完整驗證 | Grant 會保存 Registry revision；共享核准／撤銷交易已驗證，完整 Registry Conformance 尚未完成。 |
| Golden Vectors | 第二版部分完成，尚未完整通過 | 已建立 canonical state、ResponseSource、Admission Registry revision 與 HTTP 安全錯誤 fixture；JWS／完整錯誤碼向量仍待補齊。 |
| Candidate retention | PostgreSQL 實作完成，待遠端驗證 | 已有 scope／hash／期限、共享 Candidate table、Admission 有效引用查詢與受保護 GC。 |
| Replay Store | PostgreSQL 實作完成，待遠端驗證 | 已有 issuer／audience／jti 唯一消費與 expiry GC；完整 JWS 入口尚未接入。 |
| Fault Matrix | 第二版部分完成，尚未完整通過 | 已加入 deadline equality、PostgreSQL 重啟後 Claim、Emergency Revocation 與 storage unavailable；Network／Replay／未知交易結果仍待補齊。 |
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
- 已新增 `ProjectionCompatibilityProfile`、`DeviationApproval` 與 `ProjectionEvidence`，官方 Schema 與 Effective Projection 的差異不能無證據通過。

### 第一階段 Runtime

- [`WorldScope`](../src/deception/world/models.py) 綁定環境、部署、Session 與 World 世代。
- [`WorldSnapshot`](../src/deception/world/models.py) 使用固定 JSON 編碼與 SHA-256 驗證內容完整性。
- [`InMemoryWorldStore`](../src/deception/world/store.py) 提供 atomic create-if-absent、讀取與 CAS。
- [`AdmissionControl`](../src/deception/world/admission.py) 提供 Grant、Cutover、Claim、Send Authorization 與狀態查詢。
- Store 載入結果已區分 `world_found`、`session_not_found`、`expired`、`corrupted` 與 `storage_unavailable`。
- Admission 的 Grant、Claim、Send Authorization 會保存共同控制序列 revision，供順序驗證與稽核。
- PostgreSQL migration 已建立 WorldSnapshot、Generation control 與 ResponseAdmission 表。
- `PostgresWorldStore` 與 `PostgresAdmissionControl` 已加入，兩個獨立物件可共用同一 PostgreSQL。
- `ProjectionRegistry` 已加入契約來源／Profile 核對、單調 revision 與撤銷後拒絕。
- `PostgresProjectionRegistry` 已加入共享資料庫授權／撤銷交易。
- 第一版 Golden Vector 與 Fault Matrix 測試已加入，未將測試通過誤寫成完整 Conformance。
- Golden Vector 已固定 `ResponseAdmission.projection_registry_revision` 與 `pipeline_unavailable`／`pipeline_not_applicable` 的 status、body、request ID。
- `CandidateStore` 已加入完整 scope、精確 bytes hash、期限查詢與有效准入保護 GC 原型。
- `PostgresCandidateStore` 已加入共享 Candidate table；`PostgresAdmissionControl.active_candidate_refs()` 可提供 GC 保護集合。
- `ReplayStore` 與 `PostgresReplayStore` 已加入一次性 JTI 消費、重放拒絕與 expiry GC。
- 電商 404 已改為綁定當次請求商品 ID；攻擊樣式 ID 先 URL encode 再放入 message，避免原始字串直接回顯。
- Admission 未知或遺失時不會自動重建。
- 新增的功能與測試函式均附有功能 docstring。

## 驗證紀錄

### 本機

| 驗證 | 結果 |
| --- | --- |
| `pytest tests/test_world_runtime.py` | 6 passed |
| `python tools/check_documentation.py` | 通過，897 functions、25 tool guides |
| `python -m compileall -q src/deception/world tests/test_world_runtime.py` | 通過 |
| `git diff --check` | 通過 |
| 完整 pytest | 尚未完成；目前環境缺少既有 `openapi_core`、`pydantic_ai`、`httpx2` |
| PostgreSQL Conformance | 2 skipped | 未設定 `MIRAGE_POSTGRES_TEST_DSN`；未將 skip 視為通過 |
| Compose YAML／migration 靜態檢查 | 通過 | YAML 可解析、migration 內容存在；本機未安裝 Docker CLI，尚未啟動資料庫 |

### 遠端 MSDSS Mirage PostgreSQL 驗證

使用隔離 Compose project `mirage-pg-conformance`、port `18000` 與獨立 PostgreSQL volume 驗證；測試完成後已移除該 project、container、network 與 volume，既有 staging 未停止。

| 驗證 | 結果 |
| --- | --- |
| PostgreSQL／Mirage image build | 成功 |
| PostgreSQL healthcheck | 成功 |
| `001_world_runtime.sql` | 六張表建立成功 |
| 兩個 `PostgresWorldStore` 共用 Snapshot／CAS | 通過 |
| 兩個 `PostgresAdmissionControl` Claim 單次使用 | 通過 |
| `PostgresProjectionRegistry` 授權／撤銷 | 通過；共享資料庫可觀察撤銷結果 |
| `PostgresCandidateStore` 與 Admission 保護引用 | 通過；有效准入期間 GC 不刪除 Candidate |
| PostgreSQL Clock／Crash／Emergency Fault Matrix | 通過；期限相等、重啟後重放與撤銷競爭均拒絕 |
| `PostgresReplayStore` 兩 Instance 一次性消費 | 通過；同一 JTI 僅一個 ACCEPTED，expiry GC 通過 |
| ecommerce HTTP verifier | 通過；使用隔離 Host `127.0.0.1:18000` |
| 既有 staging containers | 持續運行 |

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
| 2 | 共用持久化 WorldStore | 共享 Store、Session Binding、Snapshot Isolation、重啟策略與故障結果 | PostgreSQL 實作完成，待完整環境驗證 |
| 3 | Projection 與領域回應整合 | Official／Effective Projection、核准差異、200／404 權威欄位與最終 HTTP 驗證 | Registry 單程序／PostgreSQL 實作完成，整合進行中 |
| 4 | Admission 多 Instance | 持久化 Grant／Claim、Cutover、Send Authorization、Emergency Revocation | 基本交易完成，撤銷與故障驗收待完成 |
| 5 | Conformance | Golden Vectors、Fault Matrix、多 Instance Suite 全部通過 | 第一版 Vector／Fault 測試完成，尚未全數通過 |
| 6 | WorldEvent | Commit、Idempotency、Epoch／Lease、Read Fence、Rotation 與復原 | 停用 |

## 下一步

1. 將 `TrustedSessionVerifier` 接入實際可信 Gateway ingress，並完成 JWS／Replay 跨 Instance Golden Vectors；目前不宣稱 Protocol v1.1 已完成。
2. 補上 Clock／Network／Crash recovery、Emergency Revocation 與未知交易結果測試。
3. 完成 Registry 與 Admission 的完整多 Instance Conformance。
4. 在上述證據完成前維持 `WorldEvent` 寫入停用。

## 授權與限制

本文件與專案程式採 Apache-2.0。進度狀態依目前本機測試與遠端驗證紀錄整理，不代表生產部署核准、正式多 Instance 符合性或真實 Medusa 資料隔離已完成。
