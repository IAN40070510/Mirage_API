# MIR-SEC-WORLD-001 — World DB Security Architecture 文件入口

此目錄與 [Architecture Draft ADR v0.1](../../adr/MIR-SEC-WORLD-001-world-db-trust-boundary.md) 保存多輪世界資料庫權限與發送授權架構審查，供 Mirage Owner、DBA、Security 與 MSDSS 跨服務驗收交接。

**目前狀態：Proposed／Security Weakness OPEN／MSDSS P2 NO-GO。沒有執行任何修復或正式發送啟用。**

| 文件 | 說明 | 建議閱讀順序 |
| --- | --- | --- |
| [ADR v0.1](../../adr/MIR-SEC-WORLD-001-world-db-trust-boundary.md) | 問題、方案 B、信任邊界、不變量、遷移及 Owner 未決事項 | 1 |
| [決策歷史](decisions-log.md) | 多輪採納／否決／校正的具體理由，避免對話結論遺失 | 2 |
| [權威證據矩陣](evidence-authority-matrix.md) | JWS、Replay、Receipt、Binding、Candidate、Admission、Operation Result 各自可信來源 | 3 |
| [交易／鎖矩陣](transaction-lock-matrix.md) | 現有鎖順序、可能循環、交易責任、未知 COMMIT 與失敗恢復 | 4 |
| [威脅能力矩陣](threat-capability-matrix.md) | R1–R5、Runtime/Verifier/主機威脅與每項控制覆蓋能力 | 5 |
| [驗收計畫](verification-plan.md) | 真實 PostgreSQL／非特權 Role、并行、Key Rotation、Restore、ASGI snapshot 的負面與正向測試 | 6 |

## 交接原則

1. 此文件以 Mirage 上游 `main` commit `88dc2008fd35a2d3873949a769653dc9f18e8980` 作**唯讀分析基準**，未來 source drift 必須更新證據。
2. 僅被檢查過的**既有行為**可標示為 observed；提議的 Verifier Role、Receipt 表、特權函式、鎖 DAG 與測試一律 Proposed／NOT_RUN。
3. 每次架構裁決更新 [決策歷史](decisions-log.md)；每次程式或 Migration 變更新增 test ID、失敗案例與 JUnit／SQLSTATE 的鏈結證據。
4. `MIR-SEC-WORLD-001` 是 Mirage 的 security weakness ID；`MSDSS P2` 是另一專案的驗收代號。兩者都需分開關閉程序。
5. 詳細攻擊操作、Runtime 真實憑證、Host Path、私人 PoC 不應放進公開文件；公開保存高層級安全 invariant 與修復證據索引，實際秘密與原始敏感日誌交由受限安全流程管理。

參考原文件：[World Runtime](../../world-runtime.md)、[Trusted Session](../../trusted-session.md)、[Profile Revocation](../../profile-revocation.md)、[Key Revocation](../../key-revocation.md)、[World Commit Result](../../commit-results.md)。
