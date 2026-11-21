# MIR-SEC-WORLD-001 — World DB Security Architecture 文件入口

此目錄與 [Architecture Draft ADR v0.2](../../adr/MIR-SEC-WORLD-001-world-db-trust-boundary.md) 保存多輪世界資料庫權限與發送授權架構審查，供 Mirage Owner、DBA、Security 與 MSDSS 跨服務驗收交接。v0.1 可透過同分支 Git 歷史追溯，不用維護兩份互相分叉的草案。

**目前狀態：Proposed／Security Weakness OPEN／MSDSS P2 NO-GO。沒有執行任何修復或正式發送啟用。**

**v0.2 Contract Freeze candidate（2026-11-21）**：唯一授權點為 `SEND_AUTHORIZED` COMMIT（Freeze v1 不變）；StartSend 只核對 Snapshot／owner／deadline／single-use／Purge Fence，沒有第二次 Policy 或 Emergency 授權；Candidate Payload 與 Snapshot Purge 分開。Operation Identity、外部 effect key、未知 `SEND_STARTED`、Restore Quarantine、Old Role Mixed Binary Fence 已有 Proposed MUST 與 22 個 NOT_RUN 測試 ID。**新控制 NOT_IMPLEMENTED，無安全修補通過證據**。

**來源追溯**：Mirage upstream `main` `88dc2008fd35a2d3873949a769653dc9f18e8980`；MSDSS `main` `5a1ee26dcf79f04cf29345a0403e3f3f8082358b` 的 Protocol Freeze v1；Mirage 文件歷史分支名 `docs/mir-sec-world-001-adr-v0.1`／**前置** Commit `003c918f142296588d2fe14b70fafe3cc5cf8458`。**前置 SHA 不是最新文件提交**，v0.1 分支名也不是 v0.2 版本權威；當前 SHA 需以 GitHub／`git rev-parse HEAD` 實查，文件版號、兩個 Source SHA、Git Commit、NOT_IMPLEMENTED、NOT_RUN 分開記錄。**Mirage main 尚未收錄此 ADR**。

**既有版本差異**：Mirage upstream 固定 SHA 的 `start_send` 仍含 Generation/Profile Emergency 再查；MSDSS Freeze v1 則規定最終 `SEND_AUTHORIZED` COMMIT 後不二次查核。這是**待 Mirage Owner 採納的原生協定差異**，不是目前 upstream 已符合新要求的證明。


| 文件 | 說明 | 建議閱讀順序 |
| --- | --- | --- |
| [ADR v0.2](../../adr/MIR-SEC-WORLD-001-world-db-trust-boundary.md) | 問題、方案 B、Freeze v1 不變、不可變 Snapshot／Operation/Purge 與 I-01～I-19、Owner 未決事項 | 1 |
| [決策歷史](decisions-log.md) | 多輪採納／否決／校正的具體理由，避免對話結論遺失 | 2 |
| [權威證據矩陣](evidence-authority-matrix.md) | JWS、Replay、Receipt、Candidate Submission／Validation／Promotion／Binding、Admission、Operation Result 各自可信來源 | 3 |
| [交易／鎖矩陣](transaction-lock-matrix.md) | 現有鎖順序、可能循環、交易責任、未知 COMMIT 與失敗恢復 | 4 |
| [威脅能力矩陣](threat-capability-matrix.md) | R1–R5、Runtime/Verifier/主機威脅與每項控制覆蓋能力 | 5 |
| [驗收計畫](verification-plan.md) | 真 PostgreSQL／非特權 Role、Snapshot/Purge、Policy Race、外部 side effect／Restore、Mixed Runtime、未知 COMMIT（22 個精確化 ID 全 NOT_RUN） | 6 |

## 交接原則

1. 此文件以 Mirage 上游 `main` commit `88dc2008fd35a2d3873949a769653dc9f18e8980` 作**唯讀分析基準**，未來 source drift 必須更新證據。
2. 僅被檢查過的**既有行為**可標示為 observed；提議的 Verifier Role、Receipt 表、特權函式、鎖 DAG 與測試一律 Proposed／NOT_RUN。
3. 每次架構裁決更新 [決策歷史](decisions-log.md)；每次程式或 Migration 變更新增 test ID、失敗案例與 JUnit／SQLSTATE 的鏈結證據。
4. `MIR-SEC-WORLD-001` 是 Mirage 的 security weakness ID；`MSDSS P2` 是另一專案的驗收代號。兩者都需分開關閉程序。
5. 詳細攻擊操作、Runtime 真實憑證、Host Path、私人 PoC 不應放進公開文件；公開保存高層級安全 invariant 與修復證據索引，實際秘密與原始敏感日誌交由受限安全流程管理。
6. **持續紀錄約定**：每輪討論若形成新架構結論，優先更新這組既有文件與 [Decisions Log](decisions-log.md)，以相同文件分支的新 Git Commit 保存更動與版本；不因對話新開便另起一套草案。未核准為 Proposed、未測試為 NOT_RUN；此約定不授權自動合併 main、修改 staging 或啟用正式發送。跨會話更新需由當次有 Repo 存取權的執行者實際執行，並非無人值守自動化。
7. **文件檢查留證**：從**完整專案 checkout** 執行 `python tools/check_documentation.py`，並另核對 Verification Plan 的所有 `WORLD-*` ID 唯一性與子案例語意；PR／提交紀錄應保存執行環境、退出碼、完整 HEAD SHA 和實際變更路徑。靜態文件 PASS 不等於 PostgreSQL 安全測試 PASS；本文件不可自我內嵌「現在的自身 Commit SHA」。

參考原文件：[World Runtime](../../world-runtime.md)、[Trusted Session](../../trusted-session.md)、[Profile Revocation](../../profile-revocation.md)、[Key Revocation](../../key-revocation.md)、[World Commit Result](../../commit-results.md)。
