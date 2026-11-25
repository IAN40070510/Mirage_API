# Mirage_API Solo Developer Security Acceptance v1

Status: **OWNER ADOPTED — 2026-11-24**. Scope: Mirage_API `MIR-SEC-WORLD-001`
G3b～G6 acceptance governance. Owner: GitHub `IAN40070510`.

本規範取代前述草稿中「Owner／DBA／Security／Release Approver 必須由四方
個別人工簽核」的**人員配置要求**。這是獨立開發專案的責任分工調整，
**不是安全測試豁免，也不是正式發送／部署核准**。若外部契約、法規或
Mirage release 自己的驗收另有必要簽核，仍須各自遵守，不能由本規範代替。

## 角色與核准權

1. **唯一最終決策 Owner**：`IAN40070510` 可同時承擔開發、資料庫、
   安全測試與發布責任，不需虛構另外三名審核者。Owner 可以在全部
   技術門檻 PASS 後以可追溯的 GitHub 紀錄核准一次特定版本／環境的
   Release；採納本制度本身**不等於**該次 Release 已核准。
2. **外部獨立安全審查**：建議但不是本個人專案 G3b～G6 的一般強制
   阻擋條件。未受審須如實標記 `EXTERNAL_REVIEW_NOT_OBTAINED`，
   不得使用「獨立第三方已簽核／已稽核」等字眼；不得用自評冒充
   GitHub PR 的獨立 reviewer approval。
3. **技術信任邊界保持獨立**：Verifier／Executor／Validator／Authorizer／
   Sender／Restore Fence 的獨立程序、DB Login、Secret、網路或權威
   不因只剩一位 Owner 而合併。安全來源的**獨立 Validator** 不等於
   可省略的**外部人工 Reviewer**。
4. **GitHub 分支規則**：如果現有 branch protection 或外部服務要求
   第三方 PR approval，必須實際滿足或另取得明確規則變更；
   本規範不宣稱 Owner 能在 GitHub 批准自己的 PR。

## 不可豁免的技術驗收

| Gate | 必須獲得的實證 | 目前狀態 |
| --- | --- | --- |
| G3b | 20 條原生 Client HTTP 成功／拒絕／重試、獨立來源與角色 ACL、精確 Payload／Header／Status | **OPEN；20 路由各有指定 Client 原生隔離 PASS**（`7ada6fd`、34 子案例）；另增七個不同實體 SCRAM／mTLS／最低 ACL 的整鏈隔離 PASS，完整 2xx／4xx、CAS／URL／正式部署 ACL 未結 |
| G4 | 不可變 Authorized Snapshot、Pin、一次性 Send Lease、真正 ASGI 首 bytes 與失敗恢復 | **OPEN；真 PG 34 筆唯一 Lease、獨立 Sender SCRAM、Purge Fence 權限預檢與 G6 ASGI／故障隔離子項 PASS**，正式 Sender Fuse 未啟 |
| G5 — 標準單機 | 無外部 Fence 的完整業務與可信發送功能、受保護本機 ACL／StartSend／Purge／已知 Restore／Unknown、正確宣告整機回滾保證缺失 | **PARTIAL_IMPLEMENTED／ISOLATED_SUBCASES_PASS，整體 OPEN**；ARM64 `7ada6fd`、53 tests；正式啟動／Restore 控制面／完整安全矩陣未結 |
| G5 — 選配外部 Fence | 僅於啟用／宣稱外部強化保護時，必驗 World DB 域外最高 Head、BD-05 原子自動解禁、雙向 COMMIT/ACK、跨復原域 Restore 與競態 | **NOT_COMPLETE／NOT_RUN** |
| G6 | PostgreSQL 真實權限、競態／故障注入、混合版本回退、端到端效能、既有功能回歸與發布前清單 | **OPEN；隔離真七 TLS 30 tests、G5／Role 53 tests PASS**；端到端效能／完整網路故障／正式回退／Owner 清單未結 |

**2026-11-25 D-74 Owner 產品方向**：Mirage 單機完整功能，外部 Fence 選配；詳見 [單機／強化模式契約](single-node-restore-profiles.md)。適用的測試集合由**實際發行 Profile** 決定；G3b、G4、G6 與單機基本安全不因外部選配而放寬。沒有域外最高可信 Head 時，**整機快照回滾不可復活的保證不可聲稱**。Owner 本次決定不等於對該殘餘風險的最終 Release 接納，也沒有解封 Trusted Send。

**2026-11-25 SHA／證據索引**：`7ada6fd539075c74ad4660919b0a2a5bc5852acc`，ARM64 七 TLS 真 JWS／PG 唯一 Lease `job_01M8939FXM001KK15ZBTSGNCTK`、`30 passed`；G5 Standard Role／Restore／混合 Sender SQL `job_01M893DRJW00Z7GF0MPMZR6H75`、`53 passed`；PR [#34](https://github.com/IAN40070510/Mirage_API/pull/34) 含不可變 SHA 與具名 JUnit 路徑。測試使用拋棄式 PG schema、短期 TLS CA、loopback，無正式外連。每路由各有子項通過，**不代表該列全 Gate PASS**。

所有操作按矩陣保留 `NOT_RUN`／`RUNNING`／`PASS`／`FAIL`／`BLOCKED`／
`STALE` 狀態，只有相符的真實實測可以變成 `PASS`。
CI／文件掃描／Mock／實驗室子案例各自標明範圍，不能互相補簽。
每個 PASS 至少追溯不可變 Commit SHA、Migration／Schema、測試環境、
DB Role、輸入／預期、實際退出狀態、SQLSTATE／故障日誌、證據 URL，
並註明 SKIP、剩餘風險與未涵蓋情境。失敗、缺失、版本漂移或
不可重現者必須維持 NO-GO，修補後重跑，不准人工改表。

## Owner 最終核准條件與格式

1. G3b～G6 每項強制子案例均已 PASS；沒有未處理的 BLOCKED／FAIL／
   STALE／NOT_RUN。剩餘不在威脅模型內的風險要有 Owner 明示接納，
   但不能將未通過的強制項目重命名為「已接受風險」而繞過。
2. 真實 Release Fuse、各服務 Role／Secret／網路、Restore 後 Quarantine
   及可靠的發送阻擋經所部署環境實測；文件中的 `OFF` 字樣不算證據。
3. Owner 在 GitHub 以一筆獨立、可稽核的最終決議記錄：目標完整 SHA、
   Gate Evidence Index、環境、殘餘風險、外部審查狀態、決策人、日期、
   `APPROVE` 或 `NO-GO`。決策可由同一 Owner 作出，但不得稱為獨立審核。
4. 舊 `NO-GO` 不因本文採納而自動翻轉。真正合併、staging／production
   部署與 Trusted Send 啟用須**另有 Owner 明確命令**；不由 Agent 自動執行。

## 本次採納的即時影響

- **移除人力阻塞**：不再為四位不同人工審核者的 GitHub 帳號等待。
- **不更動技術 Gate**：G3b～G6 仍 `OPEN`；`MIR-SEC-WORLD-001=OPEN`、
  `Mirage release=NO-GO`、正式 Trusted Send `OFF`。
- **不冒充完成驗收**：使用者於 2026-11-24 核准此**流程制度**，
  尚未核准任何最終版本／Release，亦沒有外部獨立審查完成紀錄。

沿革：[決策紀錄 D-73](decisions-log.md)、[ADR](../../adr/MIR-SEC-WORLD-001-world-db-trust-boundary.md)、
[驗收計畫](verification-plan.md) 與 [G3b 矩陣](g3b-operation-acceptance-matrix.md)。
