# G3b／G4 Oracle 共用測試主機：獨立 staging 安全驗收

本程序是一次性安全實驗，**不是正式部署、Release Fuse 放行或 Trusted Send 授權**。
只在 Owner 授權的 Oracle 測試主機使用；任何正式 MSDSS／Mirage 容器、網路、
資料庫、憑證、埠及 Volume 都不在本次操作範圍。

## 唯一名稱與先決條件

- 在**新目錄** clone 固定 SHA，事前檢查沒有同名 Compose Project、Container、
  Network、Image tag、Host loopback port 與 Secrets 目錄。
- 資料庫必須是新的 `postgres:17.6-alpine` **無 Volume** 容器，綁定
  `127.0.0.1` 隨驗收配置的非共用埠；管理者密碼使用單次隨機產生值，
  不可重用 CI 範例 `mirage_ci_only`。
- 三個新網路依角色分隔：Gateway 僅看見 Verifier；Executor 與 Validator
  位於執行網路；DB 網路僅供受限 DB 通訊。服務側無 host 發布埠。
- 新 Compose Project 由 `G3B_CI_COMPOSE_PROJECT` 指定；
  `G3B_CI_{GATEWAY,EXECUTION,DATABASE}_NETWORK` 覆寫新網路名稱；
  `G3B_CI_IMAGE` 使用不可與既有 `mirage-api:standalone` 混用的新 Tag。
- 新 DB 連線字串只經 `G3B_CI_ADMIN_DSN`（host-only）傳入準備與 Audit
  程式，避免硬編碼。`G3B_CI_HOST_PORT` 指向本次 Loopback 埠；若
  Docker `internal` 網路使 Loopback 不可達，Audit 應改由一次性 DB
  網路執行，設定 `G3B_CI_AUDIT_DB_HOST=g3b-postgres` 與
  `G3B_CI_AUDIT_DB_PORT=5432`，不得因此開通正式外部埠。
- 設定 `MIRAGE_G3B_CI_EXPLICIT=ephemeral-four-services-only`；
  `MIRAGE_TRUSTED_SEND_ENABLE=false`、不連正式外部發送端或真實 Store。

## 正向與故障驗收

1. 記錄 Git SHA、Docker Image ID、PostgreSQL 版本、隔離網路 ID、
   服務 Container ID；不能把兩個不同 SHA 的證據混合使用。
2. 使用 `g3b_ci_prepare.py` 在新 DB 建五個獨立 SCRAM Login、
   三個短期 mTLS CA 及四組各自的 Compose file Secret。
3. 用 `g3b_ci_probe.py --mode gateway` 驗證真 HTTP 路由、重播拒絕、
   Gateway 無 Executor／DB DNS 視野；`--mode audit` 核對角色、
   真實 ACL、Mount、Read-only Rootfs、無 host port 及 Network。
4. 在不會有其他使用者流量的新 DB 上，測試 DB 中斷時系統 fail-closed；
   在一次性 DB 停止前後，記錄 Replay／Receipt 數量；用
   `g3b_ci_fault_probe.py --phase degraded` 確認簽章查詢只回 `503`，
   恢復後先透過原生 World 初始化介面建立新合成 Session，再以
   `--phase recovered --recovery-session <唯一測試Session>` 確認正常 `200`
   且同請求重播 `403`。
   新查詢會產生合法 Receipt；故障期間不得增加 Receipt 或重試 Commit。
5. 另外核對 Restore Quarantine、Rollback、跨版本狀態及 G5
   外部 Anchor 的真實控制平面。**若沒有獨立系統或 Owner 證據，只能記
   `OPEN`，不得以單資料庫內的模擬取代。**

## 清理與證據

- 優先 `docker compose down` 只清理本次 Project；單獨移除本次 DB
  Container 與三個新建 Network。不能使用會波及別人的名稱 Pattern、
  `docker system prune` 或跨專案 Volume 清除。
- 保留脫敏後的 Run／Job、鏡像 SHA、角色／容器／網路匿名 ID、
  SQL 判定結果與失敗類別；**不保存私鑰、密碼、完整 DSN 或用戶資料**。
- 本次 Oracle 實驗只能支撐自己測到的 G3b/G4 子項；不能自動變更
  [Solo Owner 驗收文件](solo-developer-security-acceptance-v1.md)中的 G3b～G6
  `OPEN`、發布 `NO-GO` 或正式 Trusted Send `OFF`。

## 2026-11-25 初次隔離實測／修補紀錄

- Oracle 固定服務映像對應整合 SHA `ea6e6d0e0529feb5f55e6bdb599d44d77b8fa38b`；
  Gateway 工作 `job_01M87QNTQK00QTJMRSNPFYSP66` 通過，20/20 路由及重播／
  匿名／跨網路拒絕；獨立 Audit 工作 `job_01M87QSTAB001130H3C3FMA586`
  通過：四服務、三網路、專屬 Secret、物理 ACL、Trusted Send OFF。
- 首次停止**本次一次性 DB**，工作 `job_01M87QX7BJ00QVEG9QBVFWHH7B`
  發現已簽章讀取回傳 `500` 而非預期 `503`，因此故障驗收 **FAIL**。
  DB 已由工作 `job_01M87QXQS300ZTF1BQMW4F3XND` 啟動；
  Replay／Receipt 數量在故障前後維持 `49 → 49`。
- 根因為 `create_direct_verifier_app.verify_original` 未將 IngressTx 的
  `psycopg.Error` 轉為固定拒絕狀態。修補後應以新映像重跑，同時驗證
  `503`、回復 `200`、重放 `403` 與 Receipt 不重複，未通過不可簽收。
- 修補版 `9a010a3e9d184588b8797be048d96258adfebae1` 的中斷測試
  `job_01M87R6DQZ00DTM963N9ZBQMS2` 已證實 `503`／無洩漏；
  復原第一次檢查 `job_01M87R7PWJ00BV0HDQS4KV1ZJ7` 顯示 `503`，
  實際 PostgreSQL 時鐘超過原合成 World 的 `expires_at`（TTL 420 秒），
  因此是過期測資的拒絕。後續以原生初始化介面建立新合成 Session，
  不直接改資料表 TTL，再檢查正常查詢與重播。

## 2026-11-25 修補後證據：G3b/G4 隔離子項 PASS

| 證據 | 固定結果 | 邊界 |
| --- | --- | --- |
| [整合 CI：四服務 45493471770](https://github.com/IAN40070510/Mirage_API/actions/runs/45493471770) | success | 4 非 root 服務／3 網路／物理 ACL／mTLS |
| [整合 CI：World PG 45493471691](https://github.com/IAN40070510/Mirage_API/actions/runs/45493471691) | 177 passed；另 mTLS 5、G5 模擬 9、Fence 7 | G5 模擬不算正式 Anchor 放行 |
| [整合 CI：Container 45493471527](https://github.com/IAN40070510/Mirage_API/actions/runs/45493471527) | success | 容器展示與攻擊型請求回歸 |
| Oracle 真 HTTPS Gateway `job_01M87QNTQK00QTJMRSNPFYSP66` | 20/20 無 JWS 拒絕、簽章路徑、重播、隔離 PASS | 內部 Candidate 對帳，不是正式 Client Send |
| Oracle 真 PG／Secret Audit `job_01M87QSTAB001130H3C3FMA586` | 四角色服務、三個 `internal` 網路、SCRAM／ACL、Secret 不互見 PASS | 只限新 Lab |
| Oracle 斷線 `job_01M87R6DQZ00DTM963N9ZBQMS2` | `signed_get=503`、無狀態洩漏 PASS | 新映像 `9a010a3` |
| Oracle 恢復 `job_01M87RCBGP00FDZXWMNHWGB5CA` | 新合法合成 Session `200`、同請求重播 `403` PASS | 原 420 秒 Session 已自然過期 |
| Oracle SQL 計數 | 停機前後 Receipt `49→49`；恢復探測後 Receipt/Replay `51/51` | 中間一次過期 Session 的拒絕也原子記入 JTI |

本次 Oracle 應用映像 ID：`sha256:82d8e30ff38a991daa1b70f9eaec74c10debfe6f99d4153a3326d19313748f17`
（Arm64，`mirage-api:g3b-g4-20261125-9a010a`）；PostgreSQL **17.6**；
三個隔離網路前綴 `mirage-g3b-g4-stg-20261125-`，皆為 `internal=true`。
映像內的產品程式對應 Git 提交
[`9a010a3`](https://github.com/IAN40070510/Mirage_API/commit/9a010a3e9d184588b8797be048d96258adfebae1)；
僅測試探針後續修正，未重新建置產品映像。

**可簽收範圍**：這一輪 G3b/G4 的 Oracle 四服務隔離、持久資料庫角色
及故障拒絕／復原子案例；並非 G3b 完整 Client 原生回覆，也不包含
G4 真正外送、G5 BD-05 自動解禁、G6 混版／備份還原與最終 Owner Release。
因此所有正式 Gate 繼續 `OPEN`，正式 Trusted Send `OFF`、發布 `NO-GO`；
此處沒有虛構 Owner 或第三方安全簽核。
