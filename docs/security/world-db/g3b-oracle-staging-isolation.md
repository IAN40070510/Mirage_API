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
  程式，避免硬編碼。`G3B_CI_HOST_PORT` 指向本次 Loopback 埠。
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
   恢復後以新憑證／一次性 Receipt 檢查無錯誤重試或雙重 Commit。
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
