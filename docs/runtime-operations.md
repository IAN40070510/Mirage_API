# Runtime 封裝與資料庫更新

## 用途與邊界

## 輸入、輸出與範例

在本機專案根目錄執行：

封裝輸入為固定目錄白名單及可選的文件字串替換；輸出為工作區內的 tar.gz 與逐檔 SHA-256 manifest。只替換 Markdown，不改原始碼或設定的 bytes。排除 `.git`、虛擬環境、產物及模型權重，拒絕 symlink、憑證副檔名與 PEM 私鑰標記。原封存只有在新封存完整建立後才被替換。這些規則不能取代人工檢查：上傳前仍須檢查 manifest 與設定檔是否含業務機密。

每次使用封存時，應先核對 archive_sha256，再解封至依該 hash 命名的全新目錄，禁止覆蓋先前已送給 Docker 的 context。封存採固定檔案時間；覆蓋解封時若等長原始碼的時間也相同，Docker 增量傳輸可能誤用先前快取。本輪已實際遇到此情況，改用全新 context 後重建，並以映像內已安裝模組的原始 bytes SHA-256 對照 manifest。映像建置成功本身不足以證明最後變更已包含。

migration 工具從環境變數 `MIRAGE_POSTGRES_DSN` 讀取連線設定，不輸出 DSN。依檔名順序套用 `migrations/*.sql`，回傳已套用版本名稱；已完成者不重複執行。schema 專用 advisory lock 與版本雜湊保護同時執行；既有 SQL checksum 不符時停止，不能直接改寫已部署 migration。

## 失敗處理

封裝失敗移除 `.partial`，保留先前封存；缺檔、敏感檔或間接路徑會報錯。資料庫不可達、SQL 錯誤或 checksum 漂移時 migration 交易回滾。工具不會修復身份、重建世界或啟動 Gateway。

## 驗證方式

```powershell
python -m pytest tests/test_runtime_packaging.py -q
python tools/check_documentation.py
```

第二項 migration 測試需要專用 `MIRAGE_POSTGRES_TEST_DSN`；未設定時跳過不能視為資料庫驗收成功。封裝程式在本機執行；SSH 模式只透過授權隧道使用 Ubuntu 的隔離資料庫，與 staging 分開。

已建置映像的交易驗收為 `python -m pytest tests/test_container_runtime.py -q`。必須明確設定 `MIRAGE_CONTAINER_TEST_ORIGIN`、`MIRAGE_CONTAINER_TEST_KEY_FILE` 與 `MIRAGE_POSTGRES_TEST_DSN`；私鑰檔為本機臨時產生的 Ed25519 raw 32 bytes，只供測試簽章，不傳到容器。容器公開設定的 kid 為 acceptance、issuer 為 gateway、audience 為 mirage，並採隔離展示部署 ID。測試使用隨機 Session 寫入合成購物車與訂單；專用資料庫及容器由建立它們的驗收流程清除，禁止使用正式環境執行。這項測試證明封裝入口與交易可運作，正式 Gateway 部署與 TLS 設定須另外驗證。

容器建立完成不代表服務已就緒；驗收前先確認 Docker health=healthy 且指定 origin 的 `/healthz` 回 200，再開始寫入測試。啟動期間的連線拒絕／重設應保留為環境失敗紀錄，不將測試內的簽章或交易操作自動重試。

第三個容器案例另須 `MIRAGE_CONTAINER_PROFILE_REVOCATION_TEST=true` 及原生公開 key 設定；它會永久撤銷整個原生 Profile，必須使用可丟棄的獨立資料庫，不能在其他正向測試仍需使用的 DB 執行。測試核對新原生准入被拒絕，而已允許的合成投影仍讀同一世界。

第四個案例須 `MIRAGE_CONTAINER_KEY_REVOCATION_TEST=true`；它最後永久撤銷 acceptance 簽發 kid，之後該 key 不能再作正向驗收。只在可丟棄 DB 執行，且放在所有正向案例之後；核對撤銷拒絕不新增世界、Replay 或准入，並保存固定入口稽核。

## 隔離邏輯備份還原

還原完成後，設定 `MIRAGE_BACKUP_RESTORE_TEST=true`、`MIRAGE_BACKUP_SOURCE_TEST_DSN` 及 `MIRAGE_BACKUP_RESTORE_TEST_DSN`，執行 `python -m pytest tests/test_database_restore.py -q`。測試要求不同 DB 名稱與相同 schema，以唯讀一致快照比對所有表的列數及完整資料摘要，確認世界、事件、提交收據、兩種稽核與 Profile／key 墓碑非空，並重新驗證快照完整性及撤銷拒絕。完整性檢查不延長已到期 lease，也不重新授權世界。

這是同一隔離 PostgreSQL cluster 的停止寫入後邏輯還原證據，不能推論 PITR、跨區災難復原、正式 RPO／RTO 或秘密恢復。回復到撤銷或 Replay 記錄產生前的舊備份，會遺失較新的安全事實；正式恢復需要可信的外部撤銷／epoch 基線與完整恢復程序，不能只啟動舊備份即宣稱安全。

## 授權與目前限制

自有程式採 Apache-2.0。Python 標準庫與 psycopg／PostgreSQL 授權見[授權表](licensing.md)，未採用第三方封裝專案程式或模型。尚未包含秘密管理器、完整機密掃描、正式災難恢復與部署協調；封裝成功不代表已上傳、已部署或 Protocol v1.1 符合性通過。
