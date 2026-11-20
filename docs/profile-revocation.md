# Profile 整體撤銷

## 用途與邊界

ProjectionRegistry 與 PostgresProjectionRegistry 的 revoke_profile 停用精確的 Compatibility Profile SHA-256。墓碑獨立於個別契約，因此原契約、新契約、重新啟動的登錄程序都不能復活同一 Profile。這是 Mirage 內部管理介面，不是公開 HTTP API；管理身份與權限由上層部署管理程式負責。

撤銷範圍是同一 Registry 資料庫／schema 中該 Profile 的全部契約、Session 與部署，不是單 Session 停用。它不修改官方規格、世界快照、真實商店或庫存。需要不同撤銷域時應配置分離的 Registry。

## 輸入輸出

| 介面 | 輸入 | 輸出／副作用 |
| --- | --- | --- |
| revoke_profile | 小寫 64 位 hash、1 到 int64 上限的 registry_revision、真正 bool 的 emergency | 提交不可逆 ProfileRevocation；新增墓碑或提升版本，不允許緊急模式降級。 |
| profile_revocation | 精確 Profile hash | 等待先行撤銷交易後唯讀查墓碑；None 只表示此查詢時沒有墓碑，儲存故障不轉成 None。 |
| profile_guard | 精確 Profile hash | 狀態轉換使用的控制鎖，直到交易／原型鎖結束才釋放，不提供快取授權。 |

墓碑包含 compatibility_profile_sha256、registry_revision、emergency。只要墓碑存在就是已撤銷，emergency=False 不表示恢復有效。Profile、個別契約、Generation 的 revision 是不同序列，不互相比大小。尚無契約的 Profile 也能先設墓碑，禁止未來首次登錄。

## 一般與緊急模式

一般撤銷只阻止新 Grant、契約登錄及啟動登錄。撤銷前已取得的 Admission 保留原證據，可在原有期限內完成 Claim、Send Authorization 與發送，遵守 README 的 admission-scoped 政策。

emergency=True 阻止尚未 Claim 或尚未取得發送授權的回應，在下一控制邊界轉成 ABANDONED。Send Authorization 與緊急撤銷以同一 Profile 控制鎖排序：授權先提交時保留 SEND_AUTHORIZED 且撤銷不能追溯取消；撤銷先提交時授權拒絕。已授權的 start_send 不二次查墓碑，只核對 Claim owner、已提交狀態與 transmission_deadline。

SEND_STARTED 之後不假稱可以追回 bytes。發送者仍保存真實完成／失敗終態，不把已起送改寫成從未發送，也不宣稱客戶端已收到。一般模式不自動升級，管理呼叫端須明確指定緊急模式。

## 設定與使用範例

先依序套用 migrations 至 012，再啟動這個版本的 Registry 與 Admission 控制器。012 新增 projection_profile_revocations，保留既有契約／准入資料，不虛構歷史撤銷。所有參與 Instance 都須支援此協定；與忽略墓碑的舊版控制器混用時，不能宣稱緊急撤銷有效。正式部署與版本切換另行驗收。

```python
import os
from deception.world import PostgresProjectionRegistry

registry = PostgresProjectionRegistry(os.environ["MIRAGE_POSTGRES_DSN"])
profile_hash = reviewed_evidence.compatibility_profile.profile_sha256
normal = registry.revoke_profile(profile_hash, registry_revision=1)
urgent = registry.revoke_profile(profile_hash, registry_revision=2, emergency=True)
current = registry.profile_revocation(profile_hash)
```

reviewed_evidence 是管理端已審查資料，不從訪客 request 選取。上例是兩次明確管理動作，不是自動重試。相同或較小 revision 拒絕，緊急模式不能改回一般模式。恢復需審查新的 Profile hash 及世界相容性，不能刪墓碑或只換 revision 復活舊 Profile。

## 各節點白話說明

| 節點 | 功能 |
| --- | --- |
| 管理端 | 決定停用哪份已版本化投影，提供明確版本與模式。 |
| Profile 控制鎖 | 授權、登錄及發送邊界拿共享鎖；撤銷拿排他鎖，墓碑不存在時也能排序。 |
| PostgreSQL 墓碑 | 持久保存停用事實，程序重建不會遺忘。 |
| Grant／啟動登錄 | 查到任何墓碑就拒絕，不猜另一 Profile 或建立替代世界。 |
| Claim／發送邊界 | 查到緊急墓碑才取消尚未起送准入，一般墓碑保留原期限。 |
| 傳輸終態 | 保存已經發生的結果，不因後來撤銷而竄改歷史。 |

PostgreSQL 使用 mirage-profile 命名空間的 transaction advisory lock，不依賴墓碑列存在。Grant 保留 Profile 共享鎖與契約鎖直到交易提交；啟動批次按固定順序先取得所有 Profile 鎖。撤銷不逐一鎖住 Generation，避免大量世代互相等待。並行測試以 pg_blocking_pids 確認真正等待，不用 sleep 猜順序。

控制鎖另綁定實際墓碑資料表 OID，避免不同 schema 的同一 hash 互相阻塞。撤銷控制輸出准入，不回滾先前或並行已提交的 WorldEvent；業務授權仍由 Session／Generation 與事件交易負責。

所有控制器必須連到同一可寫 primary 的同一 schema，使用 autocommit=False 及 Read Committed；不支援以延遲副本判斷撤銷。控制方法遇到 autocommit 或 Repeatable Read／Serializable 時明確拒絕，不偷偷更改操作者設定。取得控制鎖與讀墓碑必須保留為兩個 SQL statement：Read Committed 的後一個 statement 才能看到等待期間提交的撤銷；較高隔離級別可能一直保留舊快照。依據見 [PostgreSQL 16 交易隔離](https://www.postgresql.org/docs/16/transaction-iso.html)。唯讀備份比對使用 Repeatable Read 是另一用途，不作授權判斷。

## 失敗處理與驗證

格式錯誤在連線前拒絕；版本倒退、緊急模式降級或重用已撤銷 Profile 拋出 ProjectionRegistryError。啟動批次含撤銷 Profile 時全批回滾。缺少 012、連線中斷或無法判定時停止新授權，不回退到記憶體空名冊。

COMMIT 回覆遺失不表示未提交。管理端只能用 profile_revocation 查回狀態，不盲目重寫或自動提高 revision。測試以真實 TCP 代理丟棄 COMMIT 成功回覆，再用新連線查墓碑；不知道結果時不假稱成功或未發生。

```powershell
python -m pytest tests/test_profile_revocation.py -q
python tools/check_documentation.py
```

PostgreSQL 案例需專用 MIRAGE_POSTGRES_TEST_DSN，允許建立及清理隔離 schema；未設定的 skip 不算通過。記憶體版本只是單程序原型。邏輯備份保留墓碑的隔離驗證見[運維說明](runtime-operations.md)；尚未涵蓋舊版 binary 混合部署、跨區分區、管理身份系統、正式墓碑保留政策或自動遷移。

## 套件／模型授權

自有程式採 Apache-2.0，沿用 Python、psycopg 與 PostgreSQL，不引入新套件或模型，未複製第三方撤銷實作。完整授權見[授權表](licensing.md)。
