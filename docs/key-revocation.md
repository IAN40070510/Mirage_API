# 可信簽章金鑰撤銷與輪替

## 用途與邊界

`PostgresTrustedKeyRevocations` 以永久墓碑停用指定部署內的 issuer／kid，讓已啟動且保留舊公鑰的新版 Mirage provider 也拒絕後續驗證。公鑰仍只來自固定部署設定；這個工具不從資料庫或 Token 下載、登記或信任新 key，也不保存簽章私鑰。

撤銷只控制新驗證，不追溯取消已驗證並進入業務或已起送的請求。WorldEvent 不回滾；Generation／Profile／Admission 有各自的控制邊界。舊 binary 若沒有接入這張墓碑，仍可能接受舊 key，因此不能把混合版本部署稱為全域撤銷完成。

## 輸入與輸出

建構子接受 Mirage 專用 DSN 與固定 environment_id／deployment_id。身份欄位須為非空、非純空白且最多 128 字元的字串。

| 介面 | 輸入及輸出 |
| --- | --- |
| revoke | issuer、kid、正整數 revision（最大 int64，不接受 bool）；提交後回傳 KeyRevocation。 |
| revocation | issuer／kid；新交易查墓碑，存在回傳版本，否則 None，儲存故障拋錯。 |
| guard | issuer／kid；持共享控制鎖至呼叫端 Replay 消費結束，只有 None 表示此控制邊界尚未撤銷。 |
| consume_guarded_replay | issuer／kid、Replay Store、audience／JTI／有效期；要求兩者 DSN 相同，在 Key 撤銷鎖與 Replay INSERT 同一實體連線／交易中完成，確認 COMMIT 後回傳撤銷或 Replay 結果。 |

控制域為 environment_id、deployment_id、issuer、kid。其他部署或另一 kid 不受影響。尚未設定的 kid 也能預先撤銷；日後加入設定仍會拒絕。版本只在同一墓碑內單調遞增，與 Session epoch、Profile revision 或 Replay 序列無關。沒有刪除、恢復或自動 GC API。

## 設定與管理範例

先套用 migrations 至 014，再啟用同版本 provider。`TrustedDeploymentSettings.build_provider` 自動注入此部署的共享墓碑及 Replay，不提供略過開關。直接建構 `TrustedSessionVerifier` 的舊測試／單程序原型仍可省略 guard；這種用法不能宣稱具備執行中撤銷。

```python
from deception.security.key_revocation import PostgresTrustedKeyRevocations

manager = PostgresTrustedKeyRevocations(dsn, environment_id="isolated-demo", deployment_id="isolated-demo")
state = manager.revoke("gateway", "retired-kid", revision=1)
current = manager.revocation("gateway", "retired-kid")
```

這是經授權管理程式的內部呼叫，不是對外 HTTP API。DSN、issuer、kid 與 revision 由管理者提供，不能由訪客 request 決定。換同名 kid 的公鑰不會清除墓碑；輪替須產生新的私鑰／公鑰與新 kid，不應把已洩漏 key 材料改名後重新信任。此墓碑按 issuer／kid 控制，不會自動搜尋所有公鑰別名或其他部署。

## 輪替步驟

1. 產生獨立新 key 與新 kid，私鑰只交給經授權簽發端。
2. 將新舊公鑰同時加入 Mirage 固定設定，重建所有 provider／Instance。單改磁碟檔不會熱載入新公鑰。
3. 分別驗證新舊 kid 都能通過，確認所有目標 Instance 已完成更新。
4. 由部署者讓簽發端改用新 kid；本工具不修改外部 Gateway 原始碼或啟用設定。
5. 明確撤銷舊 issuer／kid。已接入共享控制的執行中 Instance 不必重啟即可拒絕新舊 Token 中的該 kid。
6. 確認新 kid 可沿用同一 Session／世界、舊 kid 拒絕後，再從後續設定移除舊公鑰。保留墓碑，不以刪表作回復。

## 各節點白話功能

| 節點 | 功能 |
| --- | --- |
| 固定公鑰名冊 | 決定可驗哪個簽章；Token 不能自行新增 key。 |
| TrustedSessionVerifier | 先核對格式、部署、期限與簽章，再進共享撤銷邊界；撤銷拒絕不消費 Replay。 |
| key 控制鎖 | 驗證拿共享鎖、撤銷拿排他鎖；墓碑尚不存在時也能排定先後。 |
| trusted_key_revocations | 跨程序保存永久停用事實；重建 provider 或同名換公鑰不能復活。 |
| Replay | 在 key 共享鎖內以原介面原子消費 JTI；仍不允許同一授權重用。 |
| 入口稽核 | 對外固定拒絕，內部只記 trusted_ingress／unavailable，不記 kid、Token 或 JTI。 |

## 交易、失敗與恢復

控制器須使用同一可寫 primary／schema，autocommit=False、Read Committed。控制鎖以實際墓碑表 OID 與完整身份摘要區分；取得鎖與查墓碑是兩個 statement，避免使用等待前快照。Repeatable Read、Serializable 或 autocommit 明確拒絕。不能使用延遲副本或舊版程序宣稱撤銷有效。

若驗證先持共享鎖並消費 Replay，撤銷等待它完成；若撤銷先提交，後續驗證讀到墓碑後拒絕，JTI 不消費。獨立修補分支的 PostgreSQL provider 已把 **Key guard 與 Replay INSERT** 收斂為同一條連線／交易，任一寫入前錯誤或明確 rollback 均不可留下 Replay；COMMIT 回覆遺失時仍不能推定 JTI 未用。對不同 DSN 或非 PostgreSQL Replay Store 直接拒絕。**本階段尚未建立獨立可信 Ingress Receipt writer、受保護 DB 角色與完整 IngressTx**，因此不能把此局部改良稱為 `MIR-SEC-WORLD-001` 修復完成，也不可開正式發送。

連線期限 5 秒、控制 statement_timeout 5 秒，不代表整個 HTTP 操作的總期限。缺 migration、儲存不可達、鎖等待逾時或無法確定結果都停止新驗證，沒有記憶體空名冊降級。管理撤銷 COMMIT 回覆遺失只能用新連線查 revocation，不盲目重寫或自動升 revision。從撤銷前舊備份恢復會遺失新墓碑，正式恢復需另有可信安全基線，不能直接回滾即宣稱安全。

## 驗證方式

```powershell
python -m pytest tests/test_key_revocation.py tests/test_trusted_session.py tests/test_trusted_deployment.py -q
python tools/check_documentation.py
```

另以真實 TCP 代理丟棄**合併後單一 Ingress Key／Replay 交易**的 COMMIT 回覆：驗證必須拋錯，已提交 JTI 仍只一筆且後續拒絕重放；再測試 Replay INSERT 後故障的整筆回滾、Replay 禁止開第二連線、不同 DSN 事前拒絕。隔離映像的最後一項 opt-in 測試與停止寫入後的備份還原檢查見[運維說明](runtime-operations.md)。

## 授權與目前限制

自有程式 Apache-2.0，沿用 Python、psycopg、PostgreSQL 及 cryptography，沒有新模型、依賴或第三方撤銷程式；詳見[授權表](licensing.md)。目前沒有金鑰管理器、簽發端熱切換、管理身份授權系統、跨區恢復、DB 防竄改或自動保留政策。輪替測試不代表正式 Gateway 已設定或 staging 已切換。
