# MIR-SEC-WORLD-001 — 架構決策歷史與審查修正

**Consolidated v0.2 — 2026-11-21；Architecture Proposed／Weakness OPEN／MSDSS P2 NO-GO。** 本表於同一文件分支依次 Commit，保留 v0.1 歷史。

本紀錄把先前多輪對話中的**結論、假設、已否決方向、仍待 Owner 核准的決策**整理為可版本控制的狀態；不是把每則聊天當作已正式簽核的會議紀錄。完整決策權屬於 [ADR](../../adr/MIR-SEC-WORLD-001-world-db-trust-boundary.md) 指定的 Mirage Owner／DBA／Security。

## 已固定為 ADR 提案的方向（不等於已實作）

| ID | 設計結論 | 原因／邊界 |
| --- | --- | --- |
| D-01 | 缺口正式識別 `MIR-SEC-WORLD-001`；MSDSS P2 是外部驗收代號 | 避免將專案階段號重複用作跨專案安全缺口 ID |
| D-02 | 選方案 B：DB／窄特權角色強制關鍵狀態轉移 | R1 Runtime DB 身分能繞過應用程式狀態機，不能以程式自行守規矩當成 DB ACL 保證 |
| D-03 | 依 R1–R5 能力矩陣定義攻擊者；等價 SQL Injection 歸 R1 能力 | 不用攻擊名稱重複計算相同 DB 能力；R4/R5 另案 |
| D-04 | Runtime、Verifier、Authorizer 用分離 DB 身分、DSN／連線池、秘密與來源 | 不在低信任 Pool 使用 `SET ROLE`；同容器／同 Module 不自動代表可信隔離 |
| D-05 | `domain_validation='passed'` 與 `contract_validation='passed'` 是 Runtime 輸入／稽核資訊 | 不能從一個 DB 字串推得密碼學驗證來源 |
| D-06 | Verifier 必須自己驗原始 JWS、Claims、部署綁定、Session、Revocation、Replay | Runtime 不得自填 `verified`、issuer、policy、時間或 Receipt 核准結果 |
| D-07 | `replay_entries` 防重放，Receipt 證明驗證、Binding 控制一次使用、Operation Receipt 控制對帳 | 四者證明不同主張，不能互相代替 |
| D-08 | 同一 PostgreSQL IngressTx 原子消費 JTI 並建立可信 Receipt | 不承諾跨 DB 原子性；已消費 JTI 不因後續 Grant 失敗而重新開放 |
| D-09 | **IngressTx** 先建立 Replay Tombstone＋Receipt；**GrantTx** 僅鎖定並檢查既有 Receipt／Candidate／Generation／撤銷，原子建立唯一 Binding＋Admission，**不重新建立 Receipt** | 修正 v0.1 不精確措辭；兩階段在不同交易提交，不能假裝同一建立交易 |
| D-10 | 授權使用 Envelope v1 的實際應用層 bytes，Candidate 受保護不可改 | Hash 不證明 ASGI／TLS 客戶端實際收到；任何後置內容變動使 Admission 失效 |
| D-11 | AuthorizeTx／StartSendTx 用 Receipt/Binding 身分作當前 Epoch、Key、Profile、Generation 的動態查核 | Receipt 是歷史驗證事實，不是永久授權；同一 Receipt 已綁當前 Admission 並非重放 |
| D-12 | 不要求「整個 HTTP 請求單一交易」；僅要求「每個安全狀態轉移單一交易」 | World Commit／外部 side effect 與 Admission 分階段，有故障不一致，需對帳 |
| D-13 | Operation ID＋Input Digest 供唯讀 reconciliation；COMMIT 未知不得盲目重試 | 查無 Receipt 無法排除仍在途或未知提交；不得用逾時推定失敗 |
| D-14 | 不擴張 Admission State 表達稽核原因；失配前使用 `ABANDONED`＋原子 audit | SEND_STARTED 之後不能假設沒發送，不自動重送 |
| D-15 | 既有 `pg_advisory_xact_lock` 是交易級；重構需保留鎖鍵相容 | 不把它當 Session-level；不得在鎖鍵不相容時混跑新舊版 |
| D-16 | Restore 時 Fail-Closed Quarantine，不靠單純還原 DB 取得安全性 | Replay／Revocation／Epoch 舊狀態可能倒退；須核實舊 Token 全部無效才解禁 |
| D-17 | DB ACL 與 SECURITY DEFINER 都要真實 PG 負面測試 | 不能以 superuser fixture 或 13 項「成功重現」測試宣稱缺口修復 |
| D-18 | Request Provenance 本輪採**語意 A**：JWS 與 Runtime 提交 Canonical Request 相符；不證明實際 HTTP 入口來源 | 語意 B 需可信 Gateway／入口證據，另案；後續 Binding 仍須同 Request Fingerprint |
| D-19 | Verifier 的 Verified Context 僅是內部不可變資料，**不是 DB 可獨立驗證的證明** | 來源可信性依真實驗章、受限 Writer Role、窄介面與秘密／網路隔離，不接受 Runtime 自填 verified JSON |
| D-20 | Ingress Key Revocation Guard、Replay Tombstone、Receipt 共用**同一 PostgreSQL DB／Physical Connection／Transaction Coordinator** | 現有 `trusted_session.py`、`postgres_replay.py`、`key_revocation.py` 各自連線，需要重構內部交易介面與 cleanup；禁止 Store 自行 commit |
| D-21 | Candidate Submission、Validation、Promotion、Binding 為**不同授權語意**；不強制新增 staging table | Authorizer 不信任 Runtime 自填 hash／Scope／驗證旗標；Promotion 對 bytes＋Policy Revision 原子固定，避免 Validation→Promotion TOCTOU |
| D-22 | Candidate Promotion 失敗不得留下半可信物件；GC 不能刪除受保護 Bound Candidate | 需檢查真正 FK／Row Lock／GC，不能只憑 Runtime 提交的 protected_refs 清單 |
| D-23 | `WORLD_COMMITTED_ADMISSION_UNAVAILABLE` 是跨交易 **Reconciliation Classification** | 禁止擅自加入既有 AdmissionState／World Commit Enum |
| D-24 | 正式發送 OFF 須有獨立強制、可驗證且 Restore 後不倒退的控制面 | `production DECEIVE OFF` 目前作為政策要求，不宣稱存在已驗證的全域功能開關 |
| D-25 | `VerifiedContext` 只作同一可信 Verifier 程序內部資料；Receipt DB 信任由實際驗章、專用 Role、ACL、受限 Writer 與受控交易建立 | 不以 Python 型別／序列化 claims JSON 作 PostgreSQL 安全證明；跨服務 Context 傳送需獨立認證與防重放協定 |
| D-26 | `NOINHERIT` 不能取代 Role Membership／`SET ROLE` 驗收 | PG17 `pg_auth_members` 的 `set_option`／`inherit_option`／`admin_option`、間接角色鏈、`PUBLIC EXECUTE`、schema `USAGE` 都須從真實 Runtime 身分檢查 |
| D-27 | 長耗時 Candidate Validation 可在交易外，但 Promotion 必須短交易、鎖版本並重核不可變 Evidence／目前政策 | 版本須由 DB 受保護生成，Evidence 綁 Scope／Envelope／Contract／Policy／Source／Validator；避免長交易持鎖阻礙 Emergency Revoke |
| D-28 | Policy Revision 更新不等於撤銷；Grant／Authorize／StartSend 需依受保護 Policy Authority 的有效／禁止新授權／撤銷規則查核 | 新版本不自動使舊版本失效；Revocation 在 Start 前已生效則拒絕，Start 後不回溯竄改發送事實 |
| D-29 | Candidate GC 首選完整 Scope FK／UNIQUE 加全域相容鎖，且區分短期 Payload 與必要的不可變稽核 Evidence | 既有 Candidate 使用 Scope＋candidate_ref；永遠 RESTRICT 有效 Binding 可能造成 Raw Payload 無限保留，需核准 Terminal／UNRESOLVED 保留窗口 |
| D-30 | Ingress rollback、JTI 已提交消費、未知 COMMIT 分開決定可否重試與是否須新 JWS | 確定 rollback 時原 JTI 未消費，同 JWS 可能可安全受限重試；已消費不得復活；未知 Commit 不得用換新 JWS 跳過對帳 |
| D-31 | Candidate→Binding／Admission 只是局部依存順序，不能在未盤點 Session Head／Generation／Admission／Key／FK 鎖前宣告全域安全 | 目前 Grant 先取 Generation，Session Resolve 先取 Head；要交付無循環 DAG 與對抗測試後才能訂總序 |

## 曾討論但明確拒絕的捷徑

| 提議／誤解 | 處理 | 理由 |
| --- | --- | --- |
| 將 World DB 直接改成原始 Assessment Ledger 的 EXECUTE-only | **拒絕照搬** | World Native 仍需正當 SELECT／INSERT／UPDATE／部分 DELETE，須分操作改造 |
| 獨立 Python Module 或多一張 Receipt 表就算新的信任根 | **拒絕** | 沒有隔離 Role、秘密、Verifier 的真實輸入驗證，Runtime 仍可偽造 |
| Runtime 的 `domain_validation=passed` 或 Replay Tombstone 即代表 Token 已可信驗章 | **拒絕** | 稽核／防重放不是來源認證 |
| IngressTx 一開始就強制 Receipt 包含未生成的 Candidate Hash | **修正為兩階段綁定** | Ingress 綁 request＋intent；Grant 以單交易綁真正 Candidate hash |
| 查無 Operation Receipt 五分鐘就改 `EXPIRED` 並直接重試 | **拒絕** | 時間經過不證明未知 COMMIT 已 rollback，可能造成重複副作用 |
| 暫時允許部分 Runtime 自宣告授權，靠限速或人工標記 | **拒絕** | 對 R1 的授權根仍不可信，不能當正式發送最小通路 |
| 還原後直接上傳新的公鑰就解除隔離 | **拒絕自動解禁** | 舊 Token／舊金鑰撤銷與全域身分切換尚未獲證 |
| 一律在 SECURITY DEFINER 中移除 `pg_temp` 就一定安全 | **校正** | 官方安全例示將 `pg_temp` 放末尾；搭配 schema-qualified 名稱、可信 schema、撤銷 PUBLIC CREATE/EXECUTE 與負面測試 |
| COPY FROM PROGRAM 只靠一般 EXECUTE 就能執行 | **校正** | 另須 superuser 或 `pg_execute_server_program` 類權限，須審核真實有效權限 |
| PostgreSQL 不寫 volatility 就預設 IMMUTABLE／parallel safe | **校正** | DML 函式宜顯式標示 `VOLATILE PARALLEL UNSAFE` 方便審計，但不應錯稱預設為 IMMUTABLE |
| Runtime 原地改 Admission Hash 後重新授權同 Receipt | **拒絕** | 破壞 Envelope 不可變與一次性 Binding；需新 Candidate＋合法新授權流程 |
| 讓 Runtime 直接提供 `request_fingerprint` 或「原始快照」便宣稱已證明實際 HTTP 入口 | **拒絕過度承諾** | 只能證明 JWS 與提交資料相符；外部來源需另有可信入口證據 |
| 在外層增加 `BEGIN`，但 Replay／Key Guard Store 仍自行開連線 | **拒絕** | 不同 Physical Connection 無法因外層 Python 區塊產生同一 PostgreSQL 原子交易 |
| 以 Python `VerifiedContext` 類別作為資料庫身分認證 | **拒絕** | Class／JSON 不是 DB 可信來源證明，需受保護 DB 身分與寫入介面 |
| 強制 Candidate 新增 staging table 作為唯一設計 | **不預先指定** | 可沿用既有儲存並加權限、Validator／Promotion 或受限函式；以安全驗收證據裁決 |
| Validation 已 PASS 就不再核對 bytes／Policy Revision，直接 Promotion | **拒絕** | 內容或政策可能在兩階段之間改變，需不可變證據及重新驗證 |
| `NOINHERIT` 等於沒有 `SET ROLE` 權限 | **校正** | `SET ROLE` 由 Role Membership 的 SET 選項與間接鏈決定，需實際 ACL／登入測試 |
| 規定所有 Candidate Validation 必須持鎖做完 | **拒絕一刀切** | 昂貴驗證若長期占鎖會影響安全撤銷可用性；應先驗不可變快照、在短 PromotionTx 查核證據與當前政策 |
| 只要有 FK RESTRICT，就能永久保留全部 Candidate 原始 bytes 而無需 GC | **拒絕** | FK 是參照完整性；需對 Raw Payload／稽核 Metadata 設分層保留，Active／UNRESOLVED 不能誤刪 |
| 任何失敗一律必須簽發新 JWS 再試 | **拒絕** | 明確 rollback 可在原 ID/digest 與政策下受限重試；已消費不復活、未知 Commit 不得以新 Token 規避對帳 |
| `SEND_STARTED` 表示 Client 收到，或網路失聯等於沒送 | **拒絕** | DB 起送、ASGI 嘗試、Socket 寫入與客戶端接收是不同事件 |

## 仍須正式裁決（不得隱藏成既定事實）

| 決策 | 提議／待評估選項 | 目前 |
| --- | --- | --- |
| Verifier 位置與信任根 | 獨立服務＋獨立 DB Role；若不同 DB 必須重做 Ingress 原子協定 | **OPEN** |
| Authorize／StartSend／Epoch／Revocation 的總鎖序 | 先盤點全部路徑並產生無循環圖，再定量測試 | **OPEN** |
| StartSend 期限政策 | `G=0` 嚴格 Token 未過期；或短、不可延長的已核准 Grace Window | **OPEN** |
| Candidate GC 與 Grant 互斥方式 | 完整 Scope FK＋Row Lock／受限 GC；須含保留分層、全域鎖 DAG 與並行測試 | **OPEN** |
| World Commit 成功但 Admission 無法取得 | API 可查回／at-most-once／可補償與對外回應 | **OPEN** |
| Replay／Receipt 保留、還原隔離與釋放條件 | 單機 Quarantine 與外部安全錨點／保守到期窗口 | **OPEN** |
| R4/R5 額外安全需求 | 分開威脅模型或正式殘餘風險接受 | **OPEN** |
| Request Provenance 語意 A 風險接受 | 若未來要求實際入口來源驗證，採語意 B 並另行威脅分析 | **OPEN（提案採 A）** |
| Candidate Validator 身分與 Promotion 具體交易 | 受控交易外 Validation／短交易 Promotion，DB 不可變版本、可信政策撤銷與版本相容規則 | **OPEN** |
| 正式發送禁用控制面 | 查明開關與 Credential／Restore／Runtime 權限，驗證 fail-closed | **OPEN** |

## 紀錄原則

每個後續決策需有：ID、日期、決策人、選項、來源 commit／PR、威脅能力、測試結果、殘餘風險與可回滾方式。**實作完成**、**測試通過**、**Owner 核准**與**安全弱點關閉**是四個獨立狀態。

**持續紀錄工作約定（本輪已獲使用者同意）**：每次與此 ADR 有關的討論形成新結論時，將可核對內容整合到**同一文件分支**，以新的 Git Commit／版本歷史保留修改理由；不重複建構平行文件，不以「合併討論紀錄」解讀為可合併 `main`、修改 staging 或啟用正式發送。尚未核准的選項必須標為 Proposed／OPEN，測試未執行仍是 NOT_RUN；未來新對話需由取得 Repo 權限的執行者實際提交，**不宣稱已有無人值守的跨會話自動化**。

目前無正式 Owner 簽核紀錄，請勿把本檔的「已固定提案方向」解讀成已核准進入 production。
