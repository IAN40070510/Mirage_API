# MIR-SEC-WORLD-001 — 威脅能力與控制覆蓋

> 本文件以 Mirage 原生授權契約為維護範圍。歷史跨專案整合證據已移交保存，原生安全要求與驗收狀態維持原紀錄。

**v0.2 — Proposed**。舊 T1／T1.5／T2 只是對話簡稱，正式 ADR 使用可直接測試的能力 R1–R5。

| 能力 | 最強假設 | 本輪安全主張 |
| --- | --- | --- |
| R1 | 能使用 HTTP Runtime DB 憑證發出所有該 Role 允許的 SQL，不能取得獨立 Verifier／Authorizer Secret | **必須抵抗**直接建立／更新受保護 Receipt、Replay、Epoch、Generation、Admission、Key Revocation |
| R2 | 藉 SQL Injection 取得 R1 等價 SQL 能力，但不能完整控制 HTTP 程序 | DB 安全測試**等同 R1**；仍須應用端輸入驗證與參數化查詢 |
| R3-A | 可任意呼叫**合法** Verifier API 與提供惡意輸入，沒有 Verifier 特權憑證 | 必須拒絕錯簽章、錯 Scope、錯 request fingerprint、已撤銷或 replay Token，不能接受 Runtime 提供的 verified flag；合法 JWS 被搶先消費是另需緩解的可用性風險 |
| R3-B | 能讀取部分 Runtime 設定或 Secrets；具體內容取決於 OS/容器掛載 | 依取得的實際權限評估，強制 Secret 隔離、最小權限、洩漏監控及撤銷；不保證能自動偵測所有外洩 |
| R4 | 可任意執行 HTTP Runtime 程式碼，包含自行操作 ASGI send | 本輪**不承諾**阻止已受控 Runtime 自行發送；如需保證須獨立受信任 Sender 與傳輸邊界設計 |
| R5 | 能控制 Docker daemon、主機 root、DB superuser 或 Verifier 本身 | 不在本輪資料庫最小權限控制的保證範圍 |

## 控制覆蓋與殘餘風險

| 控制 | R1／R2 | R3-A | R3-B | R4／R5 殘餘風險 |
| --- | --- | --- | --- | --- |
| Runtime ACL 拒絕直接改 Admission、Generation、Session、Replay | 必須有效 | 間接 | 視實際憑證 | R4 可繞開正常應用發送；R5 可取得特權 |
| Verifier 獨立 Role／Secret／有效來源限制 | 必須有效 | 僅可呼叫窄 API | Secret 隔離才部分有效 | 若特權程序／主機受控則失效 |
| Verifier 真正重新驗章與 scope／policy | Runtime 自填證據無效 | **必須有效** | 視被竊密鑰類型 | 完整控制 Verifier 可偽造 |
| Replay＋Receipt 同交易與唯一 Binding | 必須有效 | 必須有效 | 視身分權限 | 不阻擋 Runtime 程序自行發送 |
| Candidate 不可改與 Envelope Hash | 必須有效 | 不直接涉及 | 不直接涉及 | 只能保障授權快照；不能防已受控 HTTP 直接發惡意 bytes |
| Session／Key／Profile／Generation 現時查核（**最終 Authorize COMMIT 前**） | 必須有效 | 必須有效 | 視取得身分 | Freeze v1 保留已完成 SEND_AUTHORIZED，StartSend 不重新做政策授權 |
| Snapshot Write-Once／GC Non-Retryable Fence | 必須由受保護 Role/DB Transition 強制 | 跨 scope 不能重用 | 外部 object 必須驗證固定 version/hash | R4 可自行用 ASGI 發未授權 bytes，R5 可繞過 DB／storage 保護 |
| Mixed Runtime Credential／Role Fence | 舊 Role 不得繼續 protected DML／EXECUTE；不同 Credential | 間接 | 憑證竊取需另行輪替 | 舊 Runtime 自填 protocol_version 不是身份證明 |
| 外部 Effect Key／Restore Quarantine | 新 Epoch 不重置原本外部 Key；不自動重做已提交效果 | 間接 | 需獨立外部系統對帳 | 對外 exactly-once 不在本 ADR 保證範圍 |
| Restore Quarantine／外部安全錨點 | 降低 DB 還原後錯誤放行 | 不直接涉及 | 部分 | 主機或控制面被控制無完整保證 |
| connection limit／timeout／reserved connections | 可降低阻斷面 | 不直接涉及 | 部分 | **可用性措施，不是單獨的安全隔離保證** |

## 目標有效權限：Role × Read／Write／Execute／SET ROLE

以下是**須以真實 PostgreSQL 驗收的 Proposed Matrix**，不是目前已存在的 GRANT。表內「受限」代表只可經過審核、按完整 Scope、驗證資訊與狀態機的窄介面；不得用一般表級 UPDATE 取代。

| DB 身分 | Receipt 讀取 | Receipt INSERT | Receipt UPDATE／DELETE | Replay／Key Guard | Binding／Admission 轉移 | Candidate Submission／Promotion | SET ROLE／其他角色繼承 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `mirage_http_runtime` | 不可讀原始 Claims；僅必要去識別狀態 | **拒絕** | **拒絕** | 不得自行消費／GC／改寫 | **拒絕直接 DML**；僅准受限申請／結果查回 API | 只准提交**低信任** Candidate；不能 Promotion | **拒絕** |
| `mirage_ingress_verifier` | 自己的驗證結果／必要查回 | **限同一 IngressTx Writer** | **拒絕** | 同一交易 Key Guard／Replay Consume；不得任意 GC | **拒絕** | **拒絕** | **拒絕** |
| `mirage_authorizer` | 受限讀已提交 Receipt 與 Binding | **拒絕** | **拒絕** | 受限唯讀最新撤銷／Replay 關聯；無一般 DELETE | **受限 Grant／Authorize／StartSend 函式** | 讀可信 Promoted Candidate；無任意 Promotion | **拒絕** |
| Candidate Validator／Promotion Role（名稱待決） | 無需原始 JWS／Receipt Writer 權限 | **拒絕** | **拒絕** | **拒絕** | **拒絕** | **限可信驗證與 Promotion**；不可改既有 Promoted bytes | **拒絕** |
| `mirage_replay_gc` | 僅必要保留資訊 | **拒絕** | Receipt GC 僅經正式安全保留程序 | 僅可對逾期且不受保護的墓碑 GC | **拒絕** | 僅可依正式條件 GC | **拒絕** |
| `mirage_control_admin` | 必要稽核／狀態讀 | **拒絕** | **拒絕** | 受限 Key／Profile／Emergency Revocation | 只能走管理撤銷介面 | **拒絕 Promotion** | 不繼承 Runtime／Verifier／Authorizer |
| `mirage_schema_owner`（NOLOGIN） | Migration 所需 | Migration 所需 | Migration 所需 | Migration 所需 | 管理 Schema／函式；**不可常駐登入** | Migration 所需 | 不可供 Runtime 取得、登入或 SET ROLE |

**函式／Schema Owner 仍需 DBA 逐項裁決**：使用 `SECURITY DEFINER` 時，Definer Owner 應採 NOLOGIN 與足以完成該狹窄操作的最小權限；不得因單一 Owner 擁有整庫 DML 就讓所有特權函式變成通用寫入入口。必須撤銷不必要的 `PUBLIC EXECUTE`、Runtime CREATE、Role Membership，對所有 Function Signature／Overload 做有效權限測試。**`NOINHERIT` 不等於不能 `SET ROLE`**；PostgreSQL 17 的 `pg_auth_members.set_option`、`inherit_option`、`admin_option` 與間接 membership 鏈必須一起審核。Runtime 不得是 Verifier／Authorizer 成員，Verifier 不得切換成 Authorizer，Authorizer 不得取得 Receipt Writer 權限。

**時間／Scope／政策欄位**：所有角色都不得藉由直接提交任意 `now`、`issuer`、`kid`、`generation`、`trusted_hash`、`validation_result` 或 `policy_version` 取得不屬其身分的安全決策。Runtime 參數只能作核對輸入；真正權威資料應從保護表、可信 Context 或 DB 時間取得。

## 部署驗收不能以單一 Role 名稱代替

同時確認 `SESSION_USER`／`CURRENT_USER`、`has_table_privilege`／`has_function_privilege`／`has_schema_privilege`／`pg_has_role`、`rolinherit`／`rolbypassrls`／`rolsuper`、`pg_auth_members` 的 `SET/INHERIT/ADMIN` 選項與間接角色鏈、`pg_hba.conf`／網路來源、容器掛載與 Linux UID、DSN／Pool 重用、特權 Role 是否可 `SET ROLE`、是否錯誤允許 `SET SESSION AUTHORIZATION`、`PUBLIC EXECUTE` 與 schema `USAGE`、credential rotation 後舊連線是否仍可操作。

`SESSION_USER` 是認證連線身分，`SECURITY DEFINER` 執行期間 `CURRENT_USER` 可能變成函式 owner；兩者不可混作來源認證。Role 檢查必須在**真正 Runtime SCRAM 登入連線**中完成。

主機 root、Docker daemon 或具等效控制能力的程序可突破同主機 File/Socket/Container Secret 隔離；不能用 `pg_hba.conf` 單一規則宣稱服務不可偽冒。

安全事故處理：無法透過 DB 自動強制的 Secret 外洩、主機控制、掛載錯誤，須由部署監控／人工判定觸發 production 發送 OFF、憑證撤銷或輪替、隔離、證據留存和重驗證。

**合法呼叫不等於合理速率**：在 R3-A／語意 A 下，擁有合法 JWS 的惡意 Caller 可嘗試提前消耗 JTI。Verifier 入口須有 Caller 認證、Caller／Session／Scope 的總量防護、異常消費審計與受限重新簽發；單一 JTI 的限速無法阻止大量不同合法 JTI 的消耗。這些是可用性控制，不可宣稱已證明真實 HTTP 入口來源（R4）。

## Freeze v1 和資料庫身份界線（v0.2 文件提案）

**契約與驗收分離**。Mirage Protocol Freeze v1 由本 ADR 定義。Owner 採納見 D-68，native WORLD-PROTOCOL-01／02 的完整符合性以隔離測試核對，設計要求本身不構成已部署保障。

- `mirage_http_runtime` 的 `SESSION_USER` 只證明 DB LOGIN，不證明 Tenant／Claim Owner／部署版本。特權函式須沿 Ingress Receipt → Operation Identity → Subject/Scope → Binding 驗證，拒絕跨 admission/owner/scope 的參數越權；`SET LOCAL app.tenant_id` 或版本字串非安全證據。
- `SECURITY DEFINER` Owner 為獨立 NOLOGIN，可信 fixed search_path（pg_temp 最後），撤銷 PUBLIC EXECUTE、一般 Runtime 的直接 protected DML／membership／SET ROLE 能力。DB R1 防護不等於能阻止已被完全控制的 R4 HTTP Sender。
- Policy／Emergency／Epoch／Key **只在 SEND_AUTHORIZED COMMIT 前**可否決新授權；StartSend 只檢查 Snapshot／deadline／owner／single-use／Purge Fence。原 Candidate 已 Purge 但 Snapshot 完整不構成新撤銷。
- 真 PostgreSQL ACL／多 Backend／External Object／Restore／Mixed Binary 新測試一律 `NOT_RUN`；Mirage release `NO-GO`，production DECEIVE `OFF`。
