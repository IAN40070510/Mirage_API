# MIR-SEC-WORLD-001 — 威脅能力與控制覆蓋

**v0.1 — Proposed**。舊 T1／T1.5／T2 只是對話簡稱，正式 ADR 使用可直接測試的能力 R1–R5。

| 能力 | 最強假設 | 本輪安全主張 |
| --- | --- | --- |
| R1 | 能使用 HTTP Runtime DB 憑證發出所有該 Role 允許的 SQL，不能取得獨立 Verifier／Authorizer Secret | **必須抵抗**直接建立／更新受保護 Receipt、Replay、Epoch、Generation、Admission、Key Revocation |
| R2 | 藉 SQL Injection 取得 R1 等價 SQL 能力，但不能完整控制 HTTP 程序 | DB 安全測試**等同 R1**；仍須應用端輸入驗證與參數化查詢 |
| R3-A | 可任意呼叫**合法** Verifier API 與提供惡意輸入，沒有 Verifier 特權憑證 | 必須拒絕錯簽章、錯 Scope、錯 request fingerprint、已撤銷或 replay Token，不能接受 Runtime 提供的 verified flag |
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
| Session／Key／Profile／Generation 現時查核 | 必須有效 | 必須有效 | 視取得身分 | 無法回收已送出的 bytes |
| Restore Quarantine／外部安全錨點 | 降低 DB 還原後錯誤放行 | 不直接涉及 | 部分 | 主機或控制面被控制無完整保證 |
| connection limit／timeout／reserved connections | 可降低阻斷面 | 不直接涉及 | 部分 | **可用性措施，不是單獨的安全隔離保證** |

## 部署驗收不能以單一 Role 名稱代替

同時確認 `SESSION_USER`／`CURRENT_USER`、`has_table_privilege`／`has_function_privilege`／`pg_has_role`、`rolinherit`／`rolbypassrls`／`rolsuper`、`pg_hba.conf`／網路來源、容器掛載與 Linux UID、DSN／Pool 重用、特權 Role 是否可 `SET ROLE`、credential rotation 後舊連線是否仍可操作。

`SESSION_USER` 是認證連線身分，`SECURITY DEFINER` 執行期間 `CURRENT_USER` 可能變成函式 owner；兩者不可混作來源認證。Role 檢查必須在**真正 Runtime SCRAM 登入連線**中完成。

主機 root、Docker daemon 或具等效控制能力的程序可突破同主機 File/Socket/Container Secret 隔離；不能用 `pg_hba.conf` 單一規則宣稱服務不可偽冒。

安全事故處理：無法透過 DB 自動強制的 Secret 外洩、主機控制、掛載錯誤，須由部署監控／人工判定觸發 production 發送 OFF、憑證撤銷或輪替、隔離、證據留存和重驗證。
