# MIR-SEC-WORLD-001 — 權威證據與一次性綁定矩陣

**v0.1／Proposed／OPEN**。此表描述**擬議的安全來源與資料庫約束**，不是當前 DB Schema 已具有的欄位或 Role。既有程式與新設計必須區分。

| 證據或狀態 | 現有／擬議來源 | 誰可寫入（目標） | 授權語意與不可採信的捷徑 |
| --- | --- | --- | --- |
| 原始 Trusted Session JWS | Gateway／可信簽發者；現有 `trusted_session.py` 驗證 | 只有簽發者能產生有效簽章 | Verifier 必須驗簽章、audience、issuer、scope、時間；Runtime 自稱 passed 不算 |
| Trusted Key Registry／Key Revocation | 獨立部署金鑰政策／`key_revocation.py` | Owner／Control；Runtime 無權修改 | `issuer,kid` 是查核索引，不等於金鑰材料身分永遠不變；Rotation ≠ Revocation |
| Session Head／epoch | `session.py` 的可信 Session Mapping | 特權 Session 控制介面 | 不可倒退、不可任意跳躍；StartSend 必須比對 Receipt 綁定的**完整 scope**與最新 Head |
| Replay Tombstone | 既有 `replay_entries` 已消費 `(issuer,audience,jti)` | Verifier IngressTx | **只能證明消費**；不單獨證明驗章成功；未消費 Token 沒有此表列 |
| **Ingress Receipt（擬議）** | 獨立可信 Verifier 驗證成功後在 IngressTx 建立 | Verifier 受限 DB Role | 歷史 verified claims、原始時間、request fingerprint、驗證政策版本、金鑰身分；必須與 Replay 同 DB 交易 |
| Request Observation／Domain & Contract Validation | `trusted_http.py`／`request_audit.py` | Runtime；原本的觀察與結果 | **低信任 Audit**，不可因存於 DB 就成為獨立授權根 |
| Candidate＋Envelope v1 | `transmission.py` 的固定 status、headers、body bytes | Runtime 可提出，受保護儲存不可改；GC 特權清除 | Hash 必須核對完整 Envelope、版本、Scope、request fingerprint、Generation、Projection；允許 INSERT ≠ 允許自授權 |
| **Grant Binding（擬議）** | GrantTx 讀可信 Receipt 與實際 Candidate | Authorizer 受限 Role | 同一 Receipt 最多對應一筆有效 Admission；Grant Binding＋Admission 必須同交易；Binding 生成後不可換 Candidate／Generation |
| ResponseAdmission | `models.py`、`postgres_admission.py` | Authorizer／StartSend 受限操作 | 僅受保護狀態機能進入 SEND_AUTHORIZED／SEND_STARTED；Runtime 不能直接 DML |
| Generation Control／Profile Revocation | `generation_controls`、`projection_registry.py` | 獨立特權角色 | Authorize 與 StartSend 都要重新讀取最新控制狀態；不只信任 Grant 歷史快照 |
| World Snapshot expiry | `WorldSnapshot.expires_at`／`world_snapshots` | World 受保護交易 | 現有此欄；**不得等同假定 Generation 專有 expiry 已存在** |
| Operation Receipt／World Commit Result | `commit-results.md` 既有結果與擬議特權操作 Receipt | 對應交易負責角色 | 回答「該操作是否已提交／業務是否已執行」，**不**代替 JWS 驗證或 Admission 成功 |
| Response／Security Audit | `response_audit` 與擬議 pre-send 安全事件 | 特權轉移函式／稽核 writer | 發送前 Content Mismatch 應原子與 ABANDONED 保存；不得寫假的 send_started |

## ID 及約束合約

| ID | 對應生命週期 | 建議唯一性／綁定 |
| --- | --- | --- |
| `jti` | 一次 Token 消費 | `(issuer,audience,jti)`，必要時納入 environment/deployment 的 Scope，核對實際 Schema 與 policy |
| `receipt_id` | 一次可信 ingress 驗證 | 全球唯一或 Scope＋ID 唯一；唯一有效 Grant Binding |
| `operation_id` | 一次**特定** DB 操作與結果對帳 | 必須在副作用前有可重建關聯；重複 ID 與不同 digest 直接拒絕；ID 不是權限 |
| `admission_id` | 一個授權／傳輸生命週期 | 不可重新綁其他 Receipt 或 Candidate；所有查詢要納入完整權威 Scope |
| `candidate_id` | 一份固定候選封套 | 可用現有 scoped ID；不可因相同 body 就視為同一授權，受保護 hash／Scope／版本不可變 |

## Ingress → Grant 的時間順序

1. Verifier 驗原始 JWS／請求，將完整 Claims 摘要、deployment、Session、epoch、request fingerprint、意圖、驗證 policy/key identity 保存進 Receipt；同 IngressTx 插入 Replay 墓碑。
2. Candidate 在後續流程生成；此時才有可驗證的 Envelope v1 hash。**不能在 Ingress 階段聲稱已有尚不存在的 Candidate Hash。**
3. GrantTx 在一個 PostgreSQL Transaction 中鎖定 Receipt 與 Candidate，讀取當前 Session／Revocation／Generation，建立一次性 Binding 與 Admission；任一步失敗整筆 rollback。
4. AuthorizeTx／StartSendTx 後續只沿同一 Binding 與 Receipt 重新查核**當前**權威狀態；不得接受 Runtime 提供替代 issuer/kid/session/epoch。

**關鍵語意**：Receipt 已綁定**目前** Admission 是正常後續使用；只有綁定另一個 Admission 或不符合目前安全條件才是拒絕原因。Grant 失敗不恢復已消費的 JTI；合法重試需要新的、完整合法的請求與 JTI。

## 一致性、時間與來源認證分層

- **密碼學／來源證明**：Verifier 自己核驗 JWS 與請求；只有欄位完整不代表簽發者可信。
- **DB 寫入主體證明**：只有 Verifier Role 能建立 Receipt＋Replay；Schema/Role/ACL/SECURITY DEFINER 不能把 Runtime 自填 claim 提升為可信來源。
- **狀態轉移證明**：Grant Binding、Admission、一致性鎖、Revocation、deadline 經受保護 DB 交易強制。
- **發送快照證明**：Envelope v1 與送入 ASGI 的應用層快照一致，不延伸宣稱 TLS 或 Client exactly-once delivery。

## 來源證據

- [Trusted Session 驗章與 Replay](../../trusted-session.md)；[`src/deception/security/trusted_session.py`](../../../src/deception/security/trusted_session.py)
- [Key Revocation](../../key-revocation.md)；[`src/deception/security/key_revocation.py`](../../../src/deception/security/key_revocation.py)
- [Request Audit](../../request-audit.md)；[`src/deception/world/request_audit.py`](../../../src/deception/world/request_audit.py)
- [World Runtime](../../world-runtime.md)；[`src/deception/world/models.py`](../../../src/deception/world/models.py)
- [World Commit Result](../../commit-results.md)；[`src/deception/world/transmission.py`](../../../src/deception/world/transmission.py)

原始碼核對基準：`88dc2008fd35a2d3873949a769653dc9f18e8980`；以上文件的「擬議」段落尚無執行證據，請勿將它們標示為 PASS。
