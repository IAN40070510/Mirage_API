# MIR-SEC-WORLD-001 — 權威證據與一次性綁定矩陣

**v0.2／Proposed／OPEN**。此表描述**擬議的安全來源與資料庫約束**，不是當前 DB Schema 已具有的欄位或 Role。既有程式與新設計必須區分。

| 證據或狀態 | 現有／擬議來源 | 誰可寫入（目標） | 授權語意與不可採信的捷徑 |
| --- | --- | --- | --- |
| 原始 Trusted Session JWS | Gateway／可信簽發者；現有 `trusted_session.py` 驗證 | 只有簽發者能產生有效簽章 | Verifier 必須驗簽章、audience、issuer、scope、時間；Runtime 自稱 passed 不算 |
| Trusted Key Registry／Key Revocation | 獨立部署金鑰政策／`key_revocation.py` | Owner／Control；Runtime 無權修改 | `issuer,kid` 是查核索引，不等於金鑰材料身分永遠不變；Rotation ≠ Revocation |
| Session Head／epoch | `session.py` 可信 Session Mapping | 特權 Session 控制介面 | 不可倒退；**AuthorizeTx 必須在 SEND_AUTHORIZED COMMIT 前**依受保護 Binding 查當前 Head；授權後 StartSend 不再二次查 Epoch |
| Replay Tombstone | 既有 `replay_entries` 已消費 `(issuer,audience,jti)` | Verifier IngressTx | **只能證明消費**；不單獨證明驗章成功；未消費 Token 沒有此表列 |
| **Ingress Receipt（擬議）** | 獨立可信 Verifier 驗證成功後在 IngressTx 建立 | Verifier 受限 DB Role | 歷史 verified claims、Canonically Submitted Request Fingerprint、驗證政策版本、金鑰身分；與 Replay **同 Database／Connection／Transaction**。語意 A 不等於真實 HTTP 入口來源已驗證 |
| Request Observation／Domain & Contract Validation | `trusted_http.py`／`request_audit.py` | Runtime；原本的觀察與結果 | **低信任 Audit**，不可因存於 DB 就成為獨立授權根 |
| **Candidate Submission（低信任）** | Runtime 提交 bytes／Scope／意圖 | Runtime 只能提交未授權輸入 | 不能自己提供權威 validation、trusted owner、promotion、authorization、Policy Revision；不論存在於 staging table 或既有 Store 都不得直接供 Grant 使用 |
| **Validated Candidate（擬議證據）** | Candidate Validator 檢查 Envelope v1 與核准 Policy／Projection／Source | 可信 Validator 受限 Role | 以 DB 生成的不可變 Candidate Version 綁定 bytes／Envelope hash、完整 Scope、Contract hash、Policy Revision、Source Spec SHA-256、Validator Identity／Algorithm／Timestamp；若跨程序信任邊界還要認證證據來源。**內容完整性不等於安全政策核准** |
| **Promoted Candidate（擬議）** | 受保護 Promotion 操作 | 可信 Validator／受限 Promotion Role | 在**短交易**固定已驗證 bytes／Scope／版本；若昂貴驗證在鎖外完成，Promotion 必須先鎖同版記錄、重核 Evidence／目前 Policy Authority 狀態，失敗不留下半可信資料 |
| **Bound Candidate（擬議）** | GrantTx 使用 Promoted Candidate 與可信 Receipt | Authorizer 受限 Role | Binding＋Admission 同交易；Receipt 不可被第二個不相容 Candidate／Admission 重用，GC 不得刪除有效 Binding 引用的資料。**擬議 FK 必須包含完整 Scope＋DB 生成、不可變的 Candidate Version**；現有 Store 只有五欄 scoped 主鍵，版本欄待正式 Migration |
| **Grant Binding（擬議）** | GrantTx 讀可信 Receipt 與實際 Candidate | Authorizer 受限 Role | 同一 Receipt 最多對應一筆有效 Admission；Grant Binding＋Admission 必須同交易；Binding 生成後不可換 Candidate／Generation |
| **Operation Identity**（擬議） | protected namespace／operation record | 窄特權 Operation Writer | `UNIQUE(namespace,epoch,id)`，Digest/algorithm/external_effect_key Write-Once；不能信 Runtime tenant、SESSION_USER；同 ID 不同 Digest 拒絕 |
| **Snapshot Proposal／Pin**（擬議） | 首次持久化 Proposal＋固定 Object id/version/hash | 受限 Snapshot Preparer | Proposal 未持久化不得宣稱已固定內容；外部 I/O 不持核心 DB row lock；同 operation 不可改選 |
| **Authorized Snapshot**（擬議） | 完整 Envelope v1 bytes、immutable id/version/hash | 受限 Snapshot Writer／Reader | status、ordered headers、body bytes；非 TCP hash；原 Candidate Purged 不影響此 Snapshot；Snapshot Purged 則不可起送 |
| **OperationSnapshotBinding**（擬議） | operation id UNIQUE 與 Admission/Scope/Generation | 受限 Authorizer | 不同 id/version/hash/encoding 為 SNAPSHOT_BINDING_CONFLICT；授權時鎖並引用已提交不可變 Binding；START 只能用該 Snapshot |
| **Snapshot Purge Fence／Tombstone**（擬議） | 不可重試旗標、不可重用 Candidate Logical Key 與 Snapshot 保留稽核 | 受限 GC／控制介面 | 先持久化 fence 禁新 StartSend；Active Sender 保留 snapshot 至受控中止；保留安全必要 Scope/Version/hash/operation/effect key，敏感 bytes 到期安全刪除。Tombstone 位於同一可還原 DB 時仍會倒退，必須與 Restore Quarantine／可信恢復錨點共同驗收 |
| **Authorized Snapshot execution eligibility**（擬議獨立狀態） | `AVAILABLE`／`PURGE_PENDING`／`PURGED`／`CORRUPT`／`UNAVAILABLE`；只描述**已綁定 Snapshot** 的發送執行資格 | 受保護 Snapshot GC／Integrity Writer；Runtime 不可自填 | Candidate 原始 Payload Purged 不等於 Snapshot 不可起送；Snapshot 的不可逆 Fence 禁新起送但不抹除 SEND_AUTHORIZED；`PURGED` 不復活、`CORRUPT` 需可信 Hash 失配證據、暫時 UNAVAILABLE 不可假裝永久刪除；保留 identity/hash/reason/DB time；`WORLD-PURGE-BOUNDARY-01` NOT_RUN |
| **Restore Anti-Rollback Anchor**（擬議、未選型） | World DB 還原範圍外之 Fence ID／Namespace／單調世代／DB timeline + covered position／canonical coverage manifest digest／previous hash／created_at／authenticated checkpoint，另有不可回播的最高受信任 Head | 獨立受保護恢復權威／DBA＋Security，**不是 Runtime、不是還原後的 World DB** | Hash-chain 及簽章若缺可信最新 Head 仍可整條回播；必須驗證資料表／事件種類覆蓋完整且由獨立權威建立。只看還原庫 Tombstone 是否存在、單獨 LSN／時間戳或候選 Identity version 不構成防回退。缺證 Quarantine；BD-05 OPEN，`WORLD-RESTORE-FENCE-01` NOT_RUN |
| **External Effect Receipt**（擬議） | 外部服務／業務操作的真實對帳證據 | 可信副作用執行者或正式 reconciliation | Epoch 更新不證明外部副作用 rollback；不得自動換 Key 重執行 |
| ResponseAdmission | `models.py`、`postgres_admission.py` | Authorizer／StartSend 受限操作 | 僅受保護狀態機能進入 SEND_AUTHORIZED／SEND_STARTED；Runtime 不能直接 DML |
| Generation Control／Profile Revocation | `generation_controls`、`projection_registry.py` | 獨立特權角色 | Policy/Emergency 與授權在同一受保護交易競爭；**只有 AuthorizeTx 重查**，授權後 StartSend 不回溯撤銷 |
| World Snapshot expiry | `WorldSnapshot.expires_at`／`world_snapshots` | World 受保護交易 | 現有此欄；**只有匹配同一 Admission 所綁完整 Session／Generation／Scope，且由受保護交易查得**，才可作 Transmission Deadline 上限；不是假定的 Generation-expiry |
| Operation Receipt／World Commit Result | `commit-results.md` 既有結果與擬議特權操作 Receipt | 對應交易負責角色 | 回答「該操作是否已提交／業務是否已執行」，**不**代替 JWS 驗證或 Admission 成功 |
| Response／Security Audit | `response_audit` 與擬議 pre-send 安全事件 | 特權轉移函式／稽核 writer | 發送前 Content Mismatch 應原子與 ABANDONED 保存；不得寫假的 send_started |
| Policy Authority／Revision（擬議受保護狀態） | 受保護 Policy Authority | Owner／Policy Control，Runtime 無權改寫 | ACTIVE／NO_NEW_GRANTS／REVOKED；NO_NEW_GRANTS 禁新 Grant、既有 Grant 可在其他條件有效時 Authorize；REVOKED 拒絕新 Grant/Authorize，**不回溯**既有 SEND_AUTHORIZED；REVOKED 不回 ACTIVE |
| Candidate Payload Retention（擬議 GC 合約） | `CandidateEvidence`／`CandidatePayload`／`AuthorizedSnapshot`／Purge Tombstone | 受限 GC／Owner Retention | 原 Candidate Purge 不使已授權且完整的 Snapshot 失效；Snapshot Purge 須先不可重試 Fence、確認活躍 Sender 終態／安全中止，再刪 bytes；完整 Scope/Version/FK/Pin 決定 GC，不依 Runtime protected_refs |

## ID 及約束合約

| ID | 對應生命週期 | 建議唯一性／綁定 |
| --- | --- | --- |
| `jti` | 一次 Token 消費 | `(issuer,audience,jti)`，必要時納入 environment/deployment 的 Scope，核對實際 Schema 與 policy |
| `receipt_id` | 一次可信 ingress 驗證 | 全球唯一或 Scope＋ID 唯一；唯一有效 Grant Binding |
| `operation_id` | 業務 Operation Identity／外部副作用對帳 | `UNIQUE(authority_namespace,namespace_epoch,operation_id)`；單一 immutable Digest 與首次 external_effect_key；不同 Digest 衝突；Namespace Epoch 不能改外部 key 或復活舊操作 |
| `authority_namespace + namespace_epoch` | 可信業務命名空間與 Restore Fence | 由受保護身分及 Quarantine／部署控制取得；epoch 不能藉 Runtime 自填變更或清除舊外部副作用 |
| `external_effect_key` | 一次原始業務副作用的外部冪等鍵 | 首次 Operation Identity 固定；新 epoch、retry、新 JWS 不產生替代 Key |
| `snapshot_id` | 一次不可變應用層回應 Snapshot | 與 Operation/Admission、Scope、Candidate version、encoding version、payload pin 一起 Write-Once |
| `admission_id` | 一個授權／傳輸生命週期 | 不可重新綁其他 Receipt 或 Candidate；所有查詢要納入完整權威 Scope |
| `candidate_id`／`candidate_ref`／`candidate_version` | 一份固定候選封套及其受保護版本 | **現有** `candidate_records` 主鍵為 `(environment_id,deployment_id,session_id,world_generation_id,candidate_ref)`，**沒有** version。**擬議** Binding Identity 再加入 DB 生成、不可變的 `candidate_version`；前五欄為不可重用邏輯鍵，版本更替也不能繞過 Tombstone／原 Binding；FK／GC／Snapshot 不可省略 Scope 與版本。須 Migration 才成立 |

## Ingress → Grant 的時間順序

1. Verifier 驗原始 JWS 與**提交**的 Canonical Request Snapshot；先在內部固定不可變的 Verified Context，不能讓 Runtime 提供 verified flag、claims JSON 或比對 digest。**語意 A 只證明提交資料相符；不證明獨立的實際 HTTP 入口來源**。後續全程仍綁定同一 Request Fingerprint。
2. 同一 PostgreSQL Database／Physical Connection／IngressTx 中鎖 Key Revocation、以 DB 時間重查期限／撤銷、插入 Replay 墓碑與 Receipt；Store 不得自開連線或自行 commit，僅 Coordinator 控制 commit/rollback。
3. Candidate 在後續流程生成並提交低信任內容；Validator 檢查完整 Envelope bytes、Scope、Projection、Contract／Source／Policy Revision；昂貴驗證可在鎖外進行，但憑據須綁 DB 版本和不可變資料。短 PromotionTx 原子固定**同一已驗證內容版本**並重查 Revision 狀態。**不能在 Ingress 階段聲稱已有尚不存在的 Candidate Hash。**
4. GrantTx 在**另一個** PostgreSQL Transaction 中鎖定**既有** Receipt 與 Promoted Candidate，讀取當前 Session／Revocation／Generation，僅建立一次性 Binding 與 Admission；**不得重新建立 Receipt**。任一步失敗整筆 Grant rollback，不回復已提交的 Ingress JTI。
5. **AuthorizeTx** 只沿已提交 Binding／Receipt 查核**目前** Policy、Emergency、Key、Epoch、Generation，並以 COMMIT SEND_AUTHORIZED 凍結授權；**StartSendTx** 僅核已提交授權、owner、deadline、single-use、Snapshot／Purge Fence，不重查任何政策撤銷；不得接受 Runtime 替代值。

**關鍵語意**：Receipt 已綁定**目前** Admission 是正常後續使用；只有綁定另一個 Admission 或不符合目前安全條件才是拒絕原因。**已提交 JTI 消費**之後 Grant 失敗不恢復 JTI；另起合法業務意圖才需要新 JWS／JTI，且不可重做已提交外部副作用。**已確認 IngressTx rollback** 且 DB／外部業務／HTTP **均有可驗的零副作用證據**、原 Operation Identity/Digest 可確認未執行，JWS／Session／Generation／Policy／期限仍有效時，才可受限重試；僅看 JTI 未消費或查無 Receipt 都不夠。**未知 Commit** 時不得用任何新舊 Token 盲目重試。

## 一致性、時間與來源認證分層

- **密碼學／來源證明**：Verifier 自己核驗 JWS 與提交的請求資料；語意 A 下不得宣稱已獨立證明真實入口來源，只有欄位完整不代表簽發者可信。
- **內部 Verified Context**：Python immutable class／JSON 不是 PostgreSQL 的來源認證；只在同一可信 Verifier 程序內使用，**不得把完整 Claims JSON／verified=true 當作 Writer 可直接接受的安全憑據或穿越不可信序列化邊界**。DB Writer 的強制來源由專用 Role／受限 Function／Transaction Context 決定；跨服務另需認證、防重放協定。
- **DB 寫入主體證明**：只有 Verifier Role 能建立 Receipt＋Replay；Schema/Role/ACL/SECURITY DEFINER 不能把 Runtime 自填 claim 提升為可信來源。
- **狀態轉移證明**：Grant Binding、Admission、一致性鎖、Revocation、deadline 經受保護 DB 交易強制。
- **Candidate 三種證明**：Hash Integrity（同 bytes）／Policy Authorization（同 Scope／Contract／Source／Revision）／Transport Snapshot（同 ASGI 應用層內容）必須獨立核對。
- **Policy Revision 撤銷**：Version Upgrade 不等於 REVOKED；只有 Grant／AuthorizeSend 在最終授權提交前判斷目前 Revision，StartSend 不二次授權。Emergency 先提交拒絕，SEND_AUTHORIZED 先提交保留。
- **GC 不是保留策略**：`ON DELETE RESTRICT`／等價 FK 可阻止破壞活躍參照，但無法單獨界定 Raw Payload 的資料最小保留期限；若 Binding 長期保留，需先核准 Audit Metadata 與原始內容分層設計，保留未決操作的可對帳證據。
- **發送快照證明**：Envelope v1 與送入 ASGI 的應用層快照一致，不延伸宣稱 TLS 或 Client exactly-once delivery。

## 來源證據

- [Trusted Session 驗章與 Replay](../../trusted-session.md)；[`src/deception/security/trusted_session.py`](../../../src/deception/security/trusted_session.py)
- [Key Revocation](../../key-revocation.md)；[`src/deception/security/key_revocation.py`](../../../src/deception/security/key_revocation.py)
- [Request Audit](../../request-audit.md)；[`src/deception/world/request_audit.py`](../../../src/deception/world/request_audit.py)
- [World Runtime](../../world-runtime.md)；[`src/deception/world/models.py`](../../../src/deception/world/models.py)
- [World Commit Result](../../commit-results.md)；[`src/deception/world/transmission.py`](../../../src/deception/world/transmission.py)

原始碼核對基準：`88dc2008fd35a2d3873949a769653dc9f18e8980`；以上文件的「擬議」段落尚無執行證據，請勿將它們標示為 PASS。
