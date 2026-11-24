# Mirage ↔ MSDSS Gateway 整合（過渡相容說明）

> **Mirage_API 不再擁有 Gateway Bootstrap 與 Dispatcher 實作。**
> 本 PR 必須與 MSDSS 對應 ownership PR 配對驗收；兩個倉庫尚未完成
> 正式 release 或 Oracle 服務切換。

Gateway 的部署組裝、Outbound Trusted Session JWS 簽發、
Request Fingerprint、Gateway→SOC Anchor HTTP 發送與各種
Gateway 證據／唯讀戰情室程式，都由
[MSDSS](https://github.com/IAN40070510/MSDSS)
的 `src/msdss/gateway_integration/` 負責。
對應部署設定／相容性需求與測試移至 MSDSS 的
`docs/GATEWAY_BOOTSTRAP_RUNBOOK.md`、
`docs/GATEWAY_INTEGRATION_OWNERSHIP.md` 與
`ops/compat/requirements.gateway-compatibility.txt`。

**Mirage_API 的責任不變：** 驗證 Trusted Session JWS、消費 JTI
防重放、執行 Admission／World 交易、記錄原生 Request／Response
Audit 與出具來源端可驗簽的 Signed Witness。
來源端稽核／Witness 必須在 Mirage 內完成，不能移到看不到
真實 Grant COMMIT 的 Gateway。

`integrations/msdss/gateway_bootstrap.py` 和
`integrations/msdss/trusted_session_dispatch.py` **只保留薄相容轉接**，
重新匯出 MSDSS 類別而不保留第二份 Gateway 實作。
一般 Mirage API 不使用也不匯入這兩個模組；只有
部署整合者明確使用舊匯入路徑時，才需要已安裝、版本鎖定且
契約相容的 MSDSS 套件。

SOC 戰情室只使用 Gateway 去敏事件→受身分驗證的 SOC ingest→獨立
鑑識庫→唯讀 BFF／UI，不直接操作 Mirage DB 或 API。
**此相容調整沒有啟動 Gateway DECEIVE；正式發布仍 NO-GO。**
