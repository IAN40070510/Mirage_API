# P2 原始判定查回：Mirage 原生接收邊界

> 這是舊 P2 分支原生安全修補的保留契約，並非其外部 PostgreSQL
> ledger 的部署說明。原判定寫入、一次性消耗、migration、資料庫角色與
> 故障注入驗收已移交外部消費者。production DECEIVE 仍未核准。

## 用途與安全邊界

Mirage 的 `TrustedSessionAssessmentProvider` 在 JWS 驗章、請求
fingerprint 與部署 scope 驗證後，可從部署者明確注入的
`OriginalAssessmentLookup(assessment_id)` 取得原始
`AttackAssessment`。若 `require_original_assessment=True`，
建構時無 callable 查回介面即拒絕；運作時查回缺失、錯誤、
型別不符、身份／scope／digest 不符，一律拒絕而不降級為
claims-only。外部資料庫 DSN、SQL 或 `msdss_*` 函式不是 Mirage
runtime 的組成部分。

原生 Session epoch 的 FOR SHARE／FOR UPDATE 交易界限、
SEND_AUTHORIZED、SEND_STARTED、交易未知結果與安全拒絕
仍由此分支的 Mirage 模組負責；原有 World 與 Replay
migration 不變。

## 設定、輸入與範例

部署者在自己的隔離程序準備可信查回 callable，再明確注入：

```python
provider = settings.model_copy(update={
    "require_original_assessment": True
}).build_provider(postgres_dsn=world_dsn, original_lookup=trusted_lookup)
```

也可在 `deception.domains.ecommerce.trusted_http.create_app` 使用
`original_lookup=trusted_lookup`。來源必須已核准，不能取自
訪客 header、URL 或任何未經驗證的回應。
`from_environment` 沒有公開外部 lookup 插槽；若開啟
strict 卻未由可信組裝層注入，就應拒絕啟動。

## 失敗處理、驗收與限制

Mirage 自有回歸：
`tests/test_original_assessment_binding.py`、
`tests/test_trusted_deployment.py`、
`tests/test_profile_revocation.py`、
`tests/test_postgres_conformance.py`。
原判定 ledger 的資料庫角色、未知 COMMIT、發送前 publish ACK、
跨 Instance 一次性消耗及備份還原，必須在外部專案使用隔離
PostgreSQL 另外驗證並附固定 SHA 證據；跳過不得記為通過。
本次沒有 migration 或正式資料庫操作。

自有程式 Apache-2.0，依賴授權詳見 [授權清單](licensing.md)。
