# Medusa v2.22.4 Store/Auth 子集契約

> 狀態：**靜態契約已按官方固定 tag 修正；正式部署尚未核實。** `approved: false`，不得作為已完成官方相容性驗證的證據。

## 上游來源與身份

- 上游 Repository：[medusajs/medusa](https://github.com/medusajs/medusa)
- 目標發行 tag：`v2.22.4`，固定 Commit：`81edb06c323812773c9c0dcc4da2d9784f3b3319`
- 官方完整 Store API 規格：[`www/apps/api-reference/specs/store/openapi.full.yaml`](https://github.com/medusajs/medusa/blob/81edb06c323812773c9c0dcc4da2d9784f3b3319/www/apps/api-reference/specs/store/openapi.full.yaml)
- 上游完整規格 SHA-256：`ac76bf98207021e17455819ec9db5eee3742efa6172a76b4d83d67b06d97af4d`
- 上游 Git blob SHA-1：`000dcd0fb6d124a9675e5168b49ef7b354ac8a19`
- **官方發行套件版本為 `2.22.4`，該 tag 的 Store API 文件 `info.version` 仍為 `2.22.3`。** 本子集保留官方文件值，不將兩個版本混為一談。

## 本地檔案

| 檔案 | 目的 |
| --- | --- |
| `openapi.yaml` | 已修正的 Store/Auth 子集，供 I 的正式格式 Gate 使用（尚未啟用） |
| `inputs/sources/medusa/openapi.yaml` | D 使用的同一份 bytes；與 Gate 契約完全相同 |
| `manifest.yaml.example` | 已更新固定來源 commit、子集 SHA-256；`approved: false`，不會載入 |
| `api-scope.json` | 歷史 XGBoost 推論操作範圍記錄，**不作為驗證器輸入**；其中原始來源 SHA 與這次取得的官方完整 OpenAPI SHA 不相同 |
| `input-audit.json` | 已更新子集 SHA、官方來源資訊及靜態修補狀態；靜態修補後的執行期測試仍待跑 |

本地子集（D/I 使用相同 LF 格式）的 SHA-256：

```text
15c794cf596866f13bf96b715db66470011406f659e2eadbf4761dfdbb2ccc96
```

## 已完成的靜態對照及修補

- 67 個 paths、77 個 method/path operations；官方固定 tag 有 69 paths、79 operations。未收錄的 `/store/search` 與 `/store/payment-collections/{id}/payment-sessions/{session_id}` 保持未支援。
- 77/77 operations 在排除說明性和 `x-*` 擴充欄位後，核心請求與回應契約一致。
- 本地 `components/schemas` 保留 133 個；補回原缺失的 `BaseRefund.properties.idempotency_key: string`。
- 將官方 51 個 Store operation 的 `x-allowed` 欄位白名單保留在規格中；**格式驗證器並不自動執行白名單語意，也不能由其通過推論任意 `fields` 組合可用**。
- 本地原有的 10 個「成功回應沒有 `content`」仍需要針對實際服務釐清；沒有猜測補齊 Response Schema。
- 舊版 CRLF／LF 差異已消除，D/I 來源 byte-for-byte 相同。

## 回歸測試

在專案根目錄（Python 3.11+、已安裝 `.[test]`）執行：

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_medusa_pinned_contract.py -q
$env:PYTHONPATH = "$PWD/src"
.\.venv\Scripts\python.exe -m deception.profile_builder --source inputs/sources/medusa/source.yaml --output generated
```

此回歸測試核對 D/I 相同 bytes、固定 SHA、版本區分、77 operations、133 schemas、51 份 `x-allowed`、`BaseRefund` 新欄位與內部 `$ref`；**不能替代固定 Medusa 部署的實際 HTTP 對照測試**。

## 未完成的正式啟用條件

1. 在實際 Medusa `2.22.4` 測試部署核實 origin、部署版本與 `query_contexts`，並取正常、404、授權錯誤、`fields` 等參考回應。
2. 實作／確認 `x-allowed` 與查詢選欄的策略，避免錯誤宣稱單靠 JSON Schema 即符合服務行為。
3. 對新規格重新執行 Profile 建立、OpenAPI Gate／pytest 與對照測試，確認更新無回歸。
4. 維護者完成來源、部署與覆蓋審查後，再決定是否建立 `manifest.yaml` 與核准。原始 `manifest.yaml.example` 的網站 `https://shop.example` 只是占位值。

詳細發現與修補歷程：[審查紀錄](../../docs/audits/medusa-v2.22.4-contract-2026-11-08.md)。
