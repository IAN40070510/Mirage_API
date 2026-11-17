# Medusa 購物車映射範圍與部署邊界

## 已有可驗收結果

Mirage 的 `/synthetic` 購物車、訂單、庫存預留與取消使用獨立合成契約。訪客持有資源 ID 可操作，不要求登入或新 Cookie；合成庫存與真實商店隔離。這層已具備獨立映像的實際 HTTP 驗收，但原生 Medusa client 不會自動改用這些路由。

## 已選定的 Store 映射範圍

使用者已於 2026-11-16 明確要求擴充 `/store` 映射，取代先前只說明的選擇。Mirage 內已將首組原生購物車操作轉成既有合成交易，再轉回原生格式；不要求訪客改用 `/synthetic`、不重新導向，也不透過 HTTP 重複呼叫測試入口。實作與隔離驗收見[原生映射](medusa-carts.md)。本文件保留當時比較與正式部署邊界，不再是等待是否開始實作的問題。

工作區固定來源為 `domains/ecommerce/inputs/sources/medusa/openapi.yaml`；既有全域 `profile.yaml` 仍是未載入草稿，approved=false、只列商品查詢。本次不改寫該草稿，改由原生適配器產生獨立、具來源及政策 hash 的 scoped Profile／有效契約。它只適用於明列的七個 method／path，不代表完整 Store 或正式部署核准，不能把合成 schema 改路徑就宣稱相容。

| 操作 | 已實作的原生映射 | 需保留的區別 |
| --- | --- | --- |
| 建立／取得購物車 | POST `/store/carts`、GET `/store/carts/{id}` | 固定 USD 合成地區／通路、部署公開 key 與回應投影；不支援任意地區及欄位。 |
| 加入／更新／移除 | POST line-items、POST／DELETE line-items/{line_id} | 不能要求原生 client 傳目前合成 API 的 CAS／attempt JSON；重試鍵及並行策略需在適配層明確處理。 |
| 完成購物車 | POST `/store/carts/{id}/complete` | 回覆 type=order 的未付款合成訂單；不模擬完整付款／配送前置條件，不假稱已真實支付。 |
| 訂單查詢 | GET `/store/orders/{id}` | 要遵守原生訂單存取與欄位規則，不能把可猜 ID 當成所有權證明。 |
| 合成取消／庫存回補 | 保持 Mirage 專用內部契約 | 固定 Store 規格沒有訪客「取消訂單」路由；`transfer/cancel` 是取消訂單移轉，不能混用成取消訂單。 |

方案一保留明確合成契約，優點是可直接驗收交易隔離且不改真實商店，限制是攻擊者沿原生 Store 路由不會看到這些合成業務。方案二新增版本固定、逐項核准的原生購物車 Profile，優點是可沿原路由模擬訪客流程，代價是必須實作官方欄位、前置狀態及錯誤契約；完成前仍不能宣稱 Medusa 相容。兩者都不需要改動真實庫存或付款。

## 模組與部署邊界

所有 Profile、投影與領域實作留在 Mirage。外部 Gateway 的啟動、身份及導流由整合端明確配置；本模組不修改外部來源或切換服務。七項映射的固定來源及有效投影不等於完整 Store 相容或正式部署批准，實作與配置見[原生映射](medusa-carts.md)及[可選 Gateway 組裝](gateway-bootstrap.md)。

自有文件採 Apache-2.0；採用的 Medusa 規格子集保留 MIT 聲明，未複製 Medusa 工作流程式。權利與套件見[授權表](licensing.md)。
