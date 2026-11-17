# 匿名合成購物車與訂單

## 用途與業務語意

未登入訪客可建立合成購物車，以回傳的 cart.id 加入、更新與移除商品。加入購物車只檢查合成庫存，不預留庫存；完成合成訂單才扣可用量，取消訂單歸還一次。所有價格、catalog、庫存與訂單只存在 Mirage World。

此最小合成契約的路由位於 /synthetic，與 Medusa 原生 Store API 的完整欄位、付款及運送契約分開。業務語意參考 [Medusa 訪客購物車](https://docs.medusajs.com/resources/storefront-development/cart) 與 [庫存流程](https://docs.medusajs.com/resources/commerce-modules/inventory/inventory-in-flows)，不複製其程式碼。正式 Medusa API 映射須使用對應版本的 Profile 與投影審查。

## 身份與模組邊界

匿名 catalog 查詢採固定唯讀資料，IP／UA／短期窗口只作輔助分組。建立購物車後，隨機且由 Mirage 保存的 cart.id 是該合成資源的存取能力；後續可跨 IP、UA 或連線使用同一個 ID，無需額外 Cookie 或登入。order.id 同樣映射到該資源世界。

接收端不只相信 JWS 有效便沿用其中的資源組合。可信 HTTP 會在解析世界之前，重新查核伺服器的資源登記，要求 environment、deployment、session、epoch、access_mode、resource_id 與當次購物車／訂單路徑一致。錯配、過期或查無回相同固定 503，不產生替代世界、ReadAdmission 或業務事件。Replay JTI 仍依獨立狀態機消費，不能把 scope 拒絕推定為授權可重用。直接使用領域 helper 不代表省略可信入口的檢查。

ResourceIdentityProvider 只解析固定路由前綴上、資料庫已登記的合成 ID，拒絕跨部署、到期、舊 epoch、封存與緊急撤銷。已提供但無效的顧客憑證不會降級。持有資源 ID 的人能操作該合成資源，故 ID 需保密並避免進入不必要的日誌。這個能力不證明帳號所有權，不授予真實 Medusa 資料權限。

每張合成購物車使用獨立 World，不自動合併到 Medusa 顧客帳號或其他購物車。MSDSS 原始碼與真實商店保持既有邊界；Mirage adapter 透過既有 dispatcher 注入介面接線。

## 設定與輸入輸出

先依序套用 migrations/001 到 016。以 ecommerce.trusted_http.create_app 的 enable_business=True 明確啟用。設定須與合成部署 runtime 相符，包含公開金鑰、issuer、audience、隔離 DSN 與 origin。JWS 由 Gateway 對最終請求 bytes 簽發。事件寫入使用[共用提交核心](commit-results.md)，保存結果摘要；首次建立仍使用購物車的專用初始化交易，既有 HTTP 欄位保持相容。migration 016 供新版可信 HTTP 保存[請求 Audit 關聯](request-audit.md)，不能只更新交易引擎而漏套。

| 路由 | 輸入與結果 |
| --- | --- |
| POST /synthetic/carts | JSON {}，或提供 UUIDv4 idempotency_key／commit_attempt_id。返回空 cart、版本、hash 與 attempt ID。 |
| GET /synthetic/carts/{cart_id} | 取得該合成購物車與目前版本。 |
| POST /synthetic/carts/{cart_id}/line-items | variant_id、quantity、expected_version、idempotency_key 與可選 commit_attempt_id。單價取自 catalog。 |
| POST /synthetic/carts/{cart_id}/line-items/{item_id} | quantity 與相同 CAS／重試欄位。 |
| DELETE /synthetic/carts/{cart_id}/line-items/{item_id} | JSON 內放 CAS／重試欄位，移除品項。 |
| POST /synthetic/carts/{cart_id}/complete | CAS／重試欄位。只建立合成訂單並預留合成庫存，返回 order。 |
| GET /synthetic/orders/{order_id} | 取得當前有效資源世界中的訂單。 |
| POST /synthetic/orders/{order_id}/cancel | CAS／重試欄位，歸還合成庫存一次。 |
| GET /synthetic/carts/{cart_id}/operations/{attempt} | 已確認當前資源權限後唯讀查詢原操作結果。 |

建立時若省略重試鍵，服務端產生隨機鍵。需要在回應遺失後重試同一次建立時，Client 應事先產生並保存 UUIDv4 鍵。建立鍵的範圍包含原建立者分組；該分組已切換時不能保證沿用原建立結果。其他操作的業務鍵範圍為 cart World 與 operation，相同內容回傳原結果，不重複扣回庫存。一般操作鍵在資料庫保存 SHA-256，不保存原文。

## 失敗處理

CAS 落後、品項不存在、庫存不足或無法取消等業務拒絕回傳固定 409 code；未知資源、身份、必要來源或儲存無法確認時走固定安全錯誤。輸入不接受額外價格、庫存或 World ID。回應先通過固定合成 OpenAPI，再通過 Renderer 最終 Gate、Candidate hash、共享 Admission 與傳輸事件。

預留、取消、訂單資源映射、操作結果與 WorldEvent 在同一 PostgreSQL 交易提交。回覆中斷後依原 attempt 查詢，不把 not_found 當成操作從未發生。舊世代歷史操作查詢仍須獨立 Capability，未由本路由提供。

## 驗證方式與執行位置

本機設定 MIRAGE_POSTGRES_TEST_DSN 指向可建測試 schema 的隔離 PostgreSQL，執行：

```powershell
python -m pytest tests/test_guest_carts.py tests/test_cart_http.py -q
python tools/check_documentation.py
```

本機執行身份適配、JWS、pytest、OpenAPI Gate、Renderer 與 HTTP client。SSH 伺服器 Ubuntu 提供隔離 PostgreSQL；Medusa 身份驗收另使用獨立 Medusa／Redis 容器。原始碼、測試簽章私鑰與客戶登入憑證不寫入報告。測試資料全為合成，未讀寫既有 staging 庫存或訂單。

## 套件／模型授權與限制

自有工具與契約採 Apache-2.0，沿用 FastAPI、Pydantic、openapi-core、HTTPX、psycopg 及 PostgreSQL，完整授權見 [共用表](licensing.md)。未引入付款模型或其他專案的購物車程式碼。幣別目前固定 USD，金額使用整數最小單位。沒有稅、折扣、運費、真實支付、退款、履約、會員購物車合併或完整 Medusa 欄位。
