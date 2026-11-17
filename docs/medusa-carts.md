# Medusa `/store` 合成購物車映射

## 用途與邊界

這個適配器把已核准導流的 Medusa 原生請求轉成現有 SyntheticCarts 事件，再直接回覆原請求。訪客不需要改用 `/synthetic`，沒有重新導向，也沒有對真實 Medusa 發送購物車、訂單或付款操作。

原生路徑與欄位只存在電商 Medusa 適配器。共用 WorldStore、Replay、CAS 與 Admission 不加入 Medusa 路徑。固定商品、價格與庫存由合成部署供應；其他電商需使用自己的適配器及規則。

## 第一組路由與輸入輸出

例如訪客送出 `POST /store/carts`，當 Gateway 已核准導流並簽發可信授權後，Mirage 會建立合成購物車，直接在這個請求回覆 `{"cart": {...}}`。接著送出 `POST /store/carts/{id}/line-items` 時，Mirage 依伺服器登錄的購物車 ID 找回同一個合成世界，再加入合成商品。Client 不需要知道 `/synthetic` 的存在；這裡是程式內部操作映射，不是 HTTP 轉址或再呼叫另一個公開 API。

正常流量是否送到真實 Medusa，由 Gateway 原有政策決定；啟用這個適配器本身不會把全部 `/store` 流量轉入 Mirage。已導流的請求若遇到未支援操作或驗證失敗，則明確拒絕，不改送真實商店。購物車 ID 是資源存取能力，應避免公開；IP／UA 輔助分組不代表已驗證的顧客身份。

| 原生請求 | 合成操作及回應 |
| --- | --- |
| POST `/store/carts` | 建立空購物車，或原子套用 items 的 variant_id／quantity；回覆 cart。 |
| GET `/store/carts/{id}` | 依已登記的 cart.id 能力取得同一世界的 cart。 |
| POST `/store/carts/{id}/line-items` | variant_id、quantity；加入商品，回覆 cart。 |
| POST `/store/carts/{id}/line-items/{line_id}` | quantity；更新數量，回覆 cart。 |
| DELETE `/store/carts/{id}/line-items/{line_id}` | 不需 JSON 控制欄位；回覆 id、object=line-item、deleted 與 parent cart。 |
| POST `/store/carts/{id}/complete` | 不需額外 JSON；建立待付款、未履約的合成訂單，回覆 type=order 與 order。 |
| GET `/store/orders/{id}` | 依已登記的 order.id 能力取得原生格式訂單。 |

加入／移除／更新購物車不預留庫存，完成才扣合成可用量。原生取消訂單路由不自行捏造，取消及回補仍由已存在的 `/synthetic/orders/{id}/cancel` 執行。

Client 不傳 expected_version、state_hash、commit_attempt_id；適配器以可信讀取版本做 CAS，衝突不自動重試。可選 Idempotency-Key 須唯一、格式正確，並納入 Gateway／Mirage 的 fingerprint。相同鍵換內容拒絕；沒有鍵時建立／加入是新操作，不能由相同 body 猜測是重試。完成操作另有資源內固定業務鍵，避免無額外 header 的完成重試重複下單。

建立目前接受 currency_code=usd、region_id=reg_mirage_usd、sales_channel_id=sc_mirage、email，以及最多 100 個初始品項。省略時採上述固定合成部署值。email 只是請求提供的聯絡欄位，不代表已驗證帳號，也不讀取真實顧客資料。未實作的地址、metadata、additional_data、非空 query 或其他地區／幣別會明確拒絕，不默默忽略。這是版本固定的首組映射，不是完整 Medusa checkout 能力。

## 固定來源、價格與投影批准

來源為 `domains/ecommerce/inputs/sources/medusa/openapi.yaml`，固定 SHA-256：`ced300a2de92b9829e6e600964588e894b760f07f8d79c1df657e1abe0529058`，保留既有 commit 與規格 bytes。適配器只擷取上表操作；來源異動立即停止，不自動套用其他版本。既有全域 Medusa Profile 的 approved 狀態不因新增映射被改成 true。

合成引擎使用整數「分」，原生投影轉為 USD「元」。依 [Medusa v1／v2 差異說明](https://docs.medusajs.com/learn/introduction/from-v1-to-v2)，v2 採主貨幣單位；例如內部 2509 分投影為 25.09。計算留在整數／Decimal，JSON 回應不接受負數、bool、非有限值或超出政策的金額。

目前固定來源的 StoreOrder.customer_id 要求字串，匿名合成訂單沒有顧客帳號。因此保留原始 schema，另建立唯一放寬 customer_id nullable 的有效投影；不捏造 customer_id。訂單／完成操作的 ProjectionEvidence 分別保存 official_schema_valid=False、effective_projection_valid=True 與具來源、契約、Profile hash 的 DeviationApproval。購物車投影直接核對官方 schema。原始來源驗證與有效投影通過不能混為一談。

固定來源保留 info.version=2.22.3，目標安裝版為 2.22.4；原生 profile.json 同時記錄兩者及精確來源 hash，不重標來源。建立 items 的輸入另與實際 2.22.4 validator 交叉核對，詳見[來源與語意審查](../domains/ecommerce/docs/audits/medusa-native-cart-2026-11-16.md)。

合成訂單 payment_status=not_paid、paid_total=0，不假稱已真實付款。稅、折扣、禮卡與運費目前為明確零值政策；完整配送／付款前置條件不由此適配器提供。缺少的非權威商品描述使用固定空字串，不向真實商店查詢或由模型猜測。

## 設定與部署節點

新版可信入口先套用 migrations 至 016（011 保存原生上下文、012 保存 Profile 墓碑、013 保存入口拒絕、014 保存 key 墓碑、015 保存事件操作結果摘要、016 保存請求 Audit 關聯）。現行交易寫入會使用 015 欄位，可信 HTTP 另使用 016，只套用至舊版不足以執行目前服務。`trusted_http.create_app` 需同時明確設定 enable_business=True、enable_medusa_store=True，並提供部署固定的 medusa_publishable_key。必要時以 medusa_source 指定來源檔，仍必須通過固定 hash 核對。

環境入口使用 MIRAGE_ENABLE_BUSINESS=true、MIRAGE_ENABLE_MEDUSA_STORE=true 與 MIRAGE_MEDUSA_PUBLISHABLE_KEY_FILE；預設均不啟用。Gateway 組裝設定另有 enable_medusa_store 開關，啟用時在 Mirage 內的身份適配器解析 `/store` 合成資源 ID；它不更改外部 Gateway 原始碼，也不自動開啟攔截政策。

| 節點 | 白話功能 |
| --- | --- |
| Gateway 原生資源身份適配 | 依伺服器登錄的 cart.id／order.id 找回可信 binding；不是依 IP／UA 授予寫入權。 |
| MedusaCartHTTP | 核對原生路徑、公開 key、輸入與冪等 header，直接呼叫交易引擎。 |
| SyntheticCarts | 原子保存購物車、訂單、庫存、事件、結果及原生回應上下文。 |
| Medusa 投影 | 做元／分轉換與明確欄位映射，移除內部控制資料。 |
| Gate／Renderer／Admission | 核對有效契約及來源，以精確最終 bytes 執行一次性發送。 |

## 失敗與重試

`native_time.validate_native_times()` 讓交易與讀取投影共用時間檢查：輸入為原生上下文，回傳已保存的更新時間；建立／更新／可選訂單時間必須是固定 UTC 毫秒表示，且建立 ≤ 訂單 ≤ 更新。缺失、格式或順序錯誤會停止，不改寫歷史。新事件以已保存更新時間與接收端時間的較晚者作業務邏輯時間，因此時鐘回撥不會讓資源倒退；這不修改 Lease、JWS 到期或 Replay 時鐘。重試沿用原操作的上下文，不能拿此次時間拼接舊回應。

此共用 helper 不存取資料庫、不推論真實事件時間；購物車與訂單投影也會先檢查，避免既有不合法上下文仍被 GET 回送。`tests/test_native_time.py` 驗證回撥、保存格式／順序、讀取拒絕，以及實際 PG 下單／取消／重播和 Lease 不變。沿用 Python 標準函式庫 datetime，不增加套件；自有程式採 Apache-2.0。未提供產品刪除生命週期或既有錯誤歷史修復。

格式／未支援欄位回固定 400、已知業務資源缺少回 404、CAS 或同鍵異內容回 409。必要身份、來源、DB 或契約無法確認時交由安全錯誤路徑，不回退真實 Backend。Idempotency-Key 與 x-publishable-api-key 已加入核准 fingerprint 標頭；簽章端與驗證端須使用同一版適配器，舊版不相符時拒絕，不降級。

migration 011 保存建立內容摘要與 native_response_contexts。上下文、操作結果、快照及收據同交易提交，重試不會拿新時間、catalog 或地區拼接舊操作結果。查詢仍核對當前資源、部署、世代及期限；未知上下文不重建。本文與 API 聯絡資料不寫進部署報告或鑑識介面。

## 驗證方式

```powershell
python -m pytest tests/test_medusa_cart_projection.py -q
python -m pytest tests/test_medusa_cart_http.py tests/test_guest_carts.py -q
python tools/check_documentation.py
```

投影測試在本機以固定原始 OpenAPI 與有效投影分開驗證。HTTP／交易測試需要專用 MIRAGE_POSTGRES_TEST_DSN，未設定的 skip 不算通過。SSH 模式由 Ubuntu 隔離 PostgreSQL 執行 SQL，本機執行 JWS、適配器、HTTP client 與 Gate；不代表 staging 已部署。最新結果見[進度紀錄](implementation-progress.md)。

## 授權與限制

自有適配器採 Apache-2.0；固定 Medusa 規格依原 MIT 聲明保留，不複製 Medusa 工作流程式。沿用 Pydantic、HTTPX、psycopg、openapi-core 與 referencing 等既有依賴，未引入模型。完整來源、套件及模型邊界見[授權表](licensing.md)。目前不涵蓋完整 Medusa Store、任意 query／fields 選擇、多地區幣別、真實付款配送、帳號購物車合併或 L3 真實資料銜接。
