# Medusa 原生購物車映射來源審查

## 範圍與來源

本次依使用者明確要求實作 `/store` 購物車映射，沿用 Mirage 合成交易。只有列於 `NATIVE_OPERATIONS` 的七個 method／path 組合，沒有開放全部 Store API，也未改動既有固定 OpenAPI bytes 或把全域草稿 Profile 改為部署核准。

固定來源 SHA-256 為 `ced300a2de92b9829e6e600964588e894b760f07f8d79c1df657e1abe0529058`，既有來源 commit 為 `81edb06c323812773c9c0dcc4da2d9784f3b3319`。來源檔 info.version 為 **2.22.3**，固定來源的 tag／目標環境為 **2.22.4**；保留此差異，不重寫規格版本來偽裝吻合。runtime 產生的 profile.json 同時記錄 target_version、source_info_version、來源／有效契約 hash、映射政策及 adapter version，這些資料納入 Profile hash 與 Contract hash。

## 實際輸入定義交叉核對

唯讀檢查 SSH 現有 Medusa 安裝套件（版本 2.22.4）的 `dist/api/store/carts/validators.js`，SHA-256 為 `363e18d6e29db3dfd086f13a75ef17ff8e3ef48142cb6a26e6033cf9233534d2`。僅讀取程式，不呼叫業務 API、不讀取商店資料、不修改容器。

實際 CreateCart 的 items 使用 variant_id、quantity 與可選 metadata。固定 OpenAPI StoreCreateCart.items 卻引用 StoreCartLineItem 回應型別，含伺服器生成欄位。本適配器的建立輸入明確支援 variant_id／正整數 quantity 子集，依執行版本的驗證定義核對，不要求訪客提供 cart、line id 等回應欄位，也不宣稱原始 request schema 未經差異審查即可完整使用。

metadata、地址、additional_data、locale、query fields 等尚未實作的輸入明確拒絕。完整 checkout／付款與配送工作流不在這七個操作的合成政策內；完成只建立待付款合成訂單，不宣稱已授權、扣款或捕獲真實資金。

## 回應差異與資料語意

- 原生購物車通過固定來源的回應 schema。
- 匿名 StoreOrder.customer_id 使用 null，原始 schema 不接受；僅此 nullable 放寬進入獨立有效投影。官方／有效驗證分開，訂單操作的 DeviationApproval 綁定來源、Profile 與 Contract hash。
- 內部整數分以 Decimal 除以 100 轉成 USD 元，符合 [Medusa v2 主貨幣單位](https://docs.medusajs.com/learn/introduction/from-v1-to-v2)。
- 商品／變體 ID、title、handle 從合成 catalog 投影；沒有向真實商品服務查詢。無描述／型別等資料時使用明確空字串政策，不從 schema 範例推測權威值。
- 稅、折扣、禮卡及運費為固定零政策；未收款與未履約欄位明確反映合成工作流，不生成金融事件。
- 冪等回應上下文與原操作同交易保存，包含穩定 catalog 與時間；不能以最新快照欄位拼接舊提交來源。

## 驗證與限制

投影分別以原始 OpenAPI 3.0 及有效投影測試；原生 HTTP 測試核對增刪改、同鍵重試、同鍵換內容拒絕、簽後 header 竄改、下單與內部取消。另用實際 外部判定服務 proxy／部署組裝器，經 HTTPS 呼叫獨立 Mirage 程序。各次結果與執行位置見[進度紀錄](../../../../docs/implementation-progress.md)。

這份審查不批准正式 Gateway 設定、真實資料 L3 映射或 staging 切換，也不代表完整 Medusa Store／checkout 語意相容。原生取消訂單不借用 transfer/cancel，仍保留 Mirage 專用介面。

自有程式及審查採 Apache-2.0；Medusa 規格僅依原 MIT 聲明保留，參考執行版 validator 但未複製其程式。完整授權見[授權表](../../../../docs/licensing.md)。
