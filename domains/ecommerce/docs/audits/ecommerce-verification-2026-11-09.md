# 電商 API 一致性與封裝驗證紀錄

驗證日期：2026-11-09。本次不連外部電商平台；對隔離合成契約的實際 Uvicorn 服務發送攻擊特徵請求。展示的惡意判定由伺服器明確模擬，不代表真實攻擊偵測或遠端來源認證。

## 實際 HTTP 結果

| 執行模式 | 本機目標 | 結果 | 成功商品／錯誤內容的來源 |
| --- | --- | --- | --- |
| 固定備援 | `http://127.0.0.1:18080` | 16／16 案例通過 | 8 份明確備援，0 次模型請求 |
| 預設本機模型 | `http://127.0.0.1:18081` | 16／16 案例通過 | 6 份模型生成、2 份快取重用、0 份備援；38 次模型請求 |

本機模型：`hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF:Q4_K_M`，固定權重摘要 `77a78066847b2002fd602955667bd26857eb2cb751c6ed2e975c21b4a826b0a5`，Ollama 0.17.1。模型身份由 backend 核對，並非僅依 `mode: local` 推定曾執行模型。

兩份 JSON 報告均為 `success: true`，全部商品邏輯檢查通過：

- 同商品經過 `200 → 404 → 200` 及提示／標頭注入後，成功 body bytes 一致。
- 不同商品的 ID／名稱對應各自資料，沒有串用另一商品。
- 不存在或含 SQL／腳本／命令字串的商品 ID 均回 404，不把字串當成可執行工具。
- 未審查 query、非綁定 Host、購買、刪除及 TRACE 回 503，不回顯測試憑證。
- 非法追蹤 ID 回 400，超過 1 MiB body 回 413；資料快照前後不變。

報告保存於本機 `generated/verification/ecommerce-fallback.json` 及 `generated/verification/ecommerce-foundation.json`。這些是可重建產物，未加入來源控制。測試用的兩個服務在驗證後已停止。

## 回歸、Bug 修正與註解

完整 `python -m pytest -q`：**586 passed**。本次新增展示服務、驗證工具及攻擊特徵整合案例，另修正判定期限設定為超大整數時，`math.isfinite` 先拋 `OverflowError` 的問題；現改為先檢查範圍，並增加回歸測試。

文件／函式功能 docstring 與本機連結檢查通過。原始碼的既有模型工具提示保持原語意；使用說明與 YAML 註解的架構字母代號已改成元件名稱。

這些結果能證明本次案例與已實作的查詢／拒絕範圍通過，不能保證所有可能輸入都沒有缺陷。購買扣款、退款及庫存交易尚未實作，本次驗證其拒絕行為，沒有宣稱跨 API 交易一致性已完成。

## 封裝檢查

- 已建置 `mirage_response_validator-0.1.0-py3-none-any.whl`，SHA-256：`963c8c58c0f46ae732216ca654044509e648d2d66636755448e296a6ab242632`。
- 檢查 wheel 含展示入口、完整 HTTP 接入、回送及備援模組，以及四份示意契約。
- 將 wheel 安裝至獨立目錄，確認從該目錄匯入模組並實際取得商品 200 假回應。
- `compose.yaml` 經 [官方 Compose schema](https://github.com/compose-spec/compose-spec/blob/master/schema/compose-spec.json) 驗證通過；本次 schema bytes SHA-256 為 `d549057ebc2925f39f62799eab0db7b9e2c18b35b6c00595199116da3ed10e64`。
- 已加入容器建置、健康檢查與 HTTP 案例的 [CI 工作流程](../../../../.github/workflows/container-smoke.yml)，尚未執行。

本機沒有可用的 Docker 命令，亦未找到可改用的 Linux 子系統，因此沒有執行映像 build 或容器 run，不把 wheel／schema／原生 HTTP 通過當成容器實測。容器啟動方式、input、呼叫、元件目的及套件授權見 [Docker 使用說明](../../../../docs/docker.md)。
