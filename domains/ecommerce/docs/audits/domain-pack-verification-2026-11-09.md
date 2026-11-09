# 通用領域拆分與受控弱點驗證（2026-11-09）

## 驗證範圍

本次確認電商資產與商品實作搬入領域資料夾後，共用入口、資料交換、情境派送、內容生成、契約驗證及 HTTP 回送仍可運作。測試另使用非電商工單供應器與處理器，完成協調、生成、通用映射、201 契約檢查及回送；它是擴充介面測試，並非正式工單領域包。

## 完整回歸及文件

在 Windows、專案既有 Python 虛擬環境執行：

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe tools/check_documentation.py
.\.venv\Scripts\python.exe -m compileall -q src mirage_validator tools tests
```

完整回歸為 **637 passed**，沒有失敗或跳過。文件檢查通過 **752 個函式、23 份工具文件**，語法編譯通過。回歸涵蓋舊匯入相容性、非電商派送、資料 scope／adapter 拒絕、所選領域的識別預設路徑、路徑越界、分類版次及弱點契約保護。

修正的兩個舊政策測試路徑與識別 CLI 預設位置均指向搬移後的領域包，沒有保留第二份電商資產。Medusa 固定規格與未審核狀態未因搬移改變。

## 實際 HTTP

使用 `deception.api.demo:create_app` 共用工廠，以原生 Uvicorn 分別啟動下列 loopback 展示，並由 `tools/verify_domain_api.py --domain ecommerce` 發送實際請求：

| 設定 | 請求數 | 結果 | 本機報告 |
| --- | --- | --- | --- |
| `weakness_scenario: null` | 16 | 全部通過 | `generated/domains/ecommerce/verification/domain-refactor-default.json` |
| `api3-internal-product-properties` | 16 | 全部通過 | `generated/domains/ecommerce/verification/domain-refactor-property.json` |
| `api8-debug-header-disclosure` | 16 | 全部通過 | `generated/domains/ecommerce/verification/domain-refactor-debug.json` |

三組均確認重複商品 body 一致、不同商品隔離、商品事實及快照不變、注入內容不能覆寫資料、未支援交易明確拒絕。兩個弱點另核對固定虛構備註與舊版標頭；修補後重新建立契約並重跑兩組 HTTP 測試，確認必要標頭及固定值 enum 不會破壞正常回送。單元測試獨立呼叫 gate，確認刪除／竄改備註或版本標頭會拒絕。

此輪 HTTP 全為 `fallback` 模式，沒有呼叫真實模型；先前本機 Foundation 模型結果另見 [既有驗證紀錄](ecommerce-verification-2026-11-09.md)。測試服務在驗證後停止。本機 JSON 為可重建產物，沒有加入版本控制。

## 封裝與限制

`pip wheel --no-deps` 成功建立安裝封裝，並從該 wheel 實際匯入通用／電商／安全分類模組，使用外部領域資產建立展示 app。領域 YAML、來源及分類檔是獨立部署資產，由 Dockerfile 明確複製，並不包含在程式 wheel。

Compose 通過官方格式 schema 驗證。本環境沒有 Docker 引擎，因此沒有宣稱完成容器建置、容器執行或 Oracle Cloud Linux 實測。

目前只有兩項受控回應模擬可啟用，其他八項設計情境會拒絕；這些測試不證明完整 OWASP 弱點覆蓋或實際誘捕成效。購買扣款、庫存寫入及跨 session 交易仍未實作，正式平台來源核准亦未變更。此輪沿用既有套件，沒有新增執行依賴；授權及分類資料出處見 [分類說明](../../../../docs/owasp-design.md) 與 [專案授權](../../../../README.md#開源軟體模型與資料授權)。
