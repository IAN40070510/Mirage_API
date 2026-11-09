# 通用安全分類與領域弱點情境

## 功能與目的

安全分類由共用引擎讀取，各領域在自己的資料夾選擇適用分類、定義合成資料及回應情境。`src/deception/security/catalog.py` 提供嚴格分類模型與離線目錄查詢，不執行 SQL、shell、任意 Python、訪客 URL 請求或真實弱點。

OWASP 的榜單應依技術範圍與版次區分。此專案使用 [API Security Top 10 2023](https://api-security.owasp.org/editions/2023/en/0x11-t10/) 及 [Web Top 10 2025](https://top10.owasp.org/2025/0x00_2025-Introduction/) 兩套共用分類；不能把相同順位的兩種分類當成同一風險。官方 API 專案的適用背景涵蓋多種產業，見 [專案說明](https://owasp.org/projects/api-security-project)。

本專案不假定每個產業都有一份官方獨立的 OWASP Top 10。「電商弱點情境」是本專案將共用分類映射到電商資源的設計，不是 OWASP 官方電商排行榜。新增領域時，應明確選擇已核對的榜單及版次，再設計自己的場景；不能只把 `ecommerce` 換成另一產業名稱便宣稱已有該領域的漏洞覆蓋。

## 共用分類與領域資料分工

| 位置 | 內容與責任 |
| --- | --- |
| `inputs/security_taxonomies/owasp-api-security-2023.yaml` | API 風險的版本化 ID、官方英文名稱、本專案中文名稱、來源及授權 |
| `inputs/security_taxonomies/owasp-web-2025.yaml` | Web 風險的版本化 ID、名稱、來源及授權 |
| `src/deception/security/catalog.py` | 核對分類、領域、情境狀態與引用，不猜測分類或自動下載資料 |
| `domains/ecommerce/security/owasp-scenarios.yaml` | 電商情境名稱、分類映射、固定參數、驗證要求及實作狀態 |
| 各領域處理器 | 實際提供已註冊、只操作虛構資料的回應行為 |

API 分類檔使用 `taxonomy_id: owasp-api-security-2023`；Web 分類檔使用 `taxonomy_id: owasp-web-2025`。`API3:2023`、`A01:2025` 等是 OWASP 風險識別，應保留，並不是已移除的架構工具代號。

## 輸入、輸出與查詢

`SecurityTaxonomy` 載入 `schema_version`、`taxonomy_id`、`title`、`edition`、`source_url`、`license` 與 `categories`。每個分類包含 `category_id`、`title_en`、`title_zh` 及 `url`，同榜單不能有重複 ID。

`ScenarioCatalog` 則包含明確 `domain`、目錄識別與版本、`taxonomy_ids` 及情境清單。情境的每個分類引用均須指定榜單 ID 與風險 ID；檔名、資料內識別及引用對不上時拒絕載入。

已知 `owasp-api-security-YYYY`／`owasp-web-YYYY` 分類另要求 `edition` 與 ID 年份一致，且具有該版次完整十項正式 ID。其他自訂分類可保留自己的版次及分類格式，不強迫套用 OWASP 命名。

```python
from pathlib import Path
from deception.security import load_catalog

catalog = load_catalog(
    Path("domains/ecommerce/security/owasp-scenarios.yaml"),
    domain="ecommerce",
    taxonomy_root=Path("inputs/security_taxonomies"),
)
scenario = catalog.select("api3-internal-product-properties")
print(scenario.handler_id)
```

此查詢只取得已實作情境的副本，不會自行啟動 HTTP 服務、核准平台來源或繞過契約驗證。`status: designed` 表示只有設計與驗證要求，不能選成可執行情境；`implemented` 必須提供明確 `handler_id`，並由所選領域的受控處理器支援。

## 電商情境與實作狀態

目錄為 API 十項風險各記錄一個電商情境。其中兩項已提供可啟用的回應表徵模擬，其他八項保持 `designed`：

| 風險 | 本專案電商情境 | 狀態及界線 |
| --- | --- | --- |
| `API1:2023` | 跨虛構使用者訂單存取 | 設計中；尚無訂單及使用者授權狀態 |
| `API2:2023` | 虛構登入會話缺陷 | 設計中；不使用真實帳密或弱化服務認證 |
| `API3:2023` | 虛構內部商品屬性外露 | 已實作表徵模擬；固定假註記，身份及商品事實仍受保護 |
| `API4:2023` | 看似缺少資源限制 | 設計中；真實大小、用量及執行期限仍必須生效 |
| `API5:2023` | 虛構管理功能存取 | 設計中；只可操作合成資源，不能開放實際管理權限 |
| `API6:2023` | 虛構優惠碼重用流程 | 設計中；需要後續虛構交易與去重介面 |
| `API7:2023` | 靜態內部服務資訊假象 | 設計中；不依使用者 URL 連網、讀檔或存取雲端 metadata |
| `API8:2023` | 虛構除錯版本標頭外露 | 已實作表徵模擬；只回固定假識別，不讀取實際版本、堆疊或設定 |
| `API9:2023` | 虛構舊版 API 清單 | 設計中；每個路徑仍須屬於已載入的合成契約 |
| `API10:2023` | 虛構上游資料處理缺陷 | 設計中；只處理包內固定 fixture，不下載或執行外部內容 |

商品屬性外露另映射 Web 的 `A01:2025`，除錯識別外露另映射 `A02:2025`。這些是本專案依風險性質建立的對應，不宣稱為 OWASP 官方跨榜對照，也不表示兩套榜單可以互換。

模擬回應表徵不等於重現完整弱點成因或可利用範圍。只有標記一個風險 ID，不能聲稱已完成該風險的全部測試或已有誘捕效果。

兩個可啟用情境的固定值也在來源摘要建立前寫入合成契約：商品 `internal_note` 的 enum 僅允許領域包指定值；`X-Legacy-Store-Version` 在成功與不存在分支均為 required，且 enum 僅允許指定虛構版本。如此獨立契約驗證器也會拒絕缺漏或改值，而非只依賴模板及回送封存。

## 安全及契約邊界

所有可啟用情境只使用隔離的虛構資料及管理者明列參數。即使回應刻意呈現資料外露或設定錯誤的假象，共用服務仍維持來源核對、請求關聯、大小與總預算限制、資料完整性、契約檢查及最終原樣回送。

注入、請求偽造、資源消耗、弱認證及供應鏈風險只能以受控 fixture、固定回應或虛構狀態呈現；不能為了模擬而加入實際 SQL 拼接、shell 執行、任意 URL 存取、真實無限任務或過時可利用套件。情境需要新欄位或端點時，必須先在所選合成契約宣告，不能對真實平台規格任意放寬。

分類與情境資料是離線設定，載入時不連網。來源未知、錯誤版次、未實作情境、領域不符或契約未通過時，不生成可用候選。誘餌追蹤、事件告警及交易狀態需要各自的實作，不能因分類目錄存在就宣稱已完成。

## 驗證方式及授權

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_domain_packages.py tests/test_generic_pipeline.py tests/test_security_contracts.py -q
.\.venv\Scripts\python.exe tools/check_documentation.py
```

分類檔已以共用模型檢查各有十個唯一 ID，電商目錄的所有引用均可解析。HTTP 行為、資料一致性與實際情境處理器仍須分別測試；分類載入通過不代表所有弱點已實作或官方服務已相容。

OWASP Top 10 與 API Security 的原始分類文件均採 **CC-BY-SA-4.0**，來源分別為 [Web 專案授權](https://github.com/OWASP/Top10/blob/master/LICENSE) 與 [API 專案授權](https://github.com/OWASP/API-Security/blob/master/LICENSE)。本專案將分類名稱重新編排為 YAML，中文名稱為本專案翻譯；兩份分類檔保留來源及授權。分發改作分類資料時應依原條款保留歸屬、授權及修改說明，不宣稱 OWASP 背書本專案。這裡不替整個專案原始碼選定授權。

目錄驗證沿用 Pydantic（MIT）、PyYAML（MIT）及 Python 標準庫（PSF 與隨附聲明），未新增第三方套件。分類資料授權、模型權重授權、來源契約權利及程式套件授權分開管理。
