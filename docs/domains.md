# 通用核心與領域資產包

## 分工與目的

共用核心負責請求標準化、可信判定關聯、平台／契約識別、執行預算、受控模型工具、回應組合、契約驗證及 HTTP 回送。商品、工單或其他業務的規則由明確註冊的領域處理器提供，不從 URL、訪客標頭或模型文字猜測領域。

目前內建可啟動的領域為 `ecommerce`。非電商工單測試另驗證完整協調、通用資料映射、生成、契約檢查及回送的擴充介面；它不代表已提供正式工單領域包。

```text
configs/
  app.yaml                    # 明確選擇領域與資產根目錄
  llm.yaml                    # 共用模型與解碼設定
inputs/security_taxonomies/   # 共用且明列版次的安全分類
domains/<domain>/
  domain.yaml                 # 領域資產索引
  configs/                    # 這個領域的資料、部署及展示設定
  inputs/                     # 來源、平台、政策與測試資料
  security/                   # 此領域對安全分類的情境映射
  docs/                       # 領域用法及驗證紀錄
src/deception/
  common/                     # 共用嚴格型別與資料交換
  domains/<domain>/           # 領域處理器、供應器及專用展示
  security/                   # 安全分類與情境目錄驗證
```

電商的 Medusa／WooCommerce 資訊集中在 [電商資料夾](../domains/ecommerce/README.md)。根 `configs/` 不再放電商專用設定；來源與平台套件沒有留下第二份可寫副本。搬移不改 OpenAPI bytes、固定雜湊或原有未審查狀態。

## 輸入與選擇

`configs/app.yaml` 格式如下：

```yaml
schema_version: 1
domain: ecommerce
domains_dir: domains
```

`MIRAGE_APP_CONFIG` 可指定另一份共用設定，`MIRAGE_DOMAIN`／`MIRAGE_DOMAINS_DIR` 可明確覆寫領域與資產目錄。`DomainManifest` 只記相對檔案位置，不接受 Python 匯入路徑。檔案與 manifest 的 domain ID 必須相同；路徑逃逸、錯誤檔案類型、未知領域或缺少資產都會停止，不回退電商。

manifest 的 `demo_config`、`bindings_config`、`source_dir`、`platform_dir`、`policy_dir` 及 `weakness_catalog` 必須指向領域資料夾內存在的檔案或目錄。識別 CLI／HTTP factory 依 `platform_dir`、`bindings_config` 選預設輸入；外部已核對的契約及 binding 仍可明確指定。

```powershell
$env:PYTHONPATH = "$PWD/src"
.\.venv\Scripts\python.exe -m deception.domains --list-domains
.\.venv\Scripts\python.exe -m deception.domains --domain ecommerce
.\.venv\Scripts\python.exe tools/verify_domain_api.py --domain ecommerce --base-url http://127.0.0.1:8000
```

第二個命令離線列出該領域的弱點設計及實作狀態，不發送攻擊請求或執行漏洞。HTTP 驗證器由所選領域提供，不假設所有領域都有 `/products`。

## 程式擴充介面

`deception.domains.registry.DomainImplementation` 註冊情境處理器、資料供應器、HTTP 展示、生成展示與 HTTP 驗證器。註冊只能由受信任的應用程式程式碼完成；在 YAML 多建一個資料夾或填入模組名稱不會執行外部程式。

| 介面 | 用途 |
| --- | --- |
| `DomainImplementations.register/get/domain_ids` | 管理唯一領域 ID、拒絕重複或未知實作 |
| `ScenarioDomain.prepare/resolve` | 執行自己的業務規則，產生通用組合計畫 |
| `provider.load/facts/composition_data` | 核對領域資料，投影模型可見事實與通用 JSON 映射 |
| `provider.from_files` | 選用的領域檔案載入介面，供共用組合 CLI 使用 |
| `load_application_selection/load_domain_assets` | 讀管理者的領域選擇及安全相對路徑 |
| `ScenarioCatalog.select` | 只選可用的弱點回應模擬，設計項目不能冒充實作 |

新增領域需提供自己的資料型別、業務政策、來源、契約、情境、測試與文件，並註冊完整處理器。共用協調器可明確注入資料供應器；預設供應器也依選定領域取得，沒有全域商品供應器。

既有 `deception.synthetic`、`deception.scenarios.domains.ecommerce`、`deception.api.demo.DemoConfig` 與 `deception.generation.demo` 保留相容轉出，實作只存在電商套件。新程式應從 `deception.domains.ecommerce` 匯入專用能力。共用的 `deception.api.demo.create_app` 是領域派送入口，不定義商品欄位。

## 安全分類與弱點情境

共用 OWASP 分類與各領域情境分開，版本與分類引用都由 `deception.security` 離線驗證。不是每個產業都有一份官方專屬 Top 10；領域包選擇適用分類，再定義自己的虛構資料、誘餌回應及驗證條件。詳見 [分類設計](owasp-design.md)。

## 驗證、生命週期與授權

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_domain_packages.py tests/test_generic_pipeline.py tests/test_scenario_domains.py -q
.\.venv\Scripts\python.exe tools/check_documentation.py
```

測試覆蓋領域路徑、未知領域拒絕、版本化分類、未實作情境拒絕、兩個受控電商弱點及非電商完整流程。此結果不代替真實平台部署對照或完整弱點覆蓋。應用程式仍負責關閉模型與資料庫連線，資產讀取不會自行下載或核准來源。

框架沿用 Pydantic（MIT）、既有 YAML／OpenAPI 元件及 Python 標準庫（PSF 與隨附聲明），未增加執行套件。OWASP 分類資料與本專案翻譯的 CC-BY-SA-4.0 授權另列於 [分類文件](owasp-design.md)，不與框架或模型權重授權混為一談。
