# Docker 封裝與領域選擇

## 共用封裝的目的

映像提供共用的 HTTP 入口、領域派送、受控生成／備援、契約驗證與原樣回送流程。業務契約、資料、政策、弱點情境及驗證器由明確選定的領域包提供；共用封裝不假設商品、訂單、帳戶或其他產業欄位。

目前內建可執行領域只有 `ecommerce`。具體 input、商品呼叫與已實作弱點均在 [電商領域使用說明](../domains/ecommerce/docs/usage.md)；共用入口不因資料夾名稱、訪客 URL 或 header 自動猜測領域。

展示使用合成契約與伺服器建立的模擬惡意判定，驗證判定後流程。它不提供真實攻擊偵測或遠端來源認證；領域的正式部署仍須完成自己的契約、來源及流量對照。

## 建置、選領域及啟動

需要 Docker Engine 或 Docker Desktop、Compose v2，以及建置時取得 Python 映像及依賴的網路。在專案根目錄執行：

```powershell
$env:MIRAGE_DOMAIN = 'ecommerce'
docker compose config
docker compose up --build -d --wait --wait-timeout 180
docker compose ps
curl.exe --fail http://127.0.0.1:8000/healthz
curl.exe --fail http://127.0.0.1:8000/demo/info
docker compose exec mirage python -m deception.domains --list-domains
docker compose exec mirage python -m deception.domains --domain ecommerce
```

`--domain ecommerce` 查詢此領域的情境目錄及狀態，不會自行啟用弱點。未知領域、缺少資產、未註冊實作及不符的 manifest 都拒絕，不回退電商。新增領域需提供自己的情境、資料供應、展示及 verifier 實作並明確註冊；只新增 YAML 不會執行程式碼。新領域展示須提供健康診斷端點，才可沿用映像的 `/healthz` 檢查。

`Dockerfile` 使用官方 `python:3.13.13-slim-bookworm`，先建 wheel 再安裝；執行 UID/GID 為 `10001:10001`。Compose 只向主機 loopback 發布 HTTP，根檔案系統唯讀，輸出 volume 及 `/tmp` 可寫。Uvicorn 停用自動 Server／Date、proxy headers 及 access log。健康檢查只確認入口可回應，不代表模型或真實平台已通過驗證。

## 共用 input 與設定優先序

根應用設定 `configs/app.yaml`：

```yaml
schema_version: 1
domain: ecommerce
domains_dir: domains
```

| 設定 | 功能與位置 |
| --- | --- |
| `MIRAGE_APP_CONFIG` | 共用應用設定檔；容器預設 `/app/configs/app.yaml` |
| `MIRAGE_DOMAIN` | 管理者明確選擇已註冊領域，覆寫應用設定的 `domain` |
| `MIRAGE_DOMAINS_DIR` | 領域資產根目錄，覆寫 `domains_dir`；容器預設 `/app/domains` |
| `MIRAGE_SECURITY_TAXONOMIES_DIR` | 共用版本化安全分類目錄，容器預設 `/app/inputs/security_taxonomies` |
| `MIRAGE_LLM_CONFIG` | 共用本機模型名稱、digest、解碼與規劃設定，容器預設 `/app/configs/llm.yaml` |
| `MIRAGE_DEMO_MODE` | 展示模式；`fallback` 刻意不啟動模型，`local` 嘗試已核對的本機模型 |
| `MIRAGE_DEMO_ORIGIN` | 管理者綁定實際 HTTP origin，必須與收到的 Host／埠一致 |
| `MIRAGE_OUTPUT_ROOT` | 共用可寫輸出根目錄，容器預設 `/app/generated`；展示會再分隔至 `domains/<domain>/` |
| `MIRAGE_DEMO_OUTPUT` | 相容的明確展示目錄覆寫；提供時直接使用該路徑，不再附加領域子目錄，Docker 不預設此值 |
| `MIRAGE_DEMO_CONFIG` | 選用的明確展示設定覆寫；沒有預設硬指某領域，未提供時由選定包的 manifest 找到設定 |

選擇順序為應用設定加管理者環境覆寫，再核對選定領域的 `domain.yaml` 與實作；訪客請求不能改選擇。領域 manifest 的資產路徑須留在包內，且不能指定 Python 匯入路徑。各領域展示檔案的欄位限制、覆寫規則及弱點選擇方式，在自己的文件說明。

映像帶入共用 `configs/`、共用 taxonomy 與 `domains/`；各領域的契約、政策、README 及其他資產隨包提供。這不代表包內示例已獲正式部署核准。本機環境、憑證、產物、快取與 Git bundle 由 `.dockerignore` 排除。

若用自己的領域包或設定，以唯讀掛載提供：

```yaml
services:
  mirage:
    environment:
      MIRAGE_DOMAIN: ecommerce
    volumes:
      - ./configs/app.yaml:/app/configs/app.yaml:ro
      - ./domains/ecommerce:/app/domains/ecommerce:ro
      - ./inputs/security_taxonomies:/app/inputs/security_taxonomies:ro
      - ./configs/llm.yaml:/app/configs/llm.yaml:ro
```

此例明確選電商，不是所有領域共用的商品設定。未掛載時修改主機檔案須重建映像；設定於啟動時讀取，不在訪客請求間重新選模型、核准來源或執行新程式碼。

每次啟動在 `generated/domains/<domain>/` 下建立獨立子目錄，保存該領域的契約、Profile、資料、政策與內容快取。共用 HTTP verifier 的預設報告為 `generated/domains/<domain>/verification/http-api.json`；`--output` 可明確覆寫報告位置。電商匯出範例只複製已選領域，停止時保留產物：

```powershell
docker compose cp mirage:/app/generated/domains/ecommerce ./ecommerce-output
docker compose down
```

`docker compose down -v` 會刪除命名 volume，包含產物與可選模型下載內容；需保留時先匯出。

## 呼叫與驗證

共用健康與展示資訊可用上方 HTTP 命令讀取；業務端點及 schema 由選定領域定義。電商的簡短例子：

```powershell
$info = Invoke-RestMethod http://127.0.0.1:8000/demo/info
$productId = $info.product_ids[0]
curl.exe -i "http://127.0.0.1:8000/api/products/$productId" -H 'X-Request-ID: example-001'
docker compose exec mirage python tools/verify_domain_api.py --domain ecommerce --base-url http://127.0.0.1:8000 --output /app/generated/domains/ecommerce/verification/http-api.json
```

商品矩陣、固定資料與電商專用弱點只在 [電商文件](../domains/ecommerce/docs/usage.md) 詳述。其他領域須使用自己的 verifier；共用工具不直接讀商品欄位。CLI 的共用輸入、結果及失敗碼見 [領域驗證工具](verification.md)。舊 `tools/verify_ecommerce_api.py` 僅保留相容轉出。

`MIRAGE_HTTP_PORT` 預設 8000，同時調整主機公開埠與展示 origin。若改成 8001，主機直接連 `http://127.0.0.1:8001`；容器仍監聽 8000，容器內 verifier 可明確使用 `--base-url http://127.0.0.1:8000 --host-header 127.0.0.1:8001`。Host 的可接受範圍仍由領域 verifier 核對。

## 本機模型

可選 `local-model` profile 讓 Ollama 透過 `network_mode: service:mirage` 與應用程式共享網路命名空間，只監聽 `127.0.0.1:11434`，不發布模型埠。這保留模型工具的 loopback 限制，不能直接把容器的 localhost 當成 Windows 或遠端電腦。參考 [Compose 網路模式](https://docs.docker.com/compose/how-tos/networking/) 與 [Ollama Docker 文件](https://docs.ollama.com/docker)。

```powershell
$env:MIRAGE_DOMAIN = 'ecommerce'
$env:MIRAGE_DEMO_MODE = 'local'
docker compose --profile local-model up --build -d --wait --wait-timeout 180
docker compose exec ollama ollama list
```

Compose 不自動下載模型。確認精確權重及 tokenizer 的 LICENSE／NOTICE 後才明確下載，例如設定中的 Foundation Reasoning 量化模型。預設模型及完整 digest 見 [模型工具說明](llm.md)，不能以短 ID 代替。`local` 只是設定，模型失敗後若採明確備援，結果仍須標示實際來源；不能把備援當成真模型成功。

此 profile 預設 CPU，沒有自動要求 GPU。GPU、自架模型或遠端通道應依實際環境另外配置及驗證，不以放寬端點檢查替代。

## 各共用元件的功能與目的

| 元件名稱 | 功能與目的 |
| --- | --- |
| 領域資產載入器與註冊表 | 明確選定領域、檢查路徑及資產身份，拒絕未知或任意程式碼入口 |
| 共用模型與資料交換 | 嚴格核對隔離 scope 與通用 JSON 投影；具體實體驗證由領域供應器負責 |
| 安全分類與情境目錄 | 維護版本化 OWASP 參照、領域映射及設計／已實作狀態，不自動執行漏洞 |
| HTTP 請求入口 | 保留原始請求、限制大小及處理追蹤 ID |
| 平台識別與 Profile 工具 | 核對部署、契約、版本及操作，提供可追溯 schema |
| 情境引擎與領域資料供應器 | 共用身份／判定檢查，具體業務選擇及資料關聯由領域處理 |
| 任務協調器與生成上下文 | 固定一次請求的身份、政策、資料與模型版本，共用總預算 |
| 內容生成與模型工具 | 僅生成明確允許欄位，核對本機模型及用量，不變更權威資料 |
| 修正與備援工具 | 有上限地重新生成，或採精確同契約／同結果固定值 |
| 回應組合與契約驗證器 | 套用明確映射、嚴格序列化並驗證同一份候選 |
| HTTP 回送器 | 完成最終標頭再驗證，原樣送出 bytes，阻擋修改及過期 |
| 領域 HTTP 驗證工具 | 派送領域自己的案例並保存可重建結果，不以單一領域代表通用有效性 |

介面、限制及套件版本見 [工具索引](README.md)，領域與輸出分隔見 [領域包說明](domains.md)，通用資料投影見 [共用模型與資料交換](common-data.md)，弱點設計原則見 [OWASP 說明](owasp-design.md)。

## 正式接入及執行限制

正式部署應以已審查的領域來源、部署綁定、政策、資料及可信判定供應器建立 app，再使用 `deception.api.pipeline.create_app`。用同一映像覆寫 Uvicorn app module 即可，不把展示的模擬判定當成來源認證。正式輸入唯讀掛載，輸出目錄由應用程式 UID 寫入；壓縮、CORS、反向代理等回應改寫必須納入最終驗證邊界。

歷史電商與 Medusa 實測保存在 [電商稽核目錄](../domains/ecommerce/docs/audits/)，不能用舊結果宣稱新領域、所有 OWASP 類別或新映像皆已通過。本機沒有可用 Docker，因此未宣稱 build／run 實測；後續可用 [容器驗證工作流程](../.github/workflows/container-smoke.yml) 建置映像、等待健康檢查、執行已選領域 verifier 並保存報告。加入工作流程不等於已執行。

基底映像固定 patch tag，但 tag 不是不可變 digest；build 時依 `pyproject.toml` 解析套件。正式發行需記錄映像 digest、完整依賴及實際包含內容，再對目標環境重測。

## 套件與權重授權

| 元件 | 授權與界線 |
| --- | --- |
| [Python 官方映像建置檔](https://github.com/docker-library/python/blob/master/LICENSE) | MIT；CPython 另依 PSF 及隨附聲明 |
| [setuptools](https://github.com/pypa/setuptools/blob/main/LICENSE) | MIT；沿用專案已宣告建置工具 |
| [GitHub checkout](https://github.com/actions/checkout/blob/v4/LICENSE)、[upload-artifact](https://github.com/actions/upload-artifact/blob/v4/LICENSE) | MIT；僅 CI，不加入執行映像 |
| Debian 套件 | 各套件自己的授權，不把整個 OS 視為 MIT |
| 既有 FastAPI、Pydantic、PyYAML、Faker、jsonschema、Pydantic AI | MIT；領域若未使用某套件不代表必須依賴其業務模型 |
| Starlette、Uvicorn、openapi-core、Werkzeug | BSD-3-Clause，保留對應版本聲明 |
| Ollama runtime | MIT，僅程式，模型權重另行管理 |
| Foundation Reasoning 權重 | 底層 Llama 3.1 Community License 與 Cisco 修改部分 Apache-2.0 分開管理 |

精確版本、主要間接依賴與權重條款見 [模型整合授權](orchestration.md#套件模型與資料授權) 及各領域文件。分類文字及 OWASP 來源權利見 [OWASP 設計](owasp-design.md)。封裝未新增 Python 執行期套件；此表不是完整容器 SBOM，也未替 Mirage_API 原始碼選定授權。
