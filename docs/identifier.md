# 平台識別器

## 功能確認

平台識別器以明確部署設定識別 HTTP 請求入口收到的請求，輸出唯一的站點、平台版本、契約與操作，交給任務協調器／平台規格工具使用。程式位於 `src/deception/discovery/`。這個版本不從路徑關鍵字、網站內容或請求自稱的 headers 推測平台，也不執行攻擊偵測。

| 輸入／功能 | 本次行為 |
| --- | --- |
| 部署綁定 | `domains/ecommerce/configs/bindings.yaml` 明確設定 environment、deployment、service、site、origin／prefix、平台、版本、hash 與 enabled |
| 可信執行環境 | 可由伺服器傳入 `RuntimeContext`，不由 HTTP 的 `X-Environment-ID`、Forwarded 或 X-Platform 自動填入 |
| 契約載入 | 重用 `PlatformRegistry`，核對原始檔 hash、內部引用、OpenAPI 與 manifest；無效來源使載入失敗 |
| 站點匹配 | scheme／authority 與 prefix segment 邊界匹配；不把 `/api` 當成 `/apix` |
| 操作匹配 | 先找唯一 path，靜態 exact 優先，再檢查 method；歧義或缺操作就拒絕 |
| query | 只接受 manifest 明列的已審組合，保留空值與重複值順序 |
| 原始編碼 | 使用 HTTP 請求入口的 `raw_url`，不使用已解碼 `path` 重新選路由；path parameters 保留 percent encoding |
| 識別結果 | `identified` 或 `unverifiable`；不使用契約驗證器的 response `pass`／`valid` 語意 |
| 下游介面 | `identity.profile_arguments()` 提供平台規格工具的精確查詢 keys；僅平台識別 handler 成功仍回診斷 501，完整任務協調器/HTTP 回送器接入另由 `deception.api.pipeline` 提供 |

識別成功要求部署 binding 已 enabled、契約 manifest 已 approved、平台／版本／hash／base URL 一致、query 已審查，以及 operation 唯一。binding 的 enabled 不代表來源核准，平台識別器也不會改寫來源、平台 Profile 或契約驗證器 manifest。

## 已有與網上方案評估

| 方案 | 可重用能力 | 授權 | 本次選擇 |
| --- | --- | --- | --- |
| 本 repo `PlatformRegistry` 與契約驗證器的匹配程式 | 固定契約載入、origin／prefix、query 與操作選擇 | 本專案未另選授權；上游依賴如下 | **直接重用**，抽出 `mirage_validator/request_matching.py` 供平台識別器/契約驗證器共用 |
| [openapi-core 0.19.5](https://openapi-core.readthedocs.io/en/0.19.5/reference/protocols/) | OpenAPI 規格與請求／回應協定、路徑與驗證能力 | BSD-3-Clause | 沿用既有依賴驗證規格；平台識別器不依賴其私有路由 API |
| [Connexion](https://connexion.readthedocs.io/en/stable/routing.html) | 由 OpenAPI operationId 對應 Python handler | Apache-2.0 | 已有可用的規格導向框架，但本次只需識別元件，沿用 FastAPI 與既有契約驗證器；未引入 Connexion |
| [Werkzeug Routing](https://werkzeug.palletsprojects.com/en/stable/routing/) | host、path converter、method routing | BSD-3-Clause | 已為契約驗證器的 headers 依賴，但未用它重新實作平台識別器路由；其自動排序、HEAD／slash 行為需要另外對齊契約驗證器 |
| [Starlette Routing](https://www.starlette.dev/routing/) | ASGI route、host routing、path parameters | BSD-3-Clause | 沿用 HTTP 請求入口的 FastAPI／Starlette 入口，不用 framework route 順序代替契約歧義檢查 |

本次先評估後選擇共用既有匹配器，沒有新增套件，也未複製上游路由實作。Werkzeug 的一般路由會依規則優先序選擇，平台識別器/契約驗證器則要求無法唯一判定時停止，因此不能直接以 router 的第一個命中取代契約選擇。

## 套件與授權

下列版本依本次安裝環境 metadata 核對，未鎖版者仍由 `pyproject.toml` 的範圍解析。

| 套件 | 本次版本 | 授權 | 用途 |
| --- | --- | --- | --- |
| [Pydantic](https://github.com/pydantic/pydantic/blob/main/LICENSE) | 2.14.3 | MIT | 嚴格設定與識別結果模型 |
| [PyYAML](https://github.com/yaml/pyyaml/blob/6.0.3/LICENSE) | 6.0.3 | MIT | binding 與契約設定讀取 |
| [openapi-core](https://github.com/python-openapi/openapi-core/blob/0.19.5/LICENSE) | 0.19.5 | BSD-3-Clause | 既有契約載入與契約驗證器驗證 |
| [Werkzeug](https://github.com/pallets/werkzeug/blob/3.1.1/LICENSE.txt) | 3.1.1 | BSD-3-Clause | 既有契約驗證器的 HTTP headers adapter |
| [FastAPI](https://github.com/fastapi/fastapi/blob/master/LICENSE) | 0.135.4 | MIT | 可選的 HTTP 請求入口→平台識別器 HTTP 接入 |
| [Starlette](https://github.com/Kludex/starlette/blob/main/LICENSE.md) | 1.10.0 | BSD-3-Clause | 既有 ASGI 請求與回應處理 |

標準庫的 `re`、`urllib.parse`、`dataclasses`、`pathlib` 等隨 Python 提供，依 Python 的 PSF 授權及隨附聲明管理。OpenAPI 驗證的主要間接依賴、版本與授權另見 [回應組合器套件表](composer.md#使用的套件與授權)，全專案界線見 [README 授權說明](../README.md#開源軟體模型與資料授權)。本表不是完整間接依賴 SBOM；分發實際包含的第三方套件時保存各套件的 LICENSE、版權、免責聲明及適用 NOTICE。平台識別器未修改第三方原始碼；自有程式採 Apache-2.0，個別材料邊界見 [授權總覽](licensing.md)。

## 綁定設定與使用

```yaml
schema_version: 1
bindings:
  - binding_id: medusa-demo
    environment_id: local-test
    deployment_id: medusa-demo
    service_id: storefront
    site_id: shop-example
    base_url: https://shop.example
    platform_id: medusa
    platform_version: '2.22.4'
    spec_sha256: <與manifest相同的SHA256>
    enabled: false
```

repo 的 `domains/ecommerce/configs/bindings.yaml` 只有未啟用的占位範例，沒有宣稱任何真實站點已受審查。目前 Medusa 來源及部署仍待核對，不能為了得到成功結果就將 approved 改為 true。只有完成來源、部署、base URLs 與 query 上下文審查後，才啟用相應設定。

CLI 只做本地識別，不發送 HTTP：

```powershell
$env:PYTHONPATH = "$PWD/src"
.\.venv\Scripts\python.exe -m deception.discovery --url "https://shop.example/store/products/prod-test" --method GET
```

預設範例會回 `unverifiable`／`binding_disabled` 並以非零結束碼停止。可用 `--platforms <契約目錄>` 與 `--bindings <設定檔>` 指定已審查設定。多環境需要由可信執行環境一併指定 `--environment-id`、`--deployment-id`、`--service-id`，三者必須同時提供；它們只篩選部署 binding，不會隱藏契約驗證器 registry 的重疊版本。

CLI 與僅識別 HTTP factory 未提供路徑時，都使用所選領域 manifest 的 `platform_dir` 與 `bindings_config`；共用選擇與覆寫方式見 [領域設定](domains.md)。兩個路徑都明確提供時可獨立使用，不必載入領域 manifest。

同一 URL 若在不同環境使用不同契約，應為各執行 instance 配置對應的 registry／契約驗證器，而不是把所有衝突版本載入同一 registry 再讓平台識別器偏選一個版本。集中管理、代理轉接及環境來源認證尚未實作。

## 與 HTTP 請求入口／平台規格工具接合

```python
from pathlib import Path
from deception.discovery import PlatformIdentifier
from deception.profile_builder import ProfileTool

identifier = PlatformIdentifier.from_paths(Path("domains/ecommerce/inputs/platforms"), Path("domains/ecommerce/configs/bindings.yaml"))
result = identifier.identify_request(normalized_request, context=trusted_runtime_context)
if result.decision == "identified":
    context = ProfileTool(Path("generated")).get_operation(**result.identity.profile_arguments())
```

平台規格工具仍有自己的來源審查檢查；平台識別器識別成功不會自動核准另一份平台規格工具 source。合成資料工具的 scenario、run、seed 也由任務協調器明確決定，不由平台識別器從請求自稱內容產生。

可選的 HTTP 請求入口→平台識別器接入：

```powershell
$env:PYTHONPATH = "$PWD/src"
$env:MIRAGE_DOMAIN = "ecommerce"
.\.venv\Scripts\python.exe -m uvicorn deception.api.identified:create_app --factory --host 127.0.0.1 --port 8001 --no-proxy-headers
```

`MIRAGE_ENVIRONMENT_ID`、`MIRAGE_DEPLOYMENT_ID`、`MIRAGE_SERVICE_ID` 可由部署環境同時設定。此僅平台識別入口識別失敗回 409，成功仍回 `501 orchestrator_not_implemented` 與身份摘要，保持診斷用途。完整 HTTP 請求入口→任務協調與修正備援→HTTP 回送器已可用，但須另外以伺服器可信的判定 provider 及核對後工具建立 [完整 HTTP app](renderer.md#可選的-http-請求入口--任務協調器--http-回送器接入)，不會因啟動僅平台識別入口而自動啟用。對外診斷不回顯 body、query、path parameter 值或 Authorization，`X-Request-ID` 與 HTTP 請求入口一致；HTTP server 的 access log 仍可能記錄 path／query。

HTTP 請求入口原有的 `deception.api.app:app` 仍是獨立入口。平台識別器不信任任意 Forwarded／X-* header 來覆寫綁定，但若上游 server 已重寫 scheme／host／path，HTTP 請求入口看到的 URL 就已改變；需由部署設定與可信代理界線處理。多個 Host header 會被 HTTP 請求入口→平台識別器拒絕。

## 匹配細節與有效性驗證

- origin 的 hostname 大小寫不影響匹配；scheme、明確 port 與 path prefix 維持契約驗證器的嚴格語意。例如 `https://host` 與 `https://host:443` 不自動合併。
- prefix 只在 segment 邊界吻合；兩個命中的 base 或兩個版本不採最長 prefix／載入順序自動選擇。disabled 的重疊 binding 也不會被偷偷略過作為版本回退。
- 靜態 path 優先於 template，之後才檢查 method；未選到的動態 template 不會因重複參數名而擋住有效靜態路由。對選定 template，若同一 URL 有多種合法參數拆分，例如 `/{first}{second}` 或多個分隔符造成 `{first}-{second}` 不唯一，會回 `operation_not_unique`。只有唯一可拆分的參數才交給下游。不自動把 HEAD 當 GET，也不補斜線、合併 slash 或做重導向。
- path 不解碼；`prod%2F1` 仍是單一路徑參數的原始編碼值。query 解碼為 UTF-8，保留空值與重複值的順序；不合法 percent、UTF-8、port、userinfo、fragment、控制字元或反斜線會失敗。
- 內部 `$ref` fragment 先解碼一次再解析 Pointer，解析失敗回 `contract_reference_error`。Path Item 引用只支援 summary／description sibling，其他結構 sibling（例如 servers）在原始或中間引用任何一層都會拒絕載入，與平台規格工具的限制一致，避免解引用時丟失部署覆寫。合法的 `paths.x-*` 註記不參與路由；鎖版驗證器的副本會排除這些註記，平台規格工具與回應組合器共用同一相容處理。原始檔、hash 及 response／schema 限制不改寫；引用該註記作為契約內容的用法仍不支援。

測試使用暫存合成契約驗證平台識別器/契約驗證器操作一致、靜態／動態歧義、query、percent encoding、設定與版本隔離、偽造 headers，以及 HTTP 請求入口→平台識別器、平台識別器→平台規格工具→合成資料工具→回應組合器→契約驗證器的整合。另以 repo 的 Medusa 快照確認 enabled binding 仍不能核准未審來源，不會更改 repo 的 approved 設定。

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_identifier.py tests/test_identifier_integration.py tests/test_gate.py -q
```

識別通過不是回應通過：完整回應仍須由回應組合器組合，再由契約驗證器驗證同一份 status／headers／body 及候選身份。
