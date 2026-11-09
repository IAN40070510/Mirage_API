# 專案授權與第三方材料

## 用途與適用範圍

Mirage_API 自行撰寫的程式、測試、設定與原創說明文件採 **Apache License 2.0**，完整條款見根目錄 [LICENSE](../LICENSE)，專案歸屬與第三方材料摘要見 [NOTICE](../NOTICE)。Apache-2.0 包含第 3 條所定範圍的專利授權，不代表授權人交出全部專利，也不會把第三方材料改成 Apache-2.0。

本頁區分程式、API 規格、分類資料與模型權重，供使用、修改及封裝本專案時查閱。第三方原文、資料與權重依各自的授權處理；沒有明確再授權的材料不因放在本儲存庫中而取得新的權利。

| 材料 | 適用授權與邊界 |
| --- | --- |
| 本專案原創程式及文件 | Apache-2.0；見根目錄 `LICENSE`、`NOTICE` |
| Medusa 固定來源的 OpenAPI 子集及保留的上游內容 | MIT，保留上游版權與許可聲明；見 [Medusa-MIT.txt](../licenses/Medusa-MIT.txt) |
| `inputs/security_taxonomies/` 兩份 OWASP 分類 YAML 及其分類翻譯 | CC-BY-SA-4.0；見 [CC-BY-SA-4.0.txt](../licenses/CC-BY-SA-4.0.txt)，不納入自有程式的 Apache-2.0 範圍 |
| 安裝或封裝的第三方 Python／系統套件 | 依實際版本的原 LICENSE、版權、免責聲明及適用 NOTICE；既有清單見 [專案套件表](../README.md#開源軟體模型與資料授權) |
| 外部模型及 tokenizer | 各自的權重與使用條款；本儲存庫及預設應用映像不打包模型權重 |

## Medusa 來源與修改

以下兩份規格保存相同的固定來源子集：

- [平台規格工具來源](../domains/ecommerce/inputs/sources/medusa/openapi.yaml)。
- [契約驗證器來源](../domains/ecommerce/inputs/platforms/medusa/openapi.yaml)。

它們依 Medusa `v2.22.4` 的固定 commit `81edb06c323812773c9c0dcc4da2d9784f3b3319` 之 Store API 規格整理，保留部分操作及其依賴 schema，並依固定官方內容修正。上游原文採 MIT，版權為 `Copyright (c) 2021 Medusajs`；本專案保留完整 [上游授權副本](../licenses/Medusa-MIT.txt)，不將這些上游內容改標為 Apache-2.0。固定來源與修改紀錄見 [Medusa 來源說明](../domains/ecommerce/inputs/platforms/medusa/README.md) 及 [修正稽核](../domains/ecommerce/docs/audits/medusa-v2.22.4-contract-2026-11-08.md)。

授權整理不更動 OpenAPI bytes、來源 SHA-256 或 `approved: false`。API 規格的授權聲明不等同目標部署核准，也不證明所有執行行為與官方服務一致。自製 PoC 契約及合成回應樣本的用途另見 [PoC 說明](poc.md)。

## OWASP 分類資料

兩份 [API Security 2023](../inputs/security_taxonomies/owasp-api-security-2023.yaml)、[Web Top 10 2025](../inputs/security_taxonomies/owasp-web-2025.yaml) 分類檔保留原專案出處、版次及 CC-BY-SA-4.0 標示。中文名稱是本專案翻譯，YAML 為本專案重新編排；分發這些改作分類資料時，保留來源、授權及修改說明，並依 CC-BY-SA-4.0 處理改作內容。

這項分類資料授權與載入／驗證它的程式碼分開；不因程式讀取分類檔，就把整套自有程式改成 CC-BY-SA。分類引用、領域映射與未實作情境的限制見 [OWASP 設計說明](owasp-design.md)，不宣稱 OWASP 背書本專案。

## 模型及套件

專案透過既有 Pydantic AI／Ollama 介面使用管理者另外安裝的模型，不在本儲存庫或預設應用映像內附 Foundation 模型權重。預設 Foundation Reasoning 變體含底層 Llama 3.1 與 Cisco 修改部分的不同條款，不能只用本專案 Apache-2.0 或 Ollama 程式的 MIT 代表整份權重授權。來源及詳細區分見 [模型與間接套件授權](orchestration.md#套件模型與資料授權)。

若另外分發模型、tokenizer、第三方套件或容器基底材料，需保留實際包含版本要求的授權與聲明。本頁及 README 清單不是完整 SBOM；僅參考的 Galah 等專案也不因此成為已打包依賴。

## 封裝輸入、產物與失敗處理

建置輸入包含根 `LICENSE`、`NOTICE` 與 `licenses/*.txt`。`pyproject.toml` 以 PEP 639 的 `license = "Apache-2.0"` 標示自有套件，並以 `license-files` 納入這些聲明；建置後端最低為 `setuptools>=77`。

wheel／sdist 應保留上述授權與聲明。Docker 建置階段複製這些檔案，執行映像亦在 `/app/LICENSE`、`/app/NOTICE` 與 `/app/licenses/` 保留可閱讀副本。領域 API 規格與分類資料仍是獨立部署資產，不因附在同一映像而變更原授權。設定與產物位置見 [Docker 說明](docker.md)。

若建置時找不到授權檔、建置後端不支援中繼資料，或發行產物漏帶第三方聲明，應先修正建置輸入並重新封裝，再分發產物；不能用 README 連結代替應隨附的許可聲明。這些檔案不改模型、網路或應用程式的執行生命週期。

## 驗證方式與目前限制

在專案根目錄執行：

```powershell
.\.venv\Scripts\python.exe tools/check_documentation.py
.\.venv\Scripts\python.exe -m pip wheel --no-deps --wheel-dir generated/releases/wheels .
.\.venv\Scripts\python.exe -m zipfile -l generated/releases/wheels/mirage_response_validator-0.1.0-py3-none-any.whl
```

確認 wheel 的 `.dist-info/licenses/` 包含根授權、NOTICE 及第三方授權副本；sdist 亦應包含相同檔案。版本號變更時，以實際產出的檔名檢查。容器另確認 `/app/` 的聲明副本。文件檢查只核對註解及本地連結，不代替封裝檢查、第三方完整授權盤點或專利審查。

本頁沒有新增執行期套件、模型或授權條款；正式條文以各隨附原文為準。授權採用不提升來源核准、不完成真實部署相容性，也不代表所有專利、商標或資料權利均由本專案持有。
