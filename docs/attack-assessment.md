# 可信攻擊判定與 provider 接入

## 這項輸入是什麼

**可信攻擊判定是外部偵測系統對「某一筆 API 請求」做出的判斷，由你的整合層驗證來源後交給 Mirage_API。** 它回答：誰做出判定、判定對應哪個請求與服務、是否確認為攻擊，以及判定何時有效。

例如，外部偵測器認為某筆請求帶有 SQL 注入特徵，整合層把結果轉成 `AttackAssessment`。Mirage_API 核對來源、請求關聯、部署身份及期限，再依領域政策決定是否生成誘餌回應。這不表示套件本身偵測出了 SQL 注入，也不表示原服務真的有該漏洞。

外部系統可以是你的分類模型、WAF 或其他偵測服務；它們原本的輸出格式不必相同，但轉接程式最後必須提供本文件定義的物件。此介面適用於所有領域，電商只是目前內建的領域實作。

```text
API 請求 → FastAPI 標準化 → provider → 判定關聯與時效核對 → 情境、生成與驗證
                              ↑
                  你的整合層提供已認證來源的判定
```

## 「可信」由誰負責

| 責任 | 目前由誰完成 |
| --- | --- |
| 分析請求是否為攻擊 | 外部偵測系統；本套件沒有內建攻擊偵測器 |
| 認證判定的實際傳送者，限制它能使用哪些 `source_id` | 你的接收／整合層 |
| 將外部結果轉成 `AttackAssessment` 並交給流程 | 你注入的 `assessment_provider` |
| 核對欄位、來源白名單、請求指紋、部署身份、期限及規則 | Mirage_API 的 HTTP 整合與情境引擎 |
| 決定允許的誘餌分支、生成欄位及回應契約 | 管理者設定的領域政策與後續工具 |

`source_id` 是來源名稱，`trusted_sources` 是允許的名稱清單，兩者都不是來源認證。訪客自行傳入 `X-Assessment-Verdict: malicious` 或 JSON 的 `trusted: true`，不會因此成為可信判定。

目前已有 provider 注入介面，**沒有公開的判定接收 API、內建來源驗簽、來源帳號管理或事件去重儲存**。整合層必須先建立信任，再交付結果；不能只因回傳物件通過 Pydantic 型別檢查，就宣稱來源已被認證。

## 輸入與輸出介面

```python
from collections.abc import Awaitable, Callable

from deception.api.ingress import NormalizedRequest
from deception.scenarios import AttackAssessment

AssessmentProvider = Callable[
    [NormalizedRequest],
    AttackAssessment | Awaitable[AttackAssessment],
]
```

- 輸入：HTTP 入口產生的 `NormalizedRequest`，包含追蹤 ID、method、URL、原始 path／query、依序保留的標頭及 body bytes。
- 輸出：這筆請求對應的 `AttackAssessment` 實例。provider 可以是同步或非同步函式。
- 失敗：資料不存在、來源認證失敗、解析錯誤或查詢逾期時應明確失敗，不應自行補成 `malicious`。完整 HTTP 接入會停止生成並回固定診斷。

provider 直接回傳 `dict`、JSON 字串或 `None` 都不符合介面。若外部資料是 JSON 文字，先使用 `AttackAssessment.model_validate_json(raw_json)` 解析，再回傳模型實例。

## 判定資料格式

以下是序列化後的 JSON 格式。指紋、身份及時間都是示意值，不能直接當成目前展示服務的有效判定。

```json
{
  "assessment_id": "assessment-001",
  "source_id": "detector-01",
  "request_id": "request-001",
  "request_fingerprint": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "environment_id": "production",
  "deployment_id": "deployment-01",
  "service_id": "public-api",
  "site_id": "site-01",
  "verdict": "malicious",
  "attack_types": ["sql-injection"],
  "observed_at": "2026-11-10T10:00:00Z",
  "expires_at": "2026-11-10T10:01:00Z"
}
```

| 欄位 | 必填 | 意義與限制 |
| --- | --- | --- |
| `assessment_id` | 是 | 這次判定的識別碼；不是防重放憑證，目前沒有依此欄位做事件去重 |
| `source_id` | 是 | 偵測來源名稱，須在領域情境政策的 `trusted_sources` 中，且由接收層認證其使用權限 |
| `request_id` | 是 | 必須與目前標準化請求相同；模型要求 1–128 字元 |
| `request_fingerprint` | 是 | `fingerprint_request(request)` 的結果，64 位小寫十六進位 SHA-256 字串 |
| `environment_id` | 是 | 環境，例如 `production`；須符合平台識別結果 |
| `deployment_id` | 是 | 部署實例，例如 `deployment-01`；須符合平台識別結果 |
| `service_id` | 是 | 目標服務，例如 `public-api`；須符合平台識別結果 |
| `site_id` | 是 | 站點身份，例如 `site-01`；須符合平台識別結果 |
| `verdict` | 是 | 僅接受 `malicious`、`benign`、`unknown` |
| `attack_types` | 否 | 自訂攻擊標籤清單，最多 64 個字串；省略時為 `[]` |
| `observed_at` | 是 | 偵測觀察時間，必須包含時區，模型會轉成 UTC |
| `expires_at` | 是 | 判定到期時間，必須包含時區且晚於 `observed_at` |

除 `request_id` 外，上表各識別碼欄位使用 `^[a-z0-9][a-z0-9._-]{0,63}$`：小寫英數起頭，總長 1–64 字元，可包含 `.`、`_`、`-`。這個規則不套用在指紋、時間、verdict 或攻擊標籤上。

HTTP 入口對 `X-Request-ID` 另有限制：英數起頭，後續只允許英數、`.`、`_`、`-`，總長最多 128；缺少時產生 UUID，重複或無效值會拒絕。這個 ID 供關聯使用，訪客知道或重用它不等於通過來源認證。

模型採嚴格型別並拒絕未知欄位。目前沒有 `confidence`、`score`、`evidence`、`domain`、`platform_id` 或 `trusted` 欄位。若偵測器有這些資訊，你的 adapter 應依其協定明確轉換並另外管理紀錄，不可直接把完整上游 JSON 當成 `AttackAssessment`。領域、平台及契約由伺服器設定與識別工具決定。

JSON 中的 ISO 時間字串應使用 `model_validate_json()` 解析。若直接以 Python 字典呼叫嚴格的 `model_validate()`，時間欄位應提供帶時區的 `datetime` 物件；不要把這兩種輸入方式混用。

## 如何確認是同一筆請求

請使用專案提供的 `fingerprint_request(request)`。它對以下內容做固定 JSON 序列化後計算 SHA-256：

- `request_id`、method、原始 URL 及 path。
- 原始 path bytes 與 query bytes 的十六進位表示。
- 保留順序與重複值的 query 配對及標頭配對。
- body bytes 的 SHA-256。

因此只對 body 做雜湊、把重複 query 轉成字典，或在代理處改寫 URL／標頭，都可能讓指紋不一致。偵測器與整合層應使用同一份標準化請求，或建立可核對的對應流程。

**不要取回舊判定後，直接把其指紋改成目前請求的指紋來通過檢查。** 應保留偵測當時的指紋，或確保外部偵測器剛分析的就是同一份請求後，再建立新判定。

指紋只是關聯摘要，不是數位簽章、來源認證或完整防重放機制。相同請求與相同 ID 在有效時間內重送，目前不會只因 `assessment_id` 重複而拒絕。需要一次性處理、去重或防重放儲存時，必須由你的接收層另外實作。

## 有效時間與等待期限

情境引擎只接受下列有效區間：

```text
observed_at <= 現在時間 < min(expires_at, observed_at + max_age_seconds)
```

`max_age_seconds` 由管理者的情境政策設定，預設 300 秒，可設 1–3600 秒。例如觀察時間是 10:00、到期時間是 10:10，但政策上限為 300 秒，實際只到 10:05 前有效。尚未生效或恰好到期的判定都會拒絕；部署時應讓相關主機的時鐘保持一致。

取得判定另有 `assessment_timeout_seconds`，預設 15 秒，只接受有限數值且 `0 < value <= 120`，不接受布林值。它限制 provider 的等待時間，不會延長判定有效時間，也不屬於稍後才建立的生成預算。

同步 provider 若阻塞，無法保證在中途強制停止；超過期限才返回也會被拒絕。查詢外部服務時應由整合程式設定自己的連線／讀取期限，避免阻塞事件迴圈。取消會向外傳遞，不會繼續產生備援回應。

## verdict、攻擊標籤與處理結果

以下行為以完整 HTTP 接入、啟用政策及必要身份檢查為前提：

| 判定或條件 | 情境／流程結果 | HTTP 接入行為 |
| --- | --- | --- |
| `malicious` 且命中唯一有效規則 | 繼續選擇領域分支、生成及驗證 | 依通過契約的分支回送，可能是 200、404 或其他已實作狀態 |
| `malicious` 但沒有命中規則 | `not_applicable` | 409，`pipeline_not_applicable` |
| `benign`，其來源與關聯等檢查亦通過 | `not_applicable` | 409，不自動轉送原服務 |
| `unknown` | `unverifiable` | 503，`pipeline_unavailable` |
| 來源、請求、部署身份或期限不符 | 不產生可用候選 | 503，`pipeline_unavailable` |
| provider 缺資料、回傳型別不符、解析失敗或逾時 | 不進入後續生成 | 503，`pipeline_unavailable` |

`attack_types` 是你與政策約定的精確字串標籤，沒有自動大小寫轉換或 OWASP 映射。規則的 `attack_types` 清單為空時不限類型；清單有值時，須與判定的標籤至少有一個完全相同。因此 `sql-injection` 與 `SQL_INJECTION` 不會自動視為相同。

判定標籤也不會自動切換展示的 `weakness_scenario`；目前該弱點設定在啟動時選定。把請求判為 `malicious` 不代表一定回 200，更不代表可以繞過契約驗證。

409／503 是完整入口的固定診斷，不是假裝成目標服務的有效回應。其他入口檢查可能先回 400／413；最終 ASGI 送出時的取消、期限或完整性錯誤由伺服器處理，不能一概保證回 503，詳見 [HTTP 回送邊界](renderer.md)。

## 可離線執行的 provider 範例

以下範例只驗證資料格式與 provider 接法，不連網、不啟動模型，也不實作來源認證。`verified_json` 模擬「接收層已完成來源認證及請求關聯後」保存的資料；正式部署必須用真正的認證整合取代這段測試資料建立流程。

```python
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone

from deception.api.ingress import NormalizedRequest
from deception.scenarios import AttackAssessment, fingerprint_request


def make_assessment_provider(verified_json: Mapping[tuple[str, str], str]):
    """複製已認證判定的查詢快照，回傳依請求 ID 及指紋查詢的 provider。"""
    records = dict(verified_json)

    def assessment_provider(request: NormalizedRequest) -> AttackAssessment:
        """回傳同一請求的嚴格判定；缺資料、格式錯誤或關聯不符時拋出例外。"""
        fingerprint = fingerprint_request(request)
        raw_json = records[(request.request_id, fingerprint)]
        result = AttackAssessment.model_validate_json(raw_json)
        if (result.request_id, result.request_fingerprint) != (
            request.request_id, fingerprint
        ):
            raise ValueError("Verified assessment does not match this request")
        return result

    return assessment_provider


# 手工快照僅供離線示範，不代表目前服務已有 /api/resources 端點。
request = NormalizedRequest(
    request_id="request-doc-001",
    method="GET",
    raw_url="http://127.0.0.1:8000/api/resources/resource-001",
    path="/api/resources/resource-001",
    raw_path=b"/api/resources/resource-001",
    query_string=b"",
    query=(),
    headers=(("host", "127.0.0.1:8000"),),
    body=b"",
)
now = datetime.now(timezone.utc)

# 僅限本機示範：此處沒有外部偵測器，也不能宣稱已完成來源認證。
example = AttackAssessment(
    assessment_id="assessment-doc-001",
    source_id="detector-01",
    request_id=request.request_id,
    request_fingerprint=fingerprint_request(request),
    environment_id="local-test",
    deployment_id="deployment-01",
    service_id="public-api",
    site_id="site-01",
    verdict="malicious",
    attack_types=["sql-injection"],
    observed_at=now,
    expires_at=now + timedelta(seconds=60),
)
verified_json = {
    (example.request_id, example.request_fingerprint): example.model_dump_json()
}
assessment_provider = make_assessment_provider(verified_json)
result = assessment_provider(request)
assert isinstance(result, AttackAssessment)
assert result.request_fingerprint == fingerprint_request(request)
print(result.model_dump_json(indent=2))
```

這個範例會輸出包含當下時間及正確指紋的判定，但不會呼叫情境引擎或建立 HTTP 回應。正式 provider 應使用入口傳入的真實 `request`，不能用手工快照替換它。若資料來源改為資料庫或遠端服務，可改成非同步 provider；外部連線與關閉由你的整合程式管理。

## 接入完整流程與政策

在你的部署程式已建立並核對工具後，將 provider 注入完整入口：

```python
from deception.api.pipeline import create_app

# 下列工具、runtime、資料設定及快照由你的部署程式建立；不是內建全域變數。
app = create_app(
    orchestrator=prepared_pipeline,
    runtime=trusted_runtime,
    generation_config=checked_data_config,
    dataset=checked_dataset,
    assessment_provider=assessment_provider,
    assessment_timeout_seconds=15.0,
)
```

部署身份要與來源判定一致。領域情境政策另需設定 `trusted_sources`、`max_age_seconds`，並提供啟用且符合平台、契約、操作、query 及攻擊標籤條件的完整規則；只有把來源放進白名單不會產生誘餌。組裝與啟動方式見 [完整 HTTP 接入](renderer.md#可選的-http-請求入口--任務協調器--http-回送器接入) 及 [任務協調器](orchestration.md)。

隔離展示的 provider 位於 `deception.domains.ecommerce.http_demo`，會為進入展示處理流程的請求建立 `simulated_malicious` 測試判定。這方便驗證判定之後的流程，不能當成外部偵測器或來源認證已完成的證據。展示使用的政策由工廠建立，不會自動啟用 repository 的停用政策範本。

## 失敗診斷與驗證方式

情境引擎的內部問題碼可用來追查判定核對失敗；HTTP 對外只提供固定診斷，不回顯這些細節或原始請求內容：

| 內部問題碼 | 意義 |
| --- | --- |
| `assessment_missing` | 直接呼叫情境引擎時沒有提供判定 |
| `assessment_source` | 來源名稱不在白名單 |
| `assessment_request` | 請求 ID 或指紋不符 |
| `assessment_context` | 環境、部署、服務或站點不符 |
| `assessment_expired` | 尚未生效、已過期或超過政策年齡上限 |
| `assessment_unknown` | 判定為 `unknown`，無法確認適用誘餌政策 |
| `rule_not_unique` | 多條最高優先序規則同時命中 |

無效資料模型可能被分類為一般準備失敗，而非上述單一問題碼；不能假設訪客會收到內部錯誤文字。紀錄問題時宜保留必要的判定 ID、來源 ID 與固定問題碼，避免把 Authorization、完整 body 或偵測器秘密資料寫進回應或紀錄。

```powershell
$env:PYTHONPATH = "$PWD/src"
.\.venv\Scripts\python.exe -m pytest tests/test_scenarios.py tests/test_pipeline_api.py tests/test_ingress.py -q
.\.venv\Scripts\python.exe tools/check_documentation.py
```

測試涵蓋來源白名單、請求及部署關聯、時效、標籤匹配、provider 型別與逾時、取消，以及原始 HTTP 資料保留。它們驗證本套件邊界，不代替你選用的外部偵測器準確率、接收層來源認證或防重放測試。上方離線範例可另存為 Python 檔，在已安裝相依套件且設定 `PYTHONPATH` 的環境執行。

## 套件、授權與目前限制

本介面沿用 Pydantic（MIT）處理嚴格資料模型，HTTP 整合沿用 FastAPI（MIT）與 Starlette（BSD-3-Clause）；指紋、時間及範例查詢使用 Python 標準庫。沒有新增套件或偵測模型，也沒有在判定解析時呼叫 Ollama。自有程式及原創文件採 Apache-2.0，第三方與模型權重條款見 [專案授權](licensing.md) 與 [元件授權表](orchestration.md#套件模型與資料授權)。

目前限制包括：沒有公開判定接收器、內建來源認證、事件去重、防重放儲存、攻擊標籤標準化或 OWASP 自動分類；`benign` 不會自動轉送原服務。這些能力若由部署整合新增，須另外記錄協定、設定、失敗處理及驗證結果。
