# 看懂安全檢查結果：可信攻擊判定與 provider

## 先用一個例子說明

假設你另外做了一個安全檢查工具，名稱叫 `my-attack-model`。有人向 API 送出請求後，流程是：

1. 你的工具檢查這筆請求，判斷「這看起來是攻擊」。
2. 你寫的接收程式確認：結果真的是這個工具提供的，而且對應到目前這筆請求。
3. 接收程式把結果交給 Mirage_API。
4. Mirage_API 再看你設定的規則，決定要回什麼假資料，檢查格式正確後才送出。

文件中的「**可信攻擊判定**」，就是第 2 步確認過來源的安全檢查結果。程式把這份結果稱為 `AttackAssessment`。

安全檢查由你另外接入的工具負責。目前的展示程式會假造測試結果，方便測試後面的假回應流程；不能把展示結果當成真的偵測到攻擊，也不能從判定推論原服務真的有漏洞。

## 先認識這幾個名字

| 程式裡的名字 | 白話意思 | 例子 |
| --- | --- | --- |
| `source_id` | 哪個安全檢查工具提供這份結果；名稱由你事先設定 | `my-attack-model` |
| `request_id` | 這份結果對應的請求編號 | `request-001` |
| `verdict` | 工具檢查後的判斷 | `malicious` 表示判斷為攻擊 |
| `assessment_provider`，簡稱 provider | 你寫的一個函式，負責替這筆請求拿到檢查結果 | 查詢你已確認來源的結果，再交給 Mirage_API |

例如你自己的模型叫 `my-attack-model`，結果就填 `"source_id": "my-attack-model"`。你願意接受哪些工具的結果，則寫在情境設定的 `trusted_sources`，意思是「允許的來源名單」：

```yaml
# 這只是完整情境設定中的一小段。
trusted_sources:
  - my-attack-model
```

**名單上有這個名字，還要確認結果真的來自這個工具。** 接收程式不能只看對方填了什麼名字，就相信它。訪客自己傳入 `X-Assessment-Verdict: malicious` 或 `trusted: true`，也不會因此取得信任。

你現在使用的電商展示程式，測試來源名稱是 `local-demo-detector`。這個名稱只表示「展示程式產生的測試結果」。之後接你自己的工具時，可以改用你設定的名稱，並在對應的來源名單中列出。

## 哪些事情要由你做

| 事情 | 目前誰負責 |
| --- | --- |
| 檢查請求是不是攻擊 | 你另外接入的安全工具，例如自己的分類模型 |
| 確認誰送來結果，以及它能使用哪個來源名稱 | 你寫的接收程式 |
| 替目前的請求拿到結果，轉成 `AttackAssessment` | 你提供的 provider 函式 |
| 確認格式、來源名單、請求內容、目標服務及時間都對得上 | Mirage_API |
| 決定要回哪種假資料，以及模型可以修改哪些欄位 | 你事先設定的情境規則與生成規則 |

Mirage_API 已經留好「交入檢查結果」的函式介面。**目前還沒有可直接接收外部判定的公開 API，也沒有替你完成外部來源認證。** 資料格式填對，只代表程式讀得懂，仍需要接收程式確認來源。

## 判定資料格式

下面是一份完整的結果格式。時間、編號及對照碼只是示意，不能直接拿去當目前展示服務的有效結果。

```json
{
  "assessment_id": "assessment-001",
  "source_id": "my-attack-model",
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

| 欄位 | 白話意思 | 必填 |
| --- | --- | --- |
| `assessment_id` | 這一份檢查結果的編號，例如「第 001 份結果」 | 是 |
| `source_id` | 提供結果的安全檢查工具名稱 | 是 |
| `request_id` | 被檢查的那筆 API 請求編號 | 是 |
| `request_fingerprint` | 依請求內容算出的一串對照碼，用來檢查結果有沒有套到別筆請求 | 是 |
| `environment_id` | 這筆請求屬於哪個環境，例如正式環境 `production` | 是 |
| `deployment_id` | 使用哪一組部署設定，例如 `deployment-01` | 是 |
| `service_id` | 目標是哪個 API 服務，例如 `public-api` | 是 |
| `site_id` | 目標是哪個網站，例如 `site-01` | 是 |
| `verdict` | 檢查結果：判斷為攻擊、一般請求，或還不確定 | 是 |
| `attack_types` | 工具認為這是什麼類型的攻擊，例如 `sql-injection` | 否；省略時為 `[]` |
| `observed_at` | 工具檢查到這筆請求的時間 | 是 |
| `expires_at` | 這份結果最晚可以用到什麼時間 | 是 |

環境、部署、服務與網站編號，都要與 Mirage_API 已設定的目標一致，避免把別個網站的檢查結果拿來使用。

`attack_types` 使用你與規則約定好的文字。程式不會自動把它翻成 OWASP 分類，也不會幫你統一大小寫。例如 `sql-injection` 與 `SQL_INJECTION` 是不同文字。規則有指定類型時，至少一個標籤要完全相同；規則沒有指定時，就不限攻擊類型。

## 檢查結果會讓系統做什麼

以下說的是已接上完整流程、啟用對應規則，並通過來源等必要檢查後的行為。

| 情況 | Mirage_API 會做什麼 |
| --- | --- |
| `malicious`：判斷為攻擊，而且符合一條適用規則 | 進入假回應流程，依選到的情境回應；可能回 200、404 或其他已支援狀態 |
| `malicious`，但沒有適用規則 | 不產生假回應；完整入口回 409 |
| `benign`：判斷為一般請求 | 不產生假回應；完整入口回 409，目前不會自動轉送原網站 |
| `unknown`：還不確定 | 停止；完整入口回 503 |
| 結果對不上請求、網站或時間 | 不接受這份結果；完整入口回 503 |
| 拿不到結果、格式錯誤或等太久 | 停止後面的生成；完整入口回 503 |

`malicious` 只是「工具判斷這像攻擊」，不會強迫系統回 200，也不會跳過回應格式檢查。展示用的弱點設定 `weakness_scenario` 是啟動時選好的，不會因每筆結果的攻擊標籤而自動切換。

409／503 是本套件的處理通知，對外內容使用固定訊息，不會把內部錯誤或原始請求送給訪客。請求本身有問題時，入口也可能先回 400／413；真正送出回應時若被取消或發現內容已變動，處理方式另見 [HTTP 回送說明](renderer.md)。

## 怎麼確認結果對應到這筆請求

`request_id` 是請求編號，`request_fingerprint` 則是根據請求內容算出的對照碼。系統會一起比對兩者，避免只因編號相同，就把別筆結果套進來。

計算時直接使用 `fingerprint_request(request)`。它會把下列內容整理成固定格式，再算出 SHA-256 對照碼：

- 請求編號、HTTP 方法、原始網址及路徑。
- 原始路徑與查詢字串的位元組資料，轉成十六進位文字。
- 保留順序與重複值的查詢參數及標頭。
- 請求 body 的 SHA-256。

只計算 body、把重複參數壓成字典，或在中途改寫網址及標頭，都可能算出不同結果。接收程式應保留工具實際檢查的那份請求資料，讓兩邊能對照。

**拿到舊結果時，不能把它的對照碼改成目前請求的對照碼。** 那會變成把別筆結果假裝成這筆的結果。應保留當時算出的碼，或讓工具重新檢查目前這筆請求，再產生新結果。

這串碼可以幫忙對照內容，但不能證明是誰送來的。目前系統也沒有記錄某份結果是否已經用過：相同請求在有效時間內重送，不會只因 `assessment_id` 重複而拒絕。如果你希望「每份結果只能使用一次」，接收程式還要另外記錄已使用的結果；這屬於事件去重或防重放處理。

## 結果可以用多久，要等多久

這是兩件不同的事：

| 設定 | 意思 | 預設 |
| --- | --- | --- |
| `observed_at`、`expires_at` | 工具說這份結果從什麼時間開始，到什麼時間到期 | 每份結果都要填 |
| `max_age_seconds` | 你另外規定「檢查完成後最多能用多久」 | 300 秒，也就是 5 分鐘 |
| `assessment_timeout_seconds` | Mirage_API 為了拿到結果，最多等多久 | 15 秒 |

例如工具在 10:00 做完檢查，說結果到 10:10 有效；但你規定最多只能用 5 分鐘，Mirage_API 就只會在 10:05 前接受。到了 10:05 就算過期。如果時間寫在未來，系統也不會提早使用。

`max_age_seconds` 可設 1–3600 秒；`assessment_timeout_seconds` 必須大於 0、最多 120 秒，不能填布林值或無限大等特殊數值。真正的有效區間是：

```text
observed_at <= 現在時間 < min(expires_at, observed_at + max_age_seconds)
```

時間要包含時區，例如 `Z` 表示 UTC，`+08:00` 表示台灣使用的時區。程式會把時間統一轉成 UTC 再比對，相關主機也應保持時鐘一致。

等待結果的 15 秒不會延長結果本身的效期，也不會算進稍後才開始的生成時間額度。接外部服務時，接收程式仍要設定自己的連線與讀取等待上限。若同步函式卡住，程式無法保證在中途把它強制停掉；即使稍後拿到結果，超過等待上限也會拒絕。請求被取消時，流程會跟著停止。

## 接入程式的寫法

程式中，provider 接收一份 `NormalizedRequest`，也就是入口整理好的請求資料，並回傳 `AttackAssessment`。它可以是一般函式，也可以是 `async` 非同步函式，型別如下：

```python
from collections.abc import Awaitable, Callable

from deception.api.ingress import NormalizedRequest
from deception.scenarios import AttackAssessment

AssessmentProvider = Callable[
    [NormalizedRequest],
    AttackAssessment | Awaitable[AttackAssessment],
]
```

如果你拿到的是 JSON 文字，要先用 `AttackAssessment.model_validate_json(raw_json)` 轉成結果物件，再回傳。直接回傳字典、文字或 `None` 都不符合這個介面。拿不到結果或確認來源失敗時，應讓流程報錯，不要自行補成 `malicious`。

### 接程式時的格式規則

- `assessment_id`、`source_id`、環境、部署、服務及網站編號：小寫英數起頭，可包含 `.`、`_`、`-`，總長 1–64 字元。對應規則是 `^[a-z0-9][a-z0-9._-]{0,63}$`。
- `request_id`：結果格式要求 1–128 字元；HTTP 入口對 `X-Request-ID` 另要求英數起頭，後面只接受英數、`.`、`_`、`-`。缺少時由入口產生 UUID，重複或無效值會拒絕。這個編號供對照使用，不代表寄件者已被認證。
- `request_fingerprint`：64 位小寫十六進位字串，由前面的函式計算。
- `attack_types`：最多 64 個字串。
- `expires_at` 必須晚於 `observed_at`，兩個時間都要包含時區。
- 程式只接受已定義的欄位。目前沒有 `confidence`、`score`、`evidence`、`domain`、`platform_id` 或 `trusted`。上游工具有這些資料時，由你的轉接程式另外處理；不能原封不動全部塞進來。
- 從 JSON 讀取時間文字時使用 `model_validate_json()`。若直接呼叫 `model_validate()` 並傳入 Python 字典，時間欄位要放帶時區的 `datetime` 物件。

## 可離線執行的 provider 範例

這段程式會假造一筆請求和檢查結果，再讓 provider 找到該結果。你可以先用它看懂資料怎麼傳，不需要開網路服務或模型。

`verified_json` 在這裡只是假裝成「已確認來源後保存的結果」。正式接入時，這些資料必須由你真正完成來源檢查的接收程式提供。

```python
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone

from deception.api.ingress import NormalizedRequest
from deception.scenarios import AttackAssessment, fingerprint_request


def make_assessment_provider(verified_json: Mapping[tuple[str, str], str]):
    """複製已確認來源的結果，建立替每筆請求查詢結果的函式。"""
    records = dict(verified_json)

    def assessment_provider(request: NormalizedRequest) -> AttackAssessment:
        """照請求編號及內容對照碼取結果；沒有資料或對不上時報錯。"""
        fingerprint = fingerprint_request(request)
        raw_json = records[(request.request_id, fingerprint)]
        result = AttackAssessment.model_validate_json(raw_json)
        if (result.request_id, result.request_fingerprint) != (
            request.request_id, fingerprint
        ):
            raise ValueError("Verified assessment does not match this request")
        return result

    return assessment_provider


# 這是手工寫的測試請求，僅供本機示範；服務沒有因此新增 /api/resources。
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

# 這裡只假造一份測試結果，沒有真的檢查攻擊，也沒有驗證外部來源。
example = AttackAssessment(
    assessment_id="assessment-doc-001",
    source_id="my-attack-model",
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

執行後會印出結果，時間是當下時間，對照碼則依範例請求計算。它只示範結果的讀取，不會產生 HTTP 假回應，也不代表已接好外部安全工具。正式 provider 要用入口傳進來的真正請求，不能用這筆手工測試資料替代。

範例會複製一份查詢表，不會連到資料庫或外部服務。如果你之後改成遠端查詢，可以用非同步函式；連線開啟及關閉要由你的整合程式管理。

## 把接收函式交給 Mirage_API

你的部署程式先準備好流程需要的工具及設定，再把 provider 傳給 `create_app()`：

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

這就是文件原本說的「注入 provider」：把你寫的函式傳給系統，系統處理請求時就會呼叫它。

你的情境設定還要列出 `trusted_sources`、`max_age_seconds`，以及允許使用的 API、服務版本、規格、查詢條件與回應規則。來源名字在名單內，只是其中一項檢查。完整啟動方式見 [HTTP 接入說明](renderer.md#可選的-http-請求入口--任務協調器--http-回送器接入) 及 [任務協調器](orchestration.md)。

電商展示中的接收函式位於 `deception.domains.ecommerce.http_demo`。它會替測試請求建立 `verdict: malicious` 的結果，表示「為了測試，假設這筆是攻擊」。`/demo/info` 另以 `assessment_mode: simulated_malicious` 提醒你這是模擬模式；`simulated_malicious` 不是可填入 verdict 的選項。展示設定由程式建立，不會自動啟用專案內那些預設停用的設定範本。

## 出問題時怎麼查

下面是內部紀錄可能出現的問題碼。對外只回固定通知，不會把這些細節或原始請求直接回給訪客。

| 內部問題碼 | 白話意思 |
| --- | --- |
| `assessment_missing` | 直接使用情境引擎時，沒有交入檢查結果 |
| `assessment_source` | 這個工具名稱不在允許名單內 |
| `assessment_request` | 請求編號或內容對照碼不一致 |
| `assessment_context` | 結果是別個環境、部署、服務或網站的 |
| `assessment_expired` | 結果還沒生效，或已經太舊、過期 |
| `assessment_unknown` | 工具還不能確定這是不是攻擊 |
| `rule_not_unique` | 同時找到多條最高優先規則，不知道要用哪一條 |

有些格式錯誤會被記成一般準備失敗，不一定出現上表的某個碼。除錯時可以保留結果編號、來源名稱與問題碼；不要把登入憑證、完整請求內容或偵測器的秘密資料寫進對外回應或紀錄。

## 如何檢查這份文件與接法

```powershell
$env:PYTHONPATH = "$PWD/src"
.\.venv\Scripts\python.exe -m pytest tests/test_scenarios.py tests/test_pipeline_api.py tests/test_ingress.py -q
.\.venv\Scripts\python.exe tools/check_documentation.py
```

這些測試會檢查來源名單、請求及服務是否對得上、結果是否過期、接收函式的回傳格式與等待時間，以及原始請求資料有沒有保留。它們不會替你證明外部偵測器有多準，也不會替你完成來源認證或一次性結果使用的檢查。

前面的本機範例可以另存成 Python 檔，在已安裝相依套件並設定 `PYTHONPATH` 後執行。

## 套件、授權與目前沒做的功能

這個介面沿用 Pydantic（MIT）檢查資料格式，FastAPI（MIT）與 Starlette（BSD-3-Clause）接收和回送 HTTP 資料；對照碼、時間及範例查詢使用 Python 標準庫。這份文件沒有新增套件或偵測模型，讀取結果時也不會呼叫 Ollama。自有程式及原創文件採 Apache-2.0，其他套件及模型權重的條款見 [專案授權](licensing.md) 與 [元件授權表](orchestration.md#套件模型與資料授權)。

目前還沒有：公開判定接收 API、外部來源認證、用過結果的去重紀錄、防重放儲存、攻擊標籤自動轉換，以及 OWASP 自動分類。一般請求也不會自動轉送原網站。若你的部署程式新增這些能力，應另外記錄使用方式、出錯時怎麼處理，以及如何驗證。
