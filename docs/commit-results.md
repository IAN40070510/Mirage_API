# 共用事件提交與 Commit Result

## 用途與邊界

`EventWorldStore` 在既有 `WorldStore` 的 Snapshot／CAS 介面外定義共用事件提交。`PostgresEventWorldStore` 在同一 PostgreSQL 交易保存新快照、事件、業務結果、Watermark、提交收據及領域資源映射。庫存與購物車的事件已沿用此核心；引擎本身沒有商品、價格或 Medusa 路徑。

低階 `compare_and_swap()` 仍回 Snapshot／例外，供既有呼叫相容；它不是五類結果介面。`SyntheticInventory.reserve/cancel` 及購物車的既有 HTTP 回應亦保留領域格式，不新增原生 Medusa 欄位。需要標準結果的受信任呼叫端使用 `commit_event()`。購物車首次建立仍使用領域初始化交易，不宣稱已改成共用事件。記憶體 Store 尚未提供此事件後端。

## 輸入與輸出

提交必須提供已由可信入口驗證的 `SessionBinding`、原先核准的 `authorized_scope`、固定操作名稱、JSON 物件命令、期望版本、業務冪等鍵、UUIDv4 `commit_attempt_id` 與 Unix 整數時間。Python DTO 本身不是授權證明；HTTP 仍須先通過 JWS、Replay、資源綁定及既有政策。IP／UA 不授予寫入權。

| 結果 | 含義與證據 |
| --- | --- |
| `committed` | 新操作交易已成功回覆；包含已提交版本／hash、結果 payload、摘要與原 attempt。 |
| `already_committed` | 同一 scope、操作、業務鍵與命令已有成功結果；保留原版本、摘要與 attempt，不產生新事件。 |
| `conflict` | CAS、同鍵異內容或資料約束衝突；不附已提交證據，使用固定 failure_code。 |
| `rejected` | 能力／scope／epoch／期限等政策拒絕，或純業務判定拒絕；只有已保存的業務拒絕攜帶結果與 observed 版本。 |
| `unverifiable` | 連線、資料完整性或提交回覆無法確認；保留原 scope、鍵與 attempt，不捏造結果、摘要或已提交版本。 |

`CommitResult` 明列 operation、idempotency_key、commit_attempt_id、result_encoding_version、committed_state_version/hash、observed_state_version/hash、result_digest、result、failure_code 及 replayed。失敗不能攜帶 committed 證據；成功不能附 failure_code。業務拒絕重試仍是 `rejected`、replayed=true，不改稱 `already_committed`。模型與巢狀結果不可變，`model_copy(update=...)` 會重新驗證摘要及狀態。

業務鍵與操作名稱只接受 1–128 個 ASCII 英數、點、底線與連字號；版本為正 int64，時間不可為負數，bool 不能冒充整數。命令在開啟交易前嚴格驗證、複製並凍結，非有限數值拒絕。格式錯誤以 ValueError／Pydantic ValidationError 回報，不是假裝發生過交易的 CommitResult。

## 設定與範例

先依序套用 `migrations/001` 至 `015`；版本化操作方式見[部署操作](runtime-operations.md)。新的事件紀錄同交易保存結果編碼與摘要。舊紀錄允許兩欄皆 NULL，但共用事件 API 不替這些歷史結果背書，也不在讀取時補寫摘要。既有領域相容介面仍可讀舊格式；新紀錄有摘要時會驗證，不能藉此繞過毀損檢查。

```python
from uuid import uuid4
from deception.world import PostgresEventWorldStore

def add_counter(state, command):
    """在合成計數器產生新狀態與結果，不執行外部副作用。"""
    next_state = {**state, "value": state["value"] + command["amount"]}
    return next_state, {"value": next_state["value"]}, True

store = PostgresEventWorldStore(
    dsn,
    compatibility=approved_world_policy,
    handlers={"counter.add": add_counter},
    write_modes=frozenset({"inventory"}),
)
# binding、scope 與 base_version 由可信服務取得，不能採信訪客提供值。
attempt = uuid4()
outcome = store.commit_event(
    binding, authorized_scope=scope, operation="counter.add", command={"amount": 1},
    expected_version=base_version, idempotency_key="business-001",
    commit_attempt_id=attempt, now=unix_now,
)
```

基礎類別的 handler 與寫入模式預設為空，沒有隱含可寫能力；目前 SessionBinding 沿用既有 `inventory`／`cart` 模式。handler 是部署端固定同步純函式，接收不可變狀態與命令，回傳新狀態、JSON 結果與 bool 接受旗標；禁止在 callback 付款、發信或呼叫外部服務。非同步函式不能登錄。領域的資源保存 hook 只能使用同一交易連線，不另行提交。註冊器無法自動證明任意 Python callback 沒有副作用，這是受信任擴充邊界。

部署應傳入伺服器核准的 `WorldCompatibility`，以固定引擎／來源／投影集合；省略政策的低階 Store 只供相容原型與獨立交易測試，不代表可信 HTTP 的完整世界政策已配置。實際電商可信入口會明確傳入並驗證政策。

## 交易節點與摘要

| 節點 | 白話功能 |
| --- | --- |
| metadata／命令檢查 | 在碰資料庫前固定此次要做的事，避免外部在等待鎖時改內容。 |
| Session／世代鎖 | 再確認目前身份、epoch 與原 scope，封存或到期就停止。 |
| 業務鍵／CAS | 先查是否已有同一結果；新操作才核對版本，不覆寫別人的更新。 |
| 純事件提案 | 用固定服務端規則計算新狀態，不讓模型或訪客定義交易程式。 |
| 原子保存 | 快照、事件、結果摘要與收據一起成功或一起回滾。 |
| 未知結果恢復 | 提交失聯後只讀查原 attempt，不因看不到回覆就再寫一次。 |

命令摘要是 Python `json.dumps(ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)` 的 UTF-8 SHA-256。結果編碼版本 1 使用同一 JSON 規則，對 `{result, version, hash, attempt, status}` 摘要；status 是保存的 `committed` 或 `rejected`，不包含讀取端 replayed 旗標。因此重播不改原結果摘要。UUID 使用標準字串。此編碼是目前 Python 格式，沒有宣稱 JCS 或任意語言數值編碼互通。

PostgreSQL 會把 `1e20` 保存成整數表示，並把 `-0.0` 轉成 `0.0`。因此事件結果及所有 PostgreSQL 快照寫入路徑會先在同交易 SELECT 取得 JSONB 的實際表示，再計算原有格式的 hash；首次回覆與之後讀取使用相同值。這不修改 hash 編碼，也不重新計算既有紀錄；舊快照或舊結果若已不符原摘要仍拒絕，不拿正規化當成修復毀損的方式。非字串鍵、非 JSON 型別、NaN／Infinity 與超出資料庫可保存範圍的值拒絕並回滾。記憶體後端保留其 JSON 表示，不宣稱輸入浮點數在不同儲存後端具有相同字面編碼。

摘要用於完整性核對，不是授權、簽章或防惡意 DBA 的 MAC。冪等鍵在資料表保存 SHA-256，DTO 原鍵不出現在 repr；完整 JSON 輸出仍包含鍵與業務結果，呼叫端不可直接寫入公開日誌。

## 失敗處理與唯讀恢復

提交只嘗試一次，不自動重試寫入。`unverifiable` 可能代表已提交；先重新確認原 scope 的讀取權，再呼叫：

```python
found = store.get_event_result(
    binding, authorized_scope=outcome.scope, operation="counter.add", command={"amount": 1},
    idempotency_key="business-001", commit_attempt_id=outcome.commit_attempt_id, now=unix_now,
)
```

查詢沿用 `CommitLookupResult` 的 committed／rejected／pending／not_found／unverifiable，已驗證紀錄另附 `commit_result`。它核對當前 epoch、世代、期限、完整 scope、操作、鍵與命令摘要，再核對已保存結果摘要。業務拒絕也能唯讀恢復。`pending` 表示 attempt 鎖未釋放；`not_found` 只表示此時沒有對應紀錄，不能推論可以盲目重送。重播讀取交易若遺失 COMMIT 回覆，未知結果會保留原紀錄的 attempt。

既有 `get_commit_result(scope, attempt, authorized_scope=scope)` 只提供低階收據／版本／hash；需要完整且核對命令的業務結果應用 `get_event_result()`。UUID 不是歷史 Capability，當前 epoch、世代或期限失效後不能用它繞過拒絕；歷史授權、清理政策與查詢 SLA 尚未提供。查詢不寫入業務表，但會使用交易／控制鎖；同 Session 的在途寫入可能使查詢等待。

快照或結果毀損回 unverifiable，不能重算新摘要把毀損內容當成原始成功，也不能稱為正常業務拒絕。儲存例外內容不進結果；只有固定失敗代碼。

## 驗證方式

`tests/fixtures/golden_vectors/commit_results.json` 固定保存 **30 組完整公開 DTO**：7 組合法結果與 23 組矛盾證據。涵蓋五類結果、成功／拒絕重播、摘要或結果改寫、版本／hash 不成對、bool 冒充版本、非 UUIDv4、未知編碼與額外欄位。保存結果的案例同時固定 UTF-8 摘要前像與 SHA-256，不在測試執行時用待測函式重產答案。

Node 的獨立 `verify_commit_results.mjs` 不匯入 Python 或重用執行結果，依相同 fixture 核對接受／拒絕及精確摘要前像。編碼案例包含繁體中文、換行、astral 字元及 BMP／astral 鍵排序，明確處理 JavaScript UTF-16 與 Python Unicode code point 排序差異。這是安全整數與 Unicode 的固定向量核對器，不是任意數值的完整跨語言驗證器、正式授權 SDK 或其他 Runtime Gate 的替代品。

```powershell
python -m pytest tests/test_commit_vectors.py -q
node tests/fixtures/golden_vectors/verify_commit_results.mjs
python -m pytest tests/test_commit_result.py tests/test_inventory_events.py tests/test_guest_carts.py tests/test_postgres_network.py -q
python tools/check_documentation.py
```

設定專用 `MIRAGE_POSTGRES_TEST_DSN` 才會執行真實交易；未設定的 skip 不算通過。Windows 本機執行測試、事件引擎與 TCP 故障代理；SSH Ubuntu 只執行隔離 PostgreSQL 16，SQL 透過 loopback 隧道傳送，不使用 staging。測試包含非電商 counter、五類結果、結果毀損、資料庫約束、同 attempt 異鍵回滾及真實 COMMIT 回覆遺失。執行結果見[進度](implementation-progress.md)。

## 套件授權與目前限制

自有程式、migration 與向量核對器採 Apache-2.0；沿用 Pydantic、psycopg、pytest 與已存在的 Node.js 互通測試環境，不新增套件或模型。Node 核對器只用內建 fs／crypto／assert，缺少 Node 時該互通案例會 skip，不能當成通過；其發行版授權另依所用 Node 環境，未把 Node 執行檔封入本工具。Python 依賴授權見[授權表](licensing.md)。此功能不接真實庫存／付款，不提供記憶體事件後端、歷史授權、自動舊資料背書、跨語言 SDK 或正式部署核准；共用結果通過不代表完整 Protocol v1.1 驗收完成。
