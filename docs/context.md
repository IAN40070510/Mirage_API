# J：GenerationContext 生成上下文

## 功能與邊界

`deception.generation.GenerationContext` 是 C 建立的嚴格資料模型，位於 `src/deception/generation/models.py`。它把同一請求的領域、部署、契約、情境、資料及模型版本關聯起來，供 G 選規則、建立快取身份及回傳追溯資料。

J 不執行推論、來源認證、資料更新或 gate 驗證。呼叫端可建立一個格式正確的物件，但物件格式本身不證明其內容可信；實際流程由 C 使用 B／D／E／F 及 backend 已核對的結果建置。

## 輸入與輸出

| 欄位 | 來源及用途 |
| --- | --- |
| `domain` | 管理者明確選定的領域，例如 `ecommerce` |
| `request_id`、`request_fingerprint` | A 請求與可信判定的關聯，指紋由 `fingerprint_request` 計算 |
| `environment_id`、`deployment_id`、`service_id` | B 核對後的部署身份 |
| `scope` | F 準備的固定 family 與 run；含 site、platform、version、契約 SHA-256、scenario、run |
| `operation_id`、`outcome_id` | B/D 的操作及 F 依資料選出的結果 |
| `scenario_decision_id`、`scenario_policy_sha256` | 本次 F 決策及固定政策版本 |
| `generation_policy_sha256` | 本次使用的 G 政策內容摘要 |
| `data_namespace`、`state_sha256` | 已核對資料集的身份與完整快照摘要 |
| `domain_context` | F 封存的領域選擇資料，電商目前包含 `product_id` |
| `model_identity` | backend 核對的模型名稱、digest、執行模式、解碼設定、規劃模式及 runtime 版本；模型尚未可用而採明確 N 備援時標示 `provider: not_used`、`execution_mode: fallback` |

`context_id` 屬性將完整 JSON 表示以固定排序及 SHA-256 摘要，回傳可追溯字串。因為包含請求身份，它不是跨請求實體內容的快取鍵；G 另依穩定的資料、實體、政策、骨架及模型資訊建立鍵。

## 使用方式

應由 [C 協調器](orchestration.md) 建立實際上下文，避免手工混用不同請求或版本。取得 `PipelineResult` 後可讀取 C 記錄的識別資訊：

```python
result = await pipeline.run(
    request, verified_assessment, runtime=trusted_runtime,
    generation_config=checked_e_config, dataset=checked_e_dataset,
)
if result.decision == "validated":
    context_id = result.trace["context_id"]
    scenario_trace = result.trace["scenario"]
    generation_trace = result.trace["generation"]
```

這些變數代表已按各工具文件建立的輸入與實例。`context_id` 只是追溯摘要，正式輸出仍須使用同一 `candidate` 與其 I 結果，不得拿另一請求的 gate pass 代替。

## 驗證與失敗處理

模型沿用嚴格型別及禁止額外欄位規則。缺欄位、錯誤 JSON 型別，及 `request_fingerprint`／`scope.spec_sha256` 已定義的摘要格式限制會由 Pydantic 檢查；其他字串摘要的真實內容與版本關係由 C/G 核對工具結果，並非 J 自行驗簽。`scope` 不符、政策變更、請求指紋變更或 F 判定到期時，流程不能回傳可用的已驗證候選。模型生成候選的發布亦須確認本機模型身份未變；[N](recovery.md) 可在模型尚未可用或規劃失敗時採用明確固定值，但不宣稱執行模型生成，並仍核對相同契約、情境、資料及 H/I。

C 建立 J 時不放入原始 body、Cookie 或 Authorization。`domain_context` 與模型可見的事實應由領域處理器受限投影，不能把任意使用者指令當成工具權限；J 的任意 JSON 欄位本身不會自動移除機密。此模型可變，不能把它當成防竄改簽章；F 的同引擎 seal、C 的原請求及快照核對各自負責原有邊界。

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_generation.py tests/test_orchestrator.py -q
```

測試涵蓋不同請求／版本的快取關聯、固定政策摘要、受保護欄位與最終候選一致性；本機模型展示與假模型邊界測試分開，見 [實測說明](orchestration.md)。

## 套件授權與限制

J 直接使用既有 Pydantic（MIT）及 Python 標準庫 `hashlib`、`json`（隨 Python 的 PSF 授權與聲明）。未新增依賴；共用元件及模型權重條款見 [C/G 授權表](orchestration.md#套件模型與資料授權)。J 不是完整對話記憶體、集中設定服務或交易狀態儲存，不能靠上下文物件宣稱已完成扣款或庫存更新。
