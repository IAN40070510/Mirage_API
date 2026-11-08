# E：合成資料工具

## 功能確認

E 的第一版範圍是平台無關的商品／變體資料，供 C、F、H 查詢與組合回應。程式位於 `src/deception/synthetic/`，設定為 `configs/generation.yaml`，產物在 `generated/synthetic_data/`。

| 功能 | 本次行為 |
| --- | --- |
| 商品與變體 | 固定 ID、商品名稱、handle、SKU、父子關聯、價格與庫存；目前不生成顧客與訂單 |
| 可重現生成 | 相同完整設定與生成器／Faker 版本可重建相同產物 bytes；文字使用獨立 Faker instance seed |
| 隔離 | site、platform、platform version、spec SHA-256、scenario、run、seed 與其餘規則共同決定 namespace |
| 查詢 | 商品列表分頁、依 ID 查商品／變體、依商品查變體；未知 ID 不新增實體 |
| 一致性 | 唯一 ID／handle／SKU、有效父子關聯、明確幣別、整數金額與非負庫存 |
| 保存與載入 | JSON 原子寫入；載入時核對呼叫端的設定，檢查型別與關聯並完整重建比對 |
| 有效性驗證 | `verify_dataset` 回傳報告；CLI `verify` 可獨立驗證既有檔案，失敗回非零結束碼 |
| 與 D 配合 | `SyntheticTool(..., profile=context)` 核對平台、版本與契約雜湊，保持 D 的審查狀態 |

這些是內部資料實體。現有 Medusa `StoreProduct` 還要求 options、images、timestamps 等欄位，庫存也不能直接套用成 StoreProductVariant 的回應欄位。因此 E 的驗證只證明內部資料符合規則與可重現性；完整平台 body 映射由 H 處理，正式 HTTP 契約由 I 驗證。C 已核對並使用同一 E 快照，完整 A/M HTTP handler 串接仍待完成。

## 現成專案評估

| 專案 | 適合用途 | 本次選擇 |
| --- | --- | --- |
| [Faker](https://faker.readthedocs.io/en/stable/) | 合成文字、多語系 provider、每個 instance 的 seeded 亂數 | **採用 `Faker==40.44.0`** 生成商品文字；ID、範圍與資料關聯由本工具管理 |
| [Polyfactory](https://github.com/litestar-org/polyfactory) | 依 Python 型別與 Pydantic 等模型產生測試資料 | 可用於後續多種實體的 factory；本版關聯與隔離規則明確，使用現有 Pydantic 模型即可 |
| [hypothesis-jsonschema](https://github.com/python-jsonschema/hypothesis-jsonschema) | 從 JSON Schema 建立 Hypothesis 測試策略 | 適合後續契約邊界測試；本版需要固定、可查詢的實體關聯，未作為執行期生成器 |

Faker 官方說明同一 seed 的結果還依賴呼叫方法及版本，且 patch 更新也可能改變資料集，因此本版鎖定確切版本。只使用文字 provider，不產生依「今天」變化的日期，也不呼叫姓名、地址或帳號 provider。商品標題帶 `Synthetic`、識別碼帶 `syn`／`SYN` 標記；生成文字可能偶然與現實文字相同，不能以文字本身作為唯一的合成來源證明。

E 直接使用的 `Faker==40.44.0` 採 MIT License；本專案只呼叫其公開 API，沒有複製 Faker 原始碼或資料。Faker 安裝時帶入的 `tzdata` 是間接依賴，發行或部署時也要依實際解析出的版本保存其授權與版權聲明。Polyfactory 與 hypothesis-jsonschema 目前只是評估過的候選，沒有列入 `pyproject.toml`，因此不構成本版本的執行期依賴。完整直接依賴清單及授權界線見 README 的[開源軟體、模型與資料授權](../README.md#開源軟體模型與資料授權)。

## 執行方式

安裝專案依賴後，在根目錄執行：

```powershell
$env:PYTHONPATH = "$PWD/src"
.\.venv\Scripts\python.exe -m deception.synthetic generate --config configs/generation.yaml --output generated
```

預設生成 10 個商品與 20 個變體，輸出：

```text
generated/synthetic_data/medusa/<namespace>.json
```

`namespace` 是完整設定、生成器版本與 Faker 版本的 SHA-256。商品／變體 ID、handle 與 SKU 也依這個身份產生；修改任何隔離維度或規則，就使用新的資料身份及檔名。原子寫入只發布完整檔案；同名檔案若已存在但損壞，會拒絕覆寫並報錯。

`generate` 會保存後再載入驗證。也可以對已產生的檔案獨立執行：

```powershell
.\.venv\Scripts\python.exe -m deception.synthetic verify --config configs/generation.yaml --dataset "<generate輸出的完整JSON路徑>"
```

成功顯示 `valid=True`、商品數與變體數；檔案損壞、內容遭改動、重複 JSON key、版本不相容或 scope／規則不同均會失敗。這是本地完整性驗證，不是針對可同時修改設定及所有產物者的數位簽章。

## 資料與查詢介面

```python
from pathlib import Path
from deception.synthetic import SyntheticTool, generate_dataset, read_config, verify_dataset

config = read_config(Path("configs/generation.yaml"))
dataset = generate_dataset(config)
assert verify_dataset(dataset, config).valid
tool = SyntheticTool(dataset, expected_scope=config.scope)
product = tool.list_products(limit=1)[0]
variants = tool.get_variants(product.id)
assert all(variant.product_id == product.id for variant in variants)
assert tool.get_product("not-found") is None
```

`Product` 保存 `variant_ids`；`Variant` 保存 `product_id`、SKU、庫存與 `{currency_code, amount_minor}`。金額是明確幣別的最小單位整數，不做匯率或平台價格表示的自動轉換。支援 `en_US`／`zh_TW` 與 `usd`／`eur`／`twd`；價格及庫存的 min/max 可以相等，也可都為零。

每個工具 instance 綁定一個 `expected_scope`，所有回傳 model 都是深複本，呼叫端修改不影響其他查詢。工具只在建立時驗證固定快照，不會在每次 GET 消耗亂數。分頁 offset 不得為負，limit 為 1–1000；商品數 0–1000、每商品變體 1–20，總變體最多 10000。

若 C 同時取得 D 的 `OperationContext`，可傳入 `profile=context`；身份不符即拒絕。E 沒有核准來源或網站綁定的權限，`profile.source.approved` 仍保持原值。未審的 D 來源仍應遵守 D 的離線預覽限制。

舊 `inputs/synthetic/medusa/state.yaml` 仍是手寫草稿，不會被本工具當作匯入資料或自動遷移。第一版只從設定規則產生新資料，避免將舊 ID 配到不同版本／run。

## 模組有效性如何驗證

測試檢查相同設定重建與 bytes 一致性、各隔離維度、全域亂數不受影響、父子關聯與唯一性、價格／庫存範圍、零資料與零值、嚴格型別、分頁及深複本、找不到 ID 不新增資料、保存再載入，以及合法型別但遭改動的資料會被拒絕。另用 repo 現有 Medusa 來源重建 D，取得商品操作後串接 E，確認身份一致與未審查狀態維持。

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_synthetic.py -q
```

這些測試驗證 E 的資料行為；它們不會宣稱 E 已生成符合完整 Medusa 契約的 HTTP 回應。
