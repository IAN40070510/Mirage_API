# 共用輸入索引

通用框架的 `inputs/` 只保存跨領域使用的中繼資料；業務來源、平台契約、情境、資料與範本放在 `domains/<domain>/inputs/`。不能因選用一個領域而把另一領域的來源或規則自動套用。

| 位置 | 用途 |
| --- | --- |
| `security_taxonomies/` | 版本化安全分類及官方來源，例如 OWASP API Security Top 10 與 Web Top 10 |
| [來源說明](sources/README.md) | 共用固定來源規則，實際檔案在各領域包 |
| [電商輸入](../domains/ecommerce/README.md) | 電商來源、部署契約、政策及歷史草稿 |

共用應用設定在 `configs/app.yaml` 選擇 `domain` 與 `domains_dir`；模型設定仍位於 `configs/llm.yaml`。領域包的 `domain.yaml` 宣告自己的相對資產位置，且需要伺服器已註冊的實作。詳細使用方式見 [Docker 領域選擇](../docs/docker.md)、[工具索引](../docs/README.md) 及 [OWASP 設計](../docs/owasp-design.md)。

分類目錄不是弱點執行器，也不是部署核准；各領域的設計與已實作情境須分開記錄。沒有任何共用輸入會自動核准真實服務、執行任意程式或接收訪客指定的 Python 匯入路徑。
