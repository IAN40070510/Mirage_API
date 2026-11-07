# 系統產物

執行 D 的 Profile builder 後產生：

- `profiles/<platform_id>.yaml`：來源資訊、操作摘要與缺口。
- `schemas/<platform_id>/<spec_sha256>.yaml`：原始 OpenAPI bytes 快照，供完整 `$ref` 解析與雜湊檢查。

這些產物不納入 Git；由固定來源重建。同一輸出目錄的一個平台只接受一份相同來源設定，版本、雜湊或審查狀態有變化時需指定新的輸出目錄，例如 `generated/releases/medusa-2.22.4-reviewed/`。這可保留舊 run 的來源身份，避免靜默覆寫。
