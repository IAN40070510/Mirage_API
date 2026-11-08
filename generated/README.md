# 系統產物

執行 D 的 Profile builder 後產生：

- `profiles/<platform_id>.yaml`：來源資訊、操作摘要與缺口。
- `schemas/<platform_id>/<spec_sha256>.yaml`：原始 OpenAPI bytes 快照，供完整 `$ref` 解析與雜湊檢查。

執行 E 的 `python -m deception.synthetic generate --config configs/generation.yaml` 後產生 `synthetic_data/<platform_id>/<namespace>.json`，包含商品、變體、關聯與生成設定。namespace 納入完整隔離身份、規則與生成器／Faker 版本，不同設定使用不同檔案。E 可另用 `verify` 指令檢查產物，見 [功能與驗證](../docs/synthetic.md)。

執行 F 的 `python -m deception.scenarios --demo --domain ecommerce --output generated` 後產生 `scenarios/<報告SHA256>.json`，保存明確選定的領域、專用合成契約、政策、資料身份及 `200 → 404 → 200` 的 F/H/I 結果。這是 `test_only` 離線驗證，不代表真實平台獲得核准。可用 `--list-domains` 查看已註冊領域；內部 API 另可直接取得情境決策與 H 計畫，見 [F 用法、驗證與授權](../docs/scenarios.md)。

執行 C／G 的 `python -m deception.generation --demo --domain ecommerce --llm-config configs/llm.yaml --output generated` 後，產生 `generation/<報告SHA256>.json` 與 `generation/cache/<展示ID>.sqlite3`。展示只使用真本機 Ollama，採臨時合成契約依次檢查 `200 → 404 → 200`、權威資料不變與內容快取一致性；實際成功與否依報告的 `success`、`real_model`、`checks` 及各次候選判讀。失敗報告也會保存，不能將檔案存在當作成功。SQLite 保存已驗證的生成內容，不保存可跨請求重用的 gate 通行結果。用法、FunctionModel 與真實模型證據區分、授權見 [C／G 說明](../docs/orchestration.md)。

執行 H 的 `python -m deception.core --plan configs/composition.yaml` 後產生 `responses/<platform_id>/<候選封套hash>.json`。封套保存固定的 status、headers、最終 body 字串及來源／run 身份；H preflight 不等於 I 的部署 gate 已放行，詳見 [H 功能、驗證與授權](../docs/composer.md)。目前 Medusa 範例需明確使用 `--allow-unreviewed` 做離線預覽。

這些產物不納入 Git；由固定來源重建。同一輸出目錄的一個平台只接受一份相同來源設定，版本、雜湊或審查狀態有變化時需指定新的輸出目錄，例如 `generated/releases/medusa-2.22.4-reviewed/`。這可保留舊 run 的來源身份，避免靜默覆寫。
