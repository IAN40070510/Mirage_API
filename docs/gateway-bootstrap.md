# 舊版外部 Gateway 組裝說明（已移交）

> 此為歷史文件入口。舊版跨倉 Gateway 組裝器、固定相容依賴與相關驗收，
> 已從 Mirage 原始碼移交外部消費端管理。歷史原件依分支封存於消費端的
> 受審查變更，**不再構成 Mirage 可執行功能或測試命令**。

## 現行範圍

Mirage 只提供獨立的可信請求接收、簽章驗證、重放拒絕、合成 World 與
交易元件；它不安裝或啟動外部 Gateway、判定模型或導流服務。
預設展示服務也不需要外部依賴，詳見[獨立安裝與驗收](standalone.md)、
[可信服務](trusted-session.md)及[運維說明](runtime-operations.md)。

## 驗收及安全邊界

- 舊版跨倉驗收結果僅代表當時的隔離測試，不能推定正式部署或主機已切換。
- 新的消費端相容測試必須由外部專案獨立執行，且不能使用 Mirage 的
  staging／production 資料、密鑰或資料庫。
- Mirage 自身驗收使用 `python -m pytest tests/test_standalone_runtime.py -q`
  及 `python tools/check_documentation.py`；測試跳過不可視為通過。
- 正式發送、安全簽核與 G3b～G6 Gate 尚未因此改為 PASS。

## 授權與限制

Mirage 原生元件沿用專案的 Apache-2.0 與既有依賴；詳見[授權表](licensing.md)。
本文件不授權部署、資料搬移或開啟 Trusted Send。
