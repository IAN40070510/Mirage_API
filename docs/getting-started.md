# 安裝與第一次使用

## 用途與邊界

Mirage 可獨立執行合成商品、世界、購物車與受保護的欺敵 HTTP 流程。
預設展示入口使用固定合成資料與備援文字。可信交易入口由部署者配置
本服務的公開金鑰、服務範圍與隔離 PostgreSQL。

## Docker Compose 啟動

先安裝 Git、可運作的 Docker Engine／Docker Desktop 與 Docker Compose v2，在終端機執行：

```sh
git clone https://github.com/IAN40070510/Mirage_API.git
cd Mirage_API
docker compose up --build -d --wait --wait-timeout 180
```

啟動後開啟 `http://127.0.0.1:8000/healthz` 確認健康，開啟 `http://127.0.0.1:8000/demo/info` 取得合成商品的 `product_ids`。選一個 ID 呼叫 `http://127.0.0.1:8000/api/products/商品ID`；同一服務內重複查詢會維持權威資料，缺少的商品回 404。

Windows PowerShell 可直接呼叫：

```powershell
$info = Invoke-RestMethod http://127.0.0.1:8000/demo/info
Invoke-RestMethod "http://127.0.0.1:8000/api/products/$($info.product_ids[0])"
```

預設僅發布 localhost 的 8000 埠。Compose 內的 PostgreSQL 不發布主機埠；展示商品流程本身是唯讀，連線資料庫不會自動啟用可信交易。需要調整埠或模式時，可複製 `.env.example` 為 `.env`，再參考[容器設定](docker.md)。首次建置需要網路下載映像與 Python 相依套件，之後的固定備援流程不會呼叫模型服務。

## 驗證結果與停止

```sh
docker compose exec -T mirage python tools/verify_domain_api.py --domain ecommerce --base-url http://127.0.0.1:8000
docker compose logs --tail=100 mirage
docker compose down
```

驗證器執行 16 個一般及攻擊特徵請求，輸出 JSON 報告與成功／失敗退出碼；報告保存在容器的 `/app/generated/domains/ecommerce/verification/http-api.json`。停止服務會保留命名 volume；再次執行 `docker compose up -d --wait` 可啟動服務。展示入口每次啟動建立自己的展示輸出，不承諾跨啟動沿用商品 ID；跨程序的業務世界由可信入口與 PostgreSQL 提供。

可匯出報告後再停止：

```sh
docker compose cp mirage:/app/generated/domains/ecommerce/verification/http-api.json ./http-api.json
```

`docker compose down --volumes` 會刪除本 Compose 的資料庫與輸出 volume；只在確定不需保留資料時使用。

## 用 Python 從原始碼啟動

需要 Python 3.11 以上。下列命令在 clone 的專案根目錄執行，讓服務找到 `configs/`、`domains/` 與契約資產。

Windows PowerShell：

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\python.exe -m uvicorn deception.api.demo:create_app --factory --host 127.0.0.1 --port 8000 --no-proxy-headers
```

Linux／macOS：

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m uvicorn deception.api.demo:create_app --factory --host 127.0.0.1 --port 8000 --no-proxy-headers
```

在另一個終端機，以同一虛擬環境執行 `python tools/verify_domain_api.py --domain ecommerce --base-url http://127.0.0.1:8000`。直接執行 Python 不會自動載入 `.env`；需要覆寫時由 shell 設定環境變數。預設備援模式由應用設定提供，啟用真實本機模型另見[模型設定](llm.md)。

## 失敗處理

- Docker 無法連線：確認 Docker Engine 已啟動，再執行 `docker compose version`。
- 8000 已占用：依[容器埠設定](docker.md)調整 `MIRAGE_HTTP_PORT`，並更新呼叫網址及 verifier Host。
- 容器未就緒：查看 `docker compose ps` 與 `docker compose logs --tail=100`；不要把建置完成當成健康通過。
- Python 找不到設定：切回專案根目錄，使用剛安裝依賴的同一個虛擬環境。
- 可信入口回 503：核對簽章、請求摘要、身份及獨立資料庫設定；展示入口不會替正式 Gateway 簽發授權。

## 開發驗證、授權與限制

```sh
python tools/check_documentation.py
python -m pytest -q
```
