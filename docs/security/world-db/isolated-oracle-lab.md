# MIR-SEC-WORLD-001 — Oracle 隔離資料庫身分驗收環境

此文件只描述獨立測試環境。`deploy/security-lab/compose.yaml`、`provision.py` 和 `probe.py` **不是**正式 Verifier／Authorizer 服務，不能拿來解除 Release Fuse、聲稱 G1/G2 完成，或啟用 production trusted send。

## 用途與安全邊界

- 在既有 Oracle ARM64 主機上，另建 `mir-sec-world001-lab-net`（`internal=true`）、`mir-sec-world001-pgdata` 和三個獨立測試容器：PostgreSQL `17.6-alpine`、Verifier Role Probe、Authorizer Role Probe。Runtime 僅用 Compose profile `negative-tests` 建立短暫探針，不屬於既有七容器。
- 網路沒有宿主對外埠，網路與既有 Mirage、MSDSS 網路沒有連接；無 production DB、Volume、Secret、Docker socket 或 Host root path 共享。
- Verifier／Authorizer／Runtime 的測試密碼分開由主機本地 CSPRNG 產生，不輸出到對話、Git 或指令參數；密碼檔 mode `0600`，數字 UID 分別為 `10011`、`10012`、`10013`，服務容器也以同 UID 執行；測試進程不取得其他服務秘密掛載。
- 探針具有 `read_only` rootfs、`cap_drop: ALL`、`no-new-privileges`、無自動重啟、有限 RAM/PIDs；使用已在主機的原始映像，明確固定本次 Mirage source SHA。Host root／Docker daemon 受控（R5）**不在**本輪身分隔離保證內。
- 只有一次性 `bootstrap` 容器為讀取不同 UID 擁有的 `0600` Secret 另外授予 `CAP_DAC_READ_SEARCH`；它不掛載 Docker socket、不能寫入 Host Secret／Source，且執行結束即退出。所有常駐探針仍 `cap_drop: ALL`；這不是供正式環境複製的金鑰管理設計。

## 輸入、輸出與部署前提

必須先由授權人員明確核准新增測試資源。只在專用 Lab 根目錄執行 Compose：來源程式 `./source`、不提交的 `./secrets`、與 `./compose.yaml`。`./source` 必須是獨立修補分支且完整 SHA 可核對；不要從既有 staging 的 `compose.yaml` 啟動。

需要的 Secret 檔名為 `pg_admin_password`、`verifier_password`、`authorizer_password`、`runtime_password`。每檔需足夠長度的獨立隨機密碼；Oracle 主機上產生並以 `0600` 保留，**禁止**傳入 GitHub、MCP 參數、測試報告或任何 HTTP 回應。只有測試用 `bootstrap` one-off 容器能同時讀取這些密碼；執行後必須退出。

受控程序：

```bash
# 在專用 Lab 根目錄執行，不得套用既有 staging Compose。
docker compose -f compose.yaml config --quiet
docker compose -f compose.yaml up -d postgres verifier-probe authorizer-probe
docker compose -f compose.yaml --profile bootstrap run --rm --no-deps bootstrap
docker compose -f compose.yaml exec -T verifier-probe python /lab/source/deploy/security-lab/probe.py verifier
docker compose -f compose.yaml exec -T authorizer-probe python /lab/source/deploy/security-lab/probe.py authorizer
docker compose -f compose.yaml --profile negative-tests run --rm --no-deps runtime-probe python /lab/source/deploy/security-lab/probe.py runtime
```

預期 `provision.py` 只在全新專用 PostgreSQL Database 執行有序 migrations，建立 `mir_sec_verifier`／`mir_sec_authorizer`／`mir_sec_http_runtime` 互不繼承的 SCRAM 登入；Runtime 無關鍵表 DML，Verifier 只具測試性 Replay INSERT／SELECT，Authorizer 只具保護表 SELECT。這些角色配置**刻意不是**完整 World API 的可運行最小權限；正式受限函式、Ingress Receipt、Grant Binding 仍未接上。

`probe.py` 必須用該角色的實體 SCRAM Session 驗證 `session_user/current_user`、`rolinherit/rolsuper/rolbypassrls`、實際 `has_table_privilege`、跨角色 Membership、SECRET 隔離，以及三種直寫 SQL 與 `SET ROLE` 的 **SQLSTATE 42501**。Verifier 的正常 Replay INSERT 必須可成功執行並於測試 rollback；Authorizer 的正常 SELECT 必須可執行。CLI 不應輸出 DSN 密碼。若有任一項失敗，環境應標記 FAIL、停止本輪信任邊界驗收，**不得放寬 ACL 來換 PASS**。

## 失敗、恢復與記錄

- `bootstrap` 僅能在全新資料庫首次成功執行；重複執行若發現角色已存在必須停止，不覆蓋任何帳密。
- PostgreSQL 啟動、SCRAM 身分、Secrets Mount、網路路由、Role Membership、SQLSTATE 或 Probe 程式異常，一律視為驗收 **FAIL／BLOCKED**；不改動已有七容器，且不開正式發送。
- 記錄 Mirage SHA、Docker image digest、Compose config hash、PostgreSQL 版本、SQLSTATE 測試摘要、Gateway job IDs、容器數與原七容器健康狀態的前後對照。Secret 值與完整 DSN 不得寫入報告。
- 清理須另行由 Owner 核准 exact Lab 名稱及證據保存政策；不要使用 `docker system prune` 或任何廣泛刪除指令。

## 驗證與限制

本地可執行 `python -m compileall -q deploy/security-lab`、`python tools/check_documentation.py` 及差異檢查。真實 PostgreSQL 驗收只有在三個測試用實體 Login、隔離網路及各自 Secrets 皆可讀時才有意義。文件／容器啟動 PASS 不會自動把 `WORLD-ACL-*`、`G1/G2`、Restore、Snapshot 或 Protocol Freeze v1 正式安全驗收改為 PASS。

現階段沒有獨立授權服務、外部 Restore Anchor、隔離強制 `pg_hba.conf` 來源白名單或部署簽核；主機 root／Docker daemon 持有人仍可讀取測試檔。此 Lab 不是 production acceptance。

自有程式採 Apache-2.0；使用專案已具備的 Python 3、psycopg 與本機 Docker Compose，PostgreSQL Alpine 與 Mirage runtime image 的來源／授權依[專案授權表](../../licensing.md)，本 Lab 不引進模型或第三方秘密管理器。
