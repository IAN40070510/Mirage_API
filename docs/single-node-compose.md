# 標準單機 Docker Compose — D-74 候選部署規格

> 產品方案：**一台 Ubuntu 主機、標準 `standard_single_node`、不要求外部 Fence**。
> 目前實作：**拓樸與隔離 Gateway 候選已具備；正式 release NO-GO**。
> 這份 Compose 不會替代尚未完成的 G3b～G6、全部 SCRAM/ACL、GC／Restore
> 故障與 Owner 驗收。**Trusted Send／DECEIVE 必須維持 OFF**。

## 用途與信任邊界

`deploy/single-node/compose.yaml` 將目前程式真正有 CLI 啟動能力的
Verifier、兩個 Executor、Native Validator、Candidate Publisher、Authorizer、
Sender 與單一 PostgreSQL 17 組裝在**同一台主機**。Gateway 使用
`single_node_gateway.py`，但只作 `isolated-gateway` 顯式 Profile 的
**loopback 封閉候選**，不提供公網預設入口；這是未解封前的部署驗證骨架。

| 服務 | 非 root UID | 網路 | 入口／出口用途 |
| --- | --- | --- | --- |
| `gateway`（選配隔離啟動） | 10020 | `edge`／`ingress`／`delivery` | Host `127.0.0.1:18443` → HTTPS Gateway；只發 Verifier／Sender mTLS |
| `verifier` | 10021 | `ingress`／`execution`／`promotion`／`database` | 從 Gateway 的 mTLS 消費原 HTTP，固定 Executor／Validator／Publisher／Authorizer |
| `inventory-executor` | 10022 | `execution`／`database` | 固定庫存業務，獨立 SCRAM |
| `cart-executor` | 10023 | `execution`／`database` | 固定 Cart／Order／Medusa 業務，獨立 SCRAM |
| `native-validator` | 10024 | `execution`／`database` | 唯讀重建原生 bytes 與 Scope |
| `candidate-publisher` | 10026 | `promotion`／`database` | 同一進程內三個**不同實體** DB 身分 Reader／Writer／Promoter |
| `authorizer` | 10027 | `promotion`／`database` | 受保護 Grant／Snapshot 寫入權 |
| `sender` | 10025 | `delivery`／`database` | 只接受 Gateway Client CA；目前始終封閉，無公網 port |
| `postgres` | 官方 PG 映像身分 | `database` | 保存 World；只有 Compose 內網，無 host port |

`ingress`、`execution`、`promotion`、`delivery`、`database` 全部為
`internal: true`；只有 Gateway 的 `edge` 可以與本機發布的埠連線。
每個 Runtime 容器皆 `read_only`、`cap_drop: ALL`、
`no-new-privileges`、獨立 UID、不同 Secret 清單；沒有任何 Fence DSN。
受保護服務的 `restart: "no"` 避免 Docker 自動重啟後繞過 Known Restore
停流；Operator 必須先完成對帳才可手動啟動。

### 啟動前準備（不能略過）

1. 單機 Ubuntu 已安裝 Docker Engine 與 Compose v2，建立固定 Revision 的
   `mirage-api:standalone`，正式釋出前改以**已審查的 image digest** 釘選。
2. 在版本庫**外**建立 `MIRAGE_SINGLE_NODE_SECRETS_DIR`，提供 Compose 所列
   55 份獨立 Secret 掛載檔。包含 PG 管理員密碼、九個最小權限 SCRAM DSN、
   不同 mTLS server/client/CA 及不含私鑰的固定證據、JWS 公鑰註冊表。
   **不得在 .env、命令列、Issue、README 或 Image 內放密碼／私鑰**。
3. 使用已核准的離線 Migration 和 SQL provisioning 流程，建立固定 Schema、
   彼此不同的 `LOGIN NOINHERIT`、必要的 SELECT/INSERT／禁止性 ACL，
   所有 DSN 綁同一 World PostgreSQL，並核對 `current_schema()`。
   Compose 不會自動給 Runtime PostgreSQL 管理員權限，尚未提供正式自動
   Provisioner；缺少一項，服務應因啟動前 ACL 檢查失敗而停機。
4. 使用每服務獨立且 SAN 正確的 TLS 身分（`verifier`、`sender` 等容器 DNS
   名稱必須符合憑證）。Verifier→Publisher 與 Verifier→Authorizer 不得
   複製相同 Client Certificate 公鑰。Gateway→Verifier／Sender 使用不同 CA。
5. **Compose `file:` Secret 使用 bind mount，`uid`／`gid`／`mode` 設定可能
   不受支援。** 主機側檔案須以真實 UID/GID 與嚴格 ACL 授權特定容器讀取，
   私鑰／DSN 不得 world-readable，路徑不可 symlink。若此條件無法成立
   **不得啟動**；請勿用 `chmod 644` 解決私鑰讀取失敗。

可由 [`deploy/single-node/env.example`](../deploy/single-node/env.example) 複製
非機密變數清單到版本庫外的環境檔，填上正式部署專用的範圍 ID、角色名稱和
已固定映像。示例值是佔位符，**不可視為正式部署值**。

### 靜態核對與候選啟動

先在**與正式主機分離的隔離環境**，且 Secret 來源已正確準備後：

```bash
# 靜態檢查：不讀取也不輸出 Secret 內容，不啟動服務。
python3 tools/check_single_node_compose.py
python3 tools/check_documentation.py

# 在部署者已載入非機密變數的 shell：只解析配置，不啟動容器。
docker compose -f deploy/single-node/compose.yaml config --quiet

# 下兩個操作必須先完成真 SCRAM／Secret／TLS／DB Schema 隔離驗證。
# docker compose -f deploy/single-node/compose.yaml up -d
# docker compose --profile isolated-gateway -f deploy/single-node/compose.yaml up -d
```

Compose 目前預設起內部七角色與 DB，`gateway` 除非指定
`--profile isolated-gateway` 不會出現。即便明確開啟，只發布
`127.0.0.1:${MIRAGE_SINGLE_NODE_GATEWAY_LOCAL_PORT:-18443}:8443`，
並要求 `MIRAGE_SINGLE_NODE_GATEWAY_MODE=sealed_candidate_only`、
`MIRAGE_TRUSTED_SEND_ENABLE=false`。Gateway 只有隔離 Candidate HTTP
轉發流程，Sender 依然拒絕正式發送，沒有開關可讓它變成正式公開入口。
Socket 健康檢查只證明 Listener 活著；`pg_isready` 只證明 DB 可連線，
**都不代表 mTLS 身分、功能、ACL 或 G3b～G6 已 PASS**。

### 獨立 PostgreSQL 生命週期實測（SINGLE-NODE-01 子項）

`tests/test_single_node_lifecycle.py` 在**明確允許銷毀的隔離 Docker 主機**
以密碼學亂數建立全新的 `mirage-sn-ci-*` Compose 專案，只啟動本份
`compose.yaml` 的 `postgres`。它會檢查真 PostgreSQL 17 啟動與 DB 身分、
不公開 Host port、專案唯一 `internal: true` 的 `database` 網段、
Compose 自有具名 World volume，寫入測試 SQL 後重啟 Postgres 並核對資料
仍存在。最終僅針對**本次亂數專案**執行 `down --volumes`，驗證該專案
容器／卷已清掉；這個刪除操作**絕不可套用正式環境**。

一般 CI 不執行此測試。只在經確認為本專用測試主機、確有
`/usr/local/bin/docker-compose` 和 `/usr/bin/docker` 且
`mirage-g3b-ci-db` 是專用拋棄式 PG Lab 的條件下，才可設：

```bash
MIRAGE_SINGLE_NODE_PG_LIFECYCLE_ISOLATED=true \
MIRAGE_SINGLE_NODE_DISPOSABLE_COMPOSE_PROJECT=true \
MIRAGE_G5_RESTORE_PG_TOOL_CONTAINER=mirage-g3b-ci-db \
python3 -m pytest -q tests/test_single_node_lifecycle.py
```

這只驗證**一個真的 PostgreSQL 容器**的啟停、隔離與持久化；
其餘八服務及選配 Gateway **沒有**一起啟動，不可由此宣稱
`SINGLE-NODE-01` 整項 PASS 或 `SINGLE-NODE-02` 最小權限已完成。
正式主機的 Schema、獨立 SCRAM／Secret、實際 mTLS、客戶端錯誤、
GC／Restore、故障注入與 Owner 仍各有獨立 Gate。

### G5 停流／還原與錯誤處理

`verifier`、`gateway` 和 `sender` 都有明確
`mirage.restore.stop_eligible=true`／`mirage.restore.role` 標籤。
受控還原必須以 `DockerRestoreIsolation` 綁**每個**實際完整 Container ID，
停止並機器核對所有入口與 Sender 後才執行 World 還原、寫入 Known Restore
Marker 並由獨立 Sender 帳號讀回。對一份忘記列出 Gateway 的 Manifest，
Docker 停機成功也**不能證明全入口已停流**；目前控制器沒有自動枚舉
部署容器、完整序列鎖、外部連線 Drain、GC 真刪除或正式放行流程。

- 容器、DB、TLS 或 ACL 錯誤：禁止回退 Demo／Runtime 明文路徑；必須停留在
  `NO-GO`，保留診斷碼與不含 Secret 的證據。
- 恢復前應備份資料並核對資料卷及權限；**禁止使用 `docker compose down -v`
  或刪除 World volume 來「修復」部署**。
- `standard_single_node` 在沒有外部獨立證據時**不保證**檢測整機
  Snapshot/VM 回滾，正式驗收應報告 `whole_host_rollback_guarantee=false`。
- 不能將隔離服務的 PASS 算作 G3b～G6 全域 GO；仍需要正式七服務啟動、
  獨立實體 Client、負面 HTTP 矩陣、GC/Restore、效能、故障與 Owner 簽核。

## 驗證與目前限制

`tests/test_single_node_compose.py` 將真 YAML 解析成部署拓樸，核對所有服務、
Secret 掛載、Role、最小網段、Restart Policy、受控 Restore Label，並故意
篡改 Gateway 公開埠、Sender／DB port、Trusted Send、外部 Fence、跨角色 DSN、
Restart、UID 與健康探針，要求全部拒絕。Gateway 測試使用**臨時真 X.509**，
核對憑證複用、權限過寬、非法 Profile 與啟動前固定 Bind。通過此套測試
仍只是 **STATIC／ISOLATED candidate PASS**，正式完整容器部署尚待可重現
端到端及 Owner 簽核。

專案程式採 Apache-2.0；Docker Compose／PostgreSQL／依賴與測試素材
的個別授權、來源與注意事項見 [授權與第三方材料](licensing.md)。
相關設計：[D-74 標準單機與選配 Fence](security/world-db/single-node-restore-profiles.md)、
[受保護角色與 mTLS](protected-services.md)、[受控還原](protected-send.md)、
[安全驗收矩陣](security/world-db/verification-plan.md)。
