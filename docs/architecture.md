# 詳細架構與執行邊界

整體目的與工具分工先看 [README 架構總覽](../README.md#系統架構)。本頁補充啟動組裝、每次請求的執行步驟、快取與失敗處理，供設定部署或查閱程式時使用。

領域資產位置與插件介面見 [領域設定](domains.md)；資料投影格式見 [共用資料交換](common-data.md)。

## 領域載入與啟動組裝

此圖對應共用展示入口 `deception.api.demo:create_app`。正式部署也可由自己的組裝程式建立元件，再注入 `deception.api.pipeline.create_app`。

```mermaid
flowchart TB
    appConfig["共用設定與環境覆寫<br/>configs/app.yaml"] --> selection["核對所選領域、資產路徑及已註冊實作"]
    assets["領域資產包<br/>domains/領域名稱/<br/>domain.yaml、configs、inputs、security"] --> selection
    registry["受信任程式註冊的領域實作<br/>src/deception/domains/<br/>情境處理器、資料供應器及展示入口"] --> selection
    selection --> factory["所選領域的展示工廠"]
    factory -->|未選弱點情境| prepare["建立領域契約、Profile、合成資料與政策"]
    factory -->|明確選用弱點情境| security["核對情境目錄與分類版次<br/>只接受已實作的受控處理器"]
    taxonomies["共用安全分類<br/>inputs/security_taxonomies/"] --> security
    security -->|套用合成契約與政策限制| prepare
    security -->|未知或僅設計中的情境| startupFailure["停止啟動"]
    prepare --> assemble["組裝共用協調器、生成器、組合器<br/>契約 gate、修正備援與 HTTP 回送器"]
    modelConfig["共用模型設定<br/>configs/llm.yaml"] --> assemble
    assemble --> app["FastAPI 展示服務<br/>模型模式或固定備援模式"]
    prepare --> outputs["領域展示產物<br/>generated/domains/領域名稱/"]
```

弱點情境在啟動時由管理者選定。展示工廠先把固定誘餌值及必要標頭等限制加入合成契約，再建立規格摘要與 Profile，並將固定值套入相應政策；目前沒有依訪客請求自動偵測 OWASP 類別或切換弱點的功能。未知領域、資產越界及不符設定也會停止啟動。

## 每次請求的生成與回送

下圖呈現完整 HTTP 接入的共用流程。虛線表示領域供應器、模型服務或內容快取的資料依賴；外部系統的來源認證由部署整合負責，隔離展示則明確注入 `simulated_malicious` 模擬判定。

```mermaid
flowchart TB
    request["HTTP API 請求"] --> ingress["FastAPI 入口<br/>標準化、大小限制與追蹤 ID"]
    ingress --> assessment["取得伺服器注入的可信判定<br/>展示使用模擬判定"]
    assessment --> identify

    subgraph orchestration["共用任務協調器：同一次執行的預算與期限"]
        identify["平台與部署識別<br/>讀取固定操作 Profile"] --> scenario["準備情境、核對領域資料<br/>選定結果分支與映射"]
        scenario --> planning["受限模型工具規劃"]
        planning --> content["白名單欄位生成<br/>查詢片段快取，未命中才生成"]
        content --> candidate["回應組合與候選契約驗證<br/>保留 scope、事實映射及固定誘餌值"]
        candidate -->|通過| checked["重查上下文與有效期限<br/>模型路徑另核對模型身份及發布內容快取"]
        planning -->|模型不可用或規劃失敗且符合備援條件| fallback["精確同分支的固定欄位備援"]
        recovery["有限欄位修正<br/>沿用同一次執行預算"]
        content -->|可修正的內容錯誤| recovery
        candidate -->|可修正的模型生成內容錯誤| recovery
        recovery -->|預算內重新生成允許欄位| content
        recovery -->|修正用盡且政策與預算仍允許| fallback
        fallback -->|套用後重新組合驗證| candidate
        fallback -->|未設定或條件不符| failure["停止生成並回固定診斷"]
        recovery -->|預算或期限耗盡| failure
        candidate -->|備援驗證失敗或其他不可修正錯誤| failure
        checked -->|重查或快取競爭核對失敗| failure
    end

    provider["所選領域的情境處理器與資料供應器<br/>事實投影及 CompositionData(scope, payload)"] -.-> scenario
    provider -.-> candidate
    model["Pydantic AI 與本機 Ollama"] -.-> planning
    model -.-> content
    cache[("已驗證的生成片段快取")] -.-> content
    checked -.->|僅模型生成路徑發布片段| cache
    checked --> renderer["HTTP 回送器<br/>完成傳輸標頭並重驗最終契約"]
    renderer -->|通過並封存| response["HTTP 誘餌回應<br/>status、headers 與原樣 body bytes"]
    renderer -->|最終驗證失敗| failure
```

組合器接收領域供應器已核對的 `CompositionData`，不限定商品或變體根節點。快取只保存生成片段，命中時仍須經過本次身份、情境、模型規劃及回應驗證；發布競爭若取得另一份勝出值，會重新組合並驗證。固定備援不寫入模型內容快取，也必須通過相同的組合、契約及最終 HTTP 驗證。

圖中修正僅處理允許的生成欄位；模型不可用或規劃失敗時，符合條件才直接選固定備援，不進入欄位重新生成迴圈。來源、身份、HTTP metadata、資料、判定關聯或期限不符時會停止，不能透過修正或備援放行。部署代理接入、遠端判定來源認證、集中設定及交易狀態更新仍列於下方「驗證與目前邊界」，未畫成已實作元件。

## 驗證與授權

本頁整理既有元件，沒有新增工具、套件或模型。設定與呼叫範例見 [Docker 與展示入口](docker.md)，功能驗證見 [HTTP 驗證工具](verification.md)。維護本頁後執行 `python tools/check_documentation.py`，並核對圖示與對應程式的執行順序；文件檢查不代替實際功能測試。

套件、模型與來源資料授權沿用 [專案授權清單](../README.md#開源軟體模型與資料授權)；OWASP 分類及領域映射另見 [分類說明](owasp-design.md)。
