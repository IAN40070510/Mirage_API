# Runtime 驗收證據與尚未完成的 Gate

本表對照 README Protocol v1.1。通過單一案例只證明該案例，不等於正式部署或完整符合性。執行結果與日期以[進度紀錄](implementation-progress.md)為準。

使用者已確認本輪以完成 Mirage 模組與隔離驗收為範圍，MSDSS 正式設定暫不處理。因此下列正式部署 Gate 保留為未來整合工作，不阻塞本版 Mirage 完成，也不將它們標示為已驗收。

2026-11-18 當前完整機器回歸為 **1221 passed、7 skipped，0 failed／errors**。四批終態 JUnit 的全部 1228 個 testcase 身份與原收集一致，無遺漏、重複、額外或非預期 skip；262 份來源／測試輸入及核准封存的非文件內容保持一致，詳見本機 `generated/acceptance-completion-20261118-summary.json`。七個 opt-in 不冒稱在該套 pytest 通過：四容器及還原已在本輪 ARM64 另驗，Medusa 身份／Gateway 兩項保留 2026-11-17 最近實測，對應身份與 dispatcher 模組本輪未變。正式部署 Gate 仍保持未核准／未啟用，不由此宣稱任意部署符合性。

| 要求 | 可重現證據 | 邊界／未完成項目 |
| --- | --- | --- |
| 可信請求、嚴格 JWS 與 Replay | test_trusted_session、test_trusted_ingress、test_trusted_clock、test_postgres_conformance | 已驗證授權使用同次接收端時間，核准 skew 內可供判定且不延長 signed exp；修正版 ARM64 有實際 HTTP／Audit 證據。需要固定金鑰政策與 TLS；正式 Gateway 注入未切換。 |
| 執行中金鑰撤銷與輪替 | migration 014、test_key_revocation | 新版入口持共享控制鎖至 Replay 完成，墓碑阻止新驗證；雙 TLS 程序沿用世界。新公鑰仍需預先配置，未涵蓋舊 binary、外部簽發端切換或已驗證在途取消。 |
| Gateway 真實 dispatcher → 獨立 HTTPS Mirage | test_msdss_wire | 使用實際 Gateway app 與測試判定器；不證明正式 detector 準確率。 |
| 真正多程序共享狀態 | test_process_conformance、test_control_processes | 不同 PID 競爭 JTI／Claim／Session，另以不同 backend PID 與真實鎖等待確認 Grant／Cutover／契約與 Profile 撤銷／發送邊界排序；獨立 reader 保留 Watermark／Lease／epoch。控制面 finish_send 是模擬回報，不代替真正 TLS 傳輸或跨主機分區。 |
| Medusa 身份與登出 | test_medusa_identity、test_medusa_live | 隔離 Medusa 2.22.4；Bearer 的客戶端登出不等於服務端 JWT 撤銷，另有 Mirage 本地撤銷。 |
| 匿名唯讀分組 | test_anonymous_identity、test_msdss_wire | IP／UA／窗口不是個人身份；NAT 合併、UA 偽造與換組限制見部署文件。 |
| 不可變 scope／snapshot、完整性與 CAS | test_world_runtime、test_session_worlds | 記憶體原型不取代共享 PostgreSQL。 |
| 世界相容性與契約更新 | test_world_compatibility、test_golden_vectors、test_container_runtime | 政策隨 state 保存並受 hash 保護，可信服務精確核對；舊快照缺少政策拒絕，不回補或重建。明列允許的 Profile 與 Registry 契約核准分別驗證；尚無自動相容遷移。 |
| Session 映射、epoch 封存與 watermark | test_session_worlds | TTL 到期拒絕；不自動續期或合併世界，尚無部署層 Lease 管理器。 |
| Registry 撤銷、Cutover、Grant／Claim 順序 | test_projection_registry、test_postgres_conformance、test_control_processes | 同一世代的真實跨程序鎖排序已有案例，不能推論任意跨世代多服務部署全數通過。 |
| 標準化事件提交結果 | world/commit.py、world/event_store.py、migration 015、test_commit_result | 已提供 EventWorldStore／CommitResult 的五類結果、保存摘要、鍵、failure code 與同 scope 唯讀恢復；庫存及購物車事件重用共用交易。低階 CAS、領域相容 DTO 與購物車初始化仍保留原介面，記憶體事件後端與跨語言數值 SDK 未提供。毀損、舊紀錄不補摘要、真正 COMMIT 失聯及 JSONB 數值已有定向證據；新版 ARM64 映像與還原已另驗，目前工作區整套回歸仍執行中，見[說明](commit-results.md)。 |
| 精確候選與單次發送 | test_renderer_admission、test_postgres_conformance | 明確固定兩個編碼版本、巢狀證據不可變、Claim 前重新驗證；舊 JSON 預設 v1。ASGI 回呼完成不是對端收到；在途部分失敗不回退真實後端。 |
| 固定安全錯誤的最終 Renderer | test_security_error_renderer、api/pipeline.py 的 _unavailable | 已改為獨立固定模板 Renderer；核對完整原請求、來源與精確封套，改寫／逾期在 start 前停止。HEAD 無 body，重複憑證標頭仍可安全拒絕；不讀 DB／World，不把 503 當權威 Medusa 404。可信 HTTP 與映像的本輪重驗另列進度。 |
| Golden Vectors | test_golden_vectors、test_trusted_session、test_commit_vectors、test_trusted_error_vectors | Node／Python 獨立重算 request fingerprint、驗章與 transport hash；另有 16 組 Admission／投影向量、30 組 CommitResult 向量及 61 組 JWS 接受／拒絕向量（15 種基本拒絕碼）。實際 Gateway 適配器也核對請求向量。Node 是固定案例的核對器／簽發器，不是完整 SDK；共享儲存、控制面故障與所有部署互通不能由這些離線向量推定完成。 |
| 未知交易結果／網路中斷 | test_postgres_network、test_postgres_conformance | 實際 TCP COMMIT 回覆遺失已有驗收；網路代理位於本機，連線經 SSH 隧道。 |
| 真正資料庫 Crash recovery | 2026-11-16 及 2026-11-17 專用 volume 與 SIGKILL／start 的紀錄 | 新版共用交易核心另驗同一版本／state hash／result digest／原 attempt，重播不重複預留，事件／操作／收據／初始化各一筆；三項耐久設定 on，WAL redo 有日誌。不是跨區災難恢復、主機斷電、備份還原或所有 fsync 故障證明。 |
| 隔離邏輯備份還原 | test_database_restore、專用 DB 的 pg_dump／pg_restore | 比對全部表摘要、世界完整性及撤銷墓碑；同 cluster、停止寫入、合成資料限定，不取代 PITR、跨區恢復或正式安全基線。 |
| 訪客購物車、合成訂單與庫存 | test_guest_carts、test_inventory_events、test_cart_http | `/synthetic` 契約；不自動符合原生 Store 全欄位。真實付款、庫存與配送不在此能力內。 |
| Medusa 原生購物車映射 | test_medusa_cart_projection、test_medusa_cart_http、test_msdss_wire 的 native-store、test_container_runtime | 七個明列的 `/store` 操作直接重用合成引擎；固定來源與有效契約分別核對。匿名訂單 customer_id 的 nullable 投影是明列差異，不宣稱原始官方 schema 全數通過。非空 query、完整付款與配送不在範圍內。 |
| 原子初始化、業務與傳輸稽核 | migration 010、test_postgres_network、test_cart_http | 不回補既有歷史事件；尚無保留政策與集中稽核平台。 |
| 請求與驗證結果的持久 Audit 關聯 | request_audit.py、migration 016、test_request_audit、test_request_audit_http | 已新增 request_observed、request_id／可信上下文摘要及基底版本，最終通過結果與 Grant 同交易，再連到傳輸稽核。合法業務安全錯誤不捏造 committed 證據，未知停止不假稱回滾。ASGI、真實交易排序、完整回歸及 ARM64 HTTP／還原均有證據，原映像揭露的時鐘落差已修正並另驗，歷史失敗保留。前置拒絕維持最小分類，沒有歷史回補或公開匯出，見[請求 Audit](request-audit.md)。 |
| 可信讀取前的拒絕稽核 | migration 013、test_ingress_audit | 跨程序保存驗章及資源錯配的固定分類，不保存憑證或原始請求；稽核故障仍拒絕並固定告警。handler 前框架拒絕與起送後故障另屬其他邊界，尚無統一管理匯出。 |
| 非 root／唯讀 ARM64 映像 | test_container_runtime、Docker inspect | 隔離容器已驗證 user 10001:10001、readonly=true、健康及交易；未替換 staging。 |
| L3 真實資料連續性 | 預設不啟用 | 缺少核准 mapping、版本／scope／到期與真實資料來源；不以猜測完成。 |

七項原生購物車映射已有固定來源與獨立有效投影，不因此批准全域草稿 Medusa Profile。尚未通過的正式 Gate 包括：正式 Gateway／身份服務設定、L3 資料映射、完整多 Instance 部署矩陣，以及生產運維的備份還原、保留與秘密輪替。這些項目需要分別提供實作與證據，不能由合成交易成功推定完成。

## README 具名 Baseline 要求核對

下表指出可定位的案例及仍不足的證據。「已有案例」不是完整符合性或正式部署聲明；實際執行結果見進度文件與本機 JUnit 報告。特別保留 HTTP、物件、執行緒與獨立程序的差別，不把不同層的通過拼成未執行的場景。

### L1／L2 最低機器驗收

| Test ID | 可定位案例 | 完成範圍或仍需處理事項 |
| --- | --- | --- |
| L1-01 | test_d_e_h_i_preserves_exact_candidate_and_passes_synthetic_contract、test_pipeline_http_returns_the_validated_product_and_request_id | 核准展示商品投影；七項原生 Store 使用自己的固定來源與有效投影，不因此核准完整 Medusa 商品規格。 |
| L1-02 | test_zero_products_is_a_valid_empty_dataset、test_fixed_zero_stock_and_zero_price_are_supported、test_guest_order_has_explicit_nullable_deviation_and_no_fake_payment、test_real_medusa_200_explicit_fixture_maps_e_and_rejects_missing_field | 空集合、合法零值、匿名 customer_id=null 與必填缺失分別驗證；手寫完整商品 fixture 只是 schema 證據。 |
| L1-03 | test_local_demo_missing_product_uses_template_without_contacting_model、test_demo_missing_id_is_encoded_before_authoritative_404_echo | 固定 404 使用本次 ID 的安全編碼；不得改用不相關 ID 或讓模型決定身份。 |
| L1-04 | test_unreviewed_attack_query_is_rejected_before_generation、test_digest_and_remote_refs、test_admission_rejects_projection_not_authorized_by_registry | 未核准 query、來源 hash 與 Registry 授權均有拒絕路徑。 |
| L1-05 | test_found_product_uses_its_actual_index_and_passes_h_i、test_admitted_renderer_sends_exact_bytes_once | Domain／契約與 Renderer 核對同一候選；傳輸故障另驗，不把 Client 收到當作已證明。 |
| L2-01 | test_known_missing_known_sequence_preserves_product_content_and_snapshot、test_published_world_content_survives_model_change_and_restart_without_inference | 同商品穿插 404 後仍保持原快照及內容；模型變更不覆寫已發布內容。 |
| L2-02 | test_world_content_versions_and_scope_never_cross_reuse、test_two_services_interleave_session_writes_without_crossing_inventory | 兩個真實 TLS 程序共用 PG，交錯不同 Session 的品項／訂單／取消，不跨世界改動。 |
| L2-03 | test_relations_uniqueness_and_generation_ranges、test_queries_paginate_and_return_independent_snapshots、原生 Store 完整流程 | 已輸出的商品／變體關聯由同一快照核對；目前不生成非空 Option／Image 實體，不能宣稱那些未提供的實體生命週期已實作。 |
| L2-04 | test_native_time、test_native_creation_context_is_atomic_and_retained_for_retries | 單調業務時間與讀寫共用檢查已有主工作區 29 項定向、完整回歸、ARM64 交易探測及四項 HTTP 證據，格式／順序不合法拒絕且不回填歷史。schema 接受 deleted_at 不證明刪除生命週期，現有商品沒有刪除操作。 |
| L2-05 | test_known_missing_known_sequence_preserves_product_content_and_snapshot、test_local_demo_missing_product_uses_template_without_contacting_model | 404 不修改資料集；首次世界初始化與業務事件明確分開，不能由「有初始化稽核」推定 GET 修改商品。 |
| L2-06 | test_store_create_if_absent_and_cas_reject_conflicts、test_postgres_cas_preserves_world_policy_and_receipts、test_concurrent_reservations_do_not_oversell | CAS 衝突不覆寫新版，合成庫存並行不超賣。 |
| L2-07 | test_generation_cannot_overwrite_protected_product_facts、test_model_cannot_add_undeclared_generation_fields、test_content_entry_publication_keeps_winning_values_and_recipe_together | 生成白名單與權威欄位隔離；購物車／訂單狀態及原生事件時間由事件引擎產生，不交模型更新。 |
| L2-08 | test_store_reports_expired_and_unavailable_without_creating_a_world、test_validly_typed_but_tampered_data_is_rejected、test_corrupted_published_entry_stops_before_models_or_fallback | 到期、故障或損壞拒絕，不建立替代世界或重新生成掩蓋問題。 |

### 安全與整合 Baseline

| Test ID | 具體案例／目前證據 | 完成範圍與缺口 |
| --- | --- | --- |
| SEC-01 | test_msdss_wire、test_guest_resource_scope_and_creation_idempotency | Gateway 忽略偽造 x-session-id，資源綁定不接受另一 cart 的 session。 |
| SEC-02 | test_replayed_jws_is_rejected_by_provider、test_process_conformance 的 replay | 已有入口重放與真正跨程序共享消費案例。 |
| SEC-03 | test_native_medusa_guest_cart_to_order_and_internal_cancellation | 每次簽新 JTI，相同建立／完成業務鍵重用結果與投影。 |
| SEC-04 | test_reservation_and_cancellation_are_idempotent、原生 HTTP 同鍵異內容 | 相同鍵換內容拒絕；不重新扣庫存。 |
| SEC-05 | test_scope_mismatches_have_identical_http_refusal_without_new_worlds | 兩個獨立 TLS 業務服務核對 72 組 cart／order、原生／合成、已存在／不存在與 scope 錯配；狀態／標頭／本文一致，世界、讀取准入及業務筆數不變。Replay 消費另計，尚無統一入口拒絕稽核匯出。 |
| SEC-06 | test_required_jws_policy_rejections_do_not_consume_valid_authorization | 20 組明列負例，另驗 13 個必填 claim 缺失；不因錯誤 token 耗用合法授權。 |
| AUTH-10 | test_same_jws_reaches_two_independent_tls_ingresses_once | 同一合法 JWS 經 TLS 並行送入兩個不同 PID 的 Mirage 驗章入口，只一次成功；重送皆 503，程序退出後另一 provider 仍見 Replay。涵蓋授權入口，不等同整套電商多主機部署。 |
| WORLD-01 | test_snapshot_nested_state_and_scope_are_immutable、原生 HTTP 商品／訂單關聯 | JSONB 單份快照、不可變與明確投影已驗；不推論未實作的分散式或多表快照。 |
| WORLD-02 | test_two_services_interleave_session_writes_without_crossing_inventory | 真正兩個 TLS 業務程序交錯加入 A／B、跨程序下單及取消 A；B 的快照／庫存／訂單／版本不變。兩程序位於同一本機，共用隔離 PostgreSQL，不宣稱跨主機分區驗收。 |
| WORLD-03 | test_concurrent_reservations_do_not_oversell、test_postgres_cas_preserves_world_policy_and_receipts | 並行 CAS 只有一次成功，不覆寫新版；政策變更失敗無收據。 |
| WORLD-04 | test_postgres_unavailable_store_is_fail_closed、快照 hash 負例 | Store 不可用或損壞不建立替代世界。 |
| WORLD-11 | test_process_conformance 的 session | 真正雙程序同步初始化，只保存同一世界；worker 退出後查回。 |
| PROJ-01 | 原生 HTTP 及 test_cart_http | 同一資源世界經建立、品項、完成、查單與取消等契約沿用。 |
| PROJ-02 | test_admission_rejects_unknown_encoding_or_mixed_evidence、Golden 拒絕向量 | 不接受另一契約或跨世代的 Admission 證據。 |
| PROJ-03 | test_policy_allows_reviewed_contracts_without_rebinding_world、原生 HTTP | 世界不綁單一 operation；只准明列 Profile，契約仍查 Registry。 |
| PROJ-04 | test_session_rejects_policy_changes_without_reinitialization、test_profile_revocation | 不相容政策不重建；整體 Profile 墓碑阻止既有／未來契約及重啟復活。一般模式保留舊准入，緊急模式核對未起送邊界；尚未驗收舊 binary 混合部署。 |
| PROJ-10 | test_registry_revoke_orders_concurrent_grant | Profile 證據仍有效但契約已撤銷，Grant 拒絕；並行順序另驗。 |
| HTTP-01 | test_admitted_renderer_sends_exact_bytes_once、test_response_transport_vector_matches_python_and_node | 比較最終封套 bytes、hash 與單次發送；不宣稱客戶端已收到。 |
| HTTP-02 | test_msdss_wire、test_asgi_fault_never_reopens_admission | 判為欺敵後失敗不回退真實後端；在途錯誤不重新開啟准入。 |
| L3-01 | SyntheticData 的 `synthetic_only=True`／`real_data_imported=False` 固定政策測試 | 目前拒絕宣稱匯入真實資料；尚無 L3 mapping／實體連續性功能，不能宣稱正向整合完成。 |

自有文件採 Apache-2.0。套件與僅參考規格的授權見[授權表](licensing.md)，本表未引入新套件或模型。
