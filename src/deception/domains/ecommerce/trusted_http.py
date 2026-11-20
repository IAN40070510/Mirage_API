"""把可信 JWS、共享 Session 世界與一次性發送准入接到合成電商 HTTP 流程。"""

import hashlib
import json
import logging
import time
import os
import re
from pathlib import Path
from uuid import uuid4

from deception.api.fingerprint import fingerprint_request
from deception.api.pipeline import _unavailable, make_pipeline_handler
from deception.core.renderer import ResponseRenderer
from deception.core.orchestrator import PipelineResult
from deception.core.handoff import verify_candidate
from deception.generation.models import digest as candidate_digest
from deception.security.trusted_deployment import TrustedDeploymentSettings
from deception.security.ingress_audit import PostgresIngressAudit
from deception.world import (PostgresAdmissionControl, PostgresCandidateStore, PostgresProjectionRegistry,
                             ProjectionCompatibilityProfile, ProjectionEvidence)
from deception.world import DeviationApproval, WorldCompatibility
from deception.world.session import PostgresSessionWorlds, SessionBinding
from deception.world.request_audit import PostgresRequestAudit, RequestObservation, RequestAuditLink
from deception.world.transmission import AdmissionTransmission, response_envelope, response_hashes
from .cart_http import CartHTTP
from .inventory_http import InventoryHTTP
from .medusa_cart_http import MedusaCartHTTP

from .http_demo import DemoConfig, create_app as create_demo_app
from .synthetic.models import SyntheticDataset


def _digest(value) -> str:
    """對固定設定或已驗證 claims 計算確定性摘要，不把原始上下文保存到 Audit。"""
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def create_app(*, settings: TrustedDeploymentSettings, postgres_dsn: str,
               config: DemoConfig, output_root=None, world_ttl: int = 3600, enable_business: bool = False,
               enable_medusa_store: bool = False, medusa_publishable_key: str | None = None,
               medusa_source: Path | None = None,
               original_assessment_dsn: str | None = None):
    """建立共享 Session、假名化觀察與持久化 Admission 的合成 HTTP app。

    配置只核准本專案的 synthetic-store 契約，支援 GET getProduct 的 200／404。
    DSN 必須先套用 migrations 至 016。身份由 JWS provider 驗證，觀察保存失敗
    不進入業務；Grant 的 Audit 關聯與准入同交易保存。可選啟用合成業務及固定
    Medusa 映射，不接真實庫存／付款；任何必要來源無法確認時回固定 503。
    """
    if type(world_ttl) is not int or world_ttl < 60:
        raise ValueError("world_ttl must be at least 60 seconds")
    if type(enable_medusa_store) is not bool or (enable_medusa_store and not enable_business):
        raise ValueError("native store requires explicitly enabled synthetic business operations")
    if enable_medusa_store and not medusa_publishable_key:
        raise ValueError("native store requires a fixed publishable key")
    settings = TrustedDeploymentSettings.model_validate(settings.model_dump())
    provider = settings.build_provider(
        postgres_dsn=postgres_dsn, original_assessment_dsn=original_assessment_dsn
    )
    candidates = PostgresCandidateStore(postgres_dsn)
    # Production HTTP always binds final Send Authorization to the persisted
    # current Session epoch. Standalone conformance controls may opt out explicitly.
    control = PostgresAdmissionControl(postgres_dsn, require_session_binding=True)
    registry = PostgresProjectionRegistry(postgres_dsn)
    request_audit = PostgresRequestAudit(postgres_dsn)
    ingress_audit = PostgresIngressAudit(postgres_dsn, environment_id=settings.environment_id,
                                       deployment_id=settings.deployment_id)

    pending_evidence = {}

    def ensure_registered(evidence):
        """收集啟動所需的明確契約，完成建置後一次提交，避免每操作重開多條連線。"""
        key = evidence.projection_contract_hash
        if key in pending_evidence and pending_evidence[key] != evidence:
            raise ValueError("conflicting synthetic projection evidence")
        pending_evidence[key] = evidence

    def admitted(candidate, request, snapshot, source, evidence, authorization_deadline, transmission_deadline, observation):
        """保存最終封套，並原子關聯已驗證觀察與來源世界 Grant；失敗不取得發送權。"""
        compatibility = snapshot.compatibility
        if compatibility is None or not compatibility.permits(evidence):
            raise ValueError("world projection compatibility refused")
        encoded = response_envelope(candidate.status_code, candidate.headers, candidate.body_bytes)
        hashes = response_hashes(candidate.status_code, candidate.headers, candidate.body_bytes)
        ref = uuid4().hex
        candidates.put(snapshot.scope, ref, encoded, expires_at=transmission_deadline)
        admission = control.grant(world_generation_id=snapshot.scope.world_generation_id,
            request_binding_digest=fingerprint_request(request), candidate_ref=ref, candidate_hash=hashes[0],
            immutable_body_hash=hashes[1], semantic_headers_hash=hashes[2],
            projection_contract_hash=evidence.projection_contract_hash, authorization_revision="synthetic-1",
            authorization_deadline=authorization_deadline, transmission_deadline=transmission_deadline,
            source=source, projection_evidence=evidence, projection_registry=registry,
            request_audit=RequestAuditLink(observation=observation, target_scope=snapshot.scope,
                                          domain_validation="passed", contract_validation="passed"))
        if admission is None:
            raise ValueError("response admission refused")
        return AdmissionTransmission(control, candidates, snapshot.scope, admission)

    def configure(pipeline, runtime, data_config, initial_dataset):
        """只核准已建置的合成 operation，再建立使用同一快照的每請求 handler。"""
        if ((settings.environment_id, settings.deployment_id, settings.service_id, settings.site_id,
             settings.source_id) != (runtime.environment_id, runtime.deployment_id, runtime.service_id,
                                    data_config.scope.site_id, "local-demo-detector")):
            raise ValueError("trusted settings must match the synthetic deployment runtime")
        scope = data_config.scope
        profile_data = {"source": scope.spec_sha256, "platform": scope.platform_id,
                        "version": scope.platform_version, "world_schema": "1", "adapter": "ecommerce-1"}
        profile = ProjectionCompatibilityProfile(
            profile_id="synthetic-product", profile_version="1", profile_sha256=_digest(profile_data),
            platform_id=scope.platform_id, platform_version=scope.platform_version,
            source_spec_sha256=scope.spec_sha256, world_schema_version="1", domain_adapter_version="ecommerce-1")
        evidence_by_status = {}
        for status in (200, 404):
            contract_hash = _digest({**profile_data, "method": "GET", "path": "/products/{id}",
                                     "operation_id": "getProduct", "status": status, "query_context": {}})
            evidence = ProjectionEvidence(source_spec_sha256=scope.spec_sha256, compatibility_profile=profile,
                projection_contract_hash=contract_hash, official_schema_valid=True, effective_projection_valid=True)
            ensure_registered(evidence)
            evidence_by_status[status] = evidence

        business = {}
        business_evidence = {}
        if enable_business:
            output = Path(output_root or "generated/domains/ecommerce") / "business-contracts"
            business = {
                "carts": CartHTTP(dsn=postgres_dsn, origin=config.origin, output=output / "carts"),
                "inventory": InventoryHTTP(dsn=postgres_dsn, origin=config.origin, output=output / "inventory"),
            }
            if enable_medusa_store:
                business["medusa"] = MedusaCartHTTP(dsn=postgres_dsn, origin=config.origin,
                    output=output / "medusa", source=medusa_source or Path(
                        "domains/ecommerce/inputs/sources/medusa/openapi.yaml"), publishable_key=medusa_publishable_key)
            for api in business.values():
                for template, methods in api.specification["paths"].items():
                    for method, operation in methods.items():
                        for status in getattr(api, "response_statuses", (200, 409)):
                            data = dict(source=api.spec_hash, operation=operation["operationId"],
                                        method=method.upper(), path=template, status=status)
                            platform = api.platform_id
                            source_hash = getattr(api, "source_sha256", api.spec_hash)
                            profile_hash = getattr(api, "profile_sha256", _digest({"source": api.spec_hash}))
                            if isinstance(api, MedusaCartHTTP):
                                data["mapping_profile_sha256"] = profile_hash
                            compatibility = ProjectionCompatibilityProfile(
                                profile_id=platform, profile_version="1", profile_sha256=profile_hash,
                                platform_id=platform, platform_version=getattr(api, "platform_version", "1"), source_spec_sha256=source_hash,
                                world_schema_version="1", domain_adapter_version="medusa-cart-1" if isinstance(api, MedusaCartHTTP) else "ecommerce-1")
                            nullable_guest = (isinstance(api, MedusaCartHTTP) and status == 200
                                and operation["operationId"] in {"GetOrdersId", "PostCartsIdComplete"})
                            approval = None if not nullable_guest else DeviationApproval(
                                approval_id="medusa-native-guest-order-nullable", approval_revision="1",
                                source_spec_sha256=source_hash, projection_contract_hash=_digest(data),
                                approved_profile_sha256=profile_hash,
                                reason="Guest synthetic orders have no customer account; customer_id is null, not a fabricated identity.")
                            evidence = ProjectionEvidence(source_spec_sha256=source_hash,
                                compatibility_profile=compatibility, projection_contract_hash=_digest(data),
                                official_schema_valid=not nullable_guest, effective_projection_valid=True,
                                deviation_approval=approval)
                            ensure_registered(evidence)
                            business_evidence[(platform, operation["operationId"], status)] = evidence

        compatibility = WorldCompatibility.create(world_schema_version="1", domain_adapter_version="ecommerce-1",
            source_spec_sha256=scope.spec_sha256,
            profiles=[item.compatibility_profile for item in pending_evidence.values()])
        worlds = PostgresSessionWorlds(postgres_dsn, compatibility=compatibility)
        for api in business.values():
            api.service = type(api.service)(postgres_dsn, compatibility=compatibility)
        registry.ensure_registered_batch(pending_evidence.values())
        product_metadata = {product.id: product for product in initial_dataset.products}

        async def handle(request):
            """驗章後重查資源綁定再解析世界；錯配回固定錯誤，成功則保存單次發送狀態。"""
            stage = "trusted_ingress"
            observation = None

            def refuse(reason="unavailable"):
                """以固定分類保存拒絕，稽核不可用仍拒絕且只輸出不含請求內容的告警。"""
                if observation is not None:
                    try:
                        request_audit.close_unverifiable(observation)
                    except Exception:
                        logging.getLogger(__name__).error("mirage_request_audit_unavailable", extra={"audit_stage": stage})
                try:
                    ingress_audit.record_refusal(stage=stage, reason=reason)
                except Exception:
                    logging.getLogger(__name__).error("mirage_ingress_audit_unavailable", extra={"audit_stage": stage})
                return _unavailable(request)

            try:
                verified = provider.verify_with_claims(request)
                claims = verified.claims
                binding = SessionBinding(environment_id=claims.environment_id, deployment_id=claims.deployment_id,
                                          session_id=claims.session_id, session_epoch=claims.session_epoch, access_mode=claims.access_mode, resource_id=claims.resource_id)
                if binding.access_mode == "read_only" and config.mode != "fallback":
                    return refuse("read_only_policy")
                now = int(time.time())
                authorization_deadline = min(now + 20, claims.exp)
                if authorization_deadline <= now:
                    return refuse("authorization_expired")
                # 簽章證明 issuer，不代表 Session／資源／路徑的組合一定一致。
                # 先重查伺服器資源登記，避免錯配 claims 造成跨資源回應或替代世界初始化。
                stage = "resource_binding"
                resource_path = re.match(r"^/(?:synthetic|store)/(?:carts|orders)/([^/]+)(?:/|$)", request.path)
                if resource_path is not None or binding.access_mode == "cart":
                    if (not enable_business or binding.access_mode != "cart" or resource_path is None
                            or resource_path[1] != binding.resource_id):
                        return refuse("resource_scope_mismatch")
                    current_binding = business["carts"].service.resource_binding(binding.resource_id,
                        environment_id=binding.environment_id, deployment_id=binding.deployment_id, now=now)
                    if current_binding != binding:
                        return refuse("resource_scope_mismatch")
                initial = {"dataset": initial_dataset.model_dump(mode="json"),
                           "inventory": {variant.sku: variant.inventory_quantity for variant in initial_dataset.variants},
                           "catalog": {variant.id: {"sku": variant.sku, "unit_price": variant.price.amount_minor,
                                    "product_id": variant.product_id, "variant_title": variant.title,
                                    "title": product_metadata[variant.product_id].title,
                                    "handle": product_metadata[variant.product_id].handle}
                                       for variant in initial_dataset.variants},
                           "reservations": {}}
                stage = "world_resolve"
                snapshot = worlds.resolve(binding, initial, now=now, ttl=world_ttl)
                transmission_deadline = min(now + 30, snapshot.expires_at)
                stage = "read_admission"
                read = worlds.admit_read(binding, request_binding_digest=fingerprint_request(request),
                                         now=now, expires_at=transmission_deadline)
                observation = RequestObservation.from_snapshot(read.snapshot,
                    request_id_digest=hashlib.sha256(request.request_id.encode("utf-8")).hexdigest(),
                    trusted_context_digest=_digest(claims.model_dump(mode="json")),
                    request_binding_digest=fingerprint_request(request))
                request_audit.begin(observation)
                stage = "response_pipeline"
                if enable_business and (request.path.startswith("/synthetic/") or (
                        enable_medusa_store and request.path.startswith("/store/"))):
                    native = enable_medusa_store and request.path.startswith("/store/")
                    is_cart = native or request.path.startswith(("/synthetic/carts", "/synthetic/orders"))
                    api = business["medusa" if native else ("carts" if is_cart else "inventory")]
                    if is_cart:
                        candidate, source, result_binding, result_snapshot = api.execute(
                            request, binding, read, now=now, initial_state=initial)
                    else:
                        candidate, source = api.execute(request, binding, read, now=now)
                        result_snapshot = read.snapshot
                    transmission_deadline = min(now + 30, result_snapshot.expires_at)
                    evidence = business_evidence[(candidate.identity.platform_id, candidate.identity.operation_id,
                                                  candidate.status_code)]

                    def business_transmission(final, value):
                        """將已驗證的合成業務候選綁定到原操作快照或提交結果。"""
                        return admitted(final, value, result_snapshot, source, evidence,
                                        authorization_deadline, transmission_deadline, observation)

                    checked = verify_candidate(candidate, api.gate, request.raw_url)
                    result = PipelineResult(decision="validated", candidate=candidate, gate_result=checked,
                        trace={"request_id": request.request_id, "request_fingerprint": fingerprint_request(request),
                               "candidate_sha256": candidate_digest(candidate.to_dict()),
                               "release_deadline_monotonic": time.monotonic() + 30})
                    return ResponseRenderer(api.gate, transmission_factory=business_transmission).render(result, request)
                dataset = SyntheticDataset.model_validate(read.snapshot.state["dataset"])
                if dataset.config != data_config:
                    raise ValueError("world dataset deployment configuration changed")

                def assessment_for_request(value):
                    """重用本次已消費 JTI 的可信判定，不再次驗證或消費同一授權。"""
                    if fingerprint_request(value) != claims.request_fingerprint:
                        raise ValueError("request changed after verification")
                    return verified.assessment

                def transmission(candidate, value):
                    """核發只引用本次快照與精確最終 bytes 的一次性准入。"""
                    identity = candidate.identity
                    if (identity.operation_id != "getProduct" or identity.method != "GET"
                            or identity.spec_sha256 != scope.spec_sha256 or value.query_string):
                        raise ValueError("candidate is outside approved synthetic projection")
                    evidence = evidence_by_status[candidate.status_code]
                    return admitted(candidate, value, read.snapshot, read.source, evidence,
                                    authorization_deadline, transmission_deadline, observation)

                handler = make_pipeline_handler(pipeline, runtime=runtime, generation_config=data_config,
                    dataset=dataset, assessment_provider=assessment_for_request,
                    renderer=ResponseRenderer(pipeline.gate, transmission_factory=transmission))
                response = await handler(request)
                if response.status_code == 503:
                    return refuse()
                return response
            except Exception:
                return refuse()

        return handle

    app = create_demo_app(config, output_root=output_root, handler_factory=configure)
    app.state.transactions_supported = enable_business
    app.state.medusa_store_enabled = enable_medusa_store
    return app


def from_environment():
    """由部署環境載入公開金鑰設定與專用 DSN，供 uvicorn --factory 使用。

    MIRAGE_ENABLE_BUSINESS 須明確設 true 才啟用合成寫入。可選的
    MIRAGE_AUTO_MIGRATE=true 會先套用 checksum migration；預設由部署流程執行。
    任何設定或 schema 錯誤都阻止啟動，不切換至模擬判定或記憶體儲存。
    """
    required = ("MIRAGE_TRUSTED_SETTINGS_FILE", "MIRAGE_POSTGRES_DSN", "MIRAGE_DEMO_ORIGIN")
    if any(not os.environ.get(name) for name in required):
        raise ValueError("trusted settings file, PostgreSQL DSN and deployment origin are required")
    settings = TrustedDeploymentSettings.model_validate_json(
        Path(os.environ["MIRAGE_TRUSTED_SETTINGS_FILE"]).read_text(encoding="utf-8"))
    for name in ("MIRAGE_AUTO_MIGRATE", "MIRAGE_ENABLE_BUSINESS", "MIRAGE_ENABLE_MEDUSA_STORE"):
        if os.environ.get(name, "false") not in {"true", "false"}:
            raise ValueError("trusted runtime feature flags must be true or false")
    if os.environ.get("MIRAGE_AUTO_MIGRATE", "false") == "true":
        from deception.world.migrations import apply_migrations

        apply_migrations(os.environ["MIRAGE_POSTGRES_DSN"],
                         Path(os.environ.get("MIRAGE_MIGRATIONS_DIR", "migrations")))
    native = os.environ.get("MIRAGE_ENABLE_MEDUSA_STORE", "false") == "true"
    publishable_key = None
    if native:
        path = os.environ.get("MIRAGE_MEDUSA_PUBLISHABLE_KEY_FILE")
        if not path:
            raise ValueError("native store requires MIRAGE_MEDUSA_PUBLISHABLE_KEY_FILE")
        publishable_key = Path(path).read_text(encoding="utf-8").strip()
    return create_app(settings=settings, postgres_dsn=os.environ["MIRAGE_POSTGRES_DSN"],
        config=DemoConfig(origin=os.environ["MIRAGE_DEMO_ORIGIN"], mode="fallback"),
        output_root=Path(os.environ.get("MIRAGE_OUTPUT_ROOT", "generated/domains/ecommerce")),
        enable_business=os.environ.get("MIRAGE_ENABLE_BUSINESS", "false") == "true",
        enable_medusa_store=native, medusa_publishable_key=publishable_key,
        original_assessment_dsn=os.environ.get("MIRAGE_ORIGINAL_ASSESSMENT_CONSUMER_DSN"),
        medusa_source=Path(os.environ.get("MIRAGE_MEDUSA_SOURCE_FILE",
            "domains/ecommerce/inputs/sources/medusa/openapi.yaml")))
