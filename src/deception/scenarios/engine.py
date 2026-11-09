"""F 的確定性選擇器：只評估固定條件，沒有網路、eval、LLM 或狀態寫入。"""

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from deception.api.ingress import NormalizedRequest
from deception.discovery.models import IdentificationResult
from deception.profile_builder.builder import read_yaml
from deception.profile_builder.models import OperationContext
from deception.common.models import DatasetScope
from mirage_validator.request_matching import (match_base_url, parse_query,
                                               parse_request_url, select_operation)

from .models import (AttackAssessment, DomainOutcome, DomainPolicy, PreparedScenario,
                     ScenarioDecision, ScenarioIssue, ScenarioPreparation)
from .registry import DomainRegistry, default_registry

IDENTITY_KEYS = ("environment_id", "deployment_id", "service_id", "site_id", "platform_id",
                 "platform_version", "spec_sha256", "operation_id", "method", "path")


def _encoded(value) -> bytes:
    """固定 JSON 序列化，讓政策、模板及決策摘要可重現且不接受 NaN。"""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _digest(value) -> str:
    """摘要只作身份／完整性記錄，不代替外部來源認證。"""
    return hashlib.sha256(_encoded(value)).hexdigest()


def fingerprint_request(request: NormalizedRequest) -> str:
    """關聯 A 的完整請求快照；保存摘要，不將 body 或憑證加入追溯輸出。"""
    return _digest({"request_id": request.request_id, "method": request.method,
                    "raw_url": request.raw_url, "path": request.path,
                    "raw_path": request.raw_path.hex(), "query_string": request.query_string.hex(),
                    "query": request.query, "headers": request.headers,
                    "body_sha256": hashlib.sha256(request.body).hexdigest()})


def load_policy(path: Path, *, domain: str | None = None,
                registry: DomainRegistry | None = None) -> DomainPolicy:
    """依明確領域選擇嚴格政策模型；未知或與呼叫端選擇不符時不回退。"""
    value = read_yaml(path.read_bytes())
    if not isinstance(value, dict) or not isinstance(value.get("domain"), str):
        raise ValueError("Scenario policy requires an explicit domain")
    if domain is not None and domain != value["domain"]:
        raise ValueError("Selected domain does not match policy domain")
    handler = (default_registry() if registry is None else registry).get(value["domain"])
    checked = handler.policy_type.model_validate(value)
    if checked.domain != value["domain"] or checked.domain != handler.domain_id:
        raise ValueError("Domain handler and policy model disagree")
    return checked


class _Refusal(ValueError):
    """內部失敗分支，只攜帶固定訊息，不回顯請求內容。"""

    def __init__(self, code: str, reason: str):
        """保存情境拒絕的固定錯誤碼與原因，交由 prepare／resolve 建立失敗結果。"""
        self.code, self.reason = code, reason
        super().__init__(reason)


def _time(now: datetime | None) -> datetime:
    """預設讀 UTC；測試可注入時鐘，但不允許沒有時區的時間。"""
    now = datetime.now(timezone.utc) if now is None else now
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise _Refusal("invalid_clock", "需要帶時區的時鐘")
    return now.astimezone(timezone.utc)


def _check_identity(request, identification, profile):
    """核對 B/D 並以原始 URL 重選相同操作，防止把別次請求的身份交給 F。"""
    if identification.decision != "identified" or identification.identity is None or identification.errors:
        raise _Refusal("identity_missing", "B 尚未確認唯一請求身份")
    identity = identification.identity
    if not identity.enabled or identification.request_id not in (None, request.request_id):
        raise _Refusal("identity_mismatch", "B 的請求或部署身份不符")
    source, operation = profile.source, profile.operation
    if (identity.platform_id, identity.platform_version, identity.spec_sha256,
        identity.operation_id, identity.method, identity.path) != (
        source.platform_id, source.platform_version, source.spec_sha256,
        operation.operation_id, operation.method, operation.path):
        raise _Refusal("profile_mismatch", "B 與 D 的平台、版本、契約或操作不符")
    url = parse_request_url(request.raw_url)
    prefix = match_base_url(url, identity.base_url)
    if prefix is None or request.method != identity.method:
        raise _Refusal("request_mismatch", "A 的原始 URL 或 method 與 B 不符")
    selected = select_operation(profile.specification, request.method, url.path[len(prefix):] or "/")
    operation_id = selected.operation.get("operationId", f"{request.method} {selected.template}")
    if (selected.template, operation_id, selected.path_parameters, parse_query(url.query)) != (
        identity.path, identity.operation_id, identity.path_parameters, identity.query):
        raise _Refusal("request_mismatch", "A、B 與 D 不是同一個操作或參數")
    return identity, selected.operation


class ScenarioEngine:
    """依政策選領域的共用引擎；業務驗證與資料選擇交給已註冊處理器。"""

    def __init__(self, policy: DomainPolicy, *, domain: str | None = None,
                 registry: DomainRegistry | None = None):
        """選擇並核對領域，以該領域模型重驗快照，不讓政策變更或 registry 增補改變此選擇。"""
        if domain is not None and domain != policy.domain:
            raise ValueError("Selected domain does not match policy domain")
        handler = (default_registry() if registry is None else registry).get(policy.domain)
        checked = handler.policy_type.model_validate(policy.model_dump(mode="json"))
        if checked.domain != policy.domain or checked.domain != handler.domain_id:
            raise ValueError("Domain handler and policy model disagree")
        self._domain_id = checked.domain
        self._handler = handler
        self._policy_type = handler.policy_type
        self._policy_json = checked.model_dump_json()
        self._policy_sha256 = _digest(checked.model_dump(mode="json"))
        self._seal_key = secrets.token_bytes(32)

    @property
    def policy_sha256(self) -> str:
        """公開唯讀的真實政策摘要，避免外部賦值污染後續追溯記錄。"""
        return self._policy_sha256

    @property
    def domain_id(self) -> str:
        """唯讀選擇結果，避免執行中改用另一個領域解讀同一封套。"""
        return self._domain_id

    def _policy(self) -> DomainPolicy:
        """以原選定領域模型取得獨立政策，保留該領域的欄位與驗證規則。"""
        return self._policy_type.model_validate_json(self._policy_json)

    def _seal(self, payload: dict) -> str:
        """封存完整交接內容，避免 resolve 使用被篡改的 ID、scope 或期限。"""
        return hmac.new(self._seal_key, _encoded(payload), hashlib.sha256).hexdigest()

    def prepare(self, request: NormalizedRequest, identification: IdentificationResult,
                profile: OperationContext, assessment: AttackAssessment | None, *, run_id: str,
                now: datetime | None = None, allow_unreviewed: bool = False) -> ScenarioPreparation:
        """先選固定 family；資料尚未生成也能決定 E scope，不把 outcome 放入 scope。"""
        try:
            policy = self._policy()
            clock = _time(now)
            if not policy.enabled:
                return ScenarioPreparation(decision="not_applicable")
            identification = IdentificationResult.model_validate(identification.model_dump(mode="python"))
            profile = OperationContext.model_validate(profile.model_dump(mode="python"))
            identity, operation = _check_identity(request, identification, profile)
            if type(allow_unreviewed) is not bool:
                raise _Refusal("invalid_preview", "離線預覽選項必須為 boolean")
            if not profile.source.approved and not allow_unreviewed:
                raise _Refusal("source_not_approved", "D 來源尚未審查，只能顯式離線預覽")
            if assessment is None:
                raise _Refusal("assessment_missing", "缺少整合層提供的可信判定")
            assessment = AttackAssessment.model_validate(assessment.model_dump(mode="python"))
            fingerprint = fingerprint_request(request)
            if assessment.source_id not in policy.trusted_sources:
                raise _Refusal("assessment_source", "判定來源不在政策白名單")
            if (assessment.request_id, assessment.request_fingerprint) != (request.request_id, fingerprint):
                raise _Refusal("assessment_request", "判定與目前請求無法關聯")
            if any(getattr(assessment, key) != getattr(identity, key) for key in
                   ("environment_id", "deployment_id", "service_id", "site_id")):
                raise _Refusal("assessment_context", "判定的部署或站點身份不符")
            deadline = min(assessment.expires_at, assessment.observed_at + timedelta(seconds=policy.max_age_seconds))
            if not assessment.observed_at <= clock < deadline:
                raise _Refusal("assessment_expired", "判定尚未生效或已逾有效期限")
            if assessment.verdict == "benign":
                return ScenarioPreparation(decision="not_applicable")
            if assessment.verdict != "malicious":
                raise _Refusal("assessment_unknown", "判定尚未確認適用誘餌政策")
            matching = [rule for rule in policy.rules if rule.enabled and
                        all(getattr(rule, key) == getattr(identity, key) for key in IDENTITY_KEYS) and
                        identity.query in rule.query_contexts and
                        (not rule.attack_types or set(rule.attack_types).intersection(assessment.attack_types))]
            if not matching:
                return ScenarioPreparation(decision="not_applicable")
            highest = max(rule.priority for rule in matching)
            matching = [rule for rule in matching if rule.priority == highest]
            if len(matching) != 1:
                raise _Refusal("rule_not_unique", "多條同優先序規則命中，無法唯一選擇情境")
            rule = matching[0]
            # 處理器只取得獨立副本，不可藉修改參數改寫已核對的請求或政策身份。
            domain_context = self._handler.prepare(rule.model_copy(deep=True), identity.model_copy(deep=True),
                                                   profile.model_copy(deep=True), json.loads(_encoded(operation)))
            scope = DatasetScope(site_id=identity.site_id, platform_id=identity.platform_id,
                                 platform_version=identity.platform_version, spec_sha256=identity.spec_sha256,
                                 scenario_id=rule.scenario_id, run_id=run_id)
            payload = dict(domain=self.domain_id, policy_sha256=self.policy_sha256,
                           rule_id=rule.rule_id, scope=scope.model_dump(),
                           request_id=request.request_id, request_fingerprint=fingerprint,
                           assessment_id=assessment.assessment_id, assessment_source=assessment.source_id,
                           environment_id=identity.environment_id, deployment_id=identity.deployment_id,
                           service_id=identity.service_id, operation_id=identity.operation_id,
                           method=identity.method, path=identity.path, domain_context=domain_context,
                           valid_from=clock.isoformat(), valid_until=deadline.isoformat(),
                           offline_preview=allow_unreviewed or not profile.source.approved)
            # 用 JSON mode 統一 aware datetime 的表示，確保 prepare/resolve 封存完全相同內容。
            prepared = PreparedScenario.model_validate_json(json.dumps(
                dict(payload, preparation_id=_digest(payload), seal="")))
            prepared.seal = self._seal(prepared.model_dump(mode="json", exclude={"seal"}))
            return ScenarioPreparation(decision="prepared", prepared=prepared)
        except _Refusal as exc:
            return ScenarioPreparation(decision="unverifiable", errors=[ScenarioIssue(code=exc.code, reason=exc.reason)])
        except Exception:
            return ScenarioPreparation(decision="unverifiable", errors=[ScenarioIssue(
                code="preparation_failed", reason="無法可靠核對情境輸入，未產生計畫")])

    def resolve(self, prepared: PreparedScenario, dataset: object, *,
                now: datetime | None = None) -> ScenarioDecision:
        """驗證領域交接後由處理器檢查資料、選分支；核心不假設資料是電商商品。"""
        try:
            clock = _time(now)
            prepared = PreparedScenario.model_validate(prepared.model_dump(mode="python"))
            payload = prepared.model_dump(mode="json", exclude={"seal"})
            if (prepared.domain != self.domain_id or
                    not hmac.compare_digest(prepared.seal, self._seal(payload)) or
                    prepared.policy_sha256 != self.policy_sha256):
                raise _Refusal("prepared_mismatch", "交接封套不是此引擎的原始選擇結果")
            if not prepared.valid_from <= clock < prepared.valid_until:
                raise _Refusal("prepared_expired", "交接封套尚未生效或已過期")
            policy = self._policy()
            rule = next(rule for rule in policy.rules if rule.rule_id == prepared.rule_id)
            outcome = self._handler.resolve(policy.model_copy(deep=True), rule.model_copy(deep=True),
                                             prepared.model_copy(deep=True), dataset)
            outcome = DomainOutcome.model_validate(outcome.model_dump(mode="python"))
            plan = outcome.composition_plan
            if (plan.scope, plan.method, plan.path) != (prepared.scope, prepared.method, prepared.path):
                raise _Refusal("domain_plan_mismatch", "領域處理器的計畫與選定的 scope 或操作不符")
            template = next(template for template in policy.templates if template.template_id == outcome.template_id)
            trace = dict(domain=self.domain_id, policy_id=policy.policy_id, policy_version=policy.policy_version,
                         policy_sha256=self.policy_sha256, rule_id=rule.rule_id,
                         preparation_id=prepared.preparation_id, request_id=prepared.request_id,
                         request_fingerprint=prepared.request_fingerprint,
                         assessment_id=prepared.assessment_id, assessment_source=prepared.assessment_source,
                         environment_id=prepared.environment_id, deployment_id=prepared.deployment_id,
                         service_id=prepared.service_id, scope=prepared.scope.model_dump(mode="json"),
                         operation_id=prepared.operation_id, outcome_id=outcome.outcome_id,
                         status_code=plan.status_code, media_type=plan.media_type,
                         template_id=template.template_id, template_sha256=_digest(template.model_dump(mode="json")),
                         data_namespace=outcome.data_namespace, state_sha256=outcome.state_sha256,
                         reason_code=outcome.reason_code,
                         offline_preview=prepared.offline_preview)
            trace["decision_id"] = _digest(trace)
            return ScenarioDecision(decision="selected", outcome_id=outcome.outcome_id, composition_plan=plan, trace=trace)
        except _Refusal as exc:
            return ScenarioDecision(decision="unverifiable", errors=[ScenarioIssue(code=exc.code, reason=exc.reason)])
        except Exception:
            return ScenarioDecision(decision="unverifiable", errors=[ScenarioIssue(
                code="resolution_failed", reason="無法可靠驗證情境或領域資料，未產生計畫")])
