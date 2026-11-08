"""H → I 交接：驗證同一份候選，並確認 I 評估的是原候選的契約身份。"""

from mirage_validator.gate import GateResult, OfficialResponseGate
from mirage_validator.models import ValidationIssue

from .models import CandidateResponse


def verify_candidate(candidate: CandidateResponse, gate: OfficialResponseGate,
                     request_url: str) -> GateResult:
    """原樣交給 I；相同 schema 的其他操作也不能代替原候選取得 pass。"""
    result = gate.validate(candidate.to_gate_request(request_url))
    expected = (candidate.identity.platform_id, candidate.identity.platform_version,
                candidate.identity.spec_sha256, candidate.identity.operation_id)
    actual = (result.platform_id, result.platform_version, result.spec_sha256, result.operation_id)
    if result.decision in ("pass", "reject") and actual != expected:
        # 保留 I 實際匹配的身份供追溯，但禁止把另一份契約的結果當作本候選的判定。
        issue = ValidationIssue(location="contract", path="", code="candidate_identity_mismatch",
                                reason="I 評估的平台、版本、規格雜湊或 operation 與 H 候選不同")
        return result.model_copy(update={"valid": False, "decision": "unverifiable",
                                         "errors": [*result.errors, issue]})
    return result
