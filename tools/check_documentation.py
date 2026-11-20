"""檢查工具文件、具名函式功能說明與本地 Markdown 連結，不匯入或執行工具。"""

import ast
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
FUNCTION_ROOTS = ("src/deception", "mirage_validator", "tests", "tools", "integrations")
GUIDES = {
    "httpx_fingerprint": ("src/deception/api/fingerprint.py", "docs/trusted-session.md"),
    "request_audit": ("src/deception/world/request_audit.py", "docs/request-audit.md"),
    "commit_result": ("src/deception/world/commit.py", "docs/commit-results.md"),
    "commit_result_vectors": ("tests/fixtures/golden_vectors/verify_commit_results.mjs", "docs/commit-results.md"),
    "trusted_refusal_vectors": ("tests/fixtures/golden_vectors/sign_trusted_errors.mjs", "docs/trusted-session.md"),
    "event_world_store": ("src/deception/world/event_store.py", "docs/commit-results.md"),
    "security_error_renderer": ("src/deception/core/security_error.py", "docs/security-errors.md"),
    "trusted_key_revocations": ("src/deception/security/key_revocation.py", "docs/key-revocation.md"),
    "ingress_refusal_audit": ("src/deception/security/ingress_audit.py", "docs/ingress-audit.md"),
    "profile_revocation": ("src/deception/world/projection_registry.py", "docs/profile-revocation.md"),
    "medusa_cart_http": ("src/deception/domains/ecommerce/medusa_cart_http.py", "docs/medusa-carts.md"),
    "medusa_cart_projection": ("src/deception/domains/ecommerce/medusa_cart_projection.py", "docs/medusa-carts.md"),
    "native_resource_time": ("src/deception/domains/ecommerce/native_time.py", "docs/medusa-carts.md"),
    "gateway_compatibility": ("integrations/msdss/requirements.compatibility-test.txt", "docs/gateway-bootstrap.md"),
    "gateway_bootstrap": ("integrations/msdss/gateway_bootstrap.py", "docs/gateway-bootstrap.md"),
    "runtime_archive": ("tools/package_runtime.py", "docs/runtime-operations.md"),
    "schema_migration": ("tools/apply_migrations.py", "docs/runtime-operations.md"),
    "migration_engine": ("src/deception/world/migrations.py", "docs/runtime-operations.md"),
    "admitted_transmission": ("src/deception/world/transmission.py", "docs/renderer.md"),
    "session_worlds": ("src/deception/world/session.py", "docs/world-runtime.md"),
    "medusa_identity": ("src/deception/security/medusa_identity.py", "docs/trusted-session.md"),
    "anonymous_identity": ("src/deception/security/anonymous_identity.py", "docs/trusted-session.md"),
    "trusted_world_http": ("src/deception/domains/ecommerce/trusted_http.py", "docs/trusted-session.md"),
    "inventory_http": ("src/deception/domains/ecommerce/inventory_http.py", "docs/inventory.md"),
    "guest_carts": ("src/deception/domains/ecommerce/carts.py", "docs/carts.md"),
    "guest_cart_http": ("src/deception/domains/ecommerce/cart_http.py", "docs/carts.md"),
    "resource_identity": ("src/deception/security/resource_identity.py", "docs/carts.md"),
    "inventory_events": ("src/deception/domains/ecommerce/inventory.py", "docs/inventory.md"),
    "trusted_session": ("src/deception/security/trusted_deployment.py", "docs/trusted-session.md"),
    "trusted_gateway": ("integrations/msdss", "docs/trusted-session.md"),
    "ingress": ("src/deception/api", "docs/ingress.md"),
    "identification": ("src/deception/discovery", "docs/identifier.md"),
    "orchestration": ("src/deception/core/orchestrator.py", "docs/orchestration.md"),
    "profiles": ("src/deception/profile_builder", "docs/profiles.md"),
    "synthetic_data": ("src/deception/synthetic", "docs/synthetic.md"),
    "ecommerce_data": ("src/deception/domains/ecommerce/synthetic", "domains/ecommerce/docs/synthetic.md"),
    "scenarios": ("src/deception/scenarios", "docs/scenarios.md"),
    "attack_assessment": ("src/deception/scenarios/models.py", "docs/attack-assessment.md"),
    "generation": ("src/deception/generation", "docs/generation.md"),
    "composition": ("src/deception/core/composer.py", "docs/composer.md"),
    "contract_validation": ("mirage_validator/gate.py", "docs/gate.md"),
    "generation_context": ("src/deception/generation/models.py", "docs/context.md"),
    "response_rendering": ("src/deception/core/renderer.py", "docs/renderer.md"),
    "recovery": ("src/deception/core/recovery.py", "docs/recovery.md"),
    "local_model": ("src/deception/llm", "docs/llm.md"),
    "poc_validation": ("mirage_validator/validator.py", "docs/poc.md"),
    "documentation": ("tools/check_documentation.py", "docs/documentation.md"),
    "demonstration_service": ("src/deception/api/demo.py", "docs/docker.md"),
    "http_verification": ("tools/verify_ecommerce_api.py", "docs/verification.md"),
    "container_packaging": ("Dockerfile", "docs/docker.md"),
    "common_data": ("src/deception/common", "docs/common-data.md"),
    "world_runtime": ("src/deception/world", "docs/world-runtime.md"),
    "domains": ("src/deception/domains", "docs/domains.md"),
    "security_catalog": ("src/deception/security", "docs/owasp-design.md"),
    "domain_verification": ("tools/verify_domain_api.py", "docs/verification.md"),
}


def check_functions(root: Path) -> tuple[int, list[str]]:
    """解析所有自有 Python 檔案，列出缺功能 docstring 或語法錯誤，不執行其內容。"""
    total, errors = 0, []
    for directory in FUNCTION_ROOTS:
        for path in sorted((root / directory).rglob("*.py")):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
            except (OSError, UnicodeError, SyntaxError) as exc:
                errors.append(f"{path.relative_to(root)}: cannot parse Python: {exc}")
                continue
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    total += 1
                    if not (ast.get_docstring(node) or "").strip():
                        errors.append(f"{path.relative_to(root)}:{node.lineno}: missing function documentation: {node.name}")
    return total, errors


def check_guides(root: Path) -> list[str]:
    """確認已實作工具都有非空文件，新頂層工具目錄也必須登錄。"""
    errors = []
    for name, (source, guide) in GUIDES.items():
        if not (root / source).exists():
            errors.append(f"{name}: missing tool source: {source}")
        if not (root / guide).is_file() or not (root / guide).read_text(encoding="utf-8-sig").strip():
            errors.append(f"{name}: missing or empty tool guide: {guide}")
    for directory in sorted((root / "src/deception").iterdir()):
        if directory.is_dir() and directory.name != "__pycache__" and any(directory.rglob("*.py")):
            source = directory.relative_to(root).as_posix()
            if not any(path == source or path.startswith(source + "/") for path, _ in GUIDES.values()):
                errors.append(f"{source}: tool directory has no registered guide")
    return errors


def check_links(root: Path) -> list[str]:
    """檢查共用 docs 與 domains 文件的本地連結；跳過範例程式、外部網址及頁內 anchor。"""
    errors = []
    paths = sorted((root / "docs").rglob("*.md")) + sorted((root / "domains").rglob("*.md"))
    for path in paths:
        value = path.read_text(encoding="utf-8-sig")
        value = re.sub(r"(?ms)^\s*```.*?^\s*```[^\n]*", "", value)
        for match in re.finditer(r"\[[^\]\n]*\]\(([^)\n]+)\)", value):
            target = match.group(1).strip()
            if target.startswith("<") and target.endswith(">"):
                target = target[1:-1]
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            destination = path.parent / unquote(parsed.path)
            if not destination.exists():
                errors.append(f"{path.relative_to(root)}: broken local link: {target}")
    return errors


WORLD_ADR_REQUIRED_IDS = (
    "WORLD-IDENTITY-01", "WORLD-OPERATION-01", "WORLD-OPERATION-02",
    "WORLD-OPERATION-03", "WORLD-POLICY-01", "WORLD-POLICY-02",
    "WORLD-PAYLOAD-01", "WORLD-PAYLOAD-02", "WORLD-PAYLOAD-03",
    "WORLD-SNAPSHOT-01", "WORLD-SNAPSHOT-ACL-01",
    "WORLD-LIFECYCLE-01", "WORLD-LIFECYCLE-02", "WORLD-LIFECYCLE-03",
    "WORLD-PURGE-01", "WORLD-TIME-01", "WORLD-LOCK-01",
    "WORLD-COMPAT-01", "WORLD-RECOVERY-03", "WORLD-RECOVERY-04",
    "WORLD-RESTORE-OP-01", "WORLD-AUDIT-02",
)


def check_world_adr_contract(root: Path) -> list[str]:
    '''Verify the Proposed ADR v0.2 tests and cross-document safety boundaries.

    The check is deliberately skipped on Mirage main while that branch has
    no ADR. It does not execute the proposed World DB safety tests.
    '''
    adr_path = root / "docs/adr/MIR-SEC-WORLD-001-world-db-trust-boundary.md"
    if not adr_path.exists():
        return []
    files = {
        "ADR": adr_path,
        "decisions": root / "docs/security/world-db/decisions-log.md",
        "verification": root / "docs/security/world-db/verification-plan.md",
        "evidence": root / "docs/security/world-db/evidence-authority-matrix.md",
        "locks": root / "docs/security/world-db/transaction-lock-matrix.md",
        "threat": root / "docs/security/world-db/threat-capability-matrix.md",
        "index": root / "docs/security/world-db/README.md",
        "docs-index": root / "docs/README.md",
        "root-index": root / "README.md",
    }
    errors: list[str] = []
    content: dict[str, str] = {}
    for name, path in files.items():
        if not path.is_file():
            errors.append(f"world-adr: missing {name}: {path.relative_to(root)}")
            continue
        content[name] = path.read_text(encoding="utf-8-sig")

    if len(content) != len(files):
        return errors
    adr = content["ADR"]
    plan = content["verification"]
    decision = content["decisions"]
    for test_id in WORLD_ADR_REQUIRED_IDS:
        if f"`{test_id}`" not in adr:
            errors.append(f"world-adr: ADR missing test {test_id}")
        if f"`{test_id}`" not in decision:
            errors.append(f"world-adr: decisions log missing test {test_id}")
        rows = [
            line for line in plan.splitlines()
            if line.startswith(f"| `{test_id}` |")
        ]
        if len(rows) != 1:
            errors.append(f"world-adr: verification must have one {test_id}, got {len(rows)}")
        elif not rows[0].endswith("| NOT_RUN |"):
            errors.append(f"world-adr: {test_id} must remain NOT_RUN")
    required = {
        "ADR": (
            "Architecture", "Proposed", "SEND_AUTHORIZED",
            "Protocol Freeze v1", "NOT_RUN", "MIR-SEC-WORLD-001",
            "MSDSS P2", "OperationSnapshotBinding", "decision_time",
            "SNAPSHOT_BINDING_CONFLICT", "WORLD_COMMITTED_ADMISSION_UNAVAILABLE",
        ),
        "verification": (
            "NOT_RUN", "WORLD_COMMITTED_ADMISSION_UNAVAILABLE",
            "SEND_STARTED", "MIR-SEC-WORLD-001", "MSDSS P2",
        ),
        "decisions": (
            "NOT_RUN", "WORLD_COMMITTED_ADMISSION_UNAVAILABLE",
            "SEND_AUTHORIZED",
        ),
        "index": ("Proposed", "NOT_RUN", "NO-GO"),
        "docs-index": ("Proposed", "OPEN", "NO-GO"),
        "root-index": ("Proposed", "OPEN", "NO-GO"),
    }
    for name, terms in required.items():
        for term in terms:
            if term not in content[name]:
                errors.append(f"world-adr: {name} missing invariant/status {term}")
    forbidden = (
        "AuthorizeTx／StartSendTx 後續只沿同一 Binding",
        "Authorize 與 StartSend 都要重新讀取最新控制狀態",
        "Grant 後、StartSend 前撤銷，禁止後續 SEND_STARTED",
        "StartSend 必須比對 Receipt 綁定",
        "| SEND_AUTHORIZED | 最後一刻重查最新安全狀態",
    )
    for name in ("ADR", "evidence", "locks", "verification"):
        for expression in forbidden:
            if expression in content[name]:
                errors.append(f"world-adr: stale pre-Freeze-v1 wording: {name}")
    return errors


def main() -> int:
    """彙整函式、文件及連結結果；成功回 0，缺漏回 1，供人工或持續整合使用。"""
    total, errors = check_functions(ROOT)
    errors.extend(check_guides(ROOT))
    errors.extend(check_links(ROOT))
    errors.extend(check_world_adr_contract(ROOT))
    if errors:
        for error in errors:
            print(error)
        print(f"Documentation check failed: {len(errors)} issue(s), {total} functions checked.")
        return 1
    print(f"Documentation check passed: {total} functions, {len(GUIDES)} tool guides, local documentation links.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
