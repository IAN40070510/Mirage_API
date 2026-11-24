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


def main() -> int:
    """彙整函式、文件及連結結果；成功回 0，缺漏回 1，供人工或持續整合使用。"""
    total, errors = check_functions(ROOT)
    errors.extend(check_guides(ROOT))
    errors.extend(check_links(ROOT))
    if errors:
        for error in errors:
            print(error)
        print(f"Documentation check failed: {len(errors)} issue(s), {total} functions checked.")
        return 1
    print(f"Documentation check passed: {total} functions, {len(GUIDES)} tool guides, local documentation links.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
