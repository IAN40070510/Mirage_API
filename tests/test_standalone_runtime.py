"""驗證 Mirage 的安裝隔離與外部消費端去耦不變條件。"""

import ast
import subprocess
import sys
from pathlib import Path


def test_installed_runtime_imports_in_isolated_python(tmp_path):
    """從空工作目錄以 Python isolated 模式匯入原生公開入口。"""
    script = """
from deception.api.demo import create_app
from deception.api.fingerprint import fingerprint_httpx_request
from deception.domains.ecommerce.trusted_http import create_app as trusted_app
from deception.security.trusted_deployment import TrustedDeploymentSettings
assert all(callable(entry) for entry in (create_app, trusted_app, fingerprint_httpx_request))
assert TrustedDeploymentSettings is not None
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script], cwd=tmp_path,
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_container_copy_sources_exist():
    """確認所有本地 Docker COPY 檔案在刪除外部組裝入口後仍存在。"""
    root = Path(__file__).resolve().parents[1]
    for line in (root / "Dockerfile").read_text(encoding="utf-8").splitlines():
        if not line.startswith("COPY ") or "--from=" in line:
            continue
        sources = [part for part in line.split()[1:-1] if not part.startswith("--")]
        for source in sources:
            assert (root / source).exists(), source


def test_no_consumer_owned_python_imports():
    """防止程式與一般測試再次依賴被移交的整合套件。"""
    root = Path(__file__).resolve().parents[1]
    assert not (root / "integrations/msdss").exists()
    for directory in ("src", "mirage_validator", "tools", "tests"):
        for path in (root / directory).rglob("*.py"):
            parsed = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(parsed):
                if isinstance(node, ast.Import):
                    assert all(not alias.name.startswith("integrations.msdss") for alias in node.names), path
                if isinstance(node, ast.ImportFrom) and node.module:
                    assert not node.module.startswith("integrations.msdss"), path
