"""驗證已安裝 Mirage 的隔離匯入與獨立執行邊界。"""

import subprocess
import sys
from pathlib import Path


def test_installed_runtime_imports_from_empty_working_directory(tmp_path):
    """在隔離 Python 模式與空目錄載入已安裝的原生服務入口。"""
    script = """
from deception.api.demo import create_app
from deception.api.fingerprint import fingerprint_httpx_request
from deception.domains.ecommerce.trusted_http import create_app as trusted_app
from deception.security.trusted_deployment import TrustedDeploymentSettings
from deception.world.postgres_admission import PostgresAdmissionControl
assert all(callable(item) for item in (create_app, trusted_app, fingerprint_httpx_request))
assert TrustedDeploymentSettings is not None
assert PostgresAdmissionControl is not None
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script], cwd=tmp_path,
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_container_copy_sources_exist_in_standalone_checkout():
    """檢查容器正常建置入口的本地 COPY 來源，防止刪除目錄後映像失效。"""
    root = Path(__file__).resolve().parents[1]
    for line in (root / "Dockerfile").read_text(encoding="utf-8").splitlines():
        if not line.startswith("COPY ") or "--from=" in line:
            continue
        sources = [part for part in line.split()[1:-1] if not part.startswith("--")]
        for source in sources:
            assert (root / source).exists(), source

def test_checkout_contains_no_consumer_assembly_modules():
    """阻止已移交給呼叫端的整合組裝目錄重新進入獨立服務。"""
    root = Path(__file__).resolve().parents[1]
    assembly = root / "integrations"
    files = [
        path.relative_to(root).as_posix()
        for path in assembly.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    ]
    assert files == []
