"""確保 Mirage 的獨立 HTTP 入口不會載入 MSDSS。"""

from pathlib import Path
import subprocess
import sys


def test_standalone_trusted_http_does_not_import_msdss():
    """封鎖 MSDSS 匯入時仍可載入 Mirage 可信 HTTP 入口。"""
    root = Path(__file__).resolve().parents[1]
    script = '''
from importlib.abc import MetaPathFinder
import sys


class DenyMSDSS(MetaPathFinder):
    """使 MSDSS 成為不可用的外部依賴。"""

    def find_spec(self, fullname, path=None, target=None):
        """拒絕獨立 Mirage 過程中的任何 MSDSS 匯入。"""
        if fullname.split(".")[0] == "msdss":
            raise AssertionError(fullname)
        return None


sys.meta_path.insert(0, DenyMSDSS())
sys.path.insert(0, sys.argv[1])
from deception.domains.ecommerce.trusted_http import create_app
assert callable(create_app)
'''
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(root / "src")],
        cwd=root, capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
