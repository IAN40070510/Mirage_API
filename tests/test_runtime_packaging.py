"""部署封存的敏感檔案拒絕、文件脫敏與版本化 migration 驗收。"""

import json
from pathlib import Path
import shutil
import tarfile

import pytest

from tools.package_runtime import ROOT_DIRECTORIES, ROOT_FILES, build_context
from test_postgres_conformance import isolated_test_dsn


def test_package_contains_only_explicit_safe_files(tmp_path):
    """封存只含白名單，文件脫敏不修改原始碼，也不包含工作區外憑證。"""
    for directory in ROOT_DIRECTORIES:
        (tmp_path / directory).mkdir(parents=True, exist_ok=True)
    for filename in ROOT_FILES:
        (tmp_path / filename).write_text("safe", encoding="utf-8")
    (tmp_path / "docs/example.md").write_text("server PRIVATE_HOST", encoding="utf-8")
    (tmp_path / "src/example.py").write_text("# PRIVATE_HOST is a placeholder", encoding="utf-8")
    (tmp_path / ".env").write_text("SECRET=do-not-package", encoding="utf-8")
    archive = tmp_path / "generated/runtime.tar.gz"
    manifest = build_context(tmp_path, archive, [("PRIVATE_HOST", "SSH_HOST")])
    with tarfile.open(archive) as packaged:
        assert ".env" not in packaged.getnames()
        assert packaged.extractfile("docs/example.md").read() == b"server SSH_HOST"
        assert packaged.extractfile("src/example.py").read() == b"# PRIVATE_HOST is a placeholder"
    assert any(entry["documentation_redacted"] for entry in manifest["files"])
    (tmp_path / "configs/private.key").write_text("not-uploaded", encoding="utf-8")
    before = archive.read_bytes()
    with pytest.raises(ValueError, match="rejected"):
        build_context(tmp_path, archive, [])
    assert archive.read_bytes() == before
    assert not archive.with_name(archive.name + ".partial").exists()


def test_migration_checksum_is_idempotent_and_rejects_drift(isolated_test_dsn, tmp_path):
    """完整 migration 重複執行無副作用，既有版本改動時停止且不改資料庫版本紀錄。"""
    import psycopg
    from deception.world.migrations import apply_migrations

    original = Path(__file__).resolve().parents[1] / "migrations"
    directory = tmp_path / "migrations"
    shutil.copytree(original, directory)
    first = apply_migrations(isolated_test_dsn, directory)
    assert len(first) == len(list(directory.glob("*.sql")))
    assert apply_migrations(isolated_test_dsn, directory) == ()
    changed = sorted(directory.glob("*.sql"))[0]
    changed.write_text(changed.read_text(encoding="utf-8") + "\n-- changed test checksum\n", encoding="utf-8")
    with pytest.raises(ValueError, match="checksum changed"):
        apply_migrations(isolated_test_dsn, directory)
    with psycopg.connect(isolated_test_dsn) as observer:
        assert observer.execute("SELECT count(*) FROM mirage_schema_migrations").fetchone() == (len(first),)
