"""建立明確檔案清單、排除憑證並可脫敏文件的 Docker runtime 建置封存。"""

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile


ROOT_FILES = ("Dockerfile", ".dockerignore", "pyproject.toml", "LICENSE", "NOTICE", "README.md")
ROOT_DIRECTORIES = ("src", "mirage_validator", "configs", "domains", "inputs/security_taxonomies",
                    "migrations", "tools", "docs", "licenses")
PRIVATE_SUFFIXES = {".key", ".pem", ".p12", ".pfx", ".gguf", ".safetensors", ".onnx"}
EXCLUDED_PARTS = {".git", ".venv", "__pycache__", "generated", "outputs", ".pytest_cache", "node_modules"}


def build_context(root: Path, output: Path, redactions: list[tuple[str, str]]) -> dict:
    """封存 Docker COPY 的明確白名單，拒絕 symlink、敏感檔名與私鑰標記。

    redactions 僅套用到 Markdown 文件，原始碼與設定保持精確 bytes。
    回傳檔案清單、雜湊與脫敏標記，不保存被替換的私人字串。
    """
    root = root.resolve()
    paths = [root / name for name in ROOT_FILES]
    for name in ROOT_DIRECTORIES:
        directory = root / name
        if not directory.is_dir():
            raise ValueError(f"required build directory is missing: {name}")
        if directory.is_symlink():
            raise ValueError(f"indirect build directory rejected: {name}")
        for path in directory.rglob("*"):
            relative = path.relative_to(root)
            if any(part in EXCLUDED_PARTS for part in relative.parts):
                continue
            if path.is_symlink():
                raise ValueError(f"indirect build path rejected: {relative.as_posix()}")
            if path.is_file():
                paths.append(path)
    output = output.resolve()
    if not output.is_relative_to(root) or output == root:
        raise ValueError("runtime archive must be inside this workspace")
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest = []
    temporary = output.with_name(output.name + ".partial")
    if temporary.is_symlink():
        raise ValueError("indirect archive temporary path rejected")
    try:
        with tarfile.open(temporary, "w:gz") as archive:
            for path in sorted(set(paths)):
                relative = path.relative_to(root)
                if any(part in EXCLUDED_PARTS for part in relative.parts) or path.suffix in {".pyc", ".pyo"}:
                    continue
                if (path.is_symlink() or not path.resolve().is_relative_to(root)
                        or path.suffix.lower() in PRIVATE_SUFFIXES or path.name.startswith(".env")):
                    raise ValueError(f"sensitive or indirect build file rejected: {relative.as_posix()}")
                data = path.read_bytes()
                if len(data) > 64 * 1024 * 1024 or re.search(rb"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----", data):
                    raise ValueError(f"private key or oversized artifact rejected: {relative.as_posix()}")
                original = data
                if path.suffix == ".md":
                    for before, after in redactions:
                        if not before:
                            raise ValueError("empty redaction value")
                        data = data.replace(before.encode(), after.encode())
                info = tarfile.TarInfo(relative.as_posix())
                info.size, info.mode = len(data), 0o644
                archive.addfile(info, io.BytesIO(data))
                manifest.append({"path": relative.as_posix(), "sha256": hashlib.sha256(data).hexdigest(),
                                 "bytes": len(data), "documentation_redacted": data != original})
        temporary.replace(output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return {"archive_sha256": hashlib.sha256(output.read_bytes()).hexdigest(), "files": manifest}


def main() -> int:
    """從 CLI 建立封存與 manifest；錯誤時停止，不自動上傳或部署。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--redact-doc", action="append", default=[])
    arguments = parser.parse_args()
    redactions = []
    for item in arguments.redact_doc:
        if "=" not in item:
            parser.error("--redact-doc must use PRIVATE=PLACEHOLDER")
        redactions.append(tuple(item.split("=", 1)))
    root = Path(__file__).resolve().parents[1]
    manifest = build_context(root, arguments.output, redactions)
    manifest_path = arguments.output.with_suffix(arguments.output.suffix + ".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Packaged {len(manifest['files'])} allowlisted files; manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
