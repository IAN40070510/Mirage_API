"""命令列入口：在不啟動 FastAPI 或 LLM 的情況下建立 D 產物。"""

import argparse
from pathlib import Path

from . import ProfileError, build_profile


def main():
    """由明確指定的本地來源編譯 Profile，失敗時回傳非零結束碼。"""
    parser = argparse.ArgumentParser(description="Build a platform Profile from local OpenAPI")
    parser.add_argument("--source", required=True, type=Path, help="Path to source.yaml")
    parser.add_argument("--output", type=Path, default=Path("generated"))
    args = parser.parse_args()
    try:
        profile = build_profile(args.source, args.output)
    except ProfileError as exc:
        parser.exit(1, f"Profile build failed: {exc}\n")
    print(f"{args.output / 'profiles' / (profile.source.platform_id + '.yaml')}: "
          f"{len(profile.operations)} operations, source approved={profile.source.approved}")


if __name__ == "__main__":
    main()
