"""F 的明確離線展示入口，不接收訪客提供的攻擊判定。"""

import argparse
from pathlib import Path


def main():
    """只有明確指定 --demo 才建立合成契約並執行展示。"""
    parser = argparse.ArgumentParser(description="Run a synthetic-only offline F scenario demonstration")
    parser.add_argument("--demo", action="store_true", help="Use temporary synthetic contracts only")
    parser.add_argument("--output", type=Path, default=Path("generated"))
    args = parser.parse_args()
    if not args.demo:
        parser.error("--demo is required; this command does not accept external verdicts")
    try:
        from .demo import run_demo

        output = run_demo(args.output)
        print("Synthetic-only B/D/E/F/H/I verified: found/200 -> missing/404 -> found/200; "
              "E unchanged; repeated product body identical.")
        print(f"Report: {output}; no repository platform approvals were changed.")
    except Exception as exc:
        parser.exit(1, f"Synthetic scenario demo failed: {exc}\n")


if __name__ == "__main__":
    main()
