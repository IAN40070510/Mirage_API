"""F 的明確離線展示入口，不接收訪客提供的攻擊判定。"""

import argparse
from pathlib import Path

from .registry import default_registry


def main():
    """可列領域；只有明確指定 --demo 與 --domain 才建立合成契約展示。"""
    parser = argparse.ArgumentParser(description="Run a synthetic-only offline F scenario demonstration")
    parser.add_argument("--demo", action="store_true", help="Use temporary synthetic contracts only")
    parser.add_argument("--list-domains", action="store_true", help="List registered scenario domains")
    parser.add_argument("--domain", help="Select a registered scenario domain, for example ecommerce")
    parser.add_argument("--output", type=Path, default=Path("generated"))
    args = parser.parse_args()
    if args.list_domains:
        if args.demo or args.domain is not None:
            parser.error("--list-domains cannot be combined with --demo or --domain")
        print("\n".join(default_registry().domain_ids()))
        return
    if not args.demo or args.domain is None:
        parser.error("Use --list-domains or --demo --domain <domain>; no external verdicts are accepted")
    try:
        from .demo import run_demo

        output = run_demo(args.output, domain=args.domain)
        print(f"Domain: {args.domain}. Synthetic-only B/D/E/F/H/I verified: found/200 -> missing/404 -> found/200; "
              "E unchanged; repeated product body identical.")
        print(f"Report: {output}; no repository platform approvals were changed.")
    except Exception as exc:
        parser.exit(1, f"Synthetic scenario demo failed: {exc}\n")


if __name__ == "__main__":
    main()
