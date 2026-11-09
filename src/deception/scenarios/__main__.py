"""依明確領域派送離線情境展示，不接收訪客提供的攻擊判定。"""

import argparse
from pathlib import Path

from deception.domains.registry import default_implementations


def main():
    """列出註冊領域，或將明確選擇的展示及輸出路徑交給該領域；缺少入口時拒絕。"""
    parser = argparse.ArgumentParser(description="Run a synthetic-only offline scenario demonstration")
    parser.add_argument("--demo", action="store_true", help="Use temporary synthetic contracts only")
    parser.add_argument("--list-domains", action="store_true", help="List registered scenario domains")
    parser.add_argument("--domain", help="Select a registered scenario domain, for example ecommerce")
    parser.add_argument("--output", type=Path, help="Override generated/domains/<domain> output directory")
    args = parser.parse_args()
    implementations = default_implementations()
    if args.list_domains:
        if args.demo or args.domain is not None:
            parser.error("--list-domains cannot be combined with --demo or --domain")
        print("\n".join(implementations.domain_ids()))
        return
    if not args.demo or args.domain is None:
        parser.error("Use --list-domains or --demo --domain <domain>; no external verdicts are accepted")
    try:
        implementation = implementations.get(args.domain)
        if implementation.scenario_demo is None:
            raise ValueError("The selected domain has no registered offline scenario demonstration")
        output_root = args.output if args.output is not None else Path("generated/domains") / args.domain
        output = implementation.scenario_demo(output_root, domain=args.domain)
        print(f"Domain: {args.domain}. Synthetic-only offline scenario demonstration completed.")
        print(f"Report: {output}; no repository platform approvals were changed.")
    except Exception as exc:
        parser.exit(1, f"Synthetic scenario demo failed: {exc}\n")


if __name__ == "__main__":
    main()
