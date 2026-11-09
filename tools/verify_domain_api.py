"""依明確領域選擇自己的 HTTP 驗證器，不在共用工具內假定商品端點。"""

import argparse
import json
from pathlib import Path

from deception.domains.assets import load_application_selection
from deception.domains.registry import default_implementations


def main() -> int:
    """列出已註冊領域，或執行所選領域的測試並保存成功／失敗報告。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list-domains", action="store_true")
    parser.add_argument("--domain")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--host-header")
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    registry = default_implementations()
    if args.list_domains:
        for domain in registry.domain_ids():
            print(domain)
        return 0
    domain = args.domain if args.domain is not None else load_application_selection()[0].domain
    implementation = registry.get(domain)
    output = args.output or Path("generated/domains") / domain / "verification" / "http-api.json"
    try:
        report = implementation.http_verifier(args.base_url, host_header=args.host_header, timeout=args.timeout)
    except Exception as exc:
        report = {"schema_version": 1, "domain": domain, "success": False,
                  "error_type": type(exc).__name__, "error": "Domain HTTP verification could not complete"}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"domain": domain, "success": report["success"], "report": str(output)}, ensure_ascii=False))
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
