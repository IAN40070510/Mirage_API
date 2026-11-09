"""本地識別診斷入口；不發出 HTTP 請求或抓取遠端規格。"""

import argparse
import sys
from pathlib import Path

from . import PlatformIdentifier, RuntimeContext
from deception.domains.assets import resolve_identification_paths


def main():
    """輸出結構化識別結果；無法確認時以非零結束碼停止後續處理。"""
    # Windows 的預設編碼可能不是 UTF-8；固定輸出，避免中文錯誤原因成為亂碼。
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Identify one explicitly bound HTTP API operation")
    parser.add_argument("--platforms", type=Path, help="Override the selected domain manifest's platform directory")
    parser.add_argument("--bindings", type=Path, help="Override the selected domain manifest's deployment bindings")
    parser.add_argument("--url", required=True)
    parser.add_argument("--method", default="GET")
    parser.add_argument("--environment-id")
    parser.add_argument("--deployment-id")
    parser.add_argument("--service-id")
    args = parser.parse_args()
    supplied = (args.environment_id, args.deployment_id, args.service_id)
    if any(supplied) and not all(supplied):
        parser.error("All three runtime context IDs must be supplied together")
    try:
        context = RuntimeContext(environment_id=args.environment_id, deployment_id=args.deployment_id,
                                 service_id=args.service_id) if all(supplied) else None
        platforms, bindings = resolve_identification_paths(args.platforms, args.bindings)
        identifier = PlatformIdentifier.from_paths(platforms, bindings)
        result = identifier.identify(args.url, args.method, context=context)
    except Exception as exc:
        parser.exit(1, f"Identifier configuration failed: {exc}\n")
    print(result.model_dump_json(indent=2))
    if result.decision != "identified":
        parser.exit(1)


if __name__ == "__main__":
    main()
