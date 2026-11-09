"""列出領域實作與其版本化安全情境，設計項目與可執行模擬明確分開。"""

import argparse
import json
import os
from pathlib import Path

from deception.security import load_catalog

from .assets import load_application_selection, load_domain_assets
from .registry import default_implementations


def main() -> int:
    """只查詢本機已註冊領域與目錄資料，不執行漏洞、下載資產或核准正式部署。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list-domains", action="store_true")
    parser.add_argument("--domain")
    parser.add_argument("--domains-dir", type=Path)
    args = parser.parse_args()
    implementations = default_implementations()
    if args.list_domains:
        print(json.dumps({"domains": list(implementations.domain_ids())}, ensure_ascii=False))
        return 0
    if args.domain is None:
        _, assets = load_application_selection()
    else:
        implementations.get(args.domain)
        assets = load_domain_assets(args.domain, args.domains_dir or Path(os.environ.get("MIRAGE_DOMAINS_DIR", "domains")))
    catalog = load_catalog(assets.resolve(assets.manifest.weakness_catalog, file=True), domain=assets.manifest.domain_id,
                           taxonomy_root=Path(os.environ.get("MIRAGE_SECURITY_TAXONOMIES_DIR", "inputs/security_taxonomies")))
    print(json.dumps({"domain": catalog.domain, "catalog_id": catalog.catalog_id, "scenarios": [
        {"scenario_id": item.scenario_id, "title": item.title, "status": item.status,
         "categories": [reference.model_dump(mode="json") for reference in item.categories]} for item in catalog.scenarios
    ]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
