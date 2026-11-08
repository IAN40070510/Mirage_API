"""離線執行 H；產物是候選封套，不是對外 HTTP 回應。"""

import argparse
import hashlib
import json
from pathlib import Path

from deception.profile_builder.builder import _atomic_write, local_path, read_yaml
from deception.synthetic import load_dataset, read_config

from . import CompositionPlan, ResponseComposer


def main():
    """讀取明確指令與可選的 E 產物，組合成功後原子保存完整候選。"""
    parser = argparse.ArgumentParser(description="Compose a contract-checked JSON response candidate")
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--profiles", type=Path, default=Path("generated"))
    parser.add_argument("--output", type=Path, default=Path("generated"))
    parser.add_argument("--dataset", type=Path)
    parser.add_argument("--generation-config", type=Path)
    parser.add_argument("--allow-unreviewed", action="store_true", help="Offline preview only")
    args = parser.parse_args()
    if bool(args.dataset) != bool(args.generation_config):
        parser.error("--dataset and --generation-config must be supplied together")
    try:
        plan = CompositionPlan.model_validate(read_yaml(args.plan.read_bytes()))
        dataset = load_dataset(args.dataset, read_config(args.generation_config)) if args.dataset else None
        candidate = ResponseComposer(args.profiles).compose(plan, dataset=dataset,
                                                         allow_unreviewed=args.allow_unreviewed)
        data = (json.dumps(candidate.to_dict(), ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        digest = hashlib.sha256(data).hexdigest()
        output = local_path(args.output, f"responses/{candidate.identity.platform_id}/{digest}.json")
        _atomic_write(output, data)
        print(f"{output}: contract preflight passed; pending I deployment gate; "
              f"source approved={candidate.identity.source_approved}")
    except Exception as exc:
        parser.exit(1, f"Composition failed: {exc}\n")


if __name__ == "__main__":
    main()
