"""命令列生成與有效性驗證，不需啟動 FastAPI 或 LLM。"""

import argparse
from pathlib import Path

from . import SyntheticError, generate_dataset, load_dataset, read_config, save_dataset, verify_dataset


def main():
    """generate 保存後再載入檢查；verify 可獨立核對既有產物。"""
    parser = argparse.ArgumentParser(description="Generate and verify isolated synthetic product data")
    subparsers = parser.add_subparsers(dest="command", required=True)
    generate = subparsers.add_parser("generate")
    generate.add_argument("--config", type=Path, required=True)
    generate.add_argument("--output", type=Path, default=Path("generated"))
    verify = subparsers.add_parser("verify")
    verify.add_argument("--config", type=Path, required=True)
    verify.add_argument("--dataset", type=Path, required=True)
    args = parser.parse_args()
    try:
        config = read_config(args.config)
        if args.command == "generate":
            dataset = generate_dataset(config)
            path = save_dataset(dataset, args.output)
        else:
            path = args.dataset
        checked = load_dataset(path, config)
        report = verify_dataset(checked, config)
        print(f"{path}: valid={report.valid}, products={report.product_count}, variants={report.variant_count}")
    except SyntheticError as exc:
        parser.exit(1, f"Synthetic data failed: {exc}\n")


if __name__ == "__main__":
    main()
