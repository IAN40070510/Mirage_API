"""明確選擇領域及本機模型的生成展示入口，不接受外部 verdict 或假模型。"""

import argparse
import asyncio
from pathlib import Path

from deception.llm import LLMConfig
from deception.llm.selection import list_local_models, select_local_model
from deception.profile_builder.builder import read_yaml
from deception.domains.registry import default_implementations


def main():
    """安全讀取固定模型設定，展示成功才回傳 0；服務或模型不符時明確失敗。"""
    parser = argparse.ArgumentParser(description="Run the selected domain's real local Ollama synthetic demonstration")
    parser.add_argument("--demo", action="store_true", help="Run the isolated synthetic local-model demo")
    registry = default_implementations()
    parser.add_argument("--domain", choices=registry.domain_ids())
    parser.add_argument("--list-models", action="store_true", help="List already installed local Ollama models")
    parser.add_argument("--model", help="Select an exact installed local model name without downloading")
    parser.add_argument("--model-digest", help="Require an additional complete SHA-256 digest match")
    parser.add_argument("--llm-config", type=Path, default=Path("configs/llm.yaml"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.list_models:
        if args.demo or args.domain is not None or args.model is not None or args.model_digest is not None:
            parser.error("--list-models cannot be combined with --demo, --domain, --model or --model-digest")
    elif not args.demo or args.domain is None:
        parser.error("Use --list-models or --demo --domain <domain>; no external requests or verdicts are accepted")
    try:
        config = LLMConfig.model_validate(read_yaml(args.llm_config.read_bytes()))
        if args.list_models:
            models = asyncio.run(list_local_models(config))
            print("NAME\tSHA256", flush=True)
            for model in models:
                print(f"{model.name}\t{model.digest}", flush=True)
            return

        async def execute_demo():
            """在同一個 event loop 固定所選模型，再把完整設定交給真本機展示。"""
            selected = await select_local_model(config, args.model, expected_digest=args.model_digest)
            print(f"Selected local model: {selected.model_name}; sha256={selected.model_digest}; "
                  f"planner_mode={selected.planner_mode}.", flush=True)
            output_root = args.output or Path("generated/domains") / args.domain
            return await registry.get(args.domain).generation_demo(output_root, domain=args.domain, llm_config=selected)

        output = asyncio.run(execute_demo())
        print(f"Local-model demonstration completed for domain: {args.domain}.", flush=True)
        print(f"Report: {output}; synthetic test only; no repository platform approvals changed.", flush=True)
    except Exception as exc:
        parser.exit(1, f"Local generation demonstration failed: {exc}\n")


if __name__ == "__main__":
    main()
