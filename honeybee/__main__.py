"""命令行入口：python -m honeybee build / inspect"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .build import build, inspect_bundle, verify_with_singbox

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SOURCES = str(ROOT / "config" / "sources.json")
DEFAULT_SETTINGS = str(ROOT / "config" / "settings.json")
DEFAULT_BASE = str(ROOT / "config" / "base.json")
DEFAULT_OUTPUT = str(ROOT / "sub" / "sub.tar.gz")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="honeybee",
        description="收集代理、清理验证、拆分、生成 sing-box JSON 并压缩为单个文件",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    builder = commands.add_parser("build", help="跑完整条流水线")
    builder.add_argument("--sources", default=DEFAULT_SOURCES, help="订阅源清单 JSON")
    builder.add_argument("--settings", default=DEFAULT_SETTINGS, help="流水线设置 JSON")
    builder.add_argument("--base", default=DEFAULT_BASE, help="sing-box 基础配置模板")
    builder.add_argument("--output", default=DEFAULT_OUTPUT, help="输出的压缩包路径")
    builder.add_argument("--max-per-file", type=int, default=None,
                         help="每份 JSON 的最大节点数（默认读 settings）")
    builder.add_argument("--offline", default=None,
                         help="不联网，只转换这份本地订阅样本（用于测试）")
    builder.add_argument("--quiet", action="store_true")

    inspector = commands.add_parser("inspect", help="检查已有压缩包")
    inspector.add_argument("--input", default=DEFAULT_OUTPUT)
    inspector.add_argument("--json", action="store_true", help="输出 JSON 而不是文本")

    checker = commands.add_parser("verify-bundle",
                                  help="用官方 sing-box 逐份复核压缩包")
    checker.add_argument("--input", default=DEFAULT_OUTPUT)
    checker.add_argument("--sing-box", default="sing-box",
                         help="sing-box 可执行文件路径（不存在时跳过）")

    args = parser.parse_args(argv)

    if args.command == "verify-bundle":
        try:
            checked, problems = verify_with_singbox(args.input, args.sing_box)
        except (OSError, ValueError) as exc:
            print(f"[honeybee] ERROR: {exc}", file=sys.stderr)
            return 2
        print(f"[honeybee] sing-box checked {checked} configs, {len(problems)} failed")
        for problem in problems[:20]:
            print(f"  ! {problem}")
        return 1 if problems else 0

    if args.command == "build":
        try:
            report = build(
                sources_path=args.sources,
                settings_path=args.settings,
                base_path=args.base,
                output=args.output,
                max_per_file=args.max_per_file,
                offline=args.offline,
                verbose=not args.quiet,
            )
        except RuntimeError as exc:
            print(f"[honeybee] ERROR: {exc}", file=sys.stderr)
            return 2
        print(f"[honeybee] OK: {report['total_nodes']} nodes in {report['files']} files")
        return 0

    try:
        summary = inspect_bundle(args.input)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[honeybee] ERROR: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print(f"files         : {len(summary['files'])}")
        print(f"config nodes  : {summary['config_nodes']}")
        print(f"manifest nodes: {summary['manifest_nodes']}")
        print(f"content hash  : {summary['content_hash']}")
        print(f"problems      : {len(summary['problems'])}")
        for problem in summary["problems"][:20]:
            print(f"  ! {problem}")
    return 1 if summary["problems"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
