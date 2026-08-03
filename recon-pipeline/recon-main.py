# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""recon-main: 纯编排主程序入口。

职责 (仅编排, 不含业务逻辑):
  1. 扫描 pipeline/stages/ 目录, 动态发现并加载所有阶段文件 (*_stage.py)
  2. 将发现的阶段注册到 pipeline.registry (按文件名稳定排序, 保证可复现)
  3. 从 .env + config/ 加载 PipelineContext (必改变量走 .env)
  4. 通过 PipelineRunner 串联执行已注册阶段, 输出标准报告

本文件不实现任何侦察/分类/认证逻辑, 所有能力由 pipeline/ 阶段提供。
新增阶段只需在 pipeline/stages/ 下放置 *_stage.py 并继承 PipelineStage,
本入口会自动发现, 无需改动此处。

用法:
    python recon-main.py
    python recon-main.py --target https://example.test --type auto
    python recon-main.py --stages classify,auth,recon,export
    python recon-main.py --export json,pyrit
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import shutil
import sys
from pathlib import Path
from typing import Any

# ── 路径引导: 允许从任意 cwd 运行 ──
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# R-012: 始终使用 UTF-8 编码
import os as _os

_os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from pipeline.registry import autodiscover, list_stages  # noqa: E402
from pipeline.runner import PipelineRunner  # noqa: E402
from pipeline.context_loader import load_context  # noqa: E402
from pipeline.stages.base import PipelineStage  # noqa: E402

logger = logging.getLogger("recon-main")

STAGES_DIR = PROJECT_ROOT / "pipeline" / "stages"

# R-008: 需要清理的临时目录和文件模式
_TEMP_DIR_PATTERNS = ("__pycache__", ".pytest_cache")
_TEMP_FILE_PATTERNS = ("*.pyc", "*.pyo")


def clean_temp_files(phase: str = "pre") -> int:
    """递归清理项目中所有 __pycache__ 目录、.pyc/.pyo 文件和 .pytest_cache 目录。

    规则 R-008: 三库统一标准 — 每次运行前和运行后自动执行。
    静默执行，不输出到 stdout。

    Args:
        phase: 清理阶段 ("pre" 或 "post")

    Returns:
        清理的文件/目录数
    """
    removed = 0

    for pattern in _TEMP_DIR_PATTERNS:
        for temp_dir in PROJECT_ROOT.rglob(pattern):
            if temp_dir.is_dir():
                shutil.rmtree(temp_dir, ignore_errors=True)
                removed += 1

    for pattern in _TEMP_FILE_PATTERNS:
        for temp_file in PROJECT_ROOT.rglob(pattern):
            if temp_file.is_file():
                temp_file.unlink(missing_ok=True)
                removed += 1

    return removed


def register_discovered_stages(stages_dir: Path = STAGES_DIR) -> list[str]:
    """发现并注册所有阶段, 返回注册成功的阶段名列表。"""
    registered = autodiscover(stages_dir)
    for name in registered:
        logger.info(f"registered stage: {name}")
    return registered


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recon-main",
        description="纯编排入口: 自动发现 pipeline/stages 并执行端到端侦察",
    )
    parser.add_argument("--target", help="目标 URL (覆盖 .env 的 TARGET_URL)")
    parser.add_argument(
        "--type", dest="target_type",
        choices=["auto", "llm_webapp", "model_platform"],
        help="目标类型提示 (覆盖 .env 的 TARGET_TYPE)",
    )
    parser.add_argument("--api-key", help="API Key (覆盖 .env 的 API_KEY)")
    parser.add_argument(
        "--auth-type",
        choices=["auto", "none", "same_domain", "cross_domain", "otp", "sliding", "sms", "qr"],
        help="认证类型提示 (覆盖 .env 的 AUTH_TYPE)",
    )
    parser.add_argument(
        "--stages",
        help="逗号分隔的自定义阶段执行顺序 (默认使用注册表的发现顺序)",
    )
    parser.add_argument(
        "--export",
        help="逗号分隔的导出格式 (json/pyrit/garak), 覆盖 .env 的 EXPORT_FORMATS",
    )
    parser.add_argument(
        "--output-dir", help="报告输出目录 (覆盖 .env 的 OUTPUT_DIR)"
    )
    parser.add_argument(
        "--list-stages", action="store_true",
        help="列出已注册阶段后退出",
    )
    parser.add_argument(
        "--stop-on-failure", action="store_true",
        help="任一阶段失败时立即停止流水线",
    )
    parser.add_argument(
        "--no-run", action="store_true",
        help="仅发现并注册阶段, 不执行 (用于验证配置)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="输出 DEBUG 级日志"
    )
    return parser


def parse_overrides(args: argparse.Namespace) -> dict[str, Any]:
    """将 CLI 参数转换为 context 覆盖字典。"""
    overrides: dict[str, Any] = {}
    if args.target:
        overrides["target_url"] = args.target
    if args.target_type:
        overrides["target_type_hint"] = args.target_type
    if args.api_key:
        overrides["api_key"] = args.api_key
    if args.auth_type:
        overrides["auth_type_hint"] = args.auth_type
    if args.export:
        overrides["export_formats"] = [f.strip() for f in args.export.split(",") if f.strip()]
    if args.output_dir:
        overrides["output_dir"] = args.output_dir
    return overrides


async def main_async() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    # R-008: 运行前清理临时文件
    clean_temp_files("pre")

    # 1. 发现并注册阶段 (动态读取 pipeline/stages/)
    registered = register_discovered_stages()
    logger.info(f"discovered and registered {len(registered)} stage(s): {registered}")

    if args.list_stages:
        print("Registered stages:")
        for name in list_stages():
            print(f"  - {name}")
        return 0

    if not registered:
        logger.error("no stages discovered; nothing to run")
        return 1

    # 2. 加载上下文 (从 .env + config/)
    ctx = load_context(overrides=parse_overrides(args))

    if args.no_run:
        logger.info("--no-run: skipping execution")
        print(json.dumps(ctx.to_dict(), indent=2, ensure_ascii=False, default=str))
        return 0

    # 3. 确定阶段执行顺序
    if args.stages:
        order = [s.strip() for s in args.stages.split(",") if s.strip()]
        # 校验阶段存在
        unknown = [s for s in order if s not in list_stages()]
        if unknown:
            logger.error(f"unknown stages in --stages: {unknown}")
            return 1
    else:
        # 默认顺序: 注册表发现顺序 (classify → auth → recon → export)
        order = list_stages()

    # 4. 编排执行
    runner = PipelineRunner(stage_order=order, stop_on_failure=args.stop_on_failure)
    result = await runner.run(ctx)

    # 5. 输出结果摘要
    print("\n" + "=" * 60)
    print("Recon Pipeline 执行完成")
    print("=" * 60)
    summary = result.to_dict()
    print(json.dumps(summary, indent=2, ensure_ascii=False, default=str))

    if ctx.classification:
        print(f"\n[分类] {ctx.classification.category.value}"
              f" / vendor={ctx.classification.platform_vendor.value}"
              f" / auth={ctx.classification.auth_topology}"
              f" / 2nd-factor={ctx.classification.second_factor}")
    if ctx.auth_decision:
        print(f"[认证] strategy={ctx.auth_decision.strategy_name}"
              f" / needs_browser={ctx.auth_decision.needs_browser}"
              f" / needs_human={ctx.auth_decision.needs_human}")

    report = result.report
    if report is not None and hasattr(report, "to_summary_dict"):
        s = report.to_summary_dict()
        print(f"\n[侦察] endpoints={len(s.get('endpoints', []))}"
              f" / fingerprints={len(s.get('llm_fingerprints', []))}"
              f" / mcp_tools={len(s.get('mcp_tools', []))}"
              f" / recommendations={len(s.get('recommendations', []))}")

    for stage in result.stages:
        if stage.stage_name == "export" and stage.status == "success":
            print(f"\n[导出] {json.dumps(stage.artifact, ensure_ascii=False)}")

    failed = len(result.failed_stages)
    return_code = 1 if failed and args.stop_on_failure else 0

    # R-008: 运行后清理临时文件
    clean_temp_files("post")

    return return_code


def main() -> int:
    """同步入口 (供命令行调用)。"""
    try:
        return asyncio.run(main_async())
    except KeyboardInterrupt:
        logger.warning("interrupted by user")
        # R-008: 异常退出也清理临时文件
        clean_temp_files("post")
        return 130


if __name__ == "__main__":
    sys.exit(main())
