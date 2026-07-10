"""
===============================================================================
RedTeam_AI Pipeline — CLI 入口
===============================================================================
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from rich.panel import Panel

from pipeline.models import PipelineStage, console
from pipeline.engine import RedTeamPipeline


# ═══════════════════════════════════════════════════════════════════════
# CLI 入口
# ═══════════════════════════════════════════════════════════════════════

async def main():
    parser = argparse.ArgumentParser(
        description="RedTeam_AI — 完整 AI 红队六阶段自动化攻击流水线",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python main.py --target https://target.com --mode auto    # 全流程一键执行
  python main.py --target https://target.com --stage recon  # 从侦察开始
  python main.py --target https://target.com --stage garak  # 从Garak开始
  python main.py --target https://target.com --stage pyrit  # 直接攻击
  python main.py --profile recon/outputs/target_profile.json --stage garak
        """,
    )
    parser.add_argument(
        "--target", "-t", type=str, default="",
        help="目标 URL (e.g. https://192.168.0.20:11434)",
    )
    parser.add_argument(
        "--stage", "-s", type=str, default="auto",
        choices=["auto", "recon", "garak", "bridge", "promptfoo", "pyrit", "report"],
        help="起始阶段 (默认 auto: 全流程)",
    )
    parser.add_argument(
        "--mode", "-m", type=str, default="auto",
        choices=["auto", "recon", "garak", "bridge", "promptfoo", "pyrit", "report"],
        help="运行模式 (同 --stage)",
    )
    parser.add_argument(
        "--profile", "-p", type=str, default="",
        help="已有的 target_profile.json 路径 (跳过 L0 侦察)",
    )
    parser.add_argument(
        "--output", "-o", type=str, default="outputs",
        help="输出目录",
    )
    parser.add_argument(
        "--concurrent", "-c", type=int, default=4,
        help="并发数 (默认: 4)",
    )
    parser.add_argument(
        "--garak-mode", type=str, default="baseline",
        choices=["baseline", "deep"],
        help="Garak 扫描模式 (默认: baseline)",
    )

    args = parser.parse_args()

    # 合并 --mode 和 --stage
    stage_str = args.stage if args.stage != "auto" else args.mode
    stage = PipelineStage(stage_str)

    if not args.target and not args.profile:
        # 如果没有 target, 展示帮助
        _print_usage_guide()
        return

    target_url = args.target
    if args.profile:
        console.print(f"[cyan]📂 从 profile 恢复: {args.profile}[/cyan]")

    pipeline = RedTeamPipeline(
        target_url=target_url,
        output_dir=args.output,
    )

    # 如果提供了 profile 路径
    if args.profile and os.path.exists(args.profile):
        with open(args.profile, "r", encoding="utf-8") as f:
            pipeline.state.profile_data = json.load(f)
        pipeline.state.profile_path = args.profile
        pipeline.state.recon_done = True

    try:
        await pipeline.run(stage)
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️ 管道被用户中断[/yellow]")
        pipeline.state.save(pipeline.state_path)
        console.print(f"[dim]状态已保存: {pipeline.state_path}[/dim]")


def _print_usage_guide():
    """展示使用指南 (无参数时)。"""
    console.print()
    console.print(Panel.fit(
        "[bold white]RedTeam_AI — 完整 AI 红队六阶段自动化攻击流水线[/bold white]\n\n"
        "[bold cyan]快速开始:[/bold cyan]\n"
        "  python main.py --target https://192.168.0.20:11434 --mode auto\n\n"
        "[bold cyan]分阶段执行:[/bold cyan]\n"
        "  python main.py --target <URL> --stage recon      # L0 前置侦察\n"
        "  python main.py --target <URL> --stage garak      # L1 AI模型侦查\n"
        "  python main.py --target <URL> --stage bridge     # L2 桥接映射\n"
        "  python main.py --target <URL> --stage promptfoo  # L3 提示词模板\n"
        "  python main.py --target <URL> --stage pyrit      # L4 深度攻击\n"
        "  python main.py --target <URL> --stage report     # L5 统一报告\n\n"
        "[bold cyan]从已有侦察结果恢复:[/bold cyan]\n"
        "  python main.py --profile recon/outputs/target_profile.json --stage garak\n\n"
        "[bold cyan]管道流程:[/bold cyan]\n"
        "  L0 Recon → L1 Garak → L2 Bridge → L3 Promptfoo → L4 PyRIT → L5 Report\n"
        "  每阶段自动输出 专家指导(Expert Guidance) 推荐下一步操作",
        title="[bold red]RedTeam_AI[/bold red]",
        border_style="red",
    ))
    console.print()


if __name__ == "__main__":
    asyncio.run(main())
