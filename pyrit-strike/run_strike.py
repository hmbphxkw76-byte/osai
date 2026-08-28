"""PyRIT-Strike 标准化攻击编排入口 — 一键场景化攻击.

用法::

    # 列出所有策略
    python run_strike.py --list-strategies

    # 快速基线探测 (--burp-request 默认 data/burp/request.txt)
    python run_strike.py --strategy quick_scan

    # 全火力 L5 最优攻击
    python run_strike.py --strategy full_offensive

    # 精准攻击策略
    python run_strike.py --strategy targeted_full

    # OWASP 全覆盖策略
    python run_strike.py --strategy full_coverage

    # 自动推荐策略 (基于目标指纹)
    python run_strike.py --strategy auto

    # 多策略对比
    python run_strike.py --strategy all

    # 指定自定义 Burp 请求文件
    python run_strike.py --burp-request /path/to/request.txt --strategy targeted_full

    # 对比已有运行结果
    python run_strike.py --compare outputs/run1 outputs/run2

设计理念:
    - 策略预设封装了种子 + 技术 + Converter + 升级的最优组合
    - 基于 arXiv 学术研究的 L5 专家级 Converter 链配置
    - 每个策略可独立运行, 也可批量对比
    - 完全复用 main.py 的五阶段流水线, 不重复造轮子
"""

from __future__ import annotations

import asyncio
import atexit
import logging
import os
import shutil
import signal
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

# UTF-8 强制设置 (Windows GBK 终端兼容)
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# 项目根目录
_PROJECT_ROOT = Path(__file__).resolve().parent

# 将项目根目录加入 sys.path
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from pipeline.strategy.presets import (  # noqa: E402
    STRATEGY_PRESETS,
    get_strategy_args,
    list_strategies,
    recommend_strategy,
)
from pipeline.utils.display import print_banner, print_phase  # noqa: E402

logger = logging.getLogger(__name__)

# ── 进程终止处理 ──
# R6 HARD GATE: atexit 钩子清理临时缓存文件
# signal 处理器捕获 Ctrl+C / SIGTERM, 优雅取消所有 asyncio 任务并停止流水线


def cleanup_temp_files() -> None:
    """清理临时缓存文件 (R6 HARD GATE).

    删除 __pycache__, .pytest_cache, .ruff_cache 目录。
    幂等设计: 所有操作 ignore_errors=True, 不会抛出异常。
    """
    for cache_dir in _PROJECT_ROOT.rglob("__pycache__"):
        shutil.rmtree(cache_dir, ignore_errors=True)
    for cache_name in (".pytest_cache", ".ruff_cache"):
        shutil.rmtree(_PROJECT_ROOT / cache_name, ignore_errors=True)
    logger.info("Temp cache cleaned: __pycache__, .pytest_cache, .ruff_cache")


atexit.register(cleanup_temp_files)

_main_loop: asyncio.AbstractEventLoop | None = None


def _signal_handler(signum: int, frame: Any) -> None:
    """信号处理器: 捕获 SIGINT / SIGTERM, 优雅停止流水线."""
    sig_name = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
    logger.warning("Received %s — shutting down pipeline...", sig_name)
    print_phase("ABORT", f"Received {sig_name}, stopping pipeline...")

    if _main_loop is not None and _main_loop.is_running():
        for task in asyncio.all_tasks(_main_loop):
            task.cancel()
        logger.info("All asyncio tasks cancelled.")
    else:
        sys.exit(130)


signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


def parse_strike_args() -> Any:
    """解析 run_strike.py 专用参数."""
    import argparse

    parser = argparse.ArgumentParser(
        description="PyRIT-Strike 标准化攻击编排入口 — 一键场景化攻击",
    )

    # ── 策略 ──
    parser.add_argument(
        "--strategy",
        type=str,
        default="full_offensive",
        help=(
            "攻击策略预设 (quick_scan, stealth_bypass, persuasion_heavy, "
            "full_offensive, full_coverage, multi_turn_deep, targeted_full, auto, all)"
        ),
    )
    parser.add_argument(
        "--list-strategies",
        action="store_true",
        help="列出所有可用策略并退出",
    )

    # ── 目标 ──
    parser.add_argument(
        "--burp-request",
        type=str,
        default="data/burp/request.txt",
        help="Burp Suite 原始 HTTP 请求文件路径 (默认: data/burp/request.txt)",
    )

    # 批量攻击 — 扫描目录下所有 Burp 请求文件
    parser.add_argument(
        "--burp-dir",
        type=str,
        default=None,
        help="Burp 请求文件目录 (批量攻击模式, 使用 run_batch.py 获取完整功能)",
    )

    # Cookie 自动注入
    parser.add_argument(
        "--cookie",
        type=str,
        default=None,
        help="Cookie 值 (自动注入到 Burp 请求, 覆盖环境变量 TARGET_COOKIE)",
    )

    # ── 对比 ──
    parser.add_argument(
        "--compare",
        type=str,
        nargs="+",
        default=None,
        help="对比多个运行结果目录 (空格分隔)",
    )

    # ── 输出 ──
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="输出目录 (默认: outputs/redteam_YYYYMMDD_HHMMSS_{strategy})",
    )

    return parser.parse_args()


async def run_single_strategy(
    strategy_name: str,
    burp_request: str,
    output_dir: str | None = None,
) -> Path:
    """执行单个策略的完整攻击流水线.

    Args:
        strategy_name: 策略名称.
        burp_request: Burp 请求文件路径.
        output_dir: 输出目录 (可选).

    Returns:
        输出目录路径.
    """
    preset = STRATEGY_PRESETS.get(strategy_name)
    if preset is None:
        raise ValueError(f"Unknown strategy: {strategy_name}")

    print_phase("STRATEGY", f"Executing: {preset.name}")
    print_phase("STRATEGY", f"Description: {preset.description}")
    print_phase(
        "STRATEGY",
        f"Seeds: {preset.seeds} (max={preset.max_seeds}) | "
        f"Techniques: {preset.techniques} | "
        f"Converters: {preset.converters} | "
        f"Escalation: {preset.escalation}",
    )

    # 确定输出目录 (统一命名: redteam_YYYYMMDD_HHMMSS_strategy)
    if output_dir is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = str(
            _PROJECT_ROOT / "outputs" / f"redteam_{timestamp}_{preset.name}"
        )

    # 构建命令行参数, 调用 main.py 的流水线
    strategy_args = get_strategy_args(strategy_name)

    # 构建参数列表 (编程式调用, 不含程序名)
    # 重要: 传递 --strategy 参数, 使 main.py 能路由到 web_vuln / comprehensive 等特殊策略
    argv = [
        "--burp-request", burp_request,
        "--strategy", strategy_name,
        "--seeds", strategy_args["seeds"],
        "--max-seeds", str(strategy_args["max_seeds"]),
        "--techniques", strategy_args["techniques"],
        "--converters", strategy_args["converters"],
        "--max-attempts", str(strategy_args["max_attempts"]),
        "--max-concurrency", str(strategy_args["max_concurrency"]),
        "--timeout", str(strategy_args["timeout"]),
        "--output-dir", output_dir,
    ]

    if strategy_args["html_report"]:
        argv.append("--html-report")
    if strategy_args.get("offensive"):
        argv.append("--offensive")
    # L5 v32: 传递 escalation 标志
    if strategy_args.get("escalation"):
        argv.append("--escalation")
    else:
        argv.append("--no-escalation")

    # 编程式调用 main.py 流水线 (不修改 sys.argv)
    print_phase("PIPELINE", "Starting five-phase attack pipeline...")
    from main import main

    await main(argv)

    output_path = Path(output_dir)
    print_phase("DONE", f"Output: {output_path}")
    return output_path


async def run_all_strategies(
    burp_request: str,
    output_base: str | None = None,
) -> list[Path]:
    """执行所有策略并生成对比报告.

    Args:
        burp_request: Burp 请求文件路径.
        output_base: 输出基目录.

    Returns:
        所有运行输出目录列表.
    """
    if output_base is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_base = str(_PROJECT_ROOT / "outputs" / f"redteam_{timestamp}_comparison")

    output_base_path = Path(output_base)
    output_base_path.mkdir(parents=True, exist_ok=True)

    run_dirs: list[Path] = []

    for strategy_name in STRATEGY_PRESETS:
        print_phase("BATCH", f"Running strategy: {strategy_name}")
        run_output = output_base_path / strategy_name
        try:
            result_dir = await run_single_strategy(
                strategy_name=strategy_name,
                burp_request=burp_request,
                output_dir=str(run_output),
            )
            run_dirs.append(result_dir)
        except Exception as e:
            logger.error("Strategy %s failed: %s", strategy_name, e)

    # 生成对比报告
    if len(run_dirs) > 1:
        print_phase("COMPARE", "Generating comparison report...")
        from pipeline.report.comparator import compare_runs

        compare_runs(run_dirs, output_base_path)
        print_phase("COMPARE", f"Comparison report: {output_base_path}")

    return run_dirs


async def run_auto_strategy(
    burp_request: str,
    output_dir: str | None = None,
) -> Path:
    """自动推荐策略并执行.

    Args:
        burp_request: Burp 请求文件路径.
        output_dir: 输出目录.

    Returns:
        输出目录路径.
    """
    # 先解析 Burp 请求获取指纹
    from pipeline.recon.burp_parser import parse_burp_request

    parsed = parse_burp_request(burp_request)
    fingerprint = parsed.target_fingerprint

    # 检查是否有 adversarial target
    has_adversarial = bool(os.environ.get("ADVERSARIAL_CHAT_ENDPOINT"))

    strategy_name = recommend_strategy(fingerprint, has_adversarial=has_adversarial)

    print_phase("AUTO", f"Target fingerprint: {fingerprint}")
    print_phase("AUTO", f"Recommended strategy: {strategy_name}")

    return await run_single_strategy(strategy_name, burp_request, output_dir)


def compare_existing_runs(run_dirs: list[str]) -> None:
    """对比已有运行结果."""
    run_paths = [Path(d) for d in run_dirs]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = _PROJECT_ROOT / "outputs" / f"redteam_{timestamp}_comparison"
    output_dir.mkdir(parents=True, exist_ok=True)

    from pipeline.report.comparator import compare_runs

    compare_runs(run_paths, output_dir)
    print_phase("COMPARE", f"Comparison report: {output_dir}")


async def async_main() -> None:
    """异步主入口."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    print_banner()

    args = parse_strike_args()

    # 列出策略
    if args.list_strategies:
        print(list_strategies())
        return

    # 对比已有运行
    if args.compare:
        compare_existing_runs(args.compare)
        return

    # 批量攻击模式 --burp-dir
    # 自动转发到 run_batch.py 完整批量执行
    if getattr(args, "burp_dir", None):
        print_phase("BATCH", f"Batch mode: scanning {args.burp_dir}")
        from run_batch import run_batch

        _batch_argv = ["--burp-dir", args.burp_dir]
        if getattr(args, "cookie", None):
            _batch_argv += ["--cookie", args.cookie]
        if args.strategy and args.strategy != "full_offensive":
            _batch_argv += ["--strategy", args.strategy]
        if args.output_dir:
            _batch_argv += ["--output-base", args.output_dir]
        await run_batch(_batch_argv)
        return

    # Cookie 自动注入
    if getattr(args, "cookie", None) or os.environ.get("TARGET_COOKIE"):
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        burp_path = Path(args.burp_request)
        if burp_path.exists():
            raw_request = burp_path.read_text(encoding="utf-8", errors="replace")
            cookie_val = getattr(args, "cookie", None) or None
            raw_request = mapper.inject_cookie_into_request(raw_request, cookie_val)
            # 写入临时文件
            import tempfile
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, encoding="utf-8", newline=""
            ) as tmp:
                tmp.write(raw_request)
                args.burp_request = tmp.name
            logger.info("Cookie auto-injected to temporary Burp file: %s", tmp.name)

    # 执行攻击
    # 检查 burp_request 文件是否存在
    burp_path = Path(args.burp_request)
    if not burp_path.exists():
        print(f"Error: Burp request file not found: {args.burp_request}")
        print(f"Place your Burp HTTP request at: {args.burp_request}")
        print("Or specify a custom path: --burp-request /path/to/request.txt")
        print("Use --list-strategies to see available strategies")
        return

    if args.strategy == "all":
        await run_all_strategies(args.burp_request, args.output_dir)
    elif args.strategy == "auto":
        await run_auto_strategy(args.burp_request, args.output_dir)
    else:
        await run_single_strategy(args.strategy, args.burp_request, args.output_dir)


def main() -> None:
    """同步入口."""
    global _main_loop
    _main_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_main_loop)
    try:
        _main_loop.run_until_complete(async_main())
    except (KeyboardInterrupt, asyncio.CancelledError):
        print_phase("ABORT", "Pipeline interrupted by user (Ctrl+C).")
        logger.warning("Pipeline interrupted by user.")
    finally:
        pending = asyncio.all_tasks(_main_loop)
        for task in pending:
            task.cancel()
        if pending:
            _main_loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        _main_loop.close()


if __name__ == "__main__":
    main()
