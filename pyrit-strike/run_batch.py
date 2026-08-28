"""批量攻击编排入口 — 多端点/多目标自动化攻击。

适配任意基于 LLM 开发的 Agent 应用场景。

功能:
    1. 扫描 data/burp/ 和 data/burp/endpoints/ 目录, 发现所有 Burp 请求文件
    2. 从 target_profiles.yaml 匹配每个 Burp 请求对应的目标 Profile
    3. 自动注入 Cookie (从环境变量 TARGET_COOKIE 或 cookie.txt)
    4. 按 Profile 配置选择最优种子组合和策略
    5. 依次执行攻击, 每个生成独立输出目录
    6. 汇总所有目标的攻击结果

用法::

    # 批量攻击所有目标
    python run_batch.py

    # 指定 Burp 文件目录
    python run_batch.py --burp-dir /path/to/burp/files

    # 指定 Cookie (覆盖环境变量)
    python run_batch.py --cookie "my-session-id"

    # 只攻击特定类别 (如 mcp)
    python run_batch.py --category mcp

    # 查看攻击计划 (dry-run, 不执行)
    python run_batch.py --dry-run

    # 自定义策略 (覆盖 Profile 配置)
    python run_batch.py --strategy targeted_full

设计原则:
    - 不修改 main.py / run_strike.py 的核心流水线
    - 复用 PipelineContext + target_router + executor
    - Cookie 自动注入到临时文件
    - 每个目标独立输出目录, 便于汇总
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

# UTF-8 强制设置 (Windows GBK 终端兼容)
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

_PROJECT_ROOT = Path(__file__).resolve().parent

if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from pipeline.recon.target_mapper import TargetMapper  # noqa: E402
from pipeline.utils.display import print_banner, print_phase  # noqa: E402

logger = logging.getLogger(__name__)


def parse_batch_args(argv: list[str] | None = None) -> Any:
    """解析 run_batch.py 专用参数。

    Args:
        argv: 可选参数列表。None 时使用 sys.argv (CLI 模式)。
              传入列表时用于编程式调用 (如 run_strike.py)。
    """
    import argparse

    parser = argparse.ArgumentParser(
        description="PyRIT-Strike 批量攻击 — 多目标自动化攻击编排",
    )

    # ── 目标 ──
    parser.add_argument(
        "--burp-dir",
        type=str,
        default=None,
        help="Burp 请求文件目录 (默认: data/burp/ + data/burp/endpoints/)",
    )
    parser.add_argument(
        "--burp-file",
        type=str,
        default=None,
        help="单个 Burp 请求文件 (跳过批量扫描, 只攻击一个目标)",
    )

    # ── Cookie ──
    parser.add_argument(
        "--cookie",
        type=str,
        default=None,
        help="Cookie 值 (覆盖环境变量 TARGET_COOKIE, 注入到所有 Burp 请求)",
    )

    # ── 筛选 ──
    parser.add_argument(
        "--category",
        type=str,
        default=None,
        help="只攻击特定类别 (如 mcp, rag, prompt_injection, sqli)",
    )
    parser.add_argument(
        "--profile-ids",
        type=str,
        default=None,
        help="只攻击特定 profile_id (逗号分隔, 如 mcp_tool_hijack,rag_leakage)",
    )

    # ── 策略 ──
    parser.add_argument(
        "--strategy",
        type=str,
        default=None,
        help="覆盖 Profile 配置的策略 (如 targeted_full, web_vuln, quick_scan)",
    )
    parser.add_argument(
        "--seeds",
        type=str,
        default=None,
        help="覆盖 Profile 配置的种子 (逗号分隔, 如 mcp_attack,tool_hijack)",
    )

    # ── 执行控制 ──
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="只打印攻击计划, 不执行",
    )
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        default=True,
        help="单个目标失败后继续下一个 (默认启用)",
    )
    parser.add_argument(
        "--stop-on-first-success",
        action="store_true",
        help="第一个目标攻击成功后停止 (节省 API 调用)",
    )

    # ── 输出 ──
    parser.add_argument(
        "--output-base",
        type=str,
        default=None,
        help="输出基目录 (默认: outputs/batch_YYYYMMDD_HHMMSS/)",
    )

    return parser.parse_args(argv)


async def run_single_target_attack(
    plan_entry: dict[str, Any],
    cookie_value: str | None,
    output_dir: str,
    strategy_override: str | None = None,
    seeds_override: str | None = None,
) -> dict[str, Any]:
    """执行单个目标的攻击。

    Args:
        plan_entry: 攻击计划条目。
        cookie_value: Cookie 值 (None 时不注入)。
        output_dir: 输出目录。
        strategy_override: 策略覆盖。
        seeds_override: 种子覆盖。

    Returns:
        攻击结果摘要。
    """
    burp_file = plan_entry["burp_file"]
    profile_id = plan_entry["profile_id"]
    profile_name = plan_entry.get("profile_name", "Unknown")
    strategy = strategy_override or plan_entry.get("strategy", "targeted_full")
    seeds = seeds_override or plan_entry.get("seeds", "targeted_v2,elite_jailbreaks")

    print_phase("TARGET", f"[{profile_id}] {profile_name}")
    print_phase("TARGET", f"  Burp: {burp_file}")
    print_phase("TARGET", f"  Seeds: {seeds}")
    print_phase("TARGET", f"  Strategy: {strategy}")
    print_phase("TARGET", f"  Output: {output_dir}")

    # ── Cookie 注入 ──
    burp_path = Path(burp_file)
    raw_request = burp_path.read_text(encoding="utf-8", errors="replace")

    mapper = TargetMapper()
    if cookie_value:
        raw_request = mapper.inject_cookie_into_request(raw_request, cookie_value)
    else:
        # 尝试自动获取 Cookie
        raw_request = mapper.inject_cookie_into_request(raw_request)

    # 写入临时文件
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8", newline=""
    ) as tmp:
        tmp.write(raw_request)
        tmp_burp_path = tmp.name

    try:
        # 构建参数列表, 函数级调用 main.py 流水线
        argv = [
            "--burp-request", tmp_burp_path,
            "--seeds", seeds,
            "--strategy", strategy,
            "--output-dir", output_dir,
            "--html-report",
            "--offensive",
        ]

        print_phase("PIPELINE", f"[{profile_id}] Starting attack pipeline...")
        from main import main

        await main(argv)

        return {
            "profile_id": profile_id,
            "profile_name": profile_name,
            "status": "completed",
            "output_dir": output_dir,
            "owasp_id": plan_entry.get("owasp_id", ""),
        }

    except Exception as e:
        logger.error("[%s] Attack failed: %s", profile_id, e)
        return {
            "profile_id": profile_id,
            "profile_name": profile_name,
            "status": f"failed: {e}",
            "output_dir": output_dir,
            "owasp_id": plan_entry.get("owasp_id", ""),
        }
    finally:
        # 清理临时文件
        try:
            os.unlink(tmp_burp_path)
        except OSError:
            pass


async def run_batch(argv: list[str] | None = None) -> None:
    """批量执行攻击。

    Args:
        argv: 可选参数列表。None 时使用 sys.argv (CLI 模式)。
              传入列表时用于编程式调用 (如 run_strike.py)。
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    print_banner()

    args = parse_batch_args(argv)

    mapper = TargetMapper()

    # ── 构建攻击计划 ──
    if args.burp_file:
        # 单文件模式
        burp_path = Path(args.burp_file)
        if not burp_path.exists():
            print(f"Error: Burp file not found: {args.burp_file}")
            return

        raw_request = burp_path.read_text(encoding="utf-8", errors="replace")
        first_line = raw_request.split("\n")[0]
        path = first_line.split(" ")[1] if " " in first_line else ""

        profile = mapper.match_profile_by_path(path)
        plan = [{
            "burp_file": str(burp_path),
            "profile_id": profile.id if profile else "UNKNOWN",
            "profile_name": profile.name if profile else "Unknown Profile",
            "seeds": ",".join(profile.seeds) if profile else "targeted_v2",
            "strategy": profile.strategy if profile else "targeted_full",
            "owasp_id": profile.owasp_id if profile else "",
            "description": profile.description if profile else "",
        }]
    else:
        # 批量扫描模式
        plan = mapper.build_attack_plan(args.burp_dir)

    # ── 筛选 ──
    if args.category:
        # 按类别筛选
        plan = [p for p in plan if args.category.lower() in p.get("profile_id", "").lower()]
        print_phase("FILTER", f"Category '{args.category}': {len(plan)} targets")

    if args.profile_ids:
        # 按 profile_id 筛选
        ids = set(args.profile_ids.split(","))
        plan = [p for p in plan if p["profile_id"] in ids]
        print_phase("FILTER", f"Profile IDs {ids}: {len(plan)} targets")

    if not plan:
        print("No targets to attack. Check your Burp files and target_profiles.yaml.")
        return

    # ── 打印攻击计划 ──
    print_phase("PLAN", f"Attack plan: {len(plan)} targets")
    for i, entry in enumerate(plan, 1):
        print(
            f"  [{i}] {entry['profile_id']}: {entry['profile_name']}"
            f"  → seeds={entry['seeds']}, strategy={entry['strategy']}"
        )

    if args.dry_run:
        print_phase("DRY-RUN", "Attack plan printed, not executing.")
        return

    # ── 准备输出基目录 ──
    if args.output_base:
        output_base = Path(args.output_base)
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_base = _PROJECT_ROOT / "outputs" / f"batch_{timestamp}"

    output_base.mkdir(parents=True, exist_ok=True)

    # ── 执行攻击 ──
    results: list[dict[str, Any]] = []
    cookie_value = args.cookie

    for i, plan_entry in enumerate(plan, 1):
        print_phase(
            "BATCH",
            f"[{i}/{len(plan)}] {plan_entry['profile_id']}: {plan_entry['profile_name']}",
        )

        # 每个目标独立输出目录
        target_output = str(output_base / plan_entry["profile_id"])

        result = await run_single_target_attack(
            plan_entry=plan_entry,
            cookie_value=cookie_value,
            output_dir=target_output,
            strategy_override=args.strategy,
            seeds_override=args.seeds,
        )
        results.append(result)

        # 检查是否应该停止
        if args.stop_on_first_success and result["status"] == "completed":
            print_phase("STOP", "First success reached, stopping batch.")
            break

        if not args.continue_on_error and "failed" in result["status"]:
            print_phase("STOP", f"Target {result['profile_id']} failed, stopping (use --continue-on-error to skip).")
            break

    # ── 汇总报告 ──
    print_phase("SUMMARY", f"Batch attack complete: {len(results)} targets")
    success_count = sum(1 for r in results if r["status"] == "completed")
    fail_count = sum(1 for r in results if "failed" in r["status"])
    print(f"  Success: {success_count}")
    print(f"  Failed: {fail_count}")
    print(f"  Output base: {output_base}")

    # 生成汇总 JSON
    import json

    summary_path = output_base / "batch_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "total_targets": len(results),
            "success": success_count,
            "failed": fail_count,
            "results": results,
        }, f, indent=2, ensure_ascii=False)
    print(f"  Summary: {summary_path}")


# ── 信号处理 ──
_main_loop: asyncio.AbstractEventLoop | None = None


def _signal_handler(signum: int, frame: Any) -> None:
    """信号处理器: 优雅停止批量攻击。"""
    sig_name = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
    logger.warning("Received %s — shutting down batch attack...", sig_name)
    print_phase("ABORT", f"Received {sig_name}, stopping batch attack...")
    if _main_loop is not None and _main_loop.is_running():
        for task in asyncio.all_tasks(_main_loop):
            task.cancel()
    else:
        sys.exit(130)


signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


def main() -> None:
    """同步入口。"""
    global _main_loop
    _main_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_main_loop)
    try:
        _main_loop.run_until_complete(run_batch())
    except (KeyboardInterrupt, asyncio.CancelledError):
        print_phase("ABORT", "Batch attack interrupted by user (Ctrl+C).")
    finally:
        pending = asyncio.all_tasks(_main_loop)
        for task in pending:
            task.cancel()
        if pending:
            _main_loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        _main_loop.close()


if __name__ == "__main__":
    main()
