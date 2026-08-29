"""PyRIT-Strike 核心流水线入口 — 黑盒 Burp→攻击→报告 一键流水线。

职责:
    核心攻击流水线 (INIT → RECON → ARM → STRIKE → ASSESS → REPORT)。
    支持编程式调用 (通过 argv 参数) 和 CLI 模式 (通过 sys.argv)。

入口文件职责划分:
    - main.py: 核心流水线 (单次攻击 + 报告生成)
    - run_strike.py: 策略化攻击编排 (多策略对比 + 自动推荐)
    - run_batch.py: 批量攻击 (多目标自动化)
    - run_web_vuln.py: Web 漏洞攻击 (多端点发现 + 传统 payload)
    - regen_report.py: 离线报告重新生成 (从 evidence.json 重新生成报告)

纯黑盒场景:
    - 仅需 Burp 拦截的 HTTP 请求 (无目标 API Key, 无目标模型信息)
    - adversarial + scorer 使用用户自己的 LLM API

使用方式::

    # 默认使用 data/burp/request.txt (--burp-request 默认值)
    python main.py --offensive
    python main.py --techniques single

    # 指定自定义 Burp 请求文件
    python main.py --burp-request /path/to/request.txt --offensive

    # 编程式调用 (不修改 sys.argv)
    from main import main
    await main(["--burp-request", "req.txt", "--offensive"])

参数优先级:
    CLI --flag > config/defaults.yaml (SSOT) > 硬编码 fallback
    所有 L5 基线参数从 defaults.yaml 读取, 子模块通过
    get_effective_concurrency(ctx) / _get_config_int(ctx, key, default) 统一访问。

关键配置 (config/defaults.yaml):
    max_concurrency: 3       (SQLite WAL 安全上限)
    max_attempts: 3          (arXiv:2402.01135 N=3 ASR 1.5-2x)
    best_of_n_retries: 5    (3 Persuasion + 2 Variation, 联概率 88.5%)
    escalation_asr_threshold: 90  (单轮 ASR < 90% 触发多轮升级)
    tap_tree_width: 4, tap_tree_depth: 4   (arXiv:2312.02191)
    pair_tree_width: 1, pair_tree_depth: 7  (arXiv:2310.08419+2406.12609, depth=7 平衡 ASR/超时)
    l5_optimal_paths: 7     (arXiv:2407.01232 FIRST_SUCCESS 多路径)
"""

from __future__ import annotations

import asyncio
import atexit
import logging
import os
import shutil
import signal
import sys
from pathlib import Path
from typing import Any

# UTF-8 强制设置 (Windows GBK 终端兼容)
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from pipeline.config import ensure_output_dir, get_output_dir, parse_args, setup_environment
from pipeline.context import PipelineContext
from pipeline.utils.display import print_banner, print_phase, print_summary

logger = logging.getLogger(__name__)

# ── 进程终止处理 ──
# R6 HARD GATE: atexit 钩子清理临时缓存文件
# signal 处理器捕获 Ctrl+C / SIGTERM, 优雅取消所有 asyncio 任务并停止流水线

_PROJECT_ROOT = Path(__file__).resolve().parent


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


# 注册 atexit 钩子: 正常退出或异常退出时都会执行
atexit.register(cleanup_temp_files)


async def _cleanup_resources(ctx: PipelineContext) -> None:
    """生产级资源清理 — 关闭 Playwright 浏览器和 RateLimitedTarget 的 httpx.AsyncClient.

    在流水线结束时调用, 确保所有异步资源被正确释放。
    幂等设计: 所有清理操作都使用 try/except, 不会抛出异常。
    """
    # 1. 清理 Playwright 浏览器实例
    if getattr(ctx, "_playwright_instance", None):
        try:
            if ctx._browser_context:
                await ctx._browser_context.close()
            if ctx._browser:
                await ctx._browser.close()
            if ctx._playwright_instance:
                await ctx._playwright_instance.stop()
            logger.info("Playwright browser closed")
        except Exception as e:
            logger.debug("Playwright cleanup (non-fatal): %s", e)
        finally:
            ctx._playwright_instance = None
            ctx._browser = None
            ctx._browser_context = None

    # 2. 清理 RateLimitedTarget 的 httpx.AsyncClient
    for target_attr in ("objective_target", "adversarial_target", "scoring_target"):
        target = getattr(ctx, target_attr, None)
        if target is None:
            continue
        cleanup_fn = getattr(target, "cleanup", None)
        if cleanup_fn and asyncio.iscoroutinefunction(cleanup_fn):
            try:
                await cleanup_fn()
                logger.debug("%s cleanup completed", target_attr)
            except Exception as e:
                logger.debug("%s cleanup (non-fatal): %s", target_attr, e)


# 全局 asyncio 事件循环引用, 用于 signal 处理器中取消任务
_main_loop: asyncio.AbstractEventLoop | None = None


def _signal_handler(signum: int, frame: Any) -> None:
    """信号处理器: 捕获 SIGINT / SIGTERM, 优雅停止流水线.

    收到信号后:
        1. 取消事件循环中所有正在运行的任务
        2. 停止事件循环 (引发 KeyboardInterrupt 或 CancelledError)
        3. atexit 钩子自动清理临时文件

    Args:
        signum: 信号编号.
        frame: 当前栈帧 (未使用).
    """
    sig_name = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
    logger.warning("Received %s — shutting down pipeline...", sig_name)
    print_phase("ABORT", f"Received {sig_name}, stopping pipeline...")

    if _main_loop is not None and _main_loop.is_running():
        # 取消事件循环中所有正在运行的任务
        for task in asyncio.all_tasks(_main_loop):
            task.cancel()
        logger.info("All asyncio tasks cancelled.")
    else:
        # 没有运行中的事件循环, 直接退出
        sys.exit(130)  # 128 + SIGINT(2) = 130


# 注册信号处理器 (SIGINT=Ctrl+C, SIGTERM=kill 命令)
signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


def _is_attack_success(result: Any) -> bool:
    """判断攻击结果是否成功 (用于 Wilson Score 统计)。"""
    from pyrit.models import AttackOutcome

    outcome = getattr(result, "outcome", None)
    if outcome is not None:
        return outcome == AttackOutcome.SUCCESS

    last_score = getattr(result, "last_score", None)
    if last_score is not None:
        score_value = last_score.get_value() if hasattr(last_score, "get_value") else None
        return bool(score_value)

    return False


async def _cleanup_resources(ctx: PipelineContext) -> None:
    """生产级资源清理 — 关闭浏览器实例、httpx client 等。

    在流水线结束时调用, 确保所有异步资源被正确释放。
    幂等设计: 所有操作都包裹在 try/except 中, 不会抛出异常。
    """
    # 1. Playwright 浏览器清理
    if getattr(ctx, "_browser_context", None):
        try:
            await ctx._browser_context.close()
        except Exception as e:
            logger.debug("Browser context close failed (non-fatal): %s", e)

    if getattr(ctx, "_browser", None):
        try:
            await ctx._browser.close()
        except Exception as e:
            logger.debug("Browser close failed (non-fatal): %s", e)

    if getattr(ctx, "_playwright_instance", None):
        try:
            await ctx._playwright_instance.stop()
        except Exception as e:
            logger.debug("Playwright stop failed (non-fatal): %s", e)

    # 2. RateLimitedTarget httpx client 清理
    objective_target = getattr(ctx, "objective_target", None)
    if objective_target and hasattr(objective_target, "cleanup"):
        try:
            await objective_target.cleanup()
        except Exception as e:
            logger.debug("Objective target cleanup failed (non-fatal): %s", e)

    multi_turn_target = getattr(ctx, "multi_turn_target", None)
    if multi_turn_target and multi_turn_target is not objective_target:
        if hasattr(multi_turn_target, "cleanup"):
            try:
                await multi_turn_target.cleanup()
            except Exception as e:
                logger.debug("Multi-turn target cleanup failed (non-fatal): %s", e)

    # 3. 跨端口发现的目标清理
    extra_targets = getattr(ctx, "extra_objective_targets", {})
    for port, target in extra_targets.items():
        if hasattr(target, "cleanup"):
            try:
                await target.cleanup()
            except Exception as e:
                logger.debug("Port target %s cleanup failed (non-fatal): %s", port, e)

    logger.debug("Resource cleanup complete")


async def main(argv: list[str] | None = None) -> None:
    """主流水线入口。

    Args:
        argv: 可选的命令行参数列表。None 时使用 sys.argv (CLI 模式)。
              传入列表时用于编程式调用 (如 run_batch.py)。
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    print_banner()

    # 解析参数
    args = parse_args(argv)
    output_dir = get_output_dir(args)
    ensure_output_dir(output_dir)

    # L5 v52: 将 rate_limit 设置为环境变量, 供 _create_adversarial_target
    # 和 _create_scoring_target 读取 (它们无法直接访问 ctx.args)
    # 学术依据: PyRIT (arXiv:2407.01232) — 原生 max_requests_per_minute 限速
    rate_limit = getattr(args, "rate_limit", None)
    if rate_limit:
        os.environ["RATE_LIMIT"] = str(rate_limit)

    ctx = PipelineContext(args=args, output_dir=output_dir)
    ctx.scenario_result_id = getattr(args, "resume", None)

    # ── Web 漏洞策略路由 ──
    # web_vuln 策略使用独立的 Web 漏洞流水线
    if getattr(args, "strategy", None) == "web_vuln":
        from run_web_vuln import run_web_vuln_pipeline
        await run_web_vuln_pipeline()
        return
    if getattr(args, "strategy", None) == "comprehensive":
        from run_web_vuln import run_combined_pipeline
        await run_combined_pipeline()
        return

    # ── 初始化 PyRIT 环境 ──
    # 传入 output_dir, 自动将 SQLite 数据库放到 output_dir/db/pyrit.db
    print_phase("INIT", "Initializing PyRIT environment...")
    await setup_environment(output_dir)

    # ── Phase 1: 侦察 + 目标构建 ──
    print_phase("RECON", "Parsing Burp request & probing target...")

    # L5 v9: 注入认证状态 (如有配置)
    # 学术依据: OWASP LLM02 — 认证后的 API 端点可能有更大攻击面
    burp_request_path = args.burp_request
    if getattr(args, "auth_state", None):
        from pipeline.recon.auth_bridge import inject_auth_headers, load_auth_state
        auth_state = load_auth_state(args.auth_state)
        if auth_state:
            raw_request = Path(burp_request_path).read_text(encoding="utf-8", errors="replace")
            injected_request = inject_auth_headers(raw_request, auth_state)
            # 写入临时文件供 burp_parser 读取
            import tempfile
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, encoding="utf-8"
            ) as tmp:
                tmp.write(injected_request)
                burp_request_path = tmp.name
            logging.info("Auth state injected from %s", args.auth_state)

    from pipeline.recon.target_router import create_target

    ctx.args.burp_request = burp_request_path
    try:
        await create_target(ctx)
    except ConnectionError as e:
        logger.error("Pipeline aborted: %s", e)
        print_phase("ERROR", f"Target not available: {e}")
        print_phase("ERROR", "Please start the target service and retry.")
        sys.exit(1)
    except Exception as e:
        logger.error("Pipeline aborted during target setup: %s", e)
        print_phase("ERROR", f"Target setup failed: {e}")
        print_phase("ERROR", "Check the target service and Burp request file.")
        sys.exit(1)

    # 打印目标指纹
    if ctx.parsed_request:
        fp = ctx.parsed_request.target_fingerprint
        print_phase(
            "RECON",
            f"Target: {fp.get('app_type', 'Unknown')} | "
            f"Auth: {fp.get('auth_type', 'Unknown')} | "
            f"Path: {ctx.parsed_request.path}",
        )
        # 断点 #6: 记录侦察决策
        ctx.orchestration_log.append({
            "phase": "recon",
            "decision": "target_profiling",
            "input": {"burp_request": args.burp_request},
            "output": {
                "app_type": fp.get("app_type", "Unknown"),
                "auth_type": fp.get("auth_type", "Unknown"),
                "capabilities": fp.get("capabilities", ""),
                "model_family": fp.get("model_family", ""),
                "language": fp.get("language", ""),
                "secret_format": fp.get("secret_format", ""),
                "session_type": fp.get("session_type", ""),
                "tenant_id": fp.get("tenant_id", ""),
                "port_endpoints": fp.get("port_endpoints", []),
                "capability_confidence": fp.get("capability_confidence", {}),
                "capability_recommendations": fp.get("capability_recommendations", {}),
            },
            "reasoning": "三层探测 (被动指纹 + 主动能力 + 深度能力) 完成, "
            "结果用于指导种子/技术/Converter 选择。"
            "L5 v48: 认证状态管理 + 跨端口发现 + 置信度评分已集成",
        })

    # ── Phase 2: 武器化 ──
    print_phase("ARM", "Loading Agent attack seeds & building converter chains...")
    from pipeline.arm.converter_chains import build_converter_map
    from pipeline.arm.seed_ranker import load_seeds
    from pipeline.arm.technique_picker import filter_by_adversarial, select_techniques

    # 从目标指纹提取语言 + 能力 + 模型族
    target_language = None
    target_capabilities = None
    target_model_family = None
    if ctx.parsed_request:
        fp = ctx.parsed_request.target_fingerprint
        target_language = fp.get("language")
        # 断点 #1: 将能力指纹传递给 load_seeds, 自动追加定向种子
        target_capabilities = fp.get("capabilities")
        target_model_family = fp.get("model_family")

    ctx.seeds = load_seeds(
        args.seeds,
        args.max_seeds or 25,
        target_language=target_language,
        enable_dos=getattr(args, "enable_dos", False),
        capabilities=target_capabilities,
        model_family=target_model_family,
    )

    # 断点 #6: 记录种子选择决策
    ctx.orchestration_log.append({
        "phase": "arm",
        "decision": "seed_selection",
        "input": {
            "seed_files": args.seeds,
            "capabilities": target_capabilities or "",
            "model_family": target_model_family or "",
            "language": target_language or "",
        },
        "output": {"seed_count": len(ctx.seeds)},
        "reasoning": f"基于能力指纹自动追加定向种子 "
        f"(capabilities={target_capabilities or 'none'})",
    })

    # L5 v27: 运行时种子自动扩充 (AutoDAN 风格, 异步并行)
    # 学术依据: Liu et al. (arXiv:2310.04451) — 自动化种子扩充提升 ASR 1.5-2x
    # L5 v27: 修复 — 原版未 await convert_async, 现在使用异步版本
    if getattr(args, "auto_seeds", False) and ctx.converter_target:
        from pipeline.arm.seed_ranker import auto_generate_seeds_async
        # 从 SSOT (config/defaults.yaml) 读取扩充因子, 硬编码 3 仅作 fallback
        # arXiv:2310.04451 — AutoDAN 3x 扩充 ASR 1.5-2x
        _expansion_factor = getattr(args, "auto_seed_expansion_factor", 3)
        if not isinstance(_expansion_factor, int) or _expansion_factor < 1:
            _expansion_factor = 3
        ctx.seeds = await auto_generate_seeds_async(
            ctx.seeds,
            converter_target=ctx.converter_target,
            expansion_factor=_expansion_factor,
        )
        print_phase("ARM", f"Auto-expanded to {len(ctx.seeds)} seeds ({_expansion_factor}x expansion, L5 v27 async)")

    # 根据是否有 adversarial target 过滤技术
    has_adversarial = ctx.adversarial_target is not None
    ctx.techniques = select_techniques(args.techniques, has_adversarial=has_adversarial)
    ctx.techniques = filter_by_adversarial(ctx.techniques, has_adversarial)

    # 断点 #2: 基于能力指纹自动追加定向攻击技术
    from pipeline.arm.technique_picker import augment_techniques_by_capability
    ctx.techniques = augment_techniques_by_capability(ctx.techniques, target_capabilities)

    # 断点 #6: 记录技术选择决策
    ctx.orchestration_log.append({
        "phase": "arm",
        "decision": "technique_selection",
        "input": {
            "mode": args.techniques,
            "has_adversarial": has_adversarial,
            "capabilities": target_capabilities or "",
        },
        "output": {"techniques": ctx.techniques},
        "reasoning": "基于能力指纹追加定向技术 "
        f"(capabilities={target_capabilities or 'none'})",
    })

    # L5 v35: 使用 l5_optimal 候选列表, executor 多路径独立执行 (不串联)
    # 学术依据: Wei et al. (arXiv:2307.15043) — 串联 >2 层 ASR 急剧下降
    #           PyRIT SequentialAttack FIRST_SUCCESS (arXiv:2407.01232)
    if args.converters == "none":
        chain_names = []
    elif args.converters == "auto":
        chain_names = ["l5_optimal"]
    else:
        chain_names = args.converters.split(",")

    # 断点 #3: 传入 model_family, 自动按先验 ASR 排序 converter 候选列表
    ctx.converter_map = build_converter_map(
        technique_names=ctx.techniques,
        chain_names=chain_names,
        converter_target=ctx.converter_target,
        model_family=target_model_family,
    )

    # 断点 #6: 记录 Converter 选择决策
    ctx.orchestration_log.append({
        "phase": "arm",
        "decision": "converter_selection",
        "input": {
            "converters": args.converters,
            "model_family": target_model_family or "",
        },
        "output": {
            "converter_count": sum(len(v) for v in ctx.converter_map.values()),
        },
        "reasoning": f"基于模型族先验 ASR 排序 converter "
        f"(model_family={target_model_family or 'default'})",
    })

    print_phase(
        "ARM",
        f"Loaded {len(ctx.seeds)} seeds, {len(ctx.techniques)} techniques, "
        f"{sum(len(v) for v in ctx.converter_map.values())} converters",
    )

    # ── Phase 3: 攻击执行 ──
    print_phase("STRIKE", "Executing single-turn attacks via HTTPTarget...")
    from pipeline.strike.escalation import check_and_escalate

    # L5 v38: PyRIT 原生 TextAdaptive 场景执行路径
    # 学术依据: PyRIT (arXiv:2407.01232) — ε-贪心自适应技术选择
    # 当 techniques == "adaptive" 时使用 TextAdaptive 原生场景,
    # 否则回退到 executor.py 的 v35 多路径独立执行
    if args.techniques == "adaptive":
        print_phase("STRIKE", "Using PyRIT native TextAdaptive scenario (ε-greedy)...")
        from pipeline.strike.adaptive_executor import execute_text_adaptive
        try:
            await execute_text_adaptive(ctx)
        except Exception as e:
            logger.error("TextAdaptive execution failed: %s — falling back to v35 executor", e)
            from pipeline.strike.executor import execute_attacks
            try:
                await execute_attacks(ctx)
            except Exception as e2:
                logger.error("Single-turn attacks also failed: %s — proceeding with partial results", e2)
                print_phase("STRIKE", f"Single-turn attacks partially failed: {e2}")
    else:
        from pipeline.strike.executor import execute_attacks
        try:
            await execute_attacks(ctx)
        except Exception as e:
            logger.error("Single-turn attacks failed: %s — proceeding with partial results", e)
            print_phase("STRIKE", f"Single-turn attacks partially failed: {e}")

    # 检查是否需要升级
    # L5 v32: 尊重策略预设的 escalation 标志
    # escalation=True 时才执行多轮升级 (如 quick_scan, full_offensive)
    # escalation=False 时跳过 (如 stealth_bypass, multi_turn_deep)
    should_escalate = getattr(ctx.args, 'escalation', True)
    if should_escalate:
        print_phase("STRIKE", "Checking ASR & escalating to multi-turn if needed...")
        try:
            await check_and_escalate(ctx, ctx.attack_results)
        except Exception as e:
            logger.error("Escalation failed: %s — proceeding with single-turn results", e)
            print_phase("STRIKE", f"Escalation partially failed: {e}")
    else:
        print_phase("STRIKE", "Escalation disabled by strategy preset, skipping...")

    # ── Phase 4: 评分 ──
    print_phase("ASSESS", "Computing ASR & scoring results...")
    from pipeline.assess.asr_tracker import (
        collect_dual_judge_stats,
        compute_asr,
        compute_overall_asr,
        compute_wilson_score_interval,
        precompute_outcomes_async,
        save_asr_history,
    )

    # L5 v34: Post-hoc Dual Judge — 对所有结果做双 Judge 评分
    # v34 攻击执行时不使用 LLM 评分器 (空 AttackScoringConfig),
    # 所有结果 outcome 默认为 undecided, 双 Judge 统一评分。
    # 学术依据:
    #   - Zhang et al. (arXiv:2308.07920) — 双 Judge 交叉验证
    #   - Mazeika et al. (arXiv:2402.04249) — HarmBench 评分基准
    # 对抗性评估: 假阳性 (不可复现的 PoC) 代价远高于假阴性, 双 Judge + 仲裁确保严格。
    # Rule 11 integration: reset_stats 策略 —
    # 如果升级链已执行 (should_escalate=True), 升级中已用 reset_stats=False 做了增量评分,
    # ASSESS 阶段继续用 reset_stats=False 补充评分, 保留累积统计;
    # 如果升级未执行 (should_escalate=False), 这是首次评分, 需要 reset_stats=True 重置统计。
    _assess_reset_stats = not should_escalate
    try:
        await precompute_outcomes_async(ctx.attack_results, score_all=False, reset_stats=_assess_reset_stats)
    except Exception as e:
        logger.error("Post-hoc scoring failed: %s — proceeding with un-scored results", e)

    ctx.asr_per_technique = compute_asr(ctx.attack_results)
    ctx.overall_asr = compute_overall_asr(ctx.asr_per_technique)
    save_asr_history(ctx.asr_per_technique, attack_results=ctx.attack_results)

    # 断点 #4: 运行后更新 asr_priors.yaml (EMA, α=0.3)
    # 实现跨目标知识迁移: 本次 ASR 融合到先验中
    if ctx.parsed_request:
        model_family = ctx.parsed_request.target_fingerprint.get("model_family")
        if model_family:
            from pipeline.arm.seed_ranker import update_asr_priors
            update_asr_priors(model_family, ctx.asr_per_technique)

    # L5 v7: Wilson Score 置信区间
    # Rule 11 integration: 使用 _get_outcome 而非 _is_success, 与 compute_asr 保持一致
    # _get_outcome 返回 "success"/"failure"/"undecided", undecided 不计入分母 (与 ASR 计算一致)
    from pipeline.assess.asr_stats import _get_outcome as _get_attack_outcome
    total_successes = sum(
        1 for results in ctx.attack_results.values()
        for r in results
        if _get_attack_outcome(r) == "success"
    )
    # Rule 11 integration: Wilson CI 分母使用 total_decided (排除 undecided), 与 ASR 计算一致
    total_decided = sum(
        1 for results in ctx.attack_results.values()
        for r in results
        if _get_attack_outcome(r) in ("success", "failure")
    )
    wilson_lower, wilson_upper = compute_wilson_score_interval(
        total_successes, total_decided
    )
    logging.info(
        "ASR Wilson Score 95%% CI: [%.1f%%, %.1f%%] (point estimate: %.1f%%)",
        wilson_lower, wilson_upper, ctx.overall_asr,
    )
    ctx.wilson_ci = (wilson_lower, wilson_upper)

    # L5 v7: 双 Judge 统计
    ctx.dual_judge_stats = collect_dual_judge_stats(ctx)

    # L5 v29: Cohen's Kappa — 双 Judge 一致性度量 (替代简单 agreement_rate)
    from pipeline.assess.asr_tracker import compute_cohens_kappa
    if ctx.dual_judge_stats:
        kappa = compute_cohens_kappa(
            ctx.dual_judge_stats.get("agreements", 0),
            ctx.dual_judge_stats.get("disagreements", 0),
        )
        ctx.dual_judge_stats["cohens_kappa"] = kappa
        logging.info(
            "Dual Judge: total=%d, dual_invoked=%d (%.1f%%), "
            "agreements=%d, disagreements=%d, "
            "agreement_rate=%.1f%%, Cohen's Kappa=%.3f",
            ctx.dual_judge_stats.get("total_scored", 0),
            ctx.dual_judge_stats.get("dual_judge_invoked", 0),
            ctx.dual_judge_stats.get("dual_judge_rate", 0.0),
            ctx.dual_judge_stats.get("agreements", 0),
            ctx.dual_judge_stats.get("disagreements", 0),
            ctx.dual_judge_stats.get("agreement_rate", 0.0),
            kappa,
        )
    else:
        logging.info("Dual Judge: no stats collected")

    # ── Phase 5: 报告 ──
    print_phase("REPORT", "Collecting evidence & generating security report...")
    from pipeline.report.evidence import EvidenceCollector
    from pipeline.report.generator import generate_report

    # 提取目标指纹
    target_fingerprint = {}
    if ctx.parsed_request:
        target_fingerprint = ctx.parsed_request.target_fingerprint

    collector = EvidenceCollector(
        target_model=ctx.model_name,
        target_fingerprint=target_fingerprint,
    )
    evidence = collector.collect(
        attack_results=ctx.attack_results,
        scenario_result_id=ctx.scenario_result_id,
        asr_per_technique=ctx.asr_per_technique,
        overall_asr=ctx.overall_asr,
    )

    # L5 v8: 注入双 Judge 统计到 evidence
    if hasattr(ctx, "dual_judge_stats") and ctx.dual_judge_stats:
        evidence.dual_judge_stats = ctx.dual_judge_stats

    # L5 v29: 注入 Wilson CI + Cohen's Kappa 到 evidence
    evidence.wilson_ci = getattr(ctx, "wilson_ci", (0.0, 0.0))
    evidence.cohens_kappa = ctx.dual_judge_stats.get("cohens_kappa", 0.0) if ctx.dual_judge_stats else 0.0

    # 断点 #6: 注入编排决策日志到 evidence (报告展示)
    evidence.orchestration_log = ctx.orchestration_log

    report_path = await generate_report(ctx, evidence, output_dir)

    # ── 生产级资源清理 ──
    # 关闭 Playwright 浏览器实例 (如果使用了 --browser-url 模式)
    # 以及 RateLimitedTarget 包装的 httpx.AsyncClient
    await _cleanup_resources(ctx)

    # ── 完成 ──
    print_summary(
        total_attacks=evidence.total_attacks,
        successful_attacks=evidence.successful_attacks,
        overall_asr=ctx.overall_asr,
        report_path=str(report_path),
    )


if __name__ == "__main__":
    _main_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_main_loop)
    try:
        _main_loop.run_until_complete(main())
    except (KeyboardInterrupt, asyncio.CancelledError):
        print_phase("ABORT", "Pipeline interrupted by user (Ctrl+C).")
        logger.warning("Pipeline interrupted by user.")
    finally:
        # 取消所有剩余任务
        pending = asyncio.all_tasks(_main_loop)
        for task in pending:
            task.cancel()
        if pending:
            _main_loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        _main_loop.close()
        # atexit 钩子会自动执行 cleanup_temp_files()
