"""攻击链路编排器 — 6 阶段完整链路 (recon→arm→strike→escalate→assess→report)。

v57 重构: 从 main.py 提取核心编排逻辑, 实现关注点分离。

阶段对应模块包:
    ① recon     (recon/burp_parser.py + recon/target_router.py)
    ② arm       (arm/seed_ranker.py + arm/converter_presets.py + arm/technique_picker.py)
    ③ strike    (strike/executor.py)
    ④ escalate  (strike/escalation.py + strike/escalation_chain.py)
    ⑤ assess    (assess/scorer.py + assess/asr_tracker.py + assess/asr_stats.py)
    ⑥ report    (report/evidence.py + report/generator.py)
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)

# SIGINT/SIGTERM 信号处理
_signal_fired: bool = False
# 全局 ctx 引用 — 供信号处理器触发资源清理
_global_ctx: Any = None


def _signal_handler(signum: int, frame) -> None:
    """SIGINT/SIGTERM 信号处理器 — 优雅退出 + 资源清理。

    生产级行为:
        1. 第一次信号: 标记中断, 由 event loop 自然退出
        2. 第二次信号: 强制退出 (os._exit)

    注意: 同步信号处理器中不能直接 await async cleanup,
    但可以设置标志让 event loop 在下一个 await 点自然退出,
    然后由 try/finally 块执行 cleanup_resources。
    """
    global _signal_fired
    if _signal_fired:
        # 重复信号: 直接退出, 不等待
        os._exit(130)
    _signal_fired = True
    print("\n[!] 收到中断信号, 正在退出... (再按一次 Ctrl+C 强制退出)", file=sys.stderr)
    # 抛出 KeyboardInterrupt 让 asyncio.run 自然退出
    raise KeyboardInterrupt


async def run(argv: list[str] | None = None) -> None:
    """主流程: 6 阶段完成一次完整攻击链路。

    阶段对应模块包 (--stage 控制退出点):
        ① recon     (recon/burp_parser.py + recon/target_router.py)
        ② arm       (arm/seed_ranker.py + arm/converter_presets.py + arm/technique_picker.py)
        ③ strike    (strike/executor.py)
        ④ escalate  (strike/escalation.py + strike/escalation_chain.py)
        ⑤ assess    (assess/scorer.py + assess/asr_tracker.py + assess/asr_stats.py)
        ⑥ report    (report/evidence.py + report/generator.py)

    多 endpoint 支持 (arXiv:2302.12173 Greshake — 逐个深度攻击):
        不指定 --burp → 自动扫描 data/burp/*.txt 全部文件 (默认多端点模式)
        --burp MM_05 → 指定单个 endpoint (仍走多端点路径, 确保统一目录结构)
        --burp MM_05 --burp MM_03 --burp MM_08 → 指定多个 endpoint
        → 优先级排序: 按能力指纹排序 (MCP > function_calling > RAG > workflow > chat)
        → 对每个 endpoint 执行完整 6 阶段深度攻击链路
        → 最终汇总联合 ASR (arXiv:2310.08419 — 1 - ∏(1 - ASRᵢ))
    """
    from pipeline.cleanup import cleanup_resources, flush_and_close_logging
    from pipeline.logging_config import configure_logging, switch_log_file

    # ── 日志配置: basicConfig 初始化 root (终端 WARNING, 文件 FileHandler 后续添加) ──
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # 自身包: 提升到 INFO (写入文件)
    for _pkg in ("core", "recon", "arm", "strike", "assess", "report", "pipeline"):
        logging.getLogger(_pkg).setLevel(logging.INFO)
    # 压制噪音库
    logging.getLogger("alembic").setLevel(logging.WARNING)
    logging.getLogger("pyrit").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    # 静默已知第三方警告
    import warnings
    warnings.filterwarnings("ignore", category=SyntaxWarning, module="confusables")

    # ── 信号处理 ──
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    from core.config import ensure_output_dir, get_output_dir, parse_args, setup_environment
    from core.context import PipelineContext, apply_relaxed_adversarial_schema
    from utils.display import (
        _C_BOLD,
        _C_RESET,
        print_banner,
        print_error,
        print_joint_asr_card,
        print_phase,
        print_status,
    )

    print_banner()

    # ── 解析参数 + 输出目录 ──
    args = parse_args(argv)
    output_dir = get_output_dir(args)
    ensure_output_dir(output_dir)

    # ── 配置文件日志 + --verbose 终端控制 ──
    configure_logging(output_dir, getattr(args, "verbose", False))

    # rate_limit 环境变量 (供 target_router 中的 _create_adversarial_target 读取)
    rate_limit = getattr(args, "rate_limit", None)
    if rate_limit:
        os.environ["RATE_LIMIT"] = str(rate_limit)

    # ── 多 endpoint 检测 ──
    burp_list: list[str] = getattr(args, "_burp_list", None)
    if burp_list is None:
        burp_val = args.burp
        if isinstance(burp_val, list):
            burp_list = burp_val
        else:
            burp_list = [burp_val] if burp_val else ["request"]

    # 默认多端点模式
    logger.info(
        "Multi-endpoint mode: %d endpoint(s) — %s",
        len(burp_list),
        ", ".join(Path(b).stem for b in burp_list),
    )

    ctx = PipelineContext(args=args, output_dir=output_dir)
    ctx.scenario_result_id = getattr(args, "resume", None)

    # ── 增量借鉴: 设置运行标签到 ctx ──
    ctx.memory_labels = getattr(args, "memory_labels_parsed", {}) or {}

    # 生产级: 设置全局 ctx 引用
    global _global_ctx
    _global_ctx = ctx

    # 生产级: try/finally 确保信号中断时也执行资源清理
    try:
        # ── INIT: 初始化 PyRIT 环境 + Relaxed Adversarial Schema ──
        print_phase("INIT", "初始化 PyRIT 环境...")
        apply_relaxed_adversarial_schema()
        await setup_environment(output_dir)
        print_status("INIT", "DONE", f"Output: {output_dir}", ok=True)

        # ── 增量借鉴: 将运行标签写入 CentralMemory ──
        if ctx.memory_labels:
            try:
                from pyrit.memory import CentralMemory
                memory = CentralMemory.get_memory_instance()
                if hasattr(memory, "set_labels"):
                    memory.set_labels(ctx.memory_labels)
                else:
                    os.environ["PYRIT_MEMORY_LABELS"] = str(ctx.memory_labels)
                logger.info("Memory labels set: %s", ctx.memory_labels)
            except Exception as e:
                logger.debug("Failed to set memory labels in CentralMemory: %s", e)
                os.environ["PYRIT_MEMORY_LABELS"] = str(ctx.memory_labels)

        # ── 增量借鉴: 动态注册 Initializer (--add-initializer) ──
        initializer_specs = getattr(args, "initializer_specs", None)
        if initializer_specs:
            from core.initializer_registry import register_initializers_async
            await register_initializers_async(initializer_specs, ctx)
            logger.info("Registered %d dynamic initializer(s)", len(initializer_specs))

        # ═══════════════════════════════════════════════════════════════════════════
        # 多 endpoint 外层循环 (arXiv:2302.12173 — 逐个深度攻击)
        # ═══════════════════════════════════════════════════════════════════════════

        # 非 Burp 路径 (LiteLLM/OpenAI API/Browser) 不走多 endpoint 循环
        _non_burp_mode = (
            getattr(args, "litellm_model", None) or os.environ.get("LITELLM_MODEL")
            or (getattr(args, "target_api_endpoint", None) and getattr(args, "target_api_key", None))
            or getattr(args, "browser_url", None)
        )

        if _non_burp_mode:
            # 非 Burp 路径: 直接走单次执行逻辑
            ctx.args.burp = burp_list[0] if burp_list else "request"
            await _run_single_endpoint(ctx, args, output_dir, argv)
            await cleanup_resources(ctx)
            return

        # ── 优先级排序: 按能力指纹排序 endpoint ──
        from recon.endpoint_sorter import sort_endpoints_by_priority
        sorted_endpoints = sort_endpoints_by_priority(burp_list)

        # 精简合并: 一段输出包含 RECON phase + data/burp/ 文件名 + 排序结果
        print()
        print(f"{_C_BOLD}{'═' * 60}{_C_RESET}")
        print(f"{_C_BOLD}  ► [RECON] Endpoint 优先级排序 (能力指纹){_C_RESET}")
        _files_str = ", ".join(Path(ep['burp_path']).name for ep in sorted_endpoints)
        print(f"  data/burp/ — {_files_str}")
        print(f"{_C_BOLD}{'═' * 60}{_C_RESET}")
        for i, ep in enumerate(sorted_endpoints):
            caps_str = ", ".join(sorted(ep["capabilities"])) if ep["capabilities"] else "chat"
            print(
                f"  {i + 1}. {_C_BOLD}{ep['burp_name']}{_C_RESET} "
                f"(priority={ep['priority_score']}, caps={caps_str})"
            )

        multi_endpoint_results: list[dict[str, Any]] = []

        for idx, ep_info in enumerate(sorted_endpoints):
            burp_path = ep_info["burp_path"]
            burp_name = ep_info["burp_name"]
            ctx._current_endpoint_idx = idx

            print()
            print(f"{_C_BOLD}{'═' * 60}{_C_RESET}")
            print(f"{_C_BOLD}  Endpoint {idx + 1}/{len(burp_list)}: {burp_name}{_C_RESET}")
            print(f"{_C_BOLD}{'═' * 60}{_C_RESET}")

            # 为每个 endpoint 创建独立的子输出目录
            ep_output_dir = output_dir / f"endpoint_{idx + 1}_{burp_name}"
            ensure_output_dir(ep_output_dir)
            ctx.output_dir = ep_output_dir

            # 切换文件日志到当前 endpoint 的子目录
            switch_log_file(ep_output_dir)

            # 独立初始化 PyRIT DB
            await setup_environment(ep_output_dir)

            # R8 §8.3: 为每个 endpoint 重新设置 memory labels
            if ctx.memory_labels:
                try:
                    from pyrit.memory import CentralMemory
                    _ep_memory = CentralMemory.get_memory_instance()
                    if hasattr(_ep_memory, "set_labels"):
                        _ep_memory.set_labels(ctx.memory_labels)
                    logger.debug("Memory labels re-set for endpoint %s", burp_name)
                except Exception as e:
                    logger.debug("Failed to re-set memory labels for endpoint %s: %s", burp_name, e)

            # 设置当前 endpoint 的 burp 路径
            ctx.args.burp = burp_path

            # 重置 ctx 状态
            _reset_endpoint_state(ctx)

            try:
                ep_result = await _run_single_endpoint_to_result(
                    ctx, args, ep_output_dir, burp_name,
                )
                multi_endpoint_results.append(ep_result)
            except ConnectionError as e:
                logger.error("Endpoint %s 不可用: %s", burp_name, e)
                print_error(
                    f"Endpoint {burp_name} 不可用 (连接失败)\n"
                    f"  原因: {e}\n"
                    f"  建议: 检查目标服务是否启动, 端口是否开放, 认证是否有效"
                )
                await cleanup_resources(ctx, exclude_shared=True)
                multi_endpoint_results.append({
                    "burp_name": burp_name,
                    "endpoint": "",
                    "overall_asr": 0.0,
                    "total_attacks": 0,
                    "successful_attacks": 0,
                    "error": str(e),
                })
            except Exception as e:
                logger.error("Endpoint %s 攻击失败: %s", burp_name, e, exc_info=True)
                print_error(
                    f"Endpoint {burp_name} 攻击失败\n"
                    f"  错误类型: {type(e).__name__}\n"
                    f"  原因: {e}\n"
                    f"  该 endpoint 将被跳过, 继续处理下一个 endpoint"
                )
                await cleanup_resources(ctx, exclude_shared=True)
                multi_endpoint_results.append({
                    "burp_name": burp_name,
                    "endpoint": "",
                    "overall_asr": ctx.overall_asr,
                    "total_attacks": sum(len(v) for v in ctx.attack_results.values()),
                    "successful_attacks": sum(
                        1 for results in ctx.attack_results.values()
                        for r in results
                        if _get_result_outcome(r) == "success"
                    ),
                    "error": str(e),
                })

        # ═══════════════════════════════════════════════════════════════════════════
        # 联合 ASR 统计 (arXiv:2310.08419 — Chao et al.)
        # Joint ASR = 1 - ∏(1 - ASRᵢ)
        # ═══════════════════════════════════════════════════════════════════════════

        # 断点修复: 切换回顶层 pipeline.log
        switch_log_file(output_dir)

        from assess.joint_asr import build_joint_summary, save_joint_report

        joint_summary = build_joint_summary(multi_endpoint_results)
        joint_report_path = save_joint_report(joint_summary, output_dir)

        print()
        print(f"{_C_BOLD}{'═' * 60}{_C_RESET}")
        print(f"{_C_BOLD}  Joint ASR Summary — Multi-Endpoint Deep Attack{_C_RESET}")
        print(f"{_C_BOLD}{'═' * 60}{_C_RESET}")

        print_joint_asr_card(
            joint_asr=joint_summary["joint_asr"],
            total_endpoints=joint_summary["total_endpoints"],
            total_attacks=joint_summary["total_attacks"],
            total_successes=joint_summary["total_successes"],
            endpoint_summaries=joint_summary["endpoint_summaries"],
            report_path=str(joint_report_path),
        )

        print_status("JOINT", "DONE", f"Joint ASR = {joint_summary['joint_asr']:.1f}%", ok=True)

        # 资源清理
        await cleanup_resources(ctx)

    except KeyboardInterrupt:
        # 信号中断: 确保资源清理后退出
        logger.info("收到中断信号, 执行资源清理...")
        try:
            await cleanup_resources(ctx)
        except Exception:
            pass
        raise
    finally:
        # 最终保障: 如果上面所有路径都没有执行 cleanup
        try:
            _has_residue = (
                ctx.objective_target is not None
                or ctx.adversarial_target is not None
                or ctx.scoring_target is not None
                or ctx.converter_target is not None
                or getattr(ctx, "_browser", None) is not None
                or getattr(ctx, "_playwright_instance", None) is not None
            )
            if _has_residue:
                await cleanup_resources(ctx)
        except Exception:
            pass
        # R-02 修复: 确保所有 FileHandler flush + close
        flush_and_close_logging()


def _reset_endpoint_state(ctx: Any) -> None:
    """重置 ctx 状态 (每个 endpoint 独立攻击)。

    注意: adversarial_target / scoring_target / converter_target 不重置 —
    它们是攻击者自己的 LLM, 可在 endpoint 间复用, 循环结束后统一清理
    """
    ctx.parsed_request = None
    ctx.objective_target = None
    ctx.multi_turn_target = None
    ctx.model_name = ""
    ctx.seeds = []
    ctx.techniques = []
    ctx.converter_map = {}
    ctx.attack_results = {}
    ctx.asr_per_technique = {}
    ctx.overall_asr = 0.0
    ctx.wilson_ci = (0.0, 0.0)
    ctx.dual_judge_stats = {}
    ctx.orchestration_log = []
    ctx.extra_objective_targets = {}
    ctx.scorer = None
    ctx._mcp_dynamic_seeds = []
    ctx.scenario_result_id = getattr(ctx.args, "resume", None) if hasattr(ctx, "args") else None
    ctx.scenario_result = None
    # 重置 assess 阶段的全局统计计数器
    try:
        from assess.asr_stats import _reset_dual_judge_stats
        _reset_dual_judge_stats()
    except Exception:
        pass
    try:
        from assess.judge_manager import reset_t0_stats
        reset_t0_stats()
    except Exception:
        pass


async def _run_single_endpoint_to_result(
    ctx: PipelineContext,
    args: Any,
    ep_output_dir: Path,
    burp_name: str,
) -> dict[str, Any]:
    """对单个 endpoint 执行完整 6 阶段攻击链路, 返回结果摘要。

    学术依据: Greshake et al. (arXiv:2302.12173) — 逐个深度攻击

    Args:
        ctx: 流水线上下文 (已重置状态)。
        args: CLI 参数。
        ep_output_dir: 该 endpoint 的独立输出目录。
        burp_name: endpoint 名称 (用于报告)。

    Returns:
        该 endpoint 的攻击结果摘要字典。
    """
    # 执行单 endpoint 完整链路
    await _run_single_endpoint(ctx, args, ep_output_dir, None)

    # 提取结果摘要
    endpoint_str = ""
    if ctx.parsed_request:
        scheme = "https" if ctx.parsed_request.use_tls else "http"
        endpoint_str = f"{scheme}://{ctx.parsed_request.host}{ctx.parsed_request.path}"

    fp = {}
    if ctx.parsed_request:
        fp = ctx.parsed_request.target_fingerprint

    return {
        "burp_name": burp_name,
        "endpoint": endpoint_str,
        "overall_asr": ctx.overall_asr,
        "total_attacks": sum(len(v) for v in ctx.attack_results.values()),
        "successful_attacks": sum(
            1 for results in ctx.attack_results.values()
            for r in results
            if _get_result_outcome(r) == "success"
        ),
        "asr_per_technique": ctx.asr_per_technique,
        "wilson_ci": getattr(ctx, "wilson_ci", (0.0, 0.0)),
        "capabilities": fp.get("capabilities", ""),
        "model_family": fp.get("model_family", ""),
    }


def _get_result_outcome(result: Any) -> str:
    """获取攻击结果的 outcome (内联简版, 避免循环导入)。"""
    from assess.asr_stats import _get_outcome
    return _get_outcome(result)


async def _run_single_endpoint(
    ctx: PipelineContext,
    args: Any,
    output_dir: Path,
    argv: list[str] | None,
) -> None:
    """对单个 endpoint 执行完整 6 阶段攻击链路。

    这是原有 run() 函数的核心逻辑, 提取为独立函数以支持多 endpoint 循环。
    学术依据: PyRIT (arXiv:2407.01232) — SequentialAttack + 完整攻击链路

    Args:
        ctx: 流水线上下文。
        args: CLI 参数。
        output_dir: 输出目录。
        argv: 原始参数 (未使用, 保留兼容)。
    """
    from pipeline.cleanup import cleanup_resources
    from pipeline.logging_config import switch_log_file

    # 导入 display 函数
    from utils.display import (
        print_arm_card,
        print_assess_card,
        print_error,
        print_escalate_report_async,
        print_phase,
        print_recon_card,
        print_report_card,
        print_status,
        print_strike_report_async,
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # ① ② Burp 拦截 → 侦察: 解析 HTTP 请求 → 探测能力 → 构建 HTTPTarget
    # ═══════════════════════════════════════════════════════════════════════════
    print_phase("RECON", "解析 HTTP 请求 & 构建攻击目标...")
    from recon.target_router import create_target

    try:
        await create_target(ctx)
    except ConnectionError as e:
        logger.error("目标不可用: %s", e)
        print_error(f"目标不可用: {e}\n请启动目标服务后重试。")
        raise
    except Exception as e:
        logger.error("目标构建失败: %s", e)
        print_error(f"目标构建失败: {e}")
        raise

    # 打印侦察结果卡片
    _is_recon_only = getattr(args, "stage", None) == "recon"
    if ctx.parsed_request and not _is_recon_only:
        print_recon_card(ctx)

    # 编排日志: 记录侦察决策
    _log_recon_decision(ctx, args)

    # ── --stage recon: 只执行侦察, 输出报告后退出 ──
    if getattr(args, "stage", None) == "recon":
        from recon.recon_report import print_recon_report
        if ctx.parsed_request:
            print_recon_report(ctx.parsed_request, output_dir=output_dir)
        print_status("RECON", "DONE", "侦察阶段完成", ok=True)
        await cleanup_resources(ctx, exclude_shared=True)
        return

    # ═══════════════════════════════════════════════════════════════════════════
    # ②.5 Burp + Scores + Seeds 协同分析 (RECON → SYNERGY → ARM 数据桥接)
    # ═══════════════════════════════════════════════════════════════════════════
    _synergy_enabled_flag = getattr(args, "synergy", True)
    if _synergy_enabled_flag and ctx.parsed_request:
        print_phase("SYNERGY", "Burp + Scores + Seeds 协同分析...")
        try:
            from data.synergy_orchestrator import SynergyOrchestrator

            _burp_raw_content = None
            _burp_file_path = Path(ctx.args.burp)
            if not _burp_file_path.is_absolute():
                _burp_file_path = Path("data/burp") / _burp_file_path
            if not str(_burp_file_path).endswith(".txt"):
                _burp_file_path = _burp_file_path.with_suffix(".txt")
            if _burp_file_path.exists():
                _burp_raw_content = _burp_file_path.read_text(encoding="utf-8", errors="ignore")

            _orchestrator = SynergyOrchestrator()
            _syn_cfg = _orchestrator.build_synergy_config(
                burp_profile_name=ctx.args.burp.replace(".txt", ""),
                burp_content=_burp_raw_content,
            )
            ctx.synergy_config = _syn_cfg
            logger.info("Synergy config: %s", _syn_cfg.summary())

            if _syn_cfg.synergy_enabled and _syn_cfg.seed_names:
                _synergy_seed_value = ",".join(_syn_cfg.seed_files)
                logger.info("Synergy seed override: %s → load_seeds()", _synergy_seed_value)
                setattr(args, "seeds", _synergy_seed_value)
                print_status(
                    "SYNERGY", "SEEDS",
                    f"协同选取 {_syn_cfg.seed_files.__len__()} 个种子 "
                    f"(surface={_syn_cfg.attack_surface}, conf={_syn_cfg.confidence:.2f})",
                    ok=True,
                )
            else:
                logger.info("Synergy fallback: 使用默认种子配置")
                print_status("SYNERGY", "FALLBACK", "无匹配种子, 使用默认配置")

            if _syn_cfg.scorer_name:
                logger.info("Synergy scorer selected: %s", _syn_cfg.scorer_name)
                setattr(args, "synergy_scorer", _syn_cfg.scorer_name)
        except Exception as e:
            logger.warning("Synergy analysis failed (non-fatal, 回退默认): %s", e)
            ctx.synergy_config = None

    # ═══════════════════════════════════════════════════════════════════════════
    # ②.6 目标感知自动 L4 优化 (SYNERGY → 升级路径决策)
    # ═══════════════════════════════════════════════════════════════════════════
    _apply_auto_l4_optimization(ctx, args)

    # ═══════════════════════════════════════════════════════════════════════════
    # ③ 种子选取: 加载 YAML 种子 → ASR 排序 → 能力自适应
    # ═══════════════════════════════════════════════════════════════════════════
    print_phase("ARM", "种子选取 & ASR 排序...")
    from arm.converter_presets import build_converter_map
    from arm.seed_ranker import load_seeds
    from arm.technique_picker import augment_techniques_by_capability, filter_by_adversarial, select_techniques

    # 从目标指纹提取语言 + 能力 + 模型族
    target_language = None
    target_capabilities = None
    target_model_family = None
    if ctx.parsed_request:
        fp = ctx.parsed_request.target_fingerprint
        target_language = fp.get("language")
        target_capabilities = fp.get("capabilities")
        target_model_family = fp.get("model_family")
        if not target_model_family and fp.get("burp_model_name"):
            from recon.capability_detector import _detect_model_family
            inferred = _detect_model_family(fp["burp_model_name"])
            if inferred:
                target_model_family = inferred

    ctx.seeds = load_seeds(
        args.seeds,
        args.max_seeds or 25,
        target_language=target_language,
        enable_dos=getattr(args, "enable_dos", False),
        capabilities=target_capabilities,
        model_family=target_model_family,
        seed_filters=getattr(args, "seed_filters_parsed", None),
    )

    _seed_files_count = len(args.seeds.split(",")) if args.seeds else 0
    print_status(
        "ARM", "SEEDS",
        f"{len(ctx.seeds)} seeds loaded"
        f" (files={_seed_files_count}, lang={target_language or 'auto'})",
        ok=True,
    )

    # 协同分析信息
    _synergy_info = {}
    if ctx.synergy_config:
        _synergy_info = {
            "synergy_enabled": ctx.synergy_config.synergy_enabled,
            "attack_surface": ctx.synergy_config.attack_surface,
            "synergy_confidence": ctx.synergy_config.confidence,
            "synergy_scorer": ctx.synergy_config.scorer_name,
            "synergy_evidence": ctx.synergy_config.evidence,
        }

    ctx.orchestration_log.append({
        "phase": "arm",
        "decision": "seed_selection",
        "input": {
            "seed_files": args.seeds,
            "capabilities": target_capabilities or "",
            "model_family": target_model_family or "",
            "language": target_language or "",
            **_synergy_info,
        },
        "output": {"seed_count": len(ctx.seeds)},
        "reasoning": (
            f"基于能力指纹自动追加定向种子 (capabilities={target_capabilities or 'none'})"
            + (f", 协同分析: surface={ctx.synergy_config.attack_surface}, conf={ctx.synergy_config.confidence:.2f}"
               if ctx.synergy_config else "")
        ),
    })

    # ── P1-2: 从 OpenAPI 发现结果生成定向参数注入种子 ──
    _generate_openapi_seeds(ctx)

    # arXiv:2310.04451 — AutoDAN 3x 扩充 ASR 1.5-2x
    if getattr(args, "auto_seeds", False) and ctx.converter_target:
        from arm.seed_ranker import auto_generate_seeds_async
        _expansion_factor = getattr(args, "auto_seed_expansion_factor", 3)
        if not isinstance(_expansion_factor, int) or _expansion_factor < 1:
            _expansion_factor = 3
        ctx.seeds = await auto_generate_seeds_async(
            ctx.seeds,
            converter_target=ctx.converter_target,
            expansion_factor=_expansion_factor,
        )
        print_status("ARM", "DONE", f"AutoDAN 扩充至 {len(ctx.seeds)} 个种子", ok=True)

    # ═══════════════════════════════════════════════════════════════════════════
    # ④ Converter 转换: 构建 L5 最优多路径 Converter 链
    # ═══════════════════════════════════════════════════════════════════════════
    print_phase("ARM", "Converter: 构建 L5 最优多路径链...")

    has_adversarial = ctx.adversarial_target is not None
    ctx.techniques = select_techniques(args.techniques, has_adversarial=has_adversarial)
    ctx.techniques = filter_by_adversarial(ctx.techniques, has_adversarial)
    ctx.techniques = augment_techniques_by_capability(ctx.techniques, target_capabilities)

    ctx.orchestration_log.append({
        "phase": "arm",
        "decision": "technique_selection",
        "input": {
            "mode": args.techniques,
            "has_adversarial": has_adversarial,
            "capabilities": target_capabilities or "",
        },
        "output": {"techniques": ctx.techniques},
        "reasoning": f"基于能力指纹追加定向技术 (capabilities={target_capabilities or 'none'})",
    })

    if args.converters == "none":
        chain_names = []
    elif args.converters == "auto":
        chain_names = ["l5_optimal"]
    else:
        chain_names = args.converters.split(",")

    _target_fingerprint = None
    if ctx.parsed_request:
        _target_fingerprint = ctx.parsed_request.target_fingerprint
    from arm.converter_presets import _classify_target_type
    _target_type = _classify_target_type(target_capabilities, _target_fingerprint)
    logger.info("L5 v39: Target type for converter selection: %s", _target_type)

    if _target_fingerprint is not None:
        _target_fingerprint["target_type"] = _target_type

    ctx.converter_map = build_converter_map(
        technique_names=ctx.techniques,
        chain_names=chain_names,
        converter_target=ctx.converter_target,
        model_family=target_model_family,
        target_type=_target_type,
        target_fingerprint=_target_fingerprint,
        converter_overrides=getattr(args, "converter_overrides", None),
        seeds=ctx.seeds,
    )

    ctx.orchestration_log.append({
        "phase": "arm",
        "decision": "converter_selection",
        "input": {
            "converters": args.converters,
            "model_family": target_model_family or "",
            "target_type": _target_type,
        },
        "output": {
            "converter_count": sum(len(v) for v in ctx.converter_map.values()),
            "per_technique": {k: len(v) for k, v in ctx.converter_map.items()},
        },
        "reasoning": (
            f"目标感知+技术感知+种子感知 converter 分配 "
            f"(target_type={_target_type}, model_family={target_model_family or 'default'})"
        ),
    })

    # ── ARM 阶段输出: 武器清单 ──
    _is_arm_only_stage = getattr(args, "stage", None) == "arm"
    if _is_arm_only_stage:
        print_arm_card(ctx)

    _arm_target_type = "unknown"
    if ctx.parsed_request:
        _fp = ctx.parsed_request.target_fingerprint
        _caps = _fp.get("capabilities", "") or ""
        if "mcp" in _caps.lower() or "mcp_protocol" in _caps.lower():
            _arm_target_type = "mcp_agent"
        elif _fp.get("app_type") in ("chat", "responses", "litellm"):
            _arm_target_type = "llm_chat"
        elif _fp.get("app_type") == "browser":
            _arm_target_type = "browser"
        else:
            _arm_target_type = "http_api"
    print_status(
        "ARM", "READY",
        f"Seeds={len(ctx.seeds)} | Techs={len(ctx.techniques)} | "
        f"Converters={sum(len(v) for v in ctx.converter_map.values())} | "
        f"Target: {_arm_target_type} | Roles: 3-actor",
        ok=True,
    )

    # T-02: ARM 微卡片
    if not _is_arm_only_stage:
        try:
            from utils.display import print_arm_highlights
            print_arm_highlights(ctx)
        except Exception:
            pass

    # ── --stage arm: 武器化完成, 输出清单后退出 ──
    if _is_arm_only_stage:
        print_status("ARM", "DONE", "武器化阶段完成", ok=True)
        await cleanup_resources(ctx, exclude_shared=True)
        return

    # ═══════════════════════════════════════════════════════════════════════════
    # ⑤ 攻击发送: PyRIT 原生多路径执行 + 多轮升级链
    # ═══════════════════════════════════════════════════════════════════════════
    print_phase("STRIKE", "执行 PyRIT 原生攻击...")
    from strike.escalation import check_and_escalate

    # 进度展示: STRIKE 横幅
    try:
        from utils.display import print_strike_start_banner
        _ep_idx = getattr(ctx, "_current_endpoint_idx", None)
        _total_eps = None
        _burp_list = getattr(args, "_burp_list", None)
        if _burp_list and len(_burp_list) >= 1:
            _total_eps = len(_burp_list)
        print_strike_start_banner(ctx, total_endpoints=_total_eps, current_endpoint_idx=_ep_idx)
    except Exception:
        pass

    # ── R10: --dry-run 零 token 流水线完整性验证 ──
    _is_dry_run = getattr(args, "dry_run", False)

    if _is_dry_run:
        logger.info("[DRY-RUN] 跳过攻击执行 (strike 阶段) — 零 token 验证模式")
        print_phase("STRIKE", "[DRY-RUN] 跳过攻击执行 — 验证数据流贯通")
        ctx.attack_results = {}
    else:
        # 选择执行路径 (adaptive 模式 vs 多路径)
        if args.techniques == "adaptive":
            print_phase("STRIKE", "TextAdaptive (ε-贪心自适应)...")
            from strike.adaptive_executor import execute_text_adaptive
            try:
                await execute_text_adaptive(ctx)
            except Exception as e:
                logger.error("TextAdaptive 执行失败: %s — 回退到多路径执行", e)
                from strike.executor import execute_attacks
                try:
                    await execute_attacks(ctx)
                except Exception as e2:
                    logger.error("多路径执行也失败: %s — 继续处理部分结果", e2)
                    print_phase("STRIKE", f"部分执行失败: {e2}")
        else:
            from strike.executor import execute_attacks
            try:
                await execute_attacks(ctx)
            except Exception as e:
                logger.error("攻击执行失败: %s — 继续处理部分结果", e)
                print_phase("STRIKE", f"部分执行失败: {e}")

    # ── STRIKE 阶段过程性输出 ──
    if not _is_dry_run:
        await print_strike_report_async(ctx)

    if not _is_dry_run:
        try:
            from utils.display import _is_success as _strike_is_success
            from utils.display import print_strike_phase_summary
            _strike_elapsed = getattr(ctx, "_strike_elapsed", 0.0)
            _total_results = sum(len(v) for v in ctx.attack_results.values())
            _total_success = sum(
                1 for results in ctx.attack_results.values()
                for r in results if _strike_is_success(r)
            )
            print_strike_phase_summary(
                ctx,
                total_results=_total_results,
                total_success=_total_success,
                elapsed_seconds=_strike_elapsed,
            )
        except Exception:
            pass

    # 生产级: STRIKE 阶段编排日志
    from core.context import get_effective_concurrency as _get_concurrency
    ctx.orchestration_log.append({
        "phase": "strike",
        "decision": "attack_execution",
        "input": {
            "mode": "dry_run" if _is_dry_run else ("adaptive" if args.techniques == "adaptive" else "multi_path"),
            "seeds_count": len(ctx.seeds),
            "techniques": list(ctx.techniques) if ctx.techniques else [],
            "converter_count": sum(len(v) for v in ctx.converter_map.values()),
            "concurrency": _get_concurrency(ctx),
        },
        "output": {
            "total_results": sum(len(v) for v in ctx.attack_results.values()),
            "techniques_executed": list(ctx.attack_results.keys()),
        },
        "reasoning": (
            "[DRY-RUN] 零 token 验证 — 跳过真实 API 调用" if _is_dry_run else
            "PyRIT 原生 PromptSendingAttack + SequentialAttack(FIRST_SUCCESS) "
            "多路径独立执行, 轻量 SubStringScorer 做中间判断"
        ),
    })

    # ── --stage strike: 单轮攻击完成, 输出结果后退出 ──
    if getattr(args, "stage", None) == "strike":
        print_status("STRIKE", "DONE", "单轮攻击完成", ok=True)
        await cleanup_resources(ctx, exclude_shared=True)
        return

    # arXiv:2406.12609 — 升级链
    should_escalate = getattr(ctx.args, "escalation", True)
    if _is_dry_run:
        logger.info("[DRY-RUN] 跳过升级链 (escalate 阶段) — 零 token 验证模式")
        print_status("ESCALATE", "DRY-RUN", "跳过升级链 — 零 token 验证")
    elif should_escalate:
        print_phase("ESCALATE", "检查 ASR & 触发多轮升级链 (ASR<90% 触发)...")
        try:
            await check_and_escalate(ctx, ctx.attack_results)
        except Exception as e:
            logger.error("升级失败: %s — 继续处理单轮结果", e)
            print_phase("ESCALATE", f"升级部分失败: {e}")
    else:
        print_status("ESCALATE", "SKIP", "升级已禁用")

    # 生产级: ESCALATE 阶段编排日志
    _esc_threshold_val = getattr(ctx.args, "escalation_asr_threshold", 90)
    _post_l1_val = getattr(ctx.args, "post_l1_exit_threshold", 70)
    _post_l2_val = getattr(ctx.args, "post_l2_exit_threshold", 80)
    ctx.orchestration_log.append({
        "phase": "escalate",
        "decision": "escalation_chain",
        "input": {
            "enabled": should_escalate,
            "escalation_threshold": f"ASR<{_esc_threshold_val}% triggers",
            "post_l1_exit_threshold": _post_l1_val,
            "post_l2_exit_threshold": _post_l2_val,
            "escalation_levels": (
                ", ".join(f"L{i}" for i in sorted(getattr(ctx.args, "escalation_levels_parsed", None) or []))
                if getattr(ctx.args, "escalation_levels_parsed", None) else "L1→L2→L3→L4 (full chain)"
            ),
        },
        "output": {
            "escalated_techniques": list(ctx.attack_results.keys()),
            "total_results": sum(len(v) for v in ctx.attack_results.values()),
        },
        "reasoning": (
            "arXiv:2406.12609 升级链: Single→Best-of-N→Crescendo→TAP∥PAIR→GCG→native, "
            "ASR<90% 触发, L1≥70% 中间退出 (节省 60-80% token)"
        ),
    })

    # ── R2 §2.1: 升级链结果展示 ──
    if not _is_dry_run:
        await print_escalate_report_async(ctx)

    # ── --stage escalate: 升级链完成, 输出结果卡片后退出 ──
    if getattr(args, "stage", None) == "escalate":
        print_status("ESCALATE", "DONE", "升级链完成", ok=True)
        await cleanup_resources(ctx, exclude_shared=True)
        return

    # ═══════════════════════════════════════════════════════════════════════════
    # ⑥ 评分判定: 双 Judge 交叉验证 + ASR 统计 + 证据收集 + 报告
    # ═══════════════════════════════════════════════════════════════════════════
    print_phase("ASSESS", "双 Judge 交叉验证 & ASR 统计...")
    from assess.asr_tracker import (
        collect_dual_judge_stats,
        compute_asr,
        compute_overall_asr,
        compute_wilson_score_interval,
        precompute_outcomes_async,
        save_asr_history,
    )

    _assess_reset_stats = not should_escalate
    try:
        await precompute_outcomes_async(ctx.attack_results, score_all=False, reset_stats=_assess_reset_stats)
    except Exception as e:
        logger.error("评分失败: %s — 继续处理未评分结果", e)

    ctx.asr_per_technique = compute_asr(ctx.attack_results)
    ctx.overall_asr = compute_overall_asr(ctx.asr_per_technique)
    save_asr_history(ctx.asr_per_technique, attack_results=ctx.attack_results)

    # 运行后更新 asr_priors.yaml
    if ctx.parsed_request:
        model_family = ctx.parsed_request.target_fingerprint.get("model_family")
        if model_family:
            from arm.seed_ranker import update_asr_priors
            update_asr_priors(model_family, ctx.asr_per_technique)

    # Wilson Score 95% CI
    from assess.asr_stats import _get_outcome as _get_attack_outcome
    total_successes = sum(
        1 for results in ctx.attack_results.values()
        for r in results
        if _get_attack_outcome(r) == "success"
    )
    total_decided = sum(
        1 for results in ctx.attack_results.values()
        for r in results
        if _get_attack_outcome(r) in ("success", "failure")
    )
    wilson_lower, wilson_upper = compute_wilson_score_interval(total_successes, total_decided)
    logging.info(
        "ASR Wilson Score 95%% CI: [%.1f%%, %.1f%%] (点估计: %.1f%%)",
        wilson_lower, wilson_upper, ctx.overall_asr,
    )
    ctx.wilson_ci = (wilson_lower, wilson_upper)

    # 双 Judge 统计 + Cohen's Kappa
    ctx.dual_judge_stats = collect_dual_judge_stats(ctx)
    if ctx.dual_judge_stats:
        from assess.asr_tracker import compute_cohens_kappa
        kappa = compute_cohens_kappa(
            ctx.dual_judge_stats.get("agreements", 0),
            ctx.dual_judge_stats.get("disagreements", 0),
        )
        ctx.dual_judge_stats["cohens_kappa"] = kappa
        logging.info(
            "Dual Judge: total=%d, dual_invoked=%d (%.1f%%), "
            "agreements=%d, disagreements=%d, Cohen's Kappa=%.3f",
            ctx.dual_judge_stats.get("total_scored", 0),
            ctx.dual_judge_stats.get("dual_judge_invoked", 0),
            ctx.dual_judge_stats.get("dual_judge_rate", 0.0),
            ctx.dual_judge_stats.get("agreements", 0),
            ctx.dual_judge_stats.get("disagreements", 0),
            kappa,
        )
        # OR aggregation false-positive tracking log
        or_stats = ctx.dual_judge_stats.get("or_aggregation", {})
        if or_stats and or_stats.get("total", 0) > 0:
            logging.info(
                "OR Aggregation: total=%d, disagreements=%d (%.1f%%), "
                "j1_only_success=%d, j2_only_success=%d, "
                "potential_fpr=%.1f%%",
                or_stats.get("total", 0),
                or_stats.get("disagreements", 0),
                or_stats.get("disagreement_rate", 0.0),
                or_stats.get("j1_only_success", 0),
                or_stats.get("j2_only_success", 0),
                or_stats.get("potential_false_positive_rate", 0.0),
            )
        # T0 ScorerMetrics log
        sm = ctx.dual_judge_stats.get("scorer_metrics", {})
        if sm and sm.get("num_responses", 0) > 0:
            logging.info(
                "T0 ScorerMetrics: n=%d, accuracy=%.3f, f1=%.3f, "
                "precision=%.3f, recall=%.3f",
                sm.get("num_responses", 0),
                sm.get("accuracy", 0.0),
                sm.get("f1_score", 0.0),
                sm.get("precision", 0.0),
                sm.get("recall", 0.0),
            )

    # ── 终端展示: ASSESS 阶段结果卡片 ──
    print_assess_card(ctx)

    # ── --stage assess: 评分完成, 输出 ASR 卡片后退出 ──
    if getattr(args, "stage", None) == "assess":
        print_status("ASSESS", "DONE", "评分完成", ok=True)
        await cleanup_resources(ctx, exclude_shared=True)
        return

    # 生产级: ASSESS 阶段编排日志
    _dual_judge_enabled = getattr(ctx.args, "dual_judge_enabled", True)
    _wilson_level = getattr(ctx.args, "wilson_confidence_level", 0.95)
    ctx.orchestration_log.append({
        "phase": "assess",
        "decision": "scoring_assessment",
        "input": {
            "total_attacks": sum(len(v) for v in ctx.attack_results.values()),
            "scoring_model": "T0→J1→J2 OR 聚合 (精简 2-LLM)" if _dual_judge_enabled else "T0→J1 (single judge)",
            "dual_judge_enabled": _dual_judge_enabled,
            "wilson_confidence_level": _wilson_level,
        },
        "output": {
            "overall_asr": ctx.overall_asr,
            "wilson_ci": list(ctx.wilson_ci),
            "asr_per_technique": ctx.asr_per_technique,
            "dual_judge_invoked": ctx.dual_judge_stats.get("dual_judge_invoked", 0),
            "cohens_kappa": ctx.dual_judge_stats.get("cohens_kappa", 0.0),
        },
        "reasoning": (
            "arXiv:2308.07920 双 Judge 交叉验证 + T0 预过滤 (0 token) + "
            "Wilson Score 95% CI + Cohen's Kappa 一致性度量"
        ),
    })

    # ── 证据收集 + 报告生成 ──
    print_phase("REPORT", "收集证据 & 生成安全报告...")
    from report.evidence import EvidenceCollector
    from report.generator import generate_report

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
        memory_labels=ctx.memory_labels,
        orchestration_log=ctx.orchestration_log,
    )

    # 注入统计到 evidence
    if hasattr(ctx, "dual_judge_stats") and ctx.dual_judge_stats:
        evidence.dual_judge_stats = ctx.dual_judge_stats
    evidence.wilson_ci = getattr(ctx, "wilson_ci", (0.0, 0.0))
    evidence.cohens_kappa = ctx.dual_judge_stats.get("cohens_kappa", 0.0) if ctx.dual_judge_stats else 0.0
    evidence.orchestration_log = ctx.orchestration_log

    # ── 认证恢复历史传递到证据 ──
    auth_recovery_log: list[dict[str, str]] = []
    try:
        _target = ctx.objective_target
        if _target and hasattr(_target, "_auth_state") and _target._auth_state:
            auth_recovery_log = list(_target._auth_state.recovery_history)
            if auth_recovery_log:
                logger.info("Auth recovery log: %d recovery attempts recorded", len(auth_recovery_log))
    except Exception as e:
        logger.debug("Failed to extract auth recovery history: %s", e)

    if auth_recovery_log:
        if hasattr(evidence, "attack_surface") and evidence.attack_surface:
            evidence.attack_surface["auth_recovery_attempts"] = len(auth_recovery_log)
            evidence.attack_surface["auth_recovery_log"] = auth_recovery_log

    # R8 §8.5: 审计日志完整性
    _native_dir = output_dir / "native_output"
    _report_index_path = str(output_dir / "report.md")
    ctx.orchestration_log.append({
        "phase": "report",
        "decision": "report_generation",
        "input": {
            "evidence_count": evidence.total_attacks,
            "overall_asr": ctx.overall_asr,
        },
        "output": {
            "report_index": _report_index_path,
            "report_executive": str(output_dir / "report_executive.md"),
            "report_findings": str(output_dir / "report_findings.md"),
            "report_technical": str(output_dir / "report_technical.md"),
            "report_success": str(output_dir / "report_success.md") if evidence.successful_evidence else "",
            "native_output": str(_native_dir) if _native_dir.exists() else "",
        },
        "reasoning": f"生成分层安全报告 (ASR={ctx.overall_asr:.1f}%, {evidence.total_attacks} 条证据, 4 文件分层架构)",
    })

    report_path = await generate_report(ctx, evidence, output_dir)
    print_report_card(
        total_attacks=evidence.total_attacks,
        successful_attacks=evidence.successful_attacks,
        overall_asr=ctx.overall_asr,
        report_path=str(report_path),
        evidence_count=evidence.total_attacks,
        wilson_ci=getattr(ctx, "wilson_ci", (0.0, 0.0)),
        native_output_dir=str(_native_dir) if _native_dir.exists() else "",
    )
    print_status("REPORT", "DONE", "全链路完成", ok=True)

    # 资源清理: 两阶段分离
    await cleanup_resources(ctx, exclude_shared=True)


def _log_recon_decision(ctx: Any, args: Any) -> None:
    """记录侦察决策到编排日志。"""
    if ctx.parsed_request:
        _fp = ctx.parsed_request.target_fingerprint
        ctx.orchestration_log.append({
            "phase": "recon",
            "decision": "target_profiling",
            "input": {"burp": ctx.args.burp},
            "output": {
                "app_type": _fp.get("app_type", "Unknown"),
                "auth_type": _fp.get("auth_type", "Unknown"),
                "capabilities": _fp.get("capabilities", ""),
                "model_family": _fp.get("model_family", ""),
                "language": _fp.get("language", ""),
                "burp_model_name": _fp.get("burp_model_name", ""),
                "api_category": _fp.get("api_category", "chat"),
                "has_model_list": _fp.get("burp_model_list", ""),
                "mcp_tool_count": len(_fp.get("mcp_tools", [])),
                "openapi_endpoint_count": len(_fp.get("openapi_endpoints", [])),
                "port_endpoint_count": len(_fp.get("port_endpoints", [])),
                "probe_count": _fp.get("probe_count", 0),
                "probe_duration_seconds": _fp.get("probe_duration_seconds", 0),
                "secret_format": _fp.get("secret_format", ""),
                "session_type": _fp.get("session_type", ""),
                "tenant_id": _fp.get("tenant_id", ""),
                "ai_framework": _fp.get("ai_framework", ""),
                "ai_framework_category": _fp.get("ai_framework_category", ""),
                "system_prompt_leaked": _fp.get("system_prompt_leaked", False),
                "system_prompt_extraction_method": _fp.get("system_prompt_extraction_method", ""),
                "model_ids_count": len(_fp.get("model_ids", [])),
                "vector_db_count": len(_fp.get("vector_dbs", [])),
                "mcp_tool_safety_risky_count": sum(
                    1 for t in _fp.get("mcp_tool_safety", []) if t.get("risks")
                ),
            },
            "reasoning": (
                "三层探测 (被动指纹 + 主动能力 + 深度能力) + Burp 响应模型信息提取 + "
                "MCP 枚举 + OpenAPI 发现 + 端口发现 + 认证状态管理 + "
                "AI 框架指纹识别 + System Prompt 泄露探测 + "
                "模型族 API 行为指纹 + 向量数据库确认 + MCP 工具安全分析 完成"
            ),
        })
    else:
        # 非Burp路径: 仍需记录 recon 决策，确保编排日志完整性
        _recon_mode = "unknown"
        _recon_endpoint = ""
        if getattr(args, "litellm_model", None) or os.environ.get("LITELLM_MODEL"):
            _recon_mode = "litellm"
            _recon_endpoint = getattr(args, "litellm_model", None) or os.environ.get("LITELLM_MODEL", "")
        elif getattr(args, "target_api_endpoint", None) and getattr(args, "target_api_key", None):
            _recon_mode = getattr(args, "target_api_type", "chat")
            _recon_endpoint = getattr(args, "target_api_endpoint", "")
        elif getattr(args, "browser_url", None):
            _recon_mode = "browser"
            _recon_endpoint = getattr(args, "browser_url", "")
        ctx.orchestration_log.append({
            "phase": "recon",
            "decision": "target_profiling",
            "input": {"mode": _recon_mode, "endpoint": _recon_endpoint},
            "output": {
                "app_type": _recon_mode,
                "auth_type": "api_key" if _recon_mode in ("chat", "responses", "litellm") else "none",
                "capabilities": "",
                "model_family": ctx.model_name or "",
                "language": "",
                "target_type": _recon_mode,
            },
            "reasoning": f"非Burp路径 ({_recon_mode}) — 直接创建原生Target, 无需HTTP解析",
        })


def _apply_auto_l4_optimization(ctx: Any, args: Any) -> None:
    """②.6 目标感知自动 L4 优化 (SYNERGY → 升级路径决策)。

    学术依据:
        - InjecAgent (arXiv:2307.00929): Agent 目标需定向攻击, 通用 jailbreak 无效
        - Eidam et al. (arXiv:2407.16924): A2A 信任链攻击 ASR +15-25%
        - Greshake et al. (arXiv:2302.12173): Agent 异常检测使逐步升级适得其反
    """
    from utils.display import print_status

    _auto_l4_enabled = getattr(args, "auto_l4_optimization_enabled", True)
    _auto_l4_threshold = getattr(args, "auto_l4_confidence_threshold", 0.8)
    _auto_l4_surfaces = set(getattr(args, "auto_l4_agent_surfaces", [
        "mcp_server", "multi_agent_system", "rag_system",
    ]))
    if _auto_l4_enabled and ctx.synergy_config:
        _surface = ctx.synergy_config.attack_surface
        _confidence = ctx.synergy_config.confidence
        if (_surface in _auto_l4_surfaces and _confidence >= _auto_l4_threshold):
            _user_specified_levels = getattr(args, "escalation_levels_parsed", None)
            if _user_specified_levels is None:
                setattr(args, "escalation_levels_parsed", {4})
                _user_max_seeds = getattr(args, "max_seeds", None)
                if _user_max_seeds is None or _user_max_seeds > 12:
                    setattr(args, "max_seeds", 8)
                    logger.info("Auto L4 optimization: max_seeds limited to 8 (specialty seeds only)")
                logger.info(
                    "Auto L4 optimization activated: surface=%s, confidence=%.2f >= %.2f, "
                    "escalation_levels set to {4} (skip L1-L3)",
                    _surface, _confidence, _auto_l4_threshold,
                )
                print_status(
                    "AUTO-L4", "ESCALATION",
                    f"高置信度 Agent/MCP 目标 (surface={_surface}, conf={_confidence:.2f}), "
                    f"自动跳过 L1-L3, 直接执行 L4 专用种子攻击",
                    ok=True,
                )
                ctx.orchestration_log.append({
                    "phase": "synergy",
                    "decision": "auto_l4_optimization",
                    "input": {
                        "attack_surface": _surface,
                        "confidence": _confidence,
                        "threshold": _auto_l4_threshold,
                        "enabled": _auto_l4_enabled,
                    },
                    "output": {
                        "escalation_levels": [4],
                        "max_seeds": getattr(args, "max_seeds", 8),
                        "seed_strategy": "specialty_only",
                    },
                    "reasoning": (
                        f"Target-aware L4 optimization per InjecAgent (arXiv:2307.00929) + "
                        f"Eidam et al. (arXiv:2407.16924): confidence={_confidence:.2f} >= "
                        f"{_auto_l4_threshold:.2f}, surface={_surface} in auto_l4_surfaces. "
                        f"Using specialty seeds only (MCP/RAG/Agent), max_seeds=8"
                    ),
                })
            else:
                logger.info(
                    "Auto L4 optimization skipped: user explicitly specified escalation_levels=%s",
                    _user_specified_levels,
                )


def _generate_openapi_seeds(ctx: Any) -> None:
    """P1-2: 从 OpenAPI 发现结果生成定向参数注入种子。

    学术依据: OWASP API1 (BOLA) + API3 (BOPLA) — 参数注入需要知道 schema
    数据流: recon (openapi_discoverer) → target_fingerprint["openapi_endpoints"]
            → arm (build_openapi_attack_seeds) → ctx.seeds
    """
    from utils.display import print_status

    if ctx.parsed_request:
        _fp = ctx.parsed_request.target_fingerprint
        _openapi_endpoints = _fp.get("openapi_endpoints", [])
        if _openapi_endpoints:
            try:
                from recon.openapi_discoverer import (
                    OpenAPIDiscovery,
                    OpenAPIEndpoint,
                    build_openapi_attack_seeds,
                )

                _discovery = OpenAPIDiscovery(
                    spec_path=_fp.get("openapi_spec_path", ""),
                    spec_version=_fp.get("openapi_version", ""),
                    title=_fp.get("openapi_title", ""),
                    endpoints=[
                        OpenAPIEndpoint(
                            path=ep.get("path", ""),
                            method=ep.get("method", ""),
                            summary=ep.get("summary", ""),
                            parameters=ep.get("parameters", []),
                            has_auth=ep.get("has_auth", False),
                        )
                        for ep in _openapi_endpoints
                    ],
                    security_schemes=_fp.get("openapi_security_schemes", []),
                )
                _openapi_seeds = build_openapi_attack_seeds(_discovery)
                if _openapi_seeds:
                    from arm.seed_ranker import _build_seed_groups
                    _openapi_seed_groups = _build_seed_groups(_openapi_seeds)
                    ctx.seeds.extend(_openapi_seed_groups)
                    logger.info(
                        "P1-2: Appended %d OpenAPI-directed seeds (BOLA/BOPLA/param injection)",
                        len(_openapi_seed_groups),
                    )
                    print_status(
                        "ARM", "OPENAPI",
                        f"追加 {len(_openapi_seed_groups)} 个 OpenAPI 定向种子",
                    )
            except Exception as e:
                logger.warning("P1-2: OpenAPI seed generation failed (non-fatal): %s", e)</longcat_think>
