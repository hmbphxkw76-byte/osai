#!/usr/bin/env python3
"""main.py — 模块化 PyRIT 攻击链路入口。

攻击链路 (6 阶段, arXiv:2407.01232 — PyRIT 原生框架):
    ① recon     → Burp 拦截: 读取 HTTP 请求 (含 {PROMPT} 占位符) + 侦察: 解析, 探测能力指纹, 构建 HTTPTarget
    ② arm       → 种子选取: 从 YAML 种子文件加载, 按历史 ASR 排序 + Converter: 构建 L5 最优链
    ③ strike    → 攻击发送: PyRIT 原生 PromptSendingAttack 多路径执行 (FIRST_SUCCESS)
    ④ escalate  → 多轮升级: Crescendo→TAP→PAIR→GCG→native (ASR<90% 触发, 含中间退出)
    ⑤ assess    → 评分判定: T0→J1→J2→J3 级联评分, ASR 统计, Wilson CI, 双 Judge 交叉验证
    ⑥ report    → 报告生成: 证据收集 + MD/HTML/JSON/PoC/SARIF

    不指定 --stage 时按顺序执行全部 6 个阶段 (strike+escalate 合为一步), 向后兼容。
    指定 --stage <name> 时执行到该阶段完成后停止, 便于分阶段开发和调试。

模块化架构 (SKILL.md 目录规范):
    core/    — 流水线编排, 上下文, 配置, 架构守卫
    recon/   — Burp 拦截, HTTP 解析, 目标指纹, 能力探测
    arm/     — 种子选取, Converter 链, 技术选择
    strike/  — 攻击执行, 多路径, 升级链
    assess/  — 评分器, ASR 统计, 双 Judge
    report/  — 证据收集, 报告生成 (MD/HTML/JSON/PoC/SARIF)
    targets/ — RateLimitedTarget, 内容过滤
    utils/   — 终端输出, 缓存清理

使用方式:
    # 默认配置 (自动扫描 data/burp/*.txt 全部文件 + L5 最优 Converter + 双 Judge 评分)
    python main.py

    # 全火力模式 (AI-300 考试首选 — 最高 ASR 配置)
    python main.py --offensive

    # 分阶段执行 (--stage 控制, 6 个阶段可独立调试):
    #   recon     → 侦察: Burp 解析 + 目标探测 + 能力指纹 + HTTPTarget 构建
    #   arm       → 武器化: 种子 ASR 排序 + Converter 链 + 技术选择
    #   strike    → 单轮攻击: PyRIT 原生多路径 PromptSendingAttack
    #   escalate  → 多轮升级: Crescendo→TAP→PAIR→GCG→native (ASR<90% 触发)
    #   assess    → 评分: T0→J1→J2→J3 级联评分 + ASR 统计 + Wilson CI
    #   report    → 报告: 证据收集 + MD/HTML/JSON/PoC/SARIF 生成
    #
    # --burp <NAME> 指定单个 Burp 请求文件 (自动查找 data/burp/<NAME>.txt):
    python main.py --burp request --stage recon
    # 不指定 --burp 时自动扫描 data/burp/*.txt 全部文件, 逐个深度攻击
    python main.py --burp deepseek --stage arm
    python main.py --burp qwen --stage strike
    python main.py --stage escalate
    python main.py --stage assess
    python main.py --stage report

    # 自定义参数
    python main.py --burp request \\
        --seeds elite_jailbreaks --converters l5_optimal \\
        --techniques auto --max-seeds 25

OffSec AI-300 对齐 (高 ASR 首要目标):
    - R1 攻击者思维: 最大化 ASR, 单轮 ASR < 90% 自动触发升级链
    - R2 PyRIT 原生优先: PromptSendingAttack / CrescendoAttack / TAPAttack / PAIRAttack
    - R4 L5 标准: 7 路径独立执行 (arXiv:2407.01232 SequentialAttack FIRST_SUCCESS)
    - R5 arXiv 引用: 每个技术都有学术依据
    - R6 红队就绪: 7 种原生攻击策略 + 三角色分离 + 完整证据链
    - R7 ASR-Token 平衡: 级联评分 + 中间退出 (L1>=70% 跳过 L2-L4)
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

# UTF-8 强制 (Windows GBK 终端兼容)
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# 项目根目录加入 sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

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
    然后由 try/finally 块执行 _cleanup_resources。
    """
    global _signal_fired
    if _signal_fired:
        # 重复信号: 直接退出, 不等待
        os._exit(130)
    _signal_fired = True
    print("\n[!] 收到中断信号, 正在退出... (再按一次 Ctrl+C 强制退出)", file=sys.stderr)
    # 抛出 KeyboardInterrupt 让 asyncio.run 自然退出
    raise KeyboardInterrupt


# ═══════════════════════════════════════════════════════════════════════════════
# 攻击链路编排器 — 6 阶段完整链路 (recon→arm→strike→escalate→assess→report)
# ═══════════════════════════════════════════════════════════════════════════════

async def run(argv: list[str] | None = None) -> None:
    """主流程: 6 阶段完成一次完整攻击链路。

    阶段对应模块包 (--stage 控制退出点):
        ① recon     (recon/burp_parser.py + recon/target_router.py)
        ② arm       (arm/seed_ranker.py + arm/converter_presets.py + arm/technique_picker.py)
        ③ strike    (strike/executor.py)
        ④ escalate  (strike/escalation.py + strike/escalation_level1/2/3.py)
        ⑤ assess    (assess/scorer.py + assess/asr_tracker.py + assess/asr_stats.py)
        ⑥ report    (report/evidence.py + report/generator.py)

    多 endpoint 支持 (arXiv:2302.12173 Greshake — 逐个深度攻击):
        不指定 --burp → 自动扫描 data/burp/*.txt 全部文件
        --burp MM_05 --burp MM_03 --burp MM_08 → 指定多个 endpoint
        → 优先级排序: 按能力指纹排序 (MCP > function_calling > RAG > workflow > chat)
        → 对每个 endpoint 执行完整 6 阶段深度攻击链路
        → 最终汇总联合 ASR (arXiv:2310.08419 — 1 - ∏(1 - ASRᵢ))
    """
    # ── 日志配置: 压制第三方噪音, 突出关键信息 ──
    # 自身模块: INFO 级别, 带时间戳
    # 第三方库: 压制到 WARNING+ (Alembic/PyRIT 初始化日志噪音极大)
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # 自身包: 提升到 INFO
    logging.getLogger("core").setLevel(logging.INFO)
    logging.getLogger("recon").setLevel(logging.INFO)
    logging.getLogger("arm").setLevel(logging.INFO)
    logging.getLogger("strike").setLevel(logging.INFO)
    logging.getLogger("assess").setLevel(logging.INFO)
    logging.getLogger("report").setLevel(logging.INFO)
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

    # rate_limit 环境变量 (供 target_router 中的 _create_adversarial_target 读取)
    rate_limit = getattr(args, "rate_limit", None)
    if rate_limit:
        os.environ["RATE_LIMIT"] = str(rate_limit)

    # ── 多 endpoint 检测 ──
    # 学术依据: Greshake et al. (arXiv:2302.12173) — 逐个深度攻击
    #           Lattner et al. (arXiv:2406.12609) — 高价值目标优先
    # 不指定 --burp → 自动扫描 data/burp/*.txt 全部 .txt 文件 (逐个深度攻击)
    # --burp 可重复指定多个 endpoint: --burp MM_05 --burp MM_03 --burp MM_08
    # 多 endpoint 时按能力指纹优先级排序: MCP > function_calling > RAG > workflow > chat
    # 单 endpoint: args.burp 是 str (向后兼容)
    # 多 endpoint: args.burp 是 list[str], args._burp_list 是 list[str]
    burp_list: list[str] = getattr(args, "_burp_list", None)
    if burp_list is None:
        burp_val = args.burp
        if isinstance(burp_val, list):
            burp_list = burp_val
        else:
            burp_list = [burp_val] if burp_val else ["request"]

    is_multi_endpoint = len(burp_list) > 1

    if is_multi_endpoint:
        logger.info(
            "Multi-endpoint mode: %d endpoints — %s",
            len(burp_list),
            ", ".join(Path(b).stem for b in burp_list),
        )

    ctx = PipelineContext(args=args, output_dir=output_dir)
    ctx.scenario_result_id = getattr(args, "resume", None)

    # 生产级: 设置全局 ctx 引用, 供信号处理器在需要时触发资源清理
    global _global_ctx
    _global_ctx = ctx

    # 生产级: try/finally 确保信号中断时也执行资源清理
    # SIGINT/SIGTERM → KeyboardInterrupt → asyncio.run 自然退出 → finally 块执行 cleanup
    try:
        # ── INIT: 初始化 PyRIT 环境 + Relaxed Adversarial Schema ──
        # arXiv:2306.05685 — Zheng et al.: LLM-as-a-Judge 鲁棒性
        # Monkey-patch PyRIT JSON schema, 使 rationale 和 last_response_summary 可选
        # 解决 DeepSeek-V3 / LongCat 等模型不严格遵循 JSON schema 导致的无限重试
        print_phase("INIT", "初始化 PyRIT 环境...")
        apply_relaxed_adversarial_schema()
        await setup_environment(output_dir)
        print_status("INIT", "DONE", f"Output: {output_dir}", ok=True)

        # ═══════════════════════════════════════════════════════════════════════════
        # 多 endpoint 外层循环 (arXiv:2302.12173 — 逐个深度攻击)
        # 对每个 endpoint 执行完整 6 阶段攻击链路, 最终汇总联合 ASR
        # ═══════════════════════════════════════════════════════════════════════════

        # 非 Burp 路径 (LiteLLM/OpenAI API/Browser) 不走多 endpoint 循环
        _non_burp_mode = (
            getattr(args, "litellm_model", None) or os.environ.get("LITELLM_MODEL")
            or (getattr(args, "target_api_endpoint", None) and getattr(args, "target_api_key", None))
            or getattr(args, "browser_url", None)
        )

        if _non_burp_mode or not is_multi_endpoint:
            # 单 endpoint 或非 Burp 路径: 走原有单次执行逻辑
            ctx.args.burp = burp_list[0] if burp_list else "request"
            await _run_single_endpoint(ctx, args, output_dir, argv)
            # 单 endpoint 模式: 统一清理所有资源 (objective + adversarial + scoring)
            await _cleanup_resources(ctx)
            return

        # 多 endpoint 逐个深度攻击
        # 学术依据: Greshake et al. (arXiv:2302.12173) — 五步方法论
        #           Chao et al. (arXiv:2310.08419) — 联合 ASR = 1 - ∏(1 - ASRᵢ)
        #           Lattner et al. (arXiv:2406.12609) — 高价值目标优先

        # ── 优先级排序: 按能力指纹排序 endpoint ──
        # 学术依据: Greshake et al. (arXiv:2302.12173) §4 — 能力指纹决定攻击策略
        #   MCP/function_calling > RAG > workflow > memory > a2a > chat
        # 轻量级预侦察 (0 网络请求): 仅解析 Burp 文件, 从响应文本提取能力信号
        print_phase("RECON", "Endpoint 优先级排序 (能力指纹)...")
        from recon.endpoint_sorter import sort_endpoints_by_priority

        sorted_endpoints = sort_endpoints_by_priority(burp_list)

        # 打印排序结果
        print()
        print(f"{_C_BOLD}{'═' * 60}{_C_RESET}")
        print(f"{_C_BOLD}  Attack Priority Order (能力指纹排序){_C_RESET}")
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
            print(
                f"{_C_BOLD}  Endpoint {idx + 1}/{len(burp_list)}: {burp_name}"
                f"{'═' * max(0, 40 - len(burp_name))}{_C_RESET}"
            )
            print(f"{_C_BOLD}{'═' * 60}{_C_RESET}")

            # 为每个 endpoint 创建独立的子输出目录
            ep_output_dir = output_dir / f"endpoint_{idx + 1}_{burp_name}"
            ensure_output_dir(ep_output_dir)
            ctx.output_dir = ep_output_dir

            # 独立初始化 PyRIT DB (每 endpoint 独立 DB 避免并发冲突)
            ep_db_path = ep_output_dir / "db" / "pyrit.db"
            os.environ["PYRIT_DB_URL"] = f"sqlite:///{ep_db_path}"
            await setup_environment(ep_output_dir)

            # 设置当前 endpoint 的 burp 路径
            ctx.args.burp = burp_path

            # 重置 ctx 状态 (每个 endpoint 独立攻击)
            # 注意: adversarial_target / scoring_target / converter_target 不重置 —
            # 它们是攻击者自己的 LLM, 可在 endpoint 间复用, 循环结束后统一清理
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
            ctx.scenario_result_id = getattr(args, "resume", None)
            ctx.scenario_result = None
            # 重置 assess 阶段的全局统计计数器 (跨 endpoint 独立)
            # 数据流: precompute_outcomes_async 使用全局变量累积 dual_judge 统计,
            #   不重置会导致第 N 个 endpoint 的统计累积前 N-1 个的数据
            # 学术依据: Chao et al. (arXiv:2310.08419) — 联合 ASR 要求各 endpoint 独立计算
            try:
                from assess.asr_stats import _reset_dual_judge_stats
                _reset_dual_judge_stats()
            except Exception:
                pass
            try:
                from assess.judge_utils import reset_t0_stats
                reset_t0_stats()
            except Exception:
                pass
            # 注意: extra_adversarial_targets 不重置 — 多模型并行攻击的额外攻击者 LLM, 跨 endpoint 复用
            # Playwright 资源引用不重置 — browser 模式下可复用同一浏览器实例
            # ctx._playwright_instance / _browser / _browser_context 保留
            # 由 _cleanup_resources 在循环结束后统一清理

            try:
                ep_result = await _run_single_endpoint_to_result(
                    ctx, args, ep_output_dir, burp_name,
                )
                multi_endpoint_results.append(ep_result)
            except ConnectionError as e:
                logger.error("Endpoint %s 不可用: %s", burp_name, e)
                print_error(f"Endpoint {burp_name} 不可用: {e}")
                # 清理可能已创建的 objective target (防止 HTTP 连接泄漏)
                # 不清理 adversarial/scoring target — 跨 endpoint 复用
                await _cleanup_resources(ctx, exclude_shared=True)
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
                print_error(f"Endpoint {burp_name} 攻击失败: {e}")
                # 清理可能已创建的 objective target (防止 HTTP 连接泄漏)
                # 不清理 adversarial/scoring target — 跨 endpoint 复用
                await _cleanup_resources(ctx, exclude_shared=True)
                # 即使失败也尝试提取部分结果 (部分执行的结果可能已在 ctx 中)
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
        await _cleanup_resources(ctx)

    except KeyboardInterrupt:
        # 信号中断: 确保资源清理后退出
        logger.info("收到中断信号, 执行资源清理...")
        try:
            await _cleanup_resources(ctx)
        except Exception:
            pass
        raise
    finally:
        # 最终保障: 如果上面所有路径都没有执行 cleanup (如异常退出)
        # 确保至少尝试一次 (幂等, RateLimitedTarget._is_cleaned + _cleaned 集双重去重)
        # 检查所有可能的残留 target 引用
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
                await _cleanup_resources(ctx)
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
    """获取攻击结果的 outcome (内联简版, 避免循环导入)."""
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
    # 导入 display 函数 (独立函数作用域, 避免依赖 run() 局部导入)
    from utils.display import (
        print_arm_card,
        print_assess_report,
        print_error,
        print_escalate_report,
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

    # ctx.args.burp 已由调用方设置 (单 endpoint 或多 endpoint 循环中逐个赋值)
    # 不再从 args.burp 覆盖, 因为多 endpoint 模式下 args.burp 是 list 而非 str
    try:
        await create_target(ctx)
    except ConnectionError as e:
        logger.error("目标不可用: %s", e)
        print_error(f"目标不可用: {e}\n请启动目标服务后重试。")
        # 多 endpoint 模式下不终止进程, 而是抛出异常让调用方跳过此 endpoint
        raise
    except Exception as e:
        logger.error("目标构建失败: %s", e)
        print_error(f"目标构建失败: {e}")
        raise

    # 打印侦察结果卡片 (阶段间传递: 目标指纹→ARM/STRIKE)
    _is_recon_only = getattr(args, "stage", None) == "recon"
    if ctx.parsed_request and not _is_recon_only:
        print_recon_card(ctx)

    # 编排日志: 记录侦察决策 (无论是否 --stage recon)
    # 断点修复: 非Burp路径(LiteLLM/OpenAI API/Playwright)也需要记录 recon 决策
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
                # P1-2/P2-2: 完整侦察元数据传递到编排日志
                "mcp_tool_count": len(_fp.get("mcp_tools", [])),
                "openapi_endpoint_count": len(_fp.get("openapi_endpoints", [])),
                "port_endpoint_count": len(_fp.get("port_endpoints", [])),
                "probe_count": _fp.get("probe_count", 0),
                "probe_duration_seconds": _fp.get("probe_duration_seconds", 0),
                "secret_format": _fp.get("secret_format", ""),
                "session_type": _fp.get("session_type", ""),
                "tenant_id": _fp.get("tenant_id", ""),
            },
            "reasoning": (
                "三层探测 (被动指纹 + 主动能力 + 深度能力) + Burp 响应模型信息提取 + "
                "MCP 枚举 + OpenAPI 发现 + 端口发现 + 认证状态管理 完成"
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

    # ── --stage recon: 只执行侦察, 输出报告后退出 ──
    if getattr(args, "stage", None) == "recon":
        from recon.recon_report import print_recon_report
        if ctx.parsed_request:
            print_recon_report(ctx.parsed_request, output_dir=output_dir)
        print_status("RECON", "DONE", "侦察阶段完成", ok=True)
        await _cleanup_resources(ctx, exclude_shared=True)
        return

    # ═══════════════════════════════════════════════════════════════════════════
    # ③ 种子选取: 加载 YAML 种子 → ASR 排序 → 能力自适应
    # ═══════════════════════════════════════════════════════════════════════════
    print_phase("ARM", "种子选取 & ASR 排序...")
    from arm.converter_presets import build_converter_map
    from arm.seed_ranker import load_seeds
    from arm.technique_picker import augment_techniques_by_capability, filter_by_adversarial, select_techniques

    # 从目标指纹提取语言 + 能力 + 模型族 (能力自适应种子选取)
    # L5 v53: 如果 Burp 响应中有模型名称, 优先使用它匹配 ASR 先验
    target_language = None
    target_capabilities = None
    target_model_family = None
    if ctx.parsed_request:
        fp = ctx.parsed_request.target_fingerprint
        target_language = fp.get("language")
        target_capabilities = fp.get("capabilities")
        # 优先使用探针检测的 model_family, fallback 到 Burp 提取的模型名称
        target_model_family = fp.get("model_family")
        if not target_model_family and fp.get("burp_model_name"):
            # 复用 capability_detector 的 _detect_model_family 进行模型族推断
            from recon.capability_detector import _detect_model_family
            inferred = _detect_model_family(fp["burp_model_name"])
            if inferred:
                target_model_family = inferred

    # arXiv:2402.01135 — 种子按历史 ASR 排序, 覆盖 OWASP LLM01-10 + ASI01-10
    ctx.seeds = load_seeds(
        args.seeds,
        args.max_seeds or 25,
        target_language=target_language,
        enable_dos=getattr(args, "enable_dos", False),
        capabilities=target_capabilities,
        model_family=target_model_family,
    )

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
        "reasoning": f"基于能力指纹自动追加定向种子 (capabilities={target_capabilities or 'none'})",
    })

    # ── P1-2: 从 OpenAPI 发现结果生成定向参数注入种子 ──
    # 学术依据: OWASP API1 (BOLA) + API3 (BOPLA) — 参数注入需要知道 schema
    # 数据流: recon (openapi_discoverer) → target_fingerprint["openapi_endpoints"]
    #         → arm (build_openapi_attack_seeds) → ctx.seeds
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
                    # 将 OpenAPI 种子追加到 ctx.seeds
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
                logger.warning("P1-2: OpenAPI seed generation failed (non-fatal): %s", e)

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

    # 技术选择 (能力自适应)
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

    # arXiv:2407.01232 — PyRIT SequentialAttack FIRST_SUCCESS, 7 路径独立执行
    # arXiv:2307.15043 — 串联堆叠 >2 层 ASR 12%→4%, 每个 converter 独立一路
    if args.converters == "none":
        chain_names = []
    elif args.converters == "auto":
        chain_names = ["l5_optimal"]
    else:
        chain_names = args.converters.split(",")

    ctx.converter_map = build_converter_map(
        technique_names=ctx.techniques,
        chain_names=chain_names,
        converter_target=ctx.converter_target,
        model_family=target_model_family,
    )

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
        "reasoning": f"基于模型族先验 ASR 排序 converter (model_family={target_model_family or 'default'})",
    })

    # ── ARM 阶段输出: 种子/技术/Converter 链卡片 (阶段间传递: 武器清单→STRIKE) ──
    print_arm_card(ctx)

    print_status(
        "ARM", "READY",
        f"Seeds={len(ctx.seeds)} | Techs={len(ctx.techniques)} | "
        f"Converters={sum(len(v) for v in ctx.converter_map.values())}",
        ok=True,
    )

    # ── --stage arm: 武器化完成, 输出清单后退出 ──
    if getattr(args, "stage", None) == "arm":
        print_status("ARM", "DONE", "武器化阶段完成", ok=True)
        await _cleanup_resources(ctx, exclude_shared=True)
        return

    # ═══════════════════════════════════════════════════════════════════════════
    # ⑤ 攻击发送: PyRIT 原生多路径执行 + 多轮升级链
    # ═══════════════════════════════════════════════════════════════════════════
    print_phase("STRIKE", "执行 PyRIT 原生攻击...")
    from strike.escalation import check_and_escalate

    # 选择执行路径 (adaptive 模式 vs 多路径)
    # arXiv:2407.01232 — PyRIT 原生 PromptSendingAttack + SequentialAttack
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

    # ── STRIKE 阶段过程性输出: PyRIT 原生 output_attack_async 展示攻击结果 ──
    # R2 PyRIT 原生优先: 使用 pyrit.output 官方模块渲染每个 AttackResult
    # 攻击者直接看到完整的对话历史、评分结果、converter 链
    await print_strike_report_async(ctx)

    # 生产级: STRIKE 阶段编排日志 — 记录执行路径和结果
    ctx.orchestration_log.append({
        "phase": "strike",
        "decision": "attack_execution",
        "input": {
            "mode": "adaptive" if args.techniques == "adaptive" else "multi_path",
            "seeds_count": len(ctx.seeds),
            "techniques": list(ctx.techniques) if ctx.techniques else [],
            "converter_count": sum(len(v) for v in ctx.converter_map.values()),
            "concurrency": get_effective_concurrency(ctx),
        },
        "output": {
            "total_results": sum(len(v) for v in ctx.attack_results.values()),
            "techniques_executed": list(ctx.attack_results.keys()),
        },
        "reasoning": (
            "PyRIT 原生 PromptSendingAttack + SequentialAttack(FIRST_SUCCESS) "
            "多路径独立执行, 轻量 SubStringScorer 做中间判断"
        ),
    })

    # ── --stage strike: 单轮攻击完成, 输出结果后退出 ──
    if getattr(args, "stage", None) == "strike":
        print_status("STRIKE", "DONE", "单轮攻击完成", ok=True)
        await _cleanup_resources(ctx, exclude_shared=True)
        return

    # arXiv:2406.12609 — 升级链: Single→Best-of-N→Crescendo→TAP∥PAIR→GCG→native
    # 触发条件: 单轮 ASR < 90% (escalation_asr_threshold)
    # 中间退出: L1>=70% 跳过 L2-L4, L2>=80% 跳过 L3-L4 (节省 60-80% token)
    should_escalate = getattr(ctx.args, "escalation", True)
    if should_escalate:
        print_phase("STRIKE", "检查 ASR & 触发多轮升级链 (ASR<90% 触发)...")
        try:
            await check_and_escalate(ctx, ctx.attack_results)
        except Exception as e:
            logger.error("升级失败: %s — 继续处理单轮结果", e)
            print_phase("STRIKE", f"升级部分失败: {e}")
    else:
        print_status("STRIKE", "SKIP", "升级已禁用")

    # 生产级: ESCALATE 阶段编排日志 — 记录升级策略和结果
    ctx.orchestration_log.append({
        "phase": "escalate",
        "decision": "escalation_chain",
        "input": {
            "enabled": should_escalate,
            "pre_escalation_asr": _compute_overall_asr(ctx.attack_results) if not should_escalate else None,
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

    # ── --stage escalate: 升级链完成, 输出结果卡片后退出 ──
    if getattr(args, "stage", None) == "escalate":
        print_escalate_report(ctx)
        print_status("ESCALATE", "DONE", "升级链完成", ok=True)
        await _cleanup_resources(ctx, exclude_shared=True)
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

    # arXiv:2308.07920 — Zhang et al.: 双 Judge 交叉验证
    # T0 预过滤 (0 token) → J1 (lenient) → J2 (strict) → J3 (arbiter)
    _assess_reset_stats = not should_escalate
    try:
        await precompute_outcomes_async(ctx.attack_results, score_all=False, reset_stats=_assess_reset_stats)
    except Exception as e:
        logger.error("评分失败: %s — 继续处理未评分结果", e)

    ctx.asr_per_technique = compute_asr(ctx.attack_results)
    ctx.overall_asr = compute_overall_asr(ctx.asr_per_technique)
    save_asr_history(ctx.asr_per_technique, attack_results=ctx.attack_results)

    # 运行后更新 asr_priors.yaml (EMA 跨目标知识迁移)
    if ctx.parsed_request:
        model_family = ctx.parsed_request.target_fingerprint.get("model_family")
        if model_family:
            from arm.seed_ranker import update_asr_priors
            update_asr_priors(model_family, ctx.asr_per_technique)

    # arXiv:2308.07920 — Wilson Score 95% CI 用于 ASR 置信区间报告
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

    # ── --stage assess: 评分完成, 输出 ASR 卡片后退出 ──
    if getattr(args, "stage", None) == "assess":
        print_assess_report(ctx)
        print_status("ASSESS", "DONE", "评分完成", ok=True)
        await _cleanup_resources(ctx, exclude_shared=True)
        return

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
    )

    # 注入统计到 evidence
    if hasattr(ctx, "dual_judge_stats") and ctx.dual_judge_stats:
        evidence.dual_judge_stats = ctx.dual_judge_stats
    evidence.wilson_ci = getattr(ctx, "wilson_ci", (0.0, 0.0))
    evidence.cohens_kappa = ctx.dual_judge_stats.get("cohens_kappa", 0.0) if ctx.dual_judge_stats else 0.0
    evidence.orchestration_log = ctx.orchestration_log

    # ── 认证恢复历史传递到证据 (recon → strike → report 数据一致性) ──
    # 数据流: recon (auth_state_manager) → RateLimitedTarget._auth_state.recovery_history
    #         → evidence.auth_recovery_log → report
    # 学术依据: Heroux et al. (arXiv:2403.04206) §3.2 — 认证失效恢复策略需审计
    auth_recovery_log: list[dict[str, str]] = []
    try:
        _target = ctx.objective_target
        if _target and hasattr(_target, "_auth_state") and _target._auth_state:
            auth_recovery_log = list(_target._auth_state.recovery_history)
            if auth_recovery_log:
                logger.info(
                    "Auth recovery log: %d recovery attempts recorded",
                    len(auth_recovery_log),
                )
    except Exception as e:
        logger.debug("Failed to extract auth recovery history: %s", e)

    if auth_recovery_log:
        # 注入到 attack_surface 供报告使用
        if hasattr(evidence, "attack_surface") and evidence.attack_surface:
            evidence.attack_surface["auth_recovery_attempts"] = len(auth_recovery_log)
            evidence.attack_surface["auth_recovery_log"] = auth_recovery_log

    report_path = await generate_report(ctx, evidence, output_dir)

    # ── 报告卡片 (最终输出, 阶段间传递: 全链路结果→报告) ──
    # R2 PyRIT 原生优先: 展示 native_output 目录路径 (原生 output 优先)
    _native_dir = output_dir / "native_output"
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

    # 资源清理: 两阶段分离 (生产级生命周期管理)
    # - 阶段 1: objective_target / extra_objective_targets — 每个 endpoint 独立, 需要在此清理
    #   清理后清除 ctx 引用, 防止悬挂指针
    # - 阶段 2: adversarial_target / scoring_target / converter_target — 攻击者 LLM, 跨 endpoint 复用
    # 学术依据: Heroux et al. (arXiv:2403.04206) §3.2 — 资源生命周期管理
    await _cleanup_resources(ctx, exclude_shared=True)


# ═══════════════════════════════════════════════════════════════════════════════
# 资源清理函数
# ═══════════════════════════════════════════════════════════════════════════════


async def _cleanup_resources(
    ctx: PipelineContext,
    *,
    exclude_shared: bool = False,
) -> None:
    """生产级资源清理 — 确保所有 Target 资源在流水线结束时正确释放。

    断点修复: 之前 main.py 在各阶段退出点 (包括正常结束) 时
    没有调用 RateLimitedTarget.cleanup() 和 Playwright 资源清理,
    导致 httpx.AsyncClient 连接泄漏、DB 引擎未释放、浏览器进程残留。

    清理顺序 (LIFO — 后创建的先清理):
        1. extra_objective_targets (port_expander 发现的额外目标)
        2. multi_turn_target (多轮攻击目标, 可能与 objective_target 相同)
        3. objective_target (主攻击目标, RateLimitedTarget.cleanup)
        4. Playwright 浏览器实例 (_browser, _playwright_instance)
        5. adversarial_target / scoring_target (辅助目标, 通常无状态)

    多 endpoint 模式 (exclude_shared=True):
        仅清理 objective 相关的 targets (1-4 + Playwright),
        跳过 adversarial/scoring/converter (5), 因为这些是攻击者自己的 LLM,
        在多 endpoint 循环中跨 endpoint 复用, 由循环结束后统一清理。
        清理后将 objective 引用置为 None, 确保下个 endpoint 重建 target。

    学术依据:
        - Heroux et al. (arXiv:2403.04206) §3.2 — 资源生命周期管理
        - PyRIT (arXiv:2407.01232) — dispose_db_engine() 资源释放
        - Greshake et al. (arXiv:2302.12173) — 逐个深度攻击需独立资源
    """
    _cleaned: set[int] = set()  # 避免重复清理同一对象 (objective_target == multi_turn_target)

    async def _cleanup_target(target: Any, label: str) -> None:
        """清理单个 Target 的资源 (幂等, 非阻塞)。"""
        if target is None:
            return
        target_id = id(target)
        if target_id in _cleaned:
            return
        _cleaned.add(target_id)
        try:
            if hasattr(target, "cleanup") and callable(target.cleanup):
                result = target.cleanup()
                if asyncio.iscoroutine(result):
                    await result
                logger.debug("Cleaned up %s: %s", label, type(target).__name__)
        except Exception as e:
            logger.debug("Cleanup %s failed (non-fatal): %s", label, e)

    # 1. 清理 extra_objective_targets (port_expander 发现的额外目标)
    for port, extra_target in getattr(ctx, "extra_objective_targets", {}).items():
        await _cleanup_target(extra_target, f"extra_objective_target[port={port}]")
    ctx.extra_objective_targets = {}  # 清除引用

    # 2. 清理 multi_turn_target (可能与 objective_target 相同, _cleaned 集去重)
    await _cleanup_target(getattr(ctx, "multi_turn_target", None), "multi_turn_target")
    ctx.multi_turn_target = None  # 清除引用

    # 3. 清理 objective_target (主攻击目标)
    await _cleanup_target(getattr(ctx, "objective_target", None), "objective_target")
    ctx.objective_target = None  # 清除引用

    # 4. 清理 Playwright 浏览器实例 (browser 模式)
    # 数据流: target_router._create_playwright_target → ctx._browser_context/_browser/_playwright_instance
    #         → main.py._cleanup_resources → browser.close() + playwright.stop()
    # 幂等: 清理后清除引用, 防止 finally 块重复清理
    _browser_context = getattr(ctx, "_browser_context", None)
    _browser = getattr(ctx, "_browser", None)
    _playwright_instance = getattr(ctx, "_playwright_instance", None)
    try:
        if _browser_context is not None:
            await _browser_context.close()
            ctx._browser_context = None  # 幂等: 清除引用
            logger.debug("Closed Playwright browser context")
    except Exception as e:
        logger.debug("Playwright browser context close failed (non-fatal): %s", e)
    try:
        if _browser is not None:
            await _browser.close()
            ctx._browser = None  # 幂等: 清除引用
            logger.debug("Closed Playwright browser")
    except Exception as e:
        logger.debug("Playwright browser close failed (non-fatal): %s", e)
    try:
        if _playwright_instance is not None:
            await _playwright_instance.stop()
            ctx._playwright_instance = None  # 幂等: 清除引用
            logger.debug("Stopped Playwright instance")
    except Exception as e:
        logger.debug("Playwright instance stop failed (non-fatal): %s", e)

    # 5. adversarial_target / scoring_target 通常是 OpenAIChatTarget (无 httpx client 需关闭)
    #    但如果被 RateLimitedTarget 包装过, cleanup 已在上面执行
    #    此处仅清理未被包装的裸 Target (如 _create_adversarial_target 直接创建的)
    # 多 endpoint 模式 (exclude_shared=True): 跳过共享 targets, 由循环结束后统一清理
    if not exclude_shared:
        # 5a. extra_adversarial_targets (多模型并行攻击的额外攻击者 LLM)
        for i, extra_adv in enumerate(getattr(ctx, "extra_adversarial_targets", [])):
            await _cleanup_target(extra_adv, f"extra_adversarial_target[{i}]")
        ctx.extra_adversarial_targets = []  # 清除引用
        await _cleanup_target(getattr(ctx, "adversarial_target", None), "adversarial_target")
        ctx.adversarial_target = None  # 清除引用
        await _cleanup_target(getattr(ctx, "scoring_target", None), "scoring_target")
        ctx.scoring_target = None  # 清除引用
        await _cleanup_target(getattr(ctx, "converter_target", None), "converter_target")
        ctx.converter_target = None  # 清除引用

    logger.info(
        "Resource cleanup complete (cleaned %d targets, shared_excluded=%s)",
        len(_cleaned),
        exclude_shared,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 入口
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\n[!] 用户中断, 退出")
        sys.exit(130)
