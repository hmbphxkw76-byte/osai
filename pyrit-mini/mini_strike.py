#!/usr/bin/env python3
"""mini_strike.py — 模块化 PyRIT 攻击链路入口。

攻击链路 (6 步, arXiv:2407.01232 — PyRIT 原生框架):
    ① Burp 拦截 → 读取 Burp 拦截的 HTTP 请求 (含 {PROMPT} 占位符)
    ② 侦察     → 解析 HTTP 请求, 探测目标能力指纹, 构建 HTTPTarget
    ③ 种子选取 → 从 YAML 种子文件加载攻击种子, 按历史 ASR 排序
    ④ Converter → 构建 L5 最优 Converter 链 (编码/说服/分解/混淆)
    ⑤ 攻击发送 → PyRIT 原生 PromptSendingAttack 多路径执行 + 多轮升级
    ⑥ 评分判定 → 双 Judge 交叉验证, ASR 统计, 证据收集 + 报告生成

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
    # 默认配置 (单轮 + L5 最优 Converter + 双 Judge 评分)
    python mini_strike.py

    # 全火力模式 (AI-300 考试首选 — 最高 ASR 配置)
    python mini_strike.py --offensive

    # 自定义参数
    python mini_strike.py --burp-request data/burp/request.txt \\
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

# UTF-8 强制 (Windows GBK 终端兼容)
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# 项目根目录加入 sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

logger = logging.getLogger(__name__)

# 全局取消事件 (SIGINT/SIGTERM 信号处理)
_cancel_event: asyncio.Event | None = None


def _signal_handler(signum: int, frame) -> None:
    """SIGINT/SIGTERM 信号处理器 — 取消所有 asyncio 任务."""
    logger.warning("收到信号 %d, 正在取消所有攻击任务...", signum)
    if _cancel_event is not None:
        _cancel_event.set()


# ═══════════════════════════════════════════════════════════════════════════════
# 攻击链路编排器 — 6 步完整链路
# ═══════════════════════════════════════════════════════════════════════════════

async def run(argv: list[str] | None = None) -> None:
    """主流程: 6 步完成一次完整攻击链路。

    攻击链路 (每步对应一个模块包):
        ① Burp 拦截 (recon/burp_parser.py) → ② 侦察 (recon/target_router.py)
        → ③ 种子选取 (arm/seed_ranker.py) → ④ Converter (arm/converter_presets.py)
        → ⑤ 攻击发送 (strike/executor.py + strike/escalation*.py)
        → ⑥ 评分判定 (assess/scorer.py + assess/asr_tracker.py)
        → 证据收集 + 报告 (report/evidence.py + report/generator.py)
    """
    global _cancel_event

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # ── 信号处理 ──
    _cancel_event = asyncio.Event()
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    from core.config import ensure_output_dir, get_output_dir, parse_args, setup_environment
    from core.context import PipelineContext, apply_relaxed_adversarial_schema
    from utils.display import print_banner, print_phase, print_summary

    print_banner()

    # ── 解析参数 + 输出目录 ──
    args = parse_args(argv)
    output_dir = get_output_dir(args)
    ensure_output_dir(output_dir)

    # rate_limit 环境变量 (供 target_router 中的 _create_adversarial_target 读取)
    rate_limit = getattr(args, "rate_limit", None)
    if rate_limit:
        os.environ["RATE_LIMIT"] = str(rate_limit)

    ctx = PipelineContext(args=args, output_dir=output_dir)
    ctx.scenario_result_id = getattr(args, "resume", None)

    # ── INIT: 初始化 PyRIT 环境 + Relaxed Adversarial Schema ──
    # arXiv:2306.05685 — Zheng et al.: LLM-as-a-Judge 鲁棒性
    # Monkey-patch PyRIT JSON schema, 使 rationale 和 last_response_summary 可选
    # 解决 DeepSeek-V3 / LongCat 等模型不严格遵循 JSON schema 导致的无限重试
    print_phase("INIT", "初始化 PyRIT 环境...")
    apply_relaxed_adversarial_schema()
    await setup_environment(output_dir)
    print_phase("INIT", f"输出目录: {output_dir}")

    # ═══════════════════════════════════════════════════════════════════════════
    # ① ② Burp 拦截 → 侦察: 解析 HTTP 请求 → 探测能力 → 构建 HTTPTarget
    # ═══════════════════════════════════════════════════════════════════════════
    print_phase("RECON", "① Burp 拦截 → ② 侦察: 解析 HTTP 请求 & 构建攻击目标...")
    from recon.target_router import create_target

    ctx.args.burp_request = args.burp_request
    try:
        await create_target(ctx)
    except ConnectionError as e:
        logger.error("目标不可用: %s", e)
        print_phase("ERROR", f"目标不可用: {e}")
        print_phase("ERROR", "请启动目标服务后重试。")
        sys.exit(1)
    except Exception as e:
        logger.error("目标构建失败: %s", e)
        print_phase("ERROR", f"目标构建失败: {e}")
        sys.exit(1)

    # 打印目标指纹
    if ctx.parsed_request:
        fp = ctx.parsed_request.target_fingerprint
        print_phase(
            "RECON",
            f"目标: {fp.get('app_type', 'Unknown')} | "
            f"认证: {fp.get('auth_type', 'Unknown')} | "
            f"路径: {ctx.parsed_request.path}",
        )
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
            },
            "reasoning": "三层探测 (被动指纹 + 主动能力 + 深度能力) 完成",
        })

    # ═══════════════════════════════════════════════════════════════════════════
    # ③ 种子选取: 加载 YAML 种子 → ASR 排序 → 能力自适应
    # ═══════════════════════════════════════════════════════════════════════════
    print_phase("ARM", "③ 种子选取: 加载攻击种子 & 按 ASR 排序...")
    from arm.converter_presets import build_converter_map
    from arm.seed_ranker import load_seeds
    from arm.technique_picker import augment_techniques_by_capability, filter_by_adversarial, select_techniques

    # 从目标指纹提取语言 + 能力 + 模型族 (能力自适应种子选取)
    target_language = None
    target_capabilities = None
    target_model_family = None
    if ctx.parsed_request:
        fp = ctx.parsed_request.target_fingerprint
        target_language = fp.get("language")
        target_capabilities = fp.get("capabilities")
        target_model_family = fp.get("model_family")

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
        print_phase("ARM", f"AutoDAN 3x 扩充至 {len(ctx.seeds)} 个种子")

    # ═══════════════════════════════════════════════════════════════════════════
    # ④ Converter 转换: 构建 L5 最优多路径 Converter 链
    # ═══════════════════════════════════════════════════════════════════════════
    print_phase("ARM", "④ Converter: 构建 L5 最优多路径链...")

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

    print_phase(
        "ARM",
        f"种子: {len(ctx.seeds)} | 技术: {len(ctx.techniques)} | "
        f"Converter: {sum(len(v) for v in ctx.converter_map.values())}",
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # ⑤ 攻击发送: PyRIT 原生多路径执行 + 多轮升级链
    # ═══════════════════════════════════════════════════════════════════════════
    print_phase("STRIKE", "⑤ 攻击发送: 执行 PyRIT 原生攻击...")
    from strike.escalation import check_and_escalate

    # 选择执行路径 (adaptive 模式 vs 多路径)
    # arXiv:2407.01232 — PyRIT 原生 PromptSendingAttack + SequentialAttack
    if args.techniques == "adaptive":
        print_phase("STRIKE", "使用 PyRIT 原生 TextAdaptive (ε-贪心自适应)...")
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

    # arXiv:2406.12609 — 升级链: Single→Best-of-N→Crescendo→TAP∥PAIR→GCG→native
    # 触发条件: 单轮 ASR < 90% (escalation_asr_threshold)
    # 中间退出: L1>=70% 跳过 L2-L4, L2>=80% 跳过 L3-L4 (节省 60-80% token)
    should_escalate = getattr(ctx.args, "escalation", True)
    if should_escalate:
        print_phase("STRIKE", "检查 ASR & 触发多轮升级链 (ASR < 90% 触发)...")
        try:
            await check_and_escalate(ctx, ctx.attack_results)
        except Exception as e:
            logger.error("升级失败: %s — 继续处理单轮结果", e)
            print_phase("STRIKE", f"升级部分失败: {e}")
    else:
        print_phase("STRIKE", "升级已禁用, 跳过...")

    # ═══════════════════════════════════════════════════════════════════════════
    # ⑥ 评分判定: 双 Judge 交叉验证 + ASR 统计 + 证据收集 + 报告
    # ═══════════════════════════════════════════════════════════════════════════
    print_phase("ASSESS", "⑥ 评分判定: 双 Judge 交叉验证 & ASR 统计...")
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

    # ── 证据收集 + 报告生成 ──
    print_phase("REPORT", "收集证据 & 生成安全报告...")
    from report.evidence import EvidenceCollector
    from report.generator import generate_report

    target_fingerprint = {}
    if ctx.parsed_request:
        target_fingerprint = ctx.parsed_request.target_fingerprint

    # R6 §6.6 — Evidence records MUST include ALL fields non-empty:
    # jailbreak_prompt, harmful_output, conversation_history, scorer_results,
    # converter_log, arxiv_reference, validation_runs, testing_conditions,
    # confidence, mitre_technique_id
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

    report_path = await generate_report(ctx, evidence, output_dir)

    # ── 完成 ──
    print_summary(
        total_attacks=evidence.total_attacks,
        successful_attacks=evidence.successful_attacks,
        overall_asr=ctx.overall_asr,
        report_path=str(report_path),
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
