"""攻击链路编排器 — 从 main.py 提取的多端点循环 + 6 阶段控制。

承载:
    - 多 endpoint 外层循环 (arXiv:2302.12173 — 逐个深度攻击)
    - 阶段控制 (recon → arm → strike → escalate → assess → report)
    - 联合 ASR 统计 (arXiv:2310.08419 — 1 - ∏(1 - ASRᵢ))
    - 生产级信号中断 + 资源清理 (try/finally)
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)


async def run_attack_pipeline(ctx: "PipelineContext") -> None:
    """主流程: 多 endpoint 逐个深度攻击 + 联合 ASR。

    阶段对应模块包 (--stage 控制退出点):
        ① recon     (recon/burp_parser.py + recon/target_router.py)
        ② arm       (arm/seed_ranker.py + arm/converter_presets.py + arm/technique_picker.py)
        ③ strike    (strike/executor.py)
        ④ escalate  (strike/escalation.py + strike/escalation_level1/2/3.py)
        ⑤ assess    (assess/scorer.py + assess/asr_tracker.py + assess/asr_stats.py)
        ⑥ report    (report/evidence.py + report/generator.py)

    多 endpoint 支持 (arXiv:2302.12173 Greshake — 逐个深度攻击):
        不指定 --burp → 自动扫描 config/targets/burp/*.txt 全部文件
        --burp MM_05 → 指定单个 endpoint (仍走多端点路径, 确保统一目录结构)
        --burp MM_05 --burp MM_03 --burp MM_08 → 指定多个 endpoint
        → 优先级排序: 按能力指纹排序 (MCP > function_calling > RAG > workflow > chat)
        → 对每个 endpoint 执行完整 6 阶段深度攻击链路
        → 最终汇总联合 ASR (arXiv:2310.08419 — 1 - ∏(1 - ASRᵢ))
    """
    from core.cleanup import cleanup_resources, has_residual_resources
    from core.config import ensure_output_dir
    from core.logging_config import switch_log_file
    from utils.display import (
        _C_BOLD,
        _C_RESET,
        print_joint_asr_card,
        print_phase,
        print_status,
    )

    args = ctx.args
    output_dir = ctx.output_dir

    # ── 多 endpoint 检测 ──
    burp_list = _resolve_burp_list(args)

    # ── 非 Burp 路径 (LiteLLM/OpenAI API/Browser) 不走多 endpoint 循环 ──
    _non_burp_mode = _detect_non_burp_mode(args)

    if _non_burp_mode:
        # 非 Burp 路径 (LiteLLM/OpenAI API/Browser): 直接走单次执行逻辑
        ctx.args.burp = burp_list[0] if burp_list else "request"
        await run_single_endpoint(ctx, output_dir)
        await cleanup_resources(ctx)
        return

    # ── 增量借鉴: 将运行标签写入 CentralMemory ──
    await _setup_memory_labels(ctx)

    # ── 增量借鉴: 动态注册 Initializer (--add-initializer) ──
    await _register_dynamic_initializers(ctx)

    # ═══════════════════════════════════════════════════════════════════════════
    # 多 endpoint 外层循环 (arXiv:2302.12173 — 逐个深度攻击)
    # 对每个 endpoint 执行完整 6 阶段攻击链路, 最终汇总联合 ASR
    # 默认多端点模式: 即使只有 1 个 endpoint 也走多端点路径, 确保统一目录结构
    # ═══════════════════════════════════════════════════════════════════════════

    # ── 优先级排序: 按能力指纹排序 endpoint ──
    from recon.endpoint_sorter import sort_endpoints_by_priority
    sorted_endpoints = sort_endpoints_by_priority(burp_list)

    # 输出排序结果
    _print_endpoint_sort_results(sorted_endpoints)

    multi_endpoint_results: list[dict[str, Any]] = []

    for idx, ep_info in enumerate(sorted_endpoints):
        burp_path = ep_info["burp_path"]
        burp_name = ep_info["burp_name"]
        ctx._current_endpoint_idx = idx

        _print_endpoint_header(idx, len(burp_list), burp_name)

        # 为每个 endpoint 创建独立的子输出目录
        ep_output_dir = output_dir / f"endpoint_{idx + 1}_{burp_name}"
        ensure_output_dir(ep_output_dir)
        ctx.output_dir = ep_output_dir

        # 切换文件日志到当前 endpoint 的子目录
        switch_log_file(ep_output_dir)

        # 独立初始化 PyRIT DB (每 endpoint 独立 DB 避免并发冲突)
        from core.config import setup_environment
        await setup_environment(ep_output_dir)

        # R8 §8.3: setup_environment 清除 CentralMemory 单例后, memory labels 丢失
        if ctx.memory_labels:
            await _re_set_memory_labels(ctx, burp_name)

        # 设置当前 endpoint 的 burp 路径
        ctx.args.burp = burp_path

        # 重置 ctx 状态 (每个 endpoint 独立攻击)
        _reset_endpoint_state(ctx)

        try:
            ep_result = await run_single_endpoint_to_result(
                ctx, ep_output_dir, burp_name,
            )
            multi_endpoint_results.append(ep_result)
        except ConnectionError as e:
            logger.error("Endpoint %s 不可用: %s", burp_name, e)
            from utils.display import print_error
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
            from utils.display import print_error
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

    # FileHandler 仍指向最后一个 endpoint 子目录, 需切回顶层
    switch_log_file(output_dir)

    from assess.joint_asr import build_joint_summary, save_joint_report
    joint_summary = build_joint_summary(multi_endpoint_results)
    joint_report_path = save_joint_report(joint_summary, output_dir)

    _print_joint_asr_summary(joint_summary, joint_report_path)

    print_status("JOINT", "DONE", f"Joint ASR = {joint_summary['joint_asr']:.1f}%", ok=True)

    # 资源清理
    await cleanup_resources(ctx)


async def run_single_endpoint_to_result(
    ctx: "PipelineContext",
    ep_output_dir: Path,
    burp_name: str,
) -> dict[str, Any]:
    """对单个 endpoint 执行完整 6 阶段攻击链路, 返回结果摘要。

    学术依据: Greshake et al. (arXiv:2302.12173) — 逐个深度攻击

    Args:
        ctx: 流水线上下文 (已重置状态)。
        ep_output_dir: 该 endpoint 的独立输出目录。
        burp_name: endpoint 名称 (用于报告)。

    Returns:
        该 endpoint 的攻击结果摘要字典。
    """
    await run_single_endpoint(ctx, ep_output_dir)

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


async def run_single_endpoint(
    ctx: "PipelineContext",
    output_dir: Path,
) -> None:
    """对单个 endpoint 执行完整 6 阶段攻击链路。

    这是原有 run() 函数的核心逻辑, 提取为独立函数以支持多 endpoint 循环。
    学术依据: PyRIT (arXiv:2407.01232) — SequentialAttack + 完整攻击链路

    Args:
        ctx: 流水线上下文。
        output_dir: 输出目录。
    """
    from core.cleanup import cleanup_resources

    args = ctx.args

    # ═══════════════════════════════════════════════════════════════════════════
    # ① Recon: 解析 HTTP 请求 → 探测能力 → 构建 HTTPTarget
    # ═══════════════════════════════════════════════════════════════════════════
    await _run_recon_phase(ctx, output_dir)

    # ── --stage recon: 只执行侦察, 输出报告后退出 ──
    if getattr(args, "stage", None) == "recon":
        from core.cleanup import cleanup_resources
        await cleanup_resources(ctx, exclude_shared=True)
        return

    # ═══════════════════════════════════════════════════════════════════════════
    # ②.5 攻击面分类 + 技术标签映射
    # ═══════════════════════════════════════════════════════════════════════════
    await _run_synergy_phase(ctx)

    # ═══════════════════════════════════════════════════════════════════════════
    # ②.7 Scenario 路由决策
    # ═══════════════════════════════════════════════════════════════════════════
    await _run_scenario_routing(ctx)

    # ═══════════════════════════════════════════════════════════════════════════
    # ②.6 目标感知自动 L4 优化
    # ═══════════════════════════════════════════════════════════════════════════
    await _run_auto_l4_optimization(ctx)

    # ═══════════════════════════════════════════════════════════════════════════
    # ③ ARM: 种子选取 + 技术选择 + Converter 链构建
    # ═══════════════════════════════════════════════════════════════════════════
    await _run_arm_phase(ctx)

    # ── --stage arm: 武器化完成, 输出清单后退出 ──
    if getattr(args, "stage", None) == "arm":
        await cleanup_resources(ctx, exclude_shared=True)
        return

    # ═══════════════════════════════════════════════════════════════════════════
    # ④ STRIKE: 攻击执行 + 升级链
    # ═══════════════════════════════════════════════════════════════════════════
    await _run_strike_phase(ctx)

    # ═══════════════════════════════════════════════════════════════════════════
    # ⑤ ASSESS: 评分判定
    # ═══════════════════════════════════════════════════════════════════════════
    await _run_assess_phase(ctx)

    # ═══════════════════════════════════════════════════════════════════════════
    # ⑥ REPORT: 证据收集 + 报告生成
    # ═══════════════════════════════════════════════════════════════════════════
    await _run_report_phase(ctx, output_dir)

    # 资源清理: 两阶段分离
    await cleanup_resources(ctx, exclude_shared=True)


# ═══════════════════════════════════════════════════════════════════════════════
# 阶段实现 — 私有函数
# ═══════════════════════════════════════════════════════════════════════════════


async def _run_recon_phase(ctx: "PipelineContext", output_dir: Path) -> None:
    """① Recon 阶段: 解析 HTTP 请求 & 构建攻击目标。"""
    from utils.display import print_phase, print_recon_card, print_status

    print_phase("RECON", "解析 HTTP 请求 & 构建攻击目标...")
    from recon.target_router import create_target

    try:
        await create_target(ctx)
    except ConnectionError as e:
        logger.error("目标不可用: %s", e)
        from utils.display import print_error
        print_error(f"目标不可用: {e}\n请启动目标服务后重试。")
        raise
    except Exception as e:
        logger.error("目标构建失败: %s", e)
        from utils.display import print_error
        print_error(f"目标构建失败: {e}")
        raise

    # 打印侦察结果卡片
    _is_recon_only = getattr(ctx.args, "stage", None) == "recon"
    if ctx.parsed_request and not _is_recon_only:
        print_recon_card(ctx)

    # 编排日志: 记录侦察决策
    _record_recon_orchestration(ctx)

    # --stage recon 退出报告
    if _is_recon_only:
        from recon.recon_report import print_recon_report
        if ctx.parsed_request:
            print_recon_report(ctx.parsed_request, output_dir=output_dir)
        print_status("RECON", "DONE", "侦察阶段完成", ok=True)


async def _run_synergy_phase(ctx: "PipelineContext") -> None:
    """②.5 攻击面分类 + 技术标签映射。"""
    args = ctx.args
    _synergy_enabled_flag = getattr(args, "synergy", True)
    if not _synergy_enabled_flag or not ctx.parsed_request:
        return

    from utils.display import print_phase, print_status
    print_phase("SYNERGY", "攻击面分类 + 技术标签映射...")
    try:
        # v61: SynergyOrchestrator 从 data/ 迁至 core/scenario_router.py
        from core.scenario_router import SynergyOrchestrator

        _burp_raw_content = None
        _burp_file_path = Path(ctx.args.burp)
        if not _burp_file_path.is_absolute():
            _burp_file_path = Path("config/targets/burp") / _burp_file_path
        if not str(_burp_file_path).endswith(".txt"):
            _burp_file_path = _burp_file_path.with_suffix(".txt")
        if _burp_file_path.exists():
            _burp_raw_content = _burp_file_path.read_text(encoding="utf-8", errors="ignore")

        _orchestrator = SynergyOrchestrator()
        _syn_cfg = _orchestrator.build_synergy_config(
            burp_profile_name=ctx.args.burp.replace(".txt", ""),
            burp_raw_content=_burp_raw_content,
        )
        ctx.synergy_config = _syn_cfg
        logger.info("Synergy config: %s", _syn_cfg.summary())

        _tags_str = ", ".join(_syn_cfg.technique_tags) if _syn_cfg.technique_tags else "all (no filter)"
        print_status(
            "SYNERGY",
            "CLASSIFIED",
            f"攻击面={_syn_cfg.attack_surface}, "
            f"技术标签=[{_tags_str}], "
            f"置信度={_syn_cfg.confidence:.2f}",
            ok=True,
        )
    except Exception as e:
        logger.warning("Synergy analysis failed (non-fatal, 回退默认): %s", e)
        ctx.synergy_config = None


async def _run_scenario_routing(ctx: "PipelineContext") -> None:
    """②.7 Scenario 路由决策 (攻击面→技术标签映射)。"""
    args = ctx.args
    _scenario_enabled = getattr(args, "scenario_enabled", True)
    if not _scenario_enabled or not ctx.synergy_config:
        return

    from utils.display import print_status
    from core.scenario_router import apply_scenario_overrides, get_router

    _router = get_router()
    _scenario_name, _scenario_config = _router.select_scenario(
        classification=type('ClassificationResult', (), {
            'attack_surface': ctx.synergy_config.attack_surface,
            'confidence': ctx.synergy_config.confidence,
            'evidence': ctx.synergy_config.evidence,
        })(),
        user_override=getattr(args, "scenario", None),
    )
    ctx.scenario_config = _scenario_config
    ctx.scenario_name = _scenario_name

    apply_scenario_overrides(ctx, _scenario_config, args)

    _filter = getattr(args, "adaptive_technique_filter", None)
    _filter_str = ", ".join(_filter) if _filter else "all (no filter)"
    logger.info("Scenario selected: %s, technique_filter=%s", _scenario_name, _filter_str)
    print_status(
        "SCENARIO",
        "SELECTED",
        f"攻击面={ctx.synergy_config.attack_surface}, "
        f"Scenario={_scenario_name}, "
        f"技术过滤=[{_filter_str}], "
        f"置信度={ctx.synergy_config.confidence:.2f}",
        ok=True,
    )


async def _run_auto_l4_optimization(ctx: "PipelineContext") -> None:
    """②.6 目标感知自动 L4 优化 (高置信度 Agent/MCP 目标跳过 L1-L3).

    C2 合规: max_seeds 限制值从 defaults.yaml (auto_l4_max_seeds) 读取,
    不再是硬编码常量, 可通过配置上调以提升 ASR 上限.
    """
    args = ctx.args
    _auto_l4_enabled = getattr(args, "auto_l4_optimization_enabled", True)
    _auto_l4_threshold = getattr(args, "auto_l4_confidence_threshold", 0.8)
    _auto_l4_max_seeds = getattr(args, "auto_l4_max_seeds", 8)
    _auto_l4_surfaces = set(getattr(args, "auto_l4_agent_surfaces", [
        "mcp_server", "multi_agent_system", "rag_system",
    ]))
    if not _auto_l4_enabled or not ctx.synergy_config:
        return

    _surface = ctx.synergy_config.attack_surface
    _confidence = ctx.synergy_config.confidence
    if _surface in _auto_l4_surfaces and _confidence >= _auto_l4_threshold:
        _user_specified_levels = getattr(args, "escalation_levels_parsed", None)
        if _user_specified_levels is None:
            setattr(args, "escalation_levels_parsed", {4})
            _user_max_seeds = getattr(args, "max_seeds", None)
            if _user_max_seeds is None or _user_max_seeds > _auto_l4_max_seeds:
                setattr(args, "max_seeds", _auto_l4_max_seeds)
                logger.info(
                    "Auto L4 optimization: max_seeds limited to %d (specialty seeds only)",
                    _auto_l4_max_seeds,
                )
            logger.info(
                "Auto L4 optimization activated: surface=%s, confidence=%.2f >= %.2f, "
                "escalation_levels set to {4} (skip L1-L3)",
                _surface, _confidence, _auto_l4_threshold,
            )
            from utils.display import print_status
            print_status(
                "AUTO-L4",
                "ESCALATION",
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
                    "auto_l4_max_seeds": _auto_l4_max_seeds,
                },
                "output": {
                    "escalation_levels": [4],
                    "max_seeds": getattr(args, "max_seeds", _auto_l4_max_seeds),
                    "seed_strategy": "specialty_only",
                },
                "reasoning": (
                    f"Target-aware L4 optimization per InjecAgent (arXiv:2307.00929) + "
                    f"Eidam et al. (arXiv:2407.16924): confidence={_confidence:.2f} >= "
                    f"{_auto_l4_threshold:.2f}, surface={_surface} in auto_l4_surfaces. "
                    f"Using specialty seeds only (MCP/RAG/Agent), max_seeds={_auto_l4_max_seeds}"
                ),
            })


async def _run_arm_phase(ctx: "PipelineContext") -> None:
    """③ ARM 阶段: 种子选取 + 技术选择 + Converter 链构建。"""
    from utils.display import print_phase, print_arm_card, print_status, print_arm_highlights

    args = ctx.args
    print_phase("ARM", "种子选取 & ASR 排序...")

    from arm.converter_presets import build_converter_map, _classify_target_type
    from arm.seed_ranker import load_seeds
    from arm.technique_picker import augment_techniques_by_capability, filter_by_adversarial, select_techniques

    # 从目标指纹提取语言 + 能力 + 模型族
    target_language, target_capabilities, target_model_family = _extract_target_profile(ctx)

    # 种子加载
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

    # 编排日志
    _record_arm_seed_orchestration(ctx, target_language, target_capabilities, target_model_family)

    # P1-2: OpenAPI 种子生成
    await _generate_openapi_seeds(ctx)

    # AutoDAN 扩充
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

    # Converter 链构建
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

    # Converter 链
    if args.converters == "none":
        chain_names = []
    elif args.converters == "auto":
        chain_names = ["l5_optimal"]
    else:
        chain_names = args.converters.split(",")

    _target_fingerprint = None
    if ctx.parsed_request:
        _target_fingerprint = ctx.parsed_request.target_fingerprint
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

    # ARM 阶段输出
    _is_arm_only_stage = getattr(args, "stage", None) == "arm"
    if _is_arm_only_stage:
        print_arm_card(ctx)

    _arm_target_type = _get_arm_target_type(ctx)
    print_status(
        "ARM", "READY",
        f"Seeds={len(ctx.seeds)} | Techs={len(ctx.techniques)} | "
        f"Converters={sum(len(v) for v in ctx.converter_map.values())} | "
        f"Target: {_arm_target_type} | Roles: 3-actor",
        ok=True,
    )

    if not _is_arm_only_stage:
        try:
            print_arm_highlights(ctx)
        except Exception:
            pass


async def _run_strike_phase(ctx: "PipelineContext") -> None:
    """④ STRIKE 阶段: 攻击执行 + 升级链。"""
    from utils.display import (
        print_phase, print_status, print_strike_report_async,
        print_escalate_report_async, print_strike_start_banner,
        print_strike_phase_summary, _is_success,
    )

    args = ctx.args
    print_phase("STRIKE", "执行 PyRIT 原生攻击...")

    # 进度展示横幅
    try:
        _ep_idx = getattr(ctx, "_current_endpoint_idx", None)
        _total_eps = None
        _burp_list = getattr(args, "_burp_list", None)
        if _burp_list and len(_burp_list) >= 1:
            _total_eps = len(_burp_list)
        print_strike_start_banner(ctx, total_endpoints=_total_eps, current_endpoint_idx=_ep_idx)
    except Exception:
        pass

    _is_dry_run = getattr(args, "dry_run", False)

    if _is_dry_run:
        logger.info("[DRY-RUN] 跳过攻击执行 (strike 阶段) — 零 token 验证模式")
        print_phase("STRIKE", "[DRY-RUN] 跳过攻击执行 — 验证数据流贯通")
        ctx.attack_results = {}
    else:
        # 选择执行路径
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

    # STRIKE 阶段过程性输出
    if not _is_dry_run:
        await print_strike_report_async(ctx)

    # STRIKE DONE 摘要
    if not _is_dry_run:
        try:
            _strike_elapsed = getattr(ctx, "_strike_elapsed", 0.0)
            _total_results = sum(len(v) for v in ctx.attack_results.values())
            _total_success = sum(
                1 for results in ctx.attack_results.values()
                for r in results if _is_success(r)
            )
            print_strike_phase_summary(
                ctx,
                total_results=_total_results,
                total_success=_total_success,
                elapsed_seconds=_strike_elapsed,
            )
        except Exception:
            pass

    # STRIKE 阶段编排日志
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

    # --stage strike 退出
    if getattr(args, "stage", None) == "strike":
        print_status("STRIKE", "DONE", "单轮攻击完成", ok=True)
        return

    # 升级链
    should_escalate = getattr(ctx.args, "escalation", True)
    if _is_dry_run:
        logger.info("[DRY-RUN] 跳过升级链 (escalate 阶段) — 零 token 验证模式")
        print_status("ESCALATE", "DRY-RUN", "跳过升级链 — 零 token 验证")
    elif should_escalate:
        print_phase("ESCALATE", "检查 ASR & 触发多轮升级链 (ASR<90% 触发)...")
        from strike.escalation import check_and_escalate
        try:
            await check_and_escalate(ctx, ctx.attack_results)
        except Exception as e:
            logger.error("升级失败: %s — 继续处理单轮结果", e)
            print_phase("ESCALATE", f"升级部分失败: {e}")
    else:
        print_status("ESCALATE", "SKIP", "升级已禁用")

    # ESCALATE 编排日志
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

    # 升级链结果展示
    if not _is_dry_run:
        await print_escalate_report_async(ctx)

    # --stage escalate 退出
    if getattr(args, "stage", None) == "escalate":
        print_status("ESCALATE", "DONE", "升级链完成", ok=True)
        return


async def _run_assess_phase(ctx: "PipelineContext") -> None:
    """⑤ ASSESS 阶段: 评分判定 + ASR 统计。"""
    from utils.display import print_phase, print_assess_card, print_status

    args = ctx.args
    print_phase("ASSESS", "双 Judge 交叉验证 & ASR 统计...")

    from assess.asr_tracker import (
        collect_dual_judge_stats,
        compute_asr,
        compute_overall_asr,
        compute_wilson_score_interval,
        precompute_outcomes_async,
        save_asr_history,
        compute_cohens_kappa,
    )

    _assess_reset_stats = not getattr(ctx.args, "escalation", True)
    try:
        await precompute_outcomes_async(ctx.attack_results, score_all=False, reset_stats=_assess_reset_stats)
    except Exception as e:
        logger.error("评分失败: %s — 继续处理未评分结果", e)

    ctx.asr_per_technique = compute_asr(ctx.attack_results)
    ctx.overall_asr = compute_overall_asr(ctx.asr_per_technique)
    save_asr_history(ctx.asr_per_technique, attack_results=ctx.attack_results)

    # 更新 asr_priors.yaml
    if ctx.parsed_request:
        model_family = ctx.parsed_request.target_fingerprint.get("model_family")
        if model_family:
            from arm.seed_ranker import update_asr_priors
            update_asr_priors(model_family, ctx.asr_per_technique)

    # Wilson Score CI
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

    # 双 Judge 统计
    ctx.dual_judge_stats = collect_dual_judge_stats(ctx)
    if ctx.dual_judge_stats:
        kappa = compute_cohens_kappa(
            ctx.dual_judge_stats.get("agreements", 0),
            ctx.dual_judge_stats.get("disagreements", 0),
        )
        ctx.dual_judge_stats["cohens_kappa"] = kappa
        _log_dual_judge_stats(ctx.dual_judge_stats)

    # 终端展示
    print_assess_card(ctx)

    # --stage assess 退出
    if getattr(args, "stage", None) == "assess":
        print_status("ASSESS", "DONE", "评分完成", ok=True)
        return

    # ASSESS 编排日志
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


async def _run_report_phase(ctx: "PipelineContext", output_dir: Path) -> None:
    """⑥ REPORT 阶段: 证据收集 + 报告生成。"""
    from utils.display import print_phase, print_report_card, print_status

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

    # 认证恢复历史传递到证据
    auth_recovery_log = _extract_auth_recovery_log(ctx)
    if auth_recovery_log:
        if hasattr(evidence, "attack_surface") and evidence.attack_surface:
            evidence.attack_surface["auth_recovery_attempts"] = len(auth_recovery_log)
            evidence.attack_surface["auth_recovery_log"] = auth_recovery_log

    # 报告生成编排日志 (必须在 generate_report 之前)
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


# ═══════════════════════════════════════════════════════════════════════════════
# 辅助函数
# ═══════════════════════════════════════════════════════════════════════════════


def _resolve_burp_list(args: Any) -> list[str]:
    """从 CLI 参数解析 burp_list。"""
    burp_list: list[str] = getattr(args, "_burp_list", None)
    if burp_list is None:
        burp_val = args.burp
        if isinstance(burp_val, list):
            burp_list = burp_val
        else:
            burp_list = [burp_val] if burp_val else ["request"]
    return burp_list


def _detect_non_burp_mode(args: Any) -> bool:
    """检测是否为非 Burp 路径 (LiteLLM/OpenAI API/Browser)。"""
    return bool(
        getattr(args, "litellm_model", None) or os.environ.get("LITELLM_MODEL")
        or (getattr(args, "target_api_endpoint", None) and getattr(args, "target_api_key", None))
        or getattr(args, "browser_url", None)
    )


async def _setup_memory_labels(ctx: "PipelineContext") -> None:
    """将运行标签写入 CentralMemory。"""
    if not ctx.memory_labels:
        return
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


async def _re_set_memory_labels(ctx: "PipelineContext", burp_name: str) -> None:
    """为每个 endpoint 重新设置 memory labels (setup_environment 后调用)。"""
    try:
        from pyrit.memory import CentralMemory
        _ep_memory = CentralMemory.get_memory_instance()
        if hasattr(_ep_memory, "set_labels"):
            _ep_memory.set_labels(ctx.memory_labels)
        logger.debug("Memory labels re-set for endpoint %s", burp_name)
    except Exception as e:
        logger.debug("Failed to re-set memory labels for endpoint %s: %s", burp_name, e)


async def _register_dynamic_initializers(ctx: "PipelineContext") -> None:
    """动态注册 Initializer (--add-initializer)。"""
    initializer_specs = getattr(ctx.args, "initializer_specs", None)
    if initializer_specs:
        from core.initializer_registry import register_initializers_async
        await register_initializers_async(initializer_specs, ctx)
        logger.info("Registered %d dynamic initializer(s)", len(initializer_specs))


def _reset_endpoint_state(ctx: "PipelineContext") -> None:
    """重置 ctx 状态 (每个 endpoint 独立攻击)。"""
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
    ctx.scenario_result = None

    # 重置 assess 阶段的全局统计计数器
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


def _print_endpoint_sort_results(sorted_endpoints: list[dict[str, Any]]) -> None:
    """输出 endpoint 排序结果。"""
    from utils.display import _C_BOLD, _C_RESET
    print()
    print(f"{_C_BOLD}{'═' * 60}{_C_RESET}")
    print(f"{_C_BOLD}  ► [RECON] Endpoint 优先级排序 (能力指纹){_C_RESET}")
    _files_str = ", ".join(Path(ep['burp_path']).name for ep in sorted_endpoints)
    print(f"  config/targets/burp/ — {_files_str}")
    print(f"{_C_BOLD}{'═' * 60}{_C_RESET}")
    for i, ep in enumerate(sorted_endpoints):
        caps_str = ", ".join(sorted(ep["capabilities"])) if ep["capabilities"] else "chat"
        print(
            f"  {i + 1}. {_C_BOLD}{ep['burp_name']}{_C_RESET} "
            f"(priority={ep['priority_score']}, caps={caps_str})"
        )


def _print_endpoint_header(idx: int, total: int, burp_name: str) -> None:
    """输出 endpoint 开始头部。"""
    from utils.display import _C_BOLD, _C_RESET
    print()
    print(f"{_C_BOLD}{'═' * 60}{_C_RESET}")
    print(f"{_C_BOLD}  Endpoint {idx + 1}/{total}: {burp_name}{_C_RESET}")
    print(f"{_C_BOLD}{'═' * 60}{_C_RESET}")


def _print_joint_asr_summary(joint_summary: dict[str, Any], report_path: Path) -> None:
    """输出联合 ASR 汇总。"""
    from utils.display import _C_BOLD, _C_RESET, print_joint_asr_card
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
        report_path=str(report_path),
    )


def _extract_target_profile(ctx: "PipelineContext") -> tuple[str | None, str | None, str | None]:
    """从目标指纹提取语言 + 能力 + 模型族。"""
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
    return target_language, target_capabilities, target_model_family


async def _generate_openapi_seeds(ctx: "PipelineContext") -> None:
    """从 OpenAPI 发现结果生成定向参数注入种子。"""
    if not ctx.parsed_request:
        return
    _fp = ctx.parsed_request.target_fingerprint
    _openapi_endpoints = _fp.get("openapi_endpoints", [])
    if not _openapi_endpoints:
        return
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
            from utils.display import print_status
            print_status("ARM", "OPENAPI", f"追加 {len(_openapi_seed_groups)} 个 OpenAPI 定向种子")
    except Exception as e:
        logger.warning("P1-2: OpenAPI seed generation failed (non-fatal): %s", e)


def _get_arm_target_type(ctx: "PipelineContext") -> str:
    """获取 ARM 阶段的目标类型描述。"""
    if not ctx.parsed_request:
        return "unknown"
    _fp = ctx.parsed_request.target_fingerprint
    _caps = _fp.get("capabilities", "") or ""
    if "mcp" in _caps.lower() or "mcp_protocol" in _caps.lower():
        return "mcp_agent"
    elif _fp.get("app_type") in ("chat", "responses", "litellm"):
        return "llm_chat"
    elif _fp.get("app_type") == "browser":
        return "browser"
    return "http_api"


def _record_recon_orchestration(ctx: "PipelineContext") -> None:
    """记录侦察阶段的编排决策。"""
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
        if getattr(ctx.args, "litellm_model", None) or os.environ.get("LITELLM_MODEL"):
            _recon_mode = "litellm"
            _recon_endpoint = getattr(ctx.args, "litellm_model", None) or os.environ.get("LITELLM_MODEL", "")
        elif getattr(ctx.args, "target_api_endpoint", None) and getattr(ctx.args, "target_api_key", None):
            _recon_mode = getattr(ctx.args, "target_api_type", "chat")
            _recon_endpoint = getattr(ctx.args, "target_api_endpoint", "")
        elif getattr(ctx.args, "browser_url", None):
            _recon_mode = "browser"
            _recon_endpoint = getattr(ctx.args, "browser_url", "")
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


def _record_arm_seed_orchestration(
    ctx: "PipelineContext",
    target_language: str | None,
    target_capabilities: str | None,
    target_model_family: str | None,
) -> None:
    """记录 ARM 阶段种子选取的编排决策。"""
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
            "seed_files": ctx.args.seeds,
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


def _get_result_outcome(result: Any) -> str:
    """获取攻击结果的 outcome (内联简版, 避免循环导入)。"""
    from assess.asr_stats import _get_outcome
    return _get_outcome(result)


def _extract_auth_recovery_log(ctx: "PipelineContext") -> list[dict[str, str]]:
    """提取认证恢复历史。"""
    auth_recovery_log: list[dict[str, str]] = []
    try:
        _target = ctx.objective_target
        if _target and hasattr(_target, "_auth_state") and _target._auth_state:
            auth_recovery_log = list(_target._auth_state.recovery_history)
            if auth_recovery_log:
                logger.info("Auth recovery log: %d recovery attempts recorded", len(auth_recovery_log))
    except Exception as e:
        logger.debug("Failed to extract auth recovery history: %s", e)
    return auth_recovery_log


def _log_dual_judge_stats(dual_judge_stats: dict[str, Any]) -> None:
    """输出双 Judge 统计日志。"""
    kappa = dual_judge_stats.get("cohens_kappa", 0)
    logging.info(
        "Dual Judge: total=%d, dual_invoked=%d (%.1f%%), "
        "agreements=%d, disagreements=%d, Cohen's Kappa=%.3f",
        dual_judge_stats.get("total_scored", 0),
        dual_judge_stats.get("dual_judge_invoked", 0),
        dual_judge_stats.get("dual_judge_rate", 0.0),
        dual_judge_stats.get("agreements", 0),
        dual_judge_stats.get("disagreements", 0),
        kappa,
    )
    # OR aggregation false-positive tracking log
    or_stats = dual_judge_stats.get("or_aggregation", {})
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
    sm = dual_judge_stats.get("scorer_metrics", {})
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
