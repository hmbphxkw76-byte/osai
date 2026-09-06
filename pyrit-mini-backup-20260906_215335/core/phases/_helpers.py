"""辅助函数 — orchestrator 阶段的通用工具函数.

从 core/orchestrator.py 提取的辅助函数, 包括:
    - Burp 列表解析与模式检测
    - Endpoint 排序 / 头部 / 结果输出
    - Memory labels / dynamic initializers 注册
    - Endpoint 状态重置
    - Target profile 提取
    - Auth recovery log 提取
    - 编排日志记录 (recon / arm)
    - 联合 ASR 汇总输出
    - 双 Judge 统计日志输出
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

    from core.context import PipelineContext

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Burp 解析 + 模式检测
# ═══════════════════════════════════════════════════════════════════════════════


def _resolve_burp_list(args: Any) -> list[str]:
    """从 CLI 参数解析 burp_list."""
    burp_list: list[str] = getattr(args, "_burp_list", None)
    if burp_list is None:
        burp_val = args.burp
        if isinstance(burp_val, list):
            burp_list = burp_val
        else:
            burp_list = [burp_val] if burp_val else ["request"]
    return burp_list


def _detect_non_burp_mode(args: Any) -> bool:
    """检测是否为非 Burp 路径 (LiteLLM/OpenAI API/Browser)."""
    return bool(
        getattr(args, "litellm_model", None) or os.environ.get("LITELLM_MODEL")
        or (getattr(args, "target_api_endpoint", None) and getattr(args, "target_api_key", None))
        or getattr(args, "browser_url", None)
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Memory Labels + Dynamic Initializers
# ═══════════════════════════════════════════════════════════════════════════════


async def _setup_memory_labels(ctx: "PipelineContext") -> None:
    """将运行标签写入 CentralMemory."""
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
    """为每个 endpoint 重新设置 memory labels (setup_environment 后调用)."""
    try:
        from pyrit.memory import CentralMemory
        _ep_memory = CentralMemory.get_memory_instance()
        if hasattr(_ep_memory, "set_labels"):
            _ep_memory.set_labels(ctx.memory_labels)
        logger.debug("Memory labels re-set for endpoint %s", burp_name)
    except Exception as e:
        logger.debug("Failed to re-set memory labels for endpoint %s: %s", burp_name, e)


async def _register_dynamic_initializers(ctx: "PipelineContext") -> None:
    """动态注册 Initializer (--add-initializer)."""
    initializer_specs = getattr(ctx.args, "initializer_specs", None)
    if initializer_specs:
        from core.initializer_registry import register_initializers_async
        await register_initializers_async(initializer_specs, ctx)
        logger.info("Registered %d dynamic initializer(s)", len(initializer_specs))


# ═══════════════════════════════════════════════════════════════════════════════
# Endpoint 状态重置
# ═══════════════════════════════════════════════════════════════════════════════


def _reset_endpoint_state(ctx: "PipelineContext") -> None:
    """重置 ctx 状态 (每个 endpoint 独立攻击)."""
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
        from assess.judge_manager import reset_t0_stats
        reset_t0_stats()
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# Endpoint 输出
# ═══════════════════════════════════════════════════════════════════════════════


def _print_endpoint_sort_results(sorted_endpoints: list[dict[str, Any]]) -> None:
    """输出 endpoint 排序结果."""
    from utils.display import _C_BOLD, _C_RESET
    print()
    print(f"{_C_BOLD}{'═' * 60}{_C_RESET}")
    print(f"{_C_BOLD}  ► [RECON] Endpoint 优先级排序 (能力指纹){_C_RESET}")
    _files_str = ", ".join(
        __import__("pathlib").Path(ep['burp_path']).name for ep in sorted_endpoints
    )
    print(f"  config/burp/ — {_files_str}")
    print(f"{_C_BOLD}{'═' * 60}{_C_RESET}")
    for i, ep in enumerate(sorted_endpoints):
        caps_str = ", ".join(sorted(ep["capabilities"])) if ep["capabilities"] else "chat"
        print(
            f"  {i + 1}. {_C_BOLD}{ep['burp_name']}{_C_RESET} "
            f"(priority={ep['priority_score']}, caps={caps_str})"
        )


def _print_endpoint_header(idx: int, total: int, burp_name: str) -> None:
    """输出 endpoint 开始头部."""
    from utils.display import _C_BOLD, _C_RESET
    print()
    print(f"{_C_BOLD}{'═' * 60}{_C_RESET}")
    print(f"{_C_BOLD}  Endpoint {idx + 1}/{total}: {burp_name}{_C_RESET}")
    print(f"{_C_BOLD}{'═' * 60}{_C_RESET}")


# ═══════════════════════════════════════════════════════════════════════════════
# 联合 ASR 汇总输出
# ═══════════════════════════════════════════════════════════════════════════════


def _print_joint_asr_summary(joint_summary: dict[str, Any], report_path: "Path") -> None:
    """输出联合 ASR 汇总."""
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


# ═══════════════════════════════════════════════════════════════════════════════
# Target Profile + ARM Target Type
# ═══════════════════════════════════════════════════════════════════════════════


def _extract_target_profile(ctx: "PipelineContext") -> tuple[str | None, str | None, str | None]:
    """从目标指纹提取语言 + 能力 + 模型族."""
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


def _get_arm_target_type(ctx: "PipelineContext") -> str:
    """获取 ARM 阶段的目标类型描述."""
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


# ═══════════════════════════════════════════════════════════════════════════════
# 编排日志记录
# ═══════════════════════════════════════════════════════════════════════════════


def _record_recon_orchestration(ctx: "PipelineContext") -> None:
    """记录侦察阶段的编排决策."""
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
    """记录 ARM 阶段种子选取的编排决策."""
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


# ═══════════════════════════════════════════════════════════════════════════════
# 结果提取
# ═══════════════════════════════════════════════════════════════════════════════


def _get_result_outcome(result: Any) -> str:
    """获取攻击结果的 outcome (内联简版, 避免循环导入)."""
    from assess.asr_stats import _get_outcome
    return _get_outcome(result)


def _extract_auth_recovery_log(ctx: "PipelineContext") -> list[dict[str, str]]:
    """提取认证恢复历史."""
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


# ═══════════════════════════════════════════════════════════════════════════════
# 双 Judge 统计日志 (含 T0 运行时告警)
# ═══════════════════════════════════════════════════════════════════════════════


def _log_dual_judge_stats(dual_judge_stats: dict[str, Any]) -> None:
    """输出双 Judge 统计日志 + T0 假阳性率运行时告警.

    生产级监控:
        - 双 Judge 一致性统计 (Cohen's Kappa)
        - OR 聚合假阳性追踪
        - T0 启发式预过滤 ScorerMetrics
        - **运行时告警**: FPR/FNR 超阈值时记录 WARNING 日志,
          提示操作员 T0 启发式可能需要校准
    """
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
    # T0 ScorerMetrics log + 运行时告警
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

    # ═══ T0 假阳性率运行时告警 (生产级监控) ═══
    _T0_MAX_FPR = 10.0
    _T0_MAX_FNR = 10.0
    _T0_MIN_SAMPLE_SIZE = 20

    t0_stats = dual_judge_stats.get("t0_stats", {})
    if not t0_stats:
        return

    refusal_filtered = t0_stats.get("refusal_filtered", 0)
    success_filtered = t0_stats.get("success_filtered", 0)
    fnr = t0_stats.get("false_negative_rate", 0.0)
    fpr = t0_stats.get("false_positive_rate", 0.0)
    total_filtered = refusal_filtered + success_filtered

    if total_filtered < _T0_MIN_SAMPLE_SIZE:
        logging.debug(
            "T0 heuristic alert skipped: sample size %d < %d (FNR=%.1f%%, FPR=%.1f%%)",
            total_filtered,
            _T0_MIN_SAMPLE_SIZE,
            fnr,
            fpr,
        )
        return

    if fnr > _T0_MAX_FNR:
        logging.warning(
            "⚠️ T0 HEURISTIC ALERT: High False Negative Rate (FNR=%.1f%% > %.0f%% threshold). "
            "T0 refusal filter is overriding %d successful attacks as failures. "
            "Recommendation: Calibrate T0 keyword thresholds or disable T0 pre-filter for this target.",
            fnr,
            _T0_MAX_FNR,
            t0_stats.get("refusal_judge_overturned", 0),
        )

    if fpr > _T0_MAX_FPR:
        logging.warning(
            "⚠️ T0 HEURISTIC ALERT: High False Positive Rate (FPR=%.1f%% > %.0f%% threshold). "
            "T0 success filter is overriding %d failed attacks as successes. "
            "Recommendation: T0 token-saving benefits compromised — verify success keywords or adjust long-response threshold.",
            fpr,
            _T0_MAX_FPR,
            t0_stats.get("success_judge_overturned", 0),
        )

    if total_filtered > 0:
        logging.info(
            "T0 Heuristic Health: filtered=%d, FNR=%.1f%%, FPR=%.1f%%, "
            "tokens_saved≈%d — %s",
            total_filtered,
            fnr,
            fpr,
            total_filtered * 2,
            "✅ OK" if fnr <= _T0_MAX_FNR and fpr <= _T0_MAX_FPR else "⚠️ ALERT",
        )
