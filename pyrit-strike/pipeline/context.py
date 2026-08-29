"""PipelineContext — 贯穿整个流水线的状态容器。
"""

from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    import argparse

    from pyrit.models import AttackSeedGroup, ScenarioResult

    from pipeline.recon.burp_parser import ParsedBurpRequest

@dataclass
class PipelineContext:
    """流水线运行时状态。
    """

    args: "argparse.Namespace"
    output_dir: Path = Path("outputs")
    model_name: str = ""

    # Recon phase
    parsed_request: "ParsedBurpRequest | None" = None

    # Targets
    objective_target: Any = None
    multi_turn_target: Any = None  # 多轮攻击专用 (带 supports_multi_turn 声明)
    adversarial_target: Any = None
    # L5 v10: 多 adversarial targets (多模型并行攻击)
    extra_adversarial_targets: list[Any] = field(default_factory=list)
    converter_target: Any = None
    scoring_target: Any = None
    # L5 v48: 跨端口发现的额外攻击 target (port_expander)
    # 存储从非标准端口发现的 MCP/A2A/Agent 服务端点
    extra_objective_targets: dict[int, Any] = field(default_factory=dict)

    # Arm phase
    seeds: list["AttackSeedGroup"] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    converter_map: dict[str, list[Any]] = field(default_factory=dict)

    # Strike phase
    attack_results: dict[str, list[Any]] = field(default_factory=dict)

    # Assess phase
    asr_per_technique: dict[str, float] = field(default_factory=dict)
    overall_asr: float = 0.0
    wilson_ci: tuple[float, float] = (0.0, 0.0)
    dual_judge_stats: dict[str, Any] = field(default_factory=dict)
    # L5 v9: 保存已创建的 scorer 实例, 避免重新创建导致统计丢失
    scorer: Any = None

    # Scenario
    scenario_result_id: str | None = None
    scenario_result: "ScenarioResult | None" = None

    # P2-MCP: MCP 枚举动态生成的攻击种子 (由 mcp_rag_attack.py 填充)
    # 基于 target_router MCP 枚举结果 (mcp_tools/mcp_resources) 生成,
    # 在 _execute_specialized_seeds 中与静态 mcp_attack 种子合并执行
    _mcp_dynamic_seeds: list[dict[str, Any]] = field(default_factory=list)

    # 生产级资源管理: Playwright 浏览器实例引用 (流水线结束时清理)
    _playwright_instance: Any = None
    _browser: Any = None
    _browser_context: Any = None

    # 断点 #6 修复: 编排决策日志 — 记录侦察→武器化→执行每个决策的理由
    # 用于报告中的 "Orchestration Decision Log" 章节, 提供可审计性
    orchestration_log: list[dict[str, Any]] = field(default_factory=list)

def get_effective_concurrency(
    ctx: PipelineContext,
    *,
    default: int = 3,
    min_val: int = 1,
    max_val: int = 3,
) -> int:
    """从 ctx.args.max_concurrency 读取有效并发数, 统一 SSOT.
    """
    raw = getattr(getattr(ctx, "args", None), "max_concurrency", None)
    if raw is None or not isinstance(raw, int):
        return default
    return max(min_val, min(max_val, raw))

def _get_config_int(ctx: PipelineContext, key: str, default: int) -> int:
    """从 ctx.args 读取 config/defaults.yaml 中的 int 值 (SSOT).
    """
    raw = getattr(getattr(ctx, "args", None), key, None)
    if raw is None or not isinstance(raw, int):
        return default
    return raw

# 部分第三方 API (DeepSeek-V3, LongCat) 不严格遵循 JSON 输出指令,
# 缺少 rationale / last_response_summary 字段导致 InvalidJsonException
# → 无限重试 → 流水线卡死。
# 此函数通过 monkey-patch 使这两个字段可选, 符合"胶水层"增强原则,
# 不修改 PyRIT 源码, 仅运行时注入。

_relaxed_schema_applied = False

def apply_relaxed_adversarial_schema() -> None:
    """Monkey-patch PyRIT 的 adversarial_chat JSON schema, 使 rationale 和 last_response_summary 可选。
    """
    global _relaxed_schema_applied
    if _relaxed_schema_applied:
        return

    try:
        import pyrit.models.target.json_schema_definition as schema_mod

        # 确保 schema 已从 YAML 加载
        schema_mod._ensure_discovered()

        # 获取原始 schema
        original = schema_mod.get_common_json_schema("adversarial_chat")

        # 创建 relaxed 版本: 仅 next_message 必填
        relaxed = copy.deepcopy(original)
        relaxed["required"] = ["next_message"]

        # 注册 relaxed schema
        schema_mod.register_common_json_schema("adversarial_chat", relaxed)

        # 同时注册 true_false_with_rationale 的 relaxed 版本
        tf_original = schema_mod.get_common_json_schema("true_false_with_rationale")
        tf_relaxed = copy.deepcopy(tf_original)
        # 保留所有 required 字段但允许 additionalProperties
        tf_relaxed["additionalProperties"] = True
        schema_mod.register_common_json_schema("true_false_with_rationale", tf_relaxed)

        # scale_with_rationale relaxed 版本
        scale_original = schema_mod.get_common_json_schema("scale_with_rationale")
        scale_relaxed = copy.deepcopy(scale_original)
        scale_relaxed["additionalProperties"] = True
        schema_mod.register_common_json_schema("scale_with_rationale", scale_relaxed)

        _relaxed_schema_applied = True
        logger.info(
            "Relaxed adversarial schema applied: "
            "adversarial_chat (required=['next_message']), "
            "true_false_with_rationale (additionalProperties=True), "
            "scale_with_rationale (additionalProperties=True)"
        )

    except Exception:
        logger.warning("Failed to apply relaxed adversarial schema", exc_info=True)
