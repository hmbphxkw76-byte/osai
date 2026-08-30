"""PipelineContext — 贯穿整个流水线的状态容器。

所有 Phase 共享同一个 PipelineContext 实例，避免模块间隐式传参。
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

    from recon.burp_parser import ParsedBurpRequest


@dataclass
class PipelineContext:
    """流水线运行时状态。

    属性:
        args: CLI 解析结果。
        output_dir: 输出目录路径。
        model_name: 目标模型名称 (用于报告)。
        parsed_request: 解析后的 Burp 请求。
        objective_target: 被攻击目标 (PyRIT PromptTarget 实例)。
        adversarial_target: 攻击者模型 (多轮攻击使用)。
        converter_target: Converter 使用的 LLM 目标 (可选)。
        scoring_target: 评分器使用的 LLM 目标。
        seeds: 加载后的种子列表。
        techniques: 选中的攻击技术名称列表。
        converter_map: 技术名 → Converter 链列表。
        attack_results: 攻击执行结果。
        asr_per_technique: 按技术统计的 ASR。
        overall_asr: 总体 ASR。
        scenario_result_id: 场景结果 ID (用于断点续跑)。
    """

    args: "argparse.Namespace"
    output_dir: Path = Path("outputs")
    model_name: str = ""

    # Recon phase
    parsed_request: "ParsedBurpRequest | None" = None
    # 多 endpoint 支持: 每个 endpoint 的独立攻击结果
    # 学术依据: Greshake et al. (arXiv:2302.12173) — 逐个深度攻击
    #   Chao et al. (arXiv:2310.08419) — 联合 ASR = 1 - ∏(1 - ASRᵢ)
    multi_endpoint_results: list[dict[str, Any]] = field(default_factory=list)
    # 当前正在攻击的 endpoint 索引 (多 endpoint 循环中)
    _current_endpoint_idx: int = 0

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

    # ── 增量借鉴: 运行标签 (pyrit_scan --memory-labels) ──
    # 运行时标签写入 CentralMemory, 用于结果查询过滤和报告标记
    # 数据流: config.py (parse_args) → ctx.memory_labels → main.py (CentralMemory.set_labels)
    # 示例: {"run_id": "r001", "target": "deepseek", "environment": "production"}
    memory_labels: dict[str, str] = field(default_factory=dict)


def get_effective_concurrency(
    ctx: PipelineContext,
    *,
    default: int = 3,
    min_val: int = 1,
    max_val: int = 3,
) -> int:
    """从 ctx.args.max_concurrency 读取有效并发数, 统一 SSOT.

    L5 v45: 消除子模块中 max_concurrency=2 硬编码偏差。
    config/defaults.yaml 声明 max_concurrency=3, 此前子模块绕过 ctx.args
    直接硬编码 2, 导致声明与实际不一致。

    PyRIT SQLite WAL 模式下 max_concurrency=3 安全 (busy_timeout=5000ms)。
    如遇 IntegrityError, 由 RateLimitedTarget 重试机制处理。

    Args:
        ctx: 流水线上下文 (读取 ctx.args.max_concurrency)。
        default: ctx.args 无值时的 fallback (从 config/defaults.yaml 的 3)。
        min_val: 最小值 (单线程场景 = 1)。
        max_val: 最大值 (SQLite WAL 安全上限 = 3)。

    Returns:
        有效并发数, clamp 到 [min_val, max_val]。
    """
    raw = getattr(getattr(ctx, "args", None), "max_concurrency", None)
    if raw is None or not isinstance(raw, int):
        return default
    return max(min_val, min(max_val, raw))


def _get_config_int(ctx: PipelineContext, key: str, default: int) -> int:
    """从 ctx.args 读取 config/defaults.yaml 中的 int 值 (SSOT).

    L5 v45: 消除 TAP/PAIR tree_width/tree_depth 硬编码偏差。
    parse_args 阶段 _apply_defaults 已将 defaults.yaml 所有 key 映射到 args,
    所以 ctx.args.tap_tree_width 等可直接读取。

    Args:
        ctx: 流水线上下文。
        key: defaults.yaml 中的 key (如 "tap_tree_width", "pair_tree_depth")。
        default: 缺失时的 fallback。

    Returns:
        int 值。
    """
    raw = getattr(getattr(ctx, "args", None), key, None)
    if raw is None or not isinstance(raw, int):
        return default
    return raw


# ── L5 v13: Relaxed Adversarial Schema monkey-patch ──
# 学术依据: Zheng et al. (arXiv:2306.05685) — LLM-as-a-Judge 鲁棒性
# 部分第三方 API (DeepSeek-V3, LongCat) 不严格遵循 JSON 输出指令,
# 缺少 rationale / last_response_summary 字段导致 InvalidJsonException
# → 无限重试 → 流水线卡死。
# 此函数通过 monkey-patch 使这两个字段可选, 符合"胶水层"增强原则,
# 不修改 PyRIT 源码, 仅运行时注入。

_relaxed_schema_applied = False


def apply_relaxed_adversarial_schema() -> None:
    """Monkey-patch PyRIT 的 adversarial_chat JSON schema, 使 rationale 和 last_response_summary 可选。

    学术依据: Zheng et al. (arXiv:2306.05685) — LLM 评分/对抗对话
    需要鲁棒的 JSON 解析。部分模型不严格遵循 JSON schema, 导致
    InvalidJsonException 无限重试。将非关键字段改为可选可解决此问题。

    策略:
        1. 注册一个新的 "adversarial_chat_relaxed" schema, 仅 required: ["next_message"]
        2. Monkey-patch get_common_json_schema, 对 "adversarial_chat" 返回 relaxed 版本
        3. 不修改 PyRIT 源码, 仅运行时注入 (胶水层增强)
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

        # 注册 relaxed schema (overwrite=True 覆盖已注册的原版)
        schema_mod.register_common_json_schema(
            name="adversarial_chat", schema=relaxed, overwrite=True
        )

        # 同时注册 true_false_with_rationale 的 relaxed 版本
        tf_original = schema_mod.get_common_json_schema("true_false_with_rationale")
        tf_relaxed = copy.deepcopy(tf_original)
        # 保留所有 required 字段但允许 additionalProperties
        tf_relaxed["additionalProperties"] = True
        schema_mod.register_common_json_schema(
            name="true_false_with_rationale", schema=tf_relaxed, overwrite=True
        )

        # scale_with_rationale relaxed 版本
        scale_original = schema_mod.get_common_json_schema("scale_with_rationale")
        scale_relaxed = copy.deepcopy(scale_original)
        scale_relaxed["additionalProperties"] = True
        schema_mod.register_common_json_schema(
            name="scale_with_rationale", schema=scale_relaxed, overwrite=True
        )

        _relaxed_schema_applied = True
        logger.debug(
            "Relaxed adversarial schema applied: "
            "adversarial_chat (required=['next_message']), "
            "true_false_with_rationale (additionalProperties=True), "
            "scale_with_rationale (additionalProperties=True)"
        )

    except Exception as e:
        logger.debug("Relaxed adversarial schema skipped: %s", e)

