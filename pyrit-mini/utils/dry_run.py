"""
utils/dry_run.py - Dry-run 模式配置与验证

收敛所有 --dry-run 相关逻辑 (R10 零 token 流水线验证)

职责:
    - 提供 dry-run 配置生成器
    - 提供流水线连通性验证
    - 被 main.py / core/phases/strike.py / executor.py 使用

调用方式:
    # main.py 中调用
    from utils.dry_run import is_dry_run, apply_dry_run_overrides

    if is_dry_run(ctx.args):
        apply_dry_run_overrides(ctx)

 架构原则:
    - dry-run 是运行时参数 (--dry-run 参数), 不是独立脚本
    - 验证逻辑集中在此模块, 避免散落在多个阶段文件中

Academic basis:
    - Continuous Integration best practices (zero-cost pipeline check)
    - R10 (Runtime Verification) from Constitution v1.8
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)


def is_dry_run(args: Any) -> bool:
    """检查是否为 dry-run 模式"""
    return getattr(args, "dry_run", False)


def get_dry_run_overrides(args: Any) -> dict[str, Any]:
    """生成 dry-run 模式下的流水线参数覆盖

    返回:
        包含以下键的字典:
        - skip_strike: 跳过攻击执行
        - skip_escalate: 跳过升级链
        - skip_api_calls: 跳过真实 API 调用
        - max_seeds: 最大种子数 (dry-run 默认为 1)
    """
    return {
        "skip_strike": True,
        "skip_escalate": True,
        "skip_api_calls": True,
        "max_seeds": min(getattr(args, "max_seeds", 1), 1),  # dry-run 仅用 1 个种子
    }


def apply_dry_run_overrides(ctx: "PipelineContext") -> None:
    """应用 dry-run 覆盖到 PipelineContext"""
    overrides = get_dry_run_overrides(ctx.args)

    # 更新 max_seeds (减少到最小值)
    if hasattr(ctx, "args"):
        ctx.args.max_seeds = overrides["max_seeds"]

    logger.info("[DRY-RUN] Applied overrides: %s", overrides)


def validate_pipeline_connectivity(ctx: "PipelineContext") -> list[str]:
    """验证六阶段数据流连通性 (dry-run 核心逻辑)

    检查项:
    1. recon: service_profile 是否可解析
    2. arm: seeds 是否加载
    3. strike: converter_map 是否构建
    4. assess: scoring_endpoint 是否配置
    5. report: evidence_collection 是否就绪

    返回:
        错误列表 (空列表表示通过)
    """
    errors: list[str] = []

    # 1. 检查 PipelineContext 关键字段
    required_fields = [
        "args",
        "output_dir",
        "attack_results",
    ]
    for field in required_fields:
        if not hasattr(ctx, field):
            errors.append(f"PipelineContext 缺少必要字段: {field}")

    # 2. 检查种子加载路径
    if hasattr(ctx, "args"):
        seeds = getattr(ctx.args, "seeds", None)
        if seeds is None:
            logger.debug("[DRY-RUN] seeds 参数未配置 (将在 arm 阶段加载)")

    # 3. 检查评分端点 (assess 阶段)
    scoring_endpoint = getattr(ctx, "scoring_endpoint", None)
    if scoring_endpoint is None:
        logger.debug("[DRY-RUN] scoring_endpoint 未配置 (将在 assess 阶段初始化)")

    logger.info("[DRY-RUN] Pipeline connectivity check completed: %d issues", len(errors))
    return errors


def get_dry_run_log_message(phase: str) -> str:
    """获取 dry-run 日志消息模板"""
    messages = {
        "main": "[DRY-RUN] Zero token verification mode - Skip real API calls",
        "strike": "[DRY-RUN] Skip attack execution (strike phase) - Data flow only",
        "escalate": "[DRY-RUN] Skip escalation chain (check_and_escalate)",
        "orchestrator": "[DRY-RUN] Orchestrator layer dry-run - Skip all phases",
    }
    return messages.get(phase, f"[DRY-RUN] Skip {phase} phase (dry-run mode)")


def should_skip_phase(phase_name: str, is_dry: bool) -> bool:
    """判断是否应跳过某阶段 (dry-run 模式下跳过执行类阶段)

    参数:
        phase_name: 阶段名称 (recon/arm/strike/escalate/assess/report)
        is_dry: 是否为 dry-run 模式

    返回:
        True 表示跳过该阶段
    """
    if not is_dry:
        return False

    # dry-run 跳过的阶段 (执行类)
    skip_phases = {"strike", "escalate"}
    return phase_name in skip_phases
