# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""主 pipeline 攻击场景模块 — 场景创建 + 补充 PyRIT 原生不覆盖的 OWASP 2025 攻击面。.

本模块提供两类功能:

1. create_scenario() — PyRIT 原生场景创建工厂函数
   被 stage_scenario.py 调用, 根据 scenario_name 创建 PyRIT 原生 Scenario 实例。
   支持的场景:
     - airt_*           → AIRTBenchmarkScenario (PyRIT 原生)
     - garak_*          → GarakScenario (PyRIT 原生)
     - benchmark        → BenchmarkScenario (PyRIT 原生)
     - foundry          → FoundryScenario (PyRIT 原生)
   返回 None 表示未知场景 (调用方 fallback 到 text_adaptive)

2. 新增场景模块 (OWASP 2025 补充):
   - multimodal_injection — 多模态注入 (LLM01/LLM05)
   - model_extraction — 模型提取 (LLM10)
   - data_poisoning — 训练数据投毒检测 (LLM04)
   - pii_extraction — PII 提取 (LLM02)
   - vector_manipulation — 向量相似度操纵 (LLM08)
   - context_bomb — 递归上下文膨胀 (LLM10)
   - hallucination_injection — 幻觉注入 (LLM09)
   - tool_hijack — Agent 工具调用劫持 (LLM06)
   - embedding_extraction — 嵌入向量提取检测 (LLM08 扩展)
   - system_prompt_leakage — 系统提示词泄露 (LLM07)

设计原则 (R-010: PyRIT 原生优先):
  所有场景的核心组件优先使用 PyRIT 原生 API。
  自研代码仅负责编排和 OWASP 映射。

学术依据:
  - Shayegani et al. (arXiv:2306.13254): 多模态组合对抗攻击
  - Tramèr et al. (arXiv:2012.00314): 模型提取攻击
  - Wan et al. (arXiv:2401.05566): 训练数据投毒
  - Carlini et al. (arXiv:2012.07805): 训练数据提取
  - Greshake et al. (arXiv:2302.12173): RAG 投毒
  - OWASP Top 10 for LLM Applications 2025

> **日期**: 2026-8-2
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pyrit.scenario.core.scenario import Scenario
    from pyrit.score import Scorer

from pipeline.scenarios.composite_scorer import (  # noqa: F401
    create_composite_objective_scorer,
    should_use_composite_scorer,
)

logger = logging.getLogger(__name__)

__all__ = [
    "create_scenario",
    "create_composite_objective_scorer",
    "should_use_composite_scorer",
    "run_multimodal_injection",
    "run_model_extraction",
    "run_data_poisoning_detection",
    "run_pii_extraction",
    "run_vector_manipulation",
    "run_context_bomb",
    "run_hallucination_injection",
    "run_tool_hijack",
    "run_embedding_extraction",
    "run_system_prompt_leakage",
    "run_advanced_mcp_attack",
]


def create_scenario(
    scenario_name: str,
    *,
    objective_scorer: Scorer | None = None,
    scenario_result_id: str | None = None,
    **kwargs: Any,
) -> Scenario | None:
    """创建 PyRIT 原生场景实例。.

    被 stage_scenario.py 调用, 根据 scenario_name 创建对应的 PyRIT 原生 Scenario。
    text_adaptive 场景不通过此函数创建 (在 stage_scenario.py 内联构建)。

    Args:
        scenario_name: 场景名称 (airt_*, garak_*, benchmark, foundry 等)。
        objective_scorer: 目标评分器实例。
        scenario_result_id: 恢复已有运行结果的 ID (可选)。
        **kwargs: 额外场景参数。

    Returns:
        Scenario 实例, 或 None (未知场景)。
    """
    name_lower = scenario_name.lower().strip()

    # ── AIRT 场景 (PyRIT 原生) ──
    if name_lower.startswith("airt"):
        try:
            from pyrit.scenario import AIRTBenchmarkScenario

            logger.info(f"Creating AIRTBenchmarkScenario: {scenario_name}")
            return AIRTBenchmarkScenario(
                objective_scorer=objective_scorer,
                scenario_result_id=scenario_result_id,
            )
        except ImportError:
            logger.warning("AIRTBenchmarkScenario not available in PyRIT")
            return None

    # ── Garak 场景 (PyRIT 原生) ──
    if name_lower.startswith("garak"):
        try:
            from pyrit.scenario import GarakScenario

            logger.info(f"Creating GarakScenario: {scenario_name}")
            return GarakScenario(
                objective_scorer=objective_scorer,
                scenario_result_id=scenario_result_id,
            )
        except ImportError:
            logger.warning("GarakScenario not available in PyRIT")
            return None

    # ── Benchmark 场景 (PyRIT 原生) ──
    if name_lower == "benchmark":
        try:
            from pyrit.scenario import BenchmarkScenario

            logger.info(f"Creating BenchmarkScenario: {scenario_name}")
            return BenchmarkScenario(
                objective_scorer=objective_scorer,
                scenario_result_id=scenario_result_id,
            )
        except ImportError:
            logger.warning("BenchmarkScenario not available in PyRIT")
            return None

    # ── Foundry 场景 (PyRIT 原生) ──
    if name_lower == "foundry":
        try:
            from pyrit.scenario import FoundryScenario

            logger.info(f"Creating FoundryScenario: {scenario_name}")
            return FoundryScenario(
                objective_scorer=objective_scorer,
                scenario_result_id=scenario_result_id,
            )
        except ImportError:
            logger.warning("FoundryScenario not available in PyRIT")
            return None

    # ── 未知场景 ──
    logger.warning(f"Unknown scenario: {scenario_name}")
    return None


# ── OWASP 2025 补充场景 ──


def run_multimodal_injection(ctx: Any) -> Any:
    """多模态注入场景 (LLM01/LLM05) 的延迟导入入口。."""
    from pipeline.scenarios.multimodal_injection import run_multimodal_injection as _run
    return _run(ctx)


def run_model_extraction(ctx: Any) -> Any:
    """模型提取场景 (LLM10) 的延迟导入入口。."""
    from pipeline.scenarios.model_extraction import run_model_extraction as _run
    return _run(ctx)


def run_data_poisoning_detection(ctx: Any) -> Any:
    """训练数据投毒检测场景 (LLM04) 的延迟导入入口。."""
    from pipeline.scenarios.data_poisoning import run_data_poisoning_detection as _run
    return _run(ctx)


def run_pii_extraction(ctx: Any) -> Any:
    """PII 提取场景 (LLM02) 的延迟导入入口。."""
    from pipeline.scenarios.pii_extraction import run_pii_extraction as _run
    return _run(ctx)


def run_vector_manipulation(ctx: Any) -> Any:
    """向量相似度操纵场景 (LLM08) 的延迟导入入口。."""
    from pipeline.scenarios.vector_manipulation import run_vector_manipulation as _run
    return _run(ctx)


def run_context_bomb(ctx: Any) -> Any:
    """递归上下文膨胀场景 (LLM10) 的延迟导入入口。."""
    from pipeline.scenarios.context_bomb import run_context_bomb as _run
    return _run(ctx)


def run_hallucination_injection(ctx: Any) -> Any:
    """幻觉注入场景 (LLM09) 的延迟导入入口。."""
    from pipeline.scenarios.hallucination_injection import run_hallucination_injection as _run
    return _run(ctx)


def run_tool_hijack(ctx: Any) -> Any:
    """Agent 工具调用劫持场景 (LLM06) 的延迟导入入口。."""
    from pipeline.scenarios.tool_hijack import run_tool_hijack as _run
    return _run(ctx)


def run_embedding_extraction(ctx: Any) -> Any:
    """嵌入向量提取检测场景 (LLM08 扩展) 的延迟导入入口。."""
    from pipeline.scenarios.vector_manipulation import run_embedding_extraction as _run
    return _run(ctx)


def run_system_prompt_leakage(ctx: Any) -> Any:
    """系统提示词泄露场景 (LLM07) 的延迟导入入口。."""
    from pipeline.scenarios.system_prompt_leakage import run_system_prompt_leakage as _run
    return _run(ctx)


def run_advanced_mcp_attack(ctx: Any) -> Any:
    """高级 MCP 攻击场景 (Kill Chain + 跨服务器信任链) 的延迟导入入口。."""
    from pipeline.scenarios.advanced_mcp_attacks import run_advanced_mcp_attack as _run
    return _run(ctx)
