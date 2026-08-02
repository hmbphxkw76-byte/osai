# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""模型等级自动探测器 — 从 TargetRegistry 自动探测目标模型的安全过滤强度。.

PyRIT 原生不感知目标模型的安全过滤强度。本模块通过:
  1. 从 TargetRegistry 获取目标模型名称
  2. 基于模型名模式匹配推断 model_tier (strong/moderate/weak)
  3. 将 model_tier 透传到 selector / converter_router / scenario

model_tier 影响范围:
  - ASR 先验选择 (strong→gpt_4o ASR, weak→gpt_35 ASR)
  - Converter 链推荐 (strong→更多 LLM 辅助链, weak→更多编码链)
  - 失败类型路由 (strong→多轮迭代优先, weak→编码也可能有效)
  - Converter 变体创建 (weak→跳过 LLM 链避免 JSON 解析错误)

学术依据:
  - JailbreakBench (arXiv:2402.01135): 不同模型 ASR 差异巨大
  - HarmBench (arXiv:2402.04249): 模型过滤强度与 ASR 负相关
  - Wei et al. (arXiv:2307.15043): 编码攻击对不同模型效果差异

> **日期**: 2026-8-1
"""

from __future__ import annotations

import logging
import math
import re
from pathlib import Path

logger = logging.getLogger(__name__)


# ============================================================
# 模型等级常量
# ============================================================

TIER_STRONG = "strong"
TIER_MODERATE = "moderate"
TIER_WEAK = "weak"
TIER_UNKNOWN = "unknown"


# ============================================================
# P2-11: 模型名 → Tier 映射规则 — 从 data/model_tiers.yaml 加载
# ============================================================

_MODEL_TIERS_YAML = Path(__file__).parent.parent.parent / "data" / "config" / "model_tiers.yaml"


def _load_model_tier_config() -> tuple[
    list[str],
    list[str],
    list[str],
    list[tuple[float, str]],
    list[str],
]:
    """从 ``data/model_tiers.yaml`` 加载模型分级配置。.

    YAML 是唯一数据源, 模型分级模式不再硬编码在 Python 中。
    """
    if not _MODEL_TIERS_YAML.exists():
        raise FileNotFoundError(f"Model tiers YAML not found at {_MODEL_TIERS_YAML}. This is the required data source.")
    import yaml as _yaml

    with open(_MODEL_TIERS_YAML, encoding="utf-8") as f:
        data = _yaml.safe_load(f)

    strong = list(data.get("strong_patterns", []))
    moderate = list(data.get("moderate_patterns", []))
    weak = list(data.get("weak_patterns", []))

    param_map: list[tuple[float, str]] = []
    for item in data.get("param_tier_map", []):
        threshold = float(item["threshold"])
        if threshold == float("inf"):
            threshold = math.inf
        param_map.append((threshold, item["tier"]))

    llm_tiers = list(data.get("llm_converter_tiers", []))

    logger.info(f"Model tier config loaded: {len(strong)} strong, {len(moderate)} moderate, {len(weak)} weak patterns")
    return strong, moderate, weak, param_map, llm_tiers


_STRONG_PATTERNS, _MODERATE_PATTERNS, _WEAK_PATTERNS, _PARAM_TIER_MAP, _LLM_CONVERTER_TIERS = _load_model_tier_config()


def infer_model_tier(model_name: str) -> str:
    """从模型名推断安全过滤强度等级。.

    推断逻辑:
    1. 精确匹配强/中/弱模型模式
    2. 参数量匹配 (如 "7b" → moderate, "1.5b" → weak)
    3. 默认 unknown

    Args:
        model_name: 模型名称 (如 "gpt-4o", "llama-3-8b")

    Returns:
        model_tier: "strong" / "moderate" / "weak" / "unknown"
    """
    if not model_name:
        return TIER_UNKNOWN

    name_lower = model_name.lower().strip()

    # 1. 精确匹配
    for pattern in _STRONG_PATTERNS:
        if re.search(pattern, name_lower):
            return TIER_STRONG

    for pattern in _WEAK_PATTERNS:
        if re.search(pattern, name_lower):
            return TIER_WEAK

    for pattern in _MODERATE_PATTERNS:
        if re.search(pattern, name_lower):
            return TIER_MODERATE

    # 2. 参数量匹配
    param_match = re.search(r"(\d+\.?\d*)\s*b\b", name_lower)
    if param_match:
        try:
            param_size = float(param_match.group(1))
            for threshold, tier in _PARAM_TIER_MAP:
                if param_size <= threshold:
                    return tier
        except ValueError:
            pass

    # 3. 默认
    logger.debug(f"Could not infer model_tier for '{model_name}', defaulting to 'unknown'")
    return TIER_UNKNOWN


def detect_model_tier_from_registry() -> tuple[str, str]:
    """从 TargetRegistry 自动探测目标模型名称和等级。.

    优先级:
    1. TARGET_MODEL 环境变量
    2. TargetRegistry 中标记为 default_objective_target 的目标
    3. TargetRegistry 中第一个目标

    Returns:
        (model_name, model_tier) 元组
    """
    import os

    # 1. 环境变量
    model_name = os.getenv("TARGET_MODEL", "")
    if model_name:
        tier = infer_model_tier(model_name)
        logger.info(f"Model tier from TARGET_MODEL env: {model_name} → {tier}")
        return model_name, tier

    # 2. 从 TargetRegistry 获取
    try:
        from pyrit.registry import TargetRegistry

        registry = TargetRegistry.get_registry_singleton()
        entries = registry.instances.get_all_instances()

        # 优先找 default_objective_target 标签
        target_entries = registry.instances.get_by_tag(tag="default_objective_target")
        if not target_entries:
            target_entries = registry.instances.get_by_tag(tag="default")
        if not target_entries:
            target_entries = entries

        if target_entries:
            entry = target_entries[0]
            # 从 entry 获取模型名
            instance = entry.instance
            model_name = (
                getattr(instance, "model_name", None)
                or getattr(instance, "deployment_name", None)
                or getattr(instance, "_model_name", None)
                or entry.name
            )
            tier = infer_model_tier(str(model_name))
            logger.info(f"Model tier from TargetRegistry: {model_name} → {tier}")
            return str(model_name), tier
    except Exception as e:
        logger.debug(f"Failed to detect model from TargetRegistry: {e}")

    # 3. 默认
    logger.warning("Could not detect model tier, using default gpt-4o/strong")
    return "gpt-4o", TIER_STRONG


def should_use_llm_converters(model_tier: str) -> bool:
    """判断当前模型是否应该使用 LLM 辅助 Converter 链。.

    P2-11: 使用 ``data/model_tiers.yaml`` 中的 ``llm_converter_tiers`` 配置,
    替代硬编码 ``model_tier != TIER_WEAK`` 逻辑。

    弱模型 (weak) 不适合使用 LLM 辅助 Converter:
    - JSON 解析能力差, 容易触发 InvalidJsonException
    - 指令遵循能力弱, 可能无法正确执行 Converter 指令

    Args:
        model_tier: 模型等级

    Returns:
        True 如果应该使用 LLM 辅助 Converter
    """
    return model_tier in _LLM_CONVERTER_TIERS


def get_recommended_epsilon(model_tier: str) -> float:
    """根据模型等级推荐 epsilon 值。.

    强模型需要更多探索 (ASR 低, 需要尝试更多技术)
    弱模型可以更激进利用 (ASR 高, 少量技术即可命中)

    Args:
        model_tier: 模型等级

    Returns:
        推荐的 epsilon 值
    """
    if model_tier == TIER_STRONG:
        return 0.15  # 更多探索
    if model_tier == TIER_MODERATE:
        return 0.10
    if model_tier == TIER_WEAK:
        return 0.05  # 更激进利用
    return 0.10  # unknown
