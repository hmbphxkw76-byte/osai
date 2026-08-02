# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Target-Aware Converter 路由 — 根据不同 Target 类型自动选择最优 Converter 链。.

PyRIT 原生不感知 Target 类型与 Converter 链选择的关联。
本模块在原生之上增加 Target 维度:

  Target 类型 → 安全机制分析 → 最优 Converter 链序列

设计原则:
- 纯函数式路由：输入 target_type → 输出有序链名列表
- 与 ASR 排序叠加使用，Target 感知作为优先排序层
- 非 LLM 链优先（快速高成功率），LLM 链作为兜底
- 支持 converter_target 可用性检测

P5-1 外部化: 所有映射数据从 ``data/target_profiles.yaml`` 加载,
Python 代码仅保留路由逻辑。

> **日期**: 2026-8-1
> **更新记录**:
>   2026-8-1 — v8.0: 双路由集成 (CLI + Target 感知并集)
>   2026-8-1 — v8.1: P5-1 外部化, 3 个硬编码字典迁移到 YAML
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ============================================================
# P5-1: 从 data/target_profiles.yaml 加载配置 (唯一数据源)
# ============================================================

_PROFILES_YAML = Path(__file__).parent.parent.parent / "data" / "setting" / "target_profiles.yaml"


def _load_target_profiles() -> tuple[
    dict[str, str],
    dict[str, str],
    dict[str, dict[str, Any]],
]:
    """从 ``data/target_profiles.yaml`` 加载 Target 配置。.

    YAML 是唯一数据源, 3 个映射字典不再硬编码在 Python 中。

    Returns:
        (class_name_map, type_groups, converter_profiles) 三元组

    Raises:
        FileNotFoundError: YAML 文件不存在时
    """
    if not _PROFILES_YAML.exists():
        raise FileNotFoundError(
            f"Target profiles YAML not found at {_PROFILES_YAML}. This is the required data source."
        )
    import yaml as _yaml

    with open(_PROFILES_YAML, encoding="utf-8") as f:
        data = _yaml.safe_load(f)

    class_name_map: dict[str, str] = dict(data.get("class_name_map") or {})
    type_groups: dict[str, str] = dict(data.get("type_groups") or {})
    converter_profiles: dict[str, dict[str, Any]] = dict(data.get("converter_profiles") or {})

    logger.info(
        f"Target profiles loaded from YAML: "
        f"{len(class_name_map)} class mappings, "
        f"{len(type_groups)} type groups, "
        f"{len(converter_profiles)} converter profiles"
    )
    return class_name_map, type_groups, converter_profiles


# 模块级加载 (与 converter_chains.py 一致)
TARGET_CLASS_NAME_MAP, TARGET_TYPE_GROUPS, _TARGET_CONVERTER_PROFILES = _load_target_profiles()


# ============================================================
# Target 类型分组
# ============================================================


def get_target_group(target_type: str | None) -> str | None:
    """获取 Target 分组名。."""
    if not target_type:
        return None
    return TARGET_TYPE_GROUPS.get(target_type)


# ============================================================
# Target 分组 → Converter 链推荐
# ============================================================


def get_chains_for_target_type(
    target_type: str | None,
    converter_target_available: bool = False,
    model_tier: str = "unknown",
) -> dict[str, list[str]] | None:
    """根据 target_type + model_tier 返回基础技术 → Converter 链映射。.

    4 层 ASR 链推荐 (model_tier 感知):
      Layer 1 (high_asr_chains):   ASR >= 40% — 非 LLM 链, 快速高命中率
      Layer 2 (medium_asr_chains): ASR 15-40% — 非 LLM 链, 中等命中率
      Layer 3 (low_asr_chains):    ASR 5-15% — 非 LLM 链, 兜底覆盖
      Layer 4 (llm_assisted_chains): LLM 辅助 — 仅在 converter_target 可用且非弱模型时推荐

    model_tier 影响:
      - strong: 4 层全部推荐 (强模型需要 LLM 辅助绕过)
      - moderate: Layer 1-3 + 条件性 Layer 4
      - weak: 仅 Layer 1-3 (弱模型跳过 LLM 链避免 JSON 解析错误)
      - unknown: 默认 Layer 1-3 + 条件性 Layer 4

    从 Target 分组的 Converter Profile 中提取链列表，
    与 BASE_TECHNIQUES_FOR_VARIANTS 取交集。
    """
    if not target_type:
        return None

    group = get_target_group(target_type)
    if group is None:
        return None

    profile = _TARGET_CONVERTER_PROFILES.get(group)
    if profile is None:
        return None

    from pipeline.converters.chains import BASE_TECHNIQUES_FOR_VARIANTS, CONVERTER_VARIANT_CHAINS
    from pipeline.converters.model_tier_detector import should_use_llm_converters

    # 合并该分组推荐的链（按 4 层优先级排序）
    recommended_chains: list[str] = []
    for key in ("high_asr_chains", "medium_asr_chains", "low_asr_chains"):
        for chain in profile.get(key, []):
            if chain in CONVERTER_VARIANT_CHAINS and chain not in recommended_chains:
                recommended_chains.append(chain)

    # Layer 4: LLM 辅助链 — model_tier 感知
    use_llm = converter_target_available and should_use_llm_converters(model_tier)
    if use_llm:
        for chain in profile.get("llm_assisted_chains", []):
            if chain in CONVERTER_VARIANT_CHAINS and chain not in recommended_chains:
                recommended_chains.append(chain)
    elif converter_target_available and model_tier == "weak":
        logger.info(f"Skipping LLM converter chains for weak model (target_type={target_type})")

    if not recommended_chains:
        return None

    # 为每个基础技术分配推荐的链（取交集）
    mapping: dict[str, list[str]] = {}
    for base_tech, chains in BASE_TECHNIQUES_FOR_VARIANTS.items():
        filtered = [c for c in chains if c in recommended_chains]
        if filtered:
            mapping[base_tech] = filtered

    return mapping if mapping else None


def get_chain_priority_for_target(chain_name: str, target_type: str | None) -> int:
    """获取链在特定目标类型下的优先级。."""
    from pipeline.converters.chains import CONVERTER_VARIANT_CHAINS

    chain_info = CONVERTER_VARIANT_CHAINS.get(chain_name, {})
    return chain_info.get("priority", 99)


def infer_target_type(objective_target: Any) -> str | None:
    """从 objective_target 实例自动推断 target_type。.

    按优先级依次尝试:
    1. 目标实例的 _target_type 属性
    2. 目标类名在 TARGET_CLASS_NAME_MAP 中的映射
    3. CamelCase → snake_case 转换后匹配
    """
    if objective_target is None:
        return None

    # 1. 检查 _target_type 属性
    target_type = getattr(objective_target, "_target_type", None)
    if target_type:
        return target_type

    # 2. 类名直接映射
    class_name = type(objective_target).__name__
    if class_name in TARGET_CLASS_NAME_MAP:
        return TARGET_CLASS_NAME_MAP[class_name]

    # 3. CamelCase → snake_case 转换
    snake_name = (
        re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", class_name))
        .lower()
        .replace("_target", "")
    )
    if snake_name in TARGET_TYPE_GROUPS:
        return snake_name

    logger.debug(f"Could not infer target_type from class '{class_name}'")
    return None
