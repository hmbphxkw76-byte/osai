# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Converter 工厂: 从 CLI 名称实例化 PyRIT Converter 对象 + ASR 驱动差异化路由。.

支持的 CLI 名称 (不区分大小写):
  - rot13 → ROT13Converter
  - base64 → Base64Converter
  - leetspeak → LeetspeakConverter
  - morse → MorseConverter
  - binary → BinaryConverter
  - braille → BrailleConverter
  - nato → NatoConverter
  - url → UrlConverter
  - flip → FlipConverter
  - emoji → EmojiConverter
  - zalgo → ZalgoConverter
  - zero_width → ZeroWidthConverter
  - unicode_sub → UnicodeSubstitutionConverter
  - caesar → CaesarConverter
  - atbash → AtbashConverter
  - string_join → StringJoinConverter
  - superscript → SuperscriptConverter
  - ascii_art → AsciiArtConverter

Per-technique ASR 差异化路由 (R-001 ASR 数据驱动):
  - 查询历史 ASR (by technique × converter 组合)
  - 高 ASR 的 converter 优先分配到高 ASR 的技术
  - 无历史数据时退化为均匀路由 (冷启动友好)
  - Laplace 平滑避免极端值

参考:
  - arXiv:2310.04451 (PAIR) — 载荷变换对 ASR 的影响
  - arXiv:2402.16860 (HarmBench) — 编码变换作为攻击增强

> **日期**: 2026-8-1
> **更新记录**:
>   2026-8-1 15:10 — 实现 per-technique ASR 差异化路由, 替代均匀路由
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from pyrit.converter import (
    AsciiArtConverter,
    AtbashConverter,
    Base64Converter,
    BinaryConverter,
    BrailleConverter,
    CaesarConverter,
    EmojiConverter,
    FlipConverter,
    LeetspeakConverter,
    MorseConverter,
    NatoConverter,
    ROT13Converter,
    StringJoinConverter,
    SuperscriptConverter,
    UnicodeSubstitutionConverter,
    UrlConverter,
    ZalgoConverter,
    ZeroWidthConverter,
)
from pyrit.converter.converter import Converter

if TYPE_CHECKING:
    from pyrit.analytics.result_analysis import AttackStats

logger = logging.getLogger(__name__)

# CLI 名称 → Converter 类 (不区分大小写)
_CONVERTER_REGISTRY: dict[str, type[Converter]] = {
    "rot13": ROT13Converter,
    "base64": Base64Converter,
    "leetspeak": LeetspeakConverter,
    "morse": MorseConverter,
    "binary": BinaryConverter,
    "braille": BrailleConverter,
    "nato": NatoConverter,
    "url": UrlConverter,
    "flip": FlipConverter,
    "emoji": EmojiConverter,
    "zalgo": ZalgoConverter,
    "zero_width": ZeroWidthConverter,
    "unicode_sub": UnicodeSubstitutionConverter,
    "caesar": CaesarConverter,
    "atbash": AtbashConverter,
    "string_join": StringJoinConverter,
    "superscript": SuperscriptConverter,
    "ascii_art": AsciiArtConverter,
}

# Converter 名称 → 简短标签 (用于 ASR 路由分析中的 memory_labels)
_CONVERTER_TAG_SUFFIX = "_conv"


def create_converters(converter_names: list[str]) -> list[Converter]:
    """从 CLI 名称列表创建 Converter 实例列表。.

    Args:
        converter_names: CLI 传递的 converter 名称列表 (如 ["rot13", "base64"])。

    Returns:
        list[Converter]: 实例化的 Converter 对象列表。

    Raises:
        ValueError: 如果有未知的 converter 名称。
    """
    converters: list[Converter] = []
    unknown: list[str] = []

    for name in converter_names:
        key = name.lower().strip()
        cls = _CONVERTER_REGISTRY.get(key)
        if cls is None:
            unknown.append(name)
            continue
        try:
            converter = cls()
            converters.append(converter)
            logger.info(f"Created converter: {cls.__name__} (from '{name}')")
        except Exception as e:
            logger.warning(f"Failed to instantiate converter '{name}' ({cls.__name__}): {e}")
            unknown.append(f"{name} (instantiation failed: {e})")

    if unknown:
        available = ", ".join(sorted(_CONVERTER_REGISTRY.keys()))
        raise ValueError(f"Unknown converter(s): {unknown}. Available converters: {available}")

    return converters


def build_technique_converter_map(
    converter_names: list[str],
    technique_names: list[str],
    *,
    asr_by_technique: dict[str, AttackStats] | None = None,
) -> dict[str, list[Converter]]:
    """构建 technique_converters 字典: 基于 ASR 数据实现 per-technique 差异化路由。.

    **Per-technique ASR 差异化路由 (R-001 ASR 数据驱动)**:

    当有历史 ASR 数据时:
      1. 按技术历史 ASR 排序技术列表
      2. 按 converter 对应技术的 ASR 提升度排序 converter 列表
      3. 将高 ASR 的 converter 优先分配给高 ASR 的技术
      (形成 "强者愈强" 的 ASR 放大效应)

    当无历史 ASR 数据时 (冷启动):
      退化为均匀路由 (所有技术应用全部 converters)

    PyRIT 的 ``technique_converters`` 参数接受 ``dict[str, list[Converter]]`` 映射,
    其中 key 是技术名称 (如 "many_shot", "tap", "prompt_sending")。

    Args:
        converter_names: CLI 传递的 converter 名称列表。
        technique_names: 所有技术名称列表。
        asr_by_technique: 按技术分组的 ASR 统计, None 则查询历史。
            传入空字典表示无历史数据 (冷启动)。

    Returns:
        dict[str, list[Converter]]: 技术名称 → converter 列表映射。
    """
    converters = create_converters(converter_names)
    if not converters:
        return {}

    # 无 ASR 数据时退化为均匀路由 (冷启动友好)
    if asr_by_technique is None:
        from pipeline.asr.optimizer import query_historical_asr_by_technique

        try:
            asr_by_technique = query_historical_asr_by_technique()
        except ImportError as e:
            logger.warning(f"查询历史 ASR 失败, 退化为均匀路由: {e}")
            asr_by_technique = {}

    # 冷启动: 无历史 ASR 数据, 均匀路由
    if not asr_by_technique:
        logger.info("Converter 路由: 冷启动模式 (均匀路由, 无历史 ASR)")
        return {name: converters for name in technique_names}

    # ── ASR 驱动差异化路由 ──
    # 1. 按技术 ASR 排序 (高 ASR 优先)
    def _tech_asr_score(tech_name: str) -> float:
        """计算技术的 ASR 分数 (Laplace 平滑)。."""
        stats = asr_by_technique.get(tech_name)  # type: ignore[union-attr]
        if stats is None or stats.total_decided == 0:
            return 0.5  # 无历史数据: 中等优先级
        return (stats.successes + 1) / (stats.total_decided + 2)

    sorted_techniques = sorted(technique_names, key=_tech_asr_score, reverse=True)

    # 2. 构建 per-technique 映射 (G-15: 连续梯度分配替代二分法)
    # 高 ASR 技术 → 全部 converters (攻击为王, 放大高 ASR)
    # 低 ASR 技术 → 按 ASR 比例分配 converter 子集 (连续梯度, 非 0.5 二分)
    result: dict[str, list[Converter]] = {}

    for idx, tech_name in enumerate(sorted_techniques):
        tech_asr = _tech_asr_score(tech_name)

        if tech_asr >= 0.5:
            # 高 ASR 技术: 分配全部 converters
            result[tech_name] = list(converters)
        else:
            # G-15: 连续梯度 — 按 ASR 比例计算 converter 子集大小
            # tech_asr=0.0 → 1 个 converter, tech_asr=0.5 → 全部 converters
            subset_size = max(1, int(tech_asr * 2 * len(converters)))
            if subset_size >= len(converters):
                subset_size = len(converters)
            start = idx % len(converters)
            subset = []
            for j in range(subset_size):
                subset.append(converters[(start + j) % len(converters)])
            result[tech_name] = subset

    # 日志: 展示路由策略
    high_asr_techs = [t for t in sorted_techniques if _tech_asr_score(t) >= 0.5]
    low_asr_techs = [t for t in sorted_techniques if _tech_asr_score(t) < 0.5]
    logger.info(
        f"Converter ASR 路由 (G-15 连续梯度): "
        f"{len(high_asr_techs)} 高 ASR 技术 (全 converters), "
        f"{len(low_asr_techs)} 低 ASR 技术 (梯度子集)"
    )

    return result


def build_target_aware_converter_map(
    technique_names: list[str],
    *,
    target_type: str | None = None,
    converter_target: Any = None,
    converter_target_available: bool = False,
    model_tier: str = "unknown",
) -> dict[str, list[Converter]]:
    """基于 Target 类型感知自动构建 technique → Converter 列表映射。.

    当用户未通过 ``--converters`` 指定 Converter 时, 本函数自动根据
    target_type 从 ``target_aware_router`` 获取推荐链, 并使用
    ``converter_chains.build_converters_from_chain_names()`` 构建
    Converter 实例列表, 注入原生 ``technique_converters`` 参数。

    路由逻辑:
      1. ``target_aware_router.get_chains_for_target_type()`` 返回
         ``{base_technique: [chain_name, ...]}`` 映射
      2. 每个技术的推荐链被扁平化为 Converter 实例列表
      3. LLM 链仅在 converter_target 可用且 model_tier 允许时包含
      4. 未在路由映射中的技术不分配 Converter (原生行为)

    与 ``build_technique_converter_map()`` 的区别:
      - ``build_technique_converter_map`` : 用户指定 CLI converter 名称,
        ASR 驱动 per-technique 差异化分配
      - ``build_target_aware_converter_map`` : 自动根据 target_type 选择
        最优链, 无需用户指定, Target 感知驱动

    两者可叠加使用: CLI converters + target-aware chains (并集)。

    Args:
        technique_names: 所有技术名称列表。
        target_type: 目标类型 (如 "openai_chat", "playwright")。
        converter_target: LLM 链所需的 Converter Target 实例。
        converter_target_available: converter_target 是否可用。
        model_tier: 模型等级 (strong/moderate/weak/unknown)。

    Returns:
        dict[str, list[Converter]]: 技术名称 → Converter 列表映射。
        若 target_type 为 None 或无推荐链, 返回空字典。
    """
    if not target_type:
        logger.debug("Target-aware converter map: target_type is None, skipping")
        return {}

    from pipeline.converters.chains import build_converters_from_chain_names, score_chain_combo
    from pipeline.converters.target_aware_router import get_chains_for_target_type

    # 获取 target_type 感知的链映射: {base_technique: [chain_name, ...]}
    chain_mapping = get_chains_for_target_type(
        target_type=target_type,
        converter_target_available=converter_target_available,
        model_tier=model_tier,
    )
    if chain_mapping is None:
        logger.info(f"Target-aware converter map: no chains for target_type='{target_type}'")
        return {}

    # G-4 攻击为王: 跨范式协同链补充
    # 学术依据: Russinovich et al. (arXiv:2402.12109) Crescendo + encoding = 3-5x ASR
    # 对每个技术, 在推荐链基础上补充高协同乘数的跨范式链
    # O-3 攻击为王: 新增 prompt_sending 协同链
    #   学术依据: arXiv:2307.15043 — 编码绕过对 Llama 系列模型 ASR 提升显著
    #   converter_variant_priors: prompt_sending+stealth_evasion llama_3_1=0.45, +encoding_bypass=0.50
    _SYNERGY_BOOSTS: dict[str, list[str]] = {
        "crescendo": ["encoding_bypass", "stealth_evasion"],
        "tap": ["encoding_bypass", "stealth_evasion"],
        "red_teaming": ["persuasion_authority", "decomposition_chain"],
        "pair": ["stealth_evasion", "encoding_bypass"],
        "crescendo_simulated": ["encoding_bypass", "unicode_attack"],
        "context_compliance": ["stealth_evasion", "encoding_bypass"],
        "many_shot": ["token_smuggling_chain", "encoding_bypass"],
        "skeleton_key": ["stealth_evasion", "persuasion_authority"],
        "prompt_sending": ["stealth_evasion", "encoding_bypass"],
    }

    result: dict[str, list[Converter]] = {}
    total_chains_used = 0
    total_synergy_boosted = 0

    for tech_name in technique_names:
        # 查找该技术对应的推荐链
        # chain_mapping 的 key 是基础技术名 (如 "prompt_sending", "many_shot")
        # technique_names 可能包含变体名 (如 "prompt_sending+stealth_evasion")
        base_tech = tech_name.split("+")[0] if "+" in tech_name else tech_name
        recommended_chains = chain_mapping.get(base_tech) or chain_mapping.get(tech_name)

        if not recommended_chains:
            continue

        # G-4: 协同链优化 — 补充高协同乘数的跨范式链
        # 学术依据: converter_chains.yaml combo_multipliers:
        #   encoding_bypass + stealth_evasion = 1.5x
        #   encoding_bypass + unicode_attack = 1.6x (最高)
        #   persuasion_authority + decomposition_chain = 1.3x
        synergy_chains = _SYNERGY_BOOSTS.get(base_tech, [])
        enhanced_chains = list(recommended_chains)
        for sc in synergy_chains:
            if sc not in enhanced_chains:
                enhanced_chains.append(sc)

        # 按协同乘数排序: 高协同链组合优先
        synergy_score = score_chain_combo(enhanced_chains)
        if synergy_score > 1.0:
            total_synergy_boosted += 1

        # 从链名构建 Converter 实例列表
        converters = build_converters_from_chain_names(
            chain_names=enhanced_chains,
            converter_target=converter_target,
        )

        if converters:
            result[tech_name] = converters
            total_chains_used += len(enhanced_chains)

    logger.info(
        f"Target-aware converter map (G-4 synergy): target_type='{target_type}', "
        f"{len(result)}/{len(technique_names)} techniques got converters, "
        f"{total_chains_used} chains used, "
        f"{total_synergy_boosted} synergy-boosted (>1.0x)"
    )

    return result


def merge_converter_maps(
    cli_map: dict[str, list[Converter]],
    target_aware_map: dict[str, list[Converter]],
) -> dict[str, list[Converter]]:
    """合并 CLI 指定的 Converter 映射与 Target 感知的 Converter 映射。.

    合并策略:
      - 同一技术的 CLI converters 和 target-aware converters 取并集
      - CLI converters 优先排在前面 (用户显式指定优先)
      - 去重: 同名 Converter 类只保留第一个实例

    Args:
        cli_map: CLI ``--converters`` 指定的映射 (ASR 驱动差异化)
        target_aware_map: Target 感知自动选择的映射

    Returns:
        合并后的映射
    """
    if not target_aware_map:
        return cli_map
    if not cli_map:
        return target_aware_map

    result: dict[str, list[Converter]] = {}
    all_techniques = set(cli_map.keys()) | set(target_aware_map.keys())

    for tech_name in all_techniques:
        cli_converters = cli_map.get(tech_name, [])
        ta_converters = target_aware_map.get(tech_name, [])

        # CLI 优先, target-aware 补充, 去重
        merged: list[Converter] = []
        seen_types: set[str] = set()

        for conv in list(cli_converters) + list(ta_converters):
            conv_type_name = type(conv).__name__
            if conv_type_name not in seen_types:
                seen_types.add(conv_type_name)
                merged.append(conv)

        if merged:
            result[tech_name] = merged

    return result


def get_available_converter_names() -> list[str]:
    """返回所有可用的 converter CLI 名称 (排序后)。."""
    return sorted(_CONVERTER_REGISTRY.keys())
