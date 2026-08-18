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

import pyrit.converter as _pyrit_converter
from pyrit.converter.converter import Converter

if TYPE_CHECKING:
    from pyrit.analytics.result_analysis import AttackStats

logger = logging.getLogger(__name__)

# CLI 名称 → Converter 类 (不区分大小写)
# 动态注册: 从 PyRIT 1.0.1 原生 converter 模块自动获取类
# 无需 Azure 依赖的 Converter 全部注册 (77/79 = 97%, 仅排除 AzureSpeech*)


def _get_converter_cls(class_name: str) -> type[Converter] | None:
    """从 pyrit.converter 模块动态获取 Converter 类。."""
    return getattr(_pyrit_converter, class_name, None)


# (CLI名, PyRIT类名, 是否需要LLM converter_target, 模态)
# 模态: text | image | audio | video | file | multimodal
_CONVERTER_SPECS: list[tuple[str, str, bool, str]] = [
    # ── 原有 18 个 (v7.0 基线) — 全部 text 模态 ──
    ("rot13", "ROT13Converter", False, "text"),
    ("base64", "Base64Converter", False, "text"),
    ("leetspeak", "LeetspeakConverter", False, "text"),
    ("morse", "MorseConverter", False, "text"),
    ("binary", "BinaryConverter", False, "text"),
    ("braille", "BrailleConverter", False, "text"),
    ("nato", "NatoConverter", False, "text"),
    ("url", "UrlConverter", False, "text"),
    ("flip", "FlipConverter", False, "text"),
    ("emoji", "EmojiConverter", False, "text"),
    ("zalgo", "ZalgoConverter", False, "text"),
    ("zero_width", "ZeroWidthConverter", False, "text"),
    ("unicode_sub", "UnicodeSubstitutionConverter", False, "text"),
    ("caesar", "CaesarConverter", False, "text"),
    ("atbash", "AtbashConverter", False, "text"),
    ("string_join", "StringJoinConverter", False, "text"),
    ("superscript", "SuperscriptConverter", False, "text"),
    ("ascii_art", "AsciiArtConverter", False, "text"),
    # ── P0-2 新增 11 个 (v44.0) ──
    ("ansi_attack", "AnsiAttackConverter", False, "text"),
    ("arabizi", "ArabiziConverter", False, "text"),
    ("bidi", "BidiConverter", False, "text"),
    ("code_chameleon", "CodeChameleonConverter", True, "text"),
    ("negation_trap", "NegationTrapConverter", False, "text"),
    ("tone", "ToneConverter", True, "text"),
    ("variation", "VariationConverter", False, "text"),
    ("malicious_question", "MaliciousQuestionGeneratorConverter", True, "text"),
    ("toxic_sentence", "ToxicSentenceGeneratorConverter", True, "text"),
    ("image_saturation", "ImageColorSaturationConverter", False, "image"),
    ("add_image_video", "AddImageVideoConverter", False, "multimodal"),
    # ── v44.1 补全: 34 个无 LLM 依赖 Converter ──
    ("ascii_smuggler", "AsciiSmugglerConverter", False, "text"),
    ("base2048", "Base2048Converter", False, "text"),
    ("bin_ascii", "BinAsciiConverter", False, "text"),
    ("char_swap", "CharSwapConverter", False, "text"),
    ("colloquial_wordswap", "ColloquialWordswapConverter", False, "text"),
    ("ecoji", "EcojiConverter", False, "text"),
    ("first_letter", "FirstLetterConverter", False, "text"),
    ("insert_punctuation", "InsertPunctuationConverter", False, "text"),
    ("qr_code", "QRCodeConverter", False, "image"),
    ("random_capital", "RandomCapitalLettersConverter", False, "text"),
    ("repeat_token", "RepeatTokenConverter", False, "text"),
    ("search_replace", "SearchReplaceConverter", False, "text"),
    ("suffix_append", "SuffixAppendConverter", False, "text"),
    ("tatweel", "TatweelConverter", False, "text"),
    ("template_segment", "TemplateSegmentConverter", False, "text"),
    ("unicode_confusable", "UnicodeConfusableConverter", False, "text"),
    ("unicode_replacement", "UnicodeReplacementConverter", False, "text"),
    ("variation_selector_smuggler", "VariationSelectorSmugglerConverter", False, "text"),
    ("transparency_attack", "TransparencyAttackConverter", False, "image"),
    ("image_rotation", "ImageRotationConverter", False, "image"),
    ("image_resizing", "ImageResizingConverter", False, "image"),
    ("image_compression", "ImageCompressionConverter", False, "image"),
    ("image_overlay", "ImageOverlayConverter", False, "image"),
    ("add_text_image", "AddTextImageConverter", False, "multimodal"),
    ("add_image_text", "AddImageTextConverter", False, "multimodal"),
    ("pdf", "PDFConverter", False, "file"),
    ("word_doc", "WordDocConverter", False, "file"),
    ("task_framing", "TaskFramingConverter", False, "text"),
    ("selective_text", "SelectiveTextConverter", False, "text"),
    ("policy_puppetry", "PolicyPuppetryConverter", False, "text"),
    ("math_obfuscation", "MathObfuscationConverter", False, "text"),
    ("ask_to_decode", "AskToDecodeConverter", False, "text"),
    ("sneaky_bits_smuggler", "SneakyBitsSmugglerConverter", False, "text"),
    ("denylist", "DenylistConverter", True, "text"),
    # ── v44.1 补全: 14 个 LLM 依赖 Converter ──
    ("character_space", "CharacterSpaceConverter", True, "text"),
    ("diacritic", "DiacriticConverter", False, "text"),  # 实际不需 LLM
    ("noise", "NoiseConverter", True, "text"),
    ("image_prompt_style", "ImagePromptStyleConverter", True, "image"),
    ("translation", "TranslationConverter", True, "text"),
    ("random_translation", "RandomTranslationConverter", True, "text"),
    ("tense", "TenseConverter", True, "text"),
    ("persuasion", "PersuasionConverter", True, "text"),
    ("math_prompt", "MathPromptConverter", True, "text"),
    ("llm_generic_text", "LLMGenericTextConverter", True, "text"),
    ("scientific_translation", "ScientificTranslationConverter", True, "text"),
    ("arabic_presentation_form", "ArabicPresentationFormConverter", True, "text"),
    ("json_string", "JsonStringConverter", True, "text"),
]

# 模态 → CLI名列表 (自动从 _CONVERTER_SPECS 生成)
_CONVERTERS_BY_MODALITY: dict[str, list[str]] = {}
for _cli, _cls_name, _needs_t, _modality in _CONVERTER_SPECS:
    _CONVERTERS_BY_MODALITY.setdefault(_modality, []).append(_cli)

# 需要LLM converter_target 的 CLI名集合
_CONVERTERS_NEEDING_TARGET: frozenset[str] = frozenset(
    _cli for _cli, _, _needs_t, _ in _CONVERTER_SPECS if _needs_t
)

_CONVERTER_REGISTRY: dict[str, type[Converter] | None] = {}
for _cli_name, _class_name, _needs_target, _modality in _CONVERTER_SPECS:
    _cls = _get_converter_cls(_class_name)
    if _cls is not None:
        _CONVERTER_REGISTRY[_cli_name] = _cls
    else:
        logger.debug(f"Converter {_class_name} not available in PyRIT, skipping")

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


def get_converter_modality(cli_name: str) -> str:
    """返回指定 Converter 的模态类型。

    Args:
        cli_name: Converter 的 CLI 名称 (如 "rot13", "image_rotation")。

    Returns:
        str: 模态类型 — "text" | "image" | "audio" | "video" | "file" | "multimodal"。
        如果未找到则返回 "text" (安全默认值)。
    """
    key = cli_name.lower().strip()
    for _cli, _, _, _modality in _CONVERTER_SPECS:
        if _cli == key:
            return _modality
    return "text"


def get_converters_by_modality(modality: str) -> list[str]:
    """返回指定模态的所有 Converter CLI 名称列表。

    Args:
        modality: 模态类型 — "text" | "image" | "audio" | "video" | "file" | "multimodal"。

    Returns:
        list[str]: 该模态下所有已注册的 Converter CLI 名称。
    """
    return list(_CONVERTERS_BY_MODALITY.get(modality, []))


def filter_converters_by_target_modality(
    converter_names: list[str],
    target_modality: str,
) -> list[str]:
    """根据目标模态过滤 Converter 列表，跳过不兼容的 Converter。

    策略:
    - text 目标: 接受 text 模态 Converter，拒绝 image/file/multimodal
    - image 目标: 接受 text + image + multimodal Converter
    - multimodal 目标: 接受所有模态 Converter
    - file 目标: 接受 text + file Converter

    Args:
        converter_names: 用户指定的 Converter CLI 名称列表。
        target_modality: 目标模型的模态类型。

    Returns:
        list[str]: 过滤后与目标模态兼容的 Converter 名称列表。
    """
    if target_modality == "multimodal":
        return list(converter_names)

    compat_map: dict[str, frozenset[str]] = {
        "text": frozenset({"text"}),
        "image": frozenset({"text", "image", "multimodal"}),
        "file": frozenset({"text", "file"}),
        "audio": frozenset({"text"}),
        "video": frozenset({"text", "video", "multimodal"}),
    }
    accepted = compat_map.get(target_modality, frozenset({"text"}))

    filtered: list[str] = []
    for name in converter_names:
        modality = get_converter_modality(name)
        if modality in accepted:
            filtered.append(name)
        else:
            logger.info(
                f"Skipping converter '{name}' (modality={modality}) "
                f"— incompatible with target modality '{target_modality}'"
            )
    return filtered


def auto_select_converters_by_modality(target_modality: str) -> list[str]:
    """根据目标模态自动选择所有兼容的 Converter CLI 名称。

    Args:
        target_modality: 目标模型的模态类型 — "text" | "image" | "multimodal" 等。

    Returns:
        list[str]: 所有与目标模态兼容的 Converter CLI 名称列表。
    """
    if target_modality == "multimodal":
        return list(_CONVERTER_REGISTRY.keys())

    compat_map: dict[str, frozenset[str]] = {
        "text": frozenset({"text"}),
        "image": frozenset({"text", "image", "multimodal"}),
        "file": frozenset({"text", "file"}),
        "audio": frozenset({"text"}),
        "video": frozenset({"text", "video", "multimodal"}),
    }
    accepted = compat_map.get(target_modality, frozenset({"text"}))

    result: list[str] = []
    for _cli, _, _, _modality in _CONVERTER_SPECS:
        if _modality in accepted:
            result.append(_cli)
    return result


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
    filter_layer: str | None = None,
    injection_surfaces: list[str] | None = None,
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

    O2 增强: ``filter_layer`` 参数 — 基线扫描结果驱动 Converter 选择。
    当 filter_layer 非空时, 补充防护层级对应的推荐 Converter 链:
      - input_filter → encoding_bypass / base64 / rot13
      - output_guardrail → translation / homoglyph
      - semantic_filter → cross_paradigm_2layer / cross_paradigm_3layer
      - no_filter → 不补充 (无防护)

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
        filter_layer: 基线扫描防护层级 (input_filter/output_guardrail/semantic_filter/no_filter)。
        injection_surfaces: v58 攻击面拓扑注入面列表 (如 ["user_message", "tool_result"]),
                            根据注入面类型补充 Converter 链。

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
    # P3 优化: 每技术最多 1 个协同链, 避免链数膨胀导致 Converter 堆砌
    #   学术依据: HarmBench (arXiv:2402.04249) — 同范式叠加边际递减
    #   之前每技术添加 2 个协同链, 与 target_profiles 推荐叠加后
    #   扁平化为 12+ Converter, 导致 prompt 膨胀和 API 超时
    # O2: 基线扫描防护层级驱动 Converter 补充
    #   学术依据: HarmBench (arXiv:2402.04249) 基线先行分析防护层级;
    #     Zeng et al. (arXiv:2402.19181) 表示层 ASR 8-12% vs 语义层 ASR 30-40%
    _FILTER_LAYER_CHAINS: dict[str, list[str]] = {
        "input_filter": ["encoding_bypass", "base64", "rot13"],
        "output_guardrail": ["semantic_bypass", "translation", "homoglyph"],
        "semantic_filter": ["cross_paradigm_2layer", "cross_paradigm_3layer"],
        "no_filter": [],
    }
    # O2: 当 filter_layer 非空且有推荐链, 补充到每技术
    _filter_extra: list[str] = []
    if filter_layer and filter_layer in _FILTER_LAYER_CHAINS:
        _filter_extra = _FILTER_LAYER_CHAINS[filter_layer]
        if _filter_extra:
            logger.info(f"O2: filter_layer='{filter_layer}' → adding chains: {_filter_extra}")

    # v58: 拓扑驱动 Converter 选择 — 根据注入面类型补充 Converter 链
    # 学术依据: Greshake et al.(arXiv:2302.12173) 间接注入需载体适配;
    #   Zhan et al.(arXiv:2307.00929) InjecAgent 工具结果注入需隐蔽编码
    _INJECTION_SURFACE_CHAINS: dict[str, list[str]] = {
        "tool_result": ["encoding_bypass", "base64"],  # 工具结果注入需编码隐蔽
        "rag_content": ["translation", "homoglyph"],  # RAG 投毒需语义变换
        "mcp_protocol": ["encoding_bypass", "rot13"],  # MCP 协议注入需编码绕过
        "auth_token": ["base64", "rot13"],  # Token 注入需编码
        "conversation_history": ["cross_paradigm_2layer"],  # 多轮历史注入需跨范式
    }
    _surface_extra: list[str] = []
    if injection_surfaces:
        for surface in injection_surfaces:
            chains = _INJECTION_SURFACE_CHAINS.get(surface, [])
            for c in chains:
                if c not in _surface_extra:
                    _surface_extra.append(c)
        if _surface_extra:
            logger.info(f"v58: injection_surfaces={injection_surfaces} → adding chains: {_surface_extra}")

    _SYNERGY_BOOSTS: dict[str, list[str]] = {
        "crescendo": ["cross_paradigm_2layer"],
        "tap": ["cross_paradigm_2layer"],
        "red_teaming": [],
        "pair": ["cross_paradigm_2layer"],
        "crescendo_simulated": ["cross_paradigm_2layer"],
        "context_compliance": [],
        "many_shot": [],  # P2: token_smuggling_chain 重型 Converter 已全禁
        "skeleton_key": [],
        "prompt_sending": [],
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

        # O2: 基线扫描防护层级驱动 Converter 链补充
        # 学术依据: HarmBench (arXiv:2402.04249) 基线先行;
        #   Zeng et al. (arXiv:2402.19181) 表示层 vs 语义层 ASR 差异
        for fc in _filter_extra:
            if fc not in enhanced_chains:
                enhanced_chains.append(fc)

        # v58: 拓扑驱动 Converter 链补充 — 根据注入面类型
        # 学术依据: Greshake et al.(arXiv:2302.12173) 间接注入需载体适配
        for sc in _surface_extra:
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
