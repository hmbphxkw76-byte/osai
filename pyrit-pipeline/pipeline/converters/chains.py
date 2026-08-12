# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Converter 变体链定义 — 使用 PyRIT 原生 ``extra_request_converters`` API。.

PyRIT 原生 ``AttackTechniqueFactory.create(extra_request_converters=...)`` 支持在
已有 Converter 基础上追加（additive），实现渐进式 Converter 升级链:
  attempt 1: prompt_sending (无 Converter)
  attempt 2: prompt_sending + stealth_evasion (追加 Converter)
  attempt 3: prompt_sending + encoding_bypass (追加不同 Converter)

原生 ``AdaptiveTechniqueDispatcher`` 的 ``SequentialAttack(FIRST_SUCCESS)``
能按 selector 排序尝试 Converter 变体，成功即停止。

本模块定义预设 Converter 链元数据（纯数据层，不干扰原生执行）。

学术依据:
- Russinovich et al. (arXiv:2402.12109): Crescendo + encoding 协同 3-5x
- Zeng et al. (arXiv:2402.19181): 说服策略 ASR 30-40%
- Wei et al. (arXiv:2307.15043): 编码攻击表示级变换

> **日期**: 2026-8-1
"""

from __future__ import annotations

import importlib
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# P3-1: 惰性导入 Converter 类 — 避免 PyRIT 版本变更时整个模块导入失败
_converter_mod = None


def _conv(name: str) -> type:
    """惰性获取 PyRIT Converter 类 (首次调用时导入整个模块, 后续从缓存返回).

    如果类不存在, 抛出 AttributeError 并记录警告.
    """
    global _converter_mod
    if _converter_mod is None:
        _converter_mod = importlib.import_module("pyrit.converter")
    cls = getattr(_converter_mod, name, None)
    if cls is None:
        raise AttributeError(f"PyRIT Converter '{name}' not found in pyrit.converter. Check PyRIT version.")
    return cls


# P3-1: 模块级 __getattr__ — 函数体内引用 Converter 类名时自动惰性解析
# 无需修改任何 _build_*_chain() 函数体, Python 会在全局命名空间未找到时自动调用
_CONVERSION_CONFIG_IMPORTED = False


def _get_converter_configuration() -> Any:
    """惰性导入 ConverterConfiguration (仅在使用时导入)."""
    global _CONVERSION_CONFIG_IMPORTED
    if not _CONVERSION_CONFIG_IMPORTED:
        from pyrit.prompt_normalizer import ConverterConfiguration
        globals()["ConverterConfiguration"] = ConverterConfiguration
        _CONVERSION_CONFIG_IMPORTED = True
    return globals().get("ConverterConfiguration")


def __getattr__(name: str) -> Any:
    """模块级惰性导入 (P3-1): Converter 类名在首次引用时从 pyrit.converter 导入.

    支持: UnicodeConfusableConverter, Base64Converter, ROT13Converter, ...
    以及: ConverterConfiguration (从 pyrit.prompt_normalizer)
    """
    if name == "ConverterConfiguration":
        return _get_converter_configuration()
    # 尝试从 pyrit.converter 惰性获取
    try:
        return _conv(name)
    except AttributeError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None


# ============================================================
# Converter 变体链配置 — P2-10: 从 data/converter_chains.yaml 加载
# ============================================================

_CHAINS_YAML = Path(__file__).parent.parent.parent / "data" / "setting" / "converter_chains.yaml"


def _load_chain_config() -> tuple[dict[str, dict[str, Any]], dict[str, list[str]], list[dict[str, Any]]]:
    """从 ``data/converter_chains.yaml`` 加载链配置、基础技术映射和组合乘数。.

    YAML 是唯一数据源, 链元数据和映射不再硬编码在 Python 中。
    链实例化函数 (``_build_*_chain()``) 仍保留在代码中,
    因为它们需要导入和构造 PyRIT Converter 类。

    Returns:
        (chains, base_technique_map, combo_multipliers) 三元组
    """
    if not _CHAINS_YAML.exists():
        raise FileNotFoundError(f"Converter chains YAML not found at {_CHAINS_YAML}. This is the required data source.")
    import yaml as _yaml

    with open(_CHAINS_YAML, encoding="utf-8") as f:
        data = _yaml.safe_load(f)

    chains: dict[str, dict[str, Any]] = {}
    for name, meta in (data.get("chains") or {}).items():
        chains[name] = {
            "requires_llm": bool(meta.get("requires_llm", False)),
            "priority": int(meta.get("priority", 3)),
            "modality": meta.get("modality", "text"),
            "description": meta.get("description", ""),
            "cost_tier": meta.get("cost_tier", "cheap"),
        }

    base_map: dict[str, list[str]] = {}
    for tech, chain_list in (data.get("base_techniques_for_variants") or {}).items():
        base_map[tech] = list(chain_list)

    # D13: combo_multipliers — 链组合协同效应乘数
    combo_data = data.get("combo_multipliers") or {}
    combo_multipliers: list[dict[str, Any]] = combo_data.get("combos", []) or []

    logger.info(
        f"Converter chains loaded from YAML: {len(chains)} chains, "
        f"{len(base_map)} base technique mappings, {len(combo_multipliers)} combo multipliers"
    )
    return chains, base_map, combo_multipliers


CONVERTER_VARIANT_CHAINS, BASE_TECHNIQUES_FOR_VARIANTS, COMBO_MULTIPLIERS = _load_chain_config()


# ============================================================
# 链构建函数
# ============================================================


def _build_stealth_evasion_chain() -> list:
    """Unicode 混淆 + Base64 + 后缀追加."""
    return [
        _conv("UnicodeConfusableConverter")(),
        _conv("Base64Converter")(),
        _conv("SuffixAppendConverter")(suffix="!!"),
    ]


def _build_multi_encoding_v2_chain() -> list:
    """四层编码: Base64 + ROT13 + Caesar(5) + Atbash."""
    return [
        _conv("Base64Converter")(),
        _conv("ROT13Converter")(),
        _conv("CaesarConverter")(caesar_offset=5),
        _conv("AtbashConverter")(),
    ]


def _build_encoding_bypass_chain() -> list:
    """Base64 + ROT13 + Caesar 编码绕过."""
    return [
        _conv("Base64Converter")(),
        _conv("ROT13Converter")(),
        _conv("CaesarConverter")(caesar_offset=3),
    ]


def _build_unicode_attack_chain() -> list:
    """Unicode 混淆 + 双向文本 + 零宽字符."""
    return [
        _conv("UnicodeSubstitutionConverter")(),
        _conv("BidiConverter")(),
        _conv("ZeroWidthConverter")(),
    ]


def _build_random_case_chain() -> list:
    """随机大写字符绕过关键词检测."""
    return [
        _conv("RandomCapitalLettersConverter")(),
    ]


def _build_format_injection_chain() -> list:
    """ASCII 艺术格式注入."""
    return [
        _conv("AsciiArtConverter")(),
    ]


def _build_noise_bypass_chain(converter_target: Any = None) -> list:
    """NoiseConverter 噪声注入 (LLM 辅助).

    NoiseConverter 需要 converter_target 来生成噪声变体。
    """
    if converter_target is None:
        return []
    return [
        _conv("NoiseConverter")(converter_target=converter_target),
    ]


def _build_special_chars_chain() -> list:
    """特殊字符注入."""
    return [
        _conv("UnicodeConfusableConverter")(),
        _conv("StringJoinConverter")(),
    ]


def _build_persuasion_authority_chain(converter_target: Any = None) -> list:
    """权威说服 (LLM 辅助)."""
    if converter_target is None:
        return []
    return [
        _conv("PersuasionConverter")(
            converter_target=converter_target,
            persuasion_technique="authority_endorsement",
        ),
    ]


def _build_decomposition_chain(converter_target: Any = None) -> list:
    """分解重构."""
    if converter_target is None:
        return []
    return [
        _conv("DecompositionConverter")(
            converter_target=converter_target,
        ),
    ]


def _build_llm_assisted_chain(converter_target: Any = None) -> list:
    """说服 + 语气 + 翻译 (LLM 辅助)."""
    if converter_target is None:
        return []
    return [
        _conv("PersuasionConverter")(
            converter_target=converter_target,
            persuasion_technique="authority_endorsement",
        ),
        _conv("ToneConverter")(converter_target=converter_target),
        _conv("TranslationConverter")(converter_target=converter_target, languages=["en"]),
    ]


def _build_task_framing_chain(converter_target: Any = None) -> list:
    """任务框架重构."""
    if converter_target is None:
        return []
    return [
        _conv("TaskFramingConverter")(converter_target=converter_target),
    ]


# ── 补全: 非 LLM 链构建函数 ──


def _build_binary_morse_chain() -> list:
    """Binary + Morse 双层编码."""
    return [_conv("BinaryConverter")(), _conv("MorseConverter")()]


def _build_braille_nato_chain() -> list:
    """Braille + Nato 字母表替换."""
    return [_conv("BrailleConverter")(), _conv("NatoConverter")()]


def _build_leetspeak_zalgo_chain() -> list:
    """Leetspeak + Zalgo 文本变形."""
    return [_conv("LeetspeakConverter")(), _conv("ZalgoConverter")()]


def _build_emoji_superscript_chain() -> list:
    """Emoji + Superscript 字符替换."""
    return [_conv("EmojiConverter")(), _conv("SuperscriptConverter")()]


def _build_char_swap_diacritic_chain() -> list:
    """CharSwap + Diacritic 字符变形."""
    return [_conv("CharSwapConverter")(), _conv("DiacriticConverter")()]


def _build_character_space_chain() -> list:
    """CharacterSpace 字符间距混淆."""
    return [_conv("CharacterSpaceConverter")()]


def _build_punctuation_insert_chain() -> list:
    """InsertPunctuation 标点注入绕过."""
    return [_conv("InsertPunctuationConverter")()]


def _build_repeat_token_chain() -> list:
    """RepeatToken 重复令牌注入."""
    return [_conv("RepeatTokenConverter")()]


def _build_token_smuggling_chain() -> list:
    """AsciiSmuggler + SneakyBits 令牌走私."""
    return [_conv("AsciiSmugglerConverter")(), _conv("SneakyBitsSmugglerConverter")()]


def _build_url_encoding_chain() -> list:
    """Url + Base64 URL 编码绕过."""
    return [_conv("UrlConverter")(), _conv("Base64Converter")()]


def _build_base2048_ecoji_chain() -> list:
    """Base2048 + Ecoji 高基数编码."""
    return [_conv("Base2048Converter")(), _conv("EcojiConverter")()]


def _build_unicode_replacement_chain() -> list:
    """UnicodeReplacement + Tatweel Unicode 替换."""
    return [_conv("UnicodeReplacementConverter")(), _conv("TatweelConverter")()]


def _build_search_replace_chain() -> list:
    """SearchReplace 关键词替换绕过."""
    return [_conv("SearchReplaceConverter")(old_value="test", new_value="exam")]


def _build_first_letter_chain() -> list:
    """FirstLetter 首字母提取编码."""
    return [_conv("FirstLetterConverter")()]


# ── P2: 跨范式短链 (2-3 层, 学术最优组合) ──
# 学术依据:
#   - HarmBench (arXiv:2402.04249): 同范式叠加边际递减, 跨范式协同最优
#   - Russinovich et al. (arXiv:2402.12109): 编码+混淆 1.5-1.6x ASR
#   - Zeng et al. (arXiv:2402.19181): 语义层 ASR 30-40% >> 表示层 8-12%
#   - Wei et al. (arXiv:2307.15043): 编码攻击绕过表示级安全过滤


def _build_cross_paradigm_2layer_chain() -> list:
    """P2: 跨范式 2 层 — Base64 (编码) + UnicodeConfusable (混淆).

    学术依据: encoding + unicode 组合乘数 1.6x (converter_chains.yaml)
    非 LLM 链: 本地计算, 无额外 API 调用, 极速执行.
    """
    return [
        _conv("Base64Converter")(),
        _conv("UnicodeConfusableConverter")(),
    ]


def _build_cross_paradigm_3layer_chain(converter_target: Any = None) -> list:
    """P2: 跨范式 3 层 — Base64 (编码) + UnicodeConfusable (混淆) + Persuasion (语义).

    学术依据:
      - encoding + stealth 1.5x (arXiv:2402.12109)
      - 语义层 ASR 30-40% >> 表示层 (arXiv:2402.19181)
      - 3 层跨范式 = 理论最优平衡点

    LLM 链: 需要 converter_target, 无则降级为 2 层.
    """
    base = [
        _conv("Base64Converter")(),
        _conv("UnicodeConfusableConverter")(),
    ]
    if converter_target is None:
        return base
    base.append(
        _conv("PersuasionConverter")(
            converter_target=converter_target,
            persuasion_technique="authority_endorsement",
        ),
    )
    return base


# ── 补全: LLM 链构建函数 ──


def _build_tense_variation_chain(converter_target: Any = None) -> list:
    """Tense + Variation 时态变换+变体 (LLM 辅助)."""
    if converter_target is None:
        return []
    return [
        _conv("TenseConverter")(converter_target=converter_target),
        _conv("VariationConverter")(converter_target=converter_target),
    ]


def _build_persuasion_policy_chain(converter_target: Any = None) -> list:
    """Persuasion + PolicyPuppetry 说服+策略模仿."""
    if converter_target is None:
        return []
    return [
        _conv("PersuasionConverter")(
            converter_target=converter_target,
            persuasion_technique="authority_endorsement",
        ),
        _conv("PolicyPuppetryConverter")(converter_target=converter_target),
    ]


def _build_math_obfuscation_chain(converter_target: Any = None) -> list:
    """MathObfuscation 数学表达式混淆 (LLM 辅助)."""
    if converter_target is None:
        return []
    return [_conv("MathObfuscationConverter")(converter_target=converter_target)]


def _build_scientific_translation_chain(converter_target: Any = None) -> list:
    """ScientificTranslation 科学翻译变换."""
    if converter_target is None:
        return []
    return [_conv("ScientificTranslationConverter")(converter_target=converter_target)]


# 链名 → 构建函数映射
_CHAIN_BUILDERS = {
    "stealth_evasion": lambda target=None: _build_stealth_evasion_chain(),
    "multi_encoding_v2": lambda target=None: _build_multi_encoding_v2_chain(),
    "encoding_bypass": lambda target=None: _build_encoding_bypass_chain(),
    "unicode_attack": lambda target=None: _build_unicode_attack_chain(),
    "random_case": lambda target=None: _build_random_case_chain(),
    "format_injection": lambda target=None: _build_format_injection_chain(),
    "noise_bypass": lambda target=None: _build_noise_bypass_chain(),
    "special_chars": lambda target=None: _build_special_chars_chain(),
    "persuasion_authority": lambda target=None: _build_persuasion_authority_chain(target),
    "decomposition_chain": lambda target=None: _build_decomposition_chain(target),
    "llm_assisted": lambda target=None: _build_llm_assisted_chain(target),
    "task_framing_chain": lambda target=None: _build_task_framing_chain(target),
    # 补全链
    "binary_morse_chain": lambda target=None: _build_binary_morse_chain(),
    "braille_nato_chain": lambda target=None: _build_braille_nato_chain(),
    "leetspeak_zalgo_chain": lambda target=None: _build_leetspeak_zalgo_chain(),
    "emoji_superscript_chain": lambda target=None: _build_emoji_superscript_chain(),
    "char_swap_diacritic_chain": lambda target=None: _build_char_swap_diacritic_chain(),
    "character_space_chain": lambda target=None: _build_character_space_chain(),
    "punctuation_insert_chain": lambda target=None: _build_punctuation_insert_chain(),
    "repeat_token_chain": lambda target=None: _build_repeat_token_chain(),
    "token_smuggling_chain": lambda target=None: _build_token_smuggling_chain(),
    "url_encoding_chain": lambda target=None: _build_url_encoding_chain(),
    "base2048_ecoji_chain": lambda target=None: _build_base2048_ecoji_chain(),
    "unicode_replacement_chain": lambda target=None: _build_unicode_replacement_chain(),
    "search_replace_chain": lambda target=None: _build_search_replace_chain(),
    "first_letter_chain": lambda target=None: _build_first_letter_chain(),
    "tense_variation_chain": lambda target=None: _build_tense_variation_chain(target),
    "persuasion_policy_chain": lambda target=None: _build_persuasion_policy_chain(target),
    "math_obfuscation_chain": lambda target=None: _build_math_obfuscation_chain(target),
    "scientific_translation_chain": lambda target=None: _build_scientific_translation_chain(target),
    # P2: 跨范式短链
    "cross_paradigm_2layer": lambda target=None: _build_cross_paradigm_2layer_chain(),
    "cross_paradigm_3layer": lambda target=None: _build_cross_paradigm_3layer_chain(target),
}


def load_preset_converter_chain(
    chain_name: str,
    converter_target: Any = None,
) -> Any:
    """从预设链名构建 ConverterConfiguration.

    使用 PyRIT 原生 ``ConverterConfiguration`` 包装 Converter 列表，
    供 ``AttackTechniqueFactory.create(extra_request_converters=...)`` 使用。

    Args:
        chain_name: 链名
        converter_target: LLM 链所需的 Converter Target

    Returns:
        ConverterConfiguration 实例，或 None（链不存在/无法构建）
    """
    chain_info = CONVERTER_VARIANT_CHAINS.get(chain_name)
    if chain_info is None:
        return None

    builder = _CHAIN_BUILDERS.get(chain_name)
    if builder is None:
        return None

    # LLM 链需要 converter_target
    if chain_info.get("requires_llm", False) and converter_target is None:
        return None

    try:
        converters = builder(converter_target)
    except Exception as e:
        logger.warning(f"Failed to build converter chain '{chain_name}': {e}")
        return None

    if not converters:
        return None

    return _get_converter_configuration()(converters=converters)


# ============================================================
# 辅助函数
# ============================================================


# ============================================================
# D13: 链组合协同评分
# ============================================================


def score_chain_combo(chain_names: list[str]) -> float:
    """D13: 计算链组合的协同效应分数.

    基于 ``converter_chains.yaml`` 的 ``combo_multipliers`` 段,
    检查链列表中是否存在已知的高效组合.

    PyRIT 原生优先: 本函数仅用于选择层 (Stage 2),
    不修改 PyRIT 原生 ``extra_request_converters`` API.

    学术依据: Russinovich et al. (arXiv:2402.12109) —
      Crescendo + encoding = 3-5x ASR

    Args:
        chain_names: 链名列表

    Returns:
        协同效应分数 (1.0 = 无协同, >1.0 = 有协同加成)
    """
    if not chain_names or not COMBO_MULTIPLIERS:
        return 1.0

    chain_set = set(chain_names)
    best_multiplier = 1.0

    for combo in COMBO_MULTIPLIERS:
        combo_chains = set(combo.get("chains", []))
        if combo_chains.issubset(chain_set):
            multiplier = float(combo.get("multiplier", 1.0))
            if multiplier > best_multiplier:
                best_multiplier = multiplier

    return best_multiplier


#: D14: cost_tier → 预算权重映射
_COST_TIER_WEIGHT: dict[str, float] = {
    "cheap": 1.0,  # 非 LLM 链: 快速, 无 API 调用
    "moderate": 0.7,  # 混合链
    "expensive": 0.4,  # LLM 链: 慢, 每次 API 调用 2-5s
}


def get_chain_cost_weight(chain_name: str) -> float:
    """D14: 获取链的成本权重 (用于预算感知分配).

    非 LLM 链 (cheap) 权重高 (优先选择),
    LLM 链 (expensive) 权重低 (预算有限时减少).

    PyRIT 原生优先: 本函数仅用于选择层,
    PyRIT 原生 ``max_attempts_per_objective`` 不变.

    Args:
        chain_name: 链名

    Returns:
        成本权重 (0.0-1.0, 越高越优先)
    """
    chain_info = CONVERTER_VARIANT_CHAINS.get(chain_name, {})
    cost_tier = chain_info.get("cost_tier", "cheap")
    return _COST_TIER_WEIGHT.get(cost_tier, 1.0)


def is_converter_variant(technique_name: str) -> bool:
    """判断是否是 Converter 变体名（如 'prompt_sending+stealth_evasion'）。."""
    return "+" in technique_name


def get_converter_chain_from_variant(technique_name: str) -> str | None:
    """从变体名提取 Converter 链名。."""
    if "+" not in technique_name:
        return None
    return technique_name.split("+", 1)[1]


def get_base_technique_from_variant(technique_name: str) -> str:
    """从变体名提取基础技术名。."""
    if "+" not in technique_name:
        return technique_name
    return technique_name.split("+", 1)[0]


def get_dynamic_chain_mapping(
    target_type: str | None,
    converter_target_available: bool,
) -> dict[str, list[str]] | None:
    """根据 target_type 返回动态链映射。.

    当 target_type 为 None 时返回 None（使用静态映射 BASE_TECHNIQUES_FOR_VARIANTS）。
    """
    from pipeline.converters.target_aware_router import get_chains_for_target_type

    if not target_type:
        return None

    return get_chains_for_target_type(
        target_type=target_type,
        converter_target_available=converter_target_available,
    )


#: P0: Converter 链深度上限 — 防止同范式叠加导致 prompt 膨胀和 API 超时.
#:
#: 学术依据:
#:   - HarmBench (arXiv:2402.04249): 3+ 层同类型编码不提升 ASR, 边际递减
#:   - Russinovich et al. (arXiv:2402.12109): 跨范式 2-3 层协同 3-5x ASR
#:   - Zeng et al. (arXiv:2402.19181): 语义层 ASR 30-40% >> 表示层 8-12%
#:
#: 超过此值的 Converter 会被截断, 保留按链顺序排列的前 N 个.
#: 3 层 = 1 编码 + 1 混淆 + 1 语义 (跨范式最优).
MAX_CONVERTER_CHAIN_DEPTH: int = 3


def build_converters_from_chain_names(
    chain_names: list[str],
    converter_target: Any = None,
    *,
    max_depth: int | None = None,
) -> list:
    """从多个链名构建扁平化的 Converter 实例列表。.

    将多个预设 Converter 链的构建结果合并为一个扁平列表,
    供原生 ``technique_converters`` 参数使用。

    - 非 LLM 链直接构建
    - LLM 链需要 converter_target, 若为 None 则跳过该链
    - 自动去重 (同名 Converter 类只保留第一个实例)
    - P0: 链深度截断 — 最多保留 ``max_depth`` 个 Converter, 防止
      同范式叠加导致 prompt 膨胀和 API 超时

    Args:
        chain_names: 链名列表 (如 ["stealth_evasion", "encoding_bypass"])
        converter_target: LLM 链所需的 Converter Target
        max_depth: Converter 链深度上限, None 则使用模块级
            ``MAX_CONVERTER_CHAIN_DEPTH`` (默认 3).

    Returns:
        合并后的 Converter 实例列表 (可能为空)
    """
    effective_max = max_depth if max_depth is not None else MAX_CONVERTER_CHAIN_DEPTH

    result: list = []
    seen_types: set[str] = set()

    for chain_name in chain_names:
        # P0: 已达深度上限, 提前终止
        if len(result) >= effective_max:
            break

        chain_info = CONVERTER_VARIANT_CHAINS.get(chain_name)
        if chain_info is None:
            logger.debug(f"Chain '{chain_name}' not found in CONVERTER_VARIANT_CHAINS, skipping")
            continue

        builder = _CHAIN_BUILDERS.get(chain_name)
        if builder is None:
            logger.debug(f"No builder for chain '{chain_name}', skipping")
            continue

        # LLM 链需要 converter_target
        if chain_info.get("requires_llm", False) and converter_target is None:
            logger.debug(f"Chain '{chain_name}' requires LLM but no converter_target, skipping")
            continue

        try:
            converters = builder(converter_target)
        except Exception as e:
            logger.warning(f"Failed to build converter chain '{chain_name}': {e}")
            continue

        if not converters:
            continue

        # 去重: 同名 Converter 类只保留第一个实例
        for conv in converters:
            conv_type_name = type(conv).__name__
            if conv_type_name not in seen_types:
                seen_types.add(conv_type_name)
                result.append(conv)
                # P0: 达到深度上限即停止
                if len(result) >= effective_max:
                    break

    if len(result) > effective_max:
        logger.info(
            f"Converter chain truncated: {len(result)} → {effective_max} "
            f"(max depth limit, academic: HarmBench arXiv:2402.04249)"
        )
        result = result[:effective_max]

    return result
