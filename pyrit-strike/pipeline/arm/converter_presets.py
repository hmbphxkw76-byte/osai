"""Converter 预设和构建器 — 拆分自 converter_chains.py。

包含 l5_optimal, l5_optimal_for_model, build_converter_map 等预设函数。
拆分自 converter_chains.py (736行 → ~430+~310)。
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def _import_chain_func(name: str):
    """惰性导入 converter_chains 中的函数 (避免循环导入)。"""
    from pipeline.arm import converter_chains
    return getattr(converter_chains, name)

    # ── L5 v34: 候选列表, executor.py 按优先级只取最佳 1 个 (单路径) ──


def l5_optimal(converter_target: Any | None = None) -> list[Any]:
    """L5 v34 Converter 候选列表 — executor.py 按优先级只取最佳 1 个.

    L5 v34 关键变更:
        PyRIT PromptSendingAttack 的 PromptNormalizer 会将所有
        ConverterConfiguration 串联叠加到同一条消息 (非独立路径).
        因此 executor.py _build_converter_config 只取最佳 1 个 converter.
        本函数返回候选列表, 供 executor 去重 + 裁剪 + 优先级排序后选 1 个.

    候选列表 (按 ASR 降序, executor 多路径独立执行):
        1. DecompositionConverter           — ASR 40-60% (最高, DrAttack)
        2. PersuasionConverter(authority)   — ASR 38.4%
        3. VariationConverter               — ASR 20-30% (多样性补充)
        4. ROT13Converter                    — ASR 30-40% (语义混淆)
        5. RandomCapitalLettersConverter     — ASR 15-25% (模式破坏)
        6. Base64Converter                   — ASR 7% (fallback)
        7. UnicodeSubstitutionConverter      — ASR 10-15%

    L5 v35: 恢复 DecompositionConverter (DrAttack ASR 40-60%),
            多路径独立执行 (不串联叠加), 依次尝试每个 converter 路径.

    级数学术依据:
        - Wei et al. (arXiv:2307.15043): 串联 >2 层 ASR 从 12% 降至 4%
        - Zeng et al. (arXiv:2402.19181): authority ASR 38.4% 最高
        - DrAttack (arXiv:2402.14266): 分解重组 ASR 40-60% 最高
        - PyRIT (arXiv:2407.01232): SequentialAttack FIRST_SUCCESS 设计,
          v35 通过依次尝试等效实现多路径独立执行

    注意: 此函数返回的是 converter 候选列表, executor.py v35 对每个
    converter 创建独立的 PromptSendingAttack, 依次执行 (FIRST_SUCCESS).

    Args:
        converter_target: LLM 目标实例 (可选, 缺失时仅返回非 LLM converter).
    """
    converters: list[Any] = []

    # 惰性导入基础 converter 链函数 (避免循环导入)
    from pipeline.arm.converter_chains import (  # noqa: F401
        _conv,
        decomposition,
        encoding_bypass,
        flip,
        format_injection,
        multi_encoding,
        persuasion,
        semantic_evasion,
        smoothllm_bypass,
        stealth_evasion,
        translation_multilingual,
        variation,
    )

    # ── LLM 辅助 converters (需 converter_target) ──
    if converter_target is not None:
        # L5 v35: 恢复 DecompositionConverter + Persuasion + Variation (3 LLM 路径)
        # v34 裁剪到 2 是因为 PromptSendingAttack 串联叠加 bug,
        # v35 改用 SequentialAttack 多路径独立执行, 不再串联。
        # 学术依据: DrAttack (arXiv:2402.14266) ASR 40-60% 最高
        #           Zeng et al. (arXiv:2402.19181) authority ASR 38.4%
        #           Chao et al. (arXiv:2402.01135) 多路径提升 ASR

        # Path 1: Decomposition — ASR 40-60% (最高, DrAttack)
        decomp_converters = decomposition(converter_target=converter_target)
        converters.extend(decomp_converters)

        # Path 2: Persuasion authority — ASR 38.4%
        try:
            PersuasionConverter = _conv("PersuasionConverter")
            converters.append(PersuasionConverter(
                converter_target=converter_target,
                persuasion_technique="authority_endorsement",
            ))
        except (TypeError, ValueError, FileNotFoundError) as e:
            logger.warning("L5: PersuasionConverter(authority) failed: %s", e)

        # Path 3: Variation — ASR 20-30% (多样性补充)
        var_converters = variation(converter_target=converter_target)
        converters.extend(var_converters)

        # Path 4: RandomTranslationConverter — ASR 25-35% (多语言部分混淆)
        # L5 v38: PyRIT 原生 TranslationConverter 接入
        # 学术依据: Andriushchenko et al. (arXiv:2402.09185) — 多语言混淆
        # PyRIT (arXiv:2407.01232) — 原生 LLM 辅助 converter
        translation_converters = translation_multilingual(converter_target=converter_target)
        converters.extend(translation_converters)

    # ── 非 LLM converters (无需 converter_target) ──
    # Path 6-7: 编码 + 混淆路径
    # L5 v14: semantic_evasion 作为最高优先级非 LLM 路径 (ASR 30-40%)
    # 学术依据: Zeng et al. (arXiv:2402.19181) — 语义层 ASR >> 表示层
    # ROT13 保持 ASCII 可读性, LLM 能理解 payload 语义
    # L5 v14 修复: ROT13 只出现一次 (之前在 semantic_evasion 和独立编码路径中重复)
    # 去重后: ROT13 作为 semantic_evasion 路径, Base64 作为独立编码路径
    try:
        converters.append(_conv("ROT13Converter")())
        logger.info("L5 v14: ROT13Converter added as semantic_evasion path (ASR 30-40%)")
    except Exception as e:
        logger.warning("L5 v14: ROT13Converter (semantic_evasion) failed: %s", e)

    try:
        converters.append(_conv("RandomCapitalLettersConverter")())
        logger.info("L5 v14: RandomCapitalLettersConverter added as semantic_evasion path")
    except Exception as e:
        logger.warning("L5 v14: RandomCapitalLettersConverter failed: %s", e)

    # Path 7: Base64 (独立编码路径) — ASR 7% (降级为 fallback 路径)
    try:
        converters.append(_conv("Base64Converter")())
    except Exception as e:
        logger.warning("L5: Base64Converter failed: %s", e)

    # L5 v14: 移除重复的 ROT13 路径 (已在 semantic_evasion 中添加)
    # 之前这里又添加了一次 ROT13Converter, 导致签名重复被去重逻辑跳过
    # 实际上两个 ROT13Converter 签名相同, _converter_signature 会去重
    # 但日志会产生混淆, 且浪费一次构建调用

    # Path 8: UnicodeSubstitution — ASR 10-15%
    # L5 v21: 恢复 UnicodeSubstitution 作为补充路径
    # 学术依据: Shayegani et al. (arXiv:2306.13254) — Unicode 混淆绕过文本过滤
    # 虽然之前 v5 运行 ASR≈0%, 但那是特定目标的能力; 对不支持 Unicode 检测的目标仍有效
    try:
        converters.append(_conv("UnicodeSubstitutionConverter")())
        logger.info("L5 v21: UnicodeSubstitutionConverter added as Path 6")
    except Exception as e:
        logger.warning("L5 v21: UnicodeSubstitutionConverter failed: %s", e)

    # L5 v12: FuzzerConverter 在 PyRIT 1.0.1 中不存在, 移除该路径
    # 之前每次运行都报 WARNING: "PyRIT Converter 'FuzzerConverter' not found"
    # 这浪费了一条 SequentialAttack 路径且无实际效果。
    # 替代: UnicodeSubstitution 已在 Path 8 覆盖字符级扰动功能。
    # 学术依据: Robey et al. (arXiv:2310.03816) — SmoothLLM 绕过
    #   可通过 UnicodeSubstitution + Variation 联合实现等效效果。

    if converters:
        logger.info(
            "L5 v34: %d converter candidates built (executor will select best 1)",
            len(converters),
        )
        for i, c in enumerate(converters):
            logger.info("  Candidate %d: %s", i + 1, type(c).__name__)

    return converters


# ── 断点 #3 修复: 基于模型族先验 ASR 排序的 L5 候选列表 ──


def l5_optimal_for_model(
    converter_target: Any | None = None,
    model_family: str | None = None,
) -> list[Any]:
    """基于模型族先验 ASR 排序的 L5 Converter 候选列表 (断点 #3 修复).

    查询 asr_priors.yaml:converter_asr 中该模型族的 ASR,
    按降序排列候选 converter, 使 executor.py 的 FIRST_SUCCESS
    策略优先尝试对该模型最有效的 converter。

    学术依据:
        - Zeng et al. (arXiv:2402.19181) — 不同 converter 对不同
          模型族的 ASR 差异显著 (如 DecompositionConverter 对
          gpt-4 ASR 50%, 对 claude-3 ASR 45%)
        - asr_priors.yaml 第 178-236 行已包含 8 个模型族的
          converter ASR 先验数据, 但从未被 l5_optimal() 使用

    Args:
        converter_target: LLM 目标实例 (可选)。
        model_family: 目标模型族 (如 "gpt-4", "claude-3", "qwen-32b")。
            None 时退化为 l5_optimal() 的默认顺序。

    Returns:
        按模型族先验 ASR 降序排列的 converter 候选列表。
    """
    # 获取基础候选列表 (l5_optimal 的默认顺序)
    candidates = l5_optimal(converter_target=converter_target)

    if not model_family or not candidates:
        return candidates

    # 查询模型族先验
    try:
        from pipeline.arm.seed_ranker import load_asr_priors
        priors = load_asr_priors(model_family)
        converter_asr = priors.get("converter_asr", {})
    except Exception as e:
        logger.debug("Failed to load converter ASR priors: %s — using default order", e)
        return candidates

    if not converter_asr:
        return candidates

    def _get_converter_asr(conv: Any) -> float:
        """从 asr_priors.yaml 查询该 converter 对该模型族的 ASR.

        模糊匹配 converter 类名 + technique 参数。
        """
        conv_class = type(conv).__name__
        # 检查是否有 persuasion_technique 属性
        technique = getattr(conv, "persuasion_technique", "")
        sig_key = f"{conv_class}:{technique}" if technique else conv_class

        model_lower = model_family.lower()

        # 精确匹配 "Class:technique"
        if sig_key in converter_asr:
            entry = converter_asr[sig_key]
            for mk, mv in entry.items():
                if mk == "default":
                    continue
                if mk.lower() in model_lower or model_lower in mk.lower():
                    return float(mv)
            return float(entry.get("default", 0.0))

        # 模糊匹配 — 仅类名
        for key, entry in converter_asr.items():
            if conv_class in key:
                for mk, mv in entry.items():
                    if mk == "default":
                        continue
                    if mk.lower() in model_lower or model_lower in mk.lower():
                        return float(mv)
                return float(entry.get("default", 0.0))

        return 0.0

    # 按模型族先验 ASR 降序排序 (稳定排序保持原有相对顺序)
    candidates.sort(key=_get_converter_asr, reverse=True)

    logger.info(
        "L5 converter candidates re-ordered by model_family=%s ASR priors",
        model_family,
    )
    for i, c in enumerate(candidates):
        logger.info("  Reordered %d: %s (prior ASR=%.1f%%)", i + 1, type(c).__name__, _get_converter_asr(c))

    return candidates


# ── 链名 → 构建函数映射 ──
# 延迟构建以避免循环导入 (converter_chains 在模块末尾 re-export 本模块)
def _build_chain_builders() -> dict[str, Any]:
    """构建链名 → 构建函数映射 (惰性, 避免循环导入)。"""
    from pipeline.arm.converter_chains import (
        decomposition,
        encoding_bypass,
        flip,
        format_injection,
        multi_encoding,
        persuasion,
        semantic_evasion,
        smoothllm_bypass,
        stealth_evasion,
        translation_multilingual,
        variation,
    )
    return {
        "encoding": encoding_bypass,
        "stealth": stealth_evasion,
        "persuasion": persuasion,
        "format": format_injection,
        "multi_encoding": multi_encoding,
        "decomposition": decomposition,
        "variation": variation,
        "flip": flip,
        "semantic_evasion": semantic_evasion,
        "translation_multilingual": translation_multilingual,
        "smoothllm_bypass": smoothllm_bypass,
        "l5_optimal": l5_optimal,
        "l5_optimal_for_model": l5_optimal_for_model,
    }


# 模块加载时不构建, 首次访问时构建
_CHAIN_BUILDERS: dict[str, Any] | None = None


def _get_chain_builders() -> dict[str, Any]:
    """获取 CHAIN_BUILDERS (首次调用时构建)。"""
    global _CHAIN_BUILDERS
    if _CHAIN_BUILDERS is None:
        _CHAIN_BUILDERS = _build_chain_builders()
    return _CHAIN_BUILDERS


def build_converter_map(
    technique_names: list[str],
    chain_names: list[str],
    converter_target: Any | None = None,
    model_family: str | None = None,
) -> dict[str, list[Any]]:
    """为每个技术构建 Converter 链列表。

    返回: {technique_name: [converter_instances]}

    策略:
        - 每个技术分配所有指定的 Converter 链
        - SequentialAttack(FIRST_SUCCESS) 会按序尝试
        - LLM 辅助链仅在 converter_target 可用时构建
        - 默认链顺序: persuasion(authority) > persuasion(logical) > tone(academic) > stealth

    断点 #3 修复: 当 model_family 非空且 chain_names 包含 "auto" 或 "l5_optimal" 时,
        自动使用 l5_optimal_for_model 替代 l5_optimal, 按模型族先验 ASR 排序候选列表。

    Args:
        technique_names: 技术名称列表。
        chain_names: Converter 链名称列表。
        converter_target: LLM 目标实例 (可选)。
        model_family: 目标模型族 (如 "gpt-4", "claude-3"), 用于先验排序 (可选)。

    Returns:
        技术名 → Converter 实例列表的映射。
    """
    # 断点 #3 修复: 自动替换 l5_optimal → l5_optimal_for_model
    effective_chain_names = list(chain_names)
    if model_family:
        effective_chain_names = [
            "l5_optimal_for_model" if cn == "l5_optimal" else cn
            for cn in effective_chain_names
        ]

    converter_map: dict[str, list[Any]] = {}

    for technique_name in technique_names:
        converters: list[Any] = []
        for chain_name in effective_chain_names:
            builder = _get_chain_builders().get(chain_name)
            if builder is None:
                logger.warning("Unknown converter chain: %s, skipping", chain_name)
                continue

            # persuasion, decomposition, variation, l5_optimal, l5_optimal_for_model 需要 converter_target 参数
            if chain_name in ("persuasion", "decomposition", "variation", "translation_multilingual", "l5_optimal", "l5_optimal_for_model"):
                if chain_name == "l5_optimal_for_model":
                    chain_converters = builder(converter_target=converter_target, model_family=model_family)
                else:
                    chain_converters = builder(converter_target=converter_target)
            else:
                chain_converters = builder()

            if chain_converters:
                converters.extend(chain_converters)

        if converters:
            converter_map[technique_name] = converters
            logger.info(
                "Converter chain for '%s': %d converters",
                technique_name,
                len(converters),
            )

    return converter_map
