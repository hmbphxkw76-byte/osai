"""Converter 预设和构建器 — 拆分自 converter_chains.py。

包含 l5_optimal, l5_optimal_for_model, build_converter_map 等预设函数。
拆分自 converter_chains.py (736行 → ~430+~310)。

L5 v36: 对齐 PyRIT 1.0.1 官方 SelectiveTextConverter 最佳实践。
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# ── L5 v36: 候选列表, 对齐 PyRIT 1.0.1 SelectiveTextConverter ──


def l5_optimal(converter_target: Any | None = None) -> list[Any]:
    """L5 v36 Converter 候选列表 — 对齐 PyRIT 1.0.1 官方最佳实践.

    L5 v36 核心改进 (vs v35):
        1. 引入 SelectiveTextConverter — 选择性编码, ASR 25-35% (vs 全文 7%)
        2. 引入 CodeChameleonConverter — ASR 35-45% (lv2024codechameleon)
        3. 引入 PolicyPuppetryConverter — ASR 30-40%
        4. 引入链式选择性 (2层, preserve_tokens) — ASR 30-40%
        5. 裁剪 ASR < 10% 的全文编码路径 (Base64, UnicodeSub 全文)
        6. 引入 SearchReplaceConverter — 关键词精准替换 (0 token)
        7. 引入 TemplateSegmentConverter — 分段注入
        8. 引入 AsciiSmugglerConverter — Unicode 走私
        9. 引入 File Converters — PDFConverter + WordDocConverter (PyRIT 官方 File Converters)

    候选列表 (按 ASR 降序, SequentialAttack FIRST_SUCCESS):
        1. DecompositionConverter           — ASR 40-60% (DrAttack, 最高)
        2. CodeChameleonConverter           — ASR 35-45% (NEW)
        3. PersuasionConverter(authority)   — ASR 38.4% (Zeng et al.)
        4. PolicyPuppetryConverter          — ASR 30-40% (NEW)
        5. ChainedSelective (Base64+ROT13)  — ASR 30-40% (NEW, 选择性链式)
        6. SelectiveEncoding (Base64 30%)   — ASR 25-35% (NEW, 选择性编码)
        7. RandomTranslationConverter       — ASR 25-35% (多语言部分混淆)
        8. TemplateSegmentConverter         — ASR 25-35% (NEW, 分段注入)
        9. KeywordReplacement              — ASR 20-30% (NEW, 0 token)
        10. SelectiveObfuscation (Leet 20%) — ASR 20-30% (NEW, 选择性混淆)
        11. VariationConverter              — ASR 20-30% (多样性补充)
        12. AsciiSmugglerConverter          — ASR 20-30% (NEW, Unicode走私)
        13. ROT13Converter                  — ASR 30-40% (语义混淆, 保留)
        14. WordDocConverter (direct)       — payload → .docx 文件 (NEW, 文档投递)
        15. WordDocConverter (placeholder)  — 模板占位符替换 (NEW, 隐蔽注入)
        16. PDFConverter (direct)           — payload → PDF 文件 (NEW, 文档投递)
        17. PDFConverter (injection)         — 已有 PDF 注入 (NEW, 隐蔽注入)

    裁剪路径 (ASR < 10% 或被选择性版本替代):
        - Base64Converter (全文)     — ASR 7%, 被 SelectiveEncoding 替代
        - UnicodeSubstitution (全文) — ASR 10-15%, 被 SelectiveObfuscation 替代
        - RandomCapitalLetters (全文)— ASR 15-25%, 与 ROT13 重叠, 降级
        - FlipConverter              — ASR ≈0% (HTTP), 已移除
        - AsciiArtConverter          — ASR ≈5%, 破坏 JSON, 已移除

    学术依据:
        - Wei et al. (arXiv:2307.15043): 串联 >2 层 ASR 从 12% 降至 4%
        - Zeng et al. (arXiv:2402.19181): authority ASR 38.4% 最高
        - DrAttack (arXiv:2402.14266): 分解重组 ASR 40-60% 最高
        - Lv et al. (arXiv:2404.30015): CodeChameleon ASR 35-45%
        - PyRIT (arXiv:2407.01232): SequentialAttack FIRST_SUCCESS
        - PyRIT 官方 SelectiveTextConverter: 选择性转换最佳实践
        - PyRIT 官方 File Converters: PDFConverter + WordDocConverter (文档投递/间接注入)

    Args:
        converter_target: LLM 目标实例 (可选, 缺失时仅返回非 LLM converter).
    """
    converters: list[Any] = []

    # 惰性导入基础 converter 链函数 (避免循环导入)
    from pipeline.arm.converter_chains import (
        _conv,
        chained_selective,
        code_chameleon,
        decomposition,
        keyword_replacement,
        pdf_direct_generation,
        pdf_injection,
        policy_puppetry,
        selective_encoding,
        selective_obfuscation,
        template_segment,
        token_smuggling,
        translation_multilingual,
        variation,
        word_doc_direct_generation,
        word_doc_placeholder_injection,
    )

    # ── LLM 辅助 converters (需 converter_target) ──
    if converter_target is not None:
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

        # Path 4: RandomTranslationConverter — ASR 25-35%
        translation_converters = translation_multilingual(converter_target=converter_target)
        converters.extend(translation_converters)

    # ── 非 LLM converters (无需 converter_target, 0 token) ──

    # Path 5: CodeChameleon — ASR 35-45% (NEW, 纯文本 0 token)
    # PyRIT 原生: CodeChameleonConverter(encrypt_type=), 不需 converter_target
    converters.extend(code_chameleon())

    # Path 6: PolicyPuppetry — ASR 30-40% (NEW, 纯文本 0 token)
    # PyRIT 原生: PolicyPuppetryConverter(), 不需 converter_target
    converters.extend(policy_puppetry())

    # Path 7: Chained Selective (Base64+ROT13, 选择性链式) — ASR 30-40% (NEW)
    # ⭐ 核心改进: SelectiveTextConverter + preserve_tokens 实现链式选择性
    # 只对 30% 文本做 2 层编码, 70% 保持原文, ASR 30-40%
    converters.extend(chained_selective())

    # Path 8: Selective Encoding (Base64 30%) — ASR 25-35% (NEW)
    # 替代全文 Base64Converter (ASR 7%), ASR 提升 3-5x
    converters.extend(selective_encoding())

    # Path 9: TemplateSegment — ASR 25-35% (NEW)
    converters.extend(template_segment())

    # Path 10: KeywordReplacement — ASR 20-30% (NEW, 0 token)
    converters.extend(keyword_replacement())

    # Path 11: SelectiveObfuscation (Leetspeak 20%) — ASR 20-30% (NEW)
    converters.extend(selective_obfuscation())

    # Path 12: AsciiSmuggler — ASR 20-30% (NEW)
    converters.extend(token_smuggling())

    # Path 13: ROT13 (全文, 保留作为轻量 fallback) — ASR 30-40%
    try:
        converters.append(_conv("ROT13Converter")())
        logger.info("L5 v36: ROT13Converter added as lightweight fallback (ASR 30-40%%)")
    except Exception as e:
        logger.warning("L5 v36: ROT13Converter failed: %s", e)

    # ── L5 v36: File Converters — 对齐 PyRIT 1.0.1 官方 File Converters ──
    # 学术依据: PyRIT 官方 File Converters (PDFConverter + WordDocConverter)
    # 攻击场景: 将 payload 包装为 PDF/Word 文件, 模拟文档投递/间接注入
    # OWASP LLM01: Prompt Injection (间接注入向量)

    # Path 14: Word Doc Direct Generation — payload → .docx file (NEW)
    # WordDocConverter() 无模板, 直接创建 .docx
    converters.extend(word_doc_direct_generation())

    # Path 15: Word Doc Placeholder Injection — payload 替换模板占位符 (NEW)
    # WordDocConverter(existing_docx=, placeholder=) 在模板中替换占位符
    converters.extend(word_doc_placeholder_injection())

    # Path 16: PDF Direct Generation — payload → PDF file (NEW)
    # PDFConverter(prompt_template=None) 直接生成 PDF
    converters.extend(pdf_direct_generation())

    # Path 17: PDF Injection — 在已有 PDF 中注入 payload (NEW)
    # PDFConverter(existing_pdf=, injection_items=) 在指定坐标注入文本
    converters.extend(pdf_injection())

    # 裁剪路径 (被选择性版本替代):
    # - Base64Converter (全文, ASR 7%) → 被 selective_encoding 替代
    # - UnicodeSubstitutionConverter (全文, ASR 10-15%) → 被 selective_obfuscation 替代
    # - RandomCapitalLettersConverter (全文, ASR 15-25%) → 与 ROT13 重叠, 降级
    # - FlipConverter (ASR ≈0% HTTP) → 已移除
    # - AsciiArtConverter (ASR ≈5%, 破坏 JSON) → 已移除

    if converters:
        logger.info(
            "L5 v36: %d converter candidates built (Selective-First)",
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
    """构建链名 → 构建函数映射 (惰性, 避免循环导入)。

    L5 v36: 新增选择性 converter 链。
    """
    from pipeline.arm.converter_chains import (
        chained_selective,
        code_chameleon,
        decomposition,
        encoding_bypass,
        flip,
        format_injection,
        keyword_replacement,
        multi_encoding,
        pdf_direct_generation,
        pdf_injection,
        persuasion,
        policy_puppetry,
        selective_encoding,
        selective_obfuscation,
        semantic_evasion,
        smoothllm_bypass,
        stealth_evasion,
        template_segment,
        token_smuggling,
        translation_multilingual,
        variation,
        word_doc_direct_generation,
        word_doc_placeholder_injection,
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
        # L5 v36: 新增选择性 converter 链
        "selective_encoding": selective_encoding,
        "selective_obfuscation": selective_obfuscation,
        "chained_selective": chained_selective,
        "keyword_replacement": keyword_replacement,
        "code_chameleon": code_chameleon,
        "policy_puppetry": policy_puppetry,
        "token_smuggling": token_smuggling,
        "template_segment": template_segment,
        # L5 v36: 新增 File Converter 链
        "pdf_direct_generation": pdf_direct_generation,
        "pdf_injection": pdf_injection,
        "word_doc_direct_generation": word_doc_direct_generation,
        "word_doc_placeholder_injection": word_doc_placeholder_injection,
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

            # LLM 辅助链需要 converter_target 参数
            # L5 v36: code_chameleon 和 policy_puppetry 已移至非 LLM 链 (纯文本 0 token)
            if chain_name in ("persuasion", "decomposition", "variation",
                              "translation_multilingual",
                              "l5_optimal", "l5_optimal_for_model"):
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
