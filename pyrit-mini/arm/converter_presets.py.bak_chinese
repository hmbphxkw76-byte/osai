# arXiv:2307.15043 — Wei et al., Encoding Bypass (serial stacking >2 layers ASR 12%→4%)
# arXiv:2402.19181 — Zeng et al., Persuasion (authority ASR 38.4%)
# arXiv:2402.14266 — DrAttack, Decomposition (ASR 40-60%)
# arXiv:2407.01232 — PyRIT, SequentialAttack FIRST_SUCCESS
# arXiv:2302.12173 — Greshake et al., Indirect injection (file converters target-dependent)
"""Converter presets and build orchestrator — split from converter_chains.py.

Contains l5_optimal, l5_optimal_for_model, build_converter_map.

L5 v39: Target-aware + technique-aware converter selection.
    - l5_optimal gains target_type param to filter inapplicable converters
    - build_converter_map assigns different chains per technique type:
      * Baseline techniques (prompt_sending) → no converters (raw payload)
      * Context techniques (many_shot/skeleton_key/role_play) → semantic-only
      * Escalation techniques (crescendo/tap/pair) → full L5 arsenal
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# ── Target type classification ──
# arXiv:2302.12173 — Greshake et al.: target capability fingerprint determines
#   which attack vectors are effective. MCP agents accept JSON text prompts,
#   not file uploads; pure LLM chat endpoints cannot process document files.

# File-type converters only effective on targets that accept file uploads
_FILE_CONVERTER_NAMES = {"PDFConverter", "WordDocConverter"}

# ── L5 v41: l5_optimal build cache ──
# arXiv:2407.01232 — SequentialAttack FIRST_SUCCESS uses the same converter
#   candidate list for every technique. Building 17 converters (decomposition,
#   persuasion, variation, translation, code_chameleon, ...) involves LLM calls
#   and heavy object instantiation. Without caching, build_converter_map calls
#   l5_optimal once PER technique, resulting in N×17 redundant builds.
#   Cache key: (id(converter_target), target_type) — when the same target is
#   reused across techniques, we return the cached list instead of rebuilding.
_L5_OPTIMAL_CACHE: dict[tuple[int, str], list[Any]] = {}

# v57: 标记是否已打印完整候选列表 (避免逐技术重复打印)
_L5_PRINTED_FULL_CANDIDATES: bool = False
_L5_PRINTED_FULL_REORDER: bool = False

# Techniques that are pure baseline (no converter needed — raw payload)
_BASELINE_TECHNIQUES = frozenset({"prompt_sending"})

# Techniques that use context/prefix injection (semantic converters only)
_CONTEXT_TECHNIQUES = frozenset({
    "many_shot", "skeleton_key", "role_play_movie_script",
    "role_play_persuasion", "context_compliance", "flip",
})


def _classify_target_type(
    capabilities: str | None = None,
    target_fingerprint: dict[str, Any] | None = None,
) -> str:
    """Classify target type for converter filtering.

    Returns one of: 'mcp_agent', 'http_api', 'llm_chat', 'browser', 'unknown'

    arXiv:2302.12173 — target capability fingerprint determines attack surface.
    arXiv:2407.01232 — PyRIT HTTPTarget sends JSON body, no file upload support.

    Args:
        capabilities: comma-separated capability string from target_fingerprint.
        target_fingerprint: full fingerprint dict (optional, for richer inference).

    Returns:
        Target type string for converter filtering.
    """
    if target_fingerprint:
        caps = set()
        cap_str = target_fingerprint.get("capabilities", "") or ""
        if cap_str:
            caps = {c.strip().lower() for c in cap_str.split(",") if c.strip()}
        app_type = (target_fingerprint.get("app_type") or "").lower()
        target_type = (target_fingerprint.get("target_type") or "").lower()

        if "mcp" in caps or "mcp_protocol" in caps:
            return "mcp_agent"
        if app_type == "browser" or target_type == "browser":
            return "browser"
        # Agent 级能力 (工具调用/工具劫持/A2A协议/嵌入RAG) → MCP Agent 类型
        # 这些能力表明目标是 Agent 而非纯聊天端点, 接受 JSON 文本而非文件上传
        # arXiv:2302.12173 — Agent 能力指纹决定攻击面
        # arXiv:2307.00929 — InjecAgent 工具劫持
        # arXiv:2407.16924 — A2A 协议横向移动
        # arXiv:2310.06870 — 嵌入反演泄露
        if caps & {"function_calling", "tool_hijack", "a2a_protocol", "embedding_rag"}:
            return "mcp_agent"
        if app_type in ("chat", "responses", "litellm"):
            return "llm_chat"

    if capabilities:
        caps = {c.strip().lower() for c in capabilities.split(",") if c.strip()}
        if "mcp" in caps or "mcp_protocol" in caps:
            return "mcp_agent"
        # Agent 级能力 → MCP Agent 类型 (同 target_fingerprint 分支逻辑)
        if caps & {"function_calling", "tool_hijack", "a2a_protocol", "embedding_rag"}:
            return "mcp_agent"

    return "http_api"


def _is_file_converter(converter: Any) -> bool:
    """Check if converter is a file-type converter (PDF/WordDoc)."""
    return type(converter).__name__ in _FILE_CONVERTER_NAMES


def l5_optimal(
    converter_target: Any | None = None,
    *,
    target_type: str = "unknown",
) -> list[Any]:
    """L5 v39 target-aware Converter candidate list.

    L5 v39 target-aware filtering:
        - MCP Agent (JSON text prompt): excludes File Converters (PDF/WordDoc)
          because MCP agents accept JSON {"prompt": "..."} not file uploads.
        - HTTP API (Burp JSON body): excludes File Converters for same reason.
        - LLM Chat (OpenAI/LiteLLM API): excludes File Converters (no upload API).
        - Browser (Playwright): File Converters retained (browser can upload files).

    Candidate list (by ASR descending, SequentialAttack FIRST_SUCCESS):
        1. DecompositionConverter           — ASR 40-60% (DrAttack, highest)
        2. CodeChameleonConverter           — ASR 35-45%
        3. PersuasionConverter(authority)   — ASR 38.4% (Zeng et al.)
        4. PolicyPuppetryConverter          — ASR 30-40%
        5. ChainedSelective (Base64+ROT13)  — ASR 30-40% (selective chain)
        6. SelectiveEncoding (Base64 30%)   — ASR 25-35%
        7. RandomTranslationConverter       — ASR 25-35%
        8. TemplateSegmentConverter         — ASR 25-35%
        9. KeywordReplacement              — ASR 20-30% (0 token)
        10. SelectiveObfuscation (Leet 20%) — ASR 20-30%
        11. VariationConverter              — ASR 20-30%
        12. AsciiSmugglerConverter          — ASR 20-30%
        13. ROT13Converter                  — ASR 30-40%
        14. WordDocConverter (direct)       — payload → .docx (target-dependent)
        15. WordDocConverter (placeholder)  — template injection (target-dependent)
        16. PDFConverter (direct)           — payload → PDF (target-dependent)
        17. PDFConverter (injection)         — existing PDF injection (target-dependent)

    Pruned paths (ASR < 10% or selective replacements):
        - Base64Converter (full-text) → replaced by SelectiveEncoding
        - UnicodeSubstitution (full-text) → replaced by SelectiveObfuscation
        - FlipConverter (ASR ≈ 0% HTTP) → removed
        - AsciiArtConverter (ASR ≈ 0%, breaks JSON) → removed

    Academic:
        - Wei et al. (arXiv:2307.15043): serial >2 layers ASR 12%→4%
        - Zeng et al. (arXiv:2402.19181): authority ASR 38.4%
        - DrAttack (arXiv:2402.14266): decomposition ASR 40-60%
        - Lv et al. (arXiv:2404.30015): CodeChameleon ASR 35-45%
        - PyRIT (arXiv:2407.01232): SequentialAttack FIRST_SUCCESS
        - Greshake et al. (arXiv:2302.12173): target capability → attack surface

    Args:
        converter_target: LLM target instance (optional).
        target_type: target classification from _classify_target_type.
            "unknown" (default) retains all converters (backward compatible).
    """
    # L5 v41: build cache — avoid N× redundant rebuild for multi-technique runs.
    # The converter list only depends on (converter_target, target_type), so
    # the same parameters always produce the same list. Cache prevents
    # rebuilding 17 converters × N techniques = 17N redundant builds.
    cache_key = (id(converter_target), target_type)
    cached = _L5_OPTIMAL_CACHE.get(cache_key)
    if cached is not None:
        logger.info(
            "L5 v41: Returning cached converter list (%d candidates, "
            "target_type=%s) — skipped redundant rebuild",
            len(cached), target_type,
        )
        return list(cached)  # shallow copy — caller may filter/sort

    converters: list[Any] = []

    # 鎯版€у鍏ュ熀纭€ converter 閾惧嚱鏁?(閬垮厤寰幆瀵煎叆)
    from arm.converter_chains import (
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

    # 鈹€鈹€ LLM 杈呭姪 converters (闇€ converter_target) 鈹€鈹€
    if converter_target is not None:
        # Path 1: Decomposition 鈥?ASR 40-60% (鏈€楂? DrAttack)
        decomp_converters = decomposition(converter_target=converter_target)
        converters.extend(decomp_converters)

        # Path 2: Persuasion authority 鈥?ASR 38.4%
        try:
            PersuasionConverter = _conv("PersuasionConverter")
            converters.append(PersuasionConverter(
                converter_target=converter_target,
                persuasion_technique="authority_endorsement",
            ))
        except (TypeError, ValueError, FileNotFoundError) as e:
            logger.warning("L5: PersuasionConverter(authority) failed: %s", e)

        # Path 3: Variation 鈥?ASR 20-30% (澶氭牱鎬цˉ鍏?
        var_converters = variation(converter_target=converter_target)
        converters.extend(var_converters)

        # Path 4: RandomTranslationConverter 鈥?ASR 25-35%
        translation_converters = translation_multilingual(converter_target=converter_target)
        converters.extend(translation_converters)

    # 鈹€鈹€ 闈?LLM converters (鏃犻渶 converter_target, 0 token) 鈹€鈹€

    # Path 5: CodeChameleon 鈥?ASR 35-45% (NEW, 绾枃鏈?0 token)
    # PyRIT 鍘熺敓: CodeChameleonConverter(encrypt_type=), 涓嶉渶 converter_target
    converters.extend(code_chameleon())

    # Path 6: PolicyPuppetry 鈥?ASR 30-40% (NEW, 绾枃鏈?0 token)
    # PyRIT 鍘熺敓: PolicyPuppetryConverter(), 涓嶉渶 converter_target
    converters.extend(policy_puppetry())

    # Path 7: Chained Selective (Base64+ROT13, 閫夋嫨鎬ч摼寮? 鈥?ASR 30-40% (NEW)
    # 猸?鏍稿績鏀硅繘: SelectiveTextConverter + preserve_tokens 瀹炵幇閾惧紡閫夋嫨鎬?
    # 鍙 30% 鏂囨湰鍋?2 灞傜紪鐮? 70% 淇濇寔鍘熸枃, ASR 30-40%
    converters.extend(chained_selective())

    # Path 8: Selective Encoding (Base64 30%) 鈥?ASR 25-35% (NEW)
    # 鏇夸唬鍏ㄦ枃 Base64Converter (ASR 7%), ASR 鎻愬崌 3-5x
    converters.extend(selective_encoding())

    # Path 9: TemplateSegment 鈥?ASR 25-35% (NEW)
    converters.extend(template_segment())

    # Path 10: KeywordReplacement 鈥?ASR 20-30% (NEW, 0 token)
    converters.extend(keyword_replacement())

    # Path 11: SelectiveObfuscation (Leetspeak 20%) 鈥?ASR 20-30% (NEW)
    converters.extend(selective_obfuscation())

    # Path 12: AsciiSmuggler 鈥?ASR 20-30% (NEW)
    converters.extend(token_smuggling())

    # Path 13: ROT13 (鍏ㄦ枃, 淇濈暀浣滀负杞婚噺 fallback) 鈥?ASR 30-40%
    try:
        converters.append(_conv("ROT13Converter")())
        logger.info("L5 v36: ROT13Converter added as lightweight fallback (ASR 30-40%%)")
    except Exception as e:
        logger.warning("L5 v36: ROT13Converter failed: %s", e)

    # 鈹€鈹€ L5 v36: File Converters 鈥?瀵归綈 PyRIT 1.0.1 瀹樻柟 File Converters 鈹€鈹€
    # 瀛︽湳渚濇嵁: PyRIT 瀹樻柟 File Converters (PDFConverter + WordDocConverter)
    # 鏀诲嚮鍦烘櫙: 灏?payload 鍖呰涓?PDF/Word 鏂囦欢, 妯℃嫙鏂囨。鎶曢€?闂存帴娉ㄥ叆
    # OWASP LLM01: Prompt Injection (闂存帴娉ㄥ叆鍚戦噺)

    # Path 14: Word Doc Direct Generation 鈥?payload 鈫?.docx file (NEW)
    # WordDocConverter() 鏃犳ā鏉? 鐩存帴鍒涘缓 .docx
    converters.extend(word_doc_direct_generation())

    # Path 15: Word Doc Placeholder Injection 鈥?payload 鏇挎崲妯℃澘鍗犱綅绗?(NEW)
    # WordDocConverter(existing_docx=, placeholder=) 鍦ㄦā鏉夸腑鏇挎崲鍗犱綅绗?
    converters.extend(word_doc_placeholder_injection())

    # Path 16: PDF Direct Generation 鈥?payload 鈫?PDF file (NEW)
    # PDFConverter(prompt_template=None) 鐩存帴鐢熸垚 PDF
    converters.extend(pdf_direct_generation())

    # Path 17: PDF Injection 鈥?鍦ㄥ凡鏈?PDF 涓敞鍏?payload (NEW)
    # PDFConverter(existing_pdf=, injection_items=) 鍦ㄦ寚瀹氬潗鏍囨敞鍏ユ枃鏈?
    converters.extend(pdf_injection())

    # ── L5 v39: Target-aware filtering ──
    # arXiv:2302.12173 — Greshake et al.: target type determines attack surface.
    # arXiv:2407.01232 — PyRIT HTTPTarget sends JSON body, no file upload.
    # File converters (PDF/WordDoc) only work on browser targets that can
    # upload files. MCP agents / HTTP APIs / LLM chat endpoints accept
    # text in JSON body, not binary file attachments.
    _skip_file_converters = target_type in ("mcp_agent", "http_api", "llm_chat")
    if _skip_file_converters:
        before_count = len(converters)
        converters = [c for c in converters if not _is_file_converter(c)]
        pruned = before_count - len(converters)
        if pruned > 0:
            logger.info(
                "L5 v39: Target type '%s' — pruned %d file converters "
                "(PDF/WordDoc not applicable, target accepts text-only JSON)",
                target_type, pruned,
            )

    if converters:
        logger.info(
            "L5 v39: %d converter candidates built "
            "(target_type=%s, Selective-First)",
            len(converters), target_type,
        )
        # v57: 只在首次打印完整候选列表, 后续技术复用缓存时只输出摘要
        global _L5_PRINTED_FULL_CANDIDATES
        if not _L5_PRINTED_FULL_CANDIDATES:
            for i, c in enumerate(converters):
                logger.info("  Candidate %d: %s", i + 1, type(c).__name__)
            _L5_PRINTED_FULL_CANDIDATES = True
        else:
            logger.info(
                "  (candidate list same as above, cached — skipped repeat)",
            )

    # L5 v41: cache the built list for reuse across techniques
    _L5_OPTIMAL_CACHE[cache_key] = list(converters)

    return converters


def l5_optimal_for_model(
    converter_target: Any | None = None,
    model_family: str | None = None,
    *,
    target_type: str = "unknown",
) -> list[Any]:
    """Model-family ASR-ordered + target-aware converter candidate list.

    Queries asr_priors.yaml:converter_asr for model-family specific ASR,
    sorts candidates by descending ASR so executor's FIRST_SUCCESS
    strategy tries the most effective converter first.

    Academic:
        - Zeng et al. (arXiv:2402.19181): different converters have
          different ASR per model family (e.g. DecompositionConverter
          gpt-4 ASR 50%, claude-3 ASR 45%)
        - asr_priors.yaml lines 178-236 contain model-family
          converter ASR priors

    Args:
        converter_target: LLM target instance (optional).
        model_family: target model family (e.g. "gpt-4", "claude-3").
            None falls back to l5_optimal() default order.
        target_type: target classification for file converter filtering.

    Returns:
        Converter candidates sorted by model-family ASR (descending).
    """
    # Get base candidates with target-aware filtering
    candidates = l5_optimal(converter_target=converter_target, target_type=target_type)

    if not model_family or not candidates:
        return candidates

    # 鏌ヨ妯″瀷鏃忓厛楠?
    try:
        from arm.seed_ranker import load_asr_priors
        priors = load_asr_priors(model_family)
        converter_asr = priors.get("converter_asr", {})
    except Exception as e:
        logger.debug("Failed to load converter ASR priors: %s 鈥?using default order", e)
        return candidates

    if not converter_asr:
        return candidates

    def _get_converter_asr(conv: Any) -> float:
        """浠?asr_priors.yaml 鏌ヨ璇?converter 瀵硅妯″瀷鏃忕殑 ASR.

        妯＄硦鍖归厤 converter 绫诲悕 + technique 鍙傛暟銆?
        """
        conv_class = type(conv).__name__
        # 妫€鏌ユ槸鍚︽湁 persuasion_technique 灞炴€?
        technique = getattr(conv, "persuasion_technique", "")
        sig_key = f"{conv_class}:{technique}" if technique else conv_class

        model_lower = model_family.lower()

        # 精确匹配 "Class:technique"
        if sig_key in converter_asr:
            entry = converter_asr[sig_key]
            # v58: 精确匹配优先
            for mk, mv in entry.items():
                if mk == "default":
                    continue
                if mk.lower() == model_lower:
                    return float(mv)
            # Pass 2: 最长子串匹配
            best_key = ""
            best_val = None
            for mk, mv in entry.items():
                if mk == "default":
                    continue
                mkl = mk.lower()
                if mkl in model_lower and len(mkl) > len(best_key):
                    best_key = mkl
                    best_val = mv
            if best_val is not None:
                return float(best_val)
            return float(entry.get("default", 0.0))

        # 妯＄硦鍖归厤 鈥?浠呯被鍚?
        for key, entry in converter_asr.items():
            if conv_class in key:
                # v58: 精确匹配优先
                for mk, mv in entry.items():
                    if mk == "default":
                        continue
                    if mk.lower() == model_lower:
                        return float(mv)
                # Pass 2: 最长子串匹配
                best_key = ""
                best_val = None
                for mk, mv in entry.items():
                    if mk == "default":
                        continue
                    mkl = mk.lower()
                    if mkl in model_lower and len(mkl) > len(best_key):
                        best_key = mkl
                        best_val = mv
                if best_val is not None:
                    return float(best_val)
                return float(entry.get("default", 0.0))

        return 0.0

    # 鎸夋ā鍨嬫棌鍏堥獙 ASR 闄嶅簭鎺掑簭 (绋冲畾鎺掑簭淇濇寔鍘熸湁鐩稿椤哄簭)
    candidates.sort(key=_get_converter_asr, reverse=True)

    logger.info(
        "L5 converter candidates re-ordered by model_family=%s ASR priors",
        model_family,
    )
    # v57: 只在首次打印完整 reordered 列表, 后续只输出摘要
    global _L5_PRINTED_FULL_REORDER
    if not _L5_PRINTED_FULL_REORDER:
        for i, c in enumerate(candidates):
            logger.info("  Reordered %d: %s (prior ASR=%.1f%%)", i + 1, type(c).__name__, _get_converter_asr(c))
        _L5_PRINTED_FULL_REORDER = True
    else:
        # 只输出前 3 个 (最有价值的 converter) + 摘要
        for i, c in enumerate(candidates[:3]):
            logger.info("  Top %d: %s (prior ASR=%.1f%%)", i + 1, type(c).__name__, _get_converter_asr(c))
        logger.info("  ... (%d more, same as previous technique)", max(0, len(candidates) - 3))

    return candidates


# 鈹€鈹€ 閾惧悕 鈫?鏋勫缓鍑芥暟鏄犲皠 鈹€鈹€
# 寤惰繜鏋勫缓浠ラ伩鍏嶅惊鐜鍏?(converter_chains 鍦ㄦā鍧楁湯灏?re-export 鏈ā鍧?
def _build_chain_builders() -> dict[str, Any]:
    """构建链名 → 构建函数映射 (延迟加载避免循环导入)。

    L5 v42: 移除 encoding_bypass 和 multi_encoding。
        原因: 二者返回 3-4 个 converter, 隐含串联堆叠语义,
        违反 Wei et al. (arXiv:2307.15043) 三层衰减定律 (ASR <4%)。
        替换方案: 如需编码绕过, 使用 selective_encoding (ASR 25-35%, 单 converter)。

    L5 v36: 新增 SelectiveTextConverter 链。
    """
    from arm.converter_chains import (
        chained_selective,
        code_chameleon,
        decomposition,
        flip,
        format_injection,
        keyword_replacement,
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
        "stealth": stealth_evasion,
        "persuasion": persuasion,
        "format": format_injection,
        "decomposition": decomposition,
        "variation": variation,
        "flip": flip,
        "semantic_evasion": semantic_evasion,
        "translation_multilingual": translation_multilingual,
        "smoothllm_bypass": smoothllm_bypass,
        "l5_optimal": l5_optimal,
        "l5_optimal_for_model": l5_optimal_for_model,
        # L5 v36: 新 SelectiveTextConverter 链
        "selective_encoding": selective_encoding,
        "selective_obfuscation": selective_obfuscation,
        "chained_selective": chained_selective,
        "keyword_replacement": keyword_replacement,
        "code_chameleon": code_chameleon,
        "policy_puppetry": policy_puppetry,
        "token_smuggling": token_smuggling,
        "template_segment": template_segment,
        # L5 v36: 新 File Converter 链
        "pdf_direct_generation": pdf_direct_generation,
        "pdf_injection": pdf_injection,
        "word_doc_direct_generation": word_doc_direct_generation,
        "word_doc_placeholder_injection": word_doc_placeholder_injection,
    }


# 妯″潡鍔犺浇鏃朵笉鏋勫缓, 棣栨璁块棶鏃舵瀯寤?
_CHAIN_BUILDERS: dict[str, Any] | None = None


def _get_chain_builders() -> dict[str, Any]:
    """鑾峰彇 CHAIN_BUILDERS (棣栨璋冪敤鏃舵瀯寤?銆?"""
    global _CHAIN_BUILDERS
    if _CHAIN_BUILDERS is None:
        _CHAIN_BUILDERS = _build_chain_builders()
    return _CHAIN_BUILDERS


def build_converter_map(
    technique_names: list[str],
    chain_names: list[str],
    converter_target: Any | None = None,
    model_family: str | None = None,
    *,
    target_type: str = "unknown",
    target_fingerprint: dict[str, Any] | None = None,
    converter_overrides: dict[str, list[str]] | None = None,
    seeds: list[Any] | None = None,
) -> dict[str, list[Any]]:
    """Build technique-aware + target-aware + seed-aware converter map.

    Returns: {technique_name: [converter_instances]}

    L5 v41 build cache lifecycle:
        The l5_optimal cache (_L5_OPTIMAL_CACHE) stores converter instances
        that hold references to converter_target. If converter_target is
        recycled or becomes stale (e.g. expired API key, closed connection),
        cached converters would use the stale target. To prevent this,
        build_converter_map clears the cache at the start of each call,
        ensuring fresh builds for each pipeline run. The cache only helps
        within a single build_converter_map call (multiple techniques
        sharing the same base list).

    Returns: {technique_name: [converter_instances]}

    L5 v40 seed-aware adaptation:
        - 新增 seeds 参数: 从种子 metadata (category/suitable_for) 感知
          攻击向量类型, 对 context techniques 放宽编码 converter 限制
        - 学术依据: Greshake et al. (arXiv:2302.12173) —
          攻击策略必须匹配目标攻击面, 种子 category 反映攻击向量类型
        - 如果 seeds 为 None, 回退到 L5 v39 行为 (semantic-only for context)

    L5 v39 technique-aware assignment:
        - Baseline techniques (prompt_sending): no converters — raw payload
          establishes ASR baseline for comparison.
          arXiv:2307.15043 — baseline needed to measure converter effectiveness.
        - Context techniques (many_shot/skeleton_key/role_play/context_compliance):
          semantic converters only (Persuasion/Decomposition/Translation/Variation).
          These techniques rely on context/prefix injection, not encoding.
          Encoding converters would corrupt the prefix structure.
          arXiv:2402.05124 — Many-shot relies on readable Q&A pattern.
          arXiv:2406.18112 — SkeletonKey relies on readable SK prefix.
        - Escalation/multi-turn techniques (crescendo/tap/pair/red_teaming):
          full L5 arsenal (all converters). Multi-turn generates adversarial
          prompts that benefit from maximum transformation diversity.
          arXiv:2402.12109 — Crescendo benefits from encoding bypass.
          arXiv:2312.02191 — TAP tree search explores diverse paths.

    L5 v39 target-aware filtering:
        - target_type passed to l5_optimal/l5_optimal_for_model to filter
          file converters (PDF/WordDoc) for text-only targets.
        - target_fingerprint used for richer classification if available.
          arXiv:2302.12173 — target capability → attack surface.

    Args:
        technique_names: technique name list.
        chain_names: converter chain name list.
        converter_target: LLM target instance (optional).
        model_family: target model family (e.g. "gpt-4") for ASR ordering.
        target_type: target classification string (mcp_agent/http_api/llm_chat/browser).
        target_fingerprint: full fingerprint dict for richer inference.

    Returns:
        technique_name → converter instance list mapping.
    """
    # L5 v41: Clear build cache at start of each build_converter_map call.
    # This ensures stale converter instances (holding references to old
    # converter_target objects) are never reused across pipeline runs.
    # The cache only helps WITHIN this call — multiple techniques sharing
    # the same base converter list built once at line 562 below.
    _L5_OPTIMAL_CACHE.clear()
    # v57: Reset dedup flags for this pipeline run
    global _L5_PRINTED_FULL_CANDIDATES, _L5_PRINTED_FULL_REORDER
    _L5_PRINTED_FULL_CANDIDATES = False
    _L5_PRINTED_FULL_REORDER = False

    # v57: Per-technique converter assignment summary (aggregated, not per-line)
    _tech_assignment_summary: list[str] = []

    # Auto-substitute l5_optimal → l5_optimal_for_model when model_family available
    effective_chain_names = list(chain_names)
    if model_family:
        effective_chain_names = [
            "l5_optimal_for_model" if cn == "l5_optimal" else cn
            for cn in effective_chain_names
        ]

    # L5 v39: classify target type if not provided
    if target_type == "unknown" and target_fingerprint:
        target_type = _classify_target_type(
            target_fingerprint.get("capabilities"),
            target_fingerprint,
        )

    # ── L5 v41: Pre-build base converter list ONCE (not per-technique) ──
    # arXiv:2407.01232 — SequentialAttack FIRST_SUCCESS: the same converter
    #   candidate list is used for every technique. Previously, the loop below
    #   called l5_optimal_for_model() once PER technique, resulting in N×17
    #   redundant converter builds (decomposition, persuasion, variation, etc.).
    #   Now we build the base list once and filter per-technique.
    #
    # For non-l5_optimal chains (persuasion, decomposition, etc.), we also
    # build them once here and reuse across techniques.
    base_converters: list[Any] = []
    _llm_chain_names = frozenset({
        "persuasion", "decomposition", "variation",
        "translation_multilingual",
        "l5_optimal", "l5_optimal_for_model",
    })
    for chain_name in effective_chain_names:
        builder = _get_chain_builders().get(chain_name)
        if builder is None:
            logger.warning("Unknown converter chain: %s, skipping", chain_name)
            continue
        if chain_name in _llm_chain_names:
            if chain_name == "l5_optimal_for_model":
                chain_converters = builder(
                    converter_target=converter_target,
                    model_family=model_family,
                    target_type=target_type,
                )
            else:
                chain_converters = builder(
                    converter_target=converter_target,
                    target_type=target_type,
                )
        else:
            chain_converters = builder()
        if chain_converters:
            base_converters.extend(chain_converters)

    # L5 v39: Semantic converter names (preserve payload readability)
    # arXiv:2402.05124 — Many-shot needs readable Q&A pattern
    # arXiv:2406.18112 — SkeletonKey needs readable SK prefix
    _SEMANTIC_CONVERTER_NAMES = {
        "PersuasionConverter", "DecompositionConverter",
        "VariationConverter", "RandomTranslationConverter",
        "TranslationConverter", "ToneConverter",
    }
    # L5 v40: Encoding converter set — allowed when seeds have encoding category
    # arXiv:2302.12173 — category-aware converter selection
    _ENCODING_CONVERTER_NAMES_CTX = {
        "ROT13Converter", "AsciiSmugglerConverter",
        "CodeChameleonConverter", "PolicyPuppetryConverter",
        "SelectiveTextConverter", "SearchReplaceConverter",
    }
    # L5 v40: Encoding categories — seeds designed for encoding bypass
    _ENCODING_CATEGORIES = {
        "token_smuggling", "encoded_injection",
        "token_smuggling_base64", "token_smuggling_cipher",
        "token_smuggling_hex", "token_smuggling_homoglyph",
        "token_smuggling_split", "token_smuggling_unicode",
        "base64_encoding",
    }

    # L5 v41: Per-technique semantic whitelist for context techniques.
    # Different context techniques rely on different structural properties:
    #   - many_shot: Q&A pattern readability → variation + translation safe,
    #     decomposition may split Q&A pairs (risky but ASR 40-60% justifies)
    #   - skeleton_key: SK prefix must remain intact → persuasion safe,
    #     decomposition may fragment SK prefix (risky but high ASR)
    #   - role_play_*: character consistency → persuasion + variation safe,
    #     translation may break character (medium risk)
    #   - context_compliance: compliance framing → persuasion primary,
    #     variation secondary, decomposition tertiary
    #   - flip: text inversion → variation safe (inversion is morphological),
    #     translation may interfere with inversion logic (high risk)
    # arXiv:2402.05124 — Many-shot Q&A pattern
    # arXiv:2406.18112 — SkeletonKey SK prefix
    _CONTEXT_SEMANTIC_WHITELIST: dict[str, set[str]] = {
        "many_shot": {
            "DecompositionConverter", "PersuasionConverter",
            "VariationConverter", "RandomTranslationConverter",
            "TranslationConverter",
        },
        "skeleton_key": {
            "PersuasionConverter", "VariationConverter",
            "RandomTranslationConverter", "TranslationConverter",
            "DecompositionConverter",
        },
        "role_play_movie_script": {
            "PersuasionConverter", "VariationConverter",
            "DecompositionConverter",
            "RandomTranslationConverter",
        },
        "role_play_persuasion": {
            "PersuasionConverter", "VariationConverter",
            "DecompositionConverter",
        },
        "context_compliance": {
            "PersuasionConverter", "VariationConverter",
            "DecompositionConverter",
            "RandomTranslationConverter",
            "TranslationConverter",
        },
        "flip": {
            "VariationConverter", "PersuasionConverter",
        },
    }

    # L5 v40: Pre-compute seed categories (shared across all techniques)
    seed_categories = set()
    if seeds:
        for group in seeds:
            for seed in getattr(group, "seeds", []):
                meta = getattr(seed, "metadata", {}) or {}
                cat = str(meta.get("category", "")).strip().lower()
                if cat:
                    seed_categories.add(cat)
    has_encoding_category = bool(seed_categories & _ENCODING_CATEGORIES)

    converter_map: dict[str, list[Any]] = {}

    for technique_name in technique_names:
        # ── L5 v39: Technique-aware converter assignment ──
        # arXiv:2307.15043 — baseline (prompt_sending) needs no converter
        # to establish ASR reference for converter effectiveness measurement.
        if technique_name in _BASELINE_TECHNIQUES and "l5_optimal" in chain_names:
            logger.info(
                "L5 v39: Technique '%s' is baseline — no converters "
                "(raw payload for ASR reference, arXiv:2307.15043)",
                technique_name,
            )
            # Still allow explicit non-l5_optimal chains if user specified
            non_l5_chains = [c for c in effective_chain_names if c not in ("l5_optimal", "l5_optimal_for_model")]
            if not non_l5_chains:
                continue  # No converters for baseline technique
            # For baseline + non-l5 chains, filter base_converters to those
            # built from non-l5 chains only (already in base_converters)
            effective_chains_for_tech = non_l5_chains
            # Rebuild from specific chains (not from base_converters which includes l5)
            converters: list[Any] = []
            for chain_name in effective_chains_for_tech:
                builder = _get_chain_builders().get(chain_name)
                if builder is None:
                    continue
                if chain_name in _llm_chain_names:
                    chain_converters = builder(
                        converter_target=converter_target,
                        target_type=target_type,
                    )
                else:
                    chain_converters = builder()
                if chain_converters:
                    converters.extend(chain_converters)
        elif technique_name in _CONTEXT_TECHNIQUES and "l5_optimal" in chain_names:
            # Context techniques: semantic converters only (with per-technique whitelist)
            # arXiv:2402.05124 — Many-shot needs readable Q&A pattern
            # arXiv:2406.18112 — SkeletonKey needs readable SK prefix
            # Encoding/obfuscation converters would corrupt the context structure
            logger.info(
                "L5 v39: Technique '%s' is context-based — "
                "semantic converters only (encoding would corrupt prefix, "
                "arXiv:2402.05124, arXiv:2406.18112)",
                technique_name,
            )
            # L5 v41: Use pre-built base_converters (shallow copy for filtering)
            converters = list(base_converters)
        else:
            # Escalation/full techniques: use all converters
            # L5 v41: Use pre-built base_converters (shallow copy)
            converters = list(base_converters)

        if technique_name in _CONTEXT_TECHNIQUES and converters:
            if has_encoding_category:
                # L5 v40: 编码类种子 + context technique → 允许编码 converter
                # arXiv:2302.12173 — category-aware
                logger.info(
                    "L5 v40: Technique '%s' is context-based BUT seeds have "
                    "encoding category (%s) — encoding converters allowed "
                    "(category-adaptive, arXiv:2302.12173)",
                    technique_name,
                    ", ".join(seed_categories & _ENCODING_CATEGORIES),
                )
                # 不过滤, 保留全部 converter (编码 + 语义)
            else:
                # L5 v41: Per-technique semantic whitelist
                # Different context techniques preserve different structural
                # properties, so each gets a tailored whitelist.
                whitelist = _CONTEXT_SEMANTIC_WHITELIST.get(
                    technique_name, _SEMANTIC_CONVERTER_NAMES,
                )
                semantic_only = [
                    c for c in converters
                    if type(c).__name__ in whitelist
                ]
                pruned_count = len(converters) - len(semantic_only)
                if pruned_count > 0:
                    logger.info(
                        "L5 v41: Technique '%s' — pruned %d non-semantic converters "
                        "(encoding/obfuscation would corrupt context structure, "
                        "whitelist=%d, arXiv:2402.05124, arXiv:2406.18112)",
                        technique_name, pruned_count, len(whitelist),
                    )
                if semantic_only:
                    converters = semantic_only
                else:
                    logger.info(
                        "L5 v39: Technique '%s' — no semantic converters available, "
                        "using raw payload (encoding converters excluded for context techniques)",
                        technique_name,
                    )
                    converters = []

        if converters:
            converter_map[technique_name] = converters
            _tech_assignment_summary.append(
                f"  {technique_name}: {len(converters)} converters"
            )

    # ── 增量借鉴: per-technique converter 追加 (technique:converter.xxx 语法) ──
    # 借鉴 pyrit_scan 的 per-technique converter 注册模式
    # converter_overrides: {technique_name: [chain_name, ...]}
    # 为指定 technique 追加额外的 converter chain (不覆盖全局链)
    if converter_overrides:
        builders = _get_chain_builders()
        for tech_name, extra_chains in converter_overrides.items():
            extra_converters: list[Any] = []
            for chain_name in extra_chains:
                builder = builders.get(chain_name)
                if builder is None:
                    logger.warning("Unknown converter chain in override: %s, skipping", chain_name)
                    continue
                # LLM-assisted chains need converter_target
                if chain_name in ("persuasion", "decomposition", "variation",
                                  "translation_multilingual",
                                  "l5_optimal", "l5_optimal_for_model"):
                    if chain_name == "l5_optimal_for_model":
                        chain_converters = builder(
                            converter_target=converter_target,
                            model_family=model_family,
                            target_type=target_type,
                        )
                    else:
                        chain_converters = builder(
                            converter_target=converter_target,
                            target_type=target_type,
                        )
                else:
                    chain_converters = builder()
                if chain_converters:
                    extra_converters.extend(chain_converters)

            if extra_converters:
                if tech_name in converter_map:
                    converter_map[tech_name].extend(extra_converters)
                    logger.info(
                        "Per-technique override: '%s' + %d converters (%s)",
                        tech_name,
                        len(extra_converters),
                        extra_chains,
                    )
                else:
                    # technique 不在全局链中 (如 baseline 无 converter), 追加创建
                    converter_map[tech_name] = extra_converters
                    logger.info(
                        "Per-technique override: '%s' created with %d converters (%s)",
                        tech_name,
                        len(extra_converters),
                        extra_chains,
                    )

    # v57: 输出聚合的技术 converter 分配摘要 (替代逐行 INFO)
    if _tech_assignment_summary:
        logger.info(
            "Converter assignment summary (%d techniques, target_type=%s):",
            len(_tech_assignment_summary), target_type,
        )
        for line in _tech_assignment_summary:
            logger.info(line)

    return converter_map

