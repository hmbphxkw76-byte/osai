"""Converter 棰勮鍜屾瀯寤哄櫒 鈥?鎷嗗垎鑷?converter_chains.py銆?

鍖呭惈 l5_optimal, l5_optimal_for_model, build_converter_map 绛夐璁惧嚱鏁般€?
鎷嗗垎鑷?converter_chains.py (736琛?鈫?~430+~310)銆?

L5 v36: 瀵归綈 PyRIT 1.0.1 瀹樻柟 SelectiveTextConverter 鏈€浣冲疄璺点€?
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# 鈹€鈹€ L5 v36: 鍊欓€夊垪琛? 瀵归綈 PyRIT 1.0.1 SelectiveTextConverter 鈹€鈹€


def l5_optimal(converter_target: Any | None = None) -> list[Any]:
    """L5 v36 Converter 鍊欓€夊垪琛?鈥?瀵归綈 PyRIT 1.0.1 瀹樻柟鏈€浣冲疄璺?

    L5 v36 鏍稿績鏀硅繘 (vs v35):
        1. 寮曞叆 SelectiveTextConverter 鈥?閫夋嫨鎬х紪鐮? ASR 25-35% (vs 鍏ㄦ枃 7%)
        2. 寮曞叆 CodeChameleonConverter 鈥?ASR 35-45% (lv2024codechameleon)
        3. 寮曞叆 PolicyPuppetryConverter 鈥?ASR 30-40%
        4. 寮曞叆閾惧紡閫夋嫨鎬?(2灞? preserve_tokens) 鈥?ASR 30-40%
        5. 瑁佸壀 ASR < 10% 鐨勫叏鏂囩紪鐮佽矾寰?(Base64, UnicodeSub 鍏ㄦ枃)
        6. 寮曞叆 SearchReplaceConverter 鈥?鍏抽敭璇嶇簿鍑嗘浛鎹?(0 token)
        7. 寮曞叆 TemplateSegmentConverter 鈥?鍒嗘娉ㄥ叆
        8. 寮曞叆 AsciiSmugglerConverter 鈥?Unicode 璧扮
        9. 寮曞叆 File Converters 鈥?PDFConverter + WordDocConverter (PyRIT 瀹樻柟 File Converters)

    鍊欓€夊垪琛?(鎸?ASR 闄嶅簭, SequentialAttack FIRST_SUCCESS):
        1. DecompositionConverter           鈥?ASR 40-60% (DrAttack, 鏈€楂?
        2. CodeChameleonConverter           鈥?ASR 35-45% (NEW)
        3. PersuasionConverter(authority)   鈥?ASR 38.4% (Zeng et al.)
        4. PolicyPuppetryConverter          鈥?ASR 30-40% (NEW)
        5. ChainedSelective (Base64+ROT13)  鈥?ASR 30-40% (NEW, 閫夋嫨鎬ч摼寮?
        6. SelectiveEncoding (Base64 30%)   鈥?ASR 25-35% (NEW, 閫夋嫨鎬х紪鐮?
        7. RandomTranslationConverter       鈥?ASR 25-35% (澶氳瑷€閮ㄥ垎娣锋穯)
        8. TemplateSegmentConverter         鈥?ASR 25-35% (NEW, 鍒嗘娉ㄥ叆)
        9. KeywordReplacement              鈥?ASR 20-30% (NEW, 0 token)
        10. SelectiveObfuscation (Leet 20%) 鈥?ASR 20-30% (NEW, 閫夋嫨鎬ф贩娣?
        11. VariationConverter              鈥?ASR 20-30% (澶氭牱鎬цˉ鍏?
        12. AsciiSmugglerConverter          鈥?ASR 20-30% (NEW, Unicode璧扮)
        13. ROT13Converter                  鈥?ASR 30-40% (璇箟娣锋穯, 淇濈暀)
        14. WordDocConverter (direct)       鈥?payload 鈫?.docx 鏂囦欢 (NEW, 鏂囨。鎶曢€?
        15. WordDocConverter (placeholder)  鈥?妯℃澘鍗犱綅绗︽浛鎹?(NEW, 闅愯斀娉ㄥ叆)
        16. PDFConverter (direct)           鈥?payload 鈫?PDF 鏂囦欢 (NEW, 鏂囨。鎶曢€?
        17. PDFConverter (injection)         鈥?宸叉湁 PDF 娉ㄥ叆 (NEW, 闅愯斀娉ㄥ叆)

    瑁佸壀璺緞 (ASR < 10% 鎴栬閫夋嫨鎬х増鏈浛浠?:
        - Base64Converter (鍏ㄦ枃)     鈥?ASR 7%, 琚?SelectiveEncoding 鏇夸唬
        - UnicodeSubstitution (鍏ㄦ枃) 鈥?ASR 10-15%, 琚?SelectiveObfuscation 鏇夸唬
        - RandomCapitalLetters (鍏ㄦ枃)鈥?ASR 15-25%, 涓?ROT13 閲嶅彔, 闄嶇骇
        - FlipConverter              鈥?ASR 鈮?% (HTTP), 宸茬Щ闄?
        - AsciiArtConverter          鈥?ASR 鈮?%, 鐮村潖 JSON, 宸茬Щ闄?

    瀛︽湳渚濇嵁:
        - Wei et al. (arXiv:2307.15043): 涓茶仈 >2 灞?ASR 浠?12% 闄嶈嚦 4%
        - Zeng et al. (arXiv:2402.19181): authority ASR 38.4% 鏈€楂?
        - DrAttack (arXiv:2402.14266): 鍒嗚В閲嶇粍 ASR 40-60% 鏈€楂?
        - Lv et al. (arXiv:2404.30015): CodeChameleon ASR 35-45%
        - PyRIT (arXiv:2407.01232): SequentialAttack FIRST_SUCCESS
        - PyRIT 瀹樻柟 SelectiveTextConverter: 閫夋嫨鎬ц浆鎹㈡渶浣冲疄璺?
        - PyRIT 瀹樻柟 File Converters: PDFConverter + WordDocConverter (鏂囨。鎶曢€?闂存帴娉ㄥ叆)

    Args:
        converter_target: LLM 鐩爣瀹炰緥 (鍙€? 缂哄け鏃朵粎杩斿洖闈?LLM converter).
    """
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

    # 瑁佸壀璺緞 (琚€夋嫨鎬х増鏈浛浠?:
    # - Base64Converter (鍏ㄦ枃, ASR 7%) 鈫?琚?selective_encoding 鏇夸唬
    # - UnicodeSubstitutionConverter (鍏ㄦ枃, ASR 10-15%) 鈫?琚?selective_obfuscation 鏇夸唬
    # - RandomCapitalLettersConverter (鍏ㄦ枃, ASR 15-25%) 鈫?涓?ROT13 閲嶅彔, 闄嶇骇
    # - FlipConverter (ASR 鈮?% HTTP) 鈫?宸茬Щ闄?
    # - AsciiArtConverter (ASR 鈮?%, 鐮村潖 JSON) 鈫?宸茬Щ闄?

    if converters:
        logger.info(
            "L5 v36: %d converter candidates built (Selective-First)",
            len(converters),
        )
        for i, c in enumerate(converters):
            logger.info("  Candidate %d: %s", i + 1, type(c).__name__)

    return converters


# 鈹€鈹€ 鏂偣 #3 淇: 鍩轰簬妯″瀷鏃忓厛楠?ASR 鎺掑簭鐨?L5 鍊欓€夊垪琛?鈹€鈹€


def l5_optimal_for_model(
    converter_target: Any | None = None,
    model_family: str | None = None,
) -> list[Any]:
    """鍩轰簬妯″瀷鏃忓厛楠?ASR 鎺掑簭鐨?L5 Converter 鍊欓€夊垪琛?(鏂偣 #3 淇).

    鏌ヨ asr_priors.yaml:converter_asr 涓妯″瀷鏃忕殑 ASR,
    鎸夐檷搴忔帓鍒楀€欓€?converter, 浣?executor.py 鐨?FIRST_SUCCESS
    绛栫暐浼樺厛灏濊瘯瀵硅妯″瀷鏈€鏈夋晥鐨?converter銆?

    瀛︽湳渚濇嵁:
        - Zeng et al. (arXiv:2402.19181) 鈥?涓嶅悓 converter 瀵逛笉鍚?
          妯″瀷鏃忕殑 ASR 宸紓鏄捐憲 (濡?DecompositionConverter 瀵?
          gpt-4 ASR 50%, 瀵?claude-3 ASR 45%)
        - asr_priors.yaml 绗?178-236 琛屽凡鍖呭惈 8 涓ā鍨嬫棌鐨?
          converter ASR 鍏堥獙鏁版嵁, 浣嗕粠鏈 l5_optimal() 浣跨敤

    Args:
        converter_target: LLM 鐩爣瀹炰緥 (鍙€?銆?
        model_family: 鐩爣妯″瀷鏃?(濡?"gpt-4", "claude-3", "qwen-32b")銆?
            None 鏃堕€€鍖栦负 l5_optimal() 鐨勯粯璁ら『搴忋€?

    Returns:
        鎸夋ā鍨嬫棌鍏堥獙 ASR 闄嶅簭鎺掑垪鐨?converter 鍊欓€夊垪琛ㄣ€?
    """
    # 鑾峰彇鍩虹鍊欓€夊垪琛?(l5_optimal 鐨勯粯璁ら『搴?
    candidates = l5_optimal(converter_target=converter_target)

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

        # 绮剧‘鍖归厤 "Class:technique"
        if sig_key in converter_asr:
            entry = converter_asr[sig_key]
            for mk, mv in entry.items():
                if mk == "default":
                    continue
                if mk.lower() in model_lower or model_lower in mk.lower():
                    return float(mv)
            return float(entry.get("default", 0.0))

        # 妯＄硦鍖归厤 鈥?浠呯被鍚?
        for key, entry in converter_asr.items():
            if conv_class in key:
                for mk, mv in entry.items():
                    if mk == "default":
                        continue
                    if mk.lower() in model_lower or model_lower in mk.lower():
                        return float(mv)
                return float(entry.get("default", 0.0))

        return 0.0

    # 鎸夋ā鍨嬫棌鍏堥獙 ASR 闄嶅簭鎺掑簭 (绋冲畾鎺掑簭淇濇寔鍘熸湁鐩稿椤哄簭)
    candidates.sort(key=_get_converter_asr, reverse=True)

    logger.info(
        "L5 converter candidates re-ordered by model_family=%s ASR priors",
        model_family,
    )
    for i, c in enumerate(candidates):
        logger.info("  Reordered %d: %s (prior ASR=%.1f%%)", i + 1, type(c).__name__, _get_converter_asr(c))

    return candidates


# 鈹€鈹€ 閾惧悕 鈫?鏋勫缓鍑芥暟鏄犲皠 鈹€鈹€
# 寤惰繜鏋勫缓浠ラ伩鍏嶅惊鐜鍏?(converter_chains 鍦ㄦā鍧楁湯灏?re-export 鏈ā鍧?
def _build_chain_builders() -> dict[str, Any]:
    """鏋勫缓閾惧悕 鈫?鏋勫缓鍑芥暟鏄犲皠 (鎯版€? 閬垮厤寰幆瀵煎叆)銆?

    L5 v36: 鏂板閫夋嫨鎬?converter 閾俱€?
    """
    from arm.converter_chains import (
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
        # L5 v36: 鏂板閫夋嫨鎬?converter 閾?
        "selective_encoding": selective_encoding,
        "selective_obfuscation": selective_obfuscation,
        "chained_selective": chained_selective,
        "keyword_replacement": keyword_replacement,
        "code_chameleon": code_chameleon,
        "policy_puppetry": policy_puppetry,
        "token_smuggling": token_smuggling,
        "template_segment": template_segment,
        # L5 v36: 鏂板 File Converter 閾?
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
) -> dict[str, list[Any]]:
    """涓烘瘡涓妧鏈瀯寤?Converter 閾惧垪琛ㄣ€?

    杩斿洖: {technique_name: [converter_instances]}

    绛栫暐:
        - 姣忎釜鎶€鏈垎閰嶆墍鏈夋寚瀹氱殑 Converter 閾?
        - SequentialAttack(FIRST_SUCCESS) 浼氭寜搴忓皾璇?
        - LLM 杈呭姪閾句粎鍦?converter_target 鍙敤鏃舵瀯寤?
        - 榛樿閾鹃『搴? persuasion(authority) > persuasion(logical) > tone(academic) > stealth

    鏂偣 #3 淇: 褰?model_family 闈炵┖涓?chain_names 鍖呭惈 "auto" 鎴?"l5_optimal" 鏃?
        鑷姩浣跨敤 l5_optimal_for_model 鏇夸唬 l5_optimal, 鎸夋ā鍨嬫棌鍏堥獙 ASR 鎺掑簭鍊欓€夊垪琛ㄣ€?

    Args:
        technique_names: 鎶€鏈悕绉板垪琛ㄣ€?
        chain_names: Converter 閾惧悕绉板垪琛ㄣ€?
        converter_target: LLM 鐩爣瀹炰緥 (鍙€?銆?
        model_family: 鐩爣妯″瀷鏃?(濡?"gpt-4", "claude-3"), 鐢ㄤ簬鍏堥獙鎺掑簭 (鍙€?銆?

    Returns:
        鎶€鏈悕 鈫?Converter 瀹炰緥鍒楄〃鐨勬槧灏勩€?
    """
    # 鏂偣 #3 淇: 鑷姩鏇挎崲 l5_optimal 鈫?l5_optimal_for_model
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

            # LLM 杈呭姪閾鹃渶瑕?converter_target 鍙傛暟
            # L5 v36: code_chameleon 鍜?policy_puppetry 宸茬Щ鑷抽潪 LLM 閾?(绾枃鏈?0 token)
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

