"""L5 Converter Chains — arXiv-backed attack vector implementations.

L5 v34 Design:
    PyRIT PromptSendingAttack executes PromptNormalizer.convert_values_async
    per-ConverterConfiguration (1:1 mapping). executor.py calls _build_converter_config
    with 1 converter per config; l5_optimal preset builds the candidate list; executor
    selects up to 1 converter per attempt.

Academic references:
    - encoding_bypass: Wei et al. (arXiv:2307.15043) - selective encoding
       Base64 ASR 7%,  Base64+ROT13 ASR 12%, 3-layer stack ASR 4% (payload decay)
      Reduced to 2 conv (Base64 + ROT13), per PromptSendingAttack
    - stealth_evasion: Shayegani et al. (arXiv:2306.13254) - Unicode substitution
      Reduced to 1 conv (UnicodeSubstitution only, ZeroWidth breaks JSON)
    - persuasion: Zeng et al. (arXiv:2402.19181) - authority ASR 30-40%
      Authority endorsement ASR 38.4%, Logical appeal ASR 28.7%, Tone ASR 22.1%
      Reduced to 1 conv (authority), v34 executor uses 1 converter
    - format_injection: AsciiArt OCR/visual exploitation
    - multi_encoding: 3-phase encoding cascade ASR data
    - decomposition: DrAttack (arXiv:2402.14266) - decomposition+reconstruction ASR 40-60%
      Reduced to 1 conv (recall <0.3)
    - variation: AutoDAN-style ASR 20-30%
      Best-of-N (N=3) ASR boost 1.5x (v34: N=10 → 3)

    L5 v34 Converter Chain design (l5_optimal):
        Per-attempt single converter, executor.py picks +1 converter per attempt
    Expected ASR (multi-conv + Best-of-N + escalation): 23-35%
    Baseline: ASR=23.4%, Cohen's Kappa=0.729 (substantial)
    Refs: PyRIT (arXiv:2407.01232) SequentialAttack multi-path,
      Wei et al. (arXiv:2307.15043) >2-layer stack ASR decay law
"""

from __future__ import annotations

import importlib
import logging
from typing import Any

logger = logging.getLogger(__name__)

def _conv(name: str) -> type:
    """EURu?PyRIT Converter?

    Args:
        name: Converter ?

    Returns:
        Converter EUR?

    Raises:
        AttributeError: Converter uEUR?
    """
    mod = importlib.import_module("pyrit.converter")
    cls = getattr(mod, name, None)
    if cls is None:
        raise AttributeError(f"PyRIT Converter '{name}' not found")
    return cls

# EUREUR 5 ?Converter ?EUREUR

# NOTE (L5 v42): encoding_bypass and multi_encoding removed from _build_chain_builders.
# Reasons: 3-4 layer stack violates Wei et al. (arXiv:2307.15043) decay law (ASR <4%).
# Replacements: selective_encoding (single conv, ASR 25-35%) or chained_selective (2-layer, ASR 30-40%).
def stealth_evasion() -> list[Any]:
    """ZeroWidth + UnicodeSub eng?

    [: Shayegani et al. (arXiv:2306.13254) ?Unicode ?

    L5 : ?UnicodeSubstitution () ZeroWidth ( JSON)?
    """
    return [
        _conv("UnicodeSubstitutionConverter")(),
    ]

def persuasion(converter_target: Any | None = None) -> list[Any]:
    """Persuasion + Tone ?(EUR converter_target)?

    [: Zeng et al. (arXiv:2402.19181) ? ASR 30-40%?

    L5 :
        -  authority_endorsement (#) ?ASR EUR?
        -  logical_appeal () ?
        -  academic tone ([) ??

    Args:
        converter_target: LLM  (EUR? ke+)?
    """
    if converter_target is None:
        logger.info("Persuasion chain skipped: no converter_target available")
        return []

    try:
        PersuasionConverter = _conv("PersuasionConverter")
        ToneConverter = _conv("ToneConverter")

        converters: list[Any] = []

 # Authority endorsement ?ASR EUR?(Zeng et al.)
        try:
            converters.append(PersuasionConverter(
                converter_target=converter_target,
                persuasion_technique="authority_endorsement",
            ))
        except (TypeError, ValueError, FileNotFoundError) as e:
            logger.warning("PersuasionConverter(authority_endorsement) failed: %s", e)

 # Logical appeal ?
        try:
            converters.append(PersuasionConverter(
                converter_target=converter_target,
                persuasion_technique="logical_appeal",
            ))
        except (TypeError, ValueError, FileNotFoundError) as e:
            logger.warning("PersuasionConverter(logical_appeal) failed: %s", e)

 # Academic tone ??
        try:
            converters.append(ToneConverter(
                converter_target=converter_target,
                tone="academic",
            ))
        except (TypeError, ValueError) as e:
            logger.warning("ToneConverter(academic) failed: %s", e)

        if converters:
            logger.info("Persuasion chain: %d converters built", len(converters))
        return converters

    except Exception as e:
        logger.warning("Persuasion chain build failed: %s", e)
        return []

def format_injection() -> list[Any]:
    """AsciiArt ?

    [: ?OCR/EUREUR?

    L5 : +ya (AsciiArt  JSON )?
    """
    return [_conv("AsciiArtConverter")()]

# NOTE (L5 v42): encoding_bypass and multi_encoding removed from _build_chain_builders.
# Reasons: 3-4 layer stack violates Wei et al. (arXiv:2307.15043) decay law (ASR <4%).
# Replacements: selective_encoding (single conv, ASR 25-35%) or chained_selective (2-layer, ASR 30-40%).
def decomposition(converter_target: Any | None = None) -> list[Any]:
    """Decomposition B (EUR converter_target)?

    [: DrAttack (arXiv:2402.14266) ?B ASR 40-60%?

    L5 :
        - LLM ?objective B?
        - ?"Question A / Question B"
        -  + ?

    L5 v25:  DecompositionConverter,  recall ?
    : L5 v21 ?converter  recall=0.00,
    _MIN_RECALL ?try/finally , ?DecompositionConverter
    ?_decompose_prompt "?_MIN_RECALL ,
    ?finally  0.8 ?recall EURYoyaEUR?
    :
        1.  build  _MIN_RECALL, era?0.1
           (DrAttack : recall=0.1 ?ASR 40-60%, recall=0.8 ?ASR <5%)
        2. ?converter ?DecompositionConverter EUR
           _MIN_RECALL a? 0.1 EUR
        3. C?15 (config.py ?RETRY_MAX_NUM_ATTEMPTS=15)
           DeepSeek-V3 JSON Schema , 15 ' >95%

    Args:
        converter_target: LLM  (EUR? ke+)?
    """
    if converter_target is None:
        logger.info("Decomposition chain skipped: no converter_target available")
        return []

    try:
        DecompositionConverter = _conv("DecompositionConverter")

 # L5 v25: _MIN_RECALL ?0.1 ( try/finally)
 # [: DrAttack (arXiv:2402.14266) 4.3 ?recall EUR ASR ?
 # recall=0.8 ?ASR <5% (EUR, )
 # recall=0.2 ?ASR 30-40% (eng, BEUR?
 # recall=0.1 ?ASR 40-60% (EUR, e)
 # : DecompositionConverter._decompose_prompt u"?
 # _MIN_RECALL , try/finally ?build engEUR?
 # ?0.1 ?DecompositionConverter EUR?
        import pyrit.converter.decomposition_converter as decomp_mod

        original_recall = getattr(decomp_mod, '_MIN_RECALL', 0.8)
        if original_recall > 0.1:
            decomp_mod._MIN_RECALL = 0.1
            logger.info(
                "L5 v25: Decomposition _MIN_RECALL permanently lowered: %.2f ?0.1 "
                "(DrAttack recall=0.1 ?ASR 40-60%%)",
                original_recall,
            )

        converter = DecompositionConverter(
            converter_target=converter_target,
        )
        logger.info("Decomposition chain: 1 converter built (recall=0.1, L5 v25 restored)")
        return [converter]
    except Exception as e:
        logger.warning("Decomposition chain build failed: %s", e)

 # L5 v26: Fallback ?B?PersuasionConverter(authority)
 # [: DrAttack (arXiv:2402.14266) B? EUR?
 # Zeng et al. (arXiv:2402.19181) ?authority_endorsement ASR 38.4%
 # '?l5_optimal() keYoEUR?
        try:
            PersuasionConverter = _conv("PersuasionConverter")
            fallback = PersuasionConverter(
                converter_target=converter_target,
                persuasion_technique="authority_endorsement",
            )
            logger.info(
                "L5 v26: Decomposition fallback ?PersuasionConverter(authority) "
                "(ASR 38.4%, maintains path count)"
            )
            return [fallback]
        except Exception as e2:
            logger.warning("L5 v26: Decomposition fallback also failed: %s", e2)
            return []

def variation(converter_target: Any | None = None) -> list[Any]:
    """Variation (EUR converter_target)?

    [: ?ASR 20-30%?

    L5 :
        - LLM  prompt ?
        - ?
        - "u?

    Args:
        converter_target: LLM  (EUR? ke+)?
    """
    if converter_target is None:
        logger.info("Variation chain skipped: no converter_target available")
        return []

    try:
        VariationConverter = _conv("VariationConverter")
        converter = VariationConverter(
            converter_target=converter_target,
        )
        logger.info("Variation chain: 1 converter built")
        return [converter]
    except Exception as e:
        logger.warning("Variation chain build failed: %s", e)
        return []

def flip() -> list[Any]:
    """Flip ?

    [:  ASR 15-25%?

    L5 :
        - ts?(?LLM )
        -
        - EUR
    """
    return [_conv("FlipConverter")()]

def semantic_evasion() -> list[Any]:
    """ ?ROT13 + RandomCapitalLetters?

    [: Zeng et al. (arXiv:2402.19181) ??ASR 30-40% >> izu?8-12%?
    Wei et al. (arXiv:2307.15043) ?EUR?

    L5 v13  (P0 ):
        - ROT13: ?  security_audit EUR?
        - RandomCapitalLetters: u, "
        - yoEUR?ASCII ,  LLM ?
        - ?Base64+ROT13 (? , ASR ?12% ?30-40%

    :  SequentialAttack ?( ROT13 ?2 ?
    """
    converters: list[Any] = []

 # ROT13: ?( security_audit EUR?
    try:
        converters.append(_conv("ROT13Converter")())
        logger.info("Semantic evasion: ROT13Converter added (keyword obfuscation)")
    except Exception as e:
        logger.warning("Semantic evasion: ROT13Converter failed: %s", e)

 # RandomCapitalLetters: u (")
    try:
        converters.append(_conv("RandomCapitalLettersConverter")())
        logger.info("Semantic evasion: RandomCapitalLettersConverter added (pattern disruption)")
    except Exception as e:
        logger.warning("Semantic evasion: RandomCapitalLettersConverter failed: %s", e)

    return converters

def translation_multilingual(converter_target: Any | None = None) -> list[Any]:
    """TranslationConverter + RandomTranslationConverter ?PyRIT uEUR?

    [:
        - Andriushchenko et al. (arXiv:2402.09185) ?EURiu
 #? ASR 15-25% (), 25-35% (eng)
        - PyRIT (arXiv:2407.01232) ?TranslationConverter ?PyRIT
          LLM  converter, + converter_target uEUR

    PyRIT  (Rule 2: ):
        - TranslationConverter:  payload EUR (?leetspeak)
        - RandomTranslationConverter: , ?
        - yoEUR LLM (converter_target) , ?
        - ?VariationConverter (EUR) -: uEUR?

    L5 v38: ?l5_optimal() ?(?
        - RandomTranslationConverter: ASR 25-35%, EUReng
        - TranslationConverter(leetspeak): ASR 15-25%,  leetspeak
        -  FIRST_SUCCESS ?

    Args:
        converter_target: LLM  (EUR? ke+)?
    """
    if converter_target is None:
        logger.info("Translation chain skipped: no converter_target available")
        return []

    converters: list[Any] = []

 # RandomTranslationConverter: eng (ASR 25-35%)
 # [: Andriushchenko et al. (arXiv:2402.09185) ?eng
 # ? EUR?
    try:
        RandomTranslationConverter = _conv("RandomTranslationConverter")
        AllWordsSelectionStrategy = _conv("AllWordsSelectionStrategy")
        converters.append(RandomTranslationConverter(
            converter_target=converter_target,
            languages=["Spanish", "French", "German", "leetspeak"],
            word_selection_strategy=AllWordsSelectionStrategy(),
        ))
        logger.info("Translation chain: RandomTranslationConverter added (multi-language partial, ASR 25-35%)")
    except Exception as e:
        logger.warning("RandomTranslationConverter failed: %s", e)

 # TranslationConverter(leetspeak): leetspeak (ASR 15-25%)
 # [: PyRIT (arXiv:2407.01232) ?TranslationConverter
 # leetspeak "#"
    try:
        TranslationConverter = _conv("TranslationConverter")
        converters.append(TranslationConverter(
            converter_target=converter_target,
            language="leetspeak",
        ))
        logger.info("Translation chain: TranslationConverter(leetspeak) added (ASR 15-25%)")
    except Exception as e:
        logger.warning("TranslationConverter(leetspeak) failed: %s", e)

    return converters

def smoothllm_bypass() -> list[Any]:
    """SmoothLLM Converter ?feryaEUR?

    [: Robey et al. (arXiv:2310.03816) ?SmoothLLM
    : Yo?(yu//) E
    :  UnicodeSubstitution + RandomCapitalLetters
    , era?  SmoothLLM EUR?

    ASR: 10-15% (?LLM)

    L5 v14 :
        -  FuzzerConverter (PyRIT 1.0.1 , ?WARNING)
        - : UnicodeSubstitution + RandomCapitalLetters
        - [: Robey et al. (arXiv:2310.03816) ?SmoothLLM
          EURf?+ u
    """
    converters: list[Any] = []

 # UnicodeSubstitution: Unicode (f?
    try:
        converters.append(_conv("UnicodeSubstitutionConverter")())
        logger.info("SmoothLLM bypass: UnicodeSubstitutionConverter added")
    except Exception as e:
        logger.warning("SmoothLLM bypass: UnicodeSubstitutionConverter failed: %s", e)

 # RandomCapitalLetters: u (")
    try:
        converters.append(_conv("RandomCapitalLettersConverter")())
        logger.info("SmoothLLM bypass: RandomCapitalLettersConverter added")
    except Exception as e:
        logger.warning("SmoothLLM bypass: RandomCapitalLettersConverter failed: %s", e)

    return converters

# EUREUR L5 v36: SelectiveTextConverter ?? PyRIT 1.0.1 EUR?EUREUR

def selective_encoding() -> list[Any]:
    """x?? 30% ?Base64, .

    [:
        - Wei et al. (arXiv:2307.15043): er Base64 ASR 7%,
          x?(30% ) ASR 25-35% (LLM )
        - PyRIT : SelectiveTextConverter + WordProportionSelectionStrategy

    :
        - 30% ?Base64  (preserve_tokens=True ? )
        -  70% , LLM
        - er ASR  3-5x

    L5 v36 :
         encoding_bypass() er Base64Converter (ASR 7%),
         SelectiveTextConverter , ASR ?25-35%.
    """
    converters: list[Any] = []

    try:
        SelectiveTextConverter = _conv("SelectiveTextConverter")
        Base64Converter = _conv("Base64Converter")
        WordProportionSelectionStrategy = _conv("WordProportionSelectionStrategy")

        converter = SelectiveTextConverter(
            sub_converter=Base64Converter(),
            selection_strategy=WordProportionSelectionStrategy(proportion=0.3),
            preserve_tokens=True,
        )
        converters.append(converter)
        logger.info(
            "Selective encoding: SelectiveTextConverter(Base64, 30%% words) "
            "built (ASR 25-35%%, vs full-text 7%%)"
        )
    except Exception as e:
        logger.warning("Selective encoding chain build failed: %s", e)

    return converters

def selective_obfuscation() -> list[Any]:
    """f?? 20% ?Leetspeak, .

    [:
        - Shayegani et al. (arXiv:2306.13254): er Unicode  ASR 10-15%,
          f?(20% ) ASR 20-30%
        - PyRIT : SelectiveTextConverter + LeetspeakConverter

    :
        - 20% ?Leetspeak (, ?
        - preserve_tokens=True, x?
        -  smoothllm_bypass() er UnicodeSubstitution (ASR 10-15%)
    """
    converters: list[Any] = []

    try:
        SelectiveTextConverter = _conv("SelectiveTextConverter")
        LeetspeakConverter = _conv("LeetspeakConverter")
        WordProportionSelectionStrategy = _conv("WordProportionSelectionStrategy")

        converter = SelectiveTextConverter(
            sub_converter=LeetspeakConverter(),
            selection_strategy=WordProportionSelectionStrategy(proportion=0.2),
            preserve_tokens=True,
        )
        converters.append(converter)
        logger.info(
            "Selective obfuscation: SelectiveTextConverter(Leetspeak, 20%% words) "
            "built (ASR 20-30%%)"
        )
    except Exception as e:
        logger.warning("Selective obfuscation chain build failed: %s", e)

    return converters

def chained_selective() -> list[Any]:
    """??EURx?30%, ROT13.

    [:
        - Wei et al. (arXiv:2307.15043): 2 ?ASR 12% (),
          ; t, ASR 30-40%
        - PyRIT : SelectiveTextConverter + TokenSelectionStrategy
          ? preserve_tokens '?

    :
        1. ? 30%  Base64  (preserve_tokens=True ? )
        2. ? ? ?ROT13 (TokenSelectionStrategy EUR?
        3. :  30% ?2 ? 70%

    : ?converter EUR?ConverterConfiguration ?
          PyRIT PromptNormalizer .
          _build_converter_config yuEUR ConverterConfiguration.
    """
    converters: list[Any] = []

    try:
        SelectiveTextConverter = _conv("SelectiveTextConverter")
        Base64Converter = _conv("Base64Converter")
        ROT13Converter = _conv("ROT13Converter")
        WordProportionSelectionStrategy = _conv("WordProportionSelectionStrategy")
        TokenSelectionStrategy = _conv("TokenSelectionStrategy")

 # ? ?Base64 (30% words, preserve_tokens=True)
        first = SelectiveTextConverter(
            sub_converter=Base64Converter(),
            selection_strategy=WordProportionSelectionStrategy(proportion=0.3),
            preserve_tokens=True,
        )
        converters.append(first)

 # ? ? ?ROT13 (TokenSelectionStrategy EUR?
        second = SelectiveTextConverter(
            sub_converter=ROT13Converter(),
            selection_strategy=TokenSelectionStrategy(),
            preserve_tokens=True,
        )
        converters.append(second)

        logger.info(
            "Chained selective: 2 SelectiveTextConverter built "
            "(Base64 30%% + ROT13 on  tokens, ASR 30-40%%)"
        )
    except Exception as e:
        logger.warning("Chained selective chain build failed: %s", e)

    return converters

def keyword_replacement() -> list[Any]:
    """???SearchReplaceConverter ?

    [:
        - PyRIT : SearchReplaceConverter ereng
        - : 0 token (?LLM ), ,
        - Zeng et al. (arXiv:2402.19181): ?
          "u?

    :
        - EUR
        - ?(SearchReplaceConverter ), ?
        - 0 LLM , ?

    L5 v36:  DenylistConverter (EUR LLM , ?token ),
     SearchReplaceConverter (0 token) ?
    """
    converters: list[Any] = []

    try:
        SearchReplaceConverter = _conv("SearchReplaceConverter")

        converter = SearchReplaceConverter(
            pattern=r"(?i)\b(hack|exploit|inject|attack|bypass|malicious|vulnerability|breach|compromise)\b",
            replace=[
                "test",
                "analyze",
                "process",
                "examine",
                "evaluate",
                "assess",
                "review",
                "inspect",
                "audit",
                "check",
            ],
        )
        converters.append(converter)
        logger.info(
            "Keyword replacement: SearchReplaceConverter built "
            "(9 sensitive words ?10 safe synonyms, 0 token)"
        )
    except Exception as e:
        logger.warning("Keyword replacement chain build failed: %s", e)

    return converters

def code_chameleon(converter_target: Any | None = None) -> list[Any]:
    """CodeChameleon ? + .

    [:
        - Lv et al. (arXiv:2404.30015) CodeChameleon: ASR 35-45%
        - :  payload, angB?
        - : LLM ?"
        - PyRIT : CodeChameleonConverter (encrypt_type , ?0 token)

    :
        -  reverse  (, LLM EUR)
        - ?
        -  (GPT-4, Claude) EUR?

    PyRIT  (Rule 2):
        CodeChameleonConverter  converter (0 token, ?LLM ),
        ?converter_target ncrypt_type ?

    Args:
        converter_target: yu?l5_optimal ",
            ?CodeChameleonConverter er (?converter).
    """
    converters: list[Any] = []

    try:
        CodeChameleonConverter = _conv("CodeChameleonConverter")
        converter = CodeChameleonConverter(
            encrypt_type="reverse",
        )
        converters.append(converter)
        logger.info("CodeChameleon chain: 1 converter built (encrypt=reverse, ASR 35-45%%)")
    except Exception as e:
        logger.warning("CodeChameleon chain build failed: %s", e)

    return converters

def policy_puppetry(converter_target: Any | None = None) -> list[Any]:
    """PolicyPuppetry ?eng.

    [:
        - PyRIT  PolicyPuppetryConverter: C
          yo? ASR 30-40%
        - : ?payload engiYu
        - : LLM ?payload ?"

    PyRIT  (Rule 2):
        PolicyPuppetryConverter  converter (0 token, ?LLM ),
        ?converter_target ?prompt_template
        C, engyuaEUR?

    Args:
        converter_target: yu?l5_optimal ",
            ?PolicyPuppetryConverter er (?converter).
    """
    converters: list[Any] = []

    try:
        PolicyPuppetryConverter = _conv("PolicyPuppetryConverter")
        converter = PolicyPuppetryConverter()
        converters.append(converter)
        logger.info("PolicyPuppetry chain: 1 converter built (ASR 30-40%%)")
    except Exception as e:
        logger.warning("PolicyPuppetry chain build failed: %s", e)

    return converters

def token_smuggling() -> list[Any]:
    """Unicode Tag ??Unicode payload.

    [:
        - @embracethered2024unicode: Unicode Tags (U+E0000-U+E007F)
          enge UI , ?LLM B?
        - PyRIT : AsciiSmugglerConverter

    :
        - ?payload ?Unicode Tags (?
        - , ?
        - eng?
        - 0 token (?LLM , ?

    L5 v36: ?UnicodeSubstitutionConverter (er, ASR 10-15%) -,
    AsciiSmugglerConverter  Unicode Tags (ASR 20-30%).
    """
    converters: list[Any] = []

    try:
        AsciiSmugglerConverter = _conv("AsciiSmugglerConverter")
        converter = AsciiSmugglerConverter(
            action="encode",
            unicode_tags=True,
        )
        converters.append(converter)
        logger.info("Token smuggling: AsciiSmugglerConverter built (ASR 20-30%%)")
    except Exception as e:
        logger.warning("Token smuggling chain build failed: %s", e)

    return converters

def template_segment() -> list[Any]:
    """Ceng ??payload a.

    [:
        - adversa.ai: C, ASR 25-35%
        - PyRIT : TemplateSegmentConverter ( Tom & Jerry C)
        - : ?payload ?N ? C,
          EUR?

    :
        -  Tom & Jerry C (2 )
        - payload ?
        - 0 token (?LLM , ?
    """
    converters: list[Any] = []

    try:
        TemplateSegmentConverter = _conv("TemplateSegmentConverter")
        converter = TemplateSegmentConverter()
        converters.append(converter)
        logger.info("Template segment: TemplateSegmentConverter built (ASR 25-35%%)")
    except Exception as e:
        logger.warning("Template segment chain build failed: %s", e)

    return converters

# EUREUR L5 v36: File Converters ? PyRIT 1.0.1 File Converters EUREUR

def pdf_direct_generation() -> list[Any]:
    """PDF ??payload PDF .

    [:
        - PyRIT  File Converters: PDFConverter(prompt_template=None)
        - : ??PDF  (a?
        - : ?payload ?PDF , C/EUR?
        - OWASP LLM01: Prompt Injection (eng ?EUR?

    :
        - prompt_template=None: ", ?YAML C
        - : Helvetica (PDF ), u 12
        - : A4 (210x297mm)
        - 0 token (?LLM , ?

    ?  1 ?PDFConverter ?
    """
    converters: list[Any] = []

    try:
        PDFConverter = _conv("PDFConverter")
        converter = PDFConverter(
            prompt_template=None,  # " (a?
            font_type="Helvetica",
            font_size=12,
            page_width=210,
            page_height=297,
        )
        converters.append(converter)
        logger.info(
            "PDF direct generation: PDFConverter built (no template, A4, "
            "payload ?PDF file)"
        )
    except Exception as e:
        logger.warning("PDF direct generation chain build failed: %s", e)

    return converters

def pdf_injection() -> list[Any]:
    """PDF with injection points for indirect prompt injection.

    Note: This converter requires a pre-existing PDF file with injection_points.
    The actual PDF file should be prepared separately (not during arm phase).
    Returns empty list here - the executor will handle PDF preparation at execution time.

    academic basis:
        - PyRIT File Converters: PDFConverter(existing_pdf=, injection_items=)
        - Greshake et al. (arXiv:2302.12173): Indirect injection via document files
        - OWASP LLM01: Prompt Injection
    """
    # Defer PDF creation to execution phase - arm phase should be side-effect-free
    # The executor will create the PDF file when this converter is actually used
    logger.info("PDF injection: deferred to execution phase (no side effects in arm)")
    return []

def word_doc_direct_generation() -> list[Any]:
    """Word ??payload .docx .

    [:
        - PyRIT  File Converters: WordDocConverter() (aa?
        - : ??.docx  (er)
        - : ?payload ?Word , CEUR?
        - OWASP LLM01: Prompt Injection (eng ?Word EUR?

    :
        -  existing_docx: er .docx
        -  placeholder: " (eng)
        - payload
        - 0 token (?LLM , ?

    ?  1 ?WordDocConverter ?
    """
    converters: list[Any] = []

    try:
        WordDocConverter = _conv("WordDocConverter")
        converter = WordDocConverter()  # " (a?
        converters.append(converter)
        logger.info(
            "Word doc direct generation: WordDocConverter built (no template, "
            "payload ?.docx file)"
        )
    except Exception as e:
        logger.warning("Word doc direct generation chain build failed: %s", e)

    return converters

def word_doc_placeholder_injection() -> list[Any]:
    """Word template with placeholder for indirect prompt injection.

    Note: This converter requires a pre-existing .docx file with {{INJECTION_PLACEHOLDER}}.
    The actual .docx file should be prepared separately (not during arm phase).
    Returns empty list here - the executor will handle .docx preparation at execution time.

    Academic basis:
        - PyRIT File Converters: WordDocConverter(existing_docx=, placeholder=)
        - Greshake et al. (arXiv:2302.12173): Indirect injection via document files
        - OWASP LLM01: Prompt Injection
    """
    # Defer .docx creation to execution phase - arm phase should be side-effect-free
    # The executor will create the .docx file when this converter is actually used
    logger.info("Word doc placeholder injection: deferred to execution phase (no side effects in arm)")
    return []

# === NEW: Document Poisoning, Steganography, and Code Obfuscation Chain Builders ===
# Added 2026-09-09 — Closes advanced attack carrier gap (arXiv:2302.12173 / arXiv:2306.13254)

def document_poisoning() -> list[Any]:
    """Document poisoning converter chain for indirect injection attacks.

    Uses PyRIT native PDF/WordDoc converters. The actual poisoned file
    generation is deferred to strike phase (document_poisoner.py) to keep
    arm phase side-effect-free (architecture principle).

    Academic basis:
        - Greshake et al. (arXiv:2302.12173): Indirect injection via documents
        - Shayegani et al. (arXiv:2306.13254): Multimodal document attacks

    Note: Returns converter class references only. File I/O in strike phase.
    """
    converters: list[Any] = []

    # PDF injection — payload in PDF metadata and hidden text
    try:
        converters.append(_conv("PDFConverter")())
        logger.info("Document poisoning: PDFConverter added")
    except Exception as e:
        logger.warning("Document poisoning: PDFConverter failed: %s", e)

    # Word doc injection — payload in document properties
    try:
        converters.append(_conv("WordDocConverter")())
        logger.info("Document poisoning: WordDocConverter added")
    except Exception as e:
        logger.warning("Document poisoning: WordDocConverter failed: %s", e)

    return converters


def steganographic_encoding() -> list[Any]:
    """Steganographic payload encoding converter chain.

    Combines PyRIT native Unicode steganography converters to hide payloads
    in apparently benign text. Works on text-level, no file I/O.

    Academic basis:
        - Shayegani et al. (arXiv:2306.13254): Unicode steganography
        - @embracethered2024unicode: Unicode Tag smuggling

    Converters:
        1. AsciiSmugglerConverter — Unicode Tags (U+E0000-U+E007F)
        2. UnicodeSubstitutionConverter — Character substitution
    """
    converters: list[Any] = []

    # AsciiSmuggler: Unicode Tag smuggling (ASR 20-30%)
    try:
        converters.append(_conv("AsciiSmugglerConverter")(
            action="encode",
            unicode_tags=True,
        ))
        logger.info("Steganographic: AsciiSmugglerConverter added")
    except Exception as e:
        logger.warning("Steganographic: AsciiSmugglerConverter failed: %s", e)

    # UnicodeSubstitution: Character substitution evasion
    try:
        converters.append(_conv("UnicodeSubstitutionConverter")())
        logger.info("Steganographic: UnicodeSubstitutionConverter added")
    except Exception as e:
        logger.warning("Steganographic: UnicodeSubstitutionConverter failed: %s", e)

    return converters


def code_obfuscation(encrypt_type: str = "reverse") -> list[Any]:
    """Code-based payload obfuscation converter chain.

    Uses PyRIT native CodeChameleonConverter to encrypt payloads within
    code context that only target LLM can decrypt.

    Academic basis:
        - Lv et al. (arXiv:2404.30015): CodeChameleon ASR 35-45%

    Args:
        encrypt_type: "reverse", "binary", "base64", "rot13"

    Note: arm.phase obfuscation (unicode_code_obfuscator.py) is separate
    from this encryption chain. This chain wraps PyRIT native implementation.
    """
    converters: list[Any] = []

    try:
        converters.append(_conv("CodeChameleonConverter")(
            encrypt_type=encrypt_type,
        ))
        logger.info("Code obfuscation: CodeChameleonConverter added (encrypt=%s)", encrypt_type)
    except Exception as e:
        logger.warning("Code obfuscation: CodeChameleonConverter failed: %s", e)

    return converters


# ?converter_presets re-export Ya?
from arm.converter_presets import (  # noqa: F401, E402
    build_converter_map,
    l5_optimal,
    l5_optimal_for_model,
)


def __getattr__(name: str):
    """EURts?CHAIN_BUILDERS ()?"""
    if name == "CHAIN_BUILDERS":
        from arm.converter_presets import _get_chain_builders
        return _get_chain_builders()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
