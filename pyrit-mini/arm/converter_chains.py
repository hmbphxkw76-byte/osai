# -*- coding: utf-8 -*-
"""L5 converter chain catalog — facade re-exporting the SRP-split submodules.

The builder functions were split (R-DELIVERY-1) into single-responsibility
modules under `arm/`:
    - _converter_util            : shared `_conv` helper (PyRIT class resolver)
    - converter_chains_text      : text/semantic/encoding/code chains
    - converter_chains_document  : PDF/Word/poisoning (file-carrying) chains

This module re-exports the original public + private builder API so every
existing importer — including `converter_presets._get_chain_builders`'s lazy
`from arm.converter_chains import (...)` — keeps working unchanged.
"""

from __future__ import annotations

from arm._converter_util import _conv
from arm.converter_chains_document import (
    document_poisoning,
    pdf_direct_generation,
    pdf_injection,
    word_doc_direct_generation,
    word_doc_placeholder_injection,
)
from arm.converter_chains_text import (
    chained_selective,
    code_chameleon,
    code_obfuscation,
    decomposition,
    flip,
    format_injection,
    keyword_replacement,
    persuasion,
    policy_puppetry,
    selective_encoding,
    selective_obfuscation,
    semantic_evasion,
    smoothllm_bypass,
    stealth_evasion,
    steganographic_encoding,
    template_segment,
    token_smuggling,
    translation_multilingual,
    variation,
)

# Re-export the preset build/utility API so `from arm.converter_chains import
# build_converter_map / l5_optimal / l5_optimal_for_model` keeps working.
from arm.converter_presets import (
    build_converter_map,
    l5_optimal,
    l5_optimal_for_model,
)


__all__ = [
    "stealth_evasion",
    "persuasion",
    "format_injection",
    "decomposition",
    "variation",
    "flip",
    "semantic_evasion",
    "translation_multilingual",
    "smoothllm_bypass",
    "selective_encoding",
    "selective_obfuscation",
    "chained_selective",
    "keyword_replacement",
    "code_chameleon",
    "policy_puppetry",
    "token_smuggling",
    "template_segment",
    "code_obfuscation",
    "steganographic_encoding",
    "pdf_direct_generation",
    "pdf_injection",
    "word_doc_direct_generation",
    "word_doc_placeholder_injection",
    "document_poisoning",
    "_conv",
    "build_converter_map",
    "l5_optimal",
    "l5_optimal_for_model",
]
