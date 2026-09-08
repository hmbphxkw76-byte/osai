# arXiv:2307.15043 - Wei et al., Encoding Bypass (serial stacking >2 layers ASR 12%->4%)
# arXiv:2402.19181 - Zeng et al., Persuasion (authority ASR 38.4%)
# arXiv:2402.14266 - DrAttack, Decomposition (ASR 40-60%)
# arXiv:2407.01232 - PyRIT, SequentialAttack FIRST_SUCCESS
# arXiv:2302.12173 - Greshake et al., Indirect injection (file converters target-dependent)
"""Converter presets and build orchestrator - split from converter_chains.py.

Contains l5_optimal, l5_optimal_for_model, build_converter_map.

L5 v39: Target-aware + technique-aware converter selection.
    - l5_optimal gains target_type param to filter inapplicable converters
    - build_converter_map assigns different chains per technique type:
      * Baseline techniques (prompt_sending) -> no converters (raw payload)
      * Context techniques (many_shot/skeleton_key/role_play) -> semantic-only
      * Escalation techniques (crescendo/tap/pair) -> full L5 arsenal
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# == Target type classification ==
# arXiv:2302.12173 - Greshake et al.: target capability fingerprint determines
# which attack vectors are effective. MCP agents accept JSON text prompts,
# not file uploads; pure LLM chat endpoints cannot process document files.

# File-type converters only effective on targets that accept file uploads
_FILE_CONVERTER_NAMES = {"PDFConverter", "WordDocConverter"}

# == l5_optimal build cache ==
# Caches converter candidate lists to avoid redundant LLM calls during build.
# Cache is cleared at the start of each build_converter_map call to prevent
# unbounded growth and stale entries across pipeline runs.
# Note: We use target_type as cache key (not id(converter_target)) to avoid
# memory leaks from object id reuse after garbage collection.
_L5_OPTIMAL_CACHE: dict[str, list[Any]] = {}

# Techniques that are pure baseline (no converter needed - raw payload)
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
    """Classify target type based on capabilities and fingerprint."""
    # Check fingerprint first if available
    if target_fingerprint:
        cap_str = target_fingerprint.get("capabilities", "") or ""
        if cap_str:
            caps = set(cap_str.split(","))
            app_type = (target_fingerprint.get("app_type") or "").lower()
            target_type = (target_fingerprint.get("target_type") or "").lower()

            if "mcp" in caps or "mcp_protocol" in caps:
                return "mcp_agent"
            if app_type == "browser" or target_type == "browser":
                return "browser"
            if caps & {"function_calling", "tool_hijack", "a2a_protocol", "embedding_rag"}:
                return "mcp_agent"
            if app_type in ("chat", "responses", "litellm"):
                return "llm_chat"

    # Fallback to capabilities string
    if capabilities:
        caps = set(capabilities.split(","))
        if "mcp" in caps or "mcp_protocol" in caps:
            return "mcp_agent"
        if caps & {"function_calling", "tool_hijack", "a2a_protocol", "embedding_rag"}:
            return "mcp_agent"

    return "http_api"

def _is_file_converter(converter: Any) -> bool:
    """Check if converter is a file-type converter."""
    return type(converter).__name__ in _FILE_CONVERTER_NAMES

def l5_optimal(
    converter_target: Any | None = None,
    *,
    target_type: str = "unknown",
) -> list[Any]:
    """L5 v39 target-aware converter candidate list.

    Builds converter candidates filtered by target type:
        - mcp_agent: Exclude file converters (PDF/Word) that require file upload
        - http_api/llm_chat: Exclude file converters
        - unknown/browser: Include all converters

    Results are cached per target_type to avoid redundant LLM calls.
    """
    # Check cache first (keyed by target_type only - safe from id() reuse issues)
    if target_type in _L5_OPTIMAL_CACHE:
        return _L5_OPTIMAL_CACHE[target_type]

    # Import converter classes from converter_chains
    from arm.converter_chains import (
        code_chameleon,
        decomposition,
        format_injection,
        keyword_replacement,
        persuasion,
        policy_puppetry,
        selective_encoding,
        selective_obfuscation,
        smoothllm_bypass,
        template_segment,
        token_smuggling,
        translation_multilingual,
        variation,
    )

    candidates = []

    # Add converters based on target type
    if target_type != "mcp_agent":
        candidates.extend(persuasion(converter_target))
        candidates.extend(format_injection())
        candidates.extend(decomposition(converter_target))
        candidates.extend(variation(converter_target))
        candidates.extend(translation_multilingual(converter_target))
        candidates.extend(smoothllm_bypass())
        candidates.extend(selective_encoding())
        candidates.extend(selective_obfuscation())
        candidates.extend(keyword_replacement())
        candidates.extend(code_chameleon(converter_target))
        candidates.extend(policy_puppetry(converter_target))
        candidates.extend(token_smuggling())
        candidates.extend(template_segment())

    # Filter file converters for text-only targets
    if target_type in ("http_api", "llm_chat"):
        candidates = [c for c in candidates if not _is_file_converter(c)]

    # Cache and return
    _L5_OPTIMAL_CACHE[target_type] = candidates
    return candidates

def l5_optimal_for_model(
    converter_target: Any | None = None,
    *,
    model_family: str,
    target_type: str = "unknown",
) -> list[Any]:
    """L5 optimal converter list with model-specific ordering."""
    # For now, same as l5_optimal - model-specific ordering can be added later
    return l5_optimal(converter_target, target_type=target_type)

def _get_converter_asr(conv: Any) -> float:
    """Get historical ASR for converter (placeholder)."""
    return 0.0

def _build_chain_builders() -> dict[str, Any]:
    """Build chain builders dict from converter_chains."""
    from arm.converter_chains import (
        code_chameleon,
        decomposition,
        format_injection,
        keyword_replacement,
        persuasion,
        policy_puppetry,
        selective_encoding,
        selective_obfuscation,
        smoothllm_bypass,
        template_segment,
        token_smuggling,
        translation_multilingual,
        variation,
    )
    return {
        "persuasion": persuasion,
        "format_injection": format_injection,
        "decomposition": decomposition,
        "variation": variation,
        "translation_multilingual": translation_multilingual,
        "smoothllm_bypass": smoothllm_bypass,
        "selective_encoding": selective_encoding,
        "selective_obfuscation": selective_obfuscation,
        "keyword_replacement": keyword_replacement,
        "code_chameleon": code_chameleon,
        "policy_puppetry": policy_puppetry,
        "token_smuggling": token_smuggling,
        "template_segment": template_segment,
    }

def _get_chain_builders() -> dict[str, Any]:
    """Get or initialize chain builders."""
    return _build_chain_builders()

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
    """
    # Clear build cache at start of each call
    _L5_OPTIMAL_CACHE.clear()

    result: dict[str, list[Any]] = {}

    for technique in technique_names:
        if technique in _BASELINE_TECHNIQUES:
            # Baseline techniques: no converters needed
            result[technique] = []
        elif technique in _CONTEXT_TECHNIQUES:
            # Context techniques: semantic converters only
            candidates = l5_optimal(converter_target, target_type=target_type)
            # Filter to semantic-only converters (no encoding)
            semantic_converters = [
                c for c in candidates
                if type(c).__name__ not in _FILE_CONVERTER_NAMES
            ]
            result[technique] = semantic_converters
        else:
            # Escalation techniques: full L5 arsenal
            candidates = l5_optimal(converter_target, target_type=target_type)
            result[technique] = candidates

    return result
