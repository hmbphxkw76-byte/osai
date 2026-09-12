"""Seed-Converter-Technique Intelligent Router — 种子-转换器-技术智能路由器

Routes seeds to optimal PyRIT converters and attack techniques based on
seed metadata (attack_vector, suitable_for, category) and target capabilities.

Component Coverage:
    - MCP: Tool Registration Manipulation, Message Injection, Schema Poisoning
    - A2A: Cross-Agent Injection, Identity Spoofing, Lifecycle Attacks
    - Model: Prompt Injection, Jailbreak, Backdoor Trigger, Filter Bypass
    - RAG: Retrieval Poisoning, Context Injection, Vector DB Contamination
    - Session: Context Leakage, Memory Poisoning, Session Boundary Violation
    - Web: Auth Bypass, Rate Limit Evasion, Request Smuggling, Gateway Bypass

Academic basis:
    - Wei et al. (arXiv:2307.15043): >2 layer serial stacking ASR degradation
    - Zeng et al. (arXiv:2402.19181): Authority endorsement ASR 38.4%
    - Chao et al. (arXiv:2310.08419): PAIR iterative optimization
    - Zou et al. (arXiv:2307.15043): GCG adversarial attacks
    - Xiang et al. (arXiv:2402.07867): RAG poisoning taxonomy
    - OWASP API Top 2023: API attack patterns

Integration:
    - arm/seed_ranker.py: Matches seeds after loading
    - strike/executor.py: Queries router during attack execution
    - core/phases/arm.py: ARM phase router integration
    - assess/component_scorers.py: Component-specific T0 scoring
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# ── Attack Vector -> Optimal Converter Mapping ──
# Maps seed attack_vector metadata to recommended converter signatures
# Based on empirical ASR from academic benchmarks
_ATTACK_VECTOR_CONVERTER_MAP: dict[str, list[str]] = {
    # Direct injection: minimal conversion needed
    "direct_injection": [],
    "persona_injection": [
        "ToneConverter:academic",
        "PersuasionConverter:authority_endorsement",
    ],
    # Indirect injection: document/file converters
    "indirect_injection": [
        "PDFConverter:direct",
        "WordDocConverter:direct",
    ],
    "multimodal_image_injection": [
        "PDFConverter:direct",
        "WordDocConverter:placeholder",
    ],
    "multimodal_audio_injection": [],
    "multimodal_file_metadata": [
        "PDFConverter:injection",
    ],
    # Encoding evasion: encoding converters
    "encoding_evasion": [
        "ROT13Converter",
        "Base64Converter",
        "AsciiSmugglerConverter",
    ],
    "token_smuggling": [
        "ROT13Converter",
        "UnicodeSubstitutionConverter",
    ],
    # Tool abuse: context compliance
    "tool_misuse": [],
    "tool_abuse": [],
    "function_call_exploit": [],
    # Model extraction: minimal conversion (API probing)
    "architecture_probe": [],
    "parameter_side_channel": [],
    "training_data_extraction": [],
    "capability_enumeration": [],
    # Protocol attacks: minimal conversion
    "mcp_tool_registration_manipulation": [],
    "mcp_message_injection": [],
    "mcp_response_manipulation": [],
    "agent_lifecycle_attack": [],
    "agent_termination_cascade": [],
    # Supply chain: template-based
    "sbom_analysis": [],
    "signature_verification_bypass": [],
    "dependency_confusion": [],
    # Adversarial: LLM-based converters
    "adversarial_suffix_analysis": [
        "DecompositionConverter",
        "CodeChameleonConverter",
    ],
    "pair_jailbreak_iteration": [],
    "tap_multi_turn": [],
    "crescendo_gradual_escalation": [],
    # RAG attacks: context-based
    "rag_extraction": [],
    "knowledge_base_enum": [],
    # Social engineering: persuasion
    "social_engineering": [
        "PersuasionConverter:authority_endorsement",
        "PersuasionConverter:expert_endorsement",
    ],
    "personalized_extraction": [
        "PersuasionConverter:authority_endorsement",
    ],
    # RAG components
    "rag_retrieval_poisoning": [],
    "rag_context_injection": [],
    "rag_vector_contamination": [],
    "rag_ranking_manipulation": [],
    "rag_payload_hiding": [],
    # Session/Memory components
    "session_context_leakage": [],
    "session_memory_poisoning": [],
    "session_boundary_violation": [],
    "session_cross_user_leakage": [],
    "context_persistence_exploit": [],
    # Web/API components
    "web_auth_bypass": [],
    "web_jwt_tampering": [],
    "web_rate_limit_evasion": [],
    "web_request_smuggling": [],
    "web_cache_poisoning": [],
    "web_gateway_bypass": [],
    "api_scope_escalation": [],
}

# ── Seed Category -> Optimal Technique Mapping ──
# Maps seed category metadata to recommended PyRIT attack techniques
_CATEGORY_TECHNIQUE_MAP: dict[str, list[str]] = {
    # Single-turn techniques (fast, low token)
    "prompt_injection": ["prompt_sending"],
    "persona_injection": ["skeleton_key", "role_play_persuasion"],
    "indirect_injection": ["prompt_sending"],
    "jailbreak": ["skeleton_key", "many_shot"],
    "encoding_evasion": ["prompt_sending"],
    # Multi-turn techniques (higher ASR, more tokens)
    "multi_turn_jailbreak": ["crescendo_simulated", "tap"],
    "crescendo_escalation": ["crescendo_simulated", "crescendo_movie_director"],
    "tap_tree_attack": ["tap"],
    "pair_iteration": ["pair"],
    "best_of_n_variation": ["best_of_n_jailbreak"],
    # Agent-specific
    "tool_hijack": ["context_compliance"],
    "tool_misuse": ["context_compliance"],
    "function_call_exploit": ["context_compliance"],
    "workflow_escalation": ["context_compliance", "skeleton_key"],
    "cross_agent_injection": ["context_compliance"],
    "agent_identity_spoofing": ["context_compliance", "skeleton_key"],
    "memory_poisoning": ["context_compliance"],
    # Model extraction (single-turn, API probing)
    "model_architecture_extraction": ["prompt_sending"],
    "model_parameter_inference": ["prompt_sending"],
    "training_data_extraction": ["prompt_sending"],
    "functional_clone_probe": ["prompt_sending"],
    # Protocol attacks
    "mcp_enumeration": ["prompt_sending"],
    "mcp_server_injection": ["prompt_sending", "context_compliance"],
    "mcp_context_poisoning": ["context_compliance"],
    "mcp_schema_poisoning": ["prompt_sending"],
    "agent_lifecycle_attack": ["prompt_sending"],
    "agent_model_update_attack": ["prompt_sending"],
    # Multimodal
    "image_injection": ["prompt_sending"],
    "audio_injection": ["prompt_sending"],
    "file_metadata_injection": ["prompt_sending"],
    "adversarial_vision": ["prompt_sending"],
    # Supply chain
    "sbom_manipulation_detection": ["prompt_sending"],
    "signature_verification_bypass": ["prompt_sending"],
    "dependency_confusion": ["prompt_sending"],
    # Misinformation
    "misinformation_narrative_chain": ["prompt_sending", "role_play_persuasion"],
    "deepfake_persona_synthesis": ["role_play_mersuasion"],
    "social_engineering_phishing": ["prompt_sending"],
    "business_email_compromise": ["prompt_sending"],
    # Adversarial optimization
    "gcg_adversarial_suffix": ["prompt_sending"],
    "gcg_transferability": ["prompt_sending"],
    "cross_model_adversarial": ["prompt_sending"],
    # RAG
    "rag_knowledge_extraction": ["prompt_sending"],
    "vector_db_poisoning": ["prompt_sending"],
    "rag_retrieval_poisoning": ["prompt_sending", "context_compliance"],
    "rag_context_injection": ["prompt_sending"],
    "rag_vector_contamination": ["prompt_sending"],
    "rag_ranking_manipulation": ["prompt_sending"],
    # Session/Memory
    "session_context_leakage": ["prompt_sending", "crescendo_simulated"],
    "session_memory_poisoning": ["context_compliance", "crescendo_simulated"],
    "session_boundary_violation": ["prompt_sending"],
    "session_cross_user_leakage": ["prompt_sending", "crescendo_simulated"],
    "context_persistence_exploit": ["context_compliance"],
    # Web/API
    "web_auth_bypass": ["prompt_sending"],
    "web_jwt_tampering": ["prompt_sending"],
    "web_rate_limit_evasion": ["prompt_sending"],
    "web_request_smuggling": ["prompt_sending"],
    "web_cache_poisoning": ["prompt_sending"],
    "web_gateway_bypass": ["prompt_sending"],
    "api_scope_escalation": ["prompt_sending", "context_compliance"],
    # Personalized
    "personalized_attack": ["prompt_sending", "skeleton_key"],
    "personalized_targeted_attack": ["context_compliance", "skeleton_key"],
    "personalized_secret_extraction": ["prompt_sending"],
}

# ── High Token Cost Categories (disabled by default) ──
# These seed categories consume excessive tokens and are filtered by default
HIGH_TOKEN_COST_CATEGORIES: set[str] = {
    # DoS / Resource Exhaustion
    "dos_resource_exhaustion",
    "model_dos",
    "token_smuggling_dos",
    "recursive_expansion",
    # High-volume generation
    "training_data_extraction",  # Can trigger large outputs
    "knowledge_base_enum",  # Many queries needed
    # Marked as T3 (experimental, low ASR)
    "wildteaming_exploratory",
}

# ── OWASP IDs that are high-cost ──
HIGH_TOKEN_OWASP_IDS: set[str] = {
    "LLM10",  # Model DoS / Unbounded Consumption
}

# ── Suitable For -> Technique Direct Mapping ──
# Direct mapping from seed metadata "suitable_for" to PyRIT technique
_SUITABLE_FOR_MAP: dict[str, str] = {
    "prompt_sending": "prompt_sending",
    "crescendo": "crescendo_simulated",
    "tap": "tap",
    "pair": "pair",
    "red_teaming": "red_teaming",
    "many_shot": "many_shot",
    "skeleton_key": "skeleton_key",
    "best_of_n": "best_of_n_jailbreak",
}


class SeedRouter:
    """Intelligent seed-converter-technique router.

    Routes seeds to optimal PyRIT attack configurations based on
    seed metadata and target capabilities.

    Usage:
        router = SeedRouter(ctx)
        config = router.get_optimal_config(seed_metadata)
        # config = {
        #     "converters": ["DecompositionConverter", ...],
        #     "technique": "prompt_sending",
        #     "enabled": True,
        # }
    """

    def __init__(self, ctx: Any) -> None:
        self.ctx = ctx
        self._capabilities = getattr(ctx, "capabilities", {}) or {}
        args = getattr(ctx, "args", None)
        self._enable_dos = bool(getattr(args, "enable_dos", False)) if args else False

    def get_optimal_config(self, seed_metadata: dict[str, Any]) -> dict[str, Any]:
        """Get optimal converter + technique configuration for a seed.

        Args:
            seed_metadata: Seed metadata dict with keys like:
                - attack_vector: str
                - category: str
                - suitable_for: str
                - owasp_id: str
                - tier: int

        Returns:
            Dict with keys:
                - converters: list[str] - Recommended converter signatures
                - technique: str - Recommended attack technique
                - enabled: bool - Whether this seed should be executed
                - reason: str - Explanation for the routing decision
        """
        # Check if seed should be disabled (high token cost)
        is_enabled, disable_reason = self._check_enabled(seed_metadata)
        if not is_enabled:
            return {
                "converters": [],
                "technique": "prompt_sending",
                "enabled": False,
                "reason": disable_reason,
            }

        # Get optimal converters
        converters = self._get_optimal_converters(seed_metadata)

        # Get optimal technique
        technique = self._get_optimal_technique(seed_metadata)

        return {
            "converters": converters,
            "technique": technique,
            "enabled": True,
            "reason": f"attack_vector={seed_metadata.get('attack_vector', 'default')}",
        }

    def get_converter_signatures(self, seed_metadata: dict[str, Any]) -> list[str]:
        """Get ordered list of converter signatures for a seed.

        Args:
            seed_metadata: Seed metadata dict.

        Returns:
            Ordered list of converter signature strings (highest priority first).
        """
        attack_vector = seed_metadata.get("attack_vector", "")
        category = seed_metadata.get("category", "")

        # Priority 1: attack_vector specific converters
        converters = _ATTACK_VECTOR_CONVERTER_MAP.get(attack_vector, [])

        # Priority 2: category-based fallback
        if not converters:
            converters = _ATTACK_VECTOR_CONVERTER_MAP.get(category, [])

        # Priority 3: capability-based augmentation
        cap_converters = self._get_capability_converters()
        # Merge: capability converters first, then seed-specific
        merged = list(cap_converters)
        for c in converters:
            if c not in merged:
                merged.append(c)

        return merged

    def get_technique(self, seed_metadata: dict[str, Any]) -> str:
        """Get optimal attack technique for a seed.

        Args:
            seed_metadata: Seed metadata dict.

        Returns:
            PyRIT attack technique name.
        """
        return self._get_optimal_technique(seed_metadata)

    def filter_seeds(self, seeds: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Separate seeds into enabled and disabled lists.

        Args:
            seeds: List of seed dicts with metadata.

        Returns:
            Tuple of (enabled_seeds, disabled_seeds).
        """
        enabled: list[dict[str, Any]] = []
        disabled: list[dict[str, Any]] = []

        for seed in seeds:
            is_enabled, reason = self._check_enabled(seed.get("metadata", {}))
            if is_enabled:
                enabled.append(seed)
            else:
                disabled.append(seed)

        if disabled:
            logger.info(
                "SeedRouter: %d seeds disabled (high token cost), %d enabled",
                len(disabled),
                len(enabled),
            )

        return enabled, disabled

    def _check_enabled(self, seed_metadata: dict[str, Any]) -> tuple[bool, str]:
        """Check if a seed should be enabled.

        Args:
            seed_metadata: Seed metadata dict.

        Returns:
            Tuple of (enabled, reason).
        """
        # Check tier (T3 = experimental, disabled by default)
        tier = seed_metadata.get("tier")
        if tier is not None and tier >= 3:
            return False, f"T{tier} experimental seed (disabled by default)"

        # Check OWASP ID
        owasp_id = seed_metadata.get("owasp_id", "")
        if owasp_id in HIGH_TOKEN_OWASP_IDS and not self._enable_dos:
            return False, f"{owasp_id} high token cost (use --enable-dos to enable)"

        # Check category
        category = seed_metadata.get("category", "")
        if category in HIGH_TOKEN_COST_CATEGORIES and not self._enable_dos:
            return False, f"Category '{category}' high token cost (disabled by default)"

        # Check for explicit difficulty marker
        difficulty = seed_metadata.get("difficulty", "")
        if difficulty == "very_hard" and tier is not None and tier >= 3:
            return False, "very_hard + T3 seed (disabled by default)"

        return True, "enabled"

    def _get_optimal_converters(self, seed_metadata: dict[str, Any]) -> list[str]:
        """Determine optimal converters for a seed."""
        # Get attack_vector based converters
        attack_vector = seed_metadata.get("attack_vector", "")
        converters = _ATTACK_VECTOR_CONVERTER_MAP.get(attack_vector, [])

        # If no specific mapping, use category-based
        if not converters:
            category = seed_metadata.get("category", "")
            converters = _ATTACK_VECTOR_CONVERTER_MAP.get(category, [])

        # Augment with capability-based converters
        cap_converters = self._get_capability_converters()
        merged = list(cap_converters)
        for c in converters:
            if c not in merged:
                merged.append(c)

        return merged

    def _get_optimal_technique(self, seed_metadata: dict[str, Any]) -> str:
        """Determine optimal attack technique for a seed."""
        # Priority 1: explicit suitable_for
        suitable_for = seed_metadata.get("suitable_for", "")
        if suitable_for in _SUITABLE_FOR_MAP:
            return _SUITABLE_FOR_MAP[suitable_for]

        # Priority 2: category-based
        category = seed_metadata.get("category", "")
        techniques = _CATEGORY_TECHNIQUE_MAP.get(category, [])
        if techniques:
            return techniques[0]

        # Priority 3: attack_vector-based
        attack_vector = seed_metadata.get("attack_vector", "")
        techniques = _CATEGORY_TECHNIQUE_MAP.get(attack_vector, [])
        if techniques:
            return techniques[0]

        # Default: prompt_sending (most efficient)
        return "prompt_sending"

    def _get_capability_converters(self) -> list[str]:
        """Get converters based on detected target capabilities."""
        converters: list[str] = []

        capability_converter_map = {
            "mcp": ["SearchReplaceConverter"],
            "rag": ["TranslationConverter"],
            "multimodal": ["PDFConverter:direct"],
            "file_upload": ["WordDocConverter:direct"],
        }

        for cap, cap_convs in capability_converter_map.items():
            if cap in self._capabilities:
                for c in cap_convs:
                    if c not in converters:
                        converters.append(c)

        return converters


def get_seed_router(ctx: Any) -> SeedRouter:
    """Factory function to create a SeedRouter for the given context.

    Args:
        ctx: PipelineContext with capabilities and args.

    Returns:
        Configured SeedRouter instance.
    """
    return SeedRouter(ctx)


# ── Internal helper for fallback ──
def _create_default_router() -> SeedRouter:
    """Create a SeedRouter with default settings (no context)."""

    class _DefaultCtx:
        capabilities = {}
        args = None

    return SeedRouter(_DefaultCtx())


def route_seed_to_config(
    seed_metadata: dict[str, Any],
    ctx: Any,
) -> dict[str, Any]:
    """Convenience function to route a single seed to its optimal config.

    Args:
        seed_metadata: Seed metadata dict.
        ctx: PipelineContext.

    Returns:
        Optimal config dict with converters, technique, enabled, reason.
    """
    router = SeedRouter(ctx)
    return router.get_optimal_config(seed_metadata)
