"""
Target Profile Router
=====================

Layer 1 of the tiered progressive disclosure selection system.

Maps attack target types (agent, rag, mcp, llm, copilot, multimodal, etc.)
to relevant OWASP categories and technique groups. Supports automatic
inference from TargetCapabilities.

Design principles:
- Target type is the FIRST user decision (9-10 options, not 724)
- Each target type maps to a specific set of OWASP categories
- Capabilities-based auto-inference when target is known
- Does NOT modify any SeedGroup objects (pure routing/filtering)
- Optional metadata-based refinement for specialized target types
  (e.g., MULTIMODAL filters by technique_group prefix)

Alignment with PyRIT 1.0.0:
- TargetCapabilities → target_type inference
- OWASP Top 10 for LLM + Agentic AI category mapping
- Integrates at ②.5 layer (between CentralMemory and SeedGroupSelector)
- Maps to PyRIT native Target classes:
    LLM_DIRECT     → OpenAIChatTarget / OpenAIResponseTarget / HTTPTarget
    AGENT          → OpenAIResponseTarget (custom_functions) / PlaywrightTarget
    RAG_VECTOR     → AzureBlobStorageTarget / HTTPTarget (RAG endpoints)
    MCP_TOOL       → OpenAIResponseTarget (tool_calling) / HTTPTarget
    COPILOT        → WebSocketCopilotTarget / PlaywrightCopilotTarget
    MULTIMODAL     → OpenAIImageTarget / OpenAIVideoTarget / OpenAITTSTarget
    OUTPUT_HANDLING → HTTPTarget (output rendering endpoints)
    LLM_SAFETY     → OpenAIChatTarget (safety/availability testing)
    DEFENSE_BYPASS → PromptShieldTarget (defense mechanism testing)
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Set

from pyrit.models import SeedGroup

logger = logging.getLogger(__name__)


# ============================================================
# Target Type Enumeration
# ============================================================


class TargetType(str, Enum):
    """
    Attack target taxonomy.

    Each value maps to a distinct set of OWASP categories and
    represents a different class of AI system being attacked.

    Design rationale:
    - Organized by **attack domain** (what AI system you attack)
    - Each type maps to specific PyRIT native Target classes
    - DEFENSE_BYPASS is a specialized mode (test defense mechanisms)
    - Backward-compatible aliases: RAG→RAG_VECTOR, VECTOR_DB→RAG_VECTOR,
      WEB_OUTPUT→OUTPUT_HANDLING
    """

    LLM_DIRECT = "llm_direct"              # LLM01-03, 07: Direct LLM attacks
    AGENT = "agent"                         # ASI01-10: Agentic AI attacks
    RAG_VECTOR = "rag_vector"              # LLM04, LM08: RAG + Vector DB (merged)
    MCP_TOOL = "mcp_tool"                  # LLM06: MCP/Tool attacks
    COPILOT = "copilot"                    # LLM01,02,07: Copilot-specific attacks
    MULTIMODAL = "multimodal"              # LLM01: Multimodal injection/jailbreak
    OUTPUT_HANDLING = "output_handling"    # LLM05: Output handling security
    LLM_SAFETY = "llm_safety"              # LLM09-10: Safety/availability
    DEFENSE_BYPASS = "defense_bypass"      # LLM01: Defense bypass testing
    FULL_SWEEP = "full_sweep"              # All categories

    # ── Backward-compatible aliases ──
    # These allow old config values to still work after the rename/merge.
    # They are separate enum members with the same semantic meaning.

    @classmethod
    def from_string(cls, value: str) -> "TargetType":
        """
        Parse a target type string, supporting legacy aliases.

        Legacy mappings:
            "rag"       → RAG_VECTOR
            "vector_db" → RAG_VECTOR
            "web_output"→ OUTPUT_HANDLING

        Args:
            value: Target type string (e.g., "llm_direct", "rag", "copilot")

        Returns:
            TargetType enum member

        Raises:
            ValueError: If value is not a valid target type
        """
        legacy_aliases: Dict[str, "TargetType"] = {
            "rag": cls.RAG_VECTOR,
            "vector_db": cls.RAG_VECTOR,
            "web_output": cls.OUTPUT_HANDLING,
        }
        normalized = value.lower().strip()
        if normalized in legacy_aliases:
            logger.info(
                "Legacy target type '%s' mapped to '%s'",
                value, legacy_aliases[normalized].value,
            )
            return legacy_aliases[normalized]
        return cls(normalized)

    @property
    def display_name(self) -> str:
        names = {
            "llm_direct": "LLM Direct",
            "agent": "Agent",
            "rag_vector": "RAG & Vector",
            "mcp_tool": "MCP/Tool",
            "copilot": "Copilot",
            "multimodal": "Multimodal",
            "output_handling": "Output Handling",
            "llm_safety": "LLM Safety",
            "defense_bypass": "Defense Bypass",
            "full_sweep": "Full Sweep",
        }
        return names.get(self.value, self.value)

    @property
    def description(self) -> str:
        descs = {
            "llm_direct": "Direct LLM attacks (jailbreak, extraction, injection)",
            "agent": "Agentic AI attacks (goal hijack, tool misuse, trust)",
            "rag_vector": "RAG + Vector DB attacks (poisoning, injection, enumeration)",
            "mcp_tool": "MCP/Tool attacks (tool poison, capability confusion)",
            "copilot": "Copilot attacks (M365/GitHub — injection, data exfil, prompt leak)",
            "multimodal": "Multimodal attacks (image/video/audio injection, jailbreak)",
            "output_handling": "Output handling (XSS, insecure rendering, SQL injection)",
            "llm_safety": "Safety/availability (hallucination, resource exhaustion)",
            "defense_bypass": "Defense bypass (PromptShield, content filter evasion)",
            "full_sweep": "All OWASP categories",
        }
        return descs.get(self.value, "")

    @property
    def pyrit_targets(self) -> str:
        """PyRIT native Target classes for this target type."""
        targets = {
            "llm_direct": "OpenAIChatTarget, OpenAIResponseTarget, HTTPTarget",
            "agent": "OpenAIResponseTarget (custom_functions), PlaywrightTarget",
            "rag_vector": "AzureBlobStorageTarget, HTTPTarget",
            "mcp_tool": "OpenAIResponseTarget (tool_calling), HTTPTarget",
            "copilot": "WebSocketCopilotTarget, PlaywrightCopilotTarget",
            "multimodal": "OpenAIImageTarget, OpenAIVideoTarget, OpenAITTSTarget",
            "output_handling": "HTTPTarget, PlaywrightTarget",
            "llm_safety": "OpenAIChatTarget",
            "defense_bypass": "PromptShieldTarget",
            "full_sweep": "All available targets",
        }
        return targets.get(self.value, "")


# ============================================================
# Target Type → OWASP Category Mapping
# ============================================================

_TARGET_TYPE_TO_OWASP: Dict[TargetType, List[str]] = {
    TargetType.LLM_DIRECT: ["LLM01", "LLM02", "LLM03", "LLM07"],
    TargetType.AGENT: [
        "ASI01", "ASI02", "ASI03", "ASI04", "ASI05",
        "ASI06", "ASI07", "ASI08", "ASI09", "ASI10",
    ],
    TargetType.RAG_VECTOR: ["LLM04", "LLM08"],
    TargetType.MCP_TOOL: ["LLM06"],
    TargetType.COPILOT: ["LLM01", "LLM02", "LLM07"],
    TargetType.MULTIMODAL: ["LLM01"],
    TargetType.OUTPUT_HANDLING: ["LLM05"],
    TargetType.LLM_SAFETY: ["LLM09", "LLM10"],
    TargetType.DEFENSE_BYPASS: ["LLM01"],
    TargetType.FULL_SWEEP: [],  # Empty = all
}

# ── Optional metadata-based refinement ──
# Some target types need additional filtering beyond OWASP ID.
# This maps target types to a technique_group prefix that further
# narrows down seeds within the OWASP-filtered set.
_TECHNIQUE_GROUP_FILTER: Dict[TargetType, str] = {
    TargetType.MULTIMODAL: "multimodal",  # Only multimodal_* technique groups
}

# ── OWASP hint → default TargetType priority ──
# When inferring from an OWASP ID, use this mapping to resolve conflicts
# (e.g., LLM01 maps to LLM_DIRECT, COPILOT, MULTIMODAL, DEFENSE_BYPASS —
# LLM_DIRECT is the default).
_OWASP_HINT_DEFAULT: Dict[str, TargetType] = {
    "LLM01": TargetType.LLM_DIRECT,
    "LLM02": TargetType.LLM_DIRECT,
    "LLM03": TargetType.LLM_DIRECT,
    "LLM04": TargetType.RAG_VECTOR,
    "LLM05": TargetType.OUTPUT_HANDLING,
    "LLM06": TargetType.MCP_TOOL,
    "LLM07": TargetType.LLM_DIRECT,
    "LLM08": TargetType.RAG_VECTOR,
    "LLM09": TargetType.LLM_SAFETY,
    "LLM10": TargetType.LLM_SAFETY,
}


# ============================================================
# Target Profile
# ============================================================


@dataclass
class TargetProfile:
    """
    Profile of the attack target.

    Contains the target type, mapped OWASP categories, and optional
    capability information for auto-inference.

    Attributes:
        target_type: The selected target type
        owasp_categories: OWASP IDs to filter seed groups by
        capabilities: Target capabilities dict (for auto-inference)
        auth_mode: Authentication mode (api_key / identity / entra_id)
        modality: Primary modality (text / image / audio / video)
        technique_group_prefix: Optional prefix to further filter
            seeds by technique_group metadata (e.g., "multimodal")
    """

    target_type: TargetType
    owasp_categories: List[str] = field(default_factory=list)
    capabilities: Dict[str, bool] = field(default_factory=dict)
    auth_mode: str = ""
    modality: str = "text"
    technique_group_prefix: str = ""

    @property
    def is_full_sweep(self) -> bool:
        return self.target_type == TargetType.FULL_SWEEP


# ============================================================
# Target Profile Router
# ============================================================


class TargetProfileRouter:
    """
    Routes target type selection to OWASP categories.

    Layer 1 of the three-tier progressive disclosure system:
        Layer 1: TargetProfileRouter (target type → OWASP)
        Layer 2: ASRRankBuilder (OWASP → ranked technique groups)
        Layer 3: TieredSelectionWizard (strategy selection)

    Usage:
        router = TargetProfileRouter()

        # Manual selection
        profile = router.get_profile(TargetType.AGENT)

        # Auto-inference from capabilities
        profile = router.infer_profile(
            capabilities={"chat": True, "tool_calling": True, "memory": True}
        )

        # Filter seed groups by target type
        filtered = router.filter_seed_groups(all_groups, profile)

        # Backward-compatible string parsing
        tt = TargetType.from_string("rag")  # → RAG_VECTOR
    """

    # Capability → TargetType inference rules (ordered by specificity)
    _INFERENCE_RULES: List[tuple] = [
        # (capabilities_set, target_type) — most specific first
        ({"retrieval"}, TargetType.RAG_VECTOR),
        ({"tool_calling", "memory"}, TargetType.AGENT),
        ({"tool_calling", "external_tools"}, TargetType.MCP_TOOL),
        ({"tool_calling"}, TargetType.MCP_TOOL),
        ({"memory"}, TargetType.AGENT),
        ({"embedding_store"}, TargetType.RAG_VECTOR),
        ({"copilot", "websocket"}, TargetType.COPILOT),
        ({"copilot"}, TargetType.COPILOT),
        ({"image_generation"}, TargetType.MULTIMODAL),
        ({"video_generation"}, TargetType.MULTIMODAL),
        ({"audio_generation"}, TargetType.MULTIMODAL),
        ({"prompt_shield"}, TargetType.DEFENSE_BYPASS),
        ({"web_rendering"}, TargetType.OUTPUT_HANDLING),
        ({"chat"}, TargetType.LLM_DIRECT),
    ]

    @classmethod
    def get_profile(cls, target_type: TargetType) -> TargetProfile:
        """Get target profile for a specific target type."""
        owasp_cats = list(_TARGET_TYPE_TO_OWASP.get(target_type, []))
        technique_prefix = _TECHNIQUE_GROUP_FILTER.get(target_type, "")
        return TargetProfile(
            target_type=target_type,
            owasp_categories=owasp_cats,
            technique_group_prefix=technique_prefix,
        )

    @classmethod
    def infer_profile(
        cls,
        capabilities: Optional[Dict[str, bool]] = None,
        owasp_hint: Optional[str] = None,
    ) -> TargetProfile:
        """
        Infer target profile from capabilities or OWASP hint.

        Args:
            capabilities: Dict of capability → bool from TargetFactory
            owasp_hint: OWASP ID hint (e.g., "LLM01" → LLM_DIRECT)

        Returns:
            TargetProfile with inferred type and OWASP categories
        """
        # Try OWASP hint first (most direct)
        if owasp_hint:
            inferred_type = cls._infer_from_owasp_hint(owasp_hint)
            return cls.get_profile(inferred_type)

        # Try capabilities
        if capabilities:
            inferred_type = cls._infer_from_capabilities(capabilities)
            profile = cls.get_profile(inferred_type)
            profile.capabilities = capabilities
            return profile

        # Default: full sweep
        return cls.get_profile(TargetType.FULL_SWEEP)

    @classmethod
    def _infer_from_capabilities(cls, caps: Dict[str, bool]) -> TargetType:
        """Infer target type from capability set."""
        active_caps = {k for k, v in caps.items() if v}

        for required_caps, target_type in cls._INFERENCE_RULES:
            if required_caps.issubset(active_caps):
                return target_type

        # Default
        return TargetType.LLM_DIRECT

    @classmethod
    def _infer_from_owasp_hint(cls, owasp_id: str) -> TargetType:
        """Infer target type from OWASP ID using priority mapping."""
        oid = owasp_id.upper()

        # Use priority mapping for unambiguous inference
        if oid in _OWASP_HINT_DEFAULT:
            return _OWASP_HINT_DEFAULT[oid]

        # Prefix-based inference for ASI categories
        if oid.startswith("ASI"):
            return TargetType.AGENT

        # Fallback: search in mapping (less precise)
        for target_type, owasp_cats in _TARGET_TYPE_TO_OWASP.items():
            if oid in owasp_cats:
                return target_type

        return TargetType.FULL_SWEEP

    @classmethod
    def filter_seed_groups(
        cls,
        seed_groups: Sequence[SeedGroup],
        profile: TargetProfile,
    ) -> List[SeedGroup]:
        """
        Filter seed groups by target profile.

        Groups whose first seed's owasp_id matches any of the profile's
        OWASP categories are included. If profile is full_sweep, all
        groups are returned.

        For target types with a technique_group_prefix (e.g., MULTIMODAL),
        an additional metadata-based filter is applied to narrow down
        seeds within the OWASP-filtered set.

        Args:
            seed_groups: All seed groups from CentralMemory
            profile: Target profile with OWASP categories

        Returns:
            Filtered list of SeedGroups
        """
        if profile.is_full_sweep or not profile.owasp_categories:
            return list(seed_groups)

        allowed = {c.upper() for c in profile.owasp_categories}
        filtered: List[SeedGroup] = []

        for sg in seed_groups:
            owasp_id = cls._extract_owasp_id(sg)
            if owasp_id and owasp_id.upper() in allowed:
                # Apply optional technique_group filter
                if profile.technique_group_prefix:
                    if not cls._has_technique_group_prefix(
                        sg, profile.technique_group_prefix,
                    ):
                        continue
                filtered.append(sg)

        return filtered

    @staticmethod
    def _extract_owasp_id(seed_group: SeedGroup) -> str:
        """Extract OWASP ID from a seed group's first seed metadata."""
        for seed in seed_group.seeds:
            meta = getattr(seed, "metadata", None) or {}
            owasp_id = meta.get("owasp_id", "")
            if owasp_id:
                return owasp_id
        return ""

    @staticmethod
    def _has_technique_group_prefix(
        seed_group: SeedGroup,
        prefix: str,
    ) -> bool:
        """
        Check if any seed in the group has a technique_group
        matching the given prefix.
        """
        prefix_lower = prefix.lower()
        for seed in seed_group.seeds:
            meta = getattr(seed, "metadata", None) or {}
            tg = meta.get("technique_group", meta.get("technique", ""))
            if tg and tg.lower().startswith(prefix_lower):
                return True
        return False

    @classmethod
    def get_target_options(
        cls,
        seed_groups: Sequence[SeedGroup],
    ) -> List[tuple]:
        """
        Build target type selection menu with seed/group counts.

        Counts are computed **independently** for each target type by checking
        its OWASP category mapping and optional technique_group filter.
        This means seed groups can match multiple target types (e.g., an LLM01
        seed group counts toward LLM_DIRECT, COPILOT, and DEFENSE_BYPASS
        simultaneously — they share OWASP categories but represent different
        attack target platforms).

        Returns list of (index, TargetType, group_count, seed_count) tuples.
        """
        # Compute counts for each target type independently
        counts: Dict[TargetType, tuple] = {}

        for ttype in _TARGET_TYPE_TO_OWASP:
            if ttype == TargetType.FULL_SWEEP:
                continue

            owasp_cats = _TARGET_TYPE_TO_OWASP[ttype]
            if not owasp_cats:
                continue

            allowed = {c.upper() for c in owasp_cats}
            technique_prefix = _TECHNIQUE_GROUP_FILTER.get(ttype, "")

            gc = 0
            sc = 0
            for sg in seed_groups:
                owasp_id = cls._extract_owasp_id(sg)
                if not owasp_id or owasp_id.upper() not in allowed:
                    continue
                # Apply optional technique_group filter
                if technique_prefix:
                    if not cls._has_technique_group_prefix(sg, technique_prefix):
                        continue
                gc += 1
                sc += len(sg.seeds)

            counts[ttype] = (gc, sc)

        # Build ordered menu — always show all target types
        options: List[tuple] = []
        ordered_types = [
            TargetType.LLM_DIRECT,
            TargetType.AGENT,
            TargetType.RAG_VECTOR,
            TargetType.MCP_TOOL,
            TargetType.COPILOT,
            TargetType.MULTIMODAL,
            TargetType.OUTPUT_HANDLING,
            TargetType.LLM_SAFETY,
            TargetType.DEFENSE_BYPASS,
        ]

        for ttype in ordered_types:
            gc, sc = counts.get(ttype, (0, 0))
            options.append((len(options) + 1, ttype, gc, sc))

        # Full sweep
        total_groups = len(seed_groups)
        total_seeds = sum(len(sg.seeds) for sg in seed_groups)
        options.append((len(options) + 1, TargetType.FULL_SWEEP, total_groups, total_seeds))

        return options


# ============================================================
# Convenience functions
# ============================================================


def get_target_profile(target_type: TargetType) -> TargetProfile:
    """Convenience: get target profile by type."""
    return TargetProfileRouter.get_profile(target_type)


def infer_target_profile(
    capabilities: Optional[Dict[str, bool]] = None,
    owasp_hint: Optional[str] = None,
) -> TargetProfile:
    """Convenience: infer target profile."""
    return TargetProfileRouter.infer_profile(capabilities, owasp_hint)


def filter_groups_by_target(
    seed_groups: Sequence[SeedGroup],
    target_type: TargetType,
) -> List[SeedGroup]:
    """Convenience: filter seed groups by target type."""
    profile = TargetProfileRouter.get_profile(target_type)
    return TargetProfileRouter.filter_seed_groups(seed_groups, profile)
