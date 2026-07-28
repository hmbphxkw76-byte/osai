"""
Preset Schemes
==============

Attack combination preset schemes for AI-300 exam scenarios.

Provides three pre-configured attack strategies (F/R/D) that balance
success rate and execution time:

  Scheme F (FAST):        2 groups, ~15 min — quick validation
  Scheme R (RECOMMENDED): 3 groups, ~30 min — exam default
  Scheme D (DEEP):        5 groups, ~50 min — full coverage

Design principles:
- ASR-driven: highest ASR groups selected first
- Mechanism diversity: different attack principles in each scheme
- Time transparency: estimated time per scheme
- User extendable: users can add groups on top of a preset (e.g., R,8)
- Dynamically built from actual ranked data (not hardcoded)

Alignment with PyRIT 1.0.0:
- Does NOT change execution logic — only enhances selection UX
- Integrates at Layer 2 of TieredSelectionWizard
- Leverages ASRRankBuilder output (TechniqueGroupInfo)
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

from src.payloads.asr_rank_builder import TechniqueGroupInfo

logger = logging.getLogger(__name__)


# ============================================================
# Attack Mechanism Classification
# ============================================================


class AttackMechanism(str, Enum):
    """
    Classification of attack techniques by underlying principle.

    Used for mechanism diversity in preset schemes — selecting groups
    with different mechanisms increases coverage and reduces correlated
    failures.
    """

    MULTI_SHOT = "multi_shot"               # 多示例引导 (many_shot, best_of_n)
    ROLE_OVERRIDE = "role_override"         # 角色覆盖 (skeleton_key, bad_likert)
    GRADIENT_OPT = "gradient_opt"           # 梯度优化 (autodan, adversarial_suffix)
    ITERATIVE = "iterative"                 # 迭代对抗 (pair_tap, crescendo, TAP)
    MULTIMODAL = "multimodal"               # 多模态攻击 (multimodal_*)
    ENCODING = "encoding"                   # 编码混淆 (cipher, base64, etc.)
    NESTED = "nested"                       # 嵌套场景 (deep_inception)
    CONTEXT_WRAPPING = "context_wrapping"   # 上下文包装 (wrapping, cca)
    INJECTION = "injection"                 # 直接/间接注入
    EXTRACTION = "extraction"               # 信息提取 (prompt leakage, memory)
    POISONING = "poisoning"                 # 数据投毒 (rag_poison, supply_chain)
    EXPLOIT = "exploit"                     # CVE 漏洞利用
    BEHAVIORAL = "behavioral"               # 行为操纵 (goal_hijack, confused_deputy)
    RESOURCE = "resource"                   # 资源耗尽
    UNKNOWN = "unknown"

    @property
    def display_name(self) -> str:
        names = {
            "multi_shot": "多示例引导",
            "role_override": "角色覆盖",
            "gradient_opt": "梯度优化",
            "iterative": "迭代对抗",
            "multimodal": "多模态",
            "encoding": "编码混淆",
            "nested": "嵌套场景",
            "context_wrapping": "上下文包装",
            "injection": "注入攻击",
            "extraction": "信息提取",
            "poisoning": "数据投毒",
            "exploit": "漏洞利用",
            "behavioral": "行为操纵",
            "resource": "资源耗尽",
            "unknown": "未知机制",
        }
        return names.get(self.value, self.value)


# ============================================================
# Technique → Mechanism Mapping
# ============================================================


# Comprehensive mapping from technique_group name to attack mechanism.
# This covers all known techniques in the AI-300 dataset.
TECHNIQUE_MECHANISM_MAP: Dict[str, AttackMechanism] = {
    # --- Multi-shot ---
    "many_shot_jailbreak": AttackMechanism.MULTI_SHOT,
    "best_of_n_jailbreak": AttackMechanism.MULTI_SHOT,
    "few_shot_backdoor": AttackMechanism.MULTI_SHOT,

    # --- Role override ---
    "skeleton_key": AttackMechanism.ROLE_OVERRIDE,
    "bad_likert_judge": AttackMechanism.ROLE_OVERRIDE,
    "authority_endorsement": AttackMechanism.ROLE_OVERRIDE,

    # --- Gradient optimization ---
    "autodan": AttackMechanism.GRADIENT_OPT,
    "adversarial_suffix": AttackMechanism.GRADIENT_OPT,
    "glitch_token": AttackMechanism.GRADIENT_OPT,

    # --- Iterative adversarial ---
    "iteration_pair_tap": AttackMechanism.ITERATIVE,
    "crescendo": AttackMechanism.ITERATIVE,
    "crescendo_jailbreak": AttackMechanism.ITERATIVE,
    "adaptive_jailbreak": AttackMechanism.ITERATIVE,

    # --- Multimodal ---
    "multimodal_injection": AttackMechanism.MULTIMODAL,
    "multimodal_jailbreak_v2": AttackMechanism.MULTIMODAL,
    "multimodal_jailbreak": AttackMechanism.MULTIMODAL,

    # --- Encoding ---
    "cipher_chat": AttackMechanism.ENCODING,
    "encoding_bypass": AttackMechanism.ENCODING,
    "special_token_injection": AttackMechanism.ENCODING,
    "token_smuggling": AttackMechanism.ENCODING,
    "prompt_smuggling": AttackMechanism.ENCODING,

    # --- Nested scenario ---
    "deep_inception": AttackMechanism.NESTED,

    # --- Context wrapping ---
    "wrapping_attack": AttackMechanism.CONTEXT_WRAPPING,
    "cca_context_compliance": AttackMechanism.CONTEXT_WRAPPING,

    # --- Injection ---
    "direct_injection": AttackMechanism.INJECTION,
    "direct_injection_expanded": AttackMechanism.INJECTION,
    "indirect_injection": AttackMechanism.INJECTION,
    "format_injection": AttackMechanism.INJECTION,
    "structured_field_injection": AttackMechanism.INJECTION,
    "semantic_stealth_injection": AttackMechanism.INJECTION,
    "cross_agent": AttackMechanism.INJECTION,
    "a2a_injection": AttackMechanism.INJECTION,
    "parameter_pollution": AttackMechanism.INJECTION,

    # --- Extraction ---
    "system_prompt_extraction": AttackMechanism.EXTRACTION,
    "system_prompt_leak": AttackMechanism.EXTRACTION,
    "config_extraction": AttackMechanism.EXTRACTION,
    "memory_extraction": AttackMechanism.EXTRACTION,
    "training_data_extraction": AttackMechanism.EXTRACTION,
    "sensitive_info": AttackMechanism.EXTRACTION,
    "pii_anchor_extraction": AttackMechanism.EXTRACTION,

    # --- Poisoning ---
    "rag_poison": AttackMechanism.POISONING,
    "cross_namespace_rag_poison": AttackMechanism.POISONING,
    "memory_poison": AttackMechanism.POISONING,
    "supply_chain_probe": AttackMechanism.POISONING,
    "dependency_confusion": AttackMechanism.POISONING,
    "package_hallucination": AttackMechanism.POISONING,
    "model_deserialization": AttackMechanism.POISONING,
    "adversarial_embedding": AttackMechanism.POISONING,
    "vector_weakness": AttackMechanism.POISONING,

    # --- Exploit / CVE ---
    "cve_2025_32711_echoleak": AttackMechanism.EXPLOIT,
    "cve_2025_1716_picklescan_pypi_rce": AttackMechanism.EXPLOIT,
    "cve_2026_25874_lerobot_pickle_rce": AttackMechanism.EXPLOIT,
    "cve_2026_22812_opencode_unauth_rce": AttackMechanism.EXPLOIT,
    "cve_2026_25253_openclaw_token_theft": AttackMechanism.EXPLOIT,
    "cve_2026_25592_semantic_kernel_sandbox_escape": AttackMechanism.EXPLOIT,
    "cve_2026_40933_flowise_mcp_injection": AttackMechanism.EXPLOIT,
    "cve_2026_45829_chromadb_rce": AttackMechanism.EXPLOIT,

    # --- Behavioral manipulation ---
    "goal_hijack": AttackMechanism.BEHAVIORAL,
    "goal_hijack_expanded": AttackMechanism.BEHAVIORAL,
    "confused_deputy": AttackMechanism.BEHAVIORAL,
    "tool_hijack": AttackMechanism.BEHAVIORAL,
    "tool_misuse": AttackMechanism.BEHAVIORAL,
    "agent_break": AttackMechanism.BEHAVIORAL,
    "identity_abuse": AttackMechanism.BEHAVIORAL,
    "identity_abuse_expanded": AttackMechanism.BEHAVIORAL,
    "trust_exploit": AttackMechanism.BEHAVIORAL,
    "rogue_agent": AttackMechanism.BEHAVIORAL,
    "agent_comm": AttackMechanism.INJECTION,
    "agent_communication_expanded": AttackMechanism.INJECTION,
    "memory_attack": AttackMechanism.BEHAVIORAL,
    "agentic_memory_attack": AttackMechanism.BEHAVIORAL,
    "cascading_failure": AttackMechanism.BEHAVIORAL,

    # --- MCP / Tool ---
    "mcp_tool_poison": AttackMechanism.POISONING,
    "mcp_capability_confusion": AttackMechanism.BEHAVIORAL,
    "mcp_session_fix": AttackMechanism.EXPLOIT,
    "mcp_token_leak": AttackMechanism.EXTRACTION,
    "frontier_2025_003_mcp_tool_poison": AttackMechanism.POISONING,
    "frontier_2025_004_tool_data_exfil": AttackMechanism.EXTRACTION,

    # --- RAG / Vector ---
    "rag_indirect_injection": AttackMechanism.INJECTION,
    "rag_source_attribution": AttackMechanism.INJECTION,
    "vector_db_query_injection": AttackMechanism.INJECTION,
    "vector_injection": AttackMechanism.INJECTION,
    "embedding_inversion_practical": AttackMechanism.EXPLOIT,
    "cross_tenant_leakage": AttackMechanism.EXTRACTION,

    # --- Output handling ---
    "insecure_output": AttackMechanism.INJECTION,
    "xss_injection": AttackMechanism.INJECTION,

    # --- Misinformation ---
    "hallucination_exploitation": AttackMechanism.BEHAVIORAL,
    "hallucination": AttackMechanism.BEHAVIORAL,
    "citation_elicitation": AttackMechanism.BEHAVIORAL,

    # --- Resource exhaustion ---
    "resource_exhaustion": AttackMechanism.RESOURCE,
    "context_padding": AttackMechanism.RESOURCE,

    # --- Prompt leakage (Copilot) ---
    "copilot_prompt_leak": AttackMechanism.EXTRACTION,
    "frontier_2025_002_echoleak_prompt_leak": AttackMechanism.EXPLOIT,

    # --- Supply chain ---
    "supply_chain": AttackMechanism.POISONING,
    "code_execution": AttackMechanism.EXPLOIT,

    # --- HCOT / Reasoning ---
    "frontier_2025_001_hcot": AttackMechanism.BEHAVIORAL,
}


def get_mechanism(technique_group: str) -> AttackMechanism:
    """
    Get the attack mechanism for a technique group.

    Uses exact match first, then falls back to prefix matching for
    technique groups not in the explicit map.

    Args:
        technique_group: The technique_group name from seed metadata

    Returns:
        AttackMechanism enum value
    """
    # Exact match
    if technique_group in TECHNIQUE_MECHANISM_MAP:
        return TECHNIQUE_MECHANISM_MAP[technique_group]

    # Prefix-based fallback
    lower = technique_group.lower()
    if lower.startswith("multimodal"):
        return AttackMechanism.MULTIMODAL
    if lower.startswith("cve_"):
        return AttackMechanism.EXPLOIT
    if lower.startswith("rag_"):
        return AttackMechanism.POISONING
    if lower.startswith("mcp_"):
        return AttackMechanism.POISONING
    if "injection" in lower:
        return AttackMechanism.INJECTION
    if "extraction" in lower or "leak" in lower:
        return AttackMechanism.EXTRACTION
    if "poison" in lower:
        return AttackMechanism.POISONING

    return AttackMechanism.UNKNOWN


# ============================================================
# Preset Scheme Enumeration
# ============================================================


class PresetScheme(str, Enum):
    """
    Pre-configured attack combination schemes.

    FAST:        2 groups, ~15 min — quick validation
    RECOMMENDED: 3 groups, ~30 min — exam default (balanced)
    DEEP:        5 groups, ~50 min — maximum coverage
    """

    FAST = "fast"
    RECOMMENDED = "recommended"
    DEEP = "deep"

    @property
    def letter(self) -> str:
        """Single-letter identifier for interactive selection.

        Uses F/R/D to avoid conflict with Tier S/A/B/C/D classification.
        """
        return {"fast": "F", "recommended": "R", "deep": "D"}[self.value]

    @property
    def display_name(self) -> str:
        names = {
            "fast": "极速验证",
            "recommended": "考试推荐",
            "deep": "深度覆盖",
        }
        return names.get(self.value, self.value)

    @property
    def description(self) -> str:
        descs = {
            "fast": "2 groups, ~15 min — quick validation, highest ASR",
            "recommended": "3 groups, ~30 min — balanced, exam default",
            "deep": "5 groups, ~50 min — maximum coverage",
        }
        return descs.get(self.value, "")

    @property
    def target_group_count(self) -> int:
        return {"fast": 2, "recommended": 3, "deep": 5}[self.value]

    @classmethod
    def from_letter(cls, letter: str) -> Optional["PresetScheme"]:
        """Parse a single letter into a PresetScheme (case-insensitive).

        Uses F/R/D (not A/B/C) to avoid conflict with Tier letters.
        """
        mapping = {"f": cls.FAST, "r": cls.RECOMMENDED, "d": cls.DEEP}
        return mapping.get(letter.lower())


# ============================================================
# Preset Scheme Definition
# ============================================================


@dataclass
class PresetSchemeDefinition:
    """
    A fully resolved preset scheme with selected groups and metadata.

    Built dynamically by PresetSchemeBuilder from actual ranked groups.
    """

    scheme: PresetScheme
    groups: List[TechniqueGroupInfo]
    est_time_min: str = ""
    mechanisms: List[AttackMechanism] = field(default_factory=list)

    @property
    def group_count(self) -> int:
        return len(self.groups)

    @property
    def total_seeds(self) -> int:
        return sum(g.seed_count for g in self.groups)

    @property
    def weighted_asr(self) -> float:
        """
        Weighted average ASR across selected groups.

        Weighted by seed count — groups with more seeds have more impact.
        Returns 0.0 if no ASR data available.
        """
        total_weight = 0
        weighted_sum = 0.0
        for g in self.groups:
            if g.has_asr_data:
                weighted_sum += g.max_asr * g.seed_count
                total_weight += g.seed_count
        if total_weight == 0:
            return 0.0
        return weighted_sum / total_weight

    @property
    def display_asr(self) -> str:
        """Human-readable weighted ASR.

        v4.0: 当无 YAML ASR 数据时，回退到学术先验 ASR。
        """
        if self.weighted_asr > 0:
            return f"{self.weighted_asr:.0%}"
        # v4.0: 回退到学术先验
        try:
            from src.payloads.technique_name_mapper import get_normalized_asr
            total_weight = 0
            weighted_sum = 0.0
            for g in self.groups:
                academic_asr = get_normalized_asr(g.technique_group, "gpt-4o")
                if academic_asr != 0.3:  # 非中性先验
                    weighted_sum += academic_asr * g.seed_count
                    total_weight += g.seed_count
            if total_weight > 0:
                return f"{weighted_sum / total_weight:.0%}"
        except Exception:
            pass
        return "--"

    @property
    def group_names(self) -> str:
        """Comma-separated technique group names."""
        return ", ".join(g.technique_group for g in self.groups)

    @property
    def mechanism_names(self) -> str:
        """Comma-separated mechanism display names."""
        return ", ".join(m.display_name for m in self.mechanisms)

    @property
    def est_plans(self) -> int:
        """Estimated number of attack plans (≈ total seeds)."""
        return self.total_seeds


# ============================================================
# Preset Scheme Builder
# ============================================================


# Time estimation constants (seconds per plan)
_SINGLE_TURN_TIME = 15       # ~15s per single-turn plan
_MULTI_TURN_TIME = 90        # ~90s per multi-turn plan (avg 6 turns * 15s)
_L2_EFFICIENCY = 0.6         # L2 threshold reduces actual time to ~60%


class PresetSchemeBuilder:
    """
    Builds preset scheme definitions from ranked technique groups.

    Algorithm:
    1. Sort groups by effective_score (already done by ASRRankBuilder)
    2. For each scheme, select groups ensuring mechanism diversity:
       - First pass: pick highest ASR with a new mechanism
       - Second pass: fill remaining slots by ASR order
    3. Compute weighted ASR and time estimate

    Usage:
        schemes = PresetSchemeBuilder.build_schemes(ranked_groups)
        # Returns [PresetSchemeDefinition(FAST), (RECOMMENDED), (DEEP)]
    """

    @classmethod
    def build_schemes(
        cls,
        ranked_groups: List[TechniqueGroupInfo],
        model_name: str = "gpt-4o",
    ) -> List[PresetSchemeDefinition]:
        """
        Build all three preset schemes from ranked groups.

        v4.0: model_name 参数传递（向后兼容，不影响选择逻辑）

        Args:
            ranked_groups: Sorted list from ASRRankBuilder.build_ranked_groups()
            model_name: 目标模型名称 (保留参数, 供未来扩展)

        Returns:
            List of 3 PresetSchemeDefinition (FAST, RECOMMENDED, DEEP).
            If fewer groups than needed, schemes adapt to available data.
        """
        if not ranked_groups:
            return []

        schemes: List[PresetSchemeDefinition] = []

        for scheme in PresetScheme:
            target_n = scheme.target_group_count
            # Don't create a scheme if we have fewer than half the target groups
            if len(ranked_groups) < max(2, target_n // 2):
                # If very few groups, just use what we have for FAST
                if scheme == PresetScheme.FAST:
                    groups = ranked_groups[:2]
                else:
                    continue
            else:
                groups = cls._select_diverse(ranked_groups, target_n)

            if not groups:
                continue

            mechanisms = cls._get_mechanisms(groups)
            est_time = cls._estimate_time(groups)

            schemes.append(PresetSchemeDefinition(
                scheme=scheme,
                groups=groups,
                est_time_min=est_time,
                mechanisms=mechanisms,
            ))

        return schemes

    @classmethod
    def build_scheme(
        cls,
        ranked_groups: List[TechniqueGroupInfo],
        scheme: PresetScheme,
    ) -> Optional[PresetSchemeDefinition]:
        """
        Build a single preset scheme.

        Args:
            ranked_groups: Sorted list from ASRRankBuilder
            scheme: Which scheme to build

        Returns:
            PresetSchemeDefinition or None if not enough groups
        """
        if not ranked_groups:
            return None

        target_n = scheme.target_group_count
        groups = cls._select_diverse(ranked_groups, target_n)

        if not groups:
            return None

        mechanisms = cls._get_mechanisms(groups)
        est_time = cls._estimate_time(groups)

        return PresetSchemeDefinition(
            scheme=scheme,
            groups=groups,
            est_time_min=est_time,
            mechanisms=mechanisms,
        )

    # ------------------------------------------------------------------
    # Internal methods
    # ------------------------------------------------------------------

    @staticmethod
    def _select_diverse(
        ranked_groups: List[TechniqueGroupInfo],
        n: int,
    ) -> List[TechniqueGroupInfo]:
        """
        Select N groups with mechanism diversity.

        First pass: pick highest ASR with a new mechanism.
        Second pass: fill remaining by ASR order (mechanism overlap OK).
        """
        n = min(n, len(ranked_groups))
        if n <= 0:
            return []

        selected: List[TechniqueGroupInfo] = []
        used_mechanisms: Set[AttackMechanism] = set()
        used_names: Set[str] = set()

        # First pass: mechanism-diverse selection
        for g in ranked_groups:
            if len(selected) >= n:
                break
            if g.technique_group in used_names:
                continue
            mech = get_mechanism(g.technique_group)
            if mech not in used_mechanisms:
                selected.append(g)
                used_mechanisms.add(mech)
                used_names.add(g.technique_group)

        # Second pass: fill by ASR order
        if len(selected) < n:
            for g in ranked_groups:
                if len(selected) >= n:
                    break
                if g.technique_group in used_names:
                    continue
                selected.append(g)
                used_names.add(g.technique_group)

        return selected

    @staticmethod
    def _get_mechanisms(
        groups: List[TechniqueGroupInfo],
    ) -> List[AttackMechanism]:
        """Extract unique mechanisms from selected groups, preserving order."""
        seen: Set[AttackMechanism] = set()
        result: List[AttackMechanism] = []
        for g in groups:
            mech = get_mechanism(g.technique_group)
            if mech not in seen:
                seen.add(mech)
                result.append(mech)
        return result

    @staticmethod
    def _estimate_time(
        groups: List[TechniqueGroupInfo],
    ) -> str:
        """
        Estimate execution time for a set of groups.

        Based on:
        - Single-turn plans: ~15s each
        - Multi-turn plans: ~90s each
        - L2 threshold efficiency: ~60% of total

        Returns:
            Human-readable time string (e.g., "~15 min", "~1.5 hr")
        """
        single_count = 0
        multi_count = 0

        for g in groups:
            for mode in g.attack_modes:
                if "multi" in mode.lower():
                    multi_count += g.seed_count
                else:
                    single_count += g.seed_count

            # If no modes, assume single turn
            if not g.attack_modes:
                single_count += g.seed_count

        # Avoid double-counting: if a group has both single and multi modes,
        # split seeds roughly evenly
        # (This is a rough estimate; actual execution depends on plan generation)
        total_seeds = sum(g.seed_count for g in groups)
        if single_count + multi_count > total_seeds:
            # Over-counted due to multiple modes; approximate
            single_count = total_seeds * 2 // 3
            multi_count = total_seeds // 3

        total_seconds = (single_count * _SINGLE_TURN_TIME + multi_count * _MULTI_TURN_TIME) * _L2_EFFICIENCY

        if total_seconds < 60:
            return f"~{int(total_seconds)}s"
        minutes = total_seconds / 60
        if minutes < 60:
            return f"~{minutes:.0f} min"
        hours = minutes / 60
        return f"~{hours:.1f} hr"


# ============================================================
# Convenience functions
# ============================================================


def build_preset_schemes(
    ranked_groups: List[TechniqueGroupInfo],
    model_name: str = "gpt-4o",
) -> List[PresetSchemeDefinition]:
    """Convenience: build all preset schemes."""
    return PresetSchemeBuilder.build_schemes(ranked_groups, model_name=model_name)


def get_scheme_by_letter(
    letter: str,
    schemes: List[PresetSchemeDefinition],
) -> Optional[PresetSchemeDefinition]:
    """
    Get a preset scheme by its letter (F/R/D).

    Args:
        letter: Single letter (case-insensitive)
        schemes: List of PresetSchemeDefinition from build_preset_schemes

    Returns:
        Matching PresetSchemeDefinition or None
    """
    target = PresetScheme.from_letter(letter)
    if target is None:
        return None
    for s in schemes:
        if s.scheme == target:
            return s
    return None
