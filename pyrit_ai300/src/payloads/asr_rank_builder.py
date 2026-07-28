"""
ASR Rank Builder
================

Layer 2 of the tiered progressive disclosure selection system.

Groups seeds by technique_group, computes ASR (Attack Success Rate)
metrics, classifies into tiers (S/A/B/C/D), and builds ranked fallback
chains. For groups without ASR data, uses heuristic proxy ranking based
on difficulty/evasion/detection metadata.

v4.0 融合: 以ASR引导策略为标准框架
- ASR 数据源三级查询: YAML 实测 > 学术先验 > 启发式代理
- 技术名标准化: YAML technique_group → asr_prior_registry key
- 统一 Tier 阈值: S>=70% A>=40% B>=15% C>=5% D<5% (ASR引导策略学术标准)
- 模型感知: ASR 值随目标模型变化

Design principles:
- Group-level ranking (not seed-level) — same technique = same failure mode
- ASR data drives primary ranking; heuristic proxy for gaps
- Tier classification enables ordered fallback (S → A → B → C)
- Does NOT modify any SeedGroup objects

Alignment with PyRIT 1.0.0:
- Reads asr_baseline from seed metadata (PyRIT SeedPrompt.metadata)
- Integrates with AdaptiveScenario + FailureTypeRoutingSelector
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Set

from pyrit.models import SeedGroup

logger = logging.getLogger(__name__)


# ============================================================
# ASR Tier Enumeration
# ============================================================


class ASRTier(str, Enum):
    """
    ASR-based technique tier classification.

    v4.0 统一阈值 (ASR引导策略学术标准):
    S: ASR >= 70% — near-guaranteed success, try first
    A: ASR 40-70% — high success, primary fallback
    B: ASR 15-40% — moderate, secondary fallback
    C: ASR 5-15% — low, last resort
    D: ASR < 5% — very low, skip by default
    UNKNOWN: No ASR data — use heuristic proxy
    """

    S = "S"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    UNKNOWN = "UNKNOWN"

    @property
    def threshold(self) -> float:
        thresholds = {
            "S": 0.70,
            "A": 0.40,
            "B": 0.15,
            "C": 0.05,
            "D": 0.0,
            "UNKNOWN": -1.0,
        }
        return thresholds.get(self.value, -1.0)

    @property
    def priority(self) -> int:
        """Sort priority (higher = try first)."""
        priorities = {
            "S": 100,
            "A": 80,
            "B": 60,
            "C": 40,
            "D": 20,
            "UNKNOWN": 50,  # Between B and C — heuristic may adjust
        }
        return priorities.get(self.value, 0)

    @classmethod
    def from_asr(cls, max_asr: float) -> "ASRTier":
        """Classify an ASR value into a tier."""
        if max_asr >= 0.70:
            return cls.S
        elif max_asr >= 0.40:
            return cls.A
        elif max_asr >= 0.15:
            return cls.B
        elif max_asr >= 0.05:
            return cls.C
        else:
            return cls.D


# ============================================================
# Technique Group Info
# ============================================================


@dataclass
class TechniqueGroupInfo:
    """
    Metadata and ASR metrics for a single technique group.

    A technique group is a cluster of seeds sharing the same
    technique_group metadata field. All seeds in a group use
    the same attack principle.
    """

    technique_group: str               # e.g., "skeleton_key"
    owasp_id: str                       # e.g., "LLM01"
    seed_count: int                     # Number of seeds in this group
    max_asr: float                      # Highest ASR across seeds
    avg_asr: float                      # Average ASR across seeds
    has_asr_data: bool                  # Whether any seed has ASR metadata
    tier: ASRTier                       # Classified tier
    heuristic_score: float              # Heuristic proxy score (0-100)
    attack_modes: List[str]             # Unique attack modes
    difficulties: List[str]             # Unique difficulty levels
    severities: List[str]               # Unique severity levels
    evasion_levels: List[str]           # Unique evasion levels
    dataset_name: str                   # Source dataset name
    source_seed_groups: List[SeedGroup] = field(default_factory=list)
    # SeedGroups that contain seeds from this technique group

    @property
    def effective_score(self) -> float:
        """
        Effective ranking score.

        Uses max_asr * 100 if ASR data exists, otherwise heuristic_score.
        """
        if self.has_asr_data:
            return self.max_asr * 100
        return self.heuristic_score

    @property
    def display_asr(self) -> str:
        """Human-readable ASR string."""
        if self.has_asr_data:
            return f"{self.max_asr:.0%}"
        return "--"


# ============================================================
# ASR Rank Builder
# ============================================================


# Heuristic weight constants
_DIFFICULTY_WEIGHTS = {"easy": 3, "medium": 2, "hard": 1, "unknown": 1.5}
_EVASION_WEIGHTS = {"high": 3, "medium": 2, "low": 1, "unknown": 1.5}
_DETECTION_WEIGHTS = {"low": 3, "medium": 2, "high": 1, "unknown": 1.5}
_MODE_WEIGHTS = {
    "single_turn": 3,
    "converter_enhanced": 2.5,
    "sequential": 2,
    "multi_turn": 1.5,
    "unknown": 1.5,
}


class ASRRankBuilder:
    """
    Builds ASR-ranked technique group lists for payload selection.

    Layer 2 of the three-tier progressive disclosure system.

    Usage:
        builder = ASRRankBuilder()
        groups = builder.build_ranked_groups(seed_groups)
        chain = builder.build_fallback_chain(groups)

        # groups is sorted by effective_score descending
        # chain is a list of tiers, each containing ranked groups
    """

    @classmethod
    def build_ranked_groups(
        cls,
        seed_groups: Sequence[SeedGroup],
        model_name: str = "gpt-4o",
    ) -> List[TechniqueGroupInfo]:
        """
        Build ranked technique group info from seed groups.

        v4.0: 接入学术先验 ASR — 当 YAML 无 asr_baseline 时，
        通过 technique_name_mapper 标准化后查询 asr_prior_registry。

        Groups seeds by technique_group metadata, computes ASR metrics,
        classifies into tiers, and sorts by effective score descending.

        Args:
            seed_groups: Seed groups from CentralMemory (already filtered
                         by target type if desired)
            model_name: 目标模型名称 (影响学术 ASR 查询)

        Returns:
            List of TechniqueGroupInfo sorted by effective_score descending
        """
        # Cluster seeds by technique_group
        cluster: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "seeds": [],
            "seed_groups": [],
            "owasp_id": "",
            "dataset_name": "",
        })

        for sg in seed_groups:
            for seed in sg.seeds:
                meta = getattr(seed, "metadata", None) or {}
                tg = meta.get("technique_group", meta.get("technique", "ungrouped"))
                owasp_id = meta.get("owasp_id", "")
                dataset_name = getattr(seed, "dataset_name", "") or ""

                cluster[tg]["seeds"].append(seed)
                cluster[tg]["seed_groups"].append(sg)
                if owasp_id and not cluster[tg]["owasp_id"]:
                    cluster[tg]["owasp_id"] = owasp_id
                if dataset_name and not cluster[tg]["dataset_name"]:
                    cluster[tg]["dataset_name"] = dataset_name

        # Build TechniqueGroupInfo for each cluster
        groups: List[TechniqueGroupInfo] = []
        for tg_name, data in cluster.items():
            info = cls._build_group_info(tg_name, data, model_name=model_name)
            groups.append(info)

        # Sort by effective_score descending
        groups.sort(key=lambda g: -g.effective_score)

        return groups

    @classmethod
    def _build_group_info(
        cls,
        technique_group: str,
        data: Dict[str, Any],
        model_name: str = "gpt-4o",
    ) -> TechniqueGroupInfo:
        """Build TechniqueGroupInfo from a cluster of seeds.

        v4.0: 三级 ASR 查询:
        1. YAML asr_baseline (实测优先)
        2. 学术先验 (通过 technique_name_mapper 标准化)
        3. 启发式代理 (最后兑底)
        """

        seeds = data["seeds"]
        # Deduplicate SeedGroup objects by identity (SeedGroup is not hashable)
        _seen_ids: Set[int] = set()
        seed_groups: List[SeedGroup] = []
        for sg in data["seed_groups"]:
            if id(sg) not in _seen_ids:
                _seen_ids.add(id(sg))
                seed_groups.append(sg)

        # Extract ASR values
        asr_values: List[float] = []
        attack_modes: Set = set()
        difficulties: Set = set()
        severities: Set = set()
        evasion_levels: Set = set()

        for seed in seeds:
            meta = getattr(seed, "metadata", None) or {}
            asr = meta.get("asr_baseline", {})
            if asr and isinstance(asr, dict):
                asr_values.append(max(asr.values()))

            am = meta.get("attack_mode", "single_turn")
            attack_modes.add(am)

            d = meta.get("difficulty", "unknown")
            difficulties.add(d)

            s = meta.get("severity", "")
            if s:
                severities.add(s)

            e = meta.get("evasion_level", "unknown")
            evasion_levels.add(e)

        has_asr = bool(asr_values)
        max_asr = max(asr_values) if asr_values else 0.0
        avg_asr = sum(asr_values) / len(asr_values) if asr_values else 0.0
        tier = ASRTier.from_asr(max_asr) if has_asr else ASRTier.UNKNOWN

        # v4.0: 无 YAML ASR 时回退到学术先验
        if not has_asr:
            try:
                from src.payloads.technique_name_mapper import get_normalized_asr, normalize_technique_name
                from src.payloads.asr_prior_registry import get_asr_prior
                normalized_name = normalize_technique_name(technique_group)
                # 只有当标准化后的技术名确实在 registry 中存在时才使用学术先验
                # (避免中性默认值 0.3 与真实 ASR 0.30 碰撞)
                if get_asr_prior(normalized_name) is not None:
                    academic_asr = get_normalized_asr(technique_group, model_name)
                    max_asr = academic_asr
                    avg_asr = academic_asr
                    has_asr = True
                    tier = ASRTier.from_asr(max_asr)
            except Exception:
                pass  # 回退到启发式代理

        heuristic = cls._heuristic_score(
            difficulties, evasion_levels, attack_modes,
        ) if not has_asr else max_asr * 100

        return TechniqueGroupInfo(
            technique_group=technique_group,
            owasp_id=data["owasp_id"],
            seed_count=len(seeds),
            max_asr=max_asr,
            avg_asr=avg_asr,
            has_asr_data=has_asr,
            tier=tier,
            heuristic_score=heuristic,
            attack_modes=sorted(attack_modes),
            difficulties=sorted(difficulties),
            severities=sorted(severities),
            evasion_levels=sorted(evasion_levels),
            dataset_name=data["dataset_name"],
            source_seed_groups=seed_groups,
        )

    @staticmethod
    def _heuristic_score(
        difficulties: Set[str],
        evasion_levels: Set[str],
        attack_modes: Set[str],
    ) -> float:
        """
        Compute heuristic proxy score for groups without ASR data.

        Score = avg(difficulty_weight) * 10
              + avg(evasion_weight) * 10
              + avg(mode_weight) * 10
        Range: 0-90 (typical: 30-70)
        """
        def avg_weight(values: Set[str], weights: Dict[str, float]) -> float:
            if not values:
                return 1.5
            total = sum(weights.get(v, 1.5) for v in values)
            return total / len(values)

        d_score = avg_weight(difficulties, _DIFFICULTY_WEIGHTS)
        e_score = avg_weight(evasion_levels, _EVASION_WEIGHTS)
        m_score = avg_weight(attack_modes, _MODE_WEIGHTS)

        return (d_score * 10) + (e_score * 10) + (m_score * 10)

    @classmethod
    def build_fallback_chain(
        cls,
        ranked_groups: List[TechniqueGroupInfo],
    ) -> List[List[TechniqueGroupInfo]]:
        """
        Build tiered fallback chain from ranked groups.

        Returns a list of tiers, where each tier is a list of groups.
        Tiers are ordered S → A → B → C → D → UNKNOWN.
        Within each tier, groups are sorted by effective_score descending.

        Args:
            ranked_groups: Output from build_ranked_groups()

        Returns:
            List of tiers (each tier is a list of TechniqueGroupInfo)
        """
        tiers_order = [
            ASRTier.S, ASRTier.A, ASRTier.B,
            ASRTier.C, ASRTier.D, ASRTier.UNKNOWN,
        ]

        chain: List[List[TechniqueGroupInfo]] = []
        for tier in tiers_order:
            tier_groups = [g for g in ranked_groups if g.tier == tier]
            if tier_groups:
                tier_groups.sort(key=lambda g: -g.effective_score)
                chain.append(tier_groups)

        return chain

    @classmethod
    def get_top_n(
        cls,
        ranked_groups: List[TechniqueGroupInfo],
        n: int = 5,
        min_tier: Optional[ASRTier] = None,
    ) -> List[TechniqueGroupInfo]:
        """
        Get top-N groups, optionally filtered by minimum tier.

        Args:
            ranked_groups: Output from build_ranked_groups()
            n: Maximum number of groups to return
            min_tier: Minimum tier to include (S > A > B > C > D)

        Returns:
            Top-N TechniqueGroupInfo list
        """
        min_priority = min_tier.priority if min_tier else 0

        filtered = [g for g in ranked_groups if g.tier.priority >= min_priority]
        return filtered[:n]

    @classmethod
    def get_tier_summary(
        cls,
        ranked_groups: List[TechniqueGroupInfo],
    ) -> Dict[str, Dict[str, int]]:
        """
        Get summary statistics by tier.

        Returns:
            Dict mapping tier name to {groups, seeds} counts
        """
        summary: Dict[str, Dict[str, int]] = {}
        for tier in ASRTier:
            tier_groups = [g for g in ranked_groups if g.tier == tier]
            if tier_groups:
                summary[tier.value] = {
                    "groups": len(tier_groups),
                    "seeds": sum(g.seed_count for g in tier_groups),
                }
        return summary


# ============================================================
# Convenience functions
# ============================================================


def build_ranked_groups(
    seed_groups: Sequence[SeedGroup],
    model_name: str = "gpt-4o",
) -> List[TechniqueGroupInfo]:
    """Convenience: build ranked technique groups."""
    return ASRRankBuilder.build_ranked_groups(seed_groups, model_name=model_name)


def build_fallback_chain(
    ranked_groups: List[TechniqueGroupInfo],
) -> List[List[TechniqueGroupInfo]]:
    """Convenience: build fallback chain."""
    return ASRRankBuilder.build_fallback_chain(ranked_groups)


def get_top_n_groups(
    ranked_groups: List[TechniqueGroupInfo],
    n: int = 5,
    min_tier: Optional[ASRTier] = None,
) -> List[TechniqueGroupInfo]:
    """Convenience: get top-N groups."""
    return ASRRankBuilder.get_top_n(ranked_groups, n, min_tier)
