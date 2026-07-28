"""
Tiered Selection Wizard
=======================

Layer 3 of the tiered progressive disclosure selection system.

Three-layer progressive disclosure UI that reduces 724+ records to
3 decision points of 5-8 options each:

  Layer 1: Target type (Agent / RAG / MCP / LLM / ...)
  Layer 2: ASR-ranked group recommendation (auto-recommend, user confirms)
  Layer 3: Fallback strategy (Sequential / Parallel / Adaptive)

Design principles:
- User makes strategic choices (2-3 decisions), system handles tactics
- Progressive disclosure: start with summary, drill down on demand
- Non-interactive mode for CI/CD (presets/config)
- Returns List[SeedGroup] compatible with existing pipeline
- Does NOT replace SeedGroupSelector — adds routing layer on top

Alignment with PyRIT 1.0.0:
- Integrates at ②.5 layer (same as SeedGroupSelector)
- Leverages TargetProfileRouter + ASRRankBuilder
- Fallback strategy integrates with GroupFallbackExecutor
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Sequence, Set

from pyrit.models import SeedGroup

from src.payloads.target_profile_router import (
    TargetProfileRouter,
    TargetProfile,
    TargetType,
)
from src.payloads.asr_rank_builder import (
    ASRRankBuilder,
    ASRTier,
    TechniqueGroupInfo,
)
from src.payloads.preset_schemes import (
    PresetScheme,
    PresetSchemeDefinition,
    PresetSchemeBuilder,
)

logger = logging.getLogger(__name__)


# ============================================================
# Fallback Strategy Enumeration
# ============================================================


class FallbackStrategy(str, Enum):
    """
    Fallback strategy for group-level execution.

    SEQUENTIAL_ASR_DESC: Try groups in ASR descending order, stop on first success
    PARALLEL: Execute all selected groups simultaneously
    ADAPTIVE: Use FailureTypeRoutingSelector + technique upgrade on failure
    """

    SEQUENTIAL_ASR_DESC = "sequential_asr_desc"
    PARALLEL = "parallel"
    ADAPTIVE = "adaptive"

    @property
    def display_name(self) -> str:
        names = {
            "sequential_asr_desc": "Sequential ASR-desc (exam-safe)",
            "parallel": "Parallel (fastest)",
            "adaptive": "Adaptive (AI-driven upgrade)",
        }
        return names.get(self.value, self.value)

    @property
    def description(self) -> str:
        descs = {
            "sequential_asr_desc": "S -> A -> B -> C, stop on first group success",
            "parallel": "Execute all selected groups at once",
            "adaptive": "FailureTypeRoutingSelector + technique upgrade on failure",
        }
        return descs.get(self.value, "")


# ============================================================
# Selection Result
# ============================================================


@dataclass
class TieredSelectionResult:
    """
    Result of the tiered selection process.

    Contains the selected seed groups and the chosen fallback strategy.
    This is the output that feeds into the attack execution pipeline.

    Fields:
        selected_groups: User's explicitly selected groups (top-N recommendation)
        all_chain_groups: ALL groups in the fallback chain (for plan generation
                         when SEQUENTIAL/ADAPTIVE strategy is used)
        fallback_strategy: Execution strategy
        fallback_chain: Tiered chain from ASRRankBuilder
    """

    selected_groups: List[SeedGroup]
    fallback_strategy: FallbackStrategy
    target_profile: TargetProfile
    ranked_groups: List[TechniqueGroupInfo]
    fallback_chain: List[List[TechniqueGroupInfo]]
    all_chain_groups: List[SeedGroup] = field(default_factory=list)
    preset_schemes: List[PresetSchemeDefinition] = field(default_factory=list)

    @property
    def total_seeds(self) -> int:
        return sum(len(sg.seeds) for sg in self.selected_groups)

    @property
    def group_count(self) -> int:
        return len(self.selected_groups)

    @property
    def planning_groups(self) -> List[SeedGroup]:
        """
        Groups to generate AttackPlans from.

        For SEQUENTIAL/ADAPTIVE: all_chain_groups (enables tier fallback).
        For PARALLEL: selected_groups only (no fallback needed).
        """
        if self.fallback_strategy == FallbackStrategy.PARALLEL:
            return self.selected_groups
        return self.all_chain_groups if self.all_chain_groups else self.selected_groups


# ============================================================
# Preset Configuration
# ============================================================


@dataclass
class SelectionPreset:
    """
    Non-interactive preset for automated/scripted runs.

    Allows skipping all interactive prompts by pre-configuring
    target type, selection mode, and fallback strategy.
    """

    target_type: Optional[TargetType] = None
    top_n: int = 3                      # Number of groups to select
    min_tier: Optional[ASRTier] = None  # Minimum tier to include
    fallback_strategy: FallbackStrategy = FallbackStrategy.SEQUENTIAL_ASR_DESC
    select_all: bool = False            # Override: select all groups


# ============================================================
# Tiered Selection Wizard
# ============================================================


class TieredSelectionWizard:
    """
    Three-layer progressive disclosure selection wizard.

    Reduces 724+ records to 3 decision points:
      Layer 1: Target type (7-8 options)
      Layer 2: ASR-ranked groups (auto-recommend, user confirms)
      Layer 3: Fallback strategy (3 options)

    Usage (interactive):
        wizard = TieredSelectionWizard()
        result = await wizard.select(seed_groups)
        # result.selected_groups → List[SeedGroup]
        # result.fallback_strategy → FallbackStrategy

    Usage (non-interactive / preset):
        preset = SelectionPreset(target_type=TargetType.AGENT, top_n=3)
        wizard = TieredSelectionWizard(preset=preset)
        result = await wizard.select(seed_groups)
    """

    def __init__(
        self,
        *,
        enabled: bool = True,
        preset: Optional[SelectionPreset] = None,
        model_name: str = "gpt-4o",
    ):
        """
        Initialize wizard.

        Args:
            enabled: Whether to show interactive prompts (False = use preset/auto)
            preset: Non-interactive configuration (skip all prompts)
            model_name: 目标模型名称 (影响学术 ASR 查询)
        """
        self.enabled = enabled
        self.preset = preset or SelectionPreset()
        self.model_name = model_name

    async def select(
        self,
        seed_groups: Sequence[SeedGroup],
    ) -> TieredSelectionResult:
        """
        Execute the three-layer selection process.

        Args:
            seed_groups: All seed groups from CentralMemory

        Returns:
            TieredSelectionResult with selected groups and strategy
        """
        # Non-interactive mode
        if not self.enabled and self.preset.target_type is not None:
            return self._preset_select(seed_groups)
        if not self.enabled or self.preset.select_all:
            return self._auto_select(seed_groups)

        # Check preset for full auto mode
        if self.preset.target_type is not None:
            return self._preset_select(seed_groups)

        # Interactive three-layer selection
        return await self._interactive_select(seed_groups)

    # ------------------------------------------------------------------
    # Non-interactive paths
    # ------------------------------------------------------------------

    def _auto_select(
        self,
        seed_groups: Sequence[SeedGroup],
    ) -> TieredSelectionResult:
        """Full auto: select all groups with default strategy."""
        groups = list(seed_groups)
        profile = TargetProfileRouter.get_profile(TargetType.FULL_SWEEP)
        ranked = ASRRankBuilder.build_ranked_groups(groups, model_name=self.model_name)
        chain = ASRRankBuilder.build_fallback_chain(ranked)

        return TieredSelectionResult(
            selected_groups=groups,
            fallback_strategy=self.preset.fallback_strategy,
            target_profile=profile,
            ranked_groups=ranked,
            fallback_chain=chain,
            all_chain_groups=groups,
        )

    def _preset_select(
        self,
        seed_groups: Sequence[SeedGroup],
    ) -> TieredSelectionResult:
        """Preset-based selection: use configured target type and top-N."""
        profile = TargetProfileRouter.get_profile(self.preset.target_type)
        filtered = TargetProfileRouter.filter_seed_groups(seed_groups, profile)

        ranked = ASRRankBuilder.build_ranked_groups(filtered, model_name=self.model_name)
        chain = ASRRankBuilder.build_fallback_chain(ranked)

        # Select top-N groups
        top_groups = ASRRankBuilder.get_top_n(
            ranked,
            n=self.preset.top_n,
            min_tier=self.preset.min_tier,
        )

        # Extract unique SeedGroups from selected technique groups
        selected = self._extract_seed_groups(top_groups)

        if not selected:
            # Fallback: use all filtered groups
            selected = filtered
            logger.warning("Preset selection returned 0 groups, using all filtered groups")

        # Extract ALL SeedGroups from the full fallback chain (for tier fallback)
        all_chain = self._extract_seed_groups(ranked)

        print(f"  [OK] Preset: {profile.target_type.display_name} "
              f"-> {len(selected)} groups (top-{self.preset.top_n}), "
              f"{len(all_chain)} total in chain, strategy={self.preset.fallback_strategy.value}")

        return TieredSelectionResult(
            selected_groups=selected,
            fallback_strategy=self.preset.fallback_strategy,
            target_profile=profile,
            ranked_groups=ranked,
            fallback_chain=chain,
            all_chain_groups=all_chain,
        )

    # ------------------------------------------------------------------
    # Interactive three-layer selection
    # ------------------------------------------------------------------

    async def _interactive_select(
        self,
        seed_groups: Sequence[SeedGroup],
    ) -> TieredSelectionResult:
        """Interactive three-layer progressive disclosure selection."""

        # Layer 1: Target type selection
        profile = await self._layer1_target_selection(seed_groups)

        # Filter groups by target type
        filtered = TargetProfileRouter.filter_seed_groups(seed_groups, profile)

        if not filtered:
            print(f"  [!] No seed groups for {profile.target_type.display_name}, using all")
            filtered = list(seed_groups)
            profile = TargetProfileRouter.get_profile(TargetType.FULL_SWEEP)

        # Layer 2: ASR-ranked group selection (with preset schemes)
        ranked = ASRRankBuilder.build_ranked_groups(filtered, model_name=self.model_name)
        chain = ASRRankBuilder.build_fallback_chain(ranked)
        preset_schemes = PresetSchemeBuilder.build_schemes(ranked, model_name=self.model_name)
        selected = await self._layer2_group_selection(ranked, chain, preset_schemes)

        # Layer 3: Fallback strategy selection
        strategy = await self._layer3_strategy_selection()

        # Extract ALL SeedGroups from the full fallback chain (for tier fallback)
        all_chain = self._extract_seed_groups(ranked)

        return TieredSelectionResult(
            selected_groups=selected,
            fallback_strategy=strategy,
            target_profile=profile,
            ranked_groups=ranked,
            fallback_chain=chain,
            all_chain_groups=all_chain,
            preset_schemes=preset_schemes,
        )

    async def _layer1_target_selection(
        self,
        seed_groups: Sequence[SeedGroup],
    ) -> TargetProfile:
        """Layer 1: Select target type."""

        options = TargetProfileRouter.get_target_options(seed_groups)

        print("\n" + "=" * 78)
        print("  Layer 1/3: Select Attack Target Type")
        print("=" * 78)
        print(f"  {'#':>3}  {'Target':16}  {'Groups':>7}  {'Seeds':>7}  Description")
        print("-" * 78)

        for idx, ttype, gc, sc in options:
            print(f"  {idx:>3}  {ttype.display_name:16}  {gc:>7}  {sc:>7}  {ttype.description}")

        print("-" * 78)

        while True:
            try:
                choice = input(f"\n  Select target [1-{len(options)}]: ").strip()
                idx = int(choice) - 1
                if 0 <= idx < len(options):
                    _, ttype, _, _ = options[idx]
                    print(f"\n  [OK] Selected: {ttype.display_name}")
                    return TargetProfileRouter.get_profile(ttype)
                print(f"  [!] Invalid: {choice}")
            except (ValueError, EOFError, KeyboardInterrupt):
                print("\n  [OK] Cancelled -> Full Sweep")
                return TargetProfileRouter.get_profile(TargetType.FULL_SWEEP)

    async def _layer2_group_selection(
        self,
        ranked_groups: List[TechniqueGroupInfo],
        fallback_chain: List[List[TechniqueGroupInfo]],
        preset_schemes: Optional[List[PresetSchemeDefinition]] = None,
    ) -> List[SeedGroup]:
        """Layer 2: ASR-ranked group recommendation and selection.

        Supports multiple selection formats:
        - Preset: [A]=Fast, [B]=Recommended (default), [C]=Deep
        - Preset+Ext: [B,8]=Scheme B + group #8
        - Quick: [all]=all, [top-5]=top 5
        - Tier:  [S], [A], [S,A], [S-B], [S,A,C]
        - Custom: 1-11,14  or  1,3,5  or  2-6,10
        """
        if preset_schemes is None:
            preset_schemes = []

        print("\n" + "=" * 70)
        print("  Layer 2/3: ASR-Ranked Attack Groups")
        print("=" * 70)

        # --- Display Preset Schemes (primary selection) ---
        if preset_schemes:
            print("\n  Preset Schemes (recommended):")
            for scheme_def in preset_schemes:
                letter = scheme_def.scheme.letter
                marker = "  <- default" if scheme_def.scheme == PresetScheme.RECOMMENDED else ""
                print(f"    [{letter}] {scheme_def.scheme.display_name} "
                      f"({scheme_def.group_count} groups, {scheme_def.est_time_min}, "
                      f"ASR~{scheme_def.display_asr}){marker}")
                print(f"        {scheme_def.group_names}")
                print(f"        Mechanisms: {scheme_def.mechanism_names}")
            print()

        # Display tiered groups and track tier boundaries
        rank = 0
        all_displayed: List[TechniqueGroupInfo] = []
        tier_ranges: Dict[str, tuple] = {}  # tier_name -> (start_rank, end_rank)

        tier_labels = {
            "S": "S (>=70%)",
            "A": "A (40-70%)",
            "B": "B (15-40%)",
            "C": "C (5-15%)",
            "D": "D (<5%)",
            "UNKNOWN": "Heuristic (no ASR data)",
        }
        # Short tier aliases for menu display
        tier_short = {
            "S": "S",
            "A": "A",
            "B": "B",
            "C": "C",
            "D": "D",
            "UNKNOWN": "H",
        }

        for tier_groups in fallback_chain:
            if not tier_groups:
                continue
            tier = tier_groups[0].tier
            tier_val = tier.value
            tier_start = rank + 1

            print(f"\n  --- Tier {tier_labels.get(tier_val, tier_val)} ---")
            print(f"  {'#':>3}  {'OWASP':6}  {'Technique Group':36}  {'ASR':>5}  {'Seeds':>5}  {'Modes':12}")

            for g in tier_groups:
                rank += 1
                modes = ",".join(g.attack_modes[:2])
                print(f"  {rank:>3}  {g.owasp_id:6}  {g.technique_group:36}  {g.display_asr:>5}  "
                      f"{g.seed_count:>5}  {modes:12}")
                all_displayed.append(g)

            tier_ranges[tier_short.get(tier_val, tier_val)] = (tier_start, rank)

        # Build tier summary for menu
        tier_summary_parts = []
        for short_name in ["S", "A", "B", "C", "D", "H"]:
            if short_name in tier_ranges:
                start, end = tier_ranges[short_name]
                count = end - start + 1
                tier_summary_parts.append(f"{short_name}={count} groups (#{start}-#{end})")

        # Default recommendation: scheme R (Recommended) if available, else top-3
        top_3 = ASRRankBuilder.get_top_n(ranked_groups, n=3)
        default_names = [g.technique_group for g in top_3]

        has_schemes = len(preset_schemes) > 0
        if has_schemes:
            default_scheme = preset_schemes[min(1, len(preset_schemes) - 1)]  # B or last
            print(f"  Default: [{default_scheme.scheme.letter}] {default_scheme.scheme.display_name} "
                  f"({default_scheme.group_names})")
        else:
            print(f"  Default: Top-3 = {', '.join(default_names)}")
        print()
        if has_schemes:
            print("  Preset: [F]=Fast   [R]=Recommended   [D]=Deep   [R,8]=R+ext#8")
        print("  Quick:  [all]=all groups   [top-5]=top 5")
        print("  Tier:   [S]  [S,A]  [S-B]  (select by tier)")
        print("  Custom: 1-11,14  or  1,3,5  or  2-6,10  (pick by number)")
        if tier_summary_parts:
            print(f"  Tiers:  {' | '.join(tier_summary_parts)}")

        try:
            choice = input("  Selection: ").strip()
        except (EOFError, KeyboardInterrupt):
            choice = ""

        # Parse and execute selection
        return self._parse_and_execute_selection(
            choice, all_displayed, ranked_groups, tier_ranges, top_3, preset_schemes,
        )

    def _parse_and_execute_selection(
        self,
        choice: str,
        all_displayed: List[TechniqueGroupInfo],
        ranked_groups: List[TechniqueGroupInfo],
        tier_ranges: Dict[str, tuple],
        top_3: List[TechniqueGroupInfo],
        preset_schemes: Optional[List[PresetSchemeDefinition]] = None,
    ) -> List[SeedGroup]:
        """
        Parse user selection input and return selected seed groups.

        Supports:
        - Empty / "default" -> scheme R (if available) or top-3
        - Preset: F, R, D (case-insensitive) -> preset scheme
        - Preset+Ext: R,8 or F,1,3 -> scheme + extension groups
        - "all" -> all groups
        - "top-5" -> top 5
        - Tier names: S, D, H (case-insensitive) or combos S,A  S-B
        - Numbers: 1,3,5  1-11  1-11,14
        - "custom" -> prompt for numbers
        """
        if preset_schemes is None:
            preset_schemes = []

        raw = choice
        choice_lower = choice.lower().strip()

        # --- Empty / default ---
        if choice_lower == "" or choice_lower == "default":
            # Default to scheme R if available, else top-3
            if preset_schemes:
                default_scheme = preset_schemes[min(1, len(preset_schemes) - 1)]
                print(f"\n  [OK] Default: [{default_scheme.scheme.letter}] "
                      f"{default_scheme.scheme.display_name}")
                print(f"       {default_scheme.group_names}")
                return self._extract_seed_groups(default_scheme.groups)
            names = [g.technique_group for g in top_3]
            print(f"\n  [OK] Using top-3: {', '.join(names)}")
            return self._extract_seed_groups(top_3)

        # --- All ---
        if choice_lower == "all":
            print(f"\n  [OK] Using all {len(ranked_groups)} groups")
            return self._extract_seed_groups(ranked_groups)

        # --- Top-5 ---
        if choice_lower == "top-5":
            top_5 = ASRRankBuilder.get_top_n(ranked_groups, n=5)
            names = [g.technique_group for g in top_5]
            print(f"\n  [OK] Using top-5: {', '.join(names)}")
            return self._extract_seed_groups(top_5)

        # --- Custom prompt ---
        if choice_lower == "custom":
            return self._custom_selection(all_displayed)

        # --- Preset scheme selection (F/R/D or F,8 or R,1,3) ---
        # Check BEFORE tier selection to avoid F/R/D vs S/A/B/C/D conflict
        scheme_selected = self._try_scheme_selection(
            choice_lower, all_displayed, preset_schemes,
        )
        if scheme_selected is not None:
            return scheme_selected

        # --- Tier selection (S, A, S,A, S-B, etc.) ---
        tier_selected = self._try_tier_selection(choice_lower, tier_ranges, all_displayed)
        if tier_selected is not None:
            return tier_selected

        # --- Number selection (1,3,5 or 1-11 or 1-11,14) ---
        number_selected = self._try_number_selection(raw, all_displayed)
        if number_selected is not None:
            return number_selected

        # --- Invalid ---
        print(f"  [!] Invalid choice: '{raw}', using default")
        if preset_schemes:
            default_scheme = preset_schemes[min(1, len(preset_schemes) - 1)]
            print(f"  [OK] Default: [{default_scheme.scheme.letter}] "
                  f"{default_scheme.scheme.display_name}")
            return self._extract_seed_groups(default_scheme.groups)
        names = [g.technique_group for g in top_3]
        print(f"  [OK] Using top-3: {', '.join(names)}")
        return self._extract_seed_groups(top_3)

    def _try_scheme_selection(
        self,
        choice: str,
        all_displayed: List[TechniqueGroupInfo],
        preset_schemes: List[PresetSchemeDefinition],
    ) -> Optional[List[SeedGroup]]:
        """
        Try to parse choice as a preset scheme selection.

        Formats:
        - Single scheme:  F, R, D (case-insensitive)
        - Scheme + extensions:  R,8  or  F,1,3  or  D,5,7,9

        Returns None if not a scheme selection.

        Note: This is checked BEFORE tier selection so that F/R/D
        always maps to preset schemes. To select Tier A/B/C specifically,
        use combination syntax like S,A or range syntax like S-B.
        Preset letters F/R/D are distinct from Tier letters S/A/B/C/D.
        """
        if not preset_schemes:
            return None

        # Split by comma
        parts = choice.split(",")
        first = parts[0].strip()

        # Check if first part is a scheme letter
        target_scheme = PresetScheme.from_letter(first)
        if target_scheme is None:
            return None

        # Find the matching scheme definition
        scheme_def = None
        for sd in preset_schemes:
            if sd.scheme == target_scheme:
                scheme_def = sd
                break

        if scheme_def is None:
            return None

        # If only the scheme letter, return scheme groups
        if len(parts) == 1:
            print(f"\n  [OK] Scheme {scheme_def.scheme.letter}: "
                  f"{scheme_def.scheme.display_name}")
            print(f"       Groups: {scheme_def.group_names}")
            print(f"       ASR: {scheme_def.display_asr}, "
                  f"Est: {scheme_def.est_time_min}")
            return self._extract_seed_groups(scheme_def.groups)

        # Scheme + extensions: parse remaining parts as numbers
        ext_str = ",".join(parts[1:])
        ext_indices = self._parse_indices(ext_str, len(all_displayed))

        if not ext_indices:
            # Extensions were not valid numbers — not a scheme selection
            return None

        # Build combined selection (scheme groups + extension groups)
        selected_tg: List[TechniqueGroupInfo] = list(scheme_def.groups)
        existing_names: Set[str] = {g.technique_group for g in selected_tg}

        for idx in ext_indices:
            if 0 <= idx < len(all_displayed):
                g = all_displayed[idx]
                if g.technique_group not in existing_names:
                    selected_tg.append(g)
                    existing_names.add(g.technique_group)

        names = [g.technique_group for g in selected_tg]
        print(f"\n  [OK] Scheme {scheme_def.scheme.letter} + {len(ext_indices)} ext: "
              f"{len(selected_tg)} groups")
        print(f"       {', '.join(names[:8])}{'...' if len(names) > 8 else ''}")

        return self._extract_seed_groups(selected_tg)

    def _try_tier_selection(
        self,
        choice: str,
        tier_ranges: Dict[str, tuple],
        all_displayed: List[TechniqueGroupInfo],
    ) -> Optional[List[SeedGroup]]:
        """
        Try to parse choice as tier selection.

        Formats:
        - Single tier:  S, A, B, C, D, H
        - Multiple tiers:  S,A  S,A,C
        - Tier range:  S-B  S-D  A-C

        Returns None if not a tier selection.
        """
        # Normalize to lowercase for case-insensitive matching
        choice = choice.lower().strip()

        # All recognized tier names
        tier_names = {"s", "a", "b", "c", "d", "h"}
        # Map short names to canonical order
        tier_order = ["s", "a", "b", "c", "d", "h"]

        # Check if this looks like a tier selection
        # It should contain only tier names, commas, and hyphens
        cleaned = choice.replace(",", " ").replace("-", " ")
        parts = cleaned.split()
        if not parts:
            return None

        is_tier = all(p in tier_names for p in parts)
        if not is_tier:
            return None

        # Parse into set of tier names
        selected_tiers: set = set()

        for part in choice.split(","):
            part = part.strip()
            if "-" in part:
                # Range: S-B
                match = re.match(r"^([sabcdh])-([sabcdh])$", part)
                if match:
                    start_tier = match.group(1)
                    end_tier = match.group(2)
                    try:
                        start_idx = tier_order.index(start_tier)
                        end_idx = tier_order.index(end_tier)
                        if start_idx > end_idx:
                            start_idx, end_idx = end_idx, start_idx
                        for t in tier_order[start_idx:end_idx + 1]:
                            selected_tiers.add(t)
                    except ValueError:
                        return None
                else:
                    return None
            elif part in tier_names:
                selected_tiers.add(part)
            else:
                return None

        if not selected_tiers:
            return None

        # Collect groups from selected tiers
        selected_groups: List[TechniqueGroupInfo] = []
        tier_display_names = {
            "s": "S", "a": "A", "b": "B", "c": "C", "d": "D", "h": "Heuristic",
        }
        selected_labels = []

        for tier_name in tier_order:
            if tier_name not in selected_tiers:
                continue
            # tier_ranges may use uppercase or lowercase keys
            ranges_key = tier_name.upper() if tier_name.upper() in tier_ranges else tier_name
            if ranges_key not in tier_ranges:
                continue
            start, end = tier_ranges[ranges_key]
            # Convert to 0-based indices
            indices = list(range(start - 1, end))
            for idx in indices:
                if 0 <= idx < len(all_displayed):
                    selected_groups.append(all_displayed[idx])
            selected_labels.append(tier_display_names.get(tier_name, tier_name.upper()))

        if not selected_groups:
            return None

        names = [g.technique_group for g in selected_groups]
        print(f"\n  [OK] Tier {' + '.join(selected_labels)}: {len(selected_groups)} groups")
        print(f"       {', '.join(names[:8])}{'...' if len(names) > 8 else ''}")
        return self._extract_seed_groups(selected_groups)

    def _try_number_selection(
        self,
        raw: str,
        all_displayed: List[TechniqueGroupInfo],
    ) -> Optional[List[SeedGroup]]:
        """
        Try to parse choice as number selection.

        Formats:
        - Single:  1  or  5
        - Multiple:  1,3,5
        - Range:  1-11
        - Mixed:  1-11,14  or  2-6,10,12

        Returns None if not a number selection.
        """
        try:
            indices = self._parse_indices(raw, len(all_displayed))
        except (ValueError, TypeError):
            return None
        if not indices:
            return None

        # Deduplicate while preserving order
        seen = set()
        unique_indices = []
        for idx in indices:
            if idx not in seen:
                seen.add(idx)
                unique_indices.append(idx)

        selected = [all_displayed[i] for i in unique_indices]
        names = [g.technique_group for g in selected]
        print(f"\n  [OK] Custom ({len(selected)} groups): {', '.join(names[:8])}{'...' if len(names) > 8 else ''}")
        return self._extract_seed_groups(selected)

    def _custom_selection(
        self,
        all_displayed: List[TechniqueGroupInfo],
    ) -> List[SeedGroup]:
        """Custom number-based selection."""
        try:
            print("  Examples:  1,3,5  |  1-11  |  1-11,14  |  2-6,10,12")
            raw = input("  Enter numbers: ").strip()
            indices = self._parse_indices(raw, len(all_displayed))
            if not indices:
                print("  [!] No valid indices, using top-3")
                return self._extract_seed_groups(all_displayed[:3])

            selected = [all_displayed[i] for i in indices]
            names = [g.technique_group for g in selected]
            print(f"\n  [OK] Custom: {', '.join(names)}")
            return self._extract_seed_groups(selected)
        except (EOFError, KeyboardInterrupt):
            print("\n  [OK] Cancelled, using top-3")
            return self._extract_seed_groups(all_displayed[:3])

    async def _layer3_strategy_selection(self) -> FallbackStrategy:
        """Layer 3: Select fallback strategy."""

        print("\n" + "=" * 70)
        print("  Layer 3/3: Fallback Strategy")
        print("=" * 70)

        strategies = list(FallbackStrategy)
        for i, s in enumerate(strategies, 1):
            print(f"  [{i}] {s.display_name}")
            print(f"      {s.description}")

        print()

        while True:
            try:
                choice = input("  Select strategy [1-3, default=1]: ").strip()
                if not choice:
                    print(f"\n  [OK] Default: {FallbackStrategy.SEQUENTIAL_ASR_DESC.display_name}")
                    return FallbackStrategy.SEQUENTIAL_ASR_DESC

                idx = int(choice) - 1
                if 0 <= idx < len(strategies):
                    print(f"\n  [OK] Selected: {strategies[idx].display_name}")
                    return strategies[idx]
                print(f"  [!] Invalid: {choice}")
            except (ValueError, EOFError, KeyboardInterrupt):
                print(f"\n  [OK] Default: {FallbackStrategy.SEQUENTIAL_ASR_DESC.display_name}")
                return FallbackStrategy.SEQUENTIAL_ASR_DESC

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_seed_groups(
        technique_groups: List[TechniqueGroupInfo],
    ) -> List[SeedGroup]:
        """Extract unique SeedGroups from technique group info."""
        seen: set = set()
        result: List[SeedGroup] = []
        for tg in technique_groups:
            for sg in tg.source_seed_groups:
                sg_id = id(sg)
                if sg_id not in seen:
                    seen.add(sg_id)
                    result.append(sg)
        return result

    @staticmethod
    def _parse_indices(raw: str, max_len: int) -> List[int]:
        """Parse index string (e.g., '1,2,5-7' or '1-11,14').

        Returns empty list for invalid input (does not raise).
        """
        indices: List[int] = []
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                match = re.match(r"^(\d+)\s*-\s*(\d+)$", part)
                if match:
                    start, end = int(match.group(1)) - 1, int(match.group(2)) - 1
                    for idx in range(start, end + 1):
                        if 0 <= idx < max_len:
                            indices.append(idx)
            else:
                try:
                    idx = int(part) - 1
                except ValueError:
                    return []
                if 0 <= idx < max_len:
                    indices.append(idx)
        return indices


# ============================================================
# Convenience functions
# ============================================================


async def select_with_wizard(
    seed_groups: Sequence[SeedGroup],
    *,
    enabled: bool = True,
    preset: Optional[SelectionPreset] = None,
    model_name: str = "gpt-4o",
) -> TieredSelectionResult:
    """Convenience: run tiered selection wizard."""
    wizard = TieredSelectionWizard(enabled=enabled, preset=preset, model_name=model_name)
    return await wizard.select(seed_groups)
