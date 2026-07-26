"""
Tests for the tiered progressive disclosure selection system.

Covers:
  P0-1: TargetProfileRouter (target type mapping, inference, filtering,
        metadata refinement, backward compatibility)
  P0-2: ASRRankBuilder (ranking, tier classification, heuristic, fallback chain)
  P1-1: TieredSelectionWizard (preset mode, auto-select)
  P1-2: GroupFallbackExecutor (plan partitioning)
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from src.payloads.target_profile_router import (
    TargetType,
    TargetProfile,
    TargetProfileRouter,
    get_target_profile,
    infer_target_profile,
    filter_groups_by_target,
)
from src.payloads.asr_rank_builder import (
    ASRTier,
    TechniqueGroupInfo,
    ASRRankBuilder,
    build_ranked_groups,
    build_fallback_chain,
    get_top_n_groups,
)
from src.payloads.tiered_selection_wizard import (
    FallbackStrategy,
    TieredSelectionResult,
    SelectionPreset,
    TieredSelectionWizard,
    select_with_wizard,
)
from src.payloads.group_fallback_executor import (
    FallbackExecutionResult,
    GroupFallbackExecutor,
)
from src.payloads.models import AttackPlan, AttackMode, PromptItem


# ============================================================
# Test Helpers
# ============================================================


def _make_seed(value="test", metadata=None):
    """Create a mock seed with metadata."""
    seed = MagicMock()
    seed.value = value
    seed.metadata = metadata or {}
    seed.dataset_name = "owasp_test"
    return seed


def _make_seed_group(seeds=None, owasp_id="LLM01", harm_categories=None):
    """Create a mock SeedGroup."""
    if seeds is None:
        seeds = [_make_seed(metadata={"owasp_id": owasp_id})]

    sg = MagicMock()
    sg.seeds = seeds
    sg.harm_categories = harm_categories or ["prompt_injection"]
    sg.prepended_conversation = None
    sg.objective = None
    sg.prompts = [_make_seed(value=s.value) for s in seeds]
    return sg


def _make_seed_groups_with_asr():
    """Create realistic mock seed groups with ASR data."""
    groups = []

    # Tier S: skeleton_key (ASR=95%)
    seeds_s = [
        _make_seed(
            value="skeleton key payload",
            metadata={
                "owasp_id": "LLM01",
                "technique_group": "skeleton_key",
                "attack_mode": "single_turn",
                "asr_baseline": {"gpt_4o": 0.95, "claude_4_opus": 0.90},
                "difficulty": "medium",
                "evasion_level": "high",
            }
        )
    ]
    groups.append(_make_seed_group(seeds_s, "LLM01"))

    # Tier A: crescendo (ASR=65%)
    seeds_a = [
        _make_seed(
            value="crescendo payload",
            metadata={
                "owasp_id": "LLM01",
                "technique_group": "crescendo",
                "attack_mode": "multi_turn",
                "asr_baseline": {"gpt_4o": 0.65, "claude_4_opus": 0.60},
                "difficulty": "hard",
                "evasion_level": "medium",
            }
        )
    ]
    groups.append(_make_seed_group(seeds_a, "LLM01"))

    # Tier UNKNOWN: direct_injection (no ASR)
    seeds_u = [
        _make_seed(
            value="direct injection",
            metadata={
                "owasp_id": "LLM01",
                "technique_group": "direct_injection",
                "attack_mode": "single_turn",
                "difficulty": "easy",
                "evasion_level": "low",
            }
        )
    ]
    groups.append(_make_seed_group(seeds_u, "LLM01"))

    # Agent: goal_hijack (ASR=80%)
    seeds_agent = [
        _make_seed(
            value="goal hijack",
            metadata={
                "owasp_id": "ASI01",
                "technique_group": "goal_hijack",
                "attack_mode": "single_turn",
                "asr_baseline": {"gpt_4o": 0.80},
                "difficulty": "medium",
                "evasion_level": "high",
            }
        )
    ]
    groups.append(_make_seed_group(seeds_agent, "ASI01"))

    return groups


def _make_multimodal_seed_groups():
    """Create mock seed groups with multimodal technique_group prefix."""
    groups = []

    # Multimodal injection (LLM01 with multimodal prefix)
    seeds_mm = [
        _make_seed(
            value="multimodal injection payload",
            metadata={
                "owasp_id": "LLM01",
                "technique_group": "multimodal_injection",
                "attack_mode": "single_turn",
                "difficulty": "medium",
                "evasion_level": "medium",
            }
        )
    ]
    groups.append(_make_seed_group(seeds_mm, "LLM01"))

    # Multimodal jailbreak v2 (LLM01 with multimodal prefix)
    seeds_mm2 = [
        _make_seed(
            value="multimodal jailbreak payload",
            metadata={
                "owasp_id": "LLM01",
                "technique_group": "multimodal_jailbreak_v2",
                "attack_mode": "single_turn",
                "difficulty": "hard",
                "evasion_level": "high",
            }
        )
    ]
    groups.append(_make_seed_group(seeds_mm2, "LLM01"))

    # Non-multimodal LLM01 group (should NOT match MULTIMODAL filter)
    seeds_text = [
        _make_seed(
            value="text jailbreak",
            metadata={
                "owasp_id": "LLM01",
                "technique_group": "skeleton_key",
                "attack_mode": "single_turn",
            }
        )
    ]
    groups.append(_make_seed_group(seeds_text, "LLM01"))

    return groups


def _make_comprehensive_seed_groups():
    """Create seed groups covering all target types for comprehensive testing."""
    groups = _make_seed_groups_with_asr()

    # RAG (LLM04)
    seeds_rag = [
        _make_seed(
            value="rag poison",
            metadata={
                "owasp_id": "LLM04",
                "technique_group": "rag_poison",
                "attack_mode": "single_turn",
            }
        )
    ]
    groups.append(_make_seed_group(seeds_rag, "LLM04"))

    # Vector DB (LLM08)
    seeds_vec = [
        _make_seed(
            value="vector injection",
            metadata={
                "owasp_id": "LLM08",
                "technique_group": "vector_injection",
                "attack_mode": "single_turn",
            }
        )
    ]
    groups.append(_make_seed_group(seeds_vec, "LLM08"))

    # MCP/Tool (LLM06)
    seeds_mcp = [
        _make_seed(
            value="mcp tool poison",
            metadata={
                "owasp_id": "LLM06",
                "technique_group": "mcp_tool_poison",
                "attack_mode": "single_turn",
            }
        )
    ]
    groups.append(_make_seed_group(seeds_mcp, "LLM06"))

    # Output Handling (LLM05)
    seeds_out = [
        _make_seed(
            value="xss output",
            metadata={
                "owasp_id": "LLM05",
                "technique_group": "xss_injection",
                "attack_mode": "single_turn",
            }
        )
    ]
    groups.append(_make_seed_group(seeds_out, "LLM05"))

    # LLM Safety (LLM09)
    seeds_safety = [
        _make_seed(
            value="hallucination exploit",
            metadata={
                "owasp_id": "LLM09",
                "technique_group": "hallucination",
                "attack_mode": "single_turn",
            }
        )
    ]
    groups.append(_make_seed_group(seeds_safety, "LLM09"))

    # Multimodal (LLM01 with multimodal prefix)
    seeds_mm = [
        _make_seed(
            value="multimodal injection",
            metadata={
                "owasp_id": "LLM01",
                "technique_group": "multimodal_injection",
                "attack_mode": "single_turn",
            }
        )
    ]
    groups.append(_make_seed_group(seeds_mm, "LLM01"))

    # Copilot-related (LLM07 prompt leakage)
    seeds_copilot = [
        _make_seed(
            value="copilot prompt leak",
            metadata={
                "owasp_id": "LLM07",
                "technique_group": "copilot_prompt_leak",
                "attack_mode": "single_turn",
            }
        )
    ]
    groups.append(_make_seed_group(seeds_copilot, "LLM07"))

    return groups


# ============================================================
# P0-1: TargetProfileRouter Tests
# ============================================================


class TestTargetType:
    def test_target_type_values(self):
        assert TargetType.LLM_DIRECT.value == "llm_direct"
        assert TargetType.AGENT.value == "agent"
        assert TargetType.RAG_VECTOR.value == "rag_vector"
        assert TargetType.MCP_TOOL.value == "mcp_tool"
        assert TargetType.COPILOT.value == "copilot"
        assert TargetType.MULTIMODAL.value == "multimodal"
        assert TargetType.OUTPUT_HANDLING.value == "output_handling"
        assert TargetType.LLM_SAFETY.value == "llm_safety"
        assert TargetType.DEFENSE_BYPASS.value == "defense_bypass"
        assert TargetType.FULL_SWEEP.value == "full_sweep"

    def test_display_name(self):
        assert TargetType.LLM_DIRECT.display_name == "LLM Direct"
        assert TargetType.AGENT.display_name == "Agent"
        assert TargetType.RAG_VECTOR.display_name == "RAG & Vector"
        assert TargetType.COPILOT.display_name == "Copilot"
        assert TargetType.MULTIMODAL.display_name == "Multimodal"
        assert TargetType.OUTPUT_HANDLING.display_name == "Output Handling"
        assert TargetType.DEFENSE_BYPASS.display_name == "Defense Bypass"
        assert TargetType.FULL_SWEEP.display_name == "Full Sweep"

    def test_description(self):
        assert "Direct LLM" in TargetType.LLM_DIRECT.description
        assert "Agentic" in TargetType.AGENT.description
        assert "RAG" in TargetType.RAG_VECTOR.description
        assert "Copilot" in TargetType.COPILOT.description
        assert "Multimodal" in TargetType.MULTIMODAL.description
        assert "Output handling" in TargetType.OUTPUT_HANDLING.description
        assert "Defense bypass" in TargetType.DEFENSE_BYPASS.description

    def test_pyrit_targets(self):
        """Test that each target type maps to PyRIT native Target classes."""
        assert "OpenAIChatTarget" in TargetType.LLM_DIRECT.pyrit_targets
        assert "PlaywrightTarget" in TargetType.AGENT.pyrit_targets
        assert "AzureBlobStorageTarget" in TargetType.RAG_VECTOR.pyrit_targets
        assert "WebSocketCopilotTarget" in TargetType.COPILOT.pyrit_targets
        assert "OpenAIImageTarget" in TargetType.MULTIMODAL.pyrit_targets
        assert "PromptShieldTarget" in TargetType.DEFENSE_BYPASS.pyrit_targets


class TestBackwardCompatibility:
    """Test backward-compatible alias parsing via TargetType.from_string()."""

    def test_from_string_rag_alias(self):
        """Legacy 'rag' maps to RAG_VECTOR."""
        tt = TargetType.from_string("rag")
        assert tt == TargetType.RAG_VECTOR

    def test_from_string_vector_db_alias(self):
        """Legacy 'vector_db' maps to RAG_VECTOR."""
        tt = TargetType.from_string("vector_db")
        assert tt == TargetType.RAG_VECTOR

    def test_from_string_web_output_alias(self):
        """Legacy 'web_output' maps to OUTPUT_HANDLING."""
        tt = TargetType.from_string("web_output")
        assert tt == TargetType.OUTPUT_HANDLING

    def test_from_string_new_values(self):
        """New values parse directly."""
        assert TargetType.from_string("copilot") == TargetType.COPILOT
        assert TargetType.from_string("multimodal") == TargetType.MULTIMODAL
        assert TargetType.from_string("defense_bypass") == TargetType.DEFENSE_BYPASS
        assert TargetType.from_string("rag_vector") == TargetType.RAG_VECTOR
        assert TargetType.from_string("output_handling") == TargetType.OUTPUT_HANDLING

    def test_from_string_case_insensitive(self):
        """from_string is case-insensitive."""
        assert TargetType.from_string("RAG") == TargetType.RAG_VECTOR
        assert TargetType.from_string("COPILOT") == TargetType.COPILOT
        assert TargetType.from_string(" Agent ") == TargetType.AGENT

    def test_from_string_invalid_raises(self):
        """Invalid values raise ValueError."""
        with pytest.raises(ValueError):
            TargetType.from_string("nonexistent_type")


class TestTargetProfileRouter:
    def test_get_profile_llm_direct(self):
        profile = TargetProfileRouter.get_profile(TargetType.LLM_DIRECT)
        assert profile.target_type == TargetType.LLM_DIRECT
        assert "LLM01" in profile.owasp_categories
        assert "LLM02" in profile.owasp_categories
        assert "LLM07" in profile.owasp_categories

    def test_get_profile_agent(self):
        profile = TargetProfileRouter.get_profile(TargetType.AGENT)
        assert "ASI01" in profile.owasp_categories
        assert "ASI10" in profile.owasp_categories
        assert len(profile.owasp_categories) == 10

    def test_get_profile_rag_vector(self):
        """RAG_VECTOR maps to both LLM04 and LLM08."""
        profile = TargetProfileRouter.get_profile(TargetType.RAG_VECTOR)
        assert "LLM04" in profile.owasp_categories
        assert "LLM08" in profile.owasp_categories
        assert len(profile.owasp_categories) == 2

    def test_get_profile_mcp(self):
        profile = TargetProfileRouter.get_profile(TargetType.MCP_TOOL)
        assert profile.owasp_categories == ["LLM06"]

    def test_get_profile_copilot(self):
        """COPILOT maps to LLM01, LLM02, LLM07."""
        profile = TargetProfileRouter.get_profile(TargetType.COPILOT)
        assert "LLM01" in profile.owasp_categories
        assert "LLM02" in profile.owasp_categories
        assert "LLM07" in profile.owasp_categories

    def test_get_profile_multimodal(self):
        """MULTIMODAL maps to LLM01 and has technique_group_prefix."""
        profile = TargetProfileRouter.get_profile(TargetType.MULTIMODAL)
        assert profile.owasp_categories == ["LLM01"]
        assert profile.technique_group_prefix == "multimodal"

    def test_get_profile_output_handling(self):
        profile = TargetProfileRouter.get_profile(TargetType.OUTPUT_HANDLING)
        assert profile.owasp_categories == ["LLM05"]

    def test_get_profile_llm_safety(self):
        profile = TargetProfileRouter.get_profile(TargetType.LLM_SAFETY)
        assert "LLM09" in profile.owasp_categories
        assert "LLM10" in profile.owasp_categories

    def test_get_profile_defense_bypass(self):
        profile = TargetProfileRouter.get_profile(TargetType.DEFENSE_BYPASS)
        assert profile.owasp_categories == ["LLM01"]
        assert profile.technique_group_prefix == ""  # No prefix filter

    def test_get_profile_full_sweep(self):
        profile = TargetProfileRouter.get_profile(TargetType.FULL_SWEEP)
        assert profile.is_full_sweep
        assert profile.owasp_categories == []

    # ── Capability inference ──

    def test_infer_from_capabilities_agent(self):
        profile = TargetProfileRouter.infer_profile(
            capabilities={"chat": True, "tool_calling": True, "memory": True}
        )
        assert profile.target_type == TargetType.AGENT

    def test_infer_from_capabilities_rag_vector(self):
        profile = TargetProfileRouter.infer_profile(
            capabilities={"chat": True, "retrieval": True}
        )
        assert profile.target_type == TargetType.RAG_VECTOR

    def test_infer_from_capabilities_mcp(self):
        profile = TargetProfileRouter.infer_profile(
            capabilities={"chat": True, "tool_calling": True}
        )
        assert profile.target_type == TargetType.MCP_TOOL

    def test_infer_from_capabilities_llm(self):
        profile = TargetProfileRouter.infer_profile(
            capabilities={"chat": True}
        )
        assert profile.target_type == TargetType.LLM_DIRECT

    def test_infer_from_capabilities_copilot(self):
        """Copilot capability inference."""
        profile = TargetProfileRouter.infer_profile(
            capabilities={"chat": True, "copilot": True}
        )
        assert profile.target_type == TargetType.COPILOT

    def test_infer_from_capabilities_multimodal_image(self):
        """Image generation capability → MULTIMODAL."""
        profile = TargetProfileRouter.infer_profile(
            capabilities={"chat": True, "image_generation": True}
        )
        assert profile.target_type == TargetType.MULTIMODAL

    def test_infer_from_capabilities_multimodal_video(self):
        """Video generation capability → MULTIMODAL."""
        profile = TargetProfileRouter.infer_profile(
            capabilities={"chat": True, "video_generation": True}
        )
        assert profile.target_type == TargetType.MULTIMODAL

    def test_infer_from_capabilities_defense_bypass(self):
        """Prompt shield capability → DEFENSE_BYPASS."""
        profile = TargetProfileRouter.infer_profile(
            capabilities={"chat": True, "prompt_shield": True}
        )
        assert profile.target_type == TargetType.DEFENSE_BYPASS

    def test_infer_from_capabilities_embedding_store(self):
        """Embedding store capability → RAG_VECTOR (merged from VECTOR_DB)."""
        profile = TargetProfileRouter.infer_profile(
            capabilities={"chat": True, "embedding_store": True}
        )
        assert profile.target_type == TargetType.RAG_VECTOR

    def test_infer_from_capabilities_web_rendering(self):
        """Web rendering capability → OUTPUT_HANDLING (renamed from WEB_OUTPUT)."""
        profile = TargetProfileRouter.infer_profile(
            capabilities={"chat": True, "web_rendering": True}
        )
        assert profile.target_type == TargetType.OUTPUT_HANDLING

    # ── OWASP hint inference ──

    def test_infer_from_owasp_hint(self):
        profile = TargetProfileRouter.infer_profile(owasp_hint="ASI01")
        assert profile.target_type == TargetType.AGENT

    def test_infer_from_owasp_hint_llm04(self):
        """LLM04 hint → RAG_VECTOR."""
        profile = TargetProfileRouter.infer_profile(owasp_hint="LLM04")
        assert profile.target_type == TargetType.RAG_VECTOR

    def test_infer_from_owasp_hint_llm08(self):
        """LLM08 hint → RAG_VECTOR."""
        profile = TargetProfileRouter.infer_profile(owasp_hint="LLM08")
        assert profile.target_type == TargetType.RAG_VECTOR

    def test_infer_from_owasp_hint_llm05(self):
        """LLM05 hint → OUTPUT_HANDLING."""
        profile = TargetProfileRouter.infer_profile(owasp_hint="LLM05")
        assert profile.target_type == TargetType.OUTPUT_HANDLING

    def test_infer_from_owasp_hint_llm01_default(self):
        """LLM01 hint → LLM_DIRECT (default priority over COPILOT/MULTIMODAL)."""
        profile = TargetProfileRouter.infer_profile(owasp_hint="LLM01")
        assert profile.target_type == TargetType.LLM_DIRECT

    def test_infer_default(self):
        profile = TargetProfileRouter.infer_profile()
        assert profile.target_type == TargetType.FULL_SWEEP

    # ── Seed group filtering ──

    def test_filter_seed_groups_agent(self):
        groups = _make_seed_groups_with_asr()
        profile = TargetProfileRouter.get_profile(TargetType.AGENT)
        filtered = TargetProfileRouter.filter_seed_groups(groups, profile)
        # Only the ASI01 group should match
        assert len(filtered) == 1

    def test_filter_seed_groups_llm(self):
        groups = _make_seed_groups_with_asr()
        profile = TargetProfileRouter.get_profile(TargetType.LLM_DIRECT)
        filtered = TargetProfileRouter.filter_seed_groups(groups, profile)
        # LLM01 groups (3 of them)
        assert len(filtered) == 3

    def test_filter_seed_groups_rag_vector(self):
        """RAG_VECTOR filters both LLM04 and LLM08 groups."""
        groups = _make_comprehensive_seed_groups()
        profile = TargetProfileRouter.get_profile(TargetType.RAG_VECTOR)
        filtered = TargetProfileRouter.filter_seed_groups(groups, profile)
        # Should include LLM04 (rag_poison) and LLM08 (vector_injection)
        assert len(filtered) == 2

    def test_filter_seed_groups_full_sweep(self):
        groups = _make_seed_groups_with_asr()
        profile = TargetProfileRouter.get_profile(TargetType.FULL_SWEEP)
        filtered = TargetProfileRouter.filter_seed_groups(groups, profile)
        assert len(filtered) == len(groups)

    # ── Metadata-based filtering (MULTIMODAL) ──

    def test_filter_multimodal_with_prefix(self):
        """MULTIMODAL filters by technique_group prefix 'multimodal'."""
        groups = _make_multimodal_seed_groups()
        profile = TargetProfileRouter.get_profile(TargetType.MULTIMODAL)
        filtered = TargetProfileRouter.filter_seed_groups(groups, profile)

        # Should only include 2 multimodal groups, not the skeleton_key group
        assert len(filtered) == 2
        for sg in filtered:
            # Verify each filtered group has a multimodal technique
            has_mm = False
            for seed in sg.seeds:
                tg = seed.metadata.get("technique_group", "")
                if tg.startswith("multimodal"):
                    has_mm = True
                    break
            assert has_mm

    def test_filter_multimodal_excludes_non_multimodal(self):
        """MULTIMODAL filter excludes non-multimodal LLM01 groups."""
        groups = _make_multimodal_seed_groups()
        profile = TargetProfileRouter.get_profile(TargetType.MULTIMODAL)
        filtered = TargetProfileRouter.filter_seed_groups(groups, profile)

        # skeleton_key group should NOT be in filtered results
        for sg in filtered:
            for seed in sg.seeds:
                tg = seed.metadata.get("technique_group", "")
                assert not tg.startswith("skeleton")

    def test_filter_defense_bypass_no_prefix(self):
        """DEFENSE_BYPASS does not apply technique_group prefix filter."""
        groups = _make_seed_groups_with_asr()
        profile = TargetProfileRouter.get_profile(TargetType.DEFENSE_BYPASS)
        filtered = TargetProfileRouter.filter_seed_groups(groups, profile)

        # All LLM01 groups should be included (no prefix filtering)
        assert len(filtered) == 3

    # ── Target options menu ──

    def test_get_target_options(self):
        groups = _make_seed_groups_with_asr()
        options = TargetProfileRouter.get_target_options(groups)
        # Should always have 10 options (9 target types + FULL_SWEEP)
        assert len(options) == 10
        # Last option should be FULL_SWEEP
        _, last_type, _, _ = options[-1]
        assert last_type == TargetType.FULL_SWEEP

    def test_get_target_options_always_shows_all_types(self):
        """All 9 target types + Full Sweep should always appear in the menu,
        even if some have 0 matching seeds."""
        groups = _make_seed_groups_with_asr()
        options = TargetProfileRouter.get_target_options(groups)

        target_types = [opt[1] for opt in options]
        # Verify all target types are present
        for ttype in TargetType:
            assert ttype in target_types, f"{ttype} missing from options"

    def test_get_target_options_comprehensive(self):
        """Test target options with comprehensive seed groups."""
        groups = _make_comprehensive_seed_groups()
        options = TargetProfileRouter.get_target_options(groups)

        # Should have exactly 10 options (9 target types + FULL_SWEEP)
        assert len(options) == 10
        # Last should be FULL_SWEEP
        assert options[-1][1] == TargetType.FULL_SWEEP

        # Verify each option has correct counts
        for idx, ttype, gc, sc in options[:-1]:  # Exclude FULL_SWEEP
            if gc > 0:
                assert sc > 0, f"{ttype.display_name} has groups but 0 seeds"

    def test_get_target_options_includes_multimodal(self):
        """MULTIMODAL should appear in options when multimodal seeds exist."""
        groups = _make_comprehensive_seed_groups()
        options = TargetProfileRouter.get_target_options(groups)

        target_types = [opt[1] for opt in options]
        assert TargetType.MULTIMODAL in target_types

    def test_get_target_options_includes_copilot(self):
        """COPILOT should always appear in options (shares OWASP with LLM_DIRECT)."""
        groups = _make_comprehensive_seed_groups()
        options = TargetProfileRouter.get_target_options(groups)

        target_types = [opt[1] for opt in options]
        assert TargetType.COPILOT in target_types

    def test_get_target_options_includes_defense_bypass(self):
        """DEFENSE_BYPASS should always appear in options."""
        groups = _make_comprehensive_seed_groups()
        options = TargetProfileRouter.get_target_options(groups)

        target_types = [opt[1] for opt in options]
        assert TargetType.DEFENSE_BYPASS in target_types

    def test_get_target_options_copilot_shares_llm_counts(self):
        """COPILOT and LLM_DIRECT share OWASP categories, so their counts
        should reflect the same LLM01/LLM02/LLM07 seed groups."""
        groups = _make_comprehensive_seed_groups()
        options = TargetProfileRouter.get_target_options(groups)

        counts = {opt[1]: (opt[2], opt[3]) for opt in options}

        # COPILOT maps to LLM01, LLM02, LLM07
        # LLM_DIRECT also maps to LLM01, LLM02, LLM03, LLM07
        # So COPILOT count should be <= LLM_DIRECT count
        copilot_gc = counts[TargetType.COPILOT][0]
        llm_gc = counts[TargetType.LLM_DIRECT][0]
        assert copilot_gc > 0, "COPILOT should have non-zero groups"
        assert copilot_gc <= llm_gc, "COPILOT should be subset of LLM_DIRECT"

    def test_get_target_options_defense_bypass_has_counts(self):
        """DEFENSE_BYPASS maps to LLM01, so should have non-zero counts
        when LLM01 seeds exist."""
        groups = _make_comprehensive_seed_groups()
        options = TargetProfileRouter.get_target_options(groups)

        counts = {opt[1]: (opt[2], opt[3]) for opt in options}
        db_gc = counts[TargetType.DEFENSE_BYPASS][0]
        assert db_gc > 0, "DEFENSE_BYPASS should have non-zero groups"

    def test_get_target_options_multimodal_subset_of_llm(self):
        """MULTIMODAL is a filtered subset of LLM01, so its count should be
        less than or equal to LLM_DIRECT's LLM01 groups."""
        groups = _make_comprehensive_seed_groups()
        options = TargetProfileRouter.get_target_options(groups)

        counts = {opt[1]: (opt[2], opt[3]) for opt in options}
        mm_gc = counts[TargetType.MULTIMODAL][0]
        llm_gc = counts[TargetType.LLM_DIRECT][0]
        assert mm_gc > 0, "MULTIMODAL should have non-zero groups"
        assert mm_gc < llm_gc, "MULTIMODAL should be strict subset of LLM_DIRECT"


class TestConvenienceFunctions:
    def test_get_target_profile(self):
        profile = get_target_profile(TargetType.RAG_VECTOR)
        assert profile.target_type == TargetType.RAG_VECTOR

    def test_infer_target_profile(self):
        profile = infer_target_profile(capabilities={"retrieval": True})
        assert profile.target_type == TargetType.RAG_VECTOR

    def test_filter_groups_by_target(self):
        groups = _make_seed_groups_with_asr()
        filtered = filter_groups_by_target(groups, TargetType.AGENT)
        assert len(filtered) == 1

    def test_filter_groups_by_rag_vector(self):
        groups = _make_comprehensive_seed_groups()
        filtered = filter_groups_by_target(groups, TargetType.RAG_VECTOR)
        assert len(filtered) == 2

    def test_filter_groups_by_multimodal(self):
        groups = _make_multimodal_seed_groups()
        filtered = filter_groups_by_target(groups, TargetType.MULTIMODAL)
        assert len(filtered) == 2


# ============================================================
# P0-2: ASRRankBuilder Tests
# ============================================================


class TestASRTier:
    def test_from_asr_s(self):
        assert ASRTier.from_asr(0.95) == ASRTier.S
        assert ASRTier.from_asr(0.80) == ASRTier.S

    def test_from_asr_a(self):
        assert ASRTier.from_asr(0.65) == ASRTier.A
        assert ASRTier.from_asr(0.50) == ASRTier.A

    def test_from_asr_b(self):
        assert ASRTier.from_asr(0.45) == ASRTier.B
        assert ASRTier.from_asr(0.30) == ASRTier.B

    def test_from_asr_c(self):
        assert ASRTier.from_asr(0.20) == ASRTier.C
        assert ASRTier.from_asr(0.15) == ASRTier.C

    def test_from_asr_d(self):
        assert ASRTier.from_asr(0.05) == ASRTier.D
        assert ASRTier.from_asr(0.0) == ASRTier.D

    def test_priority_ordering(self):
        assert ASRTier.S.priority > ASRTier.A.priority
        assert ASRTier.A.priority > ASRTier.B.priority
        assert ASRTier.B.priority > ASRTier.C.priority


class TestASRRankBuilder:
    def test_build_ranked_groups(self):
        groups = _make_seed_groups_with_asr()
        ranked = ASRRankBuilder.build_ranked_groups(groups)
        assert len(ranked) >= 3  # skeleton_key, crescendo, direct_injection, goal_hijack

    def test_ranking_order(self):
        groups = _make_seed_groups_with_asr()
        ranked = ASRRankBuilder.build_ranked_groups(groups)
        # First group should have highest ASR (skeleton_key=95%)
        assert ranked[0].technique_group == "skeleton_key"
        assert ranked[0].max_asr == pytest.approx(0.95)

    def test_tier_classification(self):
        groups = _make_seed_groups_with_asr()
        ranked = ASRRankBuilder.build_ranked_groups(groups)

        tiers = {g.technique_group: g.tier for g in ranked}
        assert tiers["skeleton_key"] == ASRTier.S
        assert tiers["crescendo"] == ASRTier.A
        assert tiers["goal_hijack"] == ASRTier.S
        assert tiers["direct_injection"] == ASRTier.UNKNOWN

    def test_heuristic_score_for_no_asr(self):
        groups = _make_seed_groups_with_asr()
        ranked = ASRRankBuilder.build_ranked_groups(groups)

        di = next(g for g in ranked if g.technique_group == "direct_injection")
        assert not di.has_asr_data
        assert di.heuristic_score > 0
        assert di.effective_score == di.heuristic_score

    def test_build_fallback_chain(self):
        groups = _make_seed_groups_with_asr()
        ranked = ASRRankBuilder.build_ranked_groups(groups)
        chain = ASRRankBuilder.build_fallback_chain(ranked)

        # Should have at least 2 tiers (S and A and UNKNOWN)
        assert len(chain) >= 2
        # First tier should be S
        assert chain[0][0].tier == ASRTier.S

    def test_get_top_n(self):
        groups = _make_seed_groups_with_asr()
        ranked = ASRRankBuilder.build_ranked_groups(groups)
        top3 = ASRRankBuilder.get_top_n(ranked, n=3)
        assert len(top3) <= 3

    def test_get_top_n_min_tier(self):
        groups = _make_seed_groups_with_asr()
        ranked = ASRRankBuilder.build_ranked_groups(groups)
        top = ASRRankBuilder.get_top_n(ranked, n=10, min_tier=ASRTier.S)
        # Only S tier groups
        assert all(g.tier == ASRTier.S for g in top)

    def test_tier_summary(self):
        groups = _make_seed_groups_with_asr()
        ranked = ASRRankBuilder.build_ranked_groups(groups)
        summary = ASRRankBuilder.get_tier_summary(ranked)
        assert "S" in summary
        assert "A" in summary

    def test_empty_groups(self):
        ranked = ASRRankBuilder.build_ranked_groups([])
        assert ranked == []

    def test_convenience_functions(self):
        groups = _make_seed_groups_with_asr()
        ranked = build_ranked_groups(groups)
        chain = build_fallback_chain(ranked)
        top = get_top_n_groups(ranked, n=2)
        assert len(ranked) > 0
        assert len(chain) > 0
        assert len(top) <= 2

    def test_source_seed_groups_dedup_by_identity(self):
        """Test that SeedGroup deduplication works by identity (not hash)."""
        sg = _make_seed_group(
            seeds=[_make_seed(metadata={
                "owasp_id": "LLM01",
                "technique_group": "test_dedup",
                "attack_mode": "single_turn",
            })],
        )
        # Same SeedGroup object added twice
        ranked = ASRRankBuilder.build_ranked_groups([sg, sg])
        # Should have 1 technique group, not 2
        assert len(ranked) == 1
        # source_seed_groups should have 1 entry (deduped by id())
        assert len(ranked[0].source_seed_groups) == 1


# ============================================================
# P1-1: TieredSelectionWizard Tests
# ============================================================


class TestFallbackStrategy:
    def test_values(self):
        assert FallbackStrategy.SEQUENTIAL_ASR_DESC.value == "sequential_asr_desc"
        assert FallbackStrategy.PARALLEL.value == "parallel"
        assert FallbackStrategy.ADAPTIVE.value == "adaptive"

    def test_display_name(self):
        assert "Sequential" in FallbackStrategy.SEQUENTIAL_ASR_DESC.display_name
        assert "Parallel" in FallbackStrategy.PARALLEL.display_name


class TestSelectionPreset:
    def test_defaults(self):
        preset = SelectionPreset()
        assert preset.target_type is None
        assert preset.top_n == 3
        assert preset.fallback_strategy == FallbackStrategy.SEQUENTIAL_ASR_DESC
        assert preset.select_all is False


class TestTieredSelectionWizard:
    @pytest.mark.asyncio
    async def test_auto_select_all(self):
        """Test full auto mode (enabled=False, no preset target)."""
        groups = _make_seed_groups_with_asr()
        wizard = TieredSelectionWizard(enabled=False)
        result = await wizard.select(groups)

        assert len(result.selected_groups) == len(groups)
        assert result.fallback_strategy == FallbackStrategy.SEQUENTIAL_ASR_DESC
        assert result.target_profile.target_type == TargetType.FULL_SWEEP

    @pytest.mark.asyncio
    async def test_preset_select_agent(self):
        """Test preset mode with Agent target."""
        groups = _make_seed_groups_with_asr()
        preset = SelectionPreset(target_type=TargetType.AGENT, top_n=1)
        wizard = TieredSelectionWizard(enabled=False, preset=preset)
        result = await wizard.select(groups)

        assert result.target_profile.target_type == TargetType.AGENT
        assert len(result.selected_groups) >= 1

    @pytest.mark.asyncio
    async def test_preset_select_full_sweep(self):
        """Test preset with full sweep."""
        groups = _make_seed_groups_with_asr()
        preset = SelectionPreset(target_type=TargetType.FULL_SWEEP, top_n=5)
        wizard = TieredSelectionWizard(enabled=False, preset=preset)
        result = await wizard.select(groups)

        assert result.target_profile.target_type == TargetType.FULL_SWEEP

    @pytest.mark.asyncio
    async def test_preset_select_all_override(self):
        """Test select_all override."""
        groups = _make_seed_groups_with_asr()
        preset = SelectionPreset(select_all=True)
        wizard = TieredSelectionWizard(enabled=True, preset=preset)
        result = await wizard.select(groups)

        assert len(result.selected_groups) == len(groups)

    @pytest.mark.asyncio
    async def test_result_has_fallback_chain(self):
        """Test that result contains fallback chain."""
        groups = _make_seed_groups_with_asr()
        wizard = TieredSelectionWizard(enabled=False)
        result = await wizard.select(groups)

        assert len(result.fallback_chain) > 0
        assert len(result.ranked_groups) > 0

    @pytest.mark.asyncio
    async def test_all_chain_groups_populated(self):
        """Test that all_chain_groups is populated for tier fallback."""
        groups = _make_seed_groups_with_asr()
        preset = SelectionPreset(target_type=TargetType.LLM_DIRECT, top_n=1)
        wizard = TieredSelectionWizard(enabled=False, preset=preset)
        result = await wizard.select(groups)

        # all_chain_groups should contain ALL groups in the chain
        assert len(result.all_chain_groups) >= len(result.selected_groups)
        # With SEQUENTIAL strategy, planning_groups should be all_chain_groups
        assert result.fallback_strategy == FallbackStrategy.SEQUENTIAL_ASR_DESC
        assert len(result.planning_groups) == len(result.all_chain_groups)

    @pytest.mark.asyncio
    async def test_planning_groups_parallel_strategy(self):
        """Test that planning_groups = selected_groups for PARALLEL strategy."""
        groups = _make_seed_groups_with_asr()
        preset = SelectionPreset(
            target_type=TargetType.LLM_DIRECT,
            top_n=1,
            fallback_strategy=FallbackStrategy.PARALLEL,
        )
        wizard = TieredSelectionWizard(enabled=False, preset=preset)
        result = await wizard.select(groups)

        # With PARALLEL strategy, planning_groups should be selected_groups only
        assert result.fallback_strategy == FallbackStrategy.PARALLEL
        assert len(result.planning_groups) == len(result.selected_groups)

    @pytest.mark.asyncio
    async def test_preset_select_rag_vector(self):
        """Test preset with RAG_VECTOR target type."""
        groups = _make_comprehensive_seed_groups()
        preset = SelectionPreset(target_type=TargetType.RAG_VECTOR, top_n=5)
        wizard = TieredSelectionWizard(enabled=False, preset=preset)
        result = await wizard.select(groups)

        assert result.target_profile.target_type == TargetType.RAG_VECTOR
        # Should include LLM04 and LLM08 groups
        assert len(result.selected_groups) >= 1

    @pytest.mark.asyncio
    async def test_preset_select_multimodal(self):
        """Test preset with MULTIMODAL target type (metadata-filtered)."""
        groups = _make_comprehensive_seed_groups()
        preset = SelectionPreset(target_type=TargetType.MULTIMODAL, top_n=5)
        wizard = TieredSelectionWizard(enabled=False, preset=preset)
        result = await wizard.select(groups)

        assert result.target_profile.target_type == TargetType.MULTIMODAL
        # Should only include multimodal technique groups
        assert len(result.selected_groups) >= 1
        for sg in result.selected_groups:
            has_mm = any(
                seed.metadata.get("technique_group", "").startswith("multimodal")
                for seed in sg.seeds
            )
            assert has_mm, "Non-multimodal group in MULTIMODAL selection"

    @pytest.mark.asyncio
    async def test_preset_select_defense_bypass(self):
        """Test preset with DEFENSE_BYPASS target type."""
        groups = _make_seed_groups_with_asr()
        preset = SelectionPreset(target_type=TargetType.DEFENSE_BYPASS, top_n=5)
        wizard = TieredSelectionWizard(enabled=False, preset=preset)
        result = await wizard.select(groups)

        assert result.target_profile.target_type == TargetType.DEFENSE_BYPASS
        # Should include all LLM01 groups (no prefix filter)
        assert len(result.selected_groups) >= 1

    @pytest.mark.asyncio
    async def test_preset_select_copilot(self):
        """Test preset with COPILOT target type."""
        groups = _make_comprehensive_seed_groups()
        preset = SelectionPreset(target_type=TargetType.COPILOT, top_n=5)
        wizard = TieredSelectionWizard(enabled=False, preset=preset)
        result = await wizard.select(groups)

        assert result.target_profile.target_type == TargetType.COPILOT
        # COPILOT maps to LLM01, LLM02, LLM07
        assert len(result.selected_groups) >= 1

    @pytest.mark.asyncio
    async def test_convenience_function(self):
        groups = _make_seed_groups_with_asr()
        result = await select_with_wizard(groups, enabled=False)
        assert len(result.selected_groups) > 0


# ============================================================
# P1-2: GroupFallbackExecutor Tests
# ============================================================


def _make_attack_plan(plan_id="p1", technique_group="skeleton_key", owasp_id="LLM01"):
    """Create a mock AttackPlan."""
    return AttackPlan(
        plan_id=plan_id,
        prompt_item=PromptItem(
            id=f"item_{plan_id}",
            objective="test objective",
            attack_mode=AttackMode.SINGLE_TURN,
            owasp_id=owasp_id,
            metadata={"technique_group": technique_group},
        ),
        attack_technique="prompt_sending",
        owasp_id=owasp_id,
    )


class TestGroupFallbackExecutor:
    def test_partition_plans(self):
        """Test that plans are correctly partitioned by technique_group."""
        executor = GroupFallbackExecutor()

        plans = [
            _make_attack_plan("p1", "skeleton_key"),
            _make_attack_plan("p2", "skeleton_key"),
            _make_attack_plan("p3", "crescendo"),
            _make_attack_plan("p4", "direct_injection"),
        ]

        # Build a simple fallback chain
        groups = _make_seed_groups_with_asr()
        ranked = ASRRankBuilder.build_ranked_groups(groups)
        chain = ASRRankBuilder.build_fallback_chain(ranked)

        partitions = executor._partition_plans(plans, chain)

        assert "skeleton_key" in partitions
        assert len(partitions["skeleton_key"]) == 2
        assert "crescendo" in partitions
        assert len(partitions["crescendo"]) == 1

    def test_partition_empty_plans(self):
        executor = GroupFallbackExecutor()
        partitions = executor._partition_plans([], [])
        assert partitions == {}

    @pytest.mark.asyncio
    async def test_execute_parallel(self):
        """Test parallel execution (delegates to execute_batch_attacks)."""
        executor = GroupFallbackExecutor()

        plans = [_make_attack_plan("p1"), _make_attack_plan("p2")]

        # Mock execute_batch_attacks
        mock_result = MagicMock()
        mock_result.succeeded = 1
        mock_result.executed = 2
        mock_result.success_rate = 0.5

        with patch("src.executor.execute_batch_attacks", return_value=mock_result):
            result = await executor.execute_with_fallback(
                attack_plans=plans,
                fallback_chain=[],
                strategy=FallbackStrategy.PARALLEL,
                objective_target=MagicMock(),
                judge_target=MagicMock(),
            )

        assert result.batch_result == mock_result
        assert result.tiers_executed == ["ALL"]

    @pytest.mark.asyncio
    async def test_execute_sequential_with_empty_chain(self):
        """Test sequential execution with empty fallback chain."""
        executor = GroupFallbackExecutor()

        plans = [_make_attack_plan("p1")]

        mock_result = MagicMock()
        mock_result.succeeded = 0
        mock_result.executed = 1
        mock_result.success_rate = 0.0

        with patch("src.executor.execute_batch_attacks", return_value=mock_result):
            result = await executor.execute_with_fallback(
                attack_plans=plans,
                fallback_chain=[],
                strategy=FallbackStrategy.SEQUENTIAL_ASR_DESC,
                objective_target=MagicMock(),
                judge_target=MagicMock(),
            )

        # With empty chain, should fall through to parallel-like execution
        assert result is not None


class TestFallbackExecutionResult:
    def test_properties(self):
        mock_batch = MagicMock()
        mock_batch.succeeded = 5
        mock_batch.executed = 10
        mock_batch.success_rate = 0.5

        result = FallbackExecutionResult(
            batch_result=mock_batch,
            tiers_executed=["S", "A"],
            stopped_at_tier="S",
            total_tiers_available=4,
        )

        assert result.succeeded == 5
        assert result.executed == 10
        assert result.success_rate == 0.5
        assert result.stopped_at_tier == "S"
        assert len(result.tiers_executed) == 2


# ============================================================
# Layer 2 Selection Parsing Tests
# ============================================================


def _make_tgi(
    technique_group: str,
    owasp_id: str = "LLM01",
    tier: ASRTier = ASRTier.S,
    asr: float = 0.90,
    seed_count: int = 5,
) -> TechniqueGroupInfo:
    """Create a TechniqueGroupInfo for testing."""
    sg = _make_seed_group(
        [_make_seed(value=f"seed_{technique_group}", metadata={
            "owasp_id": owasp_id,
            "technique_group": technique_group,
        })],
        owasp_id,
    )
    return TechniqueGroupInfo(
        technique_group=technique_group,
        owasp_id=owasp_id,
        seed_count=seed_count,
        max_asr=asr,
        avg_asr=asr,
        has_asr_data=asr > 0,
        tier=tier,
        heuristic_score=50.0,
        attack_modes=["single_turn"],
        difficulties=["medium"],
        severities=["high"],
        evasion_levels=["medium"],
        dataset_name="test",
        source_seed_groups=[sg],
    )


def _make_test_displayed() -> tuple:
    """Create a realistic set of displayed groups across tiers.

    Returns (all_displayed, tier_ranges) matching the wizard's layout.
    """
    # Tier S: 3 groups (ranks 1-3)
    s1 = _make_tgi("many_shot", asr=0.98, tier=ASRTier.S)
    s2 = _make_tgi("skeleton_key", asr=0.95, tier=ASRTier.S)
    s3 = _make_tgi("best_of_n", asr=0.88, tier=ASRTier.S)
    # Tier A: 2 groups (ranks 4-5)
    a1 = _make_tgi("deep_inception", asr=0.72, tier=ASRTier.A)
    a2 = _make_tgi("wrapping", asr=0.68, tier=ASRTier.A)
    # Tier B: 1 group (rank 6)
    b1 = _make_tgi("pii_anchor", asr=0.45, tier=ASRTier.B)
    # Heuristic: 2 groups (ranks 7-8)
    h1 = _make_tgi("adaptive_jb", asr=0.0, tier=ASRTier.UNKNOWN)
    h2 = _make_tgi("indirect_inj", asr=0.0, tier=ASRTier.UNKNOWN)

    all_displayed = [s1, s2, s3, a1, a2, b1, h1, h2]
    tier_ranges = {
        "S": (1, 3),
        "A": (4, 5),
        "B": (6, 6),
        "H": (7, 8),
    }
    return all_displayed, tier_ranges


class TestTryTierSelection:
    """Test _try_tier_selection parsing."""

    def test_single_tier_s(self):
        """Select all Tier S groups."""
        displayed, ranges = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        result = wizard._try_tier_selection("s", ranges, displayed)
        assert result is not None
        assert len(result) == 3  # 3 Tier S groups

    def test_single_tier_a(self):
        """Select all Tier A groups."""
        displayed, ranges = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        result = wizard._try_tier_selection("a", ranges, displayed)
        assert result is not None
        assert len(result) == 2  # 2 Tier A groups

    def test_single_tier_h(self):
        """Select all Heuristic groups."""
        displayed, ranges = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        result = wizard._try_tier_selection("h", ranges, displayed)
        assert result is not None
        assert len(result) == 2  # 2 Heuristic groups

    def test_multiple_tiers_s_a(self):
        """Select Tier S + A."""
        displayed, ranges = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        result = wizard._try_tier_selection("s,a", ranges, displayed)
        assert result is not None
        assert len(result) == 5  # 3 S + 2 A

    def test_multiple_tiers_s_a_b(self):
        """Select Tier S + A + B."""
        displayed, ranges = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        result = wizard._try_tier_selection("s,a,b", ranges, displayed)
        assert result is not None
        assert len(result) == 6  # 3 S + 2 A + 1 B

    def test_tier_range_s_b(self):
        """Select Tier S through B (S-B)."""
        displayed, ranges = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        result = wizard._try_tier_selection("s-b", ranges, displayed)
        assert result is not None
        assert len(result) == 6  # 3 S + 2 A + 1 B

    def test_tier_range_a_b(self):
        """Select Tier A through B (A-B)."""
        displayed, ranges = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        result = wizard._try_tier_selection("a-b", ranges, displayed)
        assert result is not None
        assert len(result) == 3  # 2 A + 1 B

    def test_tier_range_reversed(self):
        """Reversed range B-A should still work."""
        displayed, ranges = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        result = wizard._try_tier_selection("b-a", ranges, displayed)
        assert result is not None
        assert len(result) == 3  # 2 A + 1 B

    def test_tier_case_insensitive(self):
        """Tier selection should be case-insensitive."""
        displayed, ranges = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        result_upper = wizard._try_tier_selection("S,A", ranges, displayed)
        assert result_upper is not None
        assert len(result_upper) == 5

    def test_invalid_tier_name(self):
        """Invalid tier name returns None."""
        displayed, ranges = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        assert wizard._try_tier_selection("x", ranges, displayed) is None

    def test_number_not_tier(self):
        """Numbers should not be treated as tier selection."""
        displayed, ranges = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        assert wizard._try_tier_selection("1", ranges, displayed) is None
        assert wizard._try_tier_selection("1-3", ranges, displayed) is None

    def test_empty_string(self):
        """Empty string returns None."""
        displayed, ranges = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        assert wizard._try_tier_selection("", ranges, displayed) is None

    def test_tier_not_in_ranges(self):
        """Tier D not available in test data should return None."""
        displayed, ranges = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        # D is not in tier_ranges, so no groups selected
        result = wizard._try_tier_selection("d", ranges, displayed)
        # D is a valid tier name but not in ranges → no groups → None
        assert result is None


class TestTryNumberSelection:
    """Test _try_number_selection parsing."""

    def test_single_number(self):
        """Select group #1."""
        displayed, _ = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        result = wizard._try_number_selection("1", displayed)
        assert result is not None
        assert len(result) == 1

    def test_multiple_numbers(self):
        """Select groups #1,3,5."""
        displayed, _ = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        result = wizard._try_number_selection("1,3,5", displayed)
        assert result is not None
        assert len(result) == 3

    def test_range(self):
        """Select groups #1-3."""
        displayed, _ = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        result = wizard._try_number_selection("1-3", displayed)
        assert result is not None
        assert len(result) == 3

    def test_mixed_range_and_individual(self):
        """Select groups #1-3 plus #5 (the 1-3,5 pattern)."""
        displayed, _ = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        result = wizard._try_number_selection("1-3,5", displayed)
        assert result is not None
        assert len(result) == 4  # 1,2,3,5

    def test_mixed_range_and_individual_large(self):
        """Select groups #1-5 plus #7 (the 1-5,7 pattern)."""
        displayed, _ = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        result = wizard._try_number_selection("1-5,7", displayed)
        assert result is not None
        assert len(result) == 6  # 1,2,3,4,5,7

    def test_deduplicate(self):
        """Overlapping ranges should deduplicate."""
        displayed, _ = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        result = wizard._try_number_selection("1-3,2", displayed)
        assert result is not None
        assert len(result) == 3  # 1,2,3 (not 4)

    def test_out_of_range(self):
        """Out of range numbers are silently skipped."""
        displayed, _ = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        result = wizard._try_number_selection("1,99", displayed)
        assert result is not None
        assert len(result) == 1  # Only #1

    def test_invalid_string(self):
        """Non-numeric string returns None."""
        displayed, _ = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        assert wizard._try_number_selection("abc", displayed) is None

    def test_empty_string(self):
        """Empty string returns None."""
        displayed, _ = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        assert wizard._try_number_selection("", displayed) is None

    def test_zero_returns_none(self):
        """Zero is out of range (1-based), returns None."""
        displayed, _ = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        assert wizard._try_number_selection("0", displayed) is None


class TestParseAndExecuteSelection:
    """Test the unified _parse_and_execute_selection method."""

    def test_empty_defaults_to_top3(self):
        """Empty input selects top-3."""
        displayed, ranges = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        top_3 = displayed[:3]
        result = wizard._parse_and_execute_selection(
            "", displayed, displayed, ranges, top_3,
        )
        assert len(result) == 3

    def test_all_selects_all(self):
        """'all' selects all groups."""
        displayed, ranges = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        top_3 = displayed[:3]
        result = wizard._parse_and_execute_selection(
            "all", displayed, displayed, ranges, top_3,
        )
        assert len(result) == 8

    def test_top5(self):
        """'top-5' selects top 5."""
        displayed, ranges = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        top_3 = displayed[:3]
        result = wizard._parse_and_execute_selection(
            "top-5", displayed, displayed, ranges, top_3,
        )
        assert len(result) == 5

    def test_tier_s_selection(self):
        """'S' selects all Tier S groups."""
        displayed, ranges = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        top_3 = displayed[:3]
        result = wizard._parse_and_execute_selection(
            "S", displayed, displayed, ranges, top_3,
        )
        assert len(result) == 3

    def test_tier_s_a_selection(self):
        """'S,A' selects Tier S + A groups."""
        displayed, ranges = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        top_3 = displayed[:3]
        result = wizard._parse_and_execute_selection(
            "S,A", displayed, displayed, ranges, top_3,
        )
        assert len(result) == 5

    def test_tier_range_s_b(self):
        """'S-B' selects Tier S through B."""
        displayed, ranges = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        top_3 = displayed[:3]
        result = wizard._parse_and_execute_selection(
            "S-B", displayed, displayed, ranges, top_3,
        )
        assert len(result) == 6

    def test_number_selection(self):
        """'1,3,5' selects groups #1,3,5."""
        displayed, ranges = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        top_3 = displayed[:3]
        result = wizard._parse_and_execute_selection(
            "1,3,5", displayed, displayed, ranges, top_3,
        )
        assert len(result) == 3

    def test_mixed_number_selection(self):
        """'1-3,5' selects groups #1-3 plus #5."""
        displayed, ranges = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        top_3 = displayed[:3]
        result = wizard._parse_and_execute_selection(
            "1-3,5", displayed, displayed, ranges, top_3,
        )
        assert len(result) == 4

    def test_invalid_falls_back_to_top3(self):
        """Invalid input falls back to top-3."""
        displayed, ranges = _make_test_displayed()
        wizard = TieredSelectionWizard(enabled=False)
        top_3 = displayed[:3]
        result = wizard._parse_and_execute_selection(
            "xyz", displayed, displayed, ranges, top_3,
        )
        assert len(result) == 3
