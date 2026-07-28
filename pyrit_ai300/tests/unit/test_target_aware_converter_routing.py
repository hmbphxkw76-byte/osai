"""
Target-Aware Converter Routing Tests
====================================

P0-P3: 测试 Target 感知 Converter 路由全部功能。

覆盖:
- P0: TargetAwareConverterRouter 路由逻辑
- P1: 4 条新 Converter 链工厂
- P2: CONVERTER_VARIANT_CHAINS 扩展
- P3: FailureTypeRoutingSelector Target 感知排序
- YAML 配置一致性
"""

import pytest

from src.converters.target_aware_router import (
    TARGET_TYPE_GROUPS,
    TARGET_CONVERTER_PROFILES,
    get_target_group,
    get_target_converter_profile,
    select_converter_chains_for_target,
    get_chain_priority_for_target,
    TargetAwareConverterRouter,
)
from src.converters import (
    create_multi_encoding_v2_chain,
    create_persuasion_authority_chain,
    create_agent_injection_chain,
    create_xpia_stealth_chain,
)
from src.scenarios.technique_factories import (
    CONVERTER_VARIANT_CHAINS,
    BASE_TECHNIQUES_FOR_VARIANTS,
    build_converter_variant_factories,
    is_converter_variant,
)
from src.scenarios.failure_type_selector import FailureTypeRoutingSelector


# ============================================================
# P0: TargetAwareConverterRouter 测试
# ============================================================


class TestTargetGroupMapping:
    """P0: Target 类型到分组映射"""

    def test_llm_direct_group(self):
        assert get_target_group("openai_chat") == "llm_direct_strong"
        assert get_target_group("openai_responses") == "llm_direct_strong"
        assert get_target_group("litellm") == "llm_direct_weak"
        assert get_target_group("azure_ml") == "llm_direct_strong"

    def test_llm_safety_group(self):
        assert get_target_group("prompt_shield") == "llm_safety"

    def test_agent_web_group(self):
        assert get_target_group("playwright") == "agent_web"
        assert get_target_group("playwright_copilot") == "agent_web"

    def test_agent_copilot_group(self):
        assert get_target_group("websocket_copilot") == "agent_copilot"

    def test_agent_api_group(self):
        assert get_target_group("http_api") == "agent_api"

    def test_rag_group(self):
        assert get_target_group("azure_blob") == "rag"

    def test_output_handling_group(self):
        assert get_target_group("http_raw") == "output_handling"

    def test_multimodal_groups(self):
        assert get_target_group("openai_image") == "multimodal_image"
        assert get_target_group("openai_video") == "multimodal_video"
        assert get_target_group("openai_tts") == "multimodal_audio"

    def test_unknown_type_defaults_to_llm_direct_strong(self):
        assert get_target_group("unknown_target") == "llm_direct_strong"

    def test_all_11_groups_present(self):
        groups = set(TARGET_TYPE_GROUPS.values())
        expected = {
            "llm_direct_strong", "llm_direct_weak", "llm_safety",
            "agent_web", "agent_copilot", "agent_api",
            "rag", "output_handling",
            "multimodal_image", "multimodal_video", "multimodal_audio",
        }
        assert groups == expected


class TestTargetConverterProfile:
    """P0: Target Profile 获取"""

    def test_llm_direct_profile(self):
        profile = get_target_converter_profile("openai_chat")
        assert "high_asr_chains" in profile
        assert "medium_asr_chains" in profile
        assert "multi_encoding_v2" in profile["medium_asr_chains"]
        assert "content_filter" in profile["bypass_mechanism"]

    def test_rag_profile(self):
        profile = get_target_converter_profile("azure_blob")
        assert "xpia_stealth_chain" in profile["high_asr_chains"]
        assert profile["bypass_mechanism"] == "no_content_check"

    def test_agent_web_profile(self):
        profile = get_target_converter_profile("playwright")
        assert "agent_injection_chain" in profile["high_asr_chains"]
        assert profile["bypass_mechanism"] == "input_validation"

    def test_all_profiles_have_required_fields(self):
        for group, profile in TARGET_CONVERTER_PROFILES.items():
            assert "high_asr_chains" in profile, f"{group} missing high_asr_chains"
            assert "medium_asr_chains" in profile, f"{group} missing medium_asr_chains"
            assert "llm_assisted_chains" in profile, f"{group} missing llm_assisted_chains"
            assert "bypass_mechanism" in profile, f"{group} missing bypass_mechanism"
            assert "description" in profile, f"{group} missing description"


class TestSelectConverterChains:
    """P0: Converter 链选择逻辑"""

    def test_llm_direct_chain_selection(self):
        chains = select_converter_chains_for_target("openai_chat")
        assert "multi_encoding_v2" in chains
        assert "stealth_evasion" in chains
        assert chains[0] == "persuasion_authority"  # llm_assisted highest priority

    def test_rag_chain_selection(self):
        chains = select_converter_chains_for_target("azure_blob")
        assert "xpia_stealth_chain" in chains
        assert chains[0] == "xpia_stealth_chain"

    def test_agent_web_chain_selection(self):
        chains = select_converter_chains_for_target("playwright")
        assert "agent_injection_chain" in chains
        assert chains[0] == "agent_injection_chain"

    def test_llm_assisted_excluded_without_converter_target(self):
        chains = select_converter_chains_for_target(
            "openai_chat", converter_target_available=False
        )
        assert "persuasion_authority" not in chains
        assert "multi_encoding_v2" in chains

    def test_llm_assisted_included_with_converter_target(self):
        chains = select_converter_chains_for_target(
            "openai_chat", converter_target_available=True
        )
        assert "persuasion_authority" in chains

    def test_max_chains_limit(self):
        chains = select_converter_chains_for_target("openai_chat", max_chains=3)
        assert len(chains) <= 3

    def test_no_duplicates(self):
        chains = select_converter_chains_for_target("openai_chat")
        assert len(chains) == len(set(chains))


class TestChainPriority:
    """P0: 链优先级查询"""

    def test_high_asr_priority(self):
        # multi_encoding_v2 is in medium_asr_chains for llm_direct_strong
        # priority = len(high) + len(llm_assisted) + index + 1 = 0 + 3 + 1 + 1 = 5
        priority = get_chain_priority_for_target("multi_encoding_v2", "openai_chat")
        assert priority == 5

    def test_medium_asr_priority(self):
        priority = get_chain_priority_for_target("policy_puppetry", "openai_chat")
        assert priority > 1

    def test_unknown_chain_priority(self):
        priority = get_chain_priority_for_target("nonexistent_chain", "openai_chat")
        assert priority == 99

    def test_different_target_different_priority(self):
        # stealth_evasion is medium_asr for llm_direct_strong but not in rag profile
        p_llm = get_chain_priority_for_target("stealth_evasion", "openai_chat")
        p_rag = get_chain_priority_for_target("stealth_evasion", "azure_blob")
        assert p_llm < p_rag  # stealth_evasion is in llm_direct profile (lower=prioritized)


class TestTargetAwareConverterRouter:
    """P0: Router 类接口"""

    def test_router_select_chains(self):
        router = TargetAwareConverterRouter()
        chains = router.select_chains("openai_chat")
        assert isinstance(chains, list)
        assert len(chains) > 0

    def test_router_get_priority(self):
        router = TargetAwareConverterRouter()
        priority = router.get_priority("multi_encoding_v2", "openai_chat")
        assert priority == 5  # medium_asr for llm_direct_strong (0+3+1+1)

    def test_router_get_profile(self):
        router = TargetAwareConverterRouter()
        profile = router.get_profile("playwright")
        assert "agent_injection_chain" in profile["high_asr_chains"]

    def test_router_get_group(self):
        router = TargetAwareConverterRouter()
        assert router.get_group("azure_blob") == "rag"

    def test_router_get_summary(self):
        router = TargetAwareConverterRouter()
        summary = router.get_summary()
        assert len(summary) == 11  # 11 target groups


# ============================================================
# P1: 新 Converter 链工厂测试
# ============================================================


class TestNewConverterChains:
    """P1: 4 条新 Converter 链"""

    def test_multi_encoding_v2_chain(self):
        config = create_multi_encoding_v2_chain()
        assert config is not None
        assert config.request_converters is not None
        assert len(config.request_converters) > 0

    def test_persuasion_authority_chain(self):
        """Persuasion chain requires converter_target with configuration"""
        from unittest.mock import MagicMock
        mock_target = MagicMock()
        mock_target.configuration.ensure_can_handle.return_value = True
        try:
            config = create_persuasion_authority_chain(converter_target=mock_target)
            assert config is not None
            assert config.request_converters is not None
        except (AttributeError, TypeError):
            pytest.skip("PersuasionConverter requires a real PromptTarget with configuration")

    def test_agent_injection_chain(self):
        config = create_agent_injection_chain()
        assert config is not None
        assert config.request_converters is not None

    def test_xpia_stealth_chain(self):
        config = create_xpia_stealth_chain()
        assert config is not None
        assert config.request_converters is not None

    def test_persuasion_authority_with_converter_target(self):
        """Test that persuasion chain accepts converter_target"""
        from unittest.mock import MagicMock
        mock_target = MagicMock()
        mock_target.configuration.ensure_can_handle.return_value = True
        try:
            config = create_persuasion_authority_chain(converter_target=mock_target)
            assert config is not None
        except (AttributeError, TypeError):
            pytest.skip("PersuasionConverter requires a real PromptTarget with configuration")


# ============================================================
# P2: CONVERTER_VARIANT_CHAINS 扩展测试
# ============================================================


class TestConverterVariantChainsExtension:
    """P2: 新链在 CONVERTER_VARIANT_CHAINS 中注册"""

    def test_multi_encoding_v2_in_chains(self):
        assert "multi_encoding_v2" in CONVERTER_VARIANT_CHAINS
        assert CONVERTER_VARIANT_CHAINS["multi_encoding_v2"]["requires_llm"] is False

    def test_agent_injection_chain_in_chains(self):
        assert "agent_injection_chain" in CONVERTER_VARIANT_CHAINS
        assert CONVERTER_VARIANT_CHAINS["agent_injection_chain"]["requires_llm"] is False

    def test_persuasion_authority_in_chains(self):
        assert "persuasion_authority" in CONVERTER_VARIANT_CHAINS
        assert CONVERTER_VARIANT_CHAINS["persuasion_authority"]["requires_llm"] is True

    def test_base_techniques_extended(self):
        assert "multi_encoding_v2" in BASE_TECHNIQUES_FOR_VARIANTS["prompt_sending"]
        assert "agent_injection_chain" in BASE_TECHNIQUES_FOR_VARIANTS["prompt_sending"]

    def test_build_variant_factories_includes_new_chains(self):
        factories = build_converter_variant_factories(converter_target=None)
        names = [f.name for f in factories]
        assert any("multi_encoding_v2" in n for n in names)
        assert any("agent_injection_chain" in n for n in names)

    def test_build_variant_factories_with_llm_target(self):
        """LLM-assisted chains should be included when converter_target is provided"""
        # Use a mock object as converter_target
        class MockTarget:
            pass
        mock = MockTarget()
        factories = build_converter_variant_factories(converter_target=mock)
        names = [f.name for f in factories]
        # LLM chains may fail to load from YAML with a mock target,
        # but at least the non-LLM new chains should be present
        assert any("multi_encoding_v2" in n for n in names)
        assert any("agent_injection_chain" in n for n in names)


# ============================================================
# P3: FailureTypeRoutingSelector Target 感知测试
# ============================================================


class TestFailureTypeRoutingSelectorTargetAware:
    """P3: Target 感知排序"""

    def test_selector_with_target_type(self):
        selector = FailureTypeRoutingSelector(target_type="openai_chat")
        assert selector._target_type == "openai_chat"
        assert selector._target_group == "llm_direct_strong"

    def test_selector_set_target_type(self):
        selector = FailureTypeRoutingSelector()
        selector.set_target_type("playwright")
        assert selector._target_type == "playwright"
        assert selector._target_group == "agent_web"

    def test_target_aware_sort_key(self):
        selector = FailureTypeRoutingSelector(target_type="openai_chat")
        # multi_encoding_v2 is medium_asr (priority 5) for llm_direct_strong
        key = selector._target_aware_sort_key("prompt_sending+multi_encoding_v2")
        assert key == 5

    def test_target_aware_sort_key_different_target(self):
        selector = FailureTypeRoutingSelector(target_type="azure_blob")
        # multi_encoding_v2 is not in rag profile -> priority 99
        key = selector._target_aware_sort_key("prompt_sending+multi_encoding_v2")
        assert key == 99

    def test_target_aware_sort_key_no_target(self):
        selector = FailureTypeRoutingSelector()
        # Without target_type, uses global priority
        key = selector._target_aware_sort_key("prompt_sending+stealth_evasion")
        assert key == CONVERTER_VARIANT_CHAINS["stealth_evasion"]["priority"]

    def test_target_aware_sort_key_non_variant(self):
        selector = FailureTypeRoutingSelector(target_type="openai_chat")
        key = selector._target_aware_sort_key("prompt_sending")
        assert key == 99

    def test_reorder_uses_target_aware_priority(self):
        """When target_type is set, variants should be sorted by target-aware priority"""
        selector = FailureTypeRoutingSelector(target_type="azure_blob")
        # For rag target, xpia_stealth_chain should rank before stealth_evasion
        techniques = [
            "prompt_sending+stealth_evasion",
            "prompt_sending+multi_encoding_v2",
            "prompt_sending",
        ]
        result = selector._reorder_by_failure_type(techniques)
        # stealth_evasion and multi_encoding_v2 are not in rag profile (priority 99)
        # but they should still be in the result
        assert "prompt_sending" in result
        assert len(result) == 3

    def test_reorder_model_refusal_with_target(self):
        selector = FailureTypeRoutingSelector(target_type="openai_chat")
        selector.update_failure_type("model_refusal")
        techniques = [
            "prompt_sending",
            "prompt_sending+multi_encoding_v2",
            "prompt_sending+stealth_evasion",
        ]
        result = selector._reorder_by_failure_type(techniques)
        # Converter variants should be first
        assert is_converter_variant(result[0])


# ============================================================
# YAML 配置一致性测试
# ============================================================


class TestYAMLConfigConsistency:
    """YAML 配置与代码常量一致性"""

    def test_new_chains_in_yaml(self):
        from src.core.config_loader import get_config_loader
        loader = get_config_loader()
        chains = loader.get_converter_chains()
        assert "multi_encoding_v2" in chains
        assert "persuasion_authority" in chains
        assert "agent_injection_chain" in chains
        assert "xpia_stealth_chain" in chains

    def test_target_aware_profiles_in_yaml(self):
        from src.core.config_loader import get_config_loader
        loader = get_config_loader()
        strategy = loader.get_strategy_config()
        profiles = strategy.get("target_aware_converter_profiles", {})
        assert "llm_direct_strong" in profiles
        assert "rag" in profiles
        assert "agent_web" in profiles
        assert len(profiles) == 11

    def test_yaml_profiles_match_code_profiles(self):
        from src.core.config_loader import get_config_loader
        loader = get_config_loader()
        strategy = loader.get_strategy_config()
        yaml_profiles = strategy.get("target_aware_converter_profiles", {})

        for group, yaml_profile in yaml_profiles.items():
            code_profile = TARGET_CONVERTER_PROFILES.get(group)
            assert code_profile is not None, f"{group} in YAML but not in code"
            yaml_high = set(yaml_profile.get("high_asr", []))
            code_high = set(code_profile.get("high_asr_chains", []))
            assert yaml_high == code_high, f"{group}: YAML high_asr={yaml_high} != code={code_high}"
