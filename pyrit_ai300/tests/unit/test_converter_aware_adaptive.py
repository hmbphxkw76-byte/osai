"""
Converter-Aware Adaptive Architecture 单元测试
==============================================

覆盖 P0-P4 全部功能：
  P0: Converter 变体工厂构建 + 注册
  P1: FailureTypeRoutingSelector Converter 感知排序
  P2: AI300AdaptiveScenario Converter 变体集成
  P3: adaptive_runner 原生执行入口
  P4: 结果转换 + 向后兼容
"""

import asyncio
import unittest
from unittest.mock import MagicMock, patch, AsyncMock

from src.scenarios.technique_factories import (
    AI300_TECHNIQUE_METADATA,
    CONVERTER_VARIANT_CHAINS,
    BASE_TECHNIQUES_FOR_VARIANTS,
    build_converter_variant_factories,
    get_converter_variant_names,
    is_converter_variant,
    get_base_technique_from_variant,
    get_converter_chain_from_variant,
    register_ai300_techniques,
)
from src.scenarios.failure_type_selector import (
    FailureTypeRoutingSelector,
    extract_failure_type_from_result,
    FAILURE_MODEL_REFUSAL,
    FAILURE_TIMEOUT,
    FAILURE_OBJECTIVE_NOT_ACHIEVED,
    FAILURE_SCORER_VALIDATION_ERROR,
)
from src.scenarios.adaptive_runner import (
    run_adaptive_scenario_async,
    AdaptiveRunResult,
    _convert_native_to_batch_result,
)


# ============================================================
# P0: Converter 变体工厂构建
# ============================================================


class TestP0ConverterVariantFactories(unittest.TestCase):
    """P0: Converter 变体工厂构建测试"""

    def test_converter_variant_chains_defined(self):
        """Test CONVERTER_VARIANT_CHAINS has expected entries"""
        self.assertIn("stealth_evasion", CONVERTER_VARIANT_CHAINS)
        self.assertIn("encoding_bypass", CONVERTER_VARIANT_CHAINS)
        self.assertIn("llm_assisted", CONVERTER_VARIANT_CHAINS)

    def test_converter_variant_chain_has_priority(self):
        """Test each chain has priority field"""
        for name, info in CONVERTER_VARIANT_CHAINS.items():
            self.assertIn("priority", info, f"Chain {name} missing priority")
            self.assertIn("requires_llm", info, f"Chain {name} missing requires_llm")

    def test_base_techniques_for_variants_defined(self):
        """Test BASE_TECHNIQUES_FOR_VARIANTS has expected entries"""
        self.assertIn("prompt_sending", BASE_TECHNIQUES_FOR_VARIANTS)
        self.assertIn("many_shot", BASE_TECHNIQUES_FOR_VARIANTS)
        # Multi-turn techniques should NOT be in variants (they have adversarial chat)
        self.assertNotIn("red_teaming", BASE_TECHNIQUES_FOR_VARIANTS)
        self.assertNotIn("crescendo", BASE_TECHNIQUES_FOR_VARIANTS)

    def test_get_converter_variant_names(self):
        """Test get_converter_variant_names returns expected names"""
        names = get_converter_variant_names()
        self.assertIn("prompt_sending+stealth_evasion", names)
        self.assertIn("prompt_sending+encoding_bypass", names)
        self.assertIn("many_shot+stealth_evasion", names)

    def test_is_converter_variant(self):
        """Test is_converter_variant detects variant names"""
        self.assertTrue(is_converter_variant("prompt_sending+stealth_evasion"))
        self.assertTrue(is_converter_variant("many_shot+encoding_bypass"))
        self.assertFalse(is_converter_variant("prompt_sending"))
        self.assertFalse(is_converter_variant("red_teaming"))

    def test_get_base_technique_from_variant(self):
        """Test get_base_technique_from_variant extracts base name"""
        self.assertEqual(
            get_base_technique_from_variant("prompt_sending+stealth_evasion"),
            "prompt_sending",
        )
        self.assertEqual(
            get_base_technique_from_variant("many_shot+encoding_bypass"),
            "many_shot",
        )
        # Non-variant returns original
        self.assertEqual(get_base_technique_from_variant("red_teaming"), "red_teaming")

    def test_get_converter_chain_from_variant(self):
        """Test get_converter_chain_from_variant extracts chain name"""
        self.assertEqual(
            get_converter_chain_from_variant("prompt_sending+stealth_evasion"),
            "stealth_evasion",
        )
        self.assertEqual(
            get_converter_chain_from_variant("many_shot+encoding_bypass"),
            "encoding_bypass",
        )
        # Non-variant returns None
        self.assertIsNone(get_converter_chain_from_variant("prompt_sending"))

    def test_build_converter_variant_factories_without_llm(self):
        """Test building variant factories without converter_target (non-LLM only)"""
        factories = build_converter_variant_factories(converter_target=None)
        # Should have at least stealth_evasion and encoding_bypass variants
        names = [f.name for f in factories]
        self.assertIn("prompt_sending+stealth_evasion", names)
        self.assertIn("prompt_sending+encoding_bypass", names)
        # LLM-assisted variants should NOT be present without converter_target
        self.assertNotIn("prompt_sending+llm_assisted", names)

    def test_build_converter_variant_factories_with_llm(self):
        """Test building variant factories with converter_target (all chains)"""
        mock_target = MagicMock()
        factories = build_converter_variant_factories(converter_target=mock_target)
        names = [f.name for f in factories]
        # All variants should be present
        self.assertIn("prompt_sending+stealth_evasion", names)
        self.assertIn("prompt_sending+llm_assisted", names)

    def test_variant_factory_has_converter_config_in_kwargs(self):
        """Test variant factory has attack_converter_config baked in attack_kwargs"""
        factories = build_converter_variant_factories(converter_target=None)
        for f in factories:
            # Each variant should have attack_converter_config in its attack_kwargs
            self.assertIn("attack_converter_config", f._attack_kwargs,
                          f"Factory {f.name} missing attack_converter_config")

    def test_variant_factory_has_converter_enhanced_tag(self):
        """Test variant factory has converter_enhanced tag"""
        factories = build_converter_variant_factories(converter_target=None)
        for f in factories:
            self.assertIn("converter_enhanced", f.technique_tags,
                          f"Factory {f.name} missing converter_enhanced tag")

    def test_register_ai300_techniques_includes_variants(self):
        """Test register_ai300_techniques registers converter variants"""
        count = register_ai300_techniques(
            tags=["core"],
            reset=True,
            converter_target=None,
            include_variants=True,
        )
        self.assertGreater(count, 0)
        # Should include variant names
        from pyrit.registry import AttackTechniqueRegistry
        registry = AttackTechniqueRegistry.get_registry_singleton()
        factory_names = set(registry.get_factories().keys())
        self.assertIn("prompt_sending+stealth_evasion", factory_names)

    def test_register_ai300_techniques_without_variants(self):
        """Test register_ai300_techniques without variants"""
        count = register_ai300_techniques(
            tags=["core"],
            reset=True,
            include_variants=False,
        )
        self.assertGreater(count, 0)
        from pyrit.registry import AttackTechniqueRegistry
        registry = AttackTechniqueRegistry.get_registry_singleton()
        factory_names = set(registry.get_factories().keys())
        self.assertNotIn("prompt_sending+stealth_evasion", factory_names)


# ============================================================
# P1: FailureTypeRoutingSelector Converter 感知排序
# ============================================================


class TestP1FailureTypeRoutingConverterAware(unittest.TestCase):
    """P1: FailureTypeRoutingSelector Converter 变体感知排序测试"""

    def setUp(self):
        self.selector = FailureTypeRoutingSelector()

    def test_model_refusal_prioritizes_converter_variants(self):
        """Test model_refusal routes converter variants first"""
        self.selector.update_failure_type(FAILURE_MODEL_REFUSAL)
        techniques = [
            "red_teaming",
            "prompt_sending",
            "prompt_sending+stealth_evasion",
            "prompt_sending+encoding_bypass",
            "crescendo",
        ]
        reordered = self.selector._reorder_by_failure_type(techniques)
        # Converter variants should be first
        self.assertTrue(is_converter_variant(reordered[0]))
        self.assertTrue(is_converter_variant(reordered[1]))
        # stealth_evasion (priority=1) before encoding_bypass (priority=2)
        self.assertEqual(reordered[0], "prompt_sending+stealth_evasion")
        self.assertEqual(reordered[1], "prompt_sending+encoding_bypass")

    def test_timeout_prioritizes_base_techniques(self):
        """Test timeout routes base (non-converter) single-turn first"""
        self.selector.update_failure_type(FAILURE_TIMEOUT)
        techniques = [
            "prompt_sending+stealth_evasion",
            "red_teaming",
            "prompt_sending",
            "crescendo",
        ]
        reordered = self.selector._reorder_by_failure_type(techniques)
        # Base single-turn should be first
        self.assertEqual(reordered[0], "prompt_sending")
        # Converter variants should come after base
        self.assertTrue(is_converter_variant(reordered[1]))

    def test_objective_not_achieved_prioritizes_strong_and_converter(self):
        """Test objective_not_achieved routes strong techniques + converter variants first"""
        self.selector.update_failure_type(FAILURE_OBJECTIVE_NOT_ACHIEVED)
        techniques = [
            "prompt_sending",
            "prompt_sending+stealth_evasion",
            "red_teaming",
            "prompt_sending+encoding_bypass",
        ]
        reordered = self.selector._reorder_by_failure_type(techniques)
        # Strong techniques first
        self.assertEqual(reordered[0], "red_teaming")
        # Then converter variants
        self.assertTrue(is_converter_variant(reordered[1]))

    def test_no_failure_type_prioritizes_converter_and_encoding(self):
        """Test no failure type prioritizes converter variants + encoding"""
        self.selector._last_failure_type = None
        techniques = [
            "red_teaming",
            "prompt_sending+stealth_evasion",
            "prompt_sending",
            "base64",
        ]
        reordered = self.selector._reorder_by_failure_type(techniques)
        # Converter variants first
        self.assertEqual(reordered[0], "prompt_sending+stealth_evasion")
        # Then encoding
        self.assertEqual(reordered[1], "base64")

    def test_scorer_validation_keeps_order(self):
        """Test scorer_validation_error keeps epsilon-greedy order"""
        self.selector.update_failure_type(FAILURE_SCORER_VALIDATION_ERROR)
        techniques = ["prompt_sending", "red_teaming", "crescendo"]
        reordered = self.selector._reorder_by_failure_type(techniques)
        self.assertEqual(reordered, techniques)

    def test_converter_chain_priority_ordering(self):
        """Test converter variants are sorted by chain priority"""
        self.selector.update_failure_type(FAILURE_MODEL_REFUSAL)
        # Mix of converter variants with different priorities
        techniques = [
            "prompt_sending+llm_assisted",     # priority=3
            "prompt_sending+stealth_evasion",  # priority=1
            "prompt_sending+encoding_bypass",  # priority=2
        ]
        reordered = self.selector._reorder_by_failure_type(techniques)
        # Should be sorted by priority: stealth < encoding < llm
        self.assertEqual(reordered[0], "prompt_sending+stealth_evasion")
        self.assertEqual(reordered[1], "prompt_sending+encoding_bypass")
        self.assertEqual(reordered[2], "prompt_sending+llm_assisted")


# ============================================================
# P2: AI300AdaptiveScenario Converter 变体集成
# ============================================================


class TestP2AI300AdaptiveScenario(unittest.TestCase):
    """P2: AI300AdaptiveScenario Converter 变体集成测试"""

    def test_ai300_adaptive_scenario_exists(self):
        """Test AI300AdaptiveScenario can be imported"""
        from src.scenarios.ai300_adaptive_scenario import AI300AdaptiveScenario
        self.assertIsNotNone(AI300AdaptiveScenario)

    def test_ai300_adaptive_scenario_has_converter_target_param(self):
        """Test AI300AdaptiveScenario accepts converter_target parameter"""
        from src.scenarios.ai300_adaptive_scenario import AI300AdaptiveScenario
        import inspect
        sig = inspect.signature(AI300AdaptiveScenario.__init__)
        self.assertIn("converter_target", sig.parameters)

    def test_ai300_epsilon_greedy_selector_inherits_failure_routing(self):
        """Test AI300EpsilonGreedySelector inherits FailureTypeRoutingSelector"""
        from src.scenarios.ai300_adaptive_scenario import AI300EpsilonGreedySelector
        self.assertTrue(issubclass(AI300EpsilonGreedySelector, FailureTypeRoutingSelector))

    def test_additional_parameters_includes_per_attack_timeout(self):
        """Test additional_parameters includes per_attack_timeout"""
        from src.scenarios.ai300_adaptive_scenario import AI300AdaptiveScenario
        params = AI300AdaptiveScenario.additional_parameters()
        param_names = [p.name for p in params]
        self.assertIn("per_attack_timeout", param_names)
        self.assertIn("max_attempts_per_objective", param_names)


# ============================================================
# P3: adaptive_runner 原生执行入口
# ============================================================


class TestP3AdaptiveRunner(unittest.TestCase):
    """P3: adaptive_runner 原生执行入口测试"""

    def test_adaptive_run_result_dataclass(self):
        """Test AdaptiveRunResult dataclass fields"""
        result = AdaptiveRunResult()
        self.assertEqual(result.succeeded, 0)
        self.assertEqual(result.failed, 0)
        self.assertEqual(result.success_rate, 0.0)
        self.assertEqual(result.converter_variants_used, 0)
        self.assertEqual(result.total_techniques_tried, 0)

    def test_convert_native_to_batch_result_none(self):
        """Test _convert_native_to_batch_result with None input"""
        from src.payloads.models import BatchAttackResult
        result = _convert_native_to_batch_result(None, attack_plans=[])
        self.assertIsInstance(result, BatchAttackResult)
        self.assertEqual(result.executed, 0)

    def test_convert_native_to_batch_result_with_results(self):
        """Test _convert_native_to_batch_result with mock results"""
        mock_result = MagicMock()
        mock_attack = MagicMock()
        mock_attack.outcome.value = "SUCCESS"
        mock_result.get_display_groups.return_value = {"group1": [mock_attack]}
        result = _convert_native_to_batch_result(mock_result, attack_plans=[1, 2])
        self.assertEqual(result.executed, 1)
        self.assertEqual(result.succeeded, 1)

    def test_convert_native_to_batch_result_with_failure(self):
        """Test _convert_native_to_batch_result with failure outcome"""
        mock_result = MagicMock()
        mock_attack = MagicMock()
        mock_attack.outcome.value = "FAILURE"
        mock_result.get_display_groups.return_value = {"group1": [mock_attack]}
        result = _convert_native_to_batch_result(mock_result, attack_plans=[1])
        self.assertEqual(result.failed, 1)
        self.assertEqual(result.succeeded, 0)


# ============================================================
# P4: ScenarioResultBridge 增强
# ============================================================


class TestP4ScenarioResultBridge(unittest.TestCase):
    """P4: ScenarioResultBridge 增强测试"""

    def test_scenario_result_bridge_accepts_native_result(self):
        """Test ScenarioResultBridge accepts native_result parameter"""
        from src.scenarios.scenario_result_bridge import ScenarioResultBridge
        from src.payloads.models import BatchAttackResult
        batch = BatchAttackResult(total_plans=1, executed=1, succeeded=1, failed=0, errored=0, results=[], errors=[])
        bridge = ScenarioResultBridge(batch, native_result=MagicMock())
        self.assertIsNotNone(bridge.native_result)

    def test_scenario_result_bridge_get_summary(self):
        """Test ScenarioResultBridge.get_summary includes native result info"""
        from src.scenarios.scenario_result_bridge import ScenarioResultBridge
        from src.payloads.models import BatchAttackResult
        batch = BatchAttackResult(total_plans=1, executed=1, succeeded=1, failed=0, errored=0, results=[], errors=[])
        bridge = ScenarioResultBridge(batch, native_result=MagicMock())
        summary = bridge.get_summary()
        self.assertTrue(summary["has_native_result"])

    def test_build_memory_labels_with_owasp(self):
        """Test build_memory_labels includes OWASP ID"""
        from src.scenarios.scenario_result_bridge import build_memory_labels
        labels = build_memory_labels(owasp_id="LLM01", exam_id="exam_001")
        self.assertEqual(labels["owasp_id"], "LLM01")
        self.assertEqual(labels["exam_id"], "exam_001")


# ============================================================
# 端到端: Converter 变体 + 失败路由 集成
# ============================================================


class TestEndToEndConverterAdaptiveIntegration(unittest.TestCase):
    """端到端: Converter 变体 + 失败路由集成测试"""

    def test_converter_variants_sorted_by_priority_on_refusal(self):
        """Test full flow: converter variants sorted by priority on model_refusal"""
        selector = FailureTypeRoutingSelector()
        selector.update_failure_type(FAILURE_MODEL_REFUSAL)
        
        # Simulate techniques from registry
        techniques = [
            "prompt_sending",
            "prompt_sending+stealth_evasion",
            "prompt_sending+encoding_bypass",
            "prompt_sending+llm_assisted",
            "red_teaming",
            "crescendo",
        ]
        reordered = selector._reorder_by_failure_type(techniques)
        
        # All converter variants should come first, sorted by priority
        converter_part = [t for t in reordered if is_converter_variant(t)]
        self.assertEqual(converter_part[0], "prompt_sending+stealth_evasion")
        self.assertEqual(converter_part[1], "prompt_sending+encoding_bypass")
        self.assertEqual(converter_part[2], "prompt_sending+llm_assisted")
        
        # Non-converter techniques should come after
        non_converter = [t for t in reordered if not is_converter_variant(t)]
        self.assertIn("prompt_sending", non_converter)
        self.assertIn("red_teaming", non_converter)

    def test_timeout_routes_to_base_first(self):
        """Test timeout scenario routes to base techniques first"""
        selector = FailureTypeRoutingSelector()
        selector.update_failure_type(FAILURE_TIMEOUT)
        
        techniques = [
            "prompt_sending+stealth_evasion",
            "prompt_sending+encoding_bypass",
            "prompt_sending",
            "red_teaming",
            "crescendo",
        ]
        reordered = selector._reorder_by_failure_type(techniques)
        
        # Base single-turn should be first (no converter)
        self.assertEqual(reordered[0], "prompt_sending")
        # Converter variants should come after base
        converter_idx = [i for i, t in enumerate(reordered) if is_converter_variant(t)]
        base_idx = reordered.index("prompt_sending")
        for ci in converter_idx:
            self.assertGreater(ci, base_idx)

    def test_variant_metadata_consistency(self):
        """Test variant metadata is consistent across all variant types"""
        variant_names = get_converter_variant_names()
        for name in variant_names:
            base = get_base_technique_from_variant(name)
            chain = get_converter_chain_from_variant(name)
            
            # Base technique should exist in metadata
            self.assertIn(base, AI300_TECHNIQUE_METADATA,
                          f"Base technique {base} not in metadata for variant {name}")
            
            # Chain should exist in variant chains
            self.assertIn(chain, CONVERTER_VARIANT_CHAINS,
                          f"Chain {chain} not in variant chains for variant {name}")
            
            # Base technique should be in BASE_TECHNIQUES_FOR_VARIANTS
            self.assertIn(base, BASE_TECHNIQUES_FOR_VARIANTS,
                          f"Base technique {base} not in BASE_TECHNIQUES_FOR_VARIANTS")
            
            # Chain should be listed for this base technique
            self.assertIn(chain, BASE_TECHNIQUES_FOR_VARIANTS[base],
                          f"Chain {chain} not listed for base {base}")


# ============================================================
# P5: Abstract method implementations + Converter 展示功能
# ============================================================


class TestP5AbstractMethodsAndDisplay(unittest.TestCase):
    """P5: 抽象方法实现 + Converter 变体展示功能测试"""

    def test_atomic_attack_prefix(self):
        """Test _atomic_attack_prefix returns correct value"""
        from src.scenarios.ai300_adaptive_scenario import AI300AdaptiveScenario
        prefix = AI300AdaptiveScenario._atomic_attack_prefix()
        self.assertEqual(prefix, "ai300_adaptive")

    def test_get_technique_class(self):
        """Test get_technique_class returns AI300Technique"""
        from src.scenarios.ai300_adaptive_scenario import AI300AdaptiveScenario
        from src.scenarios.ai300_technique import AI300Technique
        tech_class = AI300AdaptiveScenario.get_technique_class()
        self.assertIs(tech_class, AI300Technique)

    def test_default_dataset_config(self):
        """Test default_dataset_config returns correct config"""
        from src.scenarios.ai300_adaptive_scenario import AI300AdaptiveScenario
        config = AI300AdaptiveScenario.default_dataset_config()
        self.assertIn("airt_hate", config.dataset_names)
        self.assertIn("airt_violence", config.dataset_names)
        self.assertIn("airt_harassment", config.dataset_names)
        self.assertEqual(config.max_dataset_size, 4)

    def test_get_converter_variants_summary(self):
        """Test get_converter_variants_summary returns correct data"""
        from src.scenarios.ai300_adaptive_scenario import AI300AdaptiveScenario
        summary = AI300AdaptiveScenario.get_converter_variants_summary()
        self.assertGreater(len(summary), 0)
        # Check first entry structure
        first = summary[0]
        self.assertIn("variant_name", first)
        self.assertIn("base_technique", first)
        self.assertIn("converter_chain", first)
        self.assertIn("description", first)
        self.assertIn("requires_llm", first)
        self.assertIn("priority", first)

    def test_converter_variants_summary_contains_expected_variants(self):
        """Test summary contains expected variant names"""
        from src.scenarios.ai300_adaptive_scenario import AI300AdaptiveScenario
        summary = AI300AdaptiveScenario.get_converter_variants_summary()
        variant_names = [v["variant_name"] for v in summary]
        self.assertIn("prompt_sending+stealth_evasion", variant_names)
        self.assertIn("prompt_sending+encoding_bypass", variant_names)
        self.assertIn("prompt_sending+llm_assisted", variant_names)

    def test_display_converter_variants_non_verbose(self):
        """Test display_converter_variants with verbose=False returns count"""
        from src.scenarios.ai300_adaptive_scenario import AI300AdaptiveScenario
        count = AI300AdaptiveScenario.display_converter_variants(verbose=False)
        self.assertGreater(count, 0)
        # Should match summary length
        summary = AI300AdaptiveScenario.get_converter_variants_summary()
        self.assertEqual(count, len(summary))

    def test_extract_converters_from_identifier_none(self):
        """Test _extract_converters_from_identifier with no converter children"""
        from src.scenarios.scenario_output import _extract_converters_from_identifier
        from unittest.mock import MagicMock

        mock_id = MagicMock()
        mock_id.children = {}
        result = _extract_converters_from_identifier(mock_id)
        self.assertEqual(result, [])

    def test_extract_converters_from_identifier_with_converters(self):
        """Test _extract_converters_from_identifier with request_converters"""
        from src.scenarios.scenario_output import _extract_converters_from_identifier
        from unittest.mock import MagicMock

        mock_conv1 = MagicMock()
        mock_conv1.class_name = "Base64Converter"
        mock_conv2 = MagicMock()
        mock_conv2.class_name = "ROT13Converter"

        mock_id = MagicMock()
        mock_id.children = {"request_converters": [mock_conv1, mock_conv2]}
        result = _extract_converters_from_identifier(mock_id)
        self.assertEqual(result, ["Base64Converter", "ROT13Converter"])

    def test_is_not_abstract(self):
        """Test AI300AdaptiveScenario is not abstract (all methods implemented)"""
        from src.scenarios.ai300_adaptive_scenario import AI300AdaptiveScenario
        from abc import ABC
        # The class should not have unimplemented abstract methods
        # (it still extends ABC via Scenario, but all abstract methods are implemented)
        abstract_methods = getattr(AI300AdaptiveScenario, "__abstractmethods__", set())
        self.assertEqual(len(abstract_methods), 0,
                         f"Unimplemented abstract methods: {abstract_methods}")


# ============================================================
# R0-R6: Target-Aware Dynamic Chain Selection + Modality Filtering
# ============================================================


class TestR0DynamicChainMapping(unittest.TestCase):
    """R0: target_type 驱动动态链选择"""

    def test_get_dynamic_chain_mapping_without_target_type(self):
        """Test _get_dynamic_chain_mapping returns None when target_type is None"""
        from src.scenarios.technique_factories import _get_dynamic_chain_mapping
        result = _get_dynamic_chain_mapping(None, converter_target_available=False)
        self.assertIsNone(result)

    def test_get_dynamic_chain_mapping_with_openai_chat(self):
        """Test _get_dynamic_chain_mapping returns dynamic mapping for openai_chat"""
        from src.scenarios.technique_factories import _get_dynamic_chain_mapping
        result = _get_dynamic_chain_mapping("openai_chat", converter_target_available=False)
        self.assertIsNotNone(result)
        # prompt_sending should be in the mapping
        self.assertIn("prompt_sending", result)
        # Chains should be from the recommended list for llm_direct
        recommended = ["multi_encoding_v2", "stealth_evasion", "encoding_bypass",
                       "policy_puppetry", "noise_case_chain", "unicode_attack"]
        for chain in result["prompt_sending"]:
            self.assertIn(chain, recommended + ["llm_assisted", "persuasion_authority",
                                                "decomposition_chain", "task_framing_chain"])

    def test_get_dynamic_chain_mapping_with_rag_target(self):
        """Test _get_dynamic_chain_mapping for RAG target returns xpia/file chains"""
        from src.scenarios.technique_factories import _get_dynamic_chain_mapping
        result = _get_dynamic_chain_mapping("azure_blob", converter_target_available=False)
        self.assertIsNotNone(result)
        # RAG recommended chains include xpia_stealth_chain
        all_chains = []
        for chains in result.values():
            all_chains.extend(chains)
        # xpia_stealth_chain should be present for RAG
        self.assertIn("xpia_stealth_chain", all_chains)

    def test_build_converter_variant_factories_with_target_type(self):
        """Test build_converter_variant_factories accepts target_type parameter"""
        from src.scenarios.technique_factories import build_converter_variant_factories
        factories = build_converter_variant_factories(
            converter_target=None,
            target_type="openai_chat",
            objective_target=None,
        )
        names = [f.name for f in factories]
        # Should have variants from llm_direct recommended chains
        self.assertTrue(any("stealth_evasion" in n for n in names))
        self.assertTrue(any("encoding_bypass" in n for n in names))


class TestR1ConverterVariantChainsFullCoverage(unittest.TestCase):
    """R1: CONVERTER_VARIANT_CHAINS 全覆盖"""

    def test_converter_variant_chains_count(self):
        """Test CONVERTER_VARIANT_CHAINS has at least 22 entries"""
        self.assertGreaterEqual(len(CONVERTER_VARIANT_CHAINS), 22)

    def test_all_chains_have_modality_field(self):
        """Test every chain has a modality field"""
        for name, info in CONVERTER_VARIANT_CHAINS.items():
            self.assertIn("modality", info, f"Chain {name} missing modality field")
            self.assertIn(info["modality"], ["text", "image", "file"],
                          f"Chain {name} has invalid modality: {info['modality']}")

    def test_new_chains_present(self):
        """Test newly added chains (R1) are present"""
        new_chains = [
            "policy_puppetry", "unicode_attack", "random_case",
            "format_injection", "text_jailbreak",
            "xpia_stealth_chain", "pdf_injection", "worddoc_injection",
            "multimodal_image_attack", "multimodal_steganography",
            "decomposition_chain", "decomposition_policy_chain",
            "policy_puppetry_chain", "task_framing_chain", "noise_case_chain",
        ]
        for chain in new_chains:
            self.assertIn(chain, CONVERTER_VARIANT_CHAINS,
                          f"Chain {chain} not in CONVERTER_VARIANT_CHAINS")

    def test_runtime_params_chains_marked(self):
        """Test chains requiring runtime params are marked"""
        self.assertTrue(CONVERTER_VARIANT_CHAINS["pdf_injection"].get("requires_runtime_params"))
        self.assertTrue(CONVERTER_VARIANT_CHAINS["worddoc_injection"].get("requires_runtime_params"))
        self.assertTrue(CONVERTER_VARIANT_CHAINS["multimodal_steganography"].get("requires_runtime_params"))
        # Chains without runtime params should not have this flag
        self.assertFalse(CONVERTER_VARIANT_CHAINS["stealth_evasion"].get("requires_runtime_params", False))


class TestR2ModalityCompatibility(unittest.TestCase):
    """R2: ModalityRouter 能力检测"""

    def test_is_chain_modality_compatible_text(self):
        """Test text modality chains are always compatible"""
        from src.scenarios.technique_factories import _is_chain_modality_compatible
        mock_target = MagicMock()
        result = _is_chain_modality_compatible(
            chain_name="stealth_evasion",
            chain_info={"modality": "text"},
            objective_target=mock_target,
            target_type="openai_chat",
        )
        self.assertTrue(result)

    def test_is_chain_modality_compatible_image_with_multimodal_group(self):
        """Test image modality chains are compatible with multimodal target group"""
        from src.scenarios.technique_factories import _is_chain_modality_compatible
        mock_target = MagicMock()
        result = _is_chain_modality_compatible(
            chain_name="multimodal_image_attack",
            chain_info={"modality": "image"},
            objective_target=mock_target,
            target_type="openai_image",
        )
        self.assertTrue(result)

    def test_is_chain_modality_compatible_file_with_rag_group(self):
        """Test file modality chains are compatible with RAG target group"""
        from src.scenarios.technique_factories import _is_chain_modality_compatible
        mock_target = MagicMock()
        result = _is_chain_modality_compatible(
            chain_name="xpia_stealth_chain",
            chain_info={"modality": "file"},
            objective_target=mock_target,
            target_type="azure_blob",
        )
        self.assertTrue(result)

    def test_build_variant_factories_skips_runtime_params_chains(self):
        """Test build_converter_variant_factories skips requires_runtime_params chains"""
        from src.scenarios.technique_factories import build_converter_variant_factories
        factories = build_converter_variant_factories(
            converter_target=None,
            target_type=None,
            objective_target=None,
        )
        names = [f.name for f in factories]
        # pdf_injection and worddoc_injection require runtime params, should be skipped
        self.assertFalse(any("pdf_injection" in n for n in names))
        self.assertFalse(any("worddoc_injection" in n for n in names))


class TestR3YamlDrivenProfiles(unittest.TestCase):
    """R3: target_aware_router.py 从 YAML 读取 Profile"""

    def test_target_type_groups_is_lazy_dict(self):
        """Test TARGET_TYPE_GROUPS is loaded from YAML (lazy)"""
        from src.converters.target_aware_router import TARGET_TYPE_GROUPS
        # Should contain openai_chat mapping
        self.assertEqual(TARGET_TYPE_GROUPS["openai_chat"], "llm_direct")
        self.assertEqual(TARGET_TYPE_GROUPS["playwright"], "agent_web")
        self.assertEqual(TARGET_TYPE_GROUPS["azure_blob"], "rag")

    def test_target_converter_profiles_is_lazy_dict(self):
        """Test TARGET_CONVERTER_PROFILES is loaded from YAML (lazy)"""
        from src.converters.target_aware_router import TARGET_CONVERTER_PROFILES
        # Should contain llm_direct profile
        profile = TARGET_CONVERTER_PROFILES["llm_direct"]
        self.assertIn("high_asr_chains", profile)
        self.assertIn("multi_encoding_v2", profile["high_asr_chains"])

    def test_config_loader_has_target_aware_methods(self):
        """Test ConfigLoader has get_target_aware_converter_profiles method"""
        from src.core.config_loader import get_config_loader
        config = get_config_loader()
        profiles = config.get_target_aware_converter_profiles()
        self.assertGreater(len(profiles), 0)
        self.assertIn("llm_direct", profiles)
        # YAML uses high_asr (not high_asr_chains)
        self.assertIn("high_asr", profiles["llm_direct"])

    def test_config_loader_get_target_aware_profile(self):
        """Test ConfigLoader.get_target_aware_profile returns specific profile"""
        from src.core.config_loader import get_config_loader
        config = get_config_loader()
        profile = config.get_target_aware_profile("agent_web")
        self.assertIsNotNone(profile)
        self.assertIn("high_asr", profile)

    def test_profile_data_matches_between_yaml_and_python(self):
        """Test YAML-loaded profiles match fallback constants"""
        from src.converters.target_aware_router import (
            TARGET_CONVERTER_PROFILES,
            _FALLBACK_TARGET_CONVERTER_PROFILES,
        )
        # llm_direct high_asr_chains should match
        yaml_chains = TARGET_CONVERTER_PROFILES["llm_direct"]["high_asr_chains"]
        fallback_chains = _FALLBACK_TARGET_CONVERTER_PROFILES["llm_direct"]["high_asr_chains"]
        self.assertEqual(yaml_chains, fallback_chains)


class TestR4R6DynamicChainSelection(unittest.TestCase):
    """R4+R6: 动态链组合 + 模态验证"""

    def test_select_dynamic_converter_chains_exists(self):
        """Test select_dynamic_converter_chains function exists"""
        from src.converters.target_aware_router import select_dynamic_converter_chains
        self.assertTrue(callable(select_dynamic_converter_chains))

    def test_select_dynamic_converter_chains_without_target(self):
        """Test select_dynamic_converter_chains without objective_target returns same as select_converter_chains_for_target"""
        from src.converters.target_aware_router import (
            select_dynamic_converter_chains,
            select_converter_chains_for_target,
        )
        chains_dynamic = select_dynamic_converter_chains("openai_chat", objective_target=None, max_chains=8)
        chains_static = select_converter_chains_for_target("openai_chat", max_chains=8)
        self.assertEqual(chains_dynamic, chains_static)

    def test_select_dynamic_converter_chains_with_text_target(self):
        """Test dynamic chains for text-only target don't filter text chains"""
        from src.converters.target_aware_router import select_dynamic_converter_chains
        mock_target = MagicMock()
        chains = select_dynamic_converter_chains(
            "openai_chat",
            objective_target=mock_target,
            converter_target_available=False,
        )
        # Text chains should still be present
        self.assertIn("stealth_evasion", chains)
        self.assertIn("encoding_bypass", chains)

    def test_target_aware_router_has_select_dynamic_chains(self):
        """Test TargetAwareConverterRouter has select_dynamic_chains method"""
        from src.converters.target_aware_router import TargetAwareConverterRouter
        router = TargetAwareConverterRouter()
        self.assertTrue(hasattr(router, "select_dynamic_chains"))
        self.assertTrue(callable(router.select_dynamic_chains))

    def test_select_dynamic_chains_returns_list(self):
        """Test select_dynamic_chains returns a list"""
        from src.converters.target_aware_router import TargetAwareConverterRouter
        router = TargetAwareConverterRouter()
        chains = router.select_dynamic_chains("openai_chat", objective_target=None)
        self.assertIsInstance(chains, list)
        self.assertGreater(len(chains), 0)


class TestRegisterWithTargetType(unittest.TestCase):
    """register_ai300_techniques 支持 target_type + objective_target"""

    def test_register_accepts_target_type(self):
        """Test register_ai300_techniques accepts target_type parameter"""
        count = register_ai300_techniques(
            tags=["core"],
            reset=True,
            converter_target=None,
            include_variants=True,
            target_type="openai_chat",
            objective_target=None,
        )
        self.assertGreater(count, 0)
        from pyrit.registry import AttackTechniqueRegistry
        registry = AttackTechniqueRegistry.get_registry_singleton()
        factory_names = set(registry.get_factories().keys())
        # Should include variant names from llm_direct recommended chains
        self.assertIn("prompt_sending+stealth_evasion", factory_names)

    def test_register_with_rag_target_type(self):
        """Test register with RAG target produces file-modality-aware variant set"""
        count = register_ai300_techniques(
            tags=["core"],
            reset=True,
            converter_target=None,
            include_variants=True,
            target_type="azure_blob",
            objective_target=None,
        )
        self.assertGreater(count, 0)
        from pyrit.registry import AttackTechniqueRegistry
        registry = AttackTechniqueRegistry.get_registry_singleton()
        factory_names = set(registry.get_factories().keys())
        # RAG target's recommended chains include xpia_stealth_chain and pdf_injection,
        # but both require_runtime_params, so they're skipped at build time.
        # The dynamic mapping intersects recommended chains with BASE_TECHNIQUES_FOR_VARIANTS,
        # so text chains like stealth_evasion (in BASE list) that are also in rag profile
        # should appear. RAG profile medium_asr includes text_jailbreak (also skipped).
        # Verify that at least some variants were created for the RAG target
        variant_names = [n for n in factory_names if "+" in n]
        self.assertGreater(len(variant_names), 0,
                           f"Expected converter variants for RAG target, got: {sorted(factory_names)[:20]}")

    def test_technique_initializer_supports_target_type(self):
        """Test AI300TechniqueInitializer supports target_type parameter"""
        from src.scenarios.technique_initializer import AI300TechniqueInitializer
        init = AI300TechniqueInitializer()
        self.assertIn("target_type", init.supported_parameters)
        self.assertIn("objective_target", init.supported_parameters)


class TestExportCompleteness(unittest.TestCase):
    """验证 __init__.py 导出完整性"""

    def test_converters_init_exports_select_dynamic(self):
        """Test converters __init__ exports select_dynamic_converter_chains"""
        from src.converters import select_dynamic_converter_chains
        self.assertTrue(callable(select_dynamic_converter_chains))

    def test_scenarios_init_exports_helper_functions(self):
        """Test scenarios __init__ exports R0/R2 helper functions"""
        from src.scenarios import _is_chain_modality_compatible, _get_dynamic_chain_mapping
        self.assertTrue(callable(_is_chain_modality_compatible))
        self.assertTrue(callable(_get_dynamic_chain_mapping))


if __name__ == "__main__":
    unittest.main()
