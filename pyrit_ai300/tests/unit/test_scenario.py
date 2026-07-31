"""
AI-300 Scenario 子系统单元测试
================================

覆盖 P0-P4 全部功能：
  P0: Scenario 基类 + BASELINE_ATTACK_POLICY + _build_atomic_attacks_async
  P1: AttackTechniqueFactory + Registry + TechniqueInitializer + ScenarioTechnique 枚举
  P2: AdaptiveScenario + EpsilonGreedyTechniqueSelector + max_attempts_per_objective
  P3: Parameter 声明式参数化 + additional_parameters + supported_parameters
  P4: ScenarioResultBridge + output_scenario_async + Per-Group Breakdown
"""

import asyncio
import unittest
from unittest.mock import MagicMock

from src.scenarios import (
    AI300Scenario,
    AI300RapidResponseScenario,
    AI300JailbreakScenario,
    AI300EncodingScenario,
    AI300Technique,
    AI300EncodingTechnique,
    AI300AdaptiveScenario,
    AI300EpsilonGreedySelector,
    FailureTypeRoutingSelector,
    extract_failure_type_from_result,
    get_core_technique_factories,
    get_extra_technique_factories,
    get_airt_technique_factories,
    get_all_technique_factories,
    register_ai300_techniques,
    AI300_TECHNIQUE_METADATA,
    AI300TechniqueInitializer,
    initialize_techniques_async,
    output_scenario_async,
    output_scenario_summary,
    sort_results_by_success_rate,
    get_per_group_breakdown,
    ScenarioResultBridge,
    batch_result_to_scenario_result,
    build_memory_labels,
)
from src.payloads.models import BatchAttackResult


# ============================================================
# P0: Scenario 基类测试
# ============================================================


class TestP0ScenarioBase(unittest.TestCase):
    """P0: Scenario 基类体系测试"""

    def test_ai300_technique_enum_members(self):
        """Test AI300Technique has required members"""
        members = [m for m in AI300Technique if not m.name.startswith("_")]
        self.assertGreater(len(members), 20, "AI300Technique should have 20+ members")

    def test_ai300_technique_has_all_aggregate(self):
        """Test ALL aggregate member exists"""
        self.assertTrue(hasattr(AI300Technique, "ALL"))
        self.assertTrue(hasattr(AI300Technique, "DEFAULT"))
        self.assertTrue(hasattr(AI300Technique, "SINGLE_TURN"))
        self.assertTrue(hasattr(AI300Technique, "MULTI_TURN"))

    def test_ai300_technique_default(self):
        """Test default() returns DEFAULT"""
        default = AI300Technique.default()
        self.assertEqual(default, AI300Technique.DEFAULT)

    def test_ai300_scenario_baseline_policy(self):
        """Test BASELINE_ATTACK_POLICY is Enabled for AI300Scenario"""
        from pyrit.scenario import BaselineAttackPolicy
        self.assertEqual(
            AI300Scenario.BASELINE_ATTACK_POLICY,
            BaselineAttackPolicy.Enabled,
        )

    def test_jailbreak_scenario_baseline_disabled(self):
        """Test Jailbreak scenario has Disabled baseline policy"""
        from pyrit.scenario import BaselineAttackPolicy
        self.assertEqual(
            AI300JailbreakScenario.BASELINE_ATTACK_POLICY,
            BaselineAttackPolicy.Disabled,
        )

    def test_encoding_scenario_has_encoding_technique(self):
        """Test EncodingScenario exists and has correct technique class"""
        self.assertTrue(hasattr(AI300EncodingScenario, "VERSION"))

    def test_ai300_technique_tags(self):
        """Test technique tags are set correctly"""
        rot13 = AI300Technique.ROT13
        self.assertIn("encoding", rot13._tags)
        self.assertIn("single_turn", rot13._tags)

        role_play = AI300Technique.ROLE_PLAY_MOVIE_SCRIPT
        self.assertIn("single_turn", role_play._tags)
        self.assertIn("light", role_play._tags)

        red_teaming = AI300Technique.RED_TEAMING
        self.assertIn("multi_turn", red_teaming._tags)

    def test_ai300_encoding_technique_enum(self):
        """Test AI300EncodingTechnique has encoding-specific members"""
        self.assertTrue(hasattr(AI300EncodingTechnique, "ROT13"))
        self.assertTrue(hasattr(AI300EncodingTechnique, "BASE64"))
        self.assertTrue(hasattr(AI300EncodingTechnique, "CAESAR"))
        self.assertTrue(hasattr(AI300EncodingTechnique, "ALL"))

    def test_rapid_response_scenario_exists(self):
        """Test AI300RapidResponseScenario exists"""
        self.assertIsNotNone(AI300RapidResponseScenario)
        self.assertTrue(issubclass(AI300RapidResponseScenario, AI300Scenario))


# ============================================================
# P1: Technique 注册与发现测试
# ============================================================


class TestP1TechniqueRegistry(unittest.TestCase):
    """P1: Technique 注册与发现测试"""

    def test_technique_metadata_completeness(self):
        """Test AI300_TECHNIQUE_METADATA has all expected techniques"""
        expected = [
            "prompt_sending", "rot13", "base64", "caesar", "binary",
            "role_play_movie_script", "red_teaming", "crescendo", "tap",
            "pair", "many_shot", "skeleton_key",
        ]
        for name in expected:
            self.assertIn(name, AI300_TECHNIQUE_METADATA, f"Missing technique: {name}")

    def test_core_factories_not_empty(self):
        """Test core technique factories list is not empty"""
        factories = get_core_technique_factories()
        self.assertGreater(len(factories), 10, "Should have 10+ core factories")

    def test_extra_factories_content(self):
        """Test extra factories contain pair and skeleton_key"""
        factories = get_extra_technique_factories()
        names = [f.name for f in factories]
        self.assertIn("pair", names)
        self.assertIn("skeleton_key", names)

    def test_all_factories_is_core_plus_extra(self):
        """Test all factories = core + extra + airt"""
        all_f = get_all_technique_factories()
        core_f = get_core_technique_factories()
        extra_f = get_extra_technique_factories()
        airt_f = get_airt_technique_factories()
        self.assertEqual(len(all_f), len(core_f) + len(extra_f) + len(airt_f))

    def test_factory_names_unique(self):
        """Test all factory names are unique"""
        all_f = get_all_technique_factories()
        names = [f.name for f in all_f]
        self.assertEqual(len(names), len(set(names)), "Duplicate factory names found")

    def test_register_techniques_idempotent(self):
        """Test technique registration is idempotent"""
        n1 = register_ai300_techniques(tags=["core"], reset=True)
        n2 = register_ai300_techniques(tags=["core"])
        self.assertGreater(n1, 0, "First registration should add techniques")
        self.assertEqual(n2, 0, "Second registration should add 0 (idempotent)")

    def test_register_all_tags(self):
        """Test registering with 'all' tags"""
        n = register_ai300_techniques(tags=["all"], reset=True)
        self.assertGreater(n, 20, "Should register 20+ techniques with 'all' tags")

    def test_technique_metadata_fields(self):
        """Test metadata has required fields"""
        for name, meta in AI300_TECHNIQUE_METADATA.items():
            self.assertIn("attack_class", meta, f"{name} missing attack_class")
            self.assertIn("tags", meta, f"{name} missing tags")
            self.assertIn("description", meta, f"{name} missing description")
            self.assertIn("uses_adversarial", meta, f"{name} missing uses_adversarial")
            self.assertIn("category", meta, f"{name} missing category")


class TestP1TechniqueInitializer(unittest.TestCase):
    """P1: TechniqueInitializer 测试"""

    def test_initializer_default_tags(self):
        """Test default tags is ['core']"""
        init = AI300TechniqueInitializer()
        self.assertEqual(init.tags, ["core"])

    def test_initializer_set_tags(self):
        """Test set_params_from_args sets tags"""
        init = AI300TechniqueInitializer()
        init.set_params_from_args(args={"tags": ["all"]})
        self.assertEqual(init.tags, ["all"])

    def test_initializer_supported_parameters(self):
        """Test supported_parameters includes tags"""
        init = AI300TechniqueInitializer()
        self.assertIn("tags", init.supported_parameters)

    def test_initialize_techniques_async(self):
        """Test initialize_techniques_async function"""
        n = asyncio.run(initialize_techniques_async(tags=["all"], reset=True))
        self.assertGreater(n, 0)


# ============================================================
# P2: Adaptive Scenario 测试
# ============================================================


class TestP2AdaptiveScenario(unittest.TestCase):
    """P2: Adaptive Scenario 集成测试"""

    def test_adaptive_scenario_exists(self):
        """Test AI300AdaptiveScenario exists"""
        self.assertIsNotNone(AI300AdaptiveScenario)

    def test_adaptive_scenario_is_subclass(self):
        """Test AI300AdaptiveScenario is subclass of AdaptiveScenario"""
        from pyrit.scenario.scenarios.adaptive import AdaptiveScenario
        self.assertTrue(issubclass(AI300AdaptiveScenario, AdaptiveScenario))

    def test_epsilon_greedy_selector_exists(self):
        """Test AI300EpsilonGreedySelector exists"""
        self.assertIsNotNone(AI300EpsilonGreedySelector)

    def test_epsilon_greedy_selector_is_subclass(self):
        """Test AI300EpsilonGreedySelector is subclass of EpsilonGreedyTechniqueSelector"""
        from pyrit.scenario.scenarios.adaptive import EpsilonGreedyTechniqueSelector
        self.assertTrue(issubclass(AI300EpsilonGreedySelector, EpsilonGreedyTechniqueSelector))

    def test_epsilon_greedy_default_epsilon(self):
        """Test default epsilon is 0.2"""
        selector = AI300EpsilonGreedySelector()
        self.assertEqual(selector._epsilon, 0.2)

    def test_adaptive_scenario_additional_parameters(self):
        """Test adaptive scenario declares max_attempts_per_objective"""
        params = AI300AdaptiveScenario.supported_parameters()
        param_names = [p.name for p in params]
        self.assertIn("max_attempts_per_objective", param_names)

    def test_adaptive_scenario_max_attempts_default(self):
        """Test max_attempts_per_objective default is 3"""
        params = AI300AdaptiveScenario.supported_parameters()
        max_attempts_param = next(
            p for p in params if p.name == "max_attempts_per_objective"
        )
        self.assertEqual(max_attempts_param.default, 3)


# ============================================================
# P3: Parameter 声明式参数化测试
# ============================================================


class TestP3Parameters(unittest.TestCase):
    """P3: Parameter 声明式参数化测试"""

    def test_ai300_scenario_has_additional_parameters(self):
        """Test AI300Scenario has additional_parameters"""
        params = AI300Scenario.additional_parameters()
        self.assertGreater(len(params), 0)

    def test_ai300_scenario_params_include_max_turns(self):
        """Test max_turns parameter is declared"""
        params = AI300Scenario.supported_parameters()
        param_names = [p.name for p in params]
        self.assertIn("max_turns", param_names)

    def test_ai300_scenario_params_include_per_attack_timeout(self):
        """Test per_attack_timeout parameter is declared"""
        params = AI300Scenario.supported_parameters()
        param_names = [p.name for p in params]
        self.assertIn("per_attack_timeout", param_names)

    def test_common_parameters_present(self):
        """Test common parameters are present in supported_parameters"""
        params = AI300Scenario.supported_parameters()
        param_names = [p.name for p in params]
        expected_common = [
            "objective_target", "scenario_techniques", "dataset_config",
            "max_concurrency", "max_retries", "include_baseline",
        ]
        for name in expected_common:
            self.assertIn(name, param_names, f"Missing common parameter: {name}")

    def test_max_turns_default_is_3(self):
        """Test max_turns default value is 3 (P3: reduced from 5 to minimize timeout risk)"""
        params = AI300Scenario.supported_parameters()
        max_turns_param = next(p for p in params if p.name == "max_turns")
        self.assertEqual(max_turns_param.default, 3)

    def test_per_attack_timeout_default(self):
        """Test per_attack_timeout default value is 300"""
        params = AI300Scenario.supported_parameters()
        timeout_param = next(p for p in params if p.name == "per_attack_timeout")
        self.assertEqual(timeout_param.default, 300)


# ============================================================
# P4: 结果标准化与弹性恢复测试
# ============================================================


class TestP4ScenarioResultBridge(unittest.TestCase):
    """P4: ScenarioResultBridge 测试"""

    def _create_mock_batch_result(self, total=10, success=7, failed=3, errored=0):
        """Create a mock BatchAttackResult"""
        br = BatchAttackResult(total_plans=total)
        br.executed = total
        br.succeeded = success
        br.failed = failed
        br.errored = errored
        br.results = []
        br.errors = []
        return br

    def test_bridge_creation(self):
        """Test ScenarioResultBridge can be created from BatchAttackResult"""
        br = self._create_mock_batch_result()
        bridge = ScenarioResultBridge(br)
        self.assertIsNotNone(bridge)

    def test_bridge_batch_result_to_scenario_result(self):
        """Test batch_result_to_scenario_result function"""
        br = self._create_mock_batch_result()
        bridge = batch_result_to_scenario_result(br)
        self.assertIsInstance(bridge, ScenarioResultBridge)

    def test_bridge_success_rate(self):
        """Test success rate calculation"""
        br = self._create_mock_batch_result(total=10, success=7, failed=3)
        bridge = ScenarioResultBridge(br)
        self.assertAlmostEqual(bridge.objective_achieved_rate(), 0.7)

    def test_bridge_summary(self):
        """Test get_summary returns correct fields"""
        br = self._create_mock_batch_result()
        bridge = ScenarioResultBridge(br)
        summary = bridge.get_summary()
        self.assertIn("scenario_name", summary)
        self.assertIn("total_attacks", summary)
        self.assertIn("successful_attacks", summary)
        self.assertIn("success_rate", summary)

    def test_bridge_per_group_stats(self):
        """Test get_per_group_stats"""
        br = self._create_mock_batch_result()
        bridge = ScenarioResultBridge(br)
        stats = bridge.get_per_group_stats()
        self.assertIsInstance(stats, list)

    def test_bridge_upgrade_stats(self):
        """Test get_upgrade_stats"""
        br = self._create_mock_batch_result()
        br.upgrade_attempts = 3
        br.upgrade_success = 2
        bridge = ScenarioResultBridge(br)
        stats = bridge.get_upgrade_stats()
        self.assertEqual(stats["upgrade_attempts"], 3)
        self.assertEqual(stats["upgrade_success"], 2)

    def test_bridge_zero_results(self):
        """Test bridge with zero results"""
        br = self._create_mock_batch_result(total=0, success=0, failed=0)
        bridge = ScenarioResultBridge(br)
        self.assertEqual(bridge.objective_achieved_rate(), 0.0)
        self.assertEqual(bridge.total_attacks, 0)


class TestP4ScenarioOutput(unittest.TestCase):
    """P4: Scenario 输出函数测试"""

    def _create_mock_batch_result(self, total=10, success=7, failed=3):
        br = BatchAttackResult(total_plans=total)
        br.executed = total
        br.succeeded = success
        br.failed = failed
        br.results = []
        br.errors = []
        return br

    def test_output_scenario_summary(self):
        """Test output_scenario_summary function"""
        br = self._create_mock_batch_result()
        summary = output_scenario_summary(br)
        self.assertIsInstance(summary, dict)
        self.assertEqual(summary["total_attacks"], 10)

    def test_get_per_group_breakdown(self):
        """Test get_per_group_breakdown function"""
        br = self._create_mock_batch_result()
        breakdown = get_per_group_breakdown(br)
        self.assertIsInstance(breakdown, list)

    def test_sort_results_by_success_rate(self):
        """Test sort_results_by_success_rate function"""
        results = [
            {"group": "a", "success_rate": 0.5},
            {"group": "b", "success_rate": 1.0},
            {"group": "c", "success_rate": 0.0},
        ]
        sorted_results = sort_results_by_success_rate(results)
        self.assertEqual(sorted_results[0]["success_rate"], 1.0)
        self.assertEqual(sorted_results[-1]["success_rate"], 0.0)

    def test_sort_results_ascending(self):
        """Test sort_results ascending"""
        results = [
            {"success_rate": 0.5},
            {"success_rate": 1.0},
            {"success_rate": 0.0},
        ]
        sorted_results = sort_results_by_success_rate(results, ascending=True)
        self.assertEqual(sorted_results[0]["success_rate"], 0.0)
        self.assertEqual(sorted_results[-1]["success_rate"], 1.0)

    def test_output_scenario_async_terminal(self):
        """Test output_scenario_async with bridge fallback returns string"""
        br = self._create_mock_batch_result()
        output = asyncio.run(output_scenario_async(br, to_terminal=False))
        self.assertIsInstance(output, str)


# ============================================================
# 集成测试
# ============================================================


class TestScenarioIntegration(unittest.TestCase):
    """集成测试：Scenario 子系统与其他模块的协作"""

    def test_scenario_module_accessible_from_src(self):
        """Test scenarios module is importable from src"""
        import src.scenarios
        self.assertTrue(hasattr(src.scenarios, "AI300Scenario"))

    def test_technique_factories_use_pyrit_classes(self):
        """Test technique factories use PyRIT native attack classes"""
        from pyrit.executor.attack import (
            PromptSendingAttack, RedTeamingAttack, CrescendoAttack,
        )
        # Check metadata references correct classes
        self.assertEqual(
            AI300_TECHNIQUE_METADATA["prompt_sending"]["attack_class"],
            PromptSendingAttack,
        )
        self.assertEqual(
            AI300_TECHNIQUE_METADATA["red_teaming"]["attack_class"],
            RedTeamingAttack,
        )
        self.assertEqual(
            AI300_TECHNIQUE_METADATA["crescendo"]["attack_class"],
            CrescendoAttack,
        )

    def test_scenario_technique_extends_pyrit(self):
        """Test AI300Technique extends PyRIT ScenarioTechnique"""
        from pyrit.scenario import ScenarioTechnique
        self.assertTrue(issubclass(AI300Technique, ScenarioTechnique))

    def test_scenario_extends_pyrit(self):
        """Test AI300Scenario extends PyRIT Scenario"""
        from pyrit.scenario import Scenario
        self.assertTrue(issubclass(AI300Scenario, Scenario))

    def test_adaptive_extends_pyrit(self):
        """Test AI300AdaptiveScenario extends PyRIT AdaptiveScenario"""
        from pyrit.scenario.scenarios.adaptive import AdaptiveScenario
        self.assertTrue(issubclass(AI300AdaptiveScenario, AdaptiveScenario))



# ============================================================
# P0: FailureTypeRoutingSelector 测试（替代自建 AttackUpgradeStrategy）
# ============================================================


class TestP0FailureTypeRoutingSelector(unittest.TestCase):
    """P0: 失败类型路由选择器测试（替代自建升级重试）"""

    def test_selector_is_subclass_of_epsilon_greedy(self):
        """Test FailureTypeRoutingSelector extends EpsilonGreedyTechniqueSelector"""
        from pyrit.scenario.scenarios.adaptive import EpsilonGreedyTechniqueSelector
        self.assertTrue(issubclass(FailureTypeRoutingSelector, EpsilonGreedyTechniqueSelector))

    def test_ai300_epsilon_greedy_is_subclass(self):
        """Test AI300EpsilonGreedySelector extends FailureTypeRoutingSelector"""
        self.assertTrue(issubclass(AI300EpsilonGreedySelector, FailureTypeRoutingSelector))

    def test_selector_default_epsilon(self):
        """Test default epsilon is 0.2"""
        selector = AI300EpsilonGreedySelector()
        self.assertEqual(selector._epsilon, 0.2)

    def test_update_failure_type(self):
        """Test update_failure_type sets last failure type"""
        selector = FailureTypeRoutingSelector()
        selector.update_failure_type("model_refusal")
        self.assertEqual(selector._last_failure_type, "model_refusal")

    def test_reorder_model_refusal_prioritizes_strategy(self):
        """Test model_refusal routes to strategy escalation (Tier S) first"""
        selector = FailureTypeRoutingSelector()
        selector.update_failure_type("model_refusal")
        # Simulate reorder
        techniques = ["red_teaming", "rot13", "crescendo", "base64", "prompt_sending"]
        reordered = selector._reorder_by_failure_type(techniques)
        # Tier S techniques should be first (strategy escalation)
        self.assertIn(reordered[0], {"red_teaming", "crescendo"})
        self.assertIn(reordered[1], {"red_teaming", "crescendo"})

    def test_reorder_timeout_prioritizes_single_turn(self):
        """Test timeout routes to single_turn techniques first"""
        selector = FailureTypeRoutingSelector()
        selector.update_failure_type("timeout")
        techniques = ["red_teaming", "rot13", "crescendo", "prompt_sending"]
        reordered = selector._reorder_by_failure_type(techniques)
        # Single turn techniques should be first
        self.assertIn(reordered[0], {"rot13", "prompt_sending"})
        # Multi turn should be last
        self.assertIn(reordered[-1], {"red_teaming", "crescendo"})

    def test_reorder_objective_not_achieved_prioritizes_strong(self):
        """Test objective_not_achieved routes to strong techniques first"""
        selector = FailureTypeRoutingSelector()
        selector.update_failure_type("objective_not_achieved")
        techniques = ["prompt_sending", "rot13", "crescendo", "red_teaming"]
        reordered = selector._reorder_by_failure_type(techniques)
        # Strong techniques should be first
        self.assertIn(reordered[0], {"crescendo", "red_teaming"})

    def test_reorder_no_failure_type_prioritizes_encoding(self):
        """Test no failure type defaults to academic ASR priority"""
        selector = FailureTypeRoutingSelector()
        techniques = ["red_teaming", "rot13", "crescendo", "base64"]
        reordered = selector._reorder_by_failure_type(techniques)
        # Tier S (red_teaming, crescendo) should be first by academic ASR
        self.assertIn(reordered[0], {"red_teaming", "crescendo"})

    def test_extract_failure_type_from_result_refusal(self):
        """Test extract_failure_type_from_result detects model_refusal"""
        mock_result = MagicMock()
        mock_result.error_message = "The model refused to respond"
        ft = extract_failure_type_from_result(mock_result)
        self.assertEqual(ft, "model_refusal")

    def test_extract_failure_type_from_result_timeout(self):
        """Test extract_failure_type_from_result detects timeout"""
        mock_result = MagicMock()
        mock_result.error_message = "Timeout occurred during execution"
        ft = extract_failure_type_from_result(mock_result)
        self.assertEqual(ft, "timeout")

    def test_extract_failure_type_from_result_none(self):
        """Test extract_failure_type_from_result handles None"""
        ft = extract_failure_type_from_result(None)
        self.assertEqual(ft, "unknown")


# ============================================================
# P1: 原生双通道输出测试（替代自建双通道）
# ============================================================


class TestP1NativeOutput(unittest.TestCase):
    """P1: 原生 output_scenario_async 双通道输出测试"""

    def _create_mock_batch_result(self, total=10, success=7, failed=3):
        br = BatchAttackResult(total_plans=total)
        br.executed = total
        br.succeeded = success
        br.failed = failed
        br.results = []
        br.errors = []
        return br

    def test_output_scenario_async_bridge_fallback(self):
        """Test output_scenario_async falls back to bridge formatting"""
        br = self._create_mock_batch_result()
        output = asyncio.run(output_scenario_async(br, to_terminal=False))
        self.assertIsInstance(output, str)

    def test_output_to_file_bridge_fallback(self):
        """Test output to file with bridge fallback"""
        import tempfile
        br = self._create_mock_batch_result()
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            path = f.name
        output = asyncio.run(output_scenario_async(
            br, to_terminal=False, to_file=True, file_path=path
        ))
        self.assertEqual(output, path)
        import os
        self.assertTrue(os.path.exists(path))
        os.unlink(path)

    def test_native_file_sink_available(self):
        """Test PyRIT native FileSink is available"""
        from pyrit.output import FileSink
        from pathlib import Path
        sink = FileSink(path=Path("/tmp/test.md"))
        self.assertIsNotNone(sink)

    def test_native_stdout_sink_available(self):
        """Test PyRIT native StdoutSink is available"""
        from pyrit.output import StdoutSink
        sink = StdoutSink()
        self.assertIsNotNone(sink)

    def test_native_output_scenario_async_available(self):
        """Test PyRIT native output_scenario_async is available"""
        from pyrit.output import output_scenario_async as native_func
        self.assertTrue(callable(native_func))


# ============================================================
# P4: OWASP 映射集成 + 弹性恢复测试
# ============================================================


class TestP4OWASPIntegration(unittest.TestCase):
    """P4: OWASP 映射通过 memory_labels 集成测试"""

    def test_build_memory_labels_with_owasp(self):
        """Test build_memory_labels includes owasp_id"""
        labels = build_memory_labels(owasp_id="LLM01")
        self.assertEqual(labels["owasp_id"], "LLM01")

    def test_build_memory_labels_with_exam_id(self):
        """Test build_memory_labels includes exam_id"""
        labels = build_memory_labels(exam_id="exam_001")
        self.assertEqual(labels["exam_id"], "exam_001")

    def test_build_memory_labels_with_extra(self):
        """Test build_memory_labels includes extra labels"""
        labels = build_memory_labels(owasp_id="LLM01", category="jailbreak")
        self.assertEqual(labels["owasp_id"], "LLM01")
        self.assertEqual(labels["category"], "jailbreak")

    def test_build_memory_labels_empty(self):
        """Test build_memory_labels with no args returns empty dict"""
        labels = build_memory_labels()
        self.assertEqual(len(labels), 0)

    def test_bridge_with_memory_labels(self):
        """Test ScenarioResultBridge stores memory_labels"""
        from src.payloads.models import BatchAttackResult
        br = BatchAttackResult(total_plans=5)
        br.executed = 5
        br.succeeded = 3
        br.failed = 2
        br.results = []
        br.errors = []
        labels = build_memory_labels(owasp_id="LLM06", exam_id="exam_002")
        bridge = ScenarioResultBridge(br, memory_labels=labels)
        self.assertEqual(bridge.memory_labels["owasp_id"], "LLM06")
        self.assertEqual(bridge.memory_labels["exam_id"], "exam_002")

    def test_bridge_get_owasp_mapping(self):
        """Test get_owasp_mapping extracts OWASP ID from memory_labels"""
        from src.payloads.models import BatchAttackResult
        br = BatchAttackResult(total_plans=5)
        br.executed = 5
        br.succeeded = 3
        br.failed = 2
        br.results = []
        br.errors = []
        labels = build_memory_labels(owasp_id="LLM01")
        bridge = ScenarioResultBridge(br, memory_labels=labels)
        mapping = bridge.get_owasp_mapping()
        self.assertIn("LLM01", mapping)

    def test_bridge_summary_includes_memory_labels(self):
        """Test get_summary includes memory_labels"""
        from src.payloads.models import BatchAttackResult
        br = BatchAttackResult(total_plans=5)
        br.executed = 5
        br.succeeded = 3
        br.failed = 2
        br.results = []
        br.errors = []
        labels = build_memory_labels(owasp_id="LLM01")
        bridge = ScenarioResultBridge(br, memory_labels=labels)
        summary = bridge.get_summary()
        self.assertIn("memory_labels", summary)
        self.assertEqual(summary["memory_labels"]["owasp_id"], "LLM01")

    def test_bridge_with_scenario_result_id(self):
        """Test bridge stores scenario_result_id for resume"""
        from src.payloads.models import BatchAttackResult
        br = BatchAttackResult(total_plans=1)
        br.executed = 1
        br.succeeded = 1
        br.failed = 0
        br.results = []
        br.errors = []
        bridge = ScenarioResultBridge(br, scenario_result_id="test-resume-id")
        self.assertEqual(bridge.id, "test-resume-id")

    def test_bridge_with_native_result(self):
        """Test bridge stores native_result reference"""
        from src.payloads.models import BatchAttackResult
        br = BatchAttackResult(total_plans=1)
        br.executed = 1
        br.succeeded = 1
        br.failed = 0
        br.results = []
        br.errors = []
        bridge = ScenarioResultBridge(br, native_result="fake_native_result")
        self.assertIsNotNone(bridge.native_result)
        self.assertEqual(bridge.native_result, "fake_native_result")

    def test_batch_result_to_scenario_result_with_options(self):
        """Test batch_result_to_scenario_result with native_result and memory_labels"""
        from src.payloads.models import BatchAttackResult
        br = BatchAttackResult(total_plans=1)
        br.executed = 1
        br.succeeded = 1
        br.failed = 0
        br.results = []
        br.errors = []
        labels = build_memory_labels(owasp_id="ASI03")
        bridge = batch_result_to_scenario_result(
            br,
            native_result="fake_native",
            scenario_result_id="resume-123",
            memory_labels=labels,
        )
        self.assertEqual(bridge.native_result, "fake_native")
        self.assertEqual(bridge.id, "resume-123")
        self.assertEqual(bridge.memory_labels["owasp_id"], "ASI03")


if __name__ == "__main__":
    unittest.main()
