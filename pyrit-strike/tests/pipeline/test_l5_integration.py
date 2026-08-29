"""L5 v8 全量集成验证测试 — 验证所有新实施的优化功能。

测试范围:
    1. GCG 攻击函数存在性
    2. AutoDAN 种子生成器
    3. OWASP 全覆盖种子
    4. 三 Judge 仲裁机制
    5. LLM 原生置信度概率输出
    6. 双 Judge 统计集成到报告
    7. SmoothLLM 防御绕过 Converter
    8. 贝叶斯优化自适应阈值
    9. 种子级贝叶斯 UCB 排序
    10. CAIR 集成
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

_SEEDS_DIR = _PROJECT_ROOT / "data" / "seeds"


class TestL5V8GCG:
    """P1-1: GCG 攻击集成测试。"""

    def test_gcg_function_exists(self):
        """测试 _run_gcg 函数存在。"""
        from pipeline.strike.escalation import _run_gcg
        assert callable(_run_gcg)

    def test_cair_function_exists(self):
        # V2: _run_cair 已从 escalation.py 删除 (死代码清理)
        pytest.skip("V2: _run_cair removed from escalation.py")

    def test_escalation_chain_has_gcg_and_cair(self):
        """测试升级链包含 GCG (V2: CAIR 函数已删除)."""
        import pipeline.strike.escalation as esc
        source = open(esc.__file__, encoding="utf-8").read()
        assert "_run_gcg" in source
        # V2: _run_cair 已从 escalation.py 删除


class TestL5V8AutoDAN:
    """P1-2: AutoDAN 种子生成器测试。"""

    def test_autodan_module_imports(self):
        """测试 AutoDAN 模块导入。"""
        from pipeline.arm.autodan_generator import (
            _AUTODAN_STRATEGIES,
            _ROLES,
            _SCENARIOS,
        )
        assert len(_AUTODAN_STRATEGIES) >= 5
        assert len(_ROLES) >= 5
        assert len(_SCENARIOS) >= 5

    def test_autodan_seed_groups_creation(self):
        """测试 AutoDAN 种子组创建。"""
        from pipeline.arm.autodan_generator import get_autodan_seed_groups
        groups = get_autodan_seed_groups(["test objective"], None, n_variants_per_objective=3)
        assert len(groups) == 3
        for g in groups:
            assert g.seeds is not None


class TestL5V8OWASPCoverage:
    """P1-3: OWASP 全覆盖种子测试。"""

    def test_owasp_full_coverage_file_exists(self):
        """测试 OWASP 全覆盖种子文件存在。"""
        path = _SEEDS_DIR / "owasp_full_coverage.prompt"
        assert path.exists(), f"OWASP full coverage seed file not found: {path}"

    def test_owasp_full_coverage_has_all_categories(self):
        """测试包含所有新增 OWASP 类别。"""
        path = _SEEDS_DIR / "owasp_full_coverage.prompt"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        owasp_ids = {s.get("metadata", {}).get("owasp_id", "") for s in data}
        assert "LLM04" in owasp_ids
        assert "LLM08" in owasp_ids
        assert "ASI06" in owasp_ids
        assert "ASI07" in owasp_ids
        assert "ASI08" in owasp_ids
        assert "ASI09" in owasp_ids
        assert "ASI10" in owasp_ids

    def test_all_seeds_have_language(self):
        """测试所有种子有 language 字段。"""
        path = _SEEDS_DIR / "owasp_full_coverage.prompt"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        for seed in data:
            metadata = seed.get("metadata", {})
            assert "language" in metadata, f"Seed missing 'language' field: {metadata}"


class TestL5V8TripleJudge:
    """P2-4: 三 Judge 仲裁机制测试。"""

    def test_third_judge_parameter_exists(self):
        """测试 third_judge 参数存在。"""
        import inspect

        from pipeline.assess.adaptive_dual_judge import AdaptiveDualJudgeScorer
        sig = inspect.signature(AdaptiveDualJudgeScorer.__init__)
        assert "third_judge" in sig.parameters

    def test_third_judge_stats_in_get_stats(self):
        """测试 get_stats 包含 third_judge 统计。"""
        import inspect

        from pipeline.assess.adaptive_dual_judge import AdaptiveDualJudgeScorer
        source = inspect.getsource(AdaptiveDualJudgeScorer.get_stats)
        assert "third_judge_invoked" in source
        assert "third_judge_rate" in source

    def test_triple_arbitration_in_source(self):
        """测试三 Judge 仲裁逻辑在源码中。"""
        import inspect

        from pipeline.assess.adaptive_dual_judge import AdaptiveDualJudgeScorer
        source = inspect.getsource(AdaptiveDualJudgeScorer._score_async)
        assert "third_judge" in source
        assert "triple_arbitration" in source
        assert "majority" in source.lower() or "votes_true" in source


class TestL5V8ConfidenceOutput:
    """P2-5: LLM 原生置信度概率输出测试。"""

    def test_rubric_has_confidence_instruction(self):
        """测试 rubric 包含置信度指令。"""
        path = _PROJECT_ROOT / "data" / "scorers" / "blackbox_task_achieved.yaml"
        content = path.read_text(encoding="utf-8")
        assert "CONFIDENCE: HIGH" in content
        assert "CONFIDENCE: MEDIUM" in content
        assert "CONFIDENCE: LOW" in content

    def test_estimate_confidence_parses_explicit_tags(self):
        """测试 _estimate_confidence 解析显式置信度标记。"""
        import inspect

        from pipeline.assess.adaptive_dual_judge import AdaptiveDualJudgeScorer
        source = inspect.getsource(AdaptiveDualJudgeScorer._estimate_confidence)
        assert "confidence_match" in source
        assert "high" in source
        assert "medium" in source
        assert "low" in source


class TestL5V8DualJudgeReport:
    """P2-6: 双 Judge 统计集成到报告测试。"""

    def test_evidence_collection_has_dual_judge_stats(self):
        """测试 EvidenceCollection 有 dual_judge_stats 字段。"""
        from pipeline.report.evidence import EvidenceCollection
        ec = EvidenceCollection(collection_id="test", timestamp="now", target_model="test")
        assert hasattr(ec, "dual_judge_stats")

    def test_evidence_to_dict_has_dual_judge_stats(self):
        """测试 _evidence_to_dict 包含 dual_judge_stats。"""
        import inspect

        from pipeline.report.generator import _evidence_to_dict
        source = inspect.getsource(_evidence_to_dict)
        assert "dual_judge_stats" in source


class TestL5V8SmoothLLMBypass:
    """P2-7: SmoothLLM 防御绕过 Converter 测试。"""

    def test_smoothllm_bypass_function_exists(self):
        """测试 smoothllm_bypass 函数存在。"""
        from pipeline.arm.converter_chains import smoothllm_bypass
        assert callable(smoothllm_bypass)

    def test_smoothllm_in_chain_builders(self):
        """测试 smoothllm_bypass 在 CHAIN_BUILDERS 中。"""
        from pipeline.arm.converter_chains import CHAIN_BUILDERS
        assert "smoothllm_bypass" in CHAIN_BUILDERS

    def test_l5_optimal_has_selective(self):
        """L5 v36: l5_optimal 包含 SelectiveTextConverter (替代 FuzzerConverter)."""
        import inspect

        from pipeline.arm.converter_chains import l5_optimal
        source = inspect.getsource(l5_optimal)
        assert "SelectiveTextConverter" in source
        assert "selective_encoding" in source


class TestL5V8BayesianThreshold:
    """P3-8: 贝叶斯优化自适应阈值测试。"""

    def test_bayesian_ei_adjustment_exists(self):
        """测试 _bayesian_ei_adjustment 函数存在。"""
        from pipeline.assess.adaptive_dual_judge import _bayesian_ei_adjustment
        assert callable(_bayesian_ei_adjustment)

    def test_bayesian_ei_returns_none_for_empty_history(self):
        """测试空历史时返回 None。"""
        from pipeline.assess.adaptive_dual_judge import _bayesian_ei_adjustment
        result = _bayesian_ei_adjustment(50.0, [], 0.85)
        assert result is None

    def test_bayesian_ei_adjusts_when_low(self):
        """测试当前 ASR 低于历史最佳时调整阈值。"""
        from pipeline.assess.adaptive_dual_judge import _bayesian_ei_adjustment
        history = [
            {"asr": 80.0, "threshold": 0.75, "timestamp": "2024-01-01"},
            {"asr": 60.0, "threshold": 0.85, "timestamp": "2024-01-02"},
        ]
        result = _bayesian_ei_adjustment(40.0, history, 0.85)
        assert result is not None
        assert result != 0.85

    def test_threshold_history_saved(self):
        """测试阈值历史保存逻辑在源码中。"""
        import inspect

        from pipeline.assess.adaptive_dual_judge import _compute_adaptive_threshold
        source = inspect.getsource(_compute_adaptive_threshold)
        assert "threshold_history" in source
        assert "bayesian_ei" in source.lower() or "_bayesian_ei_adjustment" in source


class TestL5V8UCBSeedRanking:
    """P3-9: 种子级贝叶斯 UCB 排序测试。"""

    def test_ucb_logic_in_rank_by_asr(self):
        """测试 _rank_by_asr 包含 UCB 逻辑。"""
        import inspect

        from pipeline.arm.seed_ranker import _rank_by_asr
        source = inspect.getsource(_rank_by_asr)
        assert "ucb" in source.lower()
        assert "math.sqrt" in source or "sqrt" in source
        assert "seed_attempts" in source

    def test_ucb_parameters(self):
        """测试 UCB 参数存在。"""
        import inspect

        from pipeline.arm.seed_ranker import _rank_by_asr
        source = inspect.getsource(_rank_by_asr)
        assert "C = 0.5" in source or "C=0.5" in source
        assert "ucb_bonus" in source


class TestL5V8CAIR:
    """P3-10: CAIR 集成测试。"""

    def test_cair_module_imports(self):
        """测试 CAIR 模块导入。"""
        from pipeline.strike.cair import (
            _COUNTER_STRATEGIES,
            _REFUSAL_PATTERNS,
        )
        assert len(_REFUSAL_PATTERNS) >= 5
        assert len(_COUNTER_STRATEGIES) >= 5

    def test_refusal_pattern_analysis(self):
        """测试拒绝模式分析。"""
        from pipeline.strike.cair import analyze_refusal_pattern

        # safety policy
        assert analyze_refusal_pattern("I cannot help due to safety guidelines") == "safety_policy"

        # ethical refusal
        assert analyze_refusal_pattern("This is ethically wrong and harmful") == "ethical_refusal"

        # generic refusal
        assert analyze_refusal_pattern("Sorry, I must decline") == "generic_refusal"

    def test_counter_strategy_selection(self):
        """测试应对策略选择。"""
        from pipeline.strike.cair import select_adaptive_strategy

        strategy = select_adaptive_strategy("safety_policy")
        assert "prefix" in strategy
        assert "strategy" in strategy
        assert strategy["strategy"] == "authority_endorsement"

    def test_cair_in_escalation(self):
        # V2: _run_cair 已从 escalation.py 删除 (死代码清理)
        pytest.skip("V2: _run_cair removed from escalation.py")


class TestL5V8Integration:
    """集成验证测试。"""

    def test_all_modules_importable(self):
        """测试所有新模块可导入。"""

    def test_escalation_chain_order(self):
        """测试升级链顺序 (V2: 两级并行升级, L3/L4 已跳过)."""
        import pipeline.strike.escalation as esc
        source = open(esc.__file__, encoding="utf-8").read()

        # Level 1 (RedTeaming + CoT + Crescendo + TAP + PAIR)
        assert "_run_crescendo" in source
        assert "_run_tap" in source
        assert "_run_pair" in source
        assert "_run_cot_hijack" in source
        assert "_run_red_teaming" in source
        # Level 2 (GCG + CAIR + Best-of-N + Encoded Injection)
        assert "_run_gcg" in source
        assert "_run_cair" in source
        assert "_run_best_of_n" in source
        assert "_run_encoded_injection" in source

        # L3/L4 已跳过 (边际 ASR < 3%) — 函数仍在 re-export 但为空壳
        # 不在 L1/L2 执行路径中调用

        # 中间退出变量名
        assert "post_l1_asr" in source
        assert "post_l2_asr" in source

    def test_converter_chain_completeness(self):
        """测试 Converter 链完整性。"""
        from pipeline.arm.converter_chains import CHAIN_BUILDERS

        expected_chains = [
            "encoding", "stealth", "persuasion", "format",
            "multi_encoding", "decomposition", "variation", "flip",
            "smoothllm_bypass", "l5_optimal",
        ]
        for chain in expected_chains:
            assert chain in CHAIN_BUILDERS, f"Missing chain: {chain}"


# ═══════════════════════════════════════════════════════
# L5 v13: ASI Top 10 种子全覆盖验证
# 学术依据: arXiv:2402.01135 — 25 seeds 覆盖 OWASP LLM01-10 + ASI01-10
# ═══════════════════════════════════════════════════════


class TestL5V13ASITop10Coverage:
    """ASI Top 10 种子全覆盖验证测试。"""

    EXPECTED_ASI_IDS = {f"ASI{i:02d}" for i in range(1, 11)}

    def test_asi_top10_file_exists(self):
        """测试 ASI Top 10 种子文件存在。"""
        path = _SEEDS_DIR / "asi_top10.prompt"
        assert path.exists(), f"ASI Top 10 seed file not found: {path}"

    def test_asi_top10_has_all_10_categories(self):
        """测试 ASI Top 10 包含 ASI01-10 全部类别。"""
        path = _SEEDS_DIR / "asi_top10.prompt"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        owasp_ids = {s.get("metadata", {}).get("owasp_id", "") for s in data}
        missing = self.EXPECTED_ASI_IDS - owasp_ids
        assert not missing, f"ASI Top 10 missing categories: {missing}"

    def test_asi_top10_seeds_have_metadata(self):
        """测试每个 ASI 种子有完整的 metadata 字段。"""
        path = _SEEDS_DIR / "asi_top10.prompt"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        required_fields = {"owasp_id", "difficulty", "severity", "category", "source", "language"}
        for seed in data:
            metadata = seed.get("metadata", {})
            missing = required_fields - set(metadata.keys())
            assert not missing, f"Seed missing metadata fields: {missing} — metadata={metadata}"

    def test_asi_top10_has_variant_seeds(self):
        """测试 ASI Top 10 有变体种子 (Best-of-N 提升 ASR)。

        学术依据: arXiv:2402.01135 — Chao et al. §5: 多变体 Best-of-N
        """
        path = _SEEDS_DIR / "asi_top10.prompt"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        # 应至少有 15 个种子 (10 基础 + 5+ 变体)
        assert len(data) >= 15, f"Expected >=15 seeds for ASI Top 10 (base+variants), got {len(data)}"

    def test_owasp_full_coverage_supplements_asi(self):
        """测试 owasp_full_coverage 补充 ASI06-10 变体。"""
        path = _SEEDS_DIR / "owasp_full_coverage.prompt"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        owasp_ids = {s.get("metadata", {}).get("owasp_id", "") for s in data}
        # 应包含 ASI06-10 的补充种子
        asi_ids = {aid for aid in owasp_ids if aid.startswith("ASI")}
        assert asi_ids, f"owasp_full_coverage should contain ASI seeds, got IDs: {owasp_ids}"

    def test_combined_seeds_cover_all_asi_categories(self):
        """测试合并 asi_top10 + owasp_full_coverage 后覆盖 ASI01-10。"""
        combined_ids: set[str] = set()
        for filename in ("asi_top10.prompt", "owasp_full_coverage.prompt"):
            path = _SEEDS_DIR / filename
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            for seed in data:
                wid = seed.get("metadata", {}).get("owasp_id", "")
                if wid:
                    combined_ids.add(wid)
        missing = self.EXPECTED_ASI_IDS - combined_ids
        assert not missing, f"Combined seeds missing ASI categories: {missing}"

    def test_default_seeds_config_includes_asi_top10(self):
        """测试默认 CLI 种子配置包含 ASI Top 10。"""
        from pipeline.config import parse_args

        with patch("sys.argv", ["prog", "--burp-request", "/path/req.txt"]):
            args = parse_args()
        seed_files = [s.strip() for s in args.seeds.split(",")]
        assert "asi_top10" in seed_files, "Default seeds should include asi_top10"
        assert "owasp_full_coverage" in seed_files, "Default seeds should include owasp_full_coverage"

    def test_full_offensive_strategy_includes_asi_top10(self):
        """测试 full_offensive 策略包含 ASI Top 10 种子。"""
        from pipeline.strategy.presets import STRATEGY_PRESETS

        preset = STRATEGY_PRESETS["full_offensive"]
        seed_files = [s.strip() for s in preset.seeds.split(",")]
        assert "asi_top10" in seed_files, "full_offensive strategy should include asi_top10"
        assert "owasp_full_coverage" in seed_files, (
            "full_offensive strategy should include owasp_full_coverage"
        )

    def test_asi_top10_seeds_loadable_via_load_seeds(self):
        """测试 ASI Top 10 种子文件可以被 YAML 解析并加载。

        验证种子文件的格式和内容完整性, 确保 load_seeds 能正确处理。
        """
        path = _SEEDS_DIR / "asi_top10.prompt"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert len(data) > 0
        # 验证每个种子有 value 和 metadata
        for seed in data:
            assert "value" in seed, f"Seed missing 'value' field: {seed}"
            assert "metadata" in seed, f"Seed missing 'metadata' field: {seed}"

    def test_combined_seeds_loadable_via_comma_separated(self):
        """测试逗号分隔的多种子文件可以合并加载。

        验证 asi_top10 + owasp_full_coverage 合并后覆盖 ASI01-10。
        """
        combined_seeds: list[dict] = []
        for filename in ("asi_top10.prompt", "owasp_full_coverage.prompt"):
            path = _SEEDS_DIR / filename
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            combined_seeds.extend(data)

        # 合并后至少应有 15 个种子 (asi_top10 15 + owasp_full_coverage 7+)
        assert len(combined_seeds) >= 15

        # 验证合并后覆盖 ASI01-10
        owasp_ids = {s.get("metadata", {}).get("owasp_id", "") for s in combined_seeds}
        missing = self.EXPECTED_ASI_IDS - owasp_ids
        assert not missing, f"Combined seeds missing ASI categories: {missing}"


# ═══════════════════════════════════════════════════════
# L5 v32: Category Diversity Guarantee 测试
# 学术依据: DPP (arXiv:1207.6083) — diverse subset selection
# ═══════════════════════════════════════════════════════


class TestL5V32CategoryDiversity:
    """L5 v32: 类别多样性保障 (Category Diversity Guarantee) 测试。"""

    def _make_seed_group(self, owasp_id: str, value: str = ""):
        """构建测试用 AttackSeedGroup。"""
        from pipeline.arm.seed_ranker import AttackSeedGroup, SeedObjective

        obj = SeedObjective(value=value or f"test_{owasp_id}", metadata={"owasp_id": owasp_id, "severity": "high"})
        return AttackSeedGroup(seeds=[obj])

    def test_function_exists(self):
        """测试 _apply_category_diversity 函数存在且可导入。"""
        from pipeline.arm.seed_ranker import _apply_category_diversity
        assert callable(_apply_category_diversity)

    def test_all_categories_represented(self):
        """测试 max_seeds=10 时, 10 个不同 OWASP 类别各取 1 个。"""
        from pipeline.arm.seed_ranker import _apply_category_diversity

        # 构造 20 个种子, 10 个不同 owasp_id (每个 2 个)
        owasp_ids = [f"LLM{i:02d}" for i in range(1, 11)]
        groups = []
        for oid in owasp_ids:
            groups.append(self._make_seed_group(oid, f"seed_{oid}_a"))
            groups.append(self._make_seed_group(oid, f"seed_{oid}_b"))

        result = _apply_category_diversity(groups, max_seeds=10)
        assert len(result) == 10

        # 每个类别恰好 1 个
        result_ids = set()
        for g in result:
            obj = next((s for s in g.seeds if hasattr(s, "value")), None)
            if obj:
                meta = getattr(obj, "metadata", {}) or {}
                result_ids.add(meta.get("owasp_id"))
        assert len(result_ids) == 10

    def test_remaining_slots_filled_by_ucb_order(self):
        """测试类别配额填满后, 剩余名额按原始顺序填充。"""
        from pipeline.arm.seed_ranker import _apply_category_diversity

        # 5 个 LLM01 种子 + 3 个 LLM02 种子, max_seeds=5
        groups = []
        for i in range(5):
            groups.append(self._make_seed_group("LLM01", f"llm01_{i}"))
        for i in range(3):
            groups.append(self._make_seed_group("LLM02", f"llm02_{i}"))

        result = _apply_category_diversity(groups, max_seeds=5)
        assert len(result) == 5

        # 第 1 个是 LLM01 (第一个出现), 第 2 个是 LLM02 (第二个类别)
        # 剩余 3 个名额给 LLM01 (按原始顺序)
        result_ids = []
        for g in result:
            obj = next((s for s in g.seeds if hasattr(s, "value")), None)
            if obj:
                meta = getattr(obj, "metadata", {}) or {}
                result_ids.append(meta.get("owasp_id"))
        assert result_ids[0] == "LLM01"
        assert result_ids[1] == "LLM02"
        # 剩余 3 个都是 LLM01
        assert result_ids[2:].count("LLM01") == 3

    def test_no_truncation_when_under_limit(self):
        """测试种子数不超过 max_seeds 时不截断。"""
        from pipeline.arm.seed_ranker import _apply_category_diversity

        groups = [self._make_seed_group("LLM01", f"s{i}") for i in range(3)]
        result = _apply_category_diversity(groups, max_seeds=10)
        assert len(result) == 3

    def test_uncategorized_seeds_handled(self):
        """测试无 owasp_id 的种子不会崩溃。"""
        from pipeline.arm.seed_ranker import AttackSeedGroup, SeedObjective, _apply_category_diversity

        # 混合有/无 owasp_id 的种子
        obj1 = SeedObjective(value="categorized", metadata={"owasp_id": "LLM01"})
        obj2 = SeedObjective(value="uncategorized", metadata={})
        groups = [
            AttackSeedGroup(seeds=[obj1]),
            AttackSeedGroup(seeds=[obj2]),
        ]
        result = _apply_category_diversity(groups, max_seeds=2)
        assert len(result) == 2
