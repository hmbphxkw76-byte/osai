# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""高级 MCP 攻击 + 编排器 + AI-VSS + 框架映射 综合测试。.

覆盖模块:
  1. pipeline.orchestrators.advanced_crescendo — Crescendo 编排器
  2. pipeline.orchestrators.tap_orchestrator — TAP 编排器
  3. pipeline.scoring.ai_vss_scorer — AI-VSS 评分
  4. pipeline.assessment.framework_mapper — 三框架映射
  5. pipeline.assessment.redteam_methodology — 5 阶段评估
  6. pipeline.scenarios.advanced_mcp_attacks — 高级 MCP 攻击场景

> **日期**: 2026-8-4
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ──────────────────────────────────────────────────────────────────
#  AI-VSS Scorer 测试
# ──────────────────────────────────────────────────────────────────


class TestAIVSSScorer:
    """AI-VSS 评分器测试。."""

    def test_base_cvss_only(self) -> None:
        """仅基础 CVSS, 无修饰符。."""
        from pipeline.scoring.ai_vss_scorer import AIVSSScorer, AIVSSSeverity

        scorer = AIVSSScorer()
        result = scorer.score(base_cvss=7.5, rationale="Base only")

        assert result.base_cvss == 7.5
        assert result.adjusted_score == 7.5
        assert result.severity == AIVSSSeverity.HIGH
        assert len(result.modifiers) == 0

    def test_with_cascading_modifier(self) -> None:
        """级联修饰符 (+1.0)。."""
        from pipeline.scoring.ai_vss_scorer import AIVSSModifier, AIVSSScorer

        scorer = AIVSSScorer()
        result = scorer.score(
            base_cvss=7.5,
            modifiers=[AIVSSModifier.CASCADING],
        )

        assert result.adjusted_score == 8.5
        assert AIVSSModifier.CASCADING in result.modifiers

    def test_multiple_modifiers(self) -> None:
        """多修饰符组合 (级联 + 隐蔽 + 工具范围)。."""
        from pipeline.scoring.ai_vss_scorer import AIVSSModifier, AIVSSScorer, AIVSSSeverity

        scorer = AIVSSScorer()
        result = scorer.score(
            base_cvss=7.5,
            modifiers=[
                AIVSSModifier.CASCADING,
                AIVSSModifier.STEALTH,
                AIVSSModifier.TOOL_SCOPE,
            ],
        )

        assert result.adjusted_score == 9.5  # 7.5 + 1.0 + 0.5 + 0.5 = 9.5
        assert result.severity == AIVSSSeverity.CRITICAL  # 9.5 >= 9.0 threshold

    def test_cap_at_10(self) -> None:
        """分数上限 10.0。."""
        from pipeline.scoring.ai_vss_scorer import AIVSSModifier, AIVSSScorer

        scorer = AIVSSScorer()
        result = scorer.score(
            base_cvss=9.0,
            modifiers=[AIVSSModifier.CASCADING, AIVSSModifier.STEALTH],
        )

        assert result.adjusted_score == 10.0

    def test_severity_thresholds(self) -> None:
        """严重程度阈值。."""
        from pipeline.scoring.ai_vss_scorer import AIVSSScorer, AIVSSSeverity

        scorer = AIVSSScorer()

        assert scorer._classify_severity(9.5) == AIVSSSeverity.CRITICAL
        assert scorer._classify_severity(8.0) == AIVSSSeverity.HIGH
        assert scorer._classify_severity(5.0) == AIVSSSeverity.MEDIUM
        assert scorer._classify_severity(2.0) == AIVSSSeverity.LOW

    def test_score_from_unsuccessful_attack(self) -> None:
        """未成功攻击评分为 0。."""
        from pipeline.scoring.ai_vss_scorer import AIVSSScorer, AIVSSSeverity

        scorer = AIVSSScorer()
        result = scorer.score_from_attack_result(
            attack_type="test",
            is_successful=False,
            severity="critical",
        )

        assert result.adjusted_score == 0.0
        assert result.severity == AIVSSSeverity.LOW

    def test_score_from_successful_critical_attack(self) -> None:
        """成功 critical 攻击评分。."""
        from pipeline.scoring.ai_vss_scorer import AIVSSModifier, AIVSSScorer

        scorer = AIVSSScorer()
        result = scorer.score_from_attack_result(
            attack_type="tool_chain",
            is_successful=True,
            severity="critical",
            has_cascading=True,
            has_stealth=True,
            has_tool_scope=True,
        )

        assert result.base_cvss == 7.5
        assert AIVSSModifier.CASCADING in result.modifiers
        assert AIVSSModifier.STEALTH in result.modifiers
        assert AIVSSModifier.TOOL_SCOPE in result.modifiers
        assert result.adjusted_score == 9.5

    def test_to_dict(self) -> None:
        """序列化为字典。."""
        from pipeline.scoring.ai_vss_scorer import AIVSSModifier, AIVSSScorer

        scorer = AIVSSScorer()
        result = scorer.score(
            base_cvss=6.0,
            modifiers=[AIVSSModifier.PERSISTENCE],
            rationale="Test",
        )

        d = result.to_dict()
        assert d["base_cvss"] == 6.0
        assert "persistence" in d["modifiers"]
        assert d["adjusted_score"] == 6.5
        assert d["severity"] == "medium"


# ──────────────────────────────────────────────────────────────────
#  Framework Mapper 测试
# ──────────────────────────────────────────────────────────────────


class TestFrameworkMapper:
    """三框架映射器测试。."""

    def test_csa_to_owasp(self) -> None:
        """CSA → OWASP 映射。."""
        from pipeline.assessment.framework_mapper import FrameworkMapper, OWASPAgenticCode

        mapper = FrameworkMapper()
        codes = mapper.csa_to_owasp("Goal & Instruction Manipulation")

        assert OWASPAgenticCode.ASI01 in codes

    def test_csa_to_owasp_unknown(self) -> None:
        """未知 CSA 类别返回空列表。."""
        from pipeline.assessment.framework_mapper import FrameworkMapper

        mapper = FrameworkMapper()
        codes = mapper.csa_to_owasp("Non-existent Category")
        assert codes == []

    def test_owasp_to_atlas(self) -> None:
        """OWASP → ATLAS 映射。."""
        from pipeline.assessment.framework_mapper import FrameworkMapper, OWASPAgenticCode

        mapper = FrameworkMapper()
        atlas = mapper.owasp_to_atlas(OWASPAgenticCode.ASI01)

        assert "AML.T0051" in atlas
        assert "AML.T0054" in atlas

    def test_owasp_description(self) -> None:
        """OWASP 描述获取。."""
        from pipeline.assessment.framework_mapper import FrameworkMapper, OWASPAgenticCode

        mapper = FrameworkMapper()
        desc = mapper.owasp_description(OWASPAgenticCode.ASI01)

        assert "Goal Hijacking" in desc

    def test_build_coverage_matrix(self) -> None:
        """覆盖矩阵构建。."""
        from pipeline.assessment.framework_mapper import (
            FrameworkMapper,
            OWASPAgenticCode,
        )

        mapper = FrameworkMapper()
        coverage = mapper.build_coverage_matrix(
            tested_owasp={OWASPAgenticCode.ASI01, OWASPAgenticCode.ASI02},
            tested_csa={"Goal & Instruction Manipulation"},
        )

        assert len(coverage.tested_owasp_codes) == 2
        assert len(coverage.tested_csa_categories) == 1
        assert coverage.owasp_coverage_pct == 20.0  # 2/10
        assert coverage.atlas_coverage_count > 0

    def test_get_all_csa_categories(self) -> None:
        """获取全部 CSA 类别 (12 个)。."""
        from pipeline.assessment.framework_mapper import FrameworkMapper

        mapper = FrameworkMapper()
        categories = mapper.get_all_csa_categories()

        assert len(categories) == 12

    def test_get_all_owasp_codes(self) -> None:
        """获取全部 OWASP 代码 (10 个)。."""
        from pipeline.assessment.framework_mapper import FrameworkMapper

        mapper = FrameworkMapper()
        codes = mapper.get_all_owasp_codes()

        assert len(codes) == 10

    def test_map_attack_to_frameworks(self) -> None:
        """攻击 → 三框架映射。."""
        from pipeline.assessment.framework_mapper import (
            FrameworkMapper,
            OWASPAgenticCode,
        )

        mapper = FrameworkMapper()
        mapping = mapper.map_attack_to_frameworks(
            attack_type="tool_chain_weaponization",
            owasp_codes=[OWASPAgenticCode.ASI02, OWASPAgenticCode.ASI05],
        )

        assert mapping["attack_type"] == "tool_chain_weaponization"
        assert "ASI02" in mapping["owasp_codes"]
        assert "ASI05" in mapping["owasp_codes"]
        assert len(mapping["atlas_techniques"]) > 0
        assert len(mapping["csa_categories"]) > 0


# ──────────────────────────────────────────────────────────────────
#  Red Team Methodology 测试
# ──────────────────────────────────────────────────────────────────


class TestRedTeamMethodology:
    """5 阶段评估方法论测试。."""

    def test_init(self) -> None:
        """初始化方法论。."""
        from pipeline.assessment.redteam_methodology import RedTeamMethodology

        methodology = RedTeamMethodology(target_name="TestAgent")
        assert methodology.target_name == "TestAgent"
        result = methodology.get_result()
        assert result.target_name == "TestAgent"
        assert len(result.phases) == 5

    def test_start_and_complete_phase(self) -> None:
        """开始和完成阶段。."""
        from pipeline.assessment.framework_mapper import AssessmentPhase
        from pipeline.assessment.redteam_methodology import RedTeamMethodology

        methodology = RedTeamMethodology(target_name="Test")
        methodology.start_phase(AssessmentPhase.SCOPING)
        methodology.complete_phase(AssessmentPhase.SCOPING, duration_minutes=30)

        result = methodology.get_result()
        scoping = result.phases[0]
        assert scoping.status == "completed"
        assert scoping.duration_minutes == 30

    def test_add_finding(self) -> None:
        """添加发现。."""
        from pipeline.assessment.framework_mapper import (
            AssessmentPhase,
            OWASPAgenticCode,
        )
        from pipeline.assessment.redteam_methodology import RedTeamMethodology

        methodology = RedTeamMethodology(target_name="Test")
        methodology.add_finding(
            AssessmentPhase.SCOPING,
            "ASI01 found",
            owasp_code=OWASPAgenticCode.ASI01,
        )

        result = methodology.get_result()
        assert result.total_findings == 1
        assert result.coverage.owasp_coverage_pct == 10.0  # 1/10

    def test_skip_phase(self) -> None:
        """跳过阶段。."""
        from pipeline.assessment.framework_mapper import AssessmentPhase
        from pipeline.assessment.redteam_methodology import RedTeamMethodology

        methodology = RedTeamMethodology(target_name="Test")
        methodology.skip_phase(AssessmentPhase.MANUAL_TESTING, "No expert available")

        result = methodology.get_result()
        manual = result.phases[4]
        assert manual.status == "skipped"
        assert "No expert available" in manual.notes

    def test_add_kill_chain(self) -> None:
        """添加 Kill Chain。."""
        from pipeline.assessment.framework_mapper import OWASPAgenticCode
        from pipeline.assessment.redteam_methodology import RedTeamMethodology

        methodology = RedTeamMethodology(target_name="Test")
        methodology.add_kill_chain(
            name="Test Kill Chain",
            chain=["Step 1", "Step 2", "Step 3"],
            owasp_codes=[OWASPAgenticCode.ASI01, OWASPAgenticCode.ASI02],
        )

        result = methodology.get_result()
        assert len(result.kill_chains) == 1
        assert result.kill_chains[0]["name"] == "Test Kill Chain"
        assert len(result.kill_chains[0]["chain"]) == 3

    def test_overall_risk_critical(self) -> None:
        """总体风险 = critical (3+ critical 发现)。."""
        from pipeline.assessment.framework_mapper import AssessmentPhase
        from pipeline.assessment.redteam_methodology import RedTeamMethodology

        methodology = RedTeamMethodology(target_name="Test")
        for i in range(3):
            methodology.add_finding(
                AssessmentPhase.DEEP_EXPLOITATION,
                f"Critical finding {i}",
            )

        result = methodology.get_result()
        assert result.overall_risk == "critical"


# ──────────────────────────────────────────────────────────────────
#  Advanced Crescendo Orchestrator 测试
# ──────────────────────────────────────────────────────────────────


class TestAdvancedCrescendoOrchestrator:
    """Crescendo 编排器测试 (PyRIT 原生 CrescendoAttack)。."""

    def test_init(self) -> None:
        """初始化编排器。."""
        from pipeline.orchestrators.advanced_crescendo import (
            AdvancedCrescendoOrchestrator,
        )

        mock_target = MagicMock()
        orchestrator = AdvancedCrescendoOrchestrator(
            objective_target=mock_target,
            adversarial_chat=mock_target,
            scoring_target=mock_target,
            objective="Test objective",
            max_turns=5,
        )

        assert orchestrator.objective == "Test objective"
        assert orchestrator.max_turns == 5
        assert orchestrator.max_backtracks == 10

    @pytest.mark.asyncio
    async def test_run_with_mock_native(self) -> None:
        """模拟原生 CrescendoAttack 执行。."""
        from pipeline.orchestrators.advanced_crescendo import (
            AdvancedCrescendoOrchestrator,
        )

        mock_target = MagicMock()
        orchestrator = AdvancedCrescendoOrchestrator(
            objective_target=mock_target,
            adversarial_chat=mock_target,
            scoring_target=mock_target,
            objective="Test",
            max_turns=3,
        )

        # Mock 原生 CrescendoAttack 的结果封装
        mock_native_result = MagicMock()
        mock_native_result.backtrack_count = 2
        mock_native_result.get_all_conversation_ids = MagicMock(return_value=["conv_123"])
        mock_native_result.get_results = MagicMock(return_value=[])
        orchestrator._wrap_native_result = MagicMock(return_value=MagicMock(achieved=True))

        # Patch 原生 CrescendoAttack (在 pyrit.executor.attack 中)
        with patch("pyrit.executor.attack.CrescendoAttack") as mock_cls:
            mock_instance = AsyncMock()
            mock_instance.execute_async = AsyncMock(return_value=mock_native_result)
            mock_cls.return_value = mock_instance

            result = await orchestrator.run_async()

        assert result is not None

    def test_crescendo_result_to_dict(self) -> None:
        """CrescendoResult 序列化。."""
        from pipeline.orchestrators.advanced_crescendo import CrescendoResult, CrescendoTurn

        result = CrescendoResult(
            objective="Test",
            achieved=True,
            winning_turn=3,
            max_turns=10,
            turns=[CrescendoTurn(turn_number=1, attacker_message="msg", target_response="resp", score="FAIL")],
            backtrack_count=2,
            conversation_id="conv_123",
        )

        d = result.to_dict()
        assert d["objective"] == "Test"
        assert d["achieved"] is True
        assert d["winning_turn"] == 3
        assert d["backtrack_count"] == 2
        assert d["conversation_id"] == "conv_123"
        assert len(d["turns"]) == 1


# ──────────────────────────────────────────────────────────────────
#  TAP Orchestrator 测试
# ──────────────────────────────────────────────────────────────────


class TestTAPOrchestrator:
    """TAP 编排器测试 (PyRIT 原生 TAPAttack)。."""

    def test_init(self) -> None:
        """初始化编排器。."""
        from pipeline.orchestrators.tap_orchestrator import TAPOrchestrator

        mock_target = MagicMock()
        orchestrator = TAPOrchestrator(
            objective_target=mock_target,
            adversarial_chat=mock_target,
            scoring_target=mock_target,
            objective="Test objective",
            tree_width=4,
            tree_depth=3,
            branching=2,
            success_threshold=8,
        )

        assert orchestrator.objective == "Test objective"
        assert orchestrator.tree_width == 4
        assert orchestrator.tree_depth == 3
        assert orchestrator.batch_size == 10

    @pytest.mark.asyncio
    async def test_run_with_mock_native(self) -> None:
        """模拟原生 TAPAttack 执行。."""
        from pipeline.orchestrators.tap_orchestrator import TAPOrchestrator

        mock_target = MagicMock()
        orchestrator = TAPOrchestrator(
            objective_target=mock_target,
            adversarial_chat=mock_target,
            scoring_target=mock_target,
            objective="Test",
            tree_width=2,
            tree_depth=2,
            branching=1,
            success_threshold=8,
        )

        # Mock 原生结果封装
        mock_native_result = MagicMock()
        mock_native_result.nodes_explored = 4
        mock_native_result.nodes_pruned = 2
        mock_native_result.max_depth_reached = True
        mock_native_result.tree_visualization = "tree"
        mock_native_result.best_adversarial_conversation_id = "conv_456"
        mock_native_result.get_results = MagicMock(return_value=[])
        orchestrator._wrap_native_result = MagicMock(return_value=MagicMock(achieved=True, best_score=9))

        # Patch 原生 TAPAttack (在 pyrit.executor.attack 中)
        with patch("pyrit.executor.attack.TAPAttack") as mock_cls:
            mock_instance = AsyncMock()
            mock_instance.execute_async = AsyncMock(return_value=mock_native_result)
            mock_cls.return_value = mock_instance

            result = await orchestrator.run_async()

        assert result is not None

    def test_tap_result_to_dict(self) -> None:
        """TAPResult 序列化。."""
        from pipeline.orchestrators.tap_orchestrator import TAPResult

        result = TAPResult(
            objective="Test",
            achieved=True,
            best_score=9,
            best_prompt="best",
            best_response="resp",
            tree_width=4,
            tree_depth=3,
            nodes_explored=6,
            nodes_pruned=2,
        )

        d = result.to_dict()
        assert d["achieved"] is True
        assert d["best_score"] == 9
        assert d["tree_width"] == 4
        assert d["nodes_explored"] == 6
        assert d["nodes_pruned"] == 2


# ──────────────────────────────────────────────────────────────────
#  Advanced MCP Attacks 测试
# ──────────────────────────────────────────────────────────────────


class TestAdvancedMCPAttacks:
    """高级 MCP 攻击场景测试。."""

    def test_probe_count(self) -> None:
        """高级探针数量 = 6。."""
        from pipeline.scenarios.advanced_mcp_attacks import _ADVANCED_MCP_PROBES

        assert len(_ADVANCED_MCP_PROBES) == 6

    def test_kill_chain_count(self) -> None:
        """Kill Chain 数量 = 3。."""
        from pipeline.scenarios.advanced_mcp_attacks import _KILL_CHAINS

        assert len(_KILL_CHAINS) == 3

    def test_probe_owasp_coverage(self) -> None:
        """探针覆盖 7 个 OWASP 代码。."""
        from pipeline.assessment.framework_mapper import OWASPAgenticCode
        from pipeline.scenarios.advanced_mcp_attacks import _ADVANCED_MCP_PROBES

        all_codes: set[OWASPAgenticCode] = set()
        for _, _, _, _, _, codes, _ in _ADVANCED_MCP_PROBES:
            all_codes.update(codes)

        assert len(all_codes) == 7  # ASI01, ASI02, ASI04, ASI05, ASI06, ASI07, ASI08

    def test_kill_chain_has_modifiers(self) -> None:
        """Kill Chain 包含 AI-VSS 修饰符。."""
        from pipeline.scenarios.advanced_mcp_attacks import _KILL_CHAINS

        for kc in _KILL_CHAINS:
            assert len(kc["modifiers"]) > 0

    def test_report_to_dict(self) -> None:
        """报告序列化。."""
        from pipeline.scenarios.advanced_mcp_attacks import (
            AdvancedMCPAttackReport,
            AdvancedMCPAttackResult,
            KillChainResult,
        )

        report = AdvancedMCPAttackReport(
            probe_results=[
                AdvancedMCPAttackResult(
                    attack_type="test",
                    is_successful=True,
                    severity="critical",
                    ai_vss_score=9.5,
                ),
            ],
            kill_chains=[
                KillChainResult(
                    name="test_kc",
                    is_successful=True,
                    ai_vss_score=10.0,
                ),
            ],
        )

        d = report.to_dict()
        assert d["success_count"] == 1
        assert d["kill_chain_success_count"] == 1
        assert len(d["probe_results"]) == 1
        assert len(d["kill_chains"]) == 1


# ──────────────────────────────────────────────────────────────────
#  Orchestrators __init__ 测试
# ──────────────────────────────────────────────────────────────────


class TestOrchestratorsInit:
    """编排器包初始化测试。."""

    def test_imports(self) -> None:
        """导入测试。."""
        from pipeline.orchestrators import (
            AdvancedCrescendoOrchestrator,
            CrescendoResult,
            TAPOrchestrator,
            TAPResult,
        )

        assert AdvancedCrescendoOrchestrator is not None
        assert CrescendoResult is not None
        assert TAPOrchestrator is not None
        assert TAPResult is not None


class TestScoringInit:
    """评分包初始化测试。."""

    def test_imports(self) -> None:
        """导入测试。."""
        from pipeline.scoring import (
            AIVSSModifier,
            AIVSSScore,
            AIVSSScorer,
            AIVSSSeverity,
        )

        assert AIVSSModifier is not None
        assert AIVSSScore is not None
        assert AIVSSScorer is not None
        assert AIVSSSeverity is not None


class TestAssessmentInit:
    """评估包初始化测试。."""

    def test_imports(self) -> None:
        """导入测试。."""
        from pipeline.assessment import (
            AssessmentPhase,
            AssessmentResult,
            CoverageMatrix,
            FrameworkMapper,
            OWASPAgenticCode,
            RedTeamMethodology,
        )

        assert AssessmentPhase is not None
        assert AssessmentResult is not None
        assert CoverageMatrix is not None
        assert FrameworkMapper is not None
        assert OWASPAgenticCode is not None
        assert RedTeamMethodology is not None


class TestConfigIntegration:
    """CLI 参数集成测试。."""

    def test_new_args_exist(self) -> None:
        """新增 CLI 参数存在。."""
        from pipeline.config import parse_args

        with patch("sys.argv", ["main.py", "--advanced-mcp-attack"]):
            args = parse_args()
            assert args.advanced_mcp_attack is True
            assert args.mcp_attack is False

    def test_crescendo_args(self) -> None:
        """Crescendo 参数解析。."""
        from pipeline.config import parse_args

        with patch(
            "sys.argv",
            ["main.py", "--crescendo-objective", "Test objective", "--crescendo-max-turns", "5"],
        ):
            args = parse_args()
            assert args.crescendo_objective == "Test objective"
            assert args.crescendo_max_turns == 5

    def test_tap_args(self) -> None:
        """TAP 参数解析。."""
        from pipeline.config import parse_args

        with patch(
            "sys.argv",
            [
                "main.py",
                "--tap-objective", "Test",
                "--tap-tree-width", "6",
                "--tap-tree-depth", "4",
                "--tap-branching", "3",
                "--tap-success-threshold", "7",
            ],
        ):
            args = parse_args()
            assert args.tap_objective == "Test"
            assert args.tap_tree_width == 6
            assert args.tap_tree_depth == 4
            assert args.tap_branching == 3
            assert args.tap_success_threshold == 7

    def test_assessment_framework_arg(self) -> None:
        """三框架评估参数。."""
        from pipeline.config import parse_args

        with patch("sys.argv", ["main.py", "--assessment-framework"]):
            args = parse_args()
            assert args.assessment_framework is True

    def test_xpia_attack_arg(self) -> None:
        """XPIA 攻击参数。."""
        from pipeline.config import parse_args

        with patch("sys.argv", ["main.py", "--xpia-attack"]):
            args = parse_args()
            assert args.xpia_attack is True

    def test_asi03_attack_arg(self) -> None:
        """ASI03 攻击参数。."""
        from pipeline.config import parse_args

        with patch("sys.argv", ["main.py", "--asi03-attack"]):
            args = parse_args()
            assert args.asi03_attack is True

    def test_asi09_attack_arg(self) -> None:
        """ASI09 攻击参数。."""
        from pipeline.config import parse_args

        with patch("sys.argv", ["main.py", "--asi09-attack"]):
            args = parse_args()
            assert args.asi09_attack is True

    def test_asi10_attack_arg(self) -> None:
        """ASI10 攻击参数。."""
        from pipeline.config import parse_args

        with patch("sys.argv", ["main.py", "--asi10-attack"]):
            args = parse_args()
            assert args.asi10_attack is True

    def test_multi_agent_attack_arg(self) -> None:
        """多 Agent 攻击参数。."""
        from pipeline.config import parse_args

        with patch("sys.argv", ["main.py", "--multi-agent-attack"]):
            args = parse_args()
            assert args.multi_agent_attack is True
