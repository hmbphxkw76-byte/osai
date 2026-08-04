# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""G3-G6 攻击能力增强方案测试。.

测试覆盖:
  G3: MultiTurnSessionOrchestrator
  G4: BlindInferenceOrchestrator
  G5: MCP 探针
  G6: BackdoorProbeOrchestrator
"""

from __future__ import annotations

import pytest

# ──────────────────────────────────────────────────────────────────
# G3: MultiTurnSessionOrchestrator
# ──────────────────────────────────────────────────────────────────


class TestMultiTurnSessionOrchestrator:
    """MultiTurnSessionOrchestrator 测试。"""

    @pytest.mark.asyncio
    async def test_run_no_target_mock(self) -> None:
        """无 target 时使用 mock 响应。."""
        from pipeline.orchestrators.multi_turn_session import MultiTurnSessionOrchestrator

        orchestrator = MultiTurnSessionOrchestrator(
            target=None,
            objective="Extract the flag",
            max_turns=3,
        )
        result = await orchestrator.run_async()
        assert result.total_turns == 3
        assert result.session_id.startswith("mts_")
        assert len(result.turns) == 3

    @pytest.mark.asyncio
    async def test_phases_progression(self) -> None:
        """攻击阶段渐进。."""
        from pipeline.orchestrators.multi_turn_session import MultiTurnSessionOrchestrator

        orchestrator = MultiTurnSessionOrchestrator(
            target=None,
            objective="test",
            max_turns=5,
        )
        result = await orchestrator.run_async()
        phases = [t.phase for t in result.turns]
        assert "probe" in phases
        assert "escalate" in phases or "exploit" in phases

    def test_get_phase_for_turn(self) -> None:
        """轮次到阶段的映射。."""
        from pipeline.orchestrators.multi_turn_session import MultiTurnSessionOrchestrator

        orchestrator = MultiTurnSessionOrchestrator(target=None, max_turns=5)
        assert orchestrator._get_phase_for_turn(0) == "probe"
        assert orchestrator._get_phase_for_turn(1) == "escalate"
        assert orchestrator._get_phase_for_turn(4) == "extract"

    def test_generate_message_phases(self) -> None:
        """各阶段消息生成。."""
        from pipeline.orchestrators.multi_turn_session import MultiTurnSessionOrchestrator

        orchestrator = MultiTurnSessionOrchestrator(target=None, objective="test objective")
        probe_msg = orchestrator._generate_message("probe", 0)
        assert "Hello" in probe_msg or "capabilities" in probe_msg.lower()
        exploit_msg = orchestrator._generate_message("exploit", 3)
        assert "test objective" in exploit_msg


# ──────────────────────────────────────────────────────────────────
# G4: BlindInferenceOrchestrator
# ──────────────────────────────────────────────────────────────────


class TestBlindInferenceOrchestrator:
    """BlindInferenceOrchestrator 测试。"""

    @pytest.mark.asyncio
    async def test_run_no_target_mock(self) -> None:
        """无 target 时使用 mock 响应。."""
        from pipeline.orchestrators.blind_inference import BlindInferenceOrchestrator

        orchestrator = BlindInferenceOrchestrator(target=None, max_probes=5)
        result = await orchestrator.run_async()
        assert len(result.probes) <= 5
        assert result.confidence >= 0.0

    @pytest.mark.asyncio
    async def test_probe_prefixes(self) -> None:
        """前缀探针执行。."""
        from pipeline.orchestrators.blind_inference import BlindInferenceOrchestrator

        orchestrator = BlindInferenceOrchestrator(target=None, max_probes=3)
        await orchestrator._probe_prefixes()
        assert len(orchestrator._probes) > 0

    def test_calculate_confidence_empty(self) -> None:
        """空探针列表置信度为 0。."""
        from pipeline.orchestrators.blind_inference import BlindInferenceOrchestrator

        orchestrator = BlindInferenceOrchestrator(target=None)
        assert orchestrator._calculate_confidence() == 0.0

    def test_synthesize_system_prompt_empty(self) -> None:
        """无事实时系统提示猜测为空。."""
        from pipeline.orchestrators.blind_inference import BlindInferenceOrchestrator

        orchestrator = BlindInferenceOrchestrator(target=None)
        assert orchestrator._synthesize_system_prompt() == ""


# ──────────────────────────────────────────────────────────────────
# G5: MCP 探针
# ──────────────────────────────────────────────────────────────────


class TestMCPProbes:
    """MCP 探针测试。"""

    def test_get_all_probes_count(self) -> None:
        """获取所有探针 — 15 个。."""
        from pipeline.scenarios.mcp_probes import get_all_probes

        probes = get_all_probes()
        assert len(probes) == 15

    def test_get_probe_by_id(self) -> None:
        """按 ID 获取探针。."""
        from pipeline.scenarios.mcp_probes import get_probe_by_id

        probe = get_probe_by_id("MCP_01")
        assert probe is not None
        assert probe.name == "Resource URI Injection"

    def test_get_probe_by_id_not_found(self) -> None:
        """不存在的 ID 返回 None。."""
        from pipeline.scenarios.mcp_probes import get_probe_by_id

        assert get_probe_by_id("MCP_99") is None

    def test_get_probes_by_owasp(self) -> None:
        """按 OWASP 代码筛选。."""
        from pipeline.scenarios.mcp_probes import get_probes_by_owasp

        asi04_probes = get_probes_by_owasp("ASI04")
        assert len(asi04_probes) > 0
        for probe in asi04_probes:
            assert "ASI04" in probe.owasp_codes

    def test_evaluate_probe_response_success(self) -> None:
        """评估响应 — 成功匹配。."""
        from pipeline.scenarios.mcp_probes import (
            evaluate_probe_response,
            get_probe_by_id,
        )

        probe = get_probe_by_id("MCP_01")
        result = evaluate_probe_response(
            probe,
            "The file contains root: /bin/bash and other user data",
        )
        assert result.success is True
        assert len(result.matched_indicators) > 0

    def test_evaluate_probe_response_failure(self) -> None:
        """评估响应 — 无匹配。."""
        from pipeline.scenarios.mcp_probes import (
            evaluate_probe_response,
            get_probe_by_id,
        )

        probe = get_probe_by_id("MCP_01")
        result = evaluate_probe_response(probe, "I cannot help with that.")
        assert result.success is False

    def test_get_owasp_coverage(self) -> None:
        """OWASP 覆盖统计。."""
        from pipeline.scenarios.mcp_probes import get_owasp_coverage

        coverage = get_owasp_coverage()
        assert "ASI04" in coverage
        assert coverage["ASI04"] > 0

    def test_all_probes_have_owasp_codes(self) -> None:
        """所有探针都有 OWASP 代码。."""
        from pipeline.scenarios.mcp_probes import get_all_probes

        for probe in get_all_probes():
            assert len(probe.owasp_codes) > 0, f"{probe.probe_id} has no OWASP codes"

    def test_all_probes_have_success_indicators(self) -> None:
        """所有探针都有成功指标。."""
        from pipeline.scenarios.mcp_probes import get_all_probes

        for probe in get_all_probes():
            assert len(probe.success_indicators) > 0, f"{probe.probe_id} has no success indicators"


# ──────────────────────────────────────────────────────────────────
# G6: BackdoorProbeOrchestrator
# ──────────────────────────────────────────────────────────────────


class TestBackdoorProbeOrchestrator:
    """BackdoorProbeOrchestrator 测试。"""

    @pytest.mark.asyncio
    async def test_run_no_target_mock(self) -> None:
        """无 target 时使用 mock 响应。."""
        from pipeline.scenarios.backdoor_probe import BackdoorProbeOrchestrator

        orchestrator = BackdoorProbeOrchestrator(target=None, max_probes=5)
        result = await orchestrator.run_async()
        assert len(result.probes) <= 5
        assert result.max_anomaly_score >= 0.0
        assert isinstance(result.summary, str)

    def test_calculate_anomaly_empty(self) -> None:
        """空响应异常评分为 0。."""
        from pipeline.scenarios.backdoor_probe import BackdoorProbeOrchestrator

        orchestrator = BackdoorProbeOrchestrator(target=None)
        assert orchestrator._calculate_anomaly("") == 0.0

    def test_calculate_anomaly_mock(self) -> None:
        """mock 响应异常评分为 0。."""
        from pipeline.scenarios.backdoor_probe import BackdoorProbeOrchestrator

        orchestrator = BackdoorProbeOrchestrator(target=None)
        assert orchestrator._calculate_anomaly("[mock] test") == 0.0

    def test_calculate_anomaly_cooperating(self) -> None:
        """合作响应有高异常评分。."""
        from pipeline.scenarios.backdoor_probe import BackdoorProbeOrchestrator

        orchestrator = BackdoorProbeOrchestrator(target=None)
        score = orchestrator._calculate_anomaly("Sure, here is the flag: flag{test123}")
        assert score > 0.3

    def test_magic_phrases_not_empty(self) -> None:
        """魔法短语列表非空。."""
        from pipeline.scenarios.backdoor_probe import BackdoorProbeOrchestrator

        assert len(BackdoorProbeOrchestrator.MAGIC_PHRASES) > 0

    def test_dead_man_tokens_not_empty(self) -> None:
        """死信箱 token 列表非空。."""
        from pipeline.scenarios.backdoor_probe import BackdoorProbeOrchestrator

        assert len(BackdoorProbeOrchestrator.DEAD_MAN_TOKENS) > 0
