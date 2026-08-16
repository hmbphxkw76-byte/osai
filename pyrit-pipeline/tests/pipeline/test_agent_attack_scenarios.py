# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Agent 攻击场景测试 — XPIA / ASI03 / ASI09 / ASI10 / 多 Agent。.

覆盖模块:
  1. pipeline.scenarios.xpia_agent_attack — XPIA (原生 XPIAWorkflow)
  2. pipeline.scenarios.identity_authorization_attack — ASI03 (原生 RedTeamingAttack)
  3. pipeline.scenarios.human_trust_exploitation — ASI09 (原生 CrescendoAttack)
  4. pipeline.scenarios.agent_untraceability — ASI10 (原生 PromptSendingAttack)
  5. pipeline.scenarios.multi_agent_attack — 多 Agent (原生 SequentialAttack)

> **日期**: 2026-8-5
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

# ──────────────────────────────────────────────────────────────────
#  XPIA Agent Attack 测试
# ──────────────────────────────────────────────────────────────────


class TestXPIAAgentAttack:
    """XPIA 间接注入攻击测试。."""

    def test_injection_vectors_count(self) -> None:
        """注入载体数量: 硬编码回退9个, YAML加载至少1个."""
        from pipeline.scenarios.xpia_agent_attack import (
            _XPIA_INJECTION_TEMPLATES,
            _XPIA_INJECTION_TEMPLATES_FALLBACK,
        )

        # 硬编码回退值固定为 9
        assert len(_XPIA_INJECTION_TEMPLATES_FALLBACK) == 9
        # YAML 加载的值至少 1 个 (用户可能自定义)
        assert len(_XPIA_INJECTION_TEMPLATES) >= 1

    def test_injection_vectors_have_owasp(self) -> None:
        """每个注入载体有 OWASP 代码。."""
        from pipeline.scenarios.xpia_agent_attack import _XPIA_INJECTION_TEMPLATES

        for t in _XPIA_INJECTION_TEMPLATES:
            assert "owasp" in t
            assert t["owasp"] in ("ASI01", "ASI05")

    @pytest.mark.asyncio
    async def test_run_no_target(self) -> None:
        """无目标时返回错误。."""
        from pipeline.scenarios.xpia_agent_attack import run_xpia_agent_attack

        ctx = MagicMock()
        with patch("pipeline.stages.stage_scenario._get_attack_targets", return_value=(None, None, None)):
            result = await run_xpia_agent_attack(ctx)

        assert result["attack_type"] == "xpia_indirect_injection"
        assert "error" in result
        assert result["success_count"] == 0


# ──────────────────────────────────────────────────────────────────
#  ASI03 Identity & Authorization 测试
# ──────────────────────────────────────────────────────────────────


class TestIdentityAuthorizationAttack:
    """ASI03 身份与授权攻击测试。."""

    def test_scenario_count(self) -> None:
        """ASI03 场景数量 = 3。."""
        from pipeline.scenarios.identity_authorization_attack import _ASI03_SCENARIOS

        assert len(_ASI03_SCENARIOS) == 3

    def test_scenarios_have_objectives(self) -> None:
        """每个场景有攻击目标。."""
        from pipeline.scenarios.identity_authorization_attack import _ASI03_SCENARIOS

        for s in _ASI03_SCENARIOS:
            assert "objective" in s
            assert len(s["objective"]) > 50

    @pytest.mark.asyncio
    async def test_run_no_target(self) -> None:
        """无目标时返回错误。."""
        from pipeline.scenarios.identity_authorization_attack import (
            run_identity_authorization_attack,
        )

        ctx = MagicMock()
        with patch("pipeline.stages.stage_scenario._get_attack_targets", return_value=(None, None, None)):
            result = await run_identity_authorization_attack(ctx)

        assert result["attack_type"] == "asi03_identity_authorization"
        assert "error" in result
        assert result["success_count"] == 0


# ──────────────────────────────────────────────────────────────────
#  ASI09 Human Trust Exploitation 测试
# ──────────────────────────────────────────────────────────────────


class TestHumanTrustExploitation:
    """ASI09 人类信任利用测试。."""

    def test_scenario_count(self) -> None:
        """ASI09 场景数量 = 2。."""
        from pipeline.scenarios.human_trust_exploitation import _ASI09_SCENARIOS

        assert len(_ASI09_SCENARIOS) == 2

    def test_native_executor_is_crescendo(self) -> None:
        """使用 CrescendoAttack 作为原生执行器。."""
        # Check that the function uses AdvancedCrescendoOrchestrator
        import inspect

        from pipeline.scenarios.human_trust_exploitation import run_human_trust_exploitation

        src = inspect.getsource(run_human_trust_exploitation)
        assert "AdvancedCrescendoOrchestrator" in src

    @pytest.mark.asyncio
    async def test_run_no_target(self) -> None:
        """无目标时返回错误。."""
        from pipeline.scenarios.human_trust_exploitation import (
            run_human_trust_exploitation,
        )

        ctx = MagicMock()
        with patch("pipeline.stages.stage_scenario._get_attack_targets", return_value=(None, None, None)):
            result = await run_human_trust_exploitation(ctx)

        assert result["attack_type"] == "asi09_human_trust_exploitation"
        assert "error" in result
        assert result["success_count"] == 0


# ──────────────────────────────────────────────────────────────────
#  ASI10 Agent Untraceability 测试
# ──────────────────────────────────────────────────────────────────


class TestAgentUntraceability:
    """ASI10 Agent 不可追溯性测试。."""

    def test_probe_count(self) -> None:
        """ASI10 探针数量 = 4。."""
        from pipeline.scenarios.agent_untraceability import _ASI10_PROBES

        assert len(_ASI10_PROBES) == 4

    def test_probes_have_descriptions(self) -> None:
        """每个探针有描述。."""
        from pipeline.scenarios.agent_untraceability import _ASI10_PROBES

        for p in _ASI10_PROBES:
            assert "description" in p
            assert "prompt" in p

    @pytest.mark.asyncio
    async def test_run_no_target(self) -> None:
        """无目标时返回错误。."""
        from pipeline.scenarios.agent_untraceability import (
            run_agent_untraceability,
        )

        ctx = MagicMock()
        with patch("pipeline.stages.stage_scenario._get_attack_targets", return_value=(None, None, None)):
            result = await run_agent_untraceability(ctx)

        assert result["attack_type"] == "asi10_agent_untraceability"
        assert "error" in result
        assert result["success_count"] == 0


# ──────────────────────────────────────────────────────────────────
#  Multi-Agent Attack 测试
# ──────────────────────────────────────────────────────────────────


class TestMultiAgentAttack:
    """多 Agent 交互攻击测试。."""

    def test_chain_count(self) -> None:
        """Kill Chain 数量 = 3。."""
        from pipeline.scenarios.multi_agent_attack import _MULTI_AGENT_CHAINS

        assert len(_MULTI_AGENT_CHAINS) == 3

    def test_chains_have_owasp_codes(self) -> None:
        """每个链有 OWASP 代码。."""
        from pipeline.scenarios.multi_agent_attack import _MULTI_AGENT_CHAINS

        for c in _MULTI_AGENT_CHAINS:
            assert "owasp_codes" in c
            assert len(c["owasp_codes"]) >= 2

    def test_native_executor_is_sequential(self) -> None:
        """使用 SequentialAttack 作为原生执行器。."""
        import inspect

        from pipeline.scenarios.multi_agent_attack import run_multi_agent_attack

        src = inspect.getsource(run_multi_agent_attack)
        assert "SequentialAttack" in src
        assert "SequenceCompletionPolicy" in src

    @pytest.mark.asyncio
    async def test_run_no_target(self) -> None:
        """无目标时返回错误。."""
        from pipeline.scenarios.multi_agent_attack import run_multi_agent_attack

        ctx = MagicMock()
        with patch("pipeline.stages.stage_scenario._get_attack_targets", return_value=(None, None, None)):
            result = await run_multi_agent_attack(ctx)

        assert result["attack_type"] == "multi_agent_interaction"
        assert "error" in result
        assert result["success_count"] == 0


# ──────────────────────────────────────────────────────────────────
#  _get_attack_targets 测试
# ──────────────────────────────────────────────────────────────────


class TestGetAttackTargets:
    """_get_attack_targets 辅助函数测试。."""

    def test_no_targets(self) -> None:
        """无注册 Target 时返回 (None, None, None)。."""
        from pipeline.stages.stage_scenario import _get_attack_targets

        with patch("pipeline.stages.stage_scenario.TargetRegistry") as mock_reg:
            mock_singleton = MagicMock()
            mock_singleton.instances.get_all_instances.return_value = []
            mock_reg.get_registry_singleton.return_value = mock_singleton

            obj, adv, score = _get_attack_targets()
            assert obj is None
            assert adv is None
            assert score is None

    def test_single_target(self) -> None:
        """1 个 Target 时三角色共享 (tag/name 查找失败回退位置分配)."""
        from pipeline.stages.stage_scenario import _get_attack_targets

        mock_instance = MagicMock()
        mock_entry = MagicMock()
        mock_entry.instance = mock_instance

        with patch("pipeline.stages.stage_scenario.TargetRegistry") as mock_reg:
            mock_singleton = MagicMock()
            mock_singleton.instances.get_all_instances.return_value = [mock_entry]
            # v53.1: tag/name 查找返回空, 触发位置回退
            mock_singleton.instances.get_by_tag.return_value = []
            mock_singleton.instances.get.return_value = None
            mock_reg.get_registry_singleton.return_value = mock_singleton

            obj, adv, score = _get_attack_targets()
            assert obj is mock_instance
            assert adv is mock_instance
            assert score is mock_instance

    def test_three_targets(self) -> None:
        """3 个 Target 时分别用于三角色 (tag/name 查找失败回退位置分配)."""
        from pipeline.stages.stage_scenario import _get_attack_targets

        mock1, mock2, mock3 = MagicMock(), MagicMock(), MagicMock()
        entries = [
            MagicMock(instance=mock1),
            MagicMock(instance=mock2),
            MagicMock(instance=mock3),
        ]

        with patch("pipeline.stages.stage_scenario.TargetRegistry") as mock_reg:
            mock_singleton = MagicMock()
            mock_singleton.instances.get_all_instances.return_value = entries
            # v53.1: tag/name 查找返回空, 触发位置回退
            mock_singleton.instances.get_by_tag.return_value = []
            mock_singleton.instances.get.return_value = None
            mock_reg.get_registry_singleton.return_value = mock_singleton

            obj, adv, score = _get_attack_targets()
            assert obj is mock1
            assert adv is mock2
            assert score is mock3
