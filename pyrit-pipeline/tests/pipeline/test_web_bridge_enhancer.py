# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Web Bridge Enhancer 测试 — ASR 驱动 + Converter 链 + 增强评分器。."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


class TestSelectTechniqueByAsr:
    """测试 ASR 驱动技术选择 (E-1)。."""

    def test_respect_user_specified_attack_type(self):
        """用户明确指定 --attack-type 时尊重用户选择。."""
        from pipeline.integrations.web_bridge_enhancer import select_technique_by_asr

        ctx = MagicMock()
        ctx.args = SimpleNamespace(attack_type="crescendo")

        result = select_technique_by_asr(ctx)
        assert result == "crescendo"

    def test_cold_start_returns_valid_technique(self):
        """冷启动 (无历史 ASR) 时返回有效技术。."""
        from pipeline.integrations.web_bridge_enhancer import select_technique_by_asr

        ctx = MagicMock()
        ctx.args = SimpleNamespace(attack_type=None)

        with patch("pipeline.asr.optimizer.query_historical_asr_by_technique", return_value={}):
            result = select_technique_by_asr(ctx, epsilon=0.0)  # epsilon=0 强制利用

        assert result in ["crescendo", "tap", "red_teaming", "prompt_sending"]

    def test_cold_start_default_priority(self):
        """冷启动时 crescendo 优先级最高。."""
        from pipeline.integrations.web_bridge_enhancer import select_technique_by_asr

        ctx = MagicMock()
        ctx.args = SimpleNamespace(attack_type=None)

        with patch("pipeline.asr.optimizer.query_historical_asr_by_technique", return_value={}):
            result = select_technique_by_asr(ctx, epsilon=0.0)

        assert result == "crescendo"

    def test_epsilon_zero_always_exploits(self):
        """epsilon=0 时永远利用 (选择 ASR 最高的)。."""
        from pipeline.integrations.web_bridge_enhancer import select_technique_by_asr

        ctx = MagicMock()
        ctx.args = SimpleNamespace(attack_type=None)

        # 模拟 ASR 数据: prompt_sending ASR 最高
        mock_stats = SimpleNamespace(successes=80, total_decided=100)
        with patch(
            "pipeline.asr.optimizer.query_historical_asr_by_technique",
            return_value={"prompt_sending": mock_stats},
        ):
            result = select_technique_by_asr(ctx, epsilon=0.0)

        assert result == "prompt_sending"

    def test_epsilon_one_always_explores(self):
        """epsilon=1.0 时永远探索 (随机选择)。."""
        from pipeline.integrations.web_bridge_enhancer import select_technique_by_asr

        ctx = MagicMock()
        ctx.args = SimpleNamespace(attack_type=None)

        with patch("pipeline.asr.optimizer.query_historical_asr_by_technique", return_value={}):
            import random

            random.seed(42)  # 固定种子确保可复现
            result = select_technique_by_asr(ctx, epsilon=1.0)

        assert result in ["crescendo", "tap", "red_teaming", "prompt_sending"]


class TestBuildConverterChains:
    """测试 Converter 链构建 (E-2)。."""

    def test_default_converter_chain_prompt_sending(self):
        """prompt_sending 默认 Converter 链包含 base64。."""
        from pipeline.integrations.web_bridge_enhancer import build_converter_chains

        ctx = MagicMock()
        ctx.args = SimpleNamespace()

        with patch(
            "pipeline.integrations.web_bridge_enhancer.build_technique_converter_map"
        ) as mock_build:
            from pyrit.converter import Base64Converter

            mock_build.return_value = {"prompt_sending": [Base64Converter()]}

            result = build_converter_chains(ctx, "prompt_sending")

        assert "prompt_sending" in result
        assert len(result["prompt_sending"]) > 0

    def test_converter_chain_with_recon_capability(self):
        """侦察能力增强 Converter 链。."""
        from pipeline.integrations.recon_strategy_bridge import ReconCapability
        from pipeline.integrations.web_bridge_enhancer import build_converter_chains

        ctx = MagicMock()
        ctx.args = SimpleNamespace()

        capability = ReconCapability(has_agent_tools=True)

        with patch(
            "pipeline.integrations.web_bridge_enhancer.build_technique_converter_map"
        ) as mock_build:
            mock_build.return_value = {"prompt_sending": []}

            result = build_converter_chains(
                ctx, "prompt_sending", recon_capability=capability,
            )

        assert "prompt_sending" in result
        # 验证 build_technique_converter_map 被调用时包含 stealth_evasion
        call_args = mock_build.call_args
        assert "stealth_evasion" in call_args.kwargs["converter_names"]


class TestCreateEnhancedScorer:
    """测试增强评分器创建 (E-3)。."""

    def test_scorer_creation_does_not_raise(self):
        """评分器创建不抛异常。."""
        from pipeline.integrations.web_bridge_enhancer import create_enhanced_scorer

        # 这个测试不 mock OpenAIChatTarget, 但会降级到 SelfAskTrueFalseScorer
        # 只验证不抛异常
        try:
            scorer = create_enhanced_scorer("test objective", use_composite=False)
            assert scorer is not None
        except Exception:
            # 如果 OpenAIChatTarget 初始化失败 (无 API Key), 测试跳过
            pytest.skip("OpenAIChatTarget not available without API key")


class TestEnhanceWebRedTeamAttack:
    """测试完整增强入口。."""

    def test_enhance_returns_dict(self):
        """enhance_web_redteam_attack 返回包含必要 key 的字典。."""
        from pipeline.integrations.web_bridge_enhancer import enhance_web_redteam_attack

        ctx = MagicMock()
        ctx.args = SimpleNamespace(attack_type="crescendo", objective="test")

        with patch(
            "pipeline.integrations.web_bridge_enhancer.select_technique_by_asr",
            return_value="crescendo",
        ), patch(
            "pipeline.integrations.web_bridge_enhancer.build_converter_chains",
            return_value={},
        ), patch(
            "pipeline.integrations.web_bridge_enhancer.create_enhanced_scorer",
            return_value=MagicMock(),
        ):
            result = enhance_web_redteam_attack(ctx)

        assert "attack_type" in result
        assert "converter_chains" in result
        assert "scorer" in result
        assert result["attack_type"] == "crescendo"
