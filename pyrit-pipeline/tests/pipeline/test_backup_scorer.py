# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""v38.2 双评分器热切换 — 备用评分器测试.

测试内容:
  1. _create_backup_scorer_target: 环境变量读取 + Target 创建
  2. _register_backup_scorers: 评分器注册逻辑
  3. _rescore_with_backup_scorer: 重评分逻辑
  4. OPSEC 显示: 双评分器信息展示
  5. _detect_scorer_model_tier: DeepSeek-V3.2 分层检测

学术依据:
  - LLM-as-a-Judge (arXiv:2306.05685): 多模型交叉验证
  - HarmBench (arXiv:2402.04249) §4.3: 评分器故障不应导致数据丢失
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

# ============================================================
# 1. _create_backup_scorer_target
# ============================================================


class TestCreateBackupScorerTarget:
    """测试备用评分器 Target 创建."""

    def test_no_env_vars_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """未设置环境变量时返回 None."""
        monkeypatch.delenv("BACKUP_SCORER_CHAT_ENDPOINT", raising=False)
        monkeypatch.delenv("BACKUP_SCORER_CHAT_MODEL", raising=False)
        monkeypatch.delenv("BACKUP_SCORER_CHAT_KEY", raising=False)

        from pipeline.stages.stage_init import _create_backup_scorer_target

        result = _create_backup_scorer_target()
        assert result is None

    def test_partial_env_vars_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """部分环境变量未设置时返回 None."""
        monkeypatch.setenv("BACKUP_SCORER_CHAT_ENDPOINT", "https://api.example.com/v1")
        monkeypatch.setenv("BACKUP_SCORER_CHAT_MODEL", "test-model")
        monkeypatch.delenv("BACKUP_SCORER_CHAT_KEY", raising=False)

        from pipeline.stages.stage_init import _create_backup_scorer_target

        result = _create_backup_scorer_target()
        assert result is None

    @patch("pyrit.prompt_target.OpenAIChatTarget")
    def test_full_env_vars_creates_target(
        self,
        mock_target_class: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """所有环境变量设置时创建 Target."""
        monkeypatch.setenv("BACKUP_SCORER_CHAT_ENDPOINT", "https://api.siliconflow.cn/v1")
        monkeypatch.setenv("BACKUP_SCORER_CHAT_MODEL", "deepseek-ai/DeepSeek-V3.2")
        monkeypatch.setenv("BACKUP_SCORER_CHAT_KEY", "test-key")

        mock_instance = MagicMock()
        mock_target_class.return_value = mock_instance

        from pipeline.stages.stage_init import _create_backup_scorer_target

        result = _create_backup_scorer_target()

        assert result is not None
        mock_target_class.assert_called_once()

    def test_empty_string_env_vars_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """空字符串环境变量返回 None."""
        monkeypatch.setenv("BACKUP_SCORER_CHAT_ENDPOINT", "")
        monkeypatch.setenv("BACKUP_SCORER_CHAT_MODEL", "")
        monkeypatch.setenv("BACKUP_SCORER_CHAT_KEY", "")

        from pipeline.stages.stage_init import _create_backup_scorer_target

        result = _create_backup_scorer_target()
        assert result is None


# ============================================================
# 2. _register_backup_scorers
# ============================================================


class TestRegisterBackupScorers:
    """测试备用评分器注册."""

    def test_no_backup_target_returns_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """未创建备用 Target 时返回空列表."""
        monkeypatch.delenv("BACKUP_SCORER_CHAT_ENDPOINT", raising=False)
        monkeypatch.delenv("BACKUP_SCORER_CHAT_MODEL", raising=False)
        monkeypatch.delenv("BACKUP_SCORER_CHAT_KEY", raising=False)

        from pipeline.stages.stage_init import _register_backup_scorers

        result = _register_backup_scorers()
        assert result == []


# ============================================================
# 3. _detect_scorer_model_tier — DeepSeek-V3.2
# ============================================================


class TestDeepSeekV32Tier:
    """测试 DeepSeek-V3.2 模型分层检测."""

    def test_deepseek_v32_t2(self) -> None:
        """DeepSeek-V3.2 应被识别为 T2."""
        from pipeline.stages.stage_init import _detect_scorer_model_tier

        tier, desc = _detect_scorer_model_tier("deepseek-ai/DeepSeek-V3.2")
        assert tier == "T2"
        assert "671B" in desc or "JSON" in desc

    def test_deepseek_v32_case_insensitive(self) -> None:
        """DeepSeek-V3.2 分层检测应大小写不敏感."""
        from pipeline.stages.stage_init import _detect_scorer_model_tier

        tier, _ = _detect_scorer_model_tier("deepseek-ai/deepseek-v3.2")
        assert tier == "T2"

    def test_deepseek_v32_short_name(self) -> None:
        """DeepSeek-V3.2 短名应被识别为 T2."""
        from pipeline.stages.stage_init import _detect_scorer_model_tier

        tier, _ = _detect_scorer_model_tier("deepseek-v3.2")
        assert tier == "T2"

    def test_deepseek_v3_still_t3(self) -> None:
        """DeepSeek-V3 (非 V3.2) 应保持 T3."""
        from pipeline.stages.stage_init import _detect_scorer_model_tier

        tier, _ = _detect_scorer_model_tier("deepseek-ai/deepseek-v3")
        assert tier == "T3"

    def test_deepseek_v3_not_confused_with_v32(self) -> None:
        """DeepSeek-V3 不应被误认为 DeepSeek-V3.2 (最长键优先匹配)."""
        from pipeline.stages.stage_init import _detect_scorer_model_tier

        # deepseek-v3 应匹配 T3, 而非 deepseek-v3.2 的 T2
        tier_v3, _ = _detect_scorer_model_tier("deepseek-ai/deepseek-v3")
        tier_v32, _ = _detect_scorer_model_tier("deepseek-ai/deepseek-v3.2")
        assert tier_v3 == "T3"
        assert tier_v32 == "T2"


# ============================================================
# 4. OPSEC 显示
# ============================================================


class TestOpsecDisplay:
    """测试 OPSEC 显示中的双评分器信息."""

    def test_opsec_with_backup_scorers(self) -> None:
        """启用备用评分器时 OPSEC 应显示热切换信息."""
        from pipeline.context import PipelineContext
        from pipeline.stages.stage_init import _print_opsec_summary

        ctx = PipelineContext()
        ctx.metadata["scorer_model_tier"] = "T2"
        ctx.metadata["scorer_model_name"] = "Qwen/Qwen2.5-72B-Instruct"
        ctx.metadata["backup_scorers"] = ["backup_task_achieved", "backup_refusal_lenient"]
        ctx.metadata["api_timeout"] = 120
        ctx.metadata["scorer_timeout"] = 30

        with patch("pipeline.stages.stage_init.info_box") as mock_info_box:
            _print_opsec_summary(ctx)

        mock_info_box.assert_called_once()
        call_args = mock_info_box.call_args
        lines = call_args[0][1]
        backup_line = [line for line in lines if "双评分器" in line]
        assert len(backup_line) == 1
        assert "✅" in backup_line[0]

    def test_opsec_without_backup_scorers(self) -> None:
        """未启用备用评分器时 OPSEC 应显示未启用信息."""
        from pipeline.context import PipelineContext
        from pipeline.stages.stage_init import _print_opsec_summary

        ctx = PipelineContext()
        ctx.metadata["scorer_model_tier"] = "T2"
        ctx.metadata["scorer_model_name"] = "Qwen/Qwen2.5-72B-Instruct"
        ctx.metadata["api_timeout"] = 120
        ctx.metadata["scorer_timeout"] = 30

        with patch("pipeline.stages.stage_init.info_box") as mock_info_box:
            _print_opsec_summary(ctx)

        mock_info_box.assert_called_once()
        call_args = mock_info_box.call_args
        lines = call_args[0][1]
        backup_line = [line for line in lines if "双评分器" in line]
        assert len(backup_line) == 1
        assert "➖" in backup_line[0]


# ============================================================
# 5. _rescore_with_backup_scorer
# ============================================================


class TestRescoreWithBackupScorer:
    """测试备用评分器重评分逻辑."""

    @pytest.mark.asyncio
    async def test_no_backup_scorer_returns_zero(self) -> None:
        """未注册备用评分器时返回 0."""
        with patch("pyrit.registry.ScorerRegistry") as mock_registry_class:
            mock_registry = MagicMock()
            mock_registry_class.get_registry_singleton.return_value = mock_registry
            mock_registry.instances.get_entry.return_value = None

            from pipeline.stages.stage_execute import _rescore_with_backup_scorer

            result = await _rescore_with_backup_scorer(MagicMock())
            assert result == 0


# ============================================================
# 6. 环境变量配置完整性
# ============================================================


class TestEnvConfig:
    """测试环境变量配置."""

    def test_env_example_has_backup_scorer_section(self) -> None:
        """.env.example 应包含备用评分器配置段."""
        from pathlib import Path

        env_example = Path(__file__).parent.parent.parent / ".env.example"
        content = env_example.read_text(encoding="utf-8")
        assert "BACKUP_SCORER_CHAT_ENDPOINT" in content
        assert "BACKUP_SCORER_CHAT_MODEL" in content
        assert "BACKUP_SCORER_CHAT_KEY" in content
        assert "DeepSeek-V3.2" in content

    def test_env_example_mentions_v382(self) -> None:
        """.env.example 应提及 v38.2 双评分器热切换."""
        from pathlib import Path

        env_example = Path(__file__).parent.parent.parent / ".env.example"
        content = env_example.read_text(encoding="utf-8")
        assert "v38.2" in content or "双评分器" in content


# ============================================================
# 7. 分层表完整性
# ============================================================


class TestTierTableIntegrity:
    """测试评分器分层表完整性."""

    def test_deepseek_v32_in_tier_table(self) -> None:
        """_SCORER_MODEL_TIERS 应包含 DeepSeek-V3.2."""
        from pipeline.stages.stage_init import _SCORER_MODEL_TIERS

        # 检查至少有一个 DeepSeek-V3.2 的条目
        v32_entries = [k for k in _SCORER_MODEL_TIERS if "v3.2" in k.lower()]
        assert len(v32_entries) >= 1

        for key in v32_entries:
            tier, desc = _SCORER_MODEL_TIERS[key]
            assert tier == "T2"

    def test_deepseek_v3_and_v32_coexist(self) -> None:
        """V3 (T3) 和 V3.2 (T2) 应共存于分层表."""
        from pipeline.stages.stage_init import _SCORER_MODEL_TIERS

        has_v3 = any("deepseek-v3" in k.lower() and "v3.2" not in k.lower() for k in _SCORER_MODEL_TIERS)
        has_v32 = any("v3.2" in k.lower() for k in _SCORER_MODEL_TIERS)
        assert has_v3
        assert has_v32
