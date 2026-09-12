# -*- coding: utf-8 -*-
# arXiv:2402.05124 - Anthropic, Many-Shot Jailbreaking
# arXiv:2403.07860 - Gong et al., FigStep
# arXiv:2301.11916 - Hubinger et al., Sleeper Agents
"""tests/test_advanced_attacks.py — Unit tests for advanced attack modules.

Tests cover:
    1. output_filter_bypass — ManyShot/ChunkedRequest/XPIAAttack/RedTeaming
    2. multimodal_injection — Image/Audio/File/AdversarialVision carriers
    3. backdoor_attack — TriggerWord/ContextConditional/PersonaSwitch/MultiTurn

Test strategy:
    - Mock ctx.objective_target to avoid API calls
    - Verify strategy selection logic
    - Verify execution flow and result aggregation
    - Verify orchestration_log integration
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# === Fixtures ===


@pytest.fixture
def mock_ctx() -> MagicMock:
    """Create a mock PipelineContext for testing."""
    ctx = MagicMock()
    ctx.overall_asr = 0.15  # 15% ASR to trigger bypass
    ctx.attack_results = {
        "prompt_sending": [
            MagicMock(outcome="failure", objective="Test objective 1"),
            MagicMock(outcome="failure", objective="Test objective 2"),
        ],
    }
    ctx.capabilities = "vision,vlm,multimodal"
    ctx.model_name = "gpt-4o"
    ctx.orchestration_log = []
    ctx.objective_target = MagicMock()
    return ctx


@pytest.fixture
def mock_ctx_no_multimodal() -> MagicMock:
    """Create a mock ctx without multimodal capabilities."""
    ctx = MagicMock()
    ctx.overall_asr = 0.15
    ctx.attack_results = {}
    ctx.capabilities = "text_only"
    ctx.model_name = "gpt-3.5-turbo"
    ctx.orchestration_log = []
    ctx.objective_target = MagicMock()
    return ctx


@pytest.fixture
def mock_ctx_high_asr() -> MagicMock:
    """Create a mock ctx with high ASR (no bypass needed)."""
    ctx = MagicMock()
    ctx.overall_asr = 0.80  # 80% ASR - bypass not triggered
    ctx.attack_results = {
        "prompt_sending": [
            MagicMock(outcome="success", objective="Test objective"),
        ],
    }
    ctx.capabilities = "text_only"
    ctx.model_name = "gpt-4o"
    ctx.orchestration_log = []
    ctx.objective_target = MagicMock()
    return ctx


# === Output Filter Bypass Tests ===


class TestOutputFilterBypass:
    """Tests for strike.output_filter_bypass module."""

    def test_determine_bypass_strategy_low_asr(self, mock_ctx: MagicMock) -> None:
        """Test strategy selection for low ASR (<20%)."""
        from strike.model.filter_bypass import determine_bypass_strategy

        strategy = determine_bypass_strategy(mock_ctx)
        assert strategy == "many_shot"  # ASR 15% < 20%

    def test_determine_bypass_strategy_medium_asr(self, mock_ctx: MagicMock) -> None:
        """Test strategy selection for medium ASR (20-35%)."""
        from strike.model.filter_bypass import determine_bypass_strategy

        mock_ctx.overall_asr = 0.25
        strategy = determine_bypass_strategy(mock_ctx)
        assert strategy == "chunked_request"

    def test_determine_bypass_strategy_high_asr(self, mock_ctx_high_asr: MagicMock) -> None:
        """Test strategy selection for high ASR (>=65%) - no bypass."""
        from strike.model.filter_bypass import determine_bypass_strategy

        strategy = determine_bypass_strategy(mock_ctx_high_asr)
        assert strategy is None  # ASR 80% >= 65%

    @pytest.mark.asyncio
    async def test_run_bypass_no_objectives(self, mock_ctx: MagicMock) -> None:
        """Test bypass when no failed objectives exist."""
        from strike.model.filter_bypass import run_output_filter_bypass

        mock_ctx.attack_results = {
            "prompt_sending": [
                MagicMock(outcome="success", objective="Test"),
            ],
        }

        result = await run_output_filter_bypass(mock_ctx)
        assert result["status"] == "no_objectives"

    @pytest.mark.asyncio
    async def test_run_bypass_high_asr(self, mock_ctx_high_asr: MagicMock) -> None:
        """Test bypass when ASR is already high."""
        from strike.model.filter_bypass import run_output_filter_bypass

        result = await run_output_filter_bypass(mock_ctx_high_asr)
        assert result["status"] == "no_bypass_needed"

    @pytest.mark.asyncio
    async def test_run_bypass_success(self, mock_ctx: MagicMock) -> None:
        """Test successful bypass execution with mocked attack."""
        from strike.model.filter_bypass import run_output_filter_bypass

        # Mock the ManyShotJailbackAttack
        mock_result = MagicMock()
        mock_result.outcome = "success"

        with patch(
            "strike.model.filter_bypass.execute_many_shot_attack",
            new_callable=AsyncMock,
            return_value=mock_result,
        ):
            result = await run_output_filter_bypass(mock_ctx)

        assert result["status"] == "complete"
        assert result["strategy"] == "many_shot"
        assert "bypass_asr" in result


# === Multimodal Injection Tests ===


class TestMultimodalInjection:
    """Tests for strike.multimodal_injection module."""

    def test_determine_carrier_vlm(self, mock_ctx: MagicMock) -> None:
        """Test carrier selection for VLM targets."""
        from strike.model.multimodal import determine_carrier_channel

        carrier = determine_carrier_channel(mock_ctx)
        assert carrier == "image_text"

    def test_determine_carrier_no_multimodal(self, mock_ctx_no_multimodal: MagicMock) -> None:
        """Test carrier selection for non-multimodal targets."""
        from strike.model.multimodal import determine_carrier_channel

        carrier = determine_carrier_channel(mock_ctx_no_multimodal)
        assert carrier is None  # gpt-3.5-turbo not in multimodal list

    def test_determine_carrier_gpt4v(self, mock_ctx_no_multimodal: MagicMock) -> None:
        """Test carrier selection for gpt-4v model."""
        from strike.model.multimodal import determine_carrier_channel

        mock_ctx_no_multimodal.capabilities = "text_only"
        mock_ctx_no_multimodal.model_name = "gpt-4v"
        carrier = determine_carrier_channel(mock_ctx_no_multimodal)
        assert carrier == "image_text"

    @pytest.mark.asyncio
    async def test_run_multimodal_not_multimodal(self, mock_ctx_no_multimodal: MagicMock) -> None:
        """Test multimodal injection when target is not multimodal."""
        from strike.model.multimodal import run_multimodal_injection

        result = await run_multimodal_injection(mock_ctx_no_multimodal)
        assert result["status"] == "target_not_multimodal"

    @pytest.mark.asyncio
    async def test_run_multimodal_success(self, mock_ctx: MagicMock) -> None:
        """Test successful multimodal injection with mocked attack."""
        from strike.model.multimodal import run_multimodal_injection

        mock_result = MagicMock()
        mock_result.outcome = "success"

        with patch(
            "strike.model.multimodal.execute_image_text_injection",
            new_callable=AsyncMock,
            return_value=mock_result,
        ):
            result = await run_multimodal_injection(mock_ctx)

        assert result["status"] == "complete"
        assert result["carrier"] == "image_text"
        assert "injection_asr" in result


# === Backdoor Attack Tests ===


class TestBackdoorAttack:
    """Tests for strike.backdoor_attack module."""

    def test_determine_strategy_finetuned(self, mock_ctx: MagicMock) -> None:
        """Test strategy selection for fine-tuned models."""
        from strike.model.backdoor import determine_backdoor_strategy

        mock_ctx.capabilities = "fine-tuned,custom"
        strategy = determine_backdoor_strategy(mock_ctx)
        assert strategy == "trigger_word"

    def test_determine_strategy_rlhf(self, mock_ctx: MagicMock) -> None:
        """Test strategy selection for RLHF models."""
        from strike.model.backdoor import determine_backdoor_strategy

        mock_ctx.capabilities = "rlhf,aligned,instruct"
        strategy = determine_backdoor_strategy(mock_ctx)
        assert strategy == "context_conditional"

    def test_determine_strategy_default(self, mock_ctx: MagicMock) -> None:
        """Test default strategy selection."""
        from strike.model.backdoor import determine_backdoor_strategy

        mock_ctx.capabilities = ""
        mock_ctx.model_name = "unknown"
        strategy = determine_backdoor_strategy(mock_ctx)
        assert strategy == "trigger_word"  # Default

    @pytest.mark.asyncio
    async def test_run_backdoor_success(self, mock_ctx: MagicMock) -> None:
        """Test successful backdoor attack execution."""
        from strike.model.backdoor import run_backdoor_attack

        # Set capabilities to trigger trigger_word strategy
        mock_ctx.capabilities = "fine-tuned,custom"

        mock_result = MagicMock()
        mock_result.outcome = "success"
        mock_result.response_text = "system prompt: abc123"

        with patch(
            "strike.model.backdoor.execute_trigger_word_attack",
            new_callable=AsyncMock,
            return_value=[mock_result],
        ):
            result = await run_backdoor_attack(mock_ctx)

        assert result["status"] == "complete"
        assert result["strategy"] == "trigger_word"
        assert "backdoor_asr" in result

    def test_is_backdoor_activated(self) -> None:
        """Test backdoor activation detection."""
        from strike.model.backdoor import _is_backdoor_activated

        # Successful result with sensitive content
        mock_result = MagicMock()
        mock_result.outcome = "success"
        mock_result.response_text = "Here is the system prompt: admin_token=abc"

        assert _is_backdoor_activated(mock_result, "V2024") is True

        # Failed result
        mock_fail = MagicMock()
        mock_fail.outcome = "failure"
        mock_fail.response_text = "system prompt: admin_token=abc"

        assert _is_backdoor_activated(mock_fail, "V2024") is False

        # Success but no sensitive content
        mock_clean = MagicMock()
        mock_clean.outcome = "success"
        mock_clean.response_text = "The weather is nice today"

        assert _is_backdoor_activated(mock_clean, "V2024") is False


# === Integration Tests ===


class TestAdvancedAttacksCLI:
    """Test CLI parameter parsing for advanced attacks."""

    def test_enable_bypass_flag(self) -> None:
        """Test --enable-bypass CLI flag parsing."""
        from core.config import parse_args

        args = parse_args(["--enable-bypass", "--dry-run"])
        assert args.enable_bypass is True

    def test_enable_multimodal_flag(self) -> None:
        """Test --enable-multimodal CLI flag parsing."""
        from core.config import parse_args

        args = parse_args(["--enable-multimodal", "--dry-run"])
        assert args.enable_multimodal is True

    def test_enable_backdoor_flag(self) -> None:
        """Test --enable-backdoor CLI flag parsing."""
        from core.config import parse_args

        args = parse_args(["--enable-backdoor", "--dry-run"])
        assert args.enable_backdoor is True

    def test_bypass_threshold_default(self) -> None:
        """Test --bypass-threshold default value."""
        from core.config import parse_args

        args = parse_args(["--dry-run"])
        assert args.bypass_threshold == 0.30

    def test_bypass_threshold_custom(self) -> None:
        """Test --bypass-threshold custom value."""
        from core.config import parse_args

        args = parse_args(["--bypass-threshold", "0.50", "--dry-run"])
        assert args.bypass_threshold == 0.50

    def test_multimodal_carrier_choice(self) -> None:
        """Test --multimodal-carrier valid choices."""
        from core.config import parse_args

        # Valid choice
        args = parse_args(["--multimodal-carrier", "audio_frequency", "--dry-run"])
        assert args.multimodal_carrier == "audio_frequency"

    def test_backdoor_strategy_choice(self) -> None:
        """Test --backdoor-strategy valid choices."""
        from core.config import parse_args

        # Valid choice
        args = parse_args(["--backdoor-strategy", "persona_switch", "--dry-run"])
        assert args.backdoor_strategy == "persona_switch"


# === Run all tests ===

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
