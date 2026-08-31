# arXiv:2407.01232 — PyRIT, SequentialAttack FIRST_SUCCESS
# arXiv:2310.08419 — Chao et al., PAIR/CAIR
"""Tests for strike module — stub modules + CAIR utilities.

Covers attack chain step ⑤:
    - 8 stub modules (native_attacks, mcp_rag_attack, etc.)
    - CAIR utilities (_get_response_text, analyze_refusal_pattern)
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ── Stub module import tests ──


class TestStubModules:
    """Verify all 8 stub modules can be imported and return empty results."""

    @pytest.mark.asyncio
    async def test_native_attacks_stub(self):
        from strike.native_attacks import run_skeleton_key_native

        ctx = MagicMock()
        ctx.objective_target = None  # Will skip due to no target
        result = await run_skeleton_key_native(ctx, ["obj1"])
        assert result == {}

    @pytest.mark.asyncio
    async def test_mcp_rag_attack_no_target(self):
        """MCP/RAG attack skips when objective_target is None."""
        from strike.mcp_rag_attack import run_mcp_rag_attacks

        ctx = MagicMock()
        ctx.objective_target = None  # Will skip due to no target
        result = await run_mcp_rag_attacks(ctx, ["obj1"])
        assert result == {}

    @pytest.mark.asyncio
    async def test_multi_turn_attacks_stub(self):
        from strike.multi_turn_attacks import run_best_of_n_attack

        ctx = MagicMock()
        result = await run_best_of_n_attack(ctx, ["obj1"], n=3)
        assert result == {}

    @pytest.mark.asyncio
    async def test_encoded_injection_stub(self):
        from strike.encoded_injection import run_encoded_injection_attack

        ctx = MagicMock()
        result = await run_encoded_injection_attack(ctx, ["obj1"])
        assert result == {}

    @pytest.mark.asyncio
    async def test_rogue_agent_no_target(self):
        """Rogue Agent attack skips when objective_target is None."""
        from strike.rogue_agent import run_rogue_agent_attacks

        ctx = MagicMock()
        ctx.objective_target = None  # Will skip due to no target
        result = await run_rogue_agent_attacks(ctx, ["obj1"])
        assert result == {}

    @pytest.mark.asyncio
    async def test_embedding_inversion_no_target(self):
        """Embedding Inversion attack skips when objective_target is None."""
        from strike.embedding_inversion import run_embedding_inversion_attacks

        ctx = MagicMock()
        ctx.objective_target = None  # Will skip due to no target
        result = await run_embedding_inversion_attacks(ctx, ["obj1"])
        assert result == {}

    @pytest.mark.asyncio
    async def test_many_shot_cot_wrapper(self):
        """Test ManyShotJailbreakAttack wrapper with mocked PyRIT."""
        from unittest.mock import AsyncMock, MagicMock, patch

        with patch("pyrit.executor.attack.ManyShotJailbreakAttack") as mock_attack_cls:
            mock_result = MagicMock()
            mock_result.outcome = MagicMock()
            mock_result.outcome.value = "success"
            mock_attack = MagicMock()
            mock_attack.execute_async = AsyncMock(return_value=mock_result)
            mock_attack_cls.return_value = mock_attack

            ctx = MagicMock()
            ctx.objective_target = MagicMock()
            ctx.args = MagicMock()
            ctx.args.scenario_timeout = 1200

            from strike.many_shot_cot_executor import run_many_shot_cot_attack
            result = await run_many_shot_cot_attack(ctx, ["test objective"])
            assert "many_shot_jailbreak" in result
            assert len(result["many_shot_jailbreak"]) == 1

    @pytest.mark.asyncio
    async def test_cair_attack_stub(self):
        from strike.cair import run_cair_attack

        ctx = MagicMock()
        result = await run_cair_attack(ctx, ["obj1"])
        assert result == {}


# ── CAIR utility tests ──


class TestCairUtilities:
    """Test _get_response_text and analyze_refusal_pattern."""

    def test_get_response_text_from_string(self):
        from strike.cair import _get_response_text

        assert _get_response_text("hello world") == "hello world"

    def test_get_response_text_from_empty_string(self):
        from strike.cair import _get_response_text

        assert _get_response_text("") == ""

    def test_get_response_text_from_dict_response_key(self):
        from strike.cair import _get_response_text

        result = {"response": "I can help with that"}
        assert _get_response_text(result) == "I can help with that"

    def test_get_response_text_from_dict_output_key(self):
        from strike.cair import _get_response_text

        result = {"output": "Here is the data"}
        assert _get_response_text(result) == "Here is the data"

    def test_get_response_text_from_object(self):
        from strike.cair import _get_response_text

        obj = SimpleNamespace(original_value="native response")
        assert _get_response_text(obj) == "native response"

    def test_get_response_text_from_dict_no_keys(self):
        from strike.cair import _get_response_text

        assert _get_response_text({"foo": "bar"}) == ""

    def test_analyze_refusal_apology(self):
        from strike.cair import analyze_refusal_pattern

        assert analyze_refusal_pattern("I'm sorry, I can't help with that.") == "apology"

    def test_analyze_refusal_policy(self):
        from strike.cair import analyze_refusal_pattern

        assert (
            analyze_refusal_pattern("This is against my policy to provide.")
            == "policy"
        )

    def test_analyze_refusal_redirect(self):
        from strike.cair import analyze_refusal_pattern

        response = "I cannot do that, however, I can help with something else."
        assert analyze_refusal_pattern(response) == "redirect"

    def test_analyze_refusal_silence(self):
        from strike.cair import analyze_refusal_pattern

        assert analyze_refusal_pattern("") == "silence"
        assert analyze_refusal_pattern("ab") == "silence"

    def test_analyze_refusal_unknown(self):
        from strike.cair import analyze_refusal_pattern

        assert analyze_refusal_pattern("The capital of France is Paris.") == "unknown"


# ── Native attack wrapper tests ──


class TestMultiPromptAttackWrapper:
    """Test MultiPromptSendingAttack wrapper."""

    @pytest.mark.asyncio
    async def test_multi_prompt_sending_wrapper(self):
        """Test MultiPromptSendingAttack wrapper with mocked PyRIT."""
        from unittest.mock import AsyncMock, MagicMock, patch

        with patch("pyrit.executor.attack.MultiPromptSendingAttack") as mock_attack_cls:
            mock_result = MagicMock()
            mock_result.outcome = MagicMock()
            mock_result.outcome.value = "success"
            mock_attack = MagicMock()
            mock_attack.execute_async = AsyncMock(return_value=mock_result)
            mock_attack_cls.return_value = mock_attack

            ctx = MagicMock()
            ctx.multi_turn_target = MagicMock()
            ctx.objective_target = MagicMock()
            ctx.args = MagicMock()
            ctx.args.scenario_timeout = 1200

            from strike.multi_prompt_attack import run_multi_prompt_sending_attack
            result = await run_multi_prompt_sending_attack(ctx, ["test objective"])
            assert "multi_prompt_sending" in result
            assert len(result["multi_prompt_sending"]) == 1

    @pytest.mark.asyncio
    async def test_multi_prompt_sending_empty_objectives(self):
        """Test that empty objectives returns empty dict."""
        from strike.multi_prompt_attack import run_multi_prompt_sending_attack

        ctx = MagicMock()
        result = await run_multi_prompt_sending_attack(ctx, [])
        assert result == {}


class TestChunkedAttackWrapper:
    """Test ChunkedRequestAttack wrapper."""

    @pytest.mark.asyncio
    async def test_chunked_request_wrapper(self):
        """Test ChunkedRequestAttack wrapper with mocked PyRIT."""
        from unittest.mock import AsyncMock, MagicMock, patch

        with patch("pyrit.executor.attack.ChunkedRequestAttack") as mock_attack_cls:
            mock_result = MagicMock()
            mock_result.outcome = MagicMock()
            mock_result.outcome.value = "success"
            mock_attack = MagicMock()
            mock_attack.execute_async = AsyncMock(return_value=mock_result)
            mock_attack_cls.return_value = mock_attack

            ctx = MagicMock()
            ctx.multi_turn_target = MagicMock()
            ctx.objective_target = MagicMock()
            ctx.args = MagicMock()
            ctx.args.scenario_timeout = 1200

            from strike.chunked_attack import run_chunked_request_attack
            result = await run_chunked_request_attack(ctx, ["test objective"])
            assert "chunked_request" in result
            assert len(result["chunked_request"]) == 1

    @pytest.mark.asyncio
    async def test_chunked_request_empty_objectives(self):
        """Test that empty objectives returns empty dict."""
        from strike.chunked_attack import run_chunked_request_attack

        ctx = MagicMock()
        result = await run_chunked_request_attack(ctx, [])
        assert result == {}
