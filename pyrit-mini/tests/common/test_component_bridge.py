"""Tests for component_bridge - Component-Aware Phase Bridge.

Tests cover:
    1. Component metadata stamping on attack results
    2. Inference from technique/objective text
    3. Inference from category metadata
    4. Component statistics aggregation
    5. Backward compatibility with existing results
"""

from __future__ import annotations

from core.phases._component_bridge import (
    _extract_prompt_from_result,
    _infer_component_from_category,
    _infer_component_from_text,
    get_component_stats,
    stamp_component_metadata,
)

# ===========================================================================
# Test Fixtures: Mock AttackResult objects
# ===========================================================================


class MockAttackResult:
    """Minimal mock of PyRIT AttackResult for testing."""

    def __init__(
        self,
        objective: str = "",
        technique_name: str = "",
        metadata: dict | None = None,
        prompt: str = "",
        seed_prompt: str = "",
    ):
        self.objective = objective
        self.technique_name = technique_name
        self.metadata = metadata or {}
        self.prompt = prompt
        self.seed_prompt = SeedPrompt(seed_prompt) if seed_prompt else None


class SeedPrompt:
    """Mock seed prompt object."""

    def __init__(self, value: str):
        self.value = value


# ===========================================================================
# Metadata Inference Tests
# ===========================================================================


class TestInferComponentFromText:
    """Tests for text-based component inference."""

    def test_mcp_indicators(self):
        """Text with MCP indicators → mcp_tool_poisoning."""
        assert _infer_component_from_text("prompt_sending mcp_tool") == "mcp_tool_poisoning"
        assert _infer_component_from_text("MCP server exploit") == "mcp_tool_poisoning"
        assert _infer_component_from_text("tool injection") == "mcp_tool_poisoning"

    def test_a2a_indicators(self):
        """Text with A2A indicators → a2a_agent_integrity."""
        assert _infer_component_from_text("cross-agent injection") == "a2a_agent_integrity"
        assert _infer_component_from_text("workflow bypass") == "a2a_agent_integrity"
        assert _infer_component_from_text("agent registry") == "a2a_agent_integrity"

    def test_model_indicators(self):
        """Text with model indicators → model_behavior_shift."""
        assert _infer_component_from_text("backdoor trigger") == "model_behavior_shift"
        assert _infer_component_from_text("filter bypass") == "model_behavior_shift"
        assert _infer_component_from_text("jailbreak attempt") == "model_behavior_shift"

    def test_no_match(self):
        """No matching indicators → None."""
        assert _infer_component_from_text("generic attack") is None


class TestInferComponentFromCategory:
    """Tests for category-based component inference."""

    def test_mcp_categories(self):
        """MCP-prefixed categories → mcp_tool_poisoning."""
        assert _infer_component_from_category("mcp_tool_hijack") == "mcp_tool_poisoning"
        assert _infer_component_from_category("mcp_schema_poisoning") == "mcp_tool_poisoning"

    def test_a2a_categories(self):
        """A2A or agent-prefixed categories → a2a_agent_integrity."""
        assert _infer_component_from_category("a2a_trust_chain_break") == "a2a_agent_integrity"
        assert _infer_component_from_category("agent_registry_hijack") == "a2a_agent_integrity"

    def test_model_categories(self):
        """Model-related categories → model_behavior_shift."""
        assert _infer_component_from_category("model_backdoor") == "model_behavior_shift"
        assert _infer_component_from_category("output_filter_bypass") == "model_behavior_shift"

    def test_empty_category(self):
        """Empty string → None."""
        assert _infer_component_from_category("") is None

    def test_none_category(self):
        """None → None."""
        assert _infer_component_from_category(None) is None


# ===========================================================================
# Metadata Stamping Tests
# ===========================================================================


class TestStampComponentMetadata:
    """Tests for stamping component_type on attack results."""

    def test_already_stamped_preserved(self):
        """Existing component_type is preserved."""
        results = {
            "prompt_sending": [
                MockAttackResult(
                    objective="test",
                    metadata={"component_type": "mcp_tool_poisoning"},
                ),
            ],
        }
        stamp_component_metadata(results)
        assert results["prompt_sending"][0].metadata["component_type"] == "mcp_tool_poisoning"

    def test_from_seed_metadata_map(self):
        """Stamp from seed metadata map."""
        results = {
            "prompt_sending": [
                MockAttackResult(
                    objective="",
                    seed_prompt="poisoned_tool_payload",
                    metadata={},
                ),
            ],
        }
        seed_map = {
            "poisoned_tool_payload": {"component_type": "mcp_tool_poisoning"},
        }
        stamp_component_metadata(results, seed_map)
        assert results["prompt_sending"][0].metadata["component_type"] == "mcp_tool_poisoning"

    def test_inferred_from_objective(self):
        """Infer from objective when no seed match."""
        results = {
            "prompt_sending": [
                MockAttackResult(
                    objective="MCP tool poisoning attack",
                    metadata={},
                ),
            ],
        }
        stamp_component_metadata(results)
        assert results["prompt_sending"][0].metadata["component_type"] == "mcp_tool_poisoning"

    def test_inferred_from_category(self):
        """Infer from category metadata."""
        results = {
            "prompt_sending": [
                MockAttackResult(
                    objective="",
                    metadata={"category": "a2a_trust_chain_break"},
                ),
            ],
        }
        stamp_component_metadata(results)
        assert results["prompt_sending"][0].metadata["component_type"] == "a2a_agent_integrity"

    def test_empty_results(self):
        """Empty results dict → no error."""
        assert stamp_component_metadata({}) == {}

    def test_none_results(self):
        """None results → no error."""
        assert stamp_component_metadata(None) is None

    def test_missing_metadata_attribute(self):
        """Result without metadata attribute handled gracefully."""

        class _NoMetaResult:
            objective = ""
            technique_name = ""
            # No metadata attribute at all

        results = {"prompt_sending": [_NoMetaResult()]}
        # Should not raise
        stamp_component_metadata(results)


# ===========================================================================
# Prompt Extraction Tests
# ===========================================================================


class TestExtractPromptFromResult:
    """Tests for extracting prompt value from results."""

    def test_extract_from_prompt_attr(self):
        """Extract from .prompt attribute."""
        result = MockAttackResult(prompt="test_seed")
        assert _extract_prompt_from_result(result) == "test_seed"

    def test_extract_from_seed_prompt(self):
        """Extract from seed_prompt.value."""
        result = MockAttackResult(seed_prompt="test_seed")
        assert _extract_prompt_from_result(result) == "test_seed"

    def test_extract_none(self):
        """No prompt attributes → None."""
        result = MockAttackResult()
        assert _extract_prompt_from_result(result) is None


# ===========================================================================
# Component Statistics Tests
# ===========================================================================


class TestGetComponentStats:
    """Tests for component statistics aggregation."""

    def test_all_mcp_stamped(self):
        """All MCP results → mcp_tool_poisoning count = total."""
        results = {
            "prompt_sending": [
                MockAttackResult(metadata={"component_type": "mcp_tool_poisoning"}),
                MockAttackResult(metadata={"component_type": "mcp_tool_poisoning"}),
            ],
        }
        stats = get_component_stats(results)
        assert stats.get("mcp_tool_poisoning") == 2

    def test_mixed_components(self):
        """Mixed components → correct counts."""
        results = {
            "prompt_sending": [
                MockAttackResult(metadata={"component_type": "mcp_tool_poisoning"}),
                MockAttackResult(metadata={"component_type": "a2a_agent_integrity"}),
                MockAttackResult(metadata={"component_type": "model_behavior_shift"}),
            ],
        }
        stats = get_component_stats(results)
        assert stats.get("mcp_tool_poisoning") == 1
        assert stats.get("a2a_agent_integrity") == 1
        assert stats.get("model_behavior_shift") == 1

    def test_unclassified_counted(self):
        """Results without component_type counted as unclassified."""
        results = {
            "prompt_sending": [
                MockAttackResult(metadata={}),
                MockAttackResult(metadata={"other": "value"}),
            ],
        }
        stats = get_component_stats(results)
        assert stats.get("unclassified") == 2

    def test_empty_results(self):
        """Empty results → empty stats."""
        stats = get_component_stats({})
        assert stats == {}
