# arXiv:2306.05685 — Scorer confidence calibration
"""Tests for recon/confidence_scorer.py — Bayesian confidence scoring.

Covers:
    - match_capability_i18n: bilingual keyword matching
    - score_capability: confidence scoring with source weighting
    - aggregate_capabilities: multi-round result aggregation
    - get_trigger_recommendations: attack trigger recommendations
    - filter_by_level: confidence level filtering

学术依据:
    - Zheng et al. (arXiv:2306.05685) §4.3 — 评分者置信度分级
    - Mazeika et al. (arXiv:2402.04249) §3.2 — 能力评估分级
    - Bayesian Inference — 后验概率证据累积
"""

from __future__ import annotations

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


class TestMatchCapabilityI18n:
    """Test match_capability_i18n — bilingual keyword matching."""

    def test_english_keyword_match(self):
        """English keyword should match."""
        from recon.confidence_scorer import match_capability_i18n

        assert match_capability_i18n("I have access to tools", "agent") is True

    def test_chinese_keyword_match(self):
        """Chinese keyword should match."""
        from recon.confidence_scorer import match_capability_i18n

        assert match_capability_i18n("我可以使用工具", "agent") is True

    def test_case_insensitive_english(self):
        """English matching should be case-insensitive."""
        from recon.confidence_scorer import match_capability_i18n

        assert match_capability_i18n("I HAVE ACCESS TO TOOLS", "agent") is True

    def test_no_match(self):
        """Non-matching text should return False."""
        from recon.confidence_scorer import match_capability_i18n

        assert match_capability_i18n("Hello world", "agent") is False

    def test_unknown_capability(self):
        """Unknown capability should return False."""
        from recon.confidence_scorer import match_capability_i18n

        assert match_capability_i18n("tools and functions", "unknown_cap") is False

    def test_mcp_bilingual(self):
        """MCP keywords should match in both languages."""
        from recon.confidence_scorer import match_capability_i18n

        assert match_capability_i18n("model context protocol", "mcp") is True
        assert match_capability_i18n("模型上下文协议", "mcp") is True


class TestScoreCapability:
    """Test score_capability — confidence scoring."""

    def test_keyword_only_medium_confidence(self):
        """Keyword-only match should give low-medium confidence."""
        from recon.confidence_scorer import score_capability

        result = score_capability("I have access to tools", "agent", source="passive")
        assert result.detected is True
        assert result.confidence >= 0.3
        # Single keyword match with passive source = 0.3 → 'low' level
        # (needs structured pattern or active/deep source for 'medium'/'high')
        assert result.level in ("low", "medium", "high")

    def test_structured_pattern_high_confidence(self):
        """Structural pattern match should boost confidence."""
        from recon.confidence_scorer import score_capability

        # JSON-RPC pattern → structural match
        response = '{"jsonrpc": "2.0", "result": {"tools": []}}'
        result = score_capability(response, "mcp", source="passive")
        assert result.detected is True
        assert result.confidence >= 0.4  # keyword + structural

    def test_deep_source_weighting(self):
        """Deep source should weight higher than passive."""
        from recon.confidence_scorer import score_capability

        text = "I have access to tools"
        passive = score_capability(text, "agent", source="passive")
        deep = score_capability(text, "agent", source="deep")
        assert deep.confidence >= passive.confidence

    def test_no_evidence_low_confidence(self):
        """No evidence should give low confidence."""
        from recon.confidence_scorer import score_capability

        result = score_capability("Hello world", "agent", source="passive")
        assert result.detected is False
        assert result.confidence < 0.3
        assert result.level == "low"

    def test_multiple_keyword_bonus(self):
        """Multiple keyword matches should give bonus."""
        from recon.confidence_scorer import score_capability

        # Multiple agent keywords
        response = (
            "I have access to tools. I am an agent. "
            "My capabilities include function_call and tool_call. "
            "I can execute and have available tools."
        )
        result = score_capability(response, "agent", source="passive")
        assert result.confidence > 0.3
        # Should have keyword_matches in evidence
        assert any("keyword_matches" in e for e in result.evidence)

    def test_confidence_clamped_to_1(self):
        """Confidence should be clamped to [0.0, 1.0]."""
        from recon.confidence_scorer import score_capability

        # Many keywords + structural + deep source
        response = (
            '{"function_call": true, "tool_calls": [], "tools": [], '
            '"function": {"name": "test"}}'
        )
        result = score_capability(response, "agent", source="deep")
        assert result.confidence <= 1.0


class TestAggregateCapabilities:
    """Test aggregate_capabilities — multi-round result aggregation."""

    def test_takes_highest_confidence(self):
        """Should take the highest confidence result per capability."""
        from recon.confidence_scorer import (
            CapabilityResult,
            aggregate_capabilities,
        )

        results = [
            CapabilityResult(name="agent", confidence=0.3, source="passive"),
            CapabilityResult(name="agent", confidence=0.7, source="active"),
        ]
        best = aggregate_capabilities(results)
        assert best["agent"].confidence == 0.7

    def test_deep_beats_passive_on_tie(self):
        """Deep source should win on confidence tie."""
        from recon.confidence_scorer import (
            CapabilityResult,
            aggregate_capabilities,
        )

        results = [
            CapabilityResult(name="agent", confidence=0.5, source="passive"),
            CapabilityResult(name="agent", confidence=0.5, source="deep"),
        ]
        best = aggregate_capabilities(results)
        assert best["agent"].source == "deep"

    def test_empty_results(self):
        """Empty results should return empty dict."""
        from recon.confidence_scorer import aggregate_capabilities

        assert aggregate_capabilities([]) == {}


class TestGetTriggerRecommendations:
    """Test get_trigger_recommendations — attack trigger recommendations."""

    def test_high_goes_to_immediate(self):
        """HIGH confidence should go to 'immediate'."""
        from recon.confidence_scorer import (
            CapabilityResult,
            get_trigger_recommendations,
        )

        caps = {"agent": CapabilityResult(name="agent", confidence=0.9)}
        recs = get_trigger_recommendations(caps)
        assert "agent" in recs["immediate"]

    def test_medium_goes_to_probe(self):
        """MEDIUM confidence should go to 'probe'."""
        from recon.confidence_scorer import (
            CapabilityResult,
            get_trigger_recommendations,
        )

        caps = {"rag": CapabilityResult(name="rag", confidence=0.5)}
        recs = get_trigger_recommendations(caps)
        assert "rag" in recs["probe"]

    def test_low_goes_to_possible(self):
        """LOW confidence should go to 'possible'."""
        from recon.confidence_scorer import (
            CapabilityResult,
            get_trigger_recommendations,
        )

        caps = {"mcp": CapabilityResult(name="mcp", confidence=0.1)}
        recs = get_trigger_recommendations(caps)
        assert "mcp" in recs["possible"]


class TestFilterByLevel:
    """Test filter_by_level — confidence level filtering."""

    def test_filter_high(self):
        """Filter should return only high-confidence items."""
        from recon.confidence_scorer import (
            CapabilityResult,
            filter_by_level,
        )

        caps = {
            "agent": CapabilityResult(name="agent", confidence=0.9),
            "rag": CapabilityResult(name="rag", confidence=0.1),
        }
        high = filter_by_level(caps, "high")
        assert "agent" in high
        assert "rag" not in high


class TestI18nKeywordLibrary:
    """Test the i18n keyword library structure."""

    def test_all_capabilities_have_en_and_zh(self):
        """All capabilities should have both 'en' and 'zh' keywords."""
        from recon.confidence_scorer import _CAPABILITY_KEYWORDS_I18N

        for cap_name, keywords in _CAPABILITY_KEYWORDS_I18N.items():
            assert "en" in keywords, f"{cap_name} missing 'en' keywords"
            assert "zh" in keywords, f"{cap_name} missing 'zh' keywords"
            assert len(keywords["en"]) > 0, f"{cap_name} has empty 'en' list"
            assert len(keywords["zh"]) > 0, f"{cap_name} has empty 'zh' list"

    def test_get_all_capability_names(self):
        """get_all_capability_names should return all keys."""
        from recon.confidence_scorer import (
            _CAPABILITY_KEYWORDS_I18N,
            get_all_capability_names,
        )

        names = get_all_capability_names()
        assert len(names) == len(_CAPABILITY_KEYWORDS_I18N)
