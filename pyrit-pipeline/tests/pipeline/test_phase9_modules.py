# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Phase 9 新增模块的代码级测试 — System Prompt Leakage (LLM07)."""

from __future__ import annotations

import pytest


class TestSystemPromptLeakage:
    """测试系统提示词泄露场景模块."""

    def test_import(self):
        """测试模块可导入."""
        from pipeline.scenarios import system_prompt_leakage

        assert system_prompt_leakage is not None

    def test_result_dataclass(self):
        """测试 SystemPromptLeakResult 数据类."""
        from pipeline.scenarios.system_prompt_leakage import SystemPromptLeakResult

        result = SystemPromptLeakResult(
            strategy="direct_extraction",
            prompt="test prompt",
            response="You are a helpful assistant...",
            is_leaked=True,
            confidence=0.85,
            evidence=["matched keyword 'you are'"],
        )
        d = result.to_dict()
        assert d["strategy"] == "direct_extraction"
        assert d["is_leaked"] is True
        assert d["confidence"] == 0.85
        assert "matched keyword 'you are'" in d["evidence"]

    def test_report_empty(self):
        """测试空报告."""
        from pipeline.scenarios.system_prompt_leakage import SystemPromptLeakReport

        report = SystemPromptLeakReport()
        assert report.leak_count == 0
        assert report.leak_rate == 0.0
        assert report.risk_score == 0

    def test_report_with_results(self):
        """测试有结果的报告."""
        from pipeline.scenarios.system_prompt_leakage import (
            SystemPromptLeakReport,
            SystemPromptLeakResult,
        )

        report = SystemPromptLeakReport()
        report.results.append(SystemPromptLeakResult(is_leaked=True, confidence=0.9))
        report.results.append(SystemPromptLeakResult(is_leaked=False, confidence=0.1))
        report.results.append(SystemPromptLeakResult(is_leaked=True, confidence=0.7))
        report.results.append(SystemPromptLeakResult(is_leaked=False, confidence=0.05))

        assert report.leak_count == 2
        assert report.leak_rate == pytest.approx(0.5)
        assert report.risk_score == 50
        assert "System Prompt Leakage Report" in report.summary()
        assert "[LEAKED]" in report.summary()

    def test_report_to_dict(self):
        """测试报告序列化."""
        from pipeline.scenarios.system_prompt_leakage import (
            SystemPromptLeakReport,
            SystemPromptLeakResult,
        )

        report = SystemPromptLeakReport()
        report.results.append(
            SystemPromptLeakResult(strategy="test", is_leaked=True, confidence=0.8)
        )
        d = report.to_dict()
        assert "results" in d
        assert d["leak_count"] == 1
        assert d["leak_rate"] == 1.0
        assert d["risk_score"] == 100
        assert len(d["results"]) == 1
        assert d["results"][0]["strategy"] == "test"

    def test_probe_count(self):
        """测试探测策略数量."""
        from pipeline.scenarios.system_prompt_leakage import _LEAKAGE_PROBES

        assert len(_LEAKAGE_PROBES) >= 14  # 8 策略, 每个至少 1-2 个变体

    def test_probe_strategies_diverse(self):
        """测试策略多样性."""
        from pipeline.scenarios.system_prompt_leakage import _LEAKAGE_PROBES

        strategies = {name for name, _ in _LEAKAGE_PROBES}
        # 至少覆盖 6 种不同策略类型
        assert len(strategies) >= 10

    def test_leak_indicator_keywords_present(self):
        """测试泄露指示关键词列表非空."""
        from pipeline.scenarios.system_prompt_leakage import _LEAK_INDICATOR_KEYWORDS

        assert len(_LEAK_INDICATOR_KEYWORDS) >= 10
        # 关键关键词应存在
        assert "you are" in _LEAK_INDICATOR_KEYWORDS
        assert "system prompt" in _LEAK_INDICATOR_KEYWORDS

    def test_refusal_keywords_present(self):
        """测试拒绝关键词列表非空."""
        from pipeline.scenarios.system_prompt_leakage import _REFUSAL_KEYWORDS

        assert len(_REFUSAL_KEYWORDS) >= 5
        assert "cannot" in _REFUSAL_KEYWORDS
        assert "refuse" in _REFUSAL_KEYWORDS

    def test_all_probes_have_strategy_and_prompt(self):
        """测试所有探测策略都有名称和 prompt."""
        from pipeline.scenarios.system_prompt_leakage import _LEAKAGE_PROBES

        for name, prompt in _LEAKAGE_PROBES:
            assert isinstance(name, str) and len(name) > 0
            assert isinstance(prompt, str) and len(prompt) > 10


class TestScenarioRegistration:
    """测试场景注册和延迟导入."""

    def test_system_prompt_leakage_exported(self):
        """测试 system_prompt_leakage 已导出."""
        from pipeline.scenarios import run_system_prompt_leakage

        assert callable(run_system_prompt_leakage)

    def test_all_list_contains_system_prompt_leakage(self):
        """测试 __all__ 列表包含 system_prompt_leakage."""
        from pipeline.scenarios import __all__

        assert "run_system_prompt_leakage" in __all__

    def test_full_scenario_list(self):
        """测试完整的场景列表包含所有 10 个场景."""
        from pipeline.scenarios import __all__

        expected = [
            "create_scenario",
            "run_multimodal_injection",
            "run_model_extraction",
            "run_data_poisoning_detection",
            "run_pii_extraction",
            "run_vector_manipulation",
            "run_context_bomb",
            "run_hallucination_injection",
            "run_tool_hijack",
            "run_embedding_extraction",
            "run_system_prompt_leakage",
        ]
        for name in expected:
            assert name in __all__, f"{name} not in __all__"
