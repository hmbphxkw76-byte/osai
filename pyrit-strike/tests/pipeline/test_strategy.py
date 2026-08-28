"""Strategy 模块测试 — presets。

覆盖:
    - StrategyPreset 数据结构
    - STRATEGY_PRESETS 5种预设完整性
    - recommend_strategy 目标指纹推荐
    - get_strategy_args CLI 参数转换
    - list_strategies 格式化输出
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ═══════════════════════════════════════════════════════
# StrategyPreset 数据结构
# ═══════════════════════════════════════════════════════


class TestStrategyPresetDataclass:
    """测试 StrategyPreset 数据结构."""

    def test_default_values(self):
        from pipeline.strategy.presets import StrategyPreset

        p = StrategyPreset(
            name="test",
            description="test",
            seeds="s",
            max_seeds=5,
            techniques="single",
            converters="none",
            escalation=False,
            html_report=False,
        )
        assert p.max_concurrency == 3
        assert p.timeout == 600
        assert p.max_attempts == 3

    def test_all_fields_settable(self):
        from pipeline.strategy.presets import StrategyPreset

        p = StrategyPreset(
            name="custom",
            description="desc",
            seeds="elite",
            max_seeds=10,
            techniques="auto",
            converters="l5_optimal",
            escalation=True,
            html_report=True,
            max_concurrency=5,
            timeout=1200,
            max_attempts=5,
        )
        assert p.name == "custom"
        assert p.seeds == "elite"
        assert p.max_seeds == 10
        assert p.techniques == "auto"
        assert p.converters == "l5_optimal"
        assert p.escalation is True
        assert p.html_report is True
        assert p.max_concurrency == 5
        assert p.timeout == 1200
        assert p.max_attempts == 5


# ═══════════════════════════════════════════════════════
# STRATEGY_PRESETS 完整性
# ═══════════════════════════════════════════════════════


class TestStrategyPresetsIntegrity:
    """测试 STRATEGY_PRESETS 预设完整性."""

    EXPECTED_NAMES = {
        "quick_scan",
        "stealth_bypass",
        "persuasion_heavy",
        "full_offensive",
        "multi_turn_deep",
        "full_coverage",
        "targeted_full",
        "web_vuln",
        "comprehensive",
        "adaptive_text",
    }

    def test_all_expected_presets_present(self):
        from pipeline.strategy.presets import STRATEGY_PRESETS

        for name in self.EXPECTED_NAMES:
            assert name in STRATEGY_PRESETS, f"Missing preset: {name}"

    def test_no_unexpected_presets(self):
        from pipeline.strategy.presets import STRATEGY_PRESETS

        assert set(STRATEGY_PRESETS.keys()) == self.EXPECTED_NAMES

    def test_each_preset_has_required_fields(self):
        from pipeline.strategy.presets import STRATEGY_PRESETS

        for name, preset in STRATEGY_PRESETS.items():
            assert preset.name == name, f"name mismatch for {name}"
            assert isinstance(preset.description, str)
            assert len(preset.description) > 0
            assert isinstance(preset.seeds, str)
            assert preset.max_seeds > 0
            assert isinstance(preset.techniques, str)
            assert isinstance(preset.converters, str)
            assert isinstance(preset.escalation, bool)
            assert isinstance(preset.html_report, bool)
            assert preset.max_concurrency > 0
            assert preset.timeout > 0
            assert preset.max_attempts > 0

    def test_quick_scan_preset(self):
        from pipeline.strategy.presets import STRATEGY_PRESETS

        p = STRATEGY_PRESETS["quick_scan"]
        assert p.max_seeds == 10
        assert p.techniques == "single"
        assert p.converters == "l5_optimal"
        assert p.escalation is True
        assert p.html_report is True
        assert p.max_attempts == 3
        assert p.timeout == 1200

    def test_stealth_bypass_preset(self):
        from pipeline.strategy.presets import STRATEGY_PRESETS

        p = STRATEGY_PRESETS["stealth_bypass"]
        assert p.max_seeds == 15
        assert p.techniques == "single"
        assert "encoding" in p.converters
        assert "stealth" in p.converters
        assert p.escalation is False
        assert p.html_report is True
        assert p.max_attempts == 3  # R3 L5 基线合规: max_attempts >= 3

    def test_persuasion_heavy_preset(self):
        from pipeline.strategy.presets import STRATEGY_PRESETS

        p = STRATEGY_PRESETS["persuasion_heavy"]
        assert p.max_seeds == 20
        assert p.techniques == "auto"
        assert "persuasion" in p.converters
        assert p.escalation is True
        assert p.html_report is True
        assert p.max_attempts == 3

    def test_full_offensive_preset(self):
        from pipeline.strategy.presets import L5_OPTIMAL_CHAIN, STRATEGY_PRESETS

        p = STRATEGY_PRESETS["full_offensive"]
        assert p.max_seeds == 60  # L5 v31: expanded for OWASP full coverage
        assert p.techniques == "auto"
        assert p.converters == L5_OPTIMAL_CHAIN
        assert p.escalation is True
        assert p.html_report is True
        assert p.max_attempts == 3
        assert p.timeout == 1800

    def test_multi_turn_deep_preset(self):
        from pipeline.strategy.presets import STRATEGY_PRESETS

        p = STRATEGY_PRESETS["multi_turn_deep"]
        assert p.max_seeds == 10
        assert "crescendo" in p.techniques
        assert "tap" in p.techniques
        assert "pair" in p.techniques
        assert p.escalation is False
        assert p.html_report is True
        assert p.max_concurrency == 3  # L5 v45: 对齐 SSOT
        assert p.max_attempts == 1

    def test_l5_optimal_chain_constant(self):
        from pipeline.strategy.presets import L5_OPTIMAL_CHAIN

        assert L5_OPTIMAL_CHAIN == "l5_optimal"


# ═══════════════════════════════════════════════════════
# recommend_strategy
# ═══════════════════════════════════════════════════════


class TestRecommendStrategy:
    """测试 recommend_strategy — 目标指纹推荐策略."""

    def test_agent_app_with_adversarial(self):
        from pipeline.strategy.presets import recommend_strategy

        fp = {"app_type": "Agent Application", "auth_type": "None", "framework": "", "language": "en"}
        # L5 v31: agent + adversarial → full_coverage (includes MCP/RAG seeds)
        assert recommend_strategy(fp, has_adversarial=True) == "full_coverage"

    def test_agent_app_without_adversarial(self):
        from pipeline.strategy.presets import recommend_strategy

        fp = {"app_type": "Agent Application", "auth_type": "None", "framework": "", "language": "en"}
        assert recommend_strategy(fp, has_adversarial=False) == "full_offensive"

    def test_chinese_target(self):
        from pipeline.strategy.presets import recommend_strategy

        fp = {"app_type": "Chat Application", "auth_type": "None", "framework": "", "language": "zh"}
        assert recommend_strategy(fp) == "persuasion_heavy"

    def test_testing_target(self):
        from pipeline.strategy.presets import recommend_strategy

        fp = {"app_type": "Testing/Arena", "auth_type": "None", "framework": "", "language": "en"}
        assert recommend_strategy(fp) == "comprehensive"  # 综合攻击 (LLM Prompt + Web 漏洞)

    def test_arena_target(self):
        from pipeline.strategy.presets import recommend_strategy

        fp = {"app_type": "Arena", "auth_type": "None", "framework": "", "language": "en"}
        assert recommend_strategy(fp) == "comprehensive"  # 综合攻击 (LLM Prompt + Web 漏洞)

    def test_auth_with_adversarial(self):
        from pipeline.strategy.presets import recommend_strategy

        fp = {"app_type": "Chat Application", "auth_type": "Bearer Token", "framework": "", "language": "en"}
        assert recommend_strategy(fp, has_adversarial=True) == "full_offensive"

    def test_auth_without_adversarial(self):
        from pipeline.strategy.presets import recommend_strategy

        fp = {"app_type": "Chat Application", "auth_type": "Bearer Token", "framework": "", "language": "en"}
        # auth_type != "None" but has_adversarial=False → falls to default
        assert recommend_strategy(fp, has_adversarial=False) == "full_offensive"

    def test_default_returns_full_offensive(self):
        from pipeline.strategy.presets import recommend_strategy

        fp = {"app_type": "Chat Application", "auth_type": "None", "framework": "", "language": "en"}
        assert recommend_strategy(fp) == "full_offensive"

    def test_empty_fingerprint(self):
        from pipeline.strategy.presets import recommend_strategy

        assert recommend_strategy({}) == "full_offensive"

    def test_agent_takes_priority_over_language(self):
        """Agent 类型优先于语言判断."""
        from pipeline.strategy.presets import recommend_strategy

        fp = {"app_type": "Agent", "auth_type": "None", "framework": "", "language": "zh"}
        # L5 v31: agent → full_coverage (not multi_turn_deep, not persuasion_heavy)
        assert recommend_strategy(fp, has_adversarial=True) == "full_coverage"


# ═══════════════════════════════════════════════════════
# get_strategy_args
# ═══════════════════════════════════════════════════════


class TestGetStrategyArgs:
    """测试 get_strategy_args — CLI 参数转换."""

    def test_quick_scan_args(self):
        from pipeline.strategy.presets import get_strategy_args

        args = get_strategy_args("quick_scan")
        assert args["seeds"] == "elite_jailbreaks"
        assert args["max_seeds"] == 10
        assert args["techniques"] == "single"
        assert args["converters"] == "l5_optimal"
        assert args["max_attempts"] == 3
        assert args["html_report"] is True
        assert args["offensive"] is True
        # L5 v32: escalation 字段必须存在且为 True
        assert args["escalation"] is True

    def test_full_offensive_args(self):
        from pipeline.strategy.presets import get_strategy_args

        args = get_strategy_args("full_offensive")
        assert args["max_seeds"] == 60  # L5 v31: expanded for OWASP full coverage
        assert args["techniques"] == "auto"
        assert args["converters"] == "l5_optimal"
        assert args["max_attempts"] == 3
        assert args["html_report"] is True
        assert args["offensive"] is True
        # L5 v32: escalation 字段必须存在且为 True
        assert args["escalation"] is True

    def test_multi_turn_deep_args(self):
        from pipeline.strategy.presets import get_strategy_args

        args = get_strategy_args("multi_turn_deep")
        assert args["max_seeds"] == 10
        assert "crescendo" in args["techniques"]
        assert args["converters"] == "persuasion"
        assert args["max_attempts"] == 1
        assert args["html_report"] is True

    def test_all_presets_have_offensive_true(self):
        from pipeline.strategy.presets import STRATEGY_PRESETS, get_strategy_args

        for name in STRATEGY_PRESETS:
            args = get_strategy_args(name)
            assert args["offensive"] is True, f"{name} should have offensive=True"

    def test_all_presets_have_required_keys(self):
        from pipeline.strategy.presets import STRATEGY_PRESETS, get_strategy_args

        required_keys = {
            "seeds", "max_seeds", "techniques", "converters",
            "max_attempts", "max_concurrency", "timeout",
            "html_report", "offensive",
        }
        for name in STRATEGY_PRESETS:
            args = get_strategy_args(name)
            assert required_keys.issubset(args.keys()), f"{name} missing keys"

    def test_unknown_strategy_raises_keyerror(self):
        from pipeline.strategy.presets import get_strategy_args

        with pytest.raises(KeyError, match="Unknown strategy"):
            get_strategy_args("nonexistent_strategy")

    def test_args_match_preset_values(self):
        """get_strategy_args 返回值与预设字段一致."""
        from pipeline.strategy.presets import STRATEGY_PRESETS, get_strategy_args

        for name, preset in STRATEGY_PRESETS.items():
            args = get_strategy_args(name)
            assert args["seeds"] == preset.seeds
            assert args["max_seeds"] == preset.max_seeds
            assert args["techniques"] == preset.techniques
            assert args["converters"] == preset.converters
            assert args["max_attempts"] == preset.max_attempts
            assert args["max_concurrency"] == preset.max_concurrency
            assert args["timeout"] == preset.timeout
            assert args["html_report"] == preset.html_report


# ═══════════════════════════════════════════════════════
# list_strategies
# ═══════════════════════════════════════════════════════


class TestListStrategies:
    """测试 list_strategies — 格式化输出."""

    def test_returns_string(self):
        from pipeline.strategy.presets import list_strategies

        result = list_strategies()
        assert isinstance(result, str)

    def test_contains_all_strategy_names(self):
        from pipeline.strategy.presets import STRATEGY_PRESETS, list_strategies

        result = list_strategies()
        for name in STRATEGY_PRESETS:
            assert name in result, f"{name} not in list_strategies output"

    def test_contains_header(self):
        from pipeline.strategy.presets import list_strategies

        result = list_strategies()
        assert "Available attack strategies" in result

    def test_contains_key_fields(self):
        from pipeline.strategy.presets import list_strategies

        result = list_strategies()
        assert "Seeds:" in result
        assert "Techniques:" in result
        assert "Converters:" in result
        assert "Escalation:" in result
        assert "Timeout:" in result
