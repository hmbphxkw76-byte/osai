"""tests/test_scenario_router.py — ScenarioRouter 单元测试 (v60 Tag-Based)

v60 重构: 测试场景路由器的新 tag-based 设计
    - Scenario 自动选择 (基于攻击面→technique_tags 映射)
    - 用户强制覆盖 (--scenario)
    - 置信度阈值过滤
    - Fallback 到默认 Scenario
    - Scenario 列表展示
    - apply_scenario_overrides 仅设置 adaptive_technique_filter

学术依据: NIST SP 800-115 §4 — 威胁建模驱动测试策略
"""
from __future__ import annotations

import pytest

from core.scenario_router import ScenarioRouter, apply_scenario_overrides, get_router, reset_router

# ──────────────────────────────────────────────────────────────────────────────
# 测试夹具
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def router() -> ScenarioRouter:
    """创建测试用 ScenarioRouter (使用默认配置)"""
    # 重置全局单例，确保测试隔离
    reset_router()
    return ScenarioRouter()


@pytest.fixture
def mock_classification():
    """创建模拟 ClassificationResult 的工厂函数"""
    def _create(attack_surface: str, confidence: float, evidence: list[str] | None = None):
        from recon.attack_surface_classifier import ClassificationResult
        return ClassificationResult(
            attack_surface=attack_surface,
            confidence=confidence,
            evidence=evidence or [],
        )
    return _create


# ──────────────────────────────────────────────────────────────────────────────
# 测试用例
# ──────────────────────────────────────────────────────────────────────────────

class TestScenarioRouter:
    """ScenarioRouter 单元测试 (v60 Tag-Based)"""

    def test_select_mcp_scenario(self, router, mock_classification):
        """测试 MCP 目标自动选择 mcp_scenario"""
        classification = mock_classification("mcp_server", 0.92, ["URL pattern match"])
        name, config = router.select_scenario(classification)
        assert name == "mcp_scenario"
        assert config["triggers"]["attack_surface"] == "mcp_server"
        # v60: 验证 technique_tags
        assert config["technique_tags"] == ["mcp_targeted"]

    def test_select_agent_scenario(self, router, mock_classification):
        """测试 Agent 目标自动选择 agent_scenario"""
        classification = mock_classification("multi_agent_system", 0.85, ["Agent pattern"])
        name, config = router.select_scenario(classification)
        assert name == "agent_scenario"
        assert config["triggers"]["attack_surface"] == "multi_agent_system"
        # v60: 验证 technique_tags
        assert config["technique_tags"] == ["agent_targeted"]

    def test_select_rag_scenario(self, router, mock_classification):
        """测试 RAG 目标自动选择 rag_scenario"""
        classification = mock_classification("rag_system", 0.88, ["RAG pattern"])
        name, config = router.select_scenario(classification)
        assert name == "rag_scenario"
        assert config["triggers"]["attack_surface"] == "rag_system"
        # v60: 验证 technique_tags
        assert config["technique_tags"] == ["rag_targeted"]

    def test_select_model_fallback(self, router, mock_classification):
        """测试未知类型回退到 model_scenario"""
        classification = mock_classification("unknown_api", 0.5, [])
        name, config = router.select_scenario(classification)
        assert name == "model_scenario"
        # v60: model_scenario 的 technique_tags 为 None (使用全部技术)
        assert config["technique_tags"] is None

    def test_user_override(self, router, mock_classification):
        """测试用户强制覆盖"""
        classification = mock_classification("mcp_server", 0.92, [])
        name, config = router.select_scenario(classification, user_override="model_scenario")
        assert name == "model_scenario"

    def test_confidence_threshold(self, router, mock_classification):
        """测试置信度阈值过滤 (默认 min_confidence=0.6)"""
        classification = mock_classification("mcp_server", 0.5, [])  # 低于 min_confidence=0.6
        name, config = router.select_scenario(classification)
        assert name == "model_scenario"  # fallback

    def test_list_scenarios(self, router):
        """测试列出所有 Scenario"""
        scenarios = router.list_scenarios()
        assert len(scenarios) == 4
        names = [s["name"] for s in scenarios]
        assert "mcp_scenario" in names
        assert "agent_scenario" in names
        assert "rag_scenario" in names
        assert "model_scenario" in names

    def test_invalid_override_fallback(self, router, mock_classification):
        """测试无效覆盖回退到自动选择"""
        classification = mock_classification("mcp_server", 0.92, [])
        name, config = router.select_scenario(classification, user_override="invalid_scenario")
        assert name == "mcp_scenario"  # fallback to auto

    def test_format_scenarios_display(self, router):
        """测试 Scenario 列表格式化输出"""
        display = router.format_scenarios_display()
        assert "Available Scenarios" in display
        assert "mcp_scenario" in display
        assert "agent_scenario" in display
        # v60: 验证显示包含 technique tags 信息
        assert "Technique Tags" in display or "technique" in display.lower()

    def test_validate_scenario(self, router):
        """测试 Scenario 名称验证"""
        assert router._validate_scenario("mcp_scenario") is True
        assert router._validate_scenario("invalid_scenario") is False

    def test_get_scenario_config(self, router):
        """测试获取 Scenario 配置"""
        config = router._get_scenario_config("mcp_scenario")
        assert config["triggers"]["attack_surface"] == "mcp_server"
        # v60: 验证 technique_tags
        assert config["technique_tags"] == ["mcp_targeted"]


class TestApplyScenarioOverrides:
    """apply_scenario_overrides 函数测试 (v60 简化版)"""

    def test_technique_filter_override(self, router):
        """测试 v60: 仅覆盖 adaptive_technique_filter"""
        from dataclasses import dataclass, field

        @dataclass
        class MockArgs:
            adaptive_technique_filter: list | None = None

        @dataclass
        class MockCtx:
            args: MockArgs = field(default_factory=MockArgs)

        ctx = MockCtx()
        scenario_config = router._get_scenario_config("mcp_scenario")
        apply_scenario_overrides(ctx, scenario_config, ctx.args)

        # v60: 验证设置了 adaptive_technique_filter
        assert ctx.args.adaptive_technique_filter == ["mcp_targeted"]

    def test_no_override_when_cli_set(self, router):
        """测试 v60: CLI 已设置时不覆盖"""
        from dataclasses import dataclass, field

        @dataclass
        class MockArgs:
            adaptive_technique_filter: list | None = field(default_factory=lambda: ["custom_tag"])

        @dataclass
        class MockCtx:
            args: MockArgs = field(default_factory=MockArgs)

        ctx = MockCtx()
        scenario_config = router._get_scenario_config("mcp_scenario")
        apply_scenario_overrides(ctx, scenario_config, ctx.args)

        # v60: CLI 已设置，不应被覆盖
        assert ctx.args.adaptive_technique_filter == ["custom_tag"]

    def test_model_scenario_no_filter(self, router):
        """测试 v60: model_scenario 不设 filter (使用全部技术)"""
        from dataclasses import dataclass, field

        @dataclass
        class MockArgs:
            adaptive_technique_filter: list | None = None

        @dataclass
        class MockCtx:
            args: MockArgs = field(default_factory=MockArgs)

        ctx = MockCtx()
        scenario_config = router._get_scenario_config("model_scenario")
        apply_scenario_overrides(ctx, scenario_config, ctx.args)

        # v60: model_scenario 的 technique_tags 为 None, 不设置 filter
        assert ctx.args.adaptive_technique_filter is None


class TestGlobalRouter:
    """全局路由器单例测试"""

    def test_get_router_singleton(self):
        """测试全局路由器单例模式"""
        reset_router()
        router1 = get_router()
        router2 = get_router()
        # 验证是同一个实例
        assert router1 is router2

    def test_reset_router(self):
        """测试重置路由器"""
        reset_router()
        # 重置后应能正常获取新实例
        router = get_router()
        assert router is not None


# ──────────────────────────────────────────────────────────────────────────────
# 边界条件测试
# ──────────────────────────────────────────────────────────────────────────────

class TestEdgeCases:
    """边界条件测试"""

    def test_exact_confidence_threshold(self, router, mock_classification):
        """测试精确置信度阈值 (默认 min_confidence=0.6)"""
        classification = mock_classification("mcp_server", 0.6, [])
        name, config = router.select_scenario(classification)
        assert name == "mcp_scenario"

    def test_just_below_confidence_threshold(self, router, mock_classification):
        """测试略低于置信度阈值"""
        classification = mock_classification("mcp_server", 0.59, [])
        name, config = router.select_scenario(classification)
        assert name == "model_scenario"  # fallback

    def test_scenario_config_has_technique_tags(self, router):
        """测试所有场景配置都包含 technique_tags 字段"""
        for name in ["mcp_scenario", "agent_scenario", "rag_scenario", "model_scenario"]:
            config = router._get_scenario_config(name)
            assert "technique_tags" in config, f"Scenario {name} missing technique_tags"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
