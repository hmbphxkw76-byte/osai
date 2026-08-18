# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""v57 H-1~H-4: Browser 补充攻击混合模式测试.

测试覆盖:
  H-1: should_supplement_with_browser() — 拓扑驱动判定
  H-1: _select_supplement_attacks() — 攻击子集选择
  H-2: run_browser_supplement() — 执行编排 (mock)
  H-4: _merge_dual_mode_asr() — ASR 合并
  H-5: fallback_health_card — 补充状态展示

学术依据:
  - Greshake et al. (arXiv:2302.12173): 间接注入需完整渲染链路
  - HarmBench (arXiv:2402.04249): 跨攻击向量 ASR 聚合
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pytest import CaptureFixture

from pipeline.context import PipelineContext

# ──────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────


@dataclass
class MockTopology:
    """模拟 AttackSurfaceTopology."""

    app_architecture: str = "simple_llm"
    transport_type: str = "http"
    auth_topology: str = "none"
    token_expiry_seconds: int = 0
    injection_surfaces: list[str] = field(default_factory=lambda: ["user_message"])
    has_tool_calling: bool = False
    has_rag: bool = False
    has_mcp: bool = False
    has_system_prompt: bool = False
    has_multimodal: bool = False
    discovered_tools: list[dict] = field(default_factory=list)
    model_fingerprint: dict = field(default_factory=dict)
    recommended_kill_chain: list[str] = field(default_factory=lambda: ["recon", "initial_access", "execution"])
    recommended_owasp: list[str] = field(default_factory=list)


@pytest.fixture
def supplement_args() -> argparse.Namespace:
    """模拟命令行参数 — 含 browser_supplement 参数."""
    return argparse.Namespace(
        target_url="http://example.com/chat",
        burp_request="data/burp/request.txt",
        no_browser_supplement=False,
        browser_supplement=False,
        target_type="api_platform",
        target_profile="",
        web_headless=True,
        cdp_port=9222,
        max_rpm=10,
        mfa_timeout=30,
        scenario="prompt_sending",
        objective="test",
        max_turns=1,
    )


@pytest.fixture
def supplement_ctx(supplement_args: argparse.Namespace) -> PipelineContext:
    """创建含 browser_supplement 参数的 PipelineContext."""
    return PipelineContext(args=supplement_args)


# ──────────────────────────────────────────────────────────────────
# H-1: should_supplement_with_browser 测试
# ──────────────────────────────────────────────────────────────────


class TestShouldSupplement:
    """H-1: 拓扑驱动的 Browser 补充判定."""

    def test_no_topology_returns_false(self, supplement_ctx: PipelineContext) -> None:
        """无攻击面拓扑时不触发补充."""
        from pipeline.scenarios.browser_supplement import should_supplement_with_browser

        assert should_supplement_with_browser(supplement_ctx) is False

    def test_cli_disable(self, supplement_ctx: PipelineContext) -> None:
        """--no-browser-supplement 显式禁用."""
        from pipeline.scenarios.browser_supplement import should_supplement_with_browser

        supplement_ctx.args.no_browser_supplement = True
        supplement_ctx.metadata["attack_surface_topology"] = MockTopology(has_rag=True)
        assert should_supplement_with_browser(supplement_ctx) is False

    def test_already_playwright_mode(self, supplement_ctx: PipelineContext) -> None:
        """已是 Browser 主模式时不需要补充."""
        from pipeline.scenarios.browser_supplement import should_supplement_with_browser

        supplement_ctx.target_type = "playwright"
        supplement_ctx.metadata["attack_surface_topology"] = MockTopology(has_rag=True)
        assert should_supplement_with_browser(supplement_ctx) is False

    def test_all_targets_failed(self, supplement_ctx: PipelineContext) -> None:
        """Burp 模式失败时不触发补充."""
        from pipeline.scenarios.browser_supplement import should_supplement_with_browser

        supplement_ctx.metadata["all_targets_failed"] = True
        supplement_ctx.metadata["attack_surface_topology"] = MockTopology(has_rag=True)
        assert should_supplement_with_browser(supplement_ctx) is False

    def test_has_rag_triggers_supplement(self, supplement_ctx: PipelineContext) -> None:
        """拓扑检测到 RAG 特征时触发补充."""
        from pipeline.scenarios.browser_supplement import should_supplement_with_browser

        supplement_ctx.metadata["attack_surface_topology"] = MockTopology(has_rag=True)
        with patch("builtins.__import__") as mock_import:
            mock_import.return_value = MagicMock()
            assert should_supplement_with_browser(supplement_ctx) is True

    def test_has_mcp_triggers_supplement(self, supplement_ctx: PipelineContext) -> None:
        """拓扑检测到 MCP 特征时触发补充."""
        from pipeline.scenarios.browser_supplement import should_supplement_with_browser

        supplement_ctx.metadata["attack_surface_topology"] = MockTopology(has_mcp=True)
        with patch("builtins.__import__") as mock_import:
            mock_import.return_value = MagicMock()
            assert should_supplement_with_browser(supplement_ctx) is True

    def test_has_tool_calling_triggers_supplement(self, supplement_ctx: PipelineContext) -> None:
        """拓扑检测到 Agent 工具时触发补充."""
        from pipeline.scenarios.browser_supplement import should_supplement_with_browser

        supplement_ctx.metadata["attack_surface_topology"] = MockTopology(has_tool_calling=True)
        with patch("builtins.__import__") as mock_import:
            mock_import.return_value = MagicMock()
            assert should_supplement_with_browser(supplement_ctx) is True

    def test_rag_injection_surface_triggers(self, supplement_ctx: PipelineContext) -> None:
        """注入面含 rag_content 时触发."""
        from pipeline.scenarios.browser_supplement import should_supplement_with_browser

        topology = MockTopology(injection_surfaces=["user_message", "rag_content"])
        supplement_ctx.metadata["attack_surface_topology"] = topology
        with patch("builtins.__import__") as mock_import:
            mock_import.return_value = MagicMock()
            assert should_supplement_with_browser(supplement_ctx) is True

    def test_simple_llm_no_supplement(self, supplement_ctx: PipelineContext) -> None:
        """简单 LLM (无 RAG/MCP/Agent) 不需要补充."""
        from pipeline.scenarios.browser_supplement import should_supplement_with_browser

        topology = MockTopology(
            injection_surfaces=["user_message"],
            has_rag=False,
            has_mcp=False,
            has_tool_calling=False,
        )
        supplement_ctx.metadata["attack_surface_topology"] = topology
        with patch("builtins.__import__") as mock_import:
            mock_import.return_value = MagicMock()
            assert should_supplement_with_browser(supplement_ctx) is False

    def test_explicit_enable_overrides_topology(self, supplement_ctx: PipelineContext) -> None:
        """--browser-supplement 显式启用时, 即使拓扑无特征也触发."""
        from pipeline.scenarios.browser_supplement import should_supplement_with_browser

        supplement_ctx.args.browser_supplement = True
        supplement_ctx.metadata["attack_surface_topology"] = MockTopology()
        with patch("builtins.__import__") as mock_import:
            mock_import.return_value = MagicMock()
            assert should_supplement_with_browser(supplement_ctx) is True


# ──────────────────────────────────────────────────────────────────
# H-1: _select_supplement_attacks 测试
# ──────────────────────────────────────────────────────────────────


class TestSelectSupplementAttacks:
    """H-1: 根据拓扑选择 Browser 补充攻击子集."""

    def test_rag_topology_selects_rag_attack(self, supplement_ctx: PipelineContext) -> None:
        """RAG 拓扑 → 选择 RAG 间接注入攻击."""
        from pipeline.scenarios.browser_supplement import _select_supplement_attacks

        supplement_ctx.metadata["attack_surface_topology"] = MockTopology(has_rag=True)
        attacks = _select_supplement_attacks(supplement_ctx)
        assert len(attacks) == 1
        assert attacks[0]["technique"] == "browser_rag_injection"
        assert attacks[0]["owasp"] == "LLM07"

    def test_mcp_topology_selects_mcp_attack(self, supplement_ctx: PipelineContext) -> None:
        """MCP 拓扑 → 选择 MCP 协议注入攻击."""
        from pipeline.scenarios.browser_supplement import _select_supplement_attacks

        supplement_ctx.metadata["attack_surface_topology"] = MockTopology(has_mcp=True)
        attacks = _select_supplement_attacks(supplement_ctx)
        assert len(attacks) == 1
        assert attacks[0]["technique"] == "browser_mcp_injection"
        assert attacks[0]["owasp"] == "ASI01"

    def test_agent_tools_selects_tool_hijack(self, supplement_ctx: PipelineContext) -> None:
        """Agent 工具拓扑 → 选择工具劫持攻击."""
        from pipeline.scenarios.browser_supplement import _select_supplement_attacks

        supplement_ctx.metadata["attack_surface_topology"] = MockTopology(has_tool_calling=True)
        attacks = _select_supplement_attacks(supplement_ctx)
        assert len(attacks) == 1
        assert attacks[0]["technique"] == "browser_tool_hijack"
        assert attacks[0]["owasp"] == "ASI02"

    def test_system_prompt_selects_leak_attack(self, supplement_ctx: PipelineContext) -> None:
        """系统提示拓扑 → 选择系统提示泄露攻击."""
        from pipeline.scenarios.browser_supplement import _select_supplement_attacks

        supplement_ctx.metadata["attack_surface_topology"] = MockTopology(has_system_prompt=True)
        attacks = _select_supplement_attacks(supplement_ctx)
        assert len(attacks) == 1
        assert attacks[0]["technique"] == "browser_system_prompt_leak"
        assert attacks[0]["owasp"] == "LLM06"

    def test_all_features_selects_all_attacks(self, supplement_ctx: PipelineContext) -> None:
        """所有特征 → 选择全部 4 种补充攻击."""
        from pipeline.scenarios.browser_supplement import _select_supplement_attacks

        topology = MockTopology(
            has_rag=True,
            has_mcp=True,
            has_tool_calling=True,
            has_system_prompt=True,
        )
        supplement_ctx.metadata["attack_surface_topology"] = topology
        attacks = _select_supplement_attacks(supplement_ctx)
        assert len(attacks) == 4
        techniques = [a["technique"] for a in attacks]
        assert "browser_rag_injection" in techniques
        assert "browser_mcp_injection" in techniques
        assert "browser_tool_hijack" in techniques
        assert "browser_system_prompt_leak" in techniques

    def test_no_topology_returns_empty(self, supplement_ctx: PipelineContext) -> None:
        """无拓扑 → 返回空列表."""
        from pipeline.scenarios.browser_supplement import _select_supplement_attacks

        attacks = _select_supplement_attacks(supplement_ctx)
        assert attacks == []

    def test_rag_surface_triggers_even_without_flag(self, supplement_ctx: PipelineContext) -> None:
        """注入面含 rag_content 但 has_rag=False 时仍然触发."""
        from pipeline.scenarios.browser_supplement import _select_supplement_attacks

        topology = MockTopology(
            has_rag=False,
            injection_surfaces=["user_message", "rag_content"],
        )
        supplement_ctx.metadata["attack_surface_topology"] = topology
        attacks = _select_supplement_attacks(supplement_ctx)
        assert len(attacks) == 1
        assert attacks[0]["technique"] == "browser_rag_injection"

    def test_attack_has_source_field(self, supplement_ctx: PipelineContext) -> None:
        """每个攻击包含 source 字段标识来源."""
        from pipeline.scenarios.browser_supplement import _select_supplement_attacks

        supplement_ctx.metadata["attack_surface_topology"] = MockTopology(has_rag=True)
        attacks = _select_supplement_attacks(supplement_ctx)
        assert attacks[0]["source"] == "topology:rag"

    def test_attack_has_description(self, supplement_ctx: PipelineContext) -> None:
        """每个攻击包含 description 字段."""
        from pipeline.scenarios.browser_supplement import _select_supplement_attacks

        supplement_ctx.metadata["attack_surface_topology"] = MockTopology(has_mcp=True)
        attacks = _select_supplement_attacks(supplement_ctx)
        assert "description" in attacks[0]
        assert len(attacks[0]["description"]) > 0


# ──────────────────────────────────────────────────────────────────
# H-2: run_browser_supplement 测试 (mock)
# ──────────────────────────────────────────────────────────────────


class TestRunBrowserSupplement:
    """H-2: Browser 补充攻击执行编排."""

    @pytest.mark.asyncio
    async def test_no_supplement_needed_returns_early(
        self, supplement_ctx: PipelineContext
    ) -> None:
        """不需要补充时直接返回, 不执行任何操作."""
        from pipeline.scenarios.browser_supplement import run_browser_supplement

        # 无拓扑, should_supplement 返回 False
        await run_browser_supplement(supplement_ctx)
        assert "browser_supplement_results" not in supplement_ctx.metadata

    @pytest.mark.asyncio
    async def test_no_target_url_returns_early(self, supplement_ctx: PipelineContext) -> None:
        """无 target_url 时直接返回."""
        from pipeline.scenarios.browser_supplement import run_browser_supplement

        supplement_ctx.args.target_url = None
        supplement_ctx.metadata["attack_surface_topology"] = MockTopology(has_rag=True)
        with patch("builtins.__import__") as mock_import:
            mock_import.return_value = MagicMock()
            await run_browser_supplement(supplement_ctx)
        assert "browser_supplement_results" not in supplement_ctx.metadata

    @pytest.mark.asyncio
    async def test_no_attacks_selected_returns_early(
        self, supplement_ctx: PipelineContext
    ) -> None:
        """拓扑无特征且无显式启用时返回."""
        from pipeline.scenarios.browser_supplement import run_browser_supplement

        supplement_ctx.metadata["attack_surface_topology"] = MockTopology()
        with patch("builtins.__import__") as mock_import:
            mock_import.return_value = MagicMock()
            with patch(
                "pipeline.scenarios.browser_supplement.should_supplement_with_browser",
                return_value=True,
            ):
                await run_browser_supplement(supplement_ctx)
        # _select_supplement_attacks 返回空, 不设置 results
        assert "browser_supplement_results" not in supplement_ctx.metadata

    @pytest.mark.asyncio
    async def test_failed_target_creation_sets_flag(
        self, supplement_ctx: PipelineContext
    ) -> None:
        """Browser Target 创建失败时设置 failed 标记."""
        from pipeline.scenarios.browser_supplement import run_browser_supplement

        supplement_ctx.metadata["attack_surface_topology"] = MockTopology(has_rag=True)
        with patch("builtins.__import__") as mock_import:
            mock_import.return_value = MagicMock()
            with patch(
                "pipeline.scenarios.browser_supplement.should_supplement_with_browser",
                return_value=True,
            ), patch(
                "pipeline.scenarios.browser_supplement._create_browser_supplement_target",
                return_value=None,
            ):
                await run_browser_supplement(supplement_ctx)

        assert supplement_ctx.metadata.get("browser_supplement_failed") is True


# ──────────────────────────────────────────────────────────────────
# H-4: _merge_dual_mode_asr 测试
# ──────────────────────────────────────────────────────────────────


class TestMergeDualModeASR:
    """H-4: Browser 补充 ASR 合并到主流水线报告."""

    def test_no_results_returns_early(self, supplement_ctx: PipelineContext) -> None:
        """无 Browser 补充结果时直接返回."""
        from pipeline.stages.stage_post_analysis import _merge_dual_mode_asr

        _merge_dual_mode_asr(supplement_ctx)
        assert "browser_supplement" not in supplement_ctx.metadata.get("post_analysis", {})

    def test_success_merged_to_asr(self, supplement_ctx: PipelineContext) -> None:
        """成功的补充攻击 ASR=100% 合并到 asr_per_technique."""
        from pipeline.stages.stage_post_analysis import _merge_dual_mode_asr

        supplement_ctx.metadata["browser_supplement_results"] = [
            {"technique": "browser_rag_injection", "achieved": True, "owasp": "LLM07"},
            {"technique": "browser_mcp_injection", "achieved": False, "owasp": "ASI01"},
        ]
        supplement_ctx.metadata["browser_supplement_success_count"] = 1

        _merge_dual_mode_asr(supplement_ctx)

        assert "browser_rag_injection [Browser]" in supplement_ctx.asr_per_technique
        assert supplement_ctx.asr_per_technique["browser_rag_injection [Browser]"] == 100.0
        assert "browser_mcp_injection [Browser]" in supplement_ctx.asr_per_technique
        assert supplement_ctx.asr_per_technique["browser_mcp_injection [Browser]"] == 0.0

    def test_takes_max_when_technique_exists(self, supplement_ctx: PipelineContext) -> None:
        """已有同名技术时取最大 ASR."""
        from pipeline.stages.stage_post_analysis import _merge_dual_mode_asr

        supplement_ctx.asr_per_technique["browser_rag_injection [Browser]"] = 50.0
        supplement_ctx.metadata["browser_supplement_results"] = [
            {"technique": "browser_rag_injection", "achieved": True, "owasp": "LLM07"},
        ]
        supplement_ctx.metadata["browser_supplement_success_count"] = 1

        _merge_dual_mode_asr(supplement_ctx)

        # 100 > 50, 取最大值
        assert supplement_ctx.asr_per_technique["browser_rag_injection [Browser]"] == 100.0

    def test_lower_asr_does_not_overwrite(self, supplement_ctx: PipelineContext) -> None:
        """补充 ASR 低于已有值时不覆盖."""
        from pipeline.stages.stage_post_analysis import _merge_dual_mode_asr

        supplement_ctx.asr_per_technique["browser_rag_injection [Browser]"] = 100.0
        supplement_ctx.metadata["browser_supplement_results"] = [
            {"technique": "browser_rag_injection", "achieved": False, "owasp": "LLM07"},
        ]
        supplement_ctx.metadata["browser_supplement_success_count"] = 0

        _merge_dual_mode_asr(supplement_ctx)

        # 0 < 100, 不覆盖
        assert supplement_ctx.asr_per_technique["browser_rag_injection [Browser]"] == 100.0

    def test_post_analysis_metadata_recorded(self, supplement_ctx: PipelineContext) -> None:
        """post_analysis metadata 中记录双模式标记."""
        from pipeline.stages.stage_post_analysis import _merge_dual_mode_asr

        supplement_ctx.metadata["browser_supplement_results"] = [
            {"technique": "browser_rag_injection", "achieved": True, "owasp": "LLM07"},
        ]
        supplement_ctx.metadata["browser_supplement_success_count"] = 1

        _merge_dual_mode_asr(supplement_ctx)

        pa = supplement_ctx.metadata.get("post_analysis", {})
        assert "browser_supplement" in pa
        assert pa["browser_supplement"]["total_attacks"] == 1
        assert pa["browser_supplement"]["success_count"] == 1
        assert pa["browser_supplement"]["merged_to_asr"] == 1

    def test_multiple_attacks_all_merged(self, supplement_ctx: PipelineContext) -> None:
        """多个补充攻击全部合并到 asr_per_technique."""
        from pipeline.stages.stage_post_analysis import _merge_dual_mode_asr

        supplement_ctx.metadata["browser_supplement_results"] = [
            {"technique": "browser_rag_injection", "achieved": True, "owasp": "LLM07"},
            {"technique": "browser_mcp_injection", "achieved": True, "owasp": "ASI01"},
            {"technique": "browser_tool_hijack", "achieved": False, "owasp": "ASI02"},
            {"technique": "browser_system_prompt_leak", "achieved": True, "owasp": "LLM06"},
        ]
        supplement_ctx.metadata["browser_supplement_success_count"] = 3

        _merge_dual_mode_asr(supplement_ctx)

        assert len([k for k in supplement_ctx.asr_per_technique if "[Browser]" in k]) == 4
        pa = supplement_ctx.metadata.get("post_analysis", {})
        assert pa["browser_supplement"]["merged_to_asr"] == 4


# ──────────────────────────────────────────────────────────────────
# H-5: display.py fallback_health_card 补充状态展示测试
# ──────────────────────────────────────────────────────────────────


class TestDisplaySupplementStatus:
    """H-5: 降级链健康度面板中的 Browser 补充状态展示."""

    def test_no_supplement_shows_nothing(
        self, supplement_ctx: PipelineContext, capsys: CaptureFixture[str]
    ) -> None:
        """无 Browser 补充时不展示相关行."""
        from pipeline.utils.display import fallback_health_card

        fallback_health_card(supplement_ctx)
        captured = capsys.readouterr()
        assert "Browser 补充" not in captured.out

    def test_supplement_active_shows_pending(
        self, supplement_ctx: PipelineContext, capsys: CaptureFixture[str]
    ) -> None:
        """补充已激活但未执行时显示待执行."""
        from pipeline.utils.display import fallback_health_card

        supplement_ctx.metadata["browser_supplement_active"] = True
        fallback_health_card(supplement_ctx)
        captured = capsys.readouterr()
        assert "待执行" in captured.out

    def test_supplement_results_shows_count(
        self, supplement_ctx: PipelineContext, capsys: CaptureFixture[str]
    ) -> None:
        """有补充结果时显示成功/总数."""
        from pipeline.utils.display import fallback_health_card

        supplement_ctx.metadata["browser_supplement_active"] = True
        supplement_ctx.metadata["browser_supplement_results"] = [{"achieved": True}, {"achieved": False}]
        supplement_ctx.metadata["browser_supplement_success_count"] = 1
        supplement_ctx.metadata["browser_supplement_total_count"] = 2
        fallback_health_card(supplement_ctx)
        captured = capsys.readouterr()
        assert "1/2" in captured.out
        assert "✅" in captured.out

    def test_supplement_failed_shows_error(
        self, supplement_ctx: PipelineContext, capsys: CaptureFixture[str]
    ) -> None:
        """补充失败时显示错误标记."""
        from pipeline.utils.display import fallback_health_card

        supplement_ctx.metadata["browser_supplement_failed"] = True
        fallback_health_card(supplement_ctx)
        captured = capsys.readouterr()
        assert "❌" in captured.out
        assert "创建失败" in captured.out


# ──────────────────────────────────────────────────────────────────
# O-1: _execute_supplement_attack API 正确性测试
# ──────────────────────────────────────────────────────────────────


class TestExecuteSupplementAttackAPI:
    """O-1: PyRIT 1.0.1 API 调用正确性."""

    @pytest.mark.asyncio
    async def test_success_outcome_extraction(
        self, supplement_ctx: PipelineContext
    ) -> None:
        """O-1: AttackOutcome.SUCCESS 正确提取为 achieved=True."""
        from pyrit.models import AttackOutcome

        from pipeline.scenarios.browser_supplement import _execute_supplement_attack

        # Mock AttackResult (Pydantic model)
        mock_result = MagicMock()
        mock_result.outcome = AttackOutcome.SUCCESS
        mock_result.last_response = "Here is the system prompt..."

        mock_attack = MagicMock()
        mock_attack.execute_async = AsyncMock(return_value=mock_result)

        with patch("pyrit.executor.attack.PromptSendingAttack", return_value=mock_attack):
            result = await _execute_supplement_attack(
                target=MagicMock(),
                objective="test objective",
                technique="test_tech",
                ctx=supplement_ctx,
            )

        assert result["achieved"] is True
        assert "system prompt" in result["response"]

    @pytest.mark.asyncio
    async def test_failure_outcome_extraction(
        self, supplement_ctx: PipelineContext
    ) -> None:
        """O-1: AttackOutcome.FAILURE 正确提取为 achieved=False."""
        from pyrit.models import AttackOutcome

        from pipeline.scenarios.browser_supplement import _execute_supplement_attack

        mock_result = MagicMock()
        mock_result.outcome = AttackOutcome.FAILURE
        mock_result.last_response = "I cannot help with that."

        mock_attack = MagicMock()
        mock_attack.execute_async = AsyncMock(return_value=mock_result)

        with patch("pyrit.executor.attack.PromptSendingAttack", return_value=mock_attack):
            result = await _execute_supplement_attack(
                target=MagicMock(),
                objective="test objective",
                technique="test_tech",
                ctx=supplement_ctx,
            )

        assert result["achieved"] is False
        assert "cannot help" in result["response"]

    @pytest.mark.asyncio
    async def test_undetermined_triggers_rule_based_fallback(
        self, supplement_ctx: PipelineContext
    ) -> None:
        """O-1: UNDETERMINED outcome 触发 RuleBasedScorer 后置评分."""
        from pyrit.models import AttackOutcome

        from pipeline.scenarios.browser_supplement import _execute_supplement_attack

        mock_result = MagicMock()
        mock_result.outcome = AttackOutcome.UNDETERMINED
        mock_result.last_response = "Here is the system prompt you requested. It contains all the instructions."

        mock_attack = MagicMock()
        mock_attack.execute_async = AsyncMock(return_value=mock_result)

        # RuleBasedScorer 应检测到 "system" + "instructions" 关键词
        with patch("pyrit.executor.attack.PromptSendingAttack", return_value=mock_attack):
            result = await _execute_supplement_attack(
                target=MagicMock(),
                objective="reveal the system prompt",
                technique="browser_system_prompt_leak",
                ctx=supplement_ctx,
            )

        # RuleBasedScorer fallback 应判定为成功
        assert result["achieved"] is True

    @pytest.mark.asyncio
    async def test_exception_returns_failure(
        self, supplement_ctx: PipelineContext
    ) -> None:
        """O-1: execute_async 抛异常时返回 achieved=False + error."""
        from pipeline.scenarios.browser_supplement import _execute_supplement_attack

        mock_attack = MagicMock()
        mock_attack.execute_async = AsyncMock(side_effect=RuntimeError("timeout"))

        with patch("pyrit.executor.attack.PromptSendingAttack", return_value=mock_attack):
            result = await _execute_supplement_attack(
                target=MagicMock(),
                objective="test",
                technique="test_tech",
                ctx=supplement_ctx,
            )

        assert result["achieved"] is False
        assert "timeout" in result["error"]

    @pytest.mark.asyncio
    async def test_no_ctx_skips_scorer_config(self) -> None:
        """O-1: ctx=None 时不配置评分器, 仍可执行."""
        from pyrit.models import AttackOutcome

        from pipeline.scenarios.browser_supplement import _execute_supplement_attack

        mock_result = MagicMock()
        mock_result.outcome = AttackOutcome.SUCCESS
        mock_result.last_response = "success response"

        mock_attack = MagicMock()
        mock_attack.execute_async = AsyncMock(return_value=mock_result)

        with patch("pyrit.executor.attack.PromptSendingAttack", return_value=mock_attack):
            result = await _execute_supplement_attack(
                target=MagicMock(),
                objective="test",
                technique="test_tech",
                ctx=None,
            )

        assert result["achieved"] is True


# ──────────────────────────────────────────────────────────────────
# O-2: 证据收集器 Browser 补充集成测试
# ──────────────────────────────────────────────────────────────────


class TestEvidenceCollectorBrowserSupplement:
    """O-2: 证据收集器集成 Browser 补充结果."""

    def test_browser_evidence_collected_on_success(
        self, supplement_ctx: PipelineContext
    ) -> None:
        """O-2: 成功的 Browser 补充攻击生成 VulnerabilityEvidence."""
        from pipeline.analysis.evidence_collector import EvidenceCollector

        collector = EvidenceCollector(
            target_model="test_model", model_tier="tier1"
        )
        metadata = {
            "browser_supplement_results": [
                {
                    "technique": "browser_rag_injection",
                    "achieved": True,
                    "owasp": "LLM07",
                    "response": "Here is the system prompt...",
                    "source": "topology:rag",
                    "description": "RAG 间接注入",
                },
            ],
            "browser_supplement_success_count": 1,
        }
        collection = collector.collect(
            attack_results={},
            metadata=metadata,
        )
        # 应有 1 个证据 (Browser 补充成功)
        assert len(collection.evidence) == 1
        assert "browser_rag_injection [Browser]" in collection.evidence[0].technique_name
        assert collection.evidence[0].owasp_id == "LLM07"
        assert collection.successful_attacks == 1
        assert collection.total_attacks == 1

    def test_browser_failure_counted_in_stats(
        self, supplement_ctx: PipelineContext
    ) -> None:
        """O-2: 失败的 Browser 补充攻击计入 failed_attacks."""
        from pipeline.analysis.evidence_collector import EvidenceCollector

        collector = EvidenceCollector(
            target_model="test_model", model_tier="tier1"
        )
        metadata = {
            "browser_supplement_results": [
                {"technique": "browser_mcp_injection", "achieved": False, "owasp": "ASI01"},
            ],
        }
        collection = collector.collect(
            attack_results={},
            metadata=metadata,
        )
        assert len(collection.evidence) == 0  # 无成功证据
        assert collection.total_attacks == 1
        assert collection.failed_attacks == 1

    def test_browser_summary_recorded(
        self, supplement_ctx: PipelineContext
    ) -> None:
        """O-2: browser_supplement_summary 正确填充."""
        from pipeline.analysis.evidence_collector import EvidenceCollector

        collector = EvidenceCollector(
            target_model="test_model", model_tier="tier1"
        )
        metadata = {
            "browser_supplement_results": [
                {"technique": "browser_rag_injection", "achieved": True, "owasp": "LLM07"},
                {"technique": "browser_mcp_injection", "achieved": False, "owasp": "ASI01"},
            ],
        }
        collection = collector.collect(
            attack_results={},
            metadata=metadata,
        )
        summary = collection.browser_supplement_summary
        assert summary["total_attacks"] == 2
        assert summary["success_count"] == 1
        assert summary["dual_mode"] is True
        assert len(summary["techniques"]) == 2

    def test_no_browser_results_no_summary(
        self, supplement_ctx: PipelineContext
    ) -> None:
        """O-2: 无 Browser 补充结果时 summary 为空."""
        from pipeline.analysis.evidence_collector import EvidenceCollector

        collector = EvidenceCollector(
            target_model="test_model", model_tier="tier1"
        )
        collection = collector.collect(
            attack_results={},
            metadata={},
        )
        assert collection.browser_supplement_summary == {}
        assert len(collection.evidence) == 0
