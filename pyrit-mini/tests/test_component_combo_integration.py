"""tests/test_component_combo_integration.py — 组合体全链路集成（plan Wave 1-6）。

端到端验证 DoD：
    识别 → ComponentGraph → 攻击链规划 → 状态机执行 → 影响链举证 → 报告投影

这是"多组件组合体"主链路的连通性测试：任一环节断链，这里就会红。
"""

from __future__ import annotations

from typing import Any

from core.component_classifier import build_component_graph, classify
from core.contracts.attack_chain import AttackStep
from core.registry import get_registry
from core.state_machine import ChainStateMachine
from report.evidence import EvidenceCollector, VulnerabilityEvidence
from report.impact_chain import ImpactChainBuilder
from strike.common.budget import BudgetController
from strike.common.chain_planner import ChainPlanner


class _FakeFingerprint:
    def __init__(self, **kw: Any) -> None:
        self._d = dict(kw)

    def to_dict(self) -> dict[str, Any]:
        return dict(self._d)


class _FakeParsed:
    def __init__(self, *, url: str = "", path: str = "", body: str = "", **fp: Any) -> None:
        self.url = url
        self.path = path
        self.host = ""
        self.body = body
        self.api_category = "chat"
        self.target_fingerprint = _FakeFingerprint(**fp)


class _Args:
    """最小 args 替身：值来自 config/defaults.yaml 的实际配置。"""

    max_steps = 12
    max_depth = 6
    budget_enabled = True
    max_total_attacks = 200
    per_component_default_quota = 40
    wall_clock_deadline_seconds = 3600
    token_budget = 2_000_000
    weight_path = 0.40
    weight_body = 0.30
    weight_capability = 0.20
    weight_profile = 0.10
    neighbor_infer_confidence = 0.30
    fallback_min_confidence = 0.20
    max_components = 6


class _Ctx:
    """最小 PipelineContext 替身（仅提供新链路消费的字段）。"""

    def __init__(self) -> None:
        self.args = _Args()
        self.service_profile: dict[str, Any] = {}
        self.budget: Any = None
        self.component_graph: Any = None
        self.attack_chain: Any = None
        self.score_manifest: Any = None
        self.impact_chains: list[Any] = []


class TestComboPipelineIntegration:
    """识别 → 图 → 链 → 举证 → 报告投影 的连通性。"""

    def _run_pipeline(self) -> tuple[_Ctx, Any]:
        ctx = _Ctx()
        parsed = _FakeParsed(
            url="https://t.example.com/mcp",
            path="/mcp",
            body='{"jsonrpc":"2.0","method":"tools/list"}',
        )
        result = classify(parsed, args=ctx.args)
        assert not result.degraded, f"识别不应降级: {result.reason}"
        ctx.component_graph = build_component_graph(result, service_profile=ctx.service_profile)

        ctx.budget = BudgetController.from_ctx(ctx)
        chain = ChainPlanner.from_ctx(ctx).plan(ctx.component_graph, budget=ctx.budget)
        assert chain.steps, "应规划出攻击链步骤"
        ctx.attack_chain = chain
        return ctx, chain

    async def test_full_pipeline_produces_impact_chain(self) -> None:
        ctx, chain = self._run_pipeline()

        async def _exec(step: AttackStep, state: Any) -> dict[str, Any]:
            return {k: f"{step.component_key}::{k}" for k in step.produces}

        result = await ChainStateMachine(chain, checkpoint_enabled=False).run(_exec)
        assert result.succeeded > 0, f"链执行应至少成功一步: {result.failures}"
        assert chain.state.acquired, "跨步骤状态应被产出"

        # 影响链：为每个成功步骤挂上 EVD-* 证据
        ic = ImpactChainBuilder().build(
            attack_chain=chain,
            evidence_by_step={s.id: ["EVD-0001"] for s in chain.steps if chain.state.status.get(s.id) == "succeeded"},
        )
        assert ic.nodes, "应产出影响链节点"
        assert ic.validate_causality() == [], "有证据时不应有举证缺口"
        assert ic.terminal_impact, "最终业务影响不得为空"

    async def test_budget_trims_are_reported(self) -> None:
        """DoD：预算裁剪原因必须可见。"""
        ctx, _ = self._run_pipeline()
        budget = BudgetController(max_total_attacks=1, per_component_default_quota=1)
        keys = ctx.component_graph.keys()
        budget.trim_components(keys, keep=1)
        assert budget.trim_report(), "裁剪必须留痕"

    def test_registry_specs_drive_every_layer(self) -> None:
        """C3/IA-3：四层落点全部来自注册表声明，无代码内硬编码。"""
        reg = get_registry()
        for key in reg.keys():
            spec = reg.spec(key)
            assert spec is not None
            # 每个组件都必须声明评分 rubric 与报告构建器（supply_chain 除外，侦察级）
            if key == "supply_chain":
                continue
            assert spec.rubric, f"{key} 缺少 rubric"
            assert spec.report_builder, f"{key} 缺少 report_builder"
            assert spec.preferred_attack_class, f"{key} 缺少 preferred_attack_class"

    def test_evidence_carries_component_metadata(self) -> None:
        """CB-2：证据必须携带 component_type，否则组件专属报告永不生成。"""
        ev = VulnerabilityEvidence(
            evidence_id="EVD-0001",
            attack_id="a1",
            technique_name="prompt_sending",
            technique_display_name="Prompt Sending",
            converter_chain="",
            owasp_id="ASI02",
            owasp_category="Tool Poisoning",
            owasp_standard="OWASP ASI Top 10",
            owasp_severity="high",
            owasp_risk_score=8.0,
            owasp_mitigations=[],
            owasp_reference="",
            objective="x",
            jailbreak_prompt="x",
            harmful_output="y",
            is_success=True,
            file_suffix="_success",
            metadata={"component_type": "mcp_tool_poisoning"},
        )
        assert (ev.metadata or {}).get("component_type") == "mcp_tool_poisoning"


class TestEvidenceIdUniqueness:
    def test_ids_unique_across_techniques(self) -> None:
        """W6 fix：EVD-* 曾在每个技术重新从 0001 编号 → 重复并互相覆盖。"""

        class _Result:
            def __init__(self, idx: int) -> None:
                self.attack_result_id = f"attack-{idx}"
                self.metadata = {"component_type": "mcp_tool_poisoning"}
                self.objective = "obj"
                self.converted_prompt = "prompt"
                self.response = "resp"
                self.converters: list[Any] = []
                self.last_score = None

        # 两个技术各 3 条结果 → 旧逻辑会产出 3 组重复的 EVD-0001..0003
        attack_results = {
            "technique_a": [_Result(i) for i in range(3)],
            "technique_b": [_Result(i + 10) for i in range(3)],
        }
        collector = EvidenceCollector(target_model="mock")
        collection = collector.collect(attack_results=attack_results)
        ids = [ev.evidence_id for ev in collection.evidence]
        assert len(ids) == len(set(ids)), f"evidence_id 必须全局唯一，实际: {ids}"
