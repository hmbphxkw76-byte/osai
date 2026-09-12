"""tests/test_attack_chain.py — 攻击链规划 / 预算控制 / 契约层（plan Wave 2-3）。

覆盖：
    - ChainPlanner：组件图 → DAG 攻击链（依赖可满足，不饥饿）
    - BudgetController：三维预算 + 按 asr_prior 降序裁剪 + 裁剪留痕
    - 契约层：EvidenceRecord(CB-2) / VerdictRecord / ScoreRunManifest
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

from core.contracts import (
    AttackStep,
    ComponentEdge,
    ComponentGraph,
    ComponentNode,
    EvidenceRecord,
    JudgeVerdict,
    ScoreRunManifest,
    StatefulAttackChain,
    VerdictRecord,
)
from strike.common.budget import BudgetController
from strike.common.chain_planner import ChainPlanner


def _graph() -> ComponentGraph:
    g = ComponentGraph()
    for key, conf in (
        ("web_api", 0.9),
        ("llm_gateway", 0.8),
        ("mcp_tool_poisoning", 0.7),
        ("model_behavior_shift", 0.6),
    ):
        g.add_node(ComponentNode(component_key=key, confidence=conf, attributes={"asr_prior": 0.8}))
    g.add_edge(ComponentEdge(src="web_api", dst="llm_gateway", relation="gated_by", confidence=0.8))
    g.add_edge(ComponentEdge(src="llm_gateway", dst="mcp_tool_poisoning", relation="delegates_to", confidence=0.7))
    g.entry_points = ["web_api"]
    return g


class _Ctx:
    def __init__(self, **kw: Any) -> None:
        self.args = type("Args", (), kw)()


# =============================================================================
# ChainPlanner
# =============================================================================


class TestChainPlanner:
    def test_plan_produces_steps_for_each_component(self) -> None:
        chain = ChainPlanner().plan(_graph())
        assert len(chain.steps) == 4
        assert set(chain.components()) == {
            "web_api",
            "llm_gateway",
            "mcp_tool_poisoning",
            "model_behavior_shift",
        }

    def test_dependencies_are_satisfiable(self) -> None:
        """每个步骤的 consumes 必须能在链内被生产，否则会饥饿停滞。"""
        chain = ChainPlanner().plan(_graph())
        producible = {p for s in chain.steps for p in s.produces}
        for step in chain.steps:
            assert all(c in producible for c in step.consumes), f"{step.id} 消费了无人产出的 {step.consumes}"

    def test_ready_steps_not_empty_initially(self) -> None:
        chain = ChainPlanner().plan(_graph())
        assert chain.ready_steps(), "首轮必须有可调度步骤（否则链停滞）"

    def test_empty_graph_yields_empty_chain(self) -> None:
        assert ChainPlanner().plan(ComponentGraph()).steps == []

    def test_max_steps_respected(self) -> None:
        chain = ChainPlanner(max_steps=2).plan(_graph())
        assert len(chain.steps) <= 2

    def test_from_ctx_reads_config(self) -> None:
        planner = ChainPlanner.from_ctx(_Ctx(max_steps=3, max_depth=2))
        assert planner.max_steps == 3
        assert planner.max_depth == 2

    def test_chain_totals(self) -> None:
        chain = ChainPlanner().plan(_graph())
        assert chain.total_cost() == len(chain.steps)
        assert chain.progress() == (0, len(chain.steps))


# =============================================================================
# BudgetController
# =============================================================================


class TestBudgetController:
    def test_consume_until_exhausted(self) -> None:
        budget = BudgetController(max_total_attacks=2)
        assert budget.consume("mcp_tool_poisoning") is True
        assert budget.consume("mcp_tool_poisoning") is True
        assert budget.consume("mcp_tool_poisoning") is False
        assert budget.is_exhausted()

    def test_per_component_quota(self) -> None:
        budget = BudgetController(max_total_attacks=100, per_component_default_quota=1)
        assert budget.consume("rag_pipeline") is True
        assert budget.consume("rag_pipeline") is False
        assert budget.consume("web_api") is True, "配额按组件独立计算"

    def test_token_budget(self) -> None:
        budget = BudgetController(max_total_attacks=100, token_budget=10)
        assert budget.consume("a", tokens=6) is True
        assert budget.consume("a", tokens=6) is False

    def test_time_budget(self) -> None:
        budget = BudgetController(max_total_attacks=100, wall_clock_deadline=timedelta(seconds=-1))
        assert budget.consume("a") is False

    def test_disabled_budget_always_allows(self) -> None:
        budget = BudgetController(max_total_attacks=0, enabled=False)
        assert budget.consume("a") is True

    def test_trim_keeps_highest_asr_prior(self) -> None:
        budget = BudgetController(max_total_attacks=100)
        kept = budget.trim_components(
            ["audit_evasion", "mcp_tool_poisoning", "supply_chain"],
            asr_priors={"audit_evasion": 0.6, "mcp_tool_poisoning": 0.9, "supply_chain": 0.55},
            keep=2,
        )
        assert kept == ["mcp_tool_poisoning", "audit_evasion"]

    def test_trim_records_reason_for_report(self) -> None:
        """DoD：裁剪原因必须出现在报告中。"""
        budget = BudgetController(max_total_attacks=100)
        budget.trim_components(["a", "b"], asr_priors={"a": 0.9, "b": 0.1}, keep=1)
        report = budget.trim_report()
        assert report and report[0]["dropped"] == ["b"]
        assert report[0]["strategy"] == "asr_prior_desc"

    def test_snapshot_serializable(self) -> None:
        budget = BudgetController(max_total_attacks=5)
        budget.consume("a")
        snap = budget.remaining().to_dict()
        assert snap["attacks_used"] == 1
        assert snap["attacks_remaining"] == 4

    def test_from_ctx_reads_config(self) -> None:
        budget = BudgetController.from_ctx(
            _Ctx(
                budget_enabled=True,
                max_total_attacks=7,
                per_component_default_quota=3,
                wall_clock_deadline_seconds=60,
                token_budget=99,
            )
        )
        assert budget.max_total_attacks == 7
        assert budget.per_component_default_quota == 3
        assert budget.token_budget == 99


# =============================================================================
# 契约层
# =============================================================================


class TestEvidenceRecord:
    def test_component_type_read_from_metadata(self) -> None:
        """CB-2：下游通过 metadata.get('component_type') 读取。"""
        rec = EvidenceRecord(evidence_id="EVD-1", metadata={"component_type": "mcp_tool_poisoning"})
        assert rec.component_type == "mcp_tool_poisoning"

    def test_stamp_component_writes_metadata(self) -> None:
        rec = EvidenceRecord(evidence_id="EVD-1")
        rec.stamp_component("rag_pipeline", extra={"category": "rag"})
        assert rec.metadata["component_type"] == "rag_pipeline"
        assert rec.component_type == "rag_pipeline"

    def test_missing_component_returns_none(self) -> None:
        assert EvidenceRecord().component_type is None

    def test_content_hash_is_stable(self) -> None:
        a = EvidenceRecord(objective="x", response="y")
        b = EvidenceRecord(objective="x", response="y")
        c = EvidenceRecord(objective="x", response="z")
        assert a.content_hash() == b.content_hash()
        assert a.content_hash() != c.content_hash()


class TestVerdictRecord:
    def test_or_aggregation(self) -> None:
        rec = VerdictRecord()
        rec.add(JudgeVerdict(judge_id="J1", score_value=False, rationale="refused"))
        rec.add(JudgeVerdict(judge_id="J2", score_value=True, rationale="complied"))
        assert rec.aggregate("or") is True
        assert rec.agreement is False

    def test_and_aggregation(self) -> None:
        rec = VerdictRecord()
        rec.add(JudgeVerdict(judge_id="J1", score_value=True))
        rec.add(JudgeVerdict(judge_id="J2", score_value=False))
        assert rec.aggregate("and") is False

    def test_no_forged_agreement_when_single_judge(self) -> None:
        """治 score_pipeline 早返伪造 agreement 的问题。"""
        rec = VerdictRecord()
        rec.add(JudgeVerdict(judge_id="J1", score_value=True))
        rec.aggregate("or")
        assert rec.agreement is None, "未双裁时 agreement 必须为 None，不得伪造"

    def test_content_hash_changes_with_verdict(self) -> None:
        r1 = VerdictRecord(objective="x")
        r1.add(JudgeVerdict(judge_id="J1", score_value=True))
        r2 = VerdictRecord(objective="x")
        r2.add(JudgeVerdict(judge_id="J1", score_value=False))
        assert r1.content_hash() != r2.content_hash()


class TestScoreRunManifest:
    def test_rubric_hash_recorded(self, tmp_path: Path) -> None:
        rubric = tmp_path / "r.yaml"
        rubric.write_text("a: 1", encoding="utf-8")
        m = ScoreRunManifest(random_seed=42, temperature=0.0)
        m.add_rubric(rubric)
        assert m.rubric_hashes, "rubric 哈希必须记录（可复现性）"

    def test_missing_rubric_does_not_crash(self, tmp_path: Path) -> None:
        m = ScoreRunManifest()
        m.add_rubric(tmp_path / "nope.yaml")
        assert m.rubric_hashes == {}

    def test_fingerprint_stable(self) -> None:
        a = ScoreRunManifest(random_seed=42, judge_models=["gpt"], temperature=0.0)
        b = ScoreRunManifest(random_seed=42, judge_models=["gpt"], temperature=0.0)
        c = ScoreRunManifest(random_seed=43, judge_models=["gpt"], temperature=0.0)
        assert a.fingerprint() == b.fingerprint()
        assert a.fingerprint() != c.fingerprint()


class TestAttackStepContract:
    def test_ready_requires_dependencies_done(self) -> None:
        step = AttackStep(id="b", component_key="x", action="y", depends_on=["a"], consumes=["tok"])
        state = StatefulAttackChain().state
        assert step.ready(state) is False
        state.mark("a", "succeeded")
        assert step.ready(state) is True
        assert step.inputs_satisfied(state) is False
        assert step.unsatisfied_inputs(state) == ["tok"]

    def test_unsatisfied_inputs_reported(self) -> None:
        step = AttackStep(id="b", component_key="x", action="y", consumes=["tok"])
        state = StatefulAttackChain().state
        assert step.unsatisfied_inputs(state) == ["tok"]
