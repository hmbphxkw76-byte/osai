"""tests/test_state_machine.py — 攻击链状态机 + checkpoint/resume（plan Wave 3）。

覆盖 DoD：
    - 链中步骤 B 能消费步骤 A 的 acquired 产出
    - 中断后 --resume 从最后一个完成步骤继续，结果一致
    - 失败步骤留痕（禁止静默）
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.contracts.attack_chain import AttackStep, ChainState, StatefulAttackChain
from core.state_machine import ChainStateMachine


def _two_step_chain() -> StatefulAttackChain:
    """A 产出 token，B 消费 token —— 验证跨步骤状态传递。"""
    chain = StatefulAttackChain(name="t")
    chain.steps = [
        AttackStep(id="a:probe", component_key="web_api", action="probe", produces=["token"]),
        AttackStep(
            id="b:exploit",
            component_key="model_behavior_shift",
            action="exploit",
            depends_on=["a:probe"],
            consumes=["token"],
            produces=["jailbreak_result"],
        ),
    ]
    for s in chain.steps:
        chain.state.status[s.id] = "pending"
    return chain


async def _ok_executor(step: AttackStep, state: ChainState) -> dict[str, Any]:
    return {k: f"value-of-{k}" for k in step.produces}


class TestDagScheduling:
    async def test_step_b_consumes_step_a_output(self) -> None:
        chain = _two_step_chain()
        result = await ChainStateMachine(chain, checkpoint_enabled=False).run(_ok_executor)

        assert result.succeeded == 2
        assert chain.state.acquired["token"] == "value-of-token"
        assert chain.state.acquired["jailbreak_result"] == "value-of-jailbreak_result"

    async def test_dependent_step_not_run_before_upstream(self) -> None:
        order: list[str] = []

        async def _tracking(step: AttackStep, state: ChainState) -> dict[str, Any]:
            order.append(step.id)
            return {k: k for k in step.produces}

        chain = _two_step_chain()
        await ChainStateMachine(chain, checkpoint_enabled=False).run(_tracking)
        assert order == ["a:probe", "b:exploit"], "依赖步骤必须排在上游之后"

    async def test_ready_steps_requires_inputs(self) -> None:
        chain = _two_step_chain()
        assert [s.id for s in chain.ready_steps()] == ["a:probe"]


class TestFailureHandling:
    async def test_failure_is_recorded_not_silent(self) -> None:
        async def _failing(step: AttackStep, state: ChainState) -> dict[str, Any]:
            if step.id == "a:probe":
                raise RuntimeError("boom")
            return {k: k for k in step.produces}

        chain = _two_step_chain()
        result = await ChainStateMachine(chain, checkpoint_enabled=False).run(_failing)

        assert result.failed == 1
        assert result.failures[0]["step_id"] == "a:probe"
        assert "boom" in result.failures[0]["reason"]
        assert chain.state.failed_steps, "失败必须写入 ChainState.failed_steps"

    async def test_stop_on_failure_when_configured(self) -> None:
        async def _failing(step: AttackStep, state: ChainState) -> dict[str, Any]:
            raise RuntimeError("stop")

        chain = _two_step_chain()
        result = await ChainStateMachine(
            chain, checkpoint_enabled=False, continue_on_step_failure=False
        ).run(_failing)
        assert result.succeeded == 0
        assert result.failed >= 1


class TestCheckpointResume:
    async def test_resume_continues_from_completed_step(self, tmp_path: Path) -> None:
        ckpt = tmp_path / "ck" / "attack_chain_checkpoint.json"

        chain = _two_step_chain()
        sm1 = ChainStateMachine(chain, checkpoint_path=ckpt)
        r1 = await sm1.run(_ok_executor)
        assert r1.succeeded == 2
        assert ckpt.is_file()

        # 新链（模拟进程重启）：步骤定义相同，状态为空
        fresh = _two_step_chain()
        sm2 = ChainStateMachine(fresh, checkpoint_path=ckpt)
        r2 = await sm2.run(_ok_executor)

        assert r2.resumed is True, "应从 checkpoint 恢复"
        assert r2.succeeded == 0, "已完成步骤不得重复执行"
        assert fresh.state.acquired["token"] == "value-of-token", "恢复后状态一致"

    async def test_resume_tolerates_corrupt_checkpoint(self, tmp_path: Path) -> None:
        ckpt = tmp_path / "bad.json"
        ckpt.write_text("{not json", encoding="utf-8")

        chain = _two_step_chain()
        result = await ChainStateMachine(chain, checkpoint_path=ckpt).run(_ok_executor)
        assert result.resumed is False
        assert result.succeeded == 2

    def test_checkpoint_file_schema(self, tmp_path: Path) -> None:
        ckpt = tmp_path / "ck.json"
        chain = _two_step_chain()
        ChainStateMachine(chain, checkpoint_path=ckpt)._checkpoint()

        payload = json.loads(ckpt.read_text(encoding="utf-8"))
        assert payload["schema_version"] == "1.0"
        assert payload["chain"]["steps"][0]["id"] == "a:probe"


class TestRollback:
    def test_rollback_clears_step_output(self) -> None:
        chain = _two_step_chain()
        chain.state.produce("token", "v")
        chain.state.mark("a:probe", "succeeded")

        sm = ChainStateMachine(chain, checkpoint_enabled=False)
        assert sm.rollback_step("a:probe") is True
        assert "token" not in chain.state.acquired
        assert chain.state.status.get("a:probe") is None

    def test_rollback_unknown_step_returns_false(self) -> None:
        chain = _two_step_chain()
        assert ChainStateMachine(chain, checkpoint_enabled=False).rollback_step("nope") is False


class TestChainContract:
    def test_progress_and_completion(self) -> None:
        chain = _two_step_chain()
        assert chain.progress() == (0, 2)
        chain.state.mark("a:probe", "succeeded")
        assert chain.progress() == (1, 2)
        assert chain.is_complete() is False

    def test_topological_steps_respects_dependencies(self) -> None:
        chain = _two_step_chain()
        order = [s.id for s in chain.topological_steps()]
        assert order.index("a:probe") < order.index("b:exploit")

    def test_cycle_does_not_crash(self) -> None:
        chain = StatefulAttackChain()
        chain.steps = [
            AttackStep(id="x", component_key="a", action="a", depends_on=["y"]),
            AttackStep(id="y", component_key="b", action="b", depends_on=["x"]),
        ]
        ids = [s.id for s in chain.topological_steps()]
        assert sorted(ids) == ["x", "y"]

    def test_chain_serialization_roundtrip(self) -> None:
        chain = _two_step_chain()
        restored = StatefulAttackChain.from_dict(chain.to_dict())
        assert [s.id for s in restored.steps] == [s.id for s in chain.steps]
