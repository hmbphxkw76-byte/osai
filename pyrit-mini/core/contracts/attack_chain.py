"""core/contracts/attack_chain.py — 有状态攻击链（StatefulAttackChain）。

单组件、单轮、无状态攻击无法还原企业场景。攻击链要求：
    1. 步骤为 DAG 而非线性表（允许条件分支与回退）
    2. 跨步骤携带 `ChainState.acquired`（能力/凭据/知识）
    3. 状态可序列化 → 支撑 checkpoint / resume（--resume 真语义）

复用既有资产（接线而非重写）：
    strike/common/escalation_runtime.py:294 run_escalation_chain    → 线性升级链雏形
    strike/injection/indirect_pi.py:319 generate_recursive_attack_chain
    strike/injection/file_upload_executor.py:341 execute_file_upload_attack_chain
    strike/web/link_evasion.py:265 generate_gradual_injection_chain
    strike/evasion/sql.py:243 generate_gradual_escalation_chain
    strike/session/session_manager.py:36 SessionStateManager
    recon/target_builder.py:57 ChatIdStateManager
    recon/api/auth_detector.py:39 AuthState
    —— 上述状态持有者统一收敛到 ChainState（宪法 C3）

Academic basis:
    - Chao et al. (arXiv:2310.08419) PAIR: 多轮迭代式攻击
    - Mehrotra et al. (arXiv:2405.17350) TAP: 树搜索式攻击链
"""

from __future__ import annotations

from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.0"

StepStatus = Literal["pending", "running", "succeeded", "failed", "skipped"]


class FailedStep(BaseModel):
    """失败步骤留痕（反静默：失败必须有 reason，禁止 except: pass）。"""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    step_id: str
    reason: str
    retriable: bool = True


class ChainState(BaseModel):
    """攻击链在任意时刻的完整状态，可序列化 → 支持 checkpoint / resume。"""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    chain_id: UUID = Field(default_factory=uuid4)
    step_index: int = 0
    acquired: dict[str, Any] = Field(default_factory=dict)
    visited_components: list[str] = Field(default_factory=list)
    failed_steps: list[FailedStep] = Field(default_factory=list)
    status: dict[str, StepStatus] = Field(default_factory=dict)
    budget_spent: int = 0

    # ------------------------------------------------------------------
    # acquired 读写（步骤间传递产出物）
    # ------------------------------------------------------------------
    def produce(self, key: str, value: Any) -> None:
        """写入产出物；同键覆盖（后者为更完整的成果）。"""
        self.acquired[key] = value

    def consume(self, key: str, default: Any = None) -> Any:
        """读取上游产出物；缺失返回 default（不抛异常）。"""
        return self.acquired.get(key, default)

    def has(self, key: str) -> bool:
        return key in self.acquired

    # ------------------------------------------------------------------
    # 步骤推进（不可变小步推进：返回新状态，便于步骤级回滚）
    # ------------------------------------------------------------------
    def snapshot(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    def visit(self, component_key: str) -> None:
        if component_key and component_key not in self.visited_components:
            self.visited_components.append(component_key)

    def mark(self, step_id: str, status: StepStatus) -> None:
        self.status[step_id] = status

    def is_done(self, step_id: str) -> bool:
        return self.status.get(step_id) in ("succeeded", "skipped")

    def record_failure(self, step_id: str, reason: str, *, retriable: bool = True) -> None:
        self.failed_steps.append(FailedStep(step_id=step_id, reason=reason, retriable=retriable))
        self.mark(step_id, "failed")


class AttackStep(BaseModel):
    """攻击链中的一个步骤。depends_on 形成 DAG。"""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    id: str
    component_key: str
    action: str  # 对应 strike 模块 id
    depends_on: list[str] = Field(default_factory=list)
    produces: list[str] = Field(default_factory=list)
    consumes: list[str] = Field(default_factory=list)
    budget_cost: int = 1
    metadata: dict[str, Any] = Field(default_factory=dict)

    def ready(self, state: ChainState) -> bool:
        """前置步骤全部完成时可调度。"""
        return all(state.is_done(dep) for dep in self.depends_on)

    def inputs_satisfied(self, state: ChainState) -> bool:
        """consumes 声明的输入是否齐备。"""
        return all(state.has(key) for key in self.consumes)

    def unsatisfied_inputs(self, state: ChainState) -> list[str]:
        return [k for k in self.consumes if not state.has(k)]


class StatefulAttackChain(BaseModel):
    """有状态攻击链：steps 为 DAG，state 跨步骤传递。"""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    chain_id: UUID = Field(default_factory=uuid4)
    name: str = ""
    steps: list[AttackStep] = Field(default_factory=list)
    state: ChainState = Field(default_factory=ChainState)

    # ------------------------------------------------------------------
    # DAG 调度
    # ------------------------------------------------------------------
    def step(self, step_id: str) -> AttackStep | None:
        for s in self.steps:
            if s.id == step_id:
                return s
        return None

    def ready_steps(self) -> list[AttackStep]:
        """返回当前可调度（前置完成 + 输入齐备 + 未完成）的步骤。"""
        return [
            s
            for s in self.steps
            if s.ready(self.state)
            and s.inputs_satisfied(self.state)
            and self.state.status.get(s.id) in (None, "pending")
        ]

    def completed_steps(self) -> list[AttackStep]:
        return [s for s in self.steps if self.state.status.get(s.id) == "succeeded"]

    def is_complete(self) -> bool:
        return all(self.state.status.get(s.id) in ("succeeded", "skipped") for s in self.steps)

    def progress(self) -> tuple[int, int]:
        done = sum(1 for s in self.steps if self.state.status.get(s.id) in ("succeeded", "skipped"))
        return done, len(self.steps)

    def total_cost(self) -> int:
        return sum(s.budget_cost for s in self.steps)

    def components(self) -> list[str]:
        out: list[str] = []
        for s in self.steps:
            if s.component_key not in out:
                out.append(s.component_key)
        return out

    def topological_steps(self) -> list[AttackStep]:
        """按 depends_on 拓扑排序；存在环时把剩余步骤按原序追加（不崩溃）。"""
        remaining = {s.id: s for s in self.steps}
        order: list[AttackStep] = []
        emitted: set[str] = set()
        while remaining:
            batch = [s for s in remaining.values() if all(d in emitted for d in s.depends_on)]
            if not batch:  # 环：按原序退出
                order.extend(remaining.values())
                break
            for s in batch:
                order.append(s)
                emitted.add(s.id)
                remaining.pop(s.id, None)
        return order

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "StatefulAttackChain":
        return cls.model_validate(data)
