"""strike/chain_planner.py — 跨组件攻击链规划器（plan Wave 3 / §3.2）。

把 `ComponentGraph`（多组件组合体拓扑）提升为 `StatefulAttackChain`（DAG 攻击链）：

    ComponentGraph（识别产出）
        → 按 entry_points 做 BFS 分层
        → 每组件生成一个 AttackStep（action = 该组件的 strike 模块）
        → 用 produces/consumes 建立跨步骤数据依赖（ChainState.acquired 传递）
        → 按 asr_prior 与预算裁剪
        → StatefulAttackChain

复用既有资产（接线而非重写）：
    `recon/a2a/attack_planner.py:115 AttackPathPlanner` 是 A2A 特化的路径规划器；
    本模块把它**泛化到全部组件**——当图中含 `a2a_agent_integrity` 节点且 A2A 拓扑
    数据可用时，会优先采纳 `generate_attack_plan()` 给出的步骤优先级。

Academic basis:
    - Mehrotra et al. (arXiv:2405.17350) TAP: 树搜索式攻击路径
    - Chao et al. (arXiv:2310.08419) PAIR: 迭代式多轮攻击链
    - Greshake et al. (arXiv:2302.12173): 跨组件间接注入
"""

from __future__ import annotations

import logging
from typing import Any

from core.contracts.attack_chain import AttackStep, ChainState, StatefulAttackChain
from core.contracts.component_graph import ComponentGraph

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 链数据流契约：组件 → （产出物，消费物）
# 这是"步骤 B 能消费步骤 A 的 acquired 产出"（DoD）的声明处。
# ---------------------------------------------------------------------------
_CHAIN_DATAFLOW: dict[str, tuple[list[str], list[str]]] = {
    # component_key: (produces, consumes)
    "web_api": (["reachable_endpoint", "auth_token"], []),
    "llm_gateway": (["system_prompt", "guardrail_profile"], ["reachable_endpoint"]),
    "rag_pipeline": (["poisoned_doc_id", "retrieved_context"], ["reachable_endpoint"]),
    "embedding": (["vector_target", "similarity_probe"], ["reachable_endpoint"]),
    "mcp_tool_poisoning": (["tool_schema", "tool_invoke_capability"], ["reachable_endpoint"]),
    "a2a_agent_integrity": (["agent_card", "agent_trust"], ["reachable_endpoint"]),
    "session_memory": (["session_id", "memory_write"], ["auth_token"]),
    "model_behavior_shift": (["jailbreak_result"], ["system_prompt", "guardrail_profile"]),
    "audit_evasion": (["log_blind_spot"], []),
    "supply_chain": (["plugin_manifest"], []),
}


def _produces_for(component_key: str) -> list[str]:
    return list(_CHAIN_DATAFLOW.get(component_key, ([], []))[0])


def _consumes_for(component_key: str) -> list[str]:
    return list(_CHAIN_DATAFLOW.get(component_key, ([], []))[1])


class ChainPlanner:
    """跨组件攻击链规划器。

    Usage:
        planner = ChainPlanner.from_ctx(ctx)
        chain = planner.plan(graph, budget=budget)
    """

    def __init__(self, *, max_steps: int = 12, max_depth: int = 6) -> None:
        self.max_steps = max(1, int(max_steps))
        self.max_depth = max(1, int(max_depth))

    @classmethod
    def from_ctx(cls, ctx: Any) -> "ChainPlanner":
        args = getattr(ctx, "args", None)

        def _g(key: str, default: Any) -> Any:
            val = getattr(args, key, None) if args is not None else None
            return default if val is None else val

        return cls(max_steps=int(_g("max_steps", 12)), max_depth=int(_g("max_depth", 6)))

    # ------------------------------------------------------------------
    # 规划
    # ------------------------------------------------------------------
    def plan(
        self,
        graph: ComponentGraph,
        *,
        budget: Any = None,
        a2a_plan: dict[str, Any] | None = None,
    ) -> StatefulAttackChain:
        """把组件拓扑图规划为有状态攻击链。

        Args:
            graph: ComponentGraph（RECON 识别产出）
            budget: BudgetController（可选；用于按 asr_prior 裁剪步骤）
            a2a_plan: `ctx.a2a_attack_plan`（可选；A2A 特化优先级来源）

        Returns:
            StatefulAttackChain。空图返回空链（IA-6：不崩溃）。
        """
        chain = StatefulAttackChain(name="component_combo_chain")

        if graph is None or not graph.nodes:
            logger.warning("[ChainPlanner] 组件图为空，生成空攻击链（降级为单组件直攻）")
            return chain

        ordered_keys = self._order_components(graph)
        # 组合体推断出的低置信节点排后，避免抢占预算
        ordered_keys.sort(
            key=lambda k: (
                bool((graph.node(k).attributes.get("inferred") if graph.node(k) else False)),
                -float((graph.node(k).confidence if graph.node(k) else 0.0)),
            )
        )

        if budget is not None:
            try:
                priors = {
                    k: float((graph.node(k).attributes.get("asr_prior", 0.0) if graph.node(k) else 0.0))
                    for k in ordered_keys
                }
                kept = budget.trim_components(ordered_keys, asr_priors=priors, keep=self.max_steps)
                # trim 会按先验重排；此处再按拓扑深度稳定化一次
                ordered_keys = [k for k in ordered_keys if k in set(kept)]
            except Exception as e:
                logger.warning("[ChainPlanner] 预算裁剪失败，使用全量组件: %s", e)

        ordered_keys = ordered_keys[: self.max_steps]

        a2a_priority = self._a2a_priority(a2a_plan)

        # 第一遍：收集本链内全部可得产出物。
        # 关键：只把"链内真有生产者"的输入声明为 consumes，否则该步骤永远
        # inputs_satisfied()==False → 整条链饥饿停滞（无上游时按 best-effort 执行）。
        producible: set[str] = set()
        for key in ordered_keys:
            producible.update(_produces_for(key))

        for idx, key in enumerate(ordered_keys):
            node = graph.node(key)
            if node is None:
                continue
            action = self._pick_action(key, node)
            produces = _produces_for(key)
            consumes = [c for c in _consumes_for(key) if c in producible and c not in produces]

            step = AttackStep(
                id=f"{key}:{action}",
                component_key=key,
                action=action,
                depends_on=[],  # 第二遍统一解析（生产者可能排在后面）
                produces=produces,
                consumes=consumes,
                budget_cost=1,
                metadata={
                    "confidence": node.confidence,
                    "asr_prior": node.attributes.get("asr_prior", 0.0),
                    "inferred": bool(node.attributes.get("inferred", False)),
                    "a2a_priority": a2a_priority.get(key),
                    "order": idx,
                },
            )
            chain.steps.append(step)
            chain.state.status[step.id] = "pending"
            chain.state.budget_spent = 0

        # 第二遍：解析 depends_on —— 生产者可能排在消费者之后，必须全量扫一遍
        for step in chain.steps:
            if not step.consumes:
                continue
            deps: list[str] = []
            for other in chain.steps:
                if other.id == step.id or other.component_key == step.component_key:
                    continue  # 同组件不串行，避免伪依赖
                if any(p in step.consumes for p in other.produces):
                    deps.append(other.id)
            if len(deps) > self.max_depth:
                deps = deps[: self.max_depth]
            step.depends_on = deps

        logger.info(
            "[ChainPlanner] 生成攻击链: %d 步 / %d 组件（入口: %s）",
            len(chain.steps),
            len(chain.components()),
            ", ".join(graph.entry_points) or "(无)",
        )
        return chain

    # ------------------------------------------------------------------
    # 内部工具
    # ------------------------------------------------------------------
    def _order_components(self, graph: ComponentGraph) -> list[str]:
        """按「入口可达深度」分层排序：入口组件先攻，逐层深入。

        复用 ComponentGraph 的 BFS 能力；不可达节点按置信度降序追加（不丢弃）。
        """
        ordered: list[str] = []
        seen: set[str] = set()

        for entry in graph.entry_points or []:
            if entry not in graph.keys():
                continue
            for key in self._bfs_layers(graph, entry):
                if key not in seen:
                    seen.add(key)
                    ordered.append(key)

        rest = [k for k in graph.keys() if k not in seen]
        rest.sort(key=lambda k: -(graph.node(k).confidence if graph.node(k) else 0.0))
        return ordered + rest

    def _bfs_layers(self, graph: ComponentGraph, src: str) -> list[str]:
        """从 src 起按层返回可达节点（广度优先，深度 <= max_depth）。"""
        from collections import deque

        out: list[str] = []
        visited: set[str] = {src}
        queue: deque[tuple[str, int]] = deque([(src, 0)])
        while queue:
            cur, depth = queue.popleft()
            out.append(cur)
            if depth >= self.max_depth:
                continue
            for nxt in graph.neighbors(cur):
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append((nxt, depth + 1))
        return out

    def _a2a_priority(self, a2a_plan: dict[str, Any] | None) -> dict[str, float]:
        """从 `ctx.a2a_attack_plan` 抽取 A2A 特化优先级（复用既有规划器产出）。"""
        if not isinstance(a2a_plan, dict):
            return {}
        out: dict[str, float] = {}
        try:
            for step in a2a_plan.get("steps", []) or []:
                if not isinstance(step, dict):
                    continue
                target = str(step.get("target_agent") or "")
                if target:
                    out["a2a_agent_integrity"] = max(
                        out.get("a2a_agent_integrity", 0.0), float(step.get("priority", 0.0) or 0.0)
                    )
        except Exception as e:
            logger.debug("[ChainPlanner] A2A 优先级解析失败（忽略）: %s", e)
        return out

    def _pick_action(self, component_key: str, node: Any) -> str:
        """为组件挑选攻击动作：优先 `preferred_attack_class`，回落首个 strike 模块。"""
        preferred = str(node.attributes.get("preferred_attack_class") or "")
        if preferred and preferred != "PromptSendingAttack":
            return preferred
        try:
            from core.registry import get_registry

            spec = get_registry().spec(component_key)
            if spec is not None and spec.strike_modules:
                return spec.strike_modules[0].rsplit(".", 1)[-1]
        except Exception:
            pass
        return "prompt_sending"


def build_chain_state(chain: StatefulAttackChain) -> ChainState:
    """初始化链状态（供 checkpoint / resume 复用）。"""
    return chain.state
