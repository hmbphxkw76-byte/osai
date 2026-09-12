"""report/impact_chain.py — 影响链举证引擎（plan Wave 3 / §3.6）。

红队报告的价值不在「某个 prompt 生效了」，而在**证明一条从入口组件到最终业务影响的
因果链**。本模块把攻击链执行结果 + 证据集升级为 `ImpactChain`。

核心约束（举证而非断言）：
    每个 `ImpactNode` 必须能追溯到 ≥1 个 `EVD-*` 证据；
    `validate_causality()` 对每条链返回 0 个缺口才算举证成立。

复用既有资产（接线而非重写）：
    `recon/a2a/trust_analyzer.py:182 _discover_chains` / `:200 _dfs_chains`
    —— 信任链 DFS 搜索实现，本模块把它提升为通用影响链搜索引擎
    （通过 `ComponentGraph.all_chains()` 复用其 DFS 语义）。

Academic basis:
    - OWASP ASI Top 10: 业务影响映射
    - CVSS v3.1: cvss_vector
    - Greshake et al. (arXiv:2302.12173): 间接注入影响传播
"""

from __future__ import annotations

import logging
from typing import Any

from core.contracts.impact_chain import CausalityGap, ImpactChain, ImpactLink, ImpactNode

logger = logging.getLogger(__name__)

# 组件 → （技术结果模板，业务影响模板，默认严重级，OWASP，CVSS 向量）
_IMPACT_TEMPLATES: dict[str, tuple[str, str, str, list[str], str]] = {
    "web_api": (
        "绕过接入层认证/限流，取得可直达业务的端点",
        "未授权访问：攻击者可在无有效凭据下调用业务接口，导致数据越权与配额耗尽",
        "high",
        ["API1", "API2"],
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    ),
    "llm_gateway": (
        "提取/绕过网关 system prompt 与护栏策略",
        "安全策略失效：内容护栏被绕过，下游所有组件的滥用风险敞口同时放大",
        "high",
        ["LLM01", "ASI01"],
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
    ),
    "rag_pipeline": (
        "向知识库注入投毒文档并诱导检索命中",
        "决策污染：业务回答被攻击者可控内容劫持，可导致错误决策与品牌/合规风险",
        "high",
        ["LLM08", "ASI04"],
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:N",
    ),
    "embedding": (
        "操纵向量检索排序 / 反演嵌入内容",
        "检索完整性丧失：敏感内容可被定向召回或反演，造成信息泄露",
        "medium",
        ["LLM08"],
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N",
    ),
    "mcp_tool_poisoning": (
        "注册/篡改 MCP 工具 Schema 并诱导模型调用",
        "任意工具执行：攻击者可借模型之手触达内部系统与数据，形成实际业务损失",
        "critical",
        ["ASI02", "ASI05"],
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    ),
    "a2a_agent_integrity": (
        "伪造 AgentCard / 劫持跨 agent 任务流",
        "供应链式信任滥用：恶意 agent 进入编排拓扑，可截获凭据与业务数据",
        "critical",
        ["ASI06", "ASI07"],
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L",
    ),
    "session_memory": (
        "投毒长期记忆 / 跨会话上下文泄漏",
        "持久化后门：一次注入在后续会话持续生效，并可能跨租户泄露",
        "high",
        ["LLM06", "ASI08"],
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
    ),
    "model_behavior_shift": (
        "越狱 / 输出过滤绕过 / 后门触发",
        "内容安全失效：模型输出违规内容或被植入行为后门，直接冲击业务合规",
        "high",
        ["LLM01", "LLM02"],
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    ),
    "audit_evasion": (
        "规避日志/追踪/告警，抹除攻击痕迹",
        "可观测性丧失：攻击行为无法被审计与溯源，事件响应能力失效",
        "medium",
        ["LLM09"],
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
    ),
    "supply_chain": (
        "枚举第三方插件/skill 与依赖清单",
        "供应链暴露：可定位含已知漏洞的插件，为后续定向利用提供入口",
        "low",
        ["LLM03", "LLM05"],
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N",
    ),
}

_FALLBACK = ("在目标组件上取得非预期行为", "业务影响待人工确认", "low", [], "")


def _template_for(component_key: str) -> tuple[str, str, str, list[str], str]:
    return _IMPACT_TEMPLATES.get(component_key, _FALLBACK)


class ImpactChainBuilder:
    """把攻击链执行结果升级为影响链。

    Usage:
        builder = ImpactChainBuilder()
        chain = builder.build(
            chain_result=run_result,
            attack_chain=ctx.attack_chain,
            evidence_by_step={"mcp_tool_poisoning:orchestrator": ["EVD-0001", ...]},
        )
        gaps = chain.validate_causality()
    """

    def build(
        self,
        *,
        chain_result: Any = None,
        attack_chain: Any = None,
        evidence_by_step: dict[str, list[str]] | None = None,
        executed_steps: list[Any] | None = None,
    ) -> ImpactChain:
        """构建影响链。

        Args:
            chain_result: `ChainRunResult`（可选，用于筛选成功步骤）
            attack_chain: `StatefulAttackChain`
            evidence_by_step: step_id → EVD-* 证据编号列表
            executed_steps: 已执行步骤列表（无 attack_chain 时使用）

        Returns:
            ImpactChain。无成功步骤时返回空链（IA-6：不崩溃）。
        """
        evidence = dict(evidence_by_step or {})
        steps = executed_steps
        if steps is None and attack_chain is not None:
            state = attack_chain.state
            steps = [s for s in attack_chain.steps if state.status.get(s.id) == "succeeded"]
        steps = list(steps or [])

        if not steps:
            logger.warning("[ImpactChain] 无成功步骤，生成空影响链")
            return ImpactChain()

        nodes: list[ImpactNode] = []
        links: list[ImpactLink] = []
        prev_by_component: dict[str, str] = {}

        for step in steps:
            step_id = str(getattr(step, "id", "") or "")
            component_key = str(getattr(step, "component_key", "") or "unknown")
            outcome, business_impact, severity, owasp, cvss = _template_for(component_key)
            ev_ids = list(evidence.get(step_id, []) or [])

            node = ImpactNode(
                step_id=step_id,
                component_key=component_key,
                outcome=outcome,
                business_impact=business_impact,
                severity=severity,  # type: ignore[arg-type]
                owasp=list(owasp),
                cvss_vector=cvss or None,
                evidence_ids=ev_ids,
            )
            nodes.append(node)

            # 因果边：与上一个已完成步骤相连（链内顺序即因果顺序）
            if prev_by_component:
                last_id = list(prev_by_component.values())[-1]
                links.append(
                    ImpactLink(
                        from_step=last_id,
                        to_step=step_id,
                        mechanism=self._mechanism(prev_by_component, component_key, step),
                        evidence_ids=list(evidence.get(last_id, []) or []),
                    )
                )
            prev_by_component[component_key] = step_id

        chain = ImpactChain(
            nodes=nodes,
            links=links,
            terminal_impact=self._terminal_impact(nodes),
            entry_step=nodes[0].step_id if nodes else None,
        )
        return chain

    # ------------------------------------------------------------------
    # 内部
    # ------------------------------------------------------------------
    @staticmethod
    def _mechanism(prev_by_component: dict[str, str], component_key: str, step: Any) -> str:
        """生成人类可读的因果机制说明。"""
        consumed = list(getattr(step, "consumes", []) or [])
        produces = list(getattr(step, "produces", []) or [])
        src = ",".join(prev_by_component.keys())
        if consumed:
            return f"上游 {src} 产出 {', '.join(consumed)}，被 {component_key} 消费后触发本步"
        if produces:
            return f"{component_key} 利用既有探测结果产出 {', '.join(produces)}"
        return f"{component_key} 在已有通道上继续深入"

    @staticmethod
    def _terminal_impact(nodes: list[ImpactNode]) -> str:
        """最终业务影响 = 最高严重级节点的业务影响。"""
        if not nodes:
            return ""
        order = ["low", "medium", "high", "critical"]
        top = max(nodes, key=lambda n: order.index(n.severity))
        return top.business_impact


def build_impact_chains_from_components(
    graph: Any,
    *,
    evidence_by_component: dict[str, list[str]] | None = None,
) -> list[ImpactChain]:
    """从组件拓扑图枚举**多条**影响链（DFS，复用 `_dfs_chains` 语义）。

    用于报告中展示「入口 → 业务影响」的全部可达路径。

    Args:
        graph: ComponentGraph
        evidence_by_component: component_key → EVD-* 列表

    Returns:
        ImpactChain 列表。空图/无路径返回空列表。
    """
    evidence = dict(evidence_by_component or {})
    if graph is None or not getattr(graph, "nodes", None):
        return []

    entries = list(getattr(graph, "entry_points", []) or [])
    if not entries:
        dominant = graph.dominant()
        entries = [dominant] if dominant else []

    leaves = [k for k in graph.keys() if not graph.neighbors(k)]
    if not leaves:
        leaves = [n.component_key for n in graph.nodes]

    chains: list[ImpactChain] = []
    for entry in entries:
        for leaf in leaves:
            for path in graph.all_chains(entry, leaf):
                chain = _chain_from_path(path, graph, evidence)
                if chain.nodes:
                    chains.append(chain)
    return chains


def _chain_from_path(path: list[str], graph: Any, evidence: dict[str, list[str]]) -> ImpactChain:
    nodes: list[ImpactNode] = []
    links: list[ImpactLink] = []
    for idx, key in enumerate(path):
        outcome, business_impact, severity, owasp, cvss = _template_for(key)
        node = ImpactNode(
            step_id=f"{idx}:{key}",
            component_key=key,
            outcome=outcome,
            business_impact=business_impact,
            severity=severity,  # type: ignore[arg-type]
            owasp=list(owasp),
            cvss_vector=cvss or None,
            evidence_ids=list(evidence.get(key, []) or []),
        )
        nodes.append(node)
        if idx > 0:
            links.append(
                ImpactLink(
                    from_step=f"{idx - 1}:{path[idx - 1]}",
                    to_step=node.step_id,
                    mechanism=f"{path[idx - 1]} 对 {key} 的关系被滥用，影响向下游传导",
                    evidence_ids=list(evidence.get(path[idx - 1], []) or []),
                )
            )
    return ImpactChain(
        nodes=nodes,
        links=links,
        terminal_impact=nodes[-1].business_impact if nodes else "",
        entry_step=nodes[0].step_id if nodes else None,
    )


def validate_all(chains: list[ImpactChain]) -> list[CausalityGap]:
    """批量校验；返回全部缺口。空列表 = 全部举证成立。"""
    gaps: list[CausalityGap] = []
    for chain in chains:
        gaps.extend(chain.validate_causality())
    return gaps
