# -*- coding: utf-8 -*-
"""recon/a2a - A2A/多智能体侦察模块 (A2A Multi-Agent Reconnaissance)

对 A2A (Agent-to-Agent) 多代理系统执行侦察:
- Agent Card 发现 (Agent Card Discovery)
- 代理拓扑分析 (Multi-Agent Topology)
- 防御感知 (Defense Awareness)
- 攻击规划 (Attack Planning)
- 能力枚举 (Capability Enumeration)
- 信任链分析 (Trust Chain Analysis)
- 防御表面映射 (Defense Surface Mapping)

模块清单:
    - agent_card              : Agent Card 数据结构与获取
    - discoverer              : Agent Card 发现器
    - topology                : 多代理拓扑分析器
    - defense_awareness       : 防御机制感知器
    - attack_planner          : 攻击规划器
    - topology_mapper         : 拓扑映射器
    - capability_enumerator   : 代理能力枚举器
    - trust_analyzer          : 信任链分析器
    - defense_mapper          : 防御表面映射器

Academic basis:
    - Eidam et al. (arXiv:2407.16924) — A2A trust chain exploitation
    - Zhan et al. (arXiv:2307.00929) — Schema-guided injection
    - Greshake et al. (arXiv:2302.12173) — Indirect prompt injection
    - OWASP ASI01 — Agent Identity Spoofing
    - OWASP ASI07 — Cross-Agent Injection

Constitution compliance:
    - R-SIZE: 每模块 < 800 行
    - R-H3: 单一职责, 无双重实现
    - R-S1: 不硬编码目标标识符
    - R-S4: 测试全部 mock
"""

from recon.a2a.agent_card import AgentCard, AgentSkill, fetch_agent_card
from recon.a2a.attack_planner import (
    A2AAttackPlan,
    AttackPathPlanner,
    AttackStep,
    AttackType,
    generate_attack_plan,
)
from recon.a2a.capability_enumerator import (
    A2ACapabilityEnumerator,
    CapabilityEnumResult,
    CapabilityInfo,
    enumerate_a2a_capabilities,
)
from recon.a2a.defense_awareness import (
    DefenseProfile,
    EvasionTactics,
    check_defense_bypass_feasibility,
    detect_defenses,
    generate_evasion_strategy,
)
from recon.a2a.defense_mapper import (
    A2ADefenseMapper,
    DefenseIndicator,
    DefenseMapResult,
    map_a2a_defenses,
)
from recon.a2a.discoverer import (
    A2AEndpoint,
    AgentCardResult,
    AgentTopologyNode,
    DiscoveryResult,
    MultiAgentInventory,
    run_a2a_discovery,
    run_inline_a2a_discovery,
    scan_agent_cards_by_ports,
)
from recon.a2a.topology import (
    AgentRole,
    ArchitecturePattern,
    ClassifiedAgent,
    TopologyAnalyzer,
    TopologyGraph,
    analyze_topology,
)
from recon.a2a.topology_mapper import (
    A2ATopologyMapper,
    AgentNode,
    TopologyMapResult,
    map_a2a_topology,
)
from recon.a2a.trust_analyzer import (
    A2ATrustAnalyzer,
    TrustAnalysisResult,
    TrustChainSegment,
    TrustEdge,
    analyze_a2a_trust,
)

__all__ = [
    # agent_card
    "AgentCard",
    "AgentSkill",
    "fetch_agent_card",
    # discoverer
    "A2AEndpoint",
    "AgentTopologyNode",
    "DiscoveryResult",
    "run_a2a_discovery",
    "AgentCardResult",
    "MultiAgentInventory",
    "scan_agent_cards_by_ports",
    "run_inline_a2a_discovery",
    # topology
    "ArchitecturePattern",
    "AgentRole",
    "ClassifiedAgent",
    "TopologyGraph",
    "TopologyAnalyzer",
    "analyze_topology",
    # defense_awareness
    "DefenseProfile",
    "EvasionTactics",
    "detect_defenses",
    "generate_evasion_strategy",
    "check_defense_bypass_feasibility",
    # attack_planner
    "A2AAttackPlan",
    "AttackStep",
    "AttackType",
    "AttackPathPlanner",
    "generate_attack_plan",
    # topology_mapper
    "AgentNode",
    "A2ATopologyMapper",
    "TopologyMapResult",
    "map_a2a_topology",
    # capability_enumerator
    "CapabilityEnumResult",
    "CapabilityInfo",
    "A2ACapabilityEnumerator",
    "enumerate_a2a_capabilities",
    # trust_analyzer
    "A2ATrustAnalyzer",
    "TrustAnalysisResult",
    "TrustChainSegment",
    "TrustEdge",
    "analyze_a2a_trust",
    # defense_mapper
    "A2ADefenseMapper",
    "DefenseIndicator",
    "DefenseMapResult",
    "map_a2a_defenses",
]
