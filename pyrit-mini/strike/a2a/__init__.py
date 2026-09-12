# -*- coding: utf-8 -*-
"""strike/a2a - A2A Multi-Agent Attack Framework

对 A2A (Agent-to-Agent) 多代理系统执行安全测试:
- 工作流攻击 (Workflow Integrity)
- 代理身份欺骗 (Agent Card Spoofing)
- 恶意代理注册 (Rogue Agent Registration)
- 信任链利用 (Trust Chain Exploitation)
- 渐进式信任建立 (Incremental Trust Building)
- 跨代理注入 (Cross-Agent Injection)

模块清单:
    - workflow_attacker       : A2A 工作流端点攻击器
    - card_spoofer            : Agent Card 欺骗器
    - rogue_registrar         : 恶意代理注册器
    - trust_builder           : 渐进式信任建立器
    - cross_agent_injector    : 跨代理注入器

Academic basis:
    - Eidam et al. (arXiv:2407.16924) — A2A trust chain exploitation
    - Zhan et al. (arXiv:2307.00929) — Schema-guided injection
    - Greshake et al. (arXiv:2302.12173) — Indirect prompt injection
    - OWASP ASI01 — Agent Identity Spoofing
    - OWASP ASI07 — Cross-Agent Injection
    - OWASP ASI10 — Rogue Agent

Constitution compliance:
    - R-SIZE: 每模块 < 800 行
    - R-H3: 单一职责, 无双重实现
    - R-S1: 不硬编码目标标识符
    - R-S4: 测试全部 mock
"""

from strike.a2a.card_spoofer import (
    AgentCardSpoofer,
    SpoofResult,
    create_agent_card_spoofer,
)
from strike.a2a.cross_agent_injector import (
    CrossAgentInjectionResult,
    CrossAgentInjector,
    cross_agent_injection_attack,
)
from strike.a2a.rogue_registrar import (
    RegistrationResult,
    RogueAgentConfig,
    RogueAgentRegistrar,
    create_rogue_agent_registrar,
)
from strike.a2a.trust_builder import (
    TrustSession,
    build_authority_session,
    build_combined_session,
    build_scope_session,
    build_workflow_session,
    create_incremental_trust_builder,
    generate_final_prompt,
)
from strike.a2a.workflow_attacker import (
    A2AWorkflowAttacker,
    PipelineAnalysis,
    WorkflowAttackResult,
    create_a2a_workflow_attacker,
)

__all__ = [
    # Workflow Attacker
    "A2AWorkflowAttacker",
    "WorkflowAttackResult",
    "PipelineAnalysis",
    "create_a2a_workflow_attacker",
    # Card Spoofer
    "AgentCardSpoofer",
    "SpoofResult",
    "create_agent_card_spoofer",
    # Rogue Registrar
    "RogueAgentRegistrar",
    "RogueAgentConfig",
    "RegistrationResult",
    "create_rogue_agent_registrar",
    # Trust Builder
    "TrustSession",
    "build_authority_session",
    "build_workflow_session",
    "build_scope_session",
    "build_combined_session",
    "generate_final_prompt",
    "create_incremental_trust_builder",
    # Cross-Agent Injector
    "CrossAgentInjector",
    "CrossAgentInjectionResult",
    "cross_agent_injection_attack",
]
