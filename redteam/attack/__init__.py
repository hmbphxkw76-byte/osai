"""AI 攻击模块（AI-300 Ch3-Ch9）。

对齐 OffSec AI-300 11 章课程体系——每个攻击模块对应一章课程内容：

  core/           — 攻击核心引擎（执行器抽象、评分器、转换器）
  agent/          — Agent 攻击（Ch3: 提示注入/记忆攻击/工具劫持/目标劫持）
  multi_agent/    — 多智能体攻击（Ch4: 跨智能体注入/A2A协议攻击）
  rag/            — RAG 攻击（Ch5: 知识库投毒/检索泄露/嵌入攻击）
  supply_chain/   — 供应链攻击（Ch8: Pickle RCE/依赖混淆/模型投毒）
  infra/          — 基础设施攻击（Ch7+Ch9: MCP攻击/云配置/K8s利用）

执行器抽象：通过 AttackRunner 接口统一 PyRIT 和 Native 执行
Library-First：载荷库是核心资产，执行引擎可替换
"""

# 核心引擎
from .core import (
    AttackRunner,
    PyRITAttackRunner,
    NativeAttackRunner,
    is_pyrit_available,
    pyrit_version,
    CONVERTER_MAP,
)

# Agent 攻击（Ch3）
from .agent import (
    INDIRECT_INJECTION_PAYLOADS,
    MEMORY_POISON_PAYLOADS,
    TOOL_HIJACK_PAYLOADS,
    GOAL_HIJACK_PAYLOADS,
    test_indirect_injection,
    poison_agent_memory,
    hijack_agent_tools,
    hijack_agent_goal,
    generate_agent_attack_findings,
)

# 多智能体攻击（Ch4）
from .agent.multi_agent import (
    CROSS_AGENT_PAYLOADS,
    cross_agent_attack,
)

# RAG 攻击（Ch5）
from .rag import (
    probe_vector_dbs,
    RAG_POISON_PAYLOADS,
    inject_rag_poison,
    check_retrieval_leakage,
    generate_rag_findings,
)

# 供应链攻击（Ch8）
from .supply_chain import (
    detect_hf_model_source,
    check_pickle_deserialization_risk,
    check_dataset_poisoning_risks,
    check_dependency_risks,
    generate_supply_chain_findings,
)

# 基础设施攻击（Ch9）
from .infra import (
    scan_cloud_misconfigs,
    check_supply_chain_risks,
    generate_infra_findings,
)

__all__ = [
    # 核心引擎
    "AttackRunner",
    "PyRITAttackRunner",
    "NativeAttackRunner",
    "is_pyrit_available",
    "pyrit_version",
    "CONVERTER_MAP",
    # Agent 攻击
    "INDIRECT_INJECTION_PAYLOADS",
    "MEMORY_POISON_PAYLOADS",
    "TOOL_HIJACK_PAYLOADS",
    "GOAL_HIJACK_PAYLOADS",
    "test_indirect_injection",
    "poison_agent_memory",
    "hijack_agent_tools",
    "hijack_agent_goal",
    "generate_agent_attack_findings",
    # 多智能体攻击
    "CROSS_AGENT_PAYLOADS",
    "cross_agent_attack",
    # RAG 攻击
    "probe_vector_dbs",
    "RAG_POISON_PAYLOADS",
    "inject_rag_poison",
    "check_retrieval_leakage",
    "generate_rag_findings",
    # 供应链攻击
    "detect_hf_model_source",
    "check_pickle_deserialization_risk",
    "check_dataset_poisoning_risks",
    "check_dependency_risks",
    "generate_supply_chain_findings",
    # 基础设施攻击
    "scan_cloud_misconfigs",
    "check_supply_chain_risks",
    "generate_infra_findings",
]
