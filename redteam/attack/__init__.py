"""AI 攻击模块（AI-300 Ch3-Ch9）。

对齐 OffSec AI-300 11 章课程体系——每个攻击模块对应一章课程内容：

  core/           — 攻击核心引擎（执行器抽象、评分器、转换器）
  agent/          — Agent 攻击（Ch3: 提示注入/记忆攻击/工具劫持/目标劫持）
  multi_agent/    — 多智能体攻击（Ch4: 跨智能体注入/A2A协议攻击）
  rag/            — RAG 攻击（Ch5: 知识库投毒/检索泄露/嵌入攻击）
  supply_chain/   — 供应链攻击（Ch8: Pickle RCE/依赖混淆/模型投毒）
  infra/          — 基础设施攻击（Ch7+Ch9: MCP攻击/云配置/K8s利用）

v2.3 Native-First 架构：
  - NativeAttackRunner: 纯 httpx 执行器，永远原生引擎
  - PyRIT 仅作为可选增强，用于多轮编排器（scenario/multi_turn_orchestrator.py）

原生增强模块：
  - 灰度评分系统（FastGrayscaleScorer、KeywordDensityScorer、RefusalPatternScorer）
  - 越狱转换器（PAIR、DAN6、AIM、Academic、ManyShot、FlipAttack）
  - 转换器注册表（分类体系、动态注册）
  - 扩展载荷库（YAML 按 OWASP 分类）
"""

# 核心引擎
from .core import (
    AttackRunner,
    NativeAttackRunner,
    is_pyrit_available,
    pyrit_version,
    # Scorer
    AttackScorer,
    RuleBasedScorer,
    HybridScorer,
    FastGrayscaleScorer,
    KeywordDensityScorer,
    RefusalPatternScorer,
    GrayscaleLevel,
    is_likely_refusal,
    build_scorer,
    build_scorers,
    # Converter
    PromptConverter,
    PAIRJailbreakConverter,
    DAN6Converter,
    AIMConverter,
    AcademicJailbreakConverter,
    ManyShotJailbreakConverter,
    FlipAttackConverter,
    RoleplayJailbreakConverter,
    ConverterCategory,
    ConverterRegistry,
    build_converter,
    build_converters,
    apply_converters,
    get_converter_registry,
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
    # MCP 工具描述投毒（Ch7）
    MCP_TOOL_POISON_PAYLOADS,
    probe_mcp_tool_descriptions,
    inject_mcp_tool_poison,
    # 上下文溢出攻击（Ch3）
    PADDING_PAYLOADS,
    OverflowConfig,
    run_context_overflow_attack,
    run_context_overflow_probe,
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
    RAG_INDIRECT_INJECTION_PAYLOADS,
    inject_rag_poison,
    inject_rag_indirect,
    check_retrieval_leakage,
    check_cross_tenant_leakage,
    generate_rag_findings,
)

# 供应链攻击（Ch8）
from .supply_chain import (
    detect_hf_model_source,
    check_pickle_deserialization_risk,
    check_dataset_poisoning_risks,
    check_dependency_risks,
    DOCKER_LABEL_PAYLOADS,
    probe_docker_api,
    inject_docker_label_payload,
    generate_docker_supply_chain_findings,
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
    "NativeAttackRunner",
    "is_pyrit_available",
    "pyrit_version",
    # 评分器
    "AttackScorer",
    "RuleBasedScorer",
    "HybridScorer",
    "FastGrayscaleScorer",
    "KeywordDensityScorer",
    "RefusalPatternScorer",
    "GrayscaleLevel",
    "is_likely_refusal",
    "build_scorer",
    "build_scorers",
    # 转换器
    "PromptConverter",
    "PAIRJailbreakConverter",
    "DAN6Converter",
    "AIMConverter",
    "AcademicJailbreakConverter",
    "ManyShotJailbreakConverter",
    "FlipAttackConverter",
    "RoleplayJailbreakConverter",
    "ConverterCategory",
    "ConverterRegistry",
    "build_converter",
    "build_converters",
    "apply_converters",
    "get_converter_registry",
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
    # Agent 攻击 - MCP 工具描述投毒 + 上下文溢出
    "MCP_TOOL_POISON_PAYLOADS",
    "probe_mcp_tool_descriptions",
    "inject_mcp_tool_poison",
    "PADDING_PAYLOADS",
    "OverflowConfig",
    "run_context_overflow_attack",
    "run_context_overflow_probe",
    # 多智能体攻击
    "CROSS_AGENT_PAYLOADS",
    "cross_agent_attack",
    # RAG 攻击
    "probe_vector_dbs",
    "RAG_POISON_PAYLOADS",
    "RAG_INDIRECT_INJECTION_PAYLOADS",
    "inject_rag_poison",
    "inject_rag_indirect",
    "check_retrieval_leakage",
    "check_cross_tenant_leakage",
    "generate_rag_findings",
    # 供应链攻击
    "detect_hf_model_source",
    "check_pickle_deserialization_risk",
    "check_dataset_poisoning_risks",
    "check_dependency_risks",
    "DOCKER_LABEL_PAYLOADS",
    "probe_docker_api",
    "inject_docker_label_payload",
    "generate_docker_supply_chain_findings",
    "generate_supply_chain_findings",
    # 基础设施攻击
    "scan_cloud_misconfigs",
    "check_supply_chain_risks",
    "generate_infra_findings",
]
