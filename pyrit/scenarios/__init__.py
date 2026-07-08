"""
===============================================================================
PyRIT Red Team — Scenarios 场景模块 (PyRIT 对齐)
===============================================================================
PyRIT 框架定义 Scenarios 为标准化的大规模评估组件，集成：
  - Prompt 数据集与变体生成
  - Converter 组合与攻击策略编排
  - 自动化评分与结果收集
  - 综合安全评估报告

目录结构:
  scenarios/
  ├── __init__.py          # 包入口，统一导出
  ├── schema.py            # YAML 模板 Pydantic Schema
  ├── orchestrator.py      # 场景编排执行引擎 (PenetratingOrchestrator)
  ├── payloads.py          # 🆕 统一 Payload 提供层 (PyRIT-aligned, 纯 YAML)
  ├── variant_generator.py # 提示词变体生成器
  ├── rag_attacks.py       # RAG 管道攻击 Payload (纯 YAML)
  ├── agent_attacks.py     # 多智能体攻击 Payload (纯 YAML)
  ├── infra_attacks.py     # 基础设施攻击 Payload (纯 YAML)
  ├── reporter.py          # 综合安全评估报告
  ├── target_presets.py    # HTTP 连接场景预设
  ├── templates/           # YAML 场景模板定义
  └── frontier/            # 🆕 前沿 AI 漏洞追踪（热插拔）
      ├── comprehensive.yaml
      ├── prompt_injection.yaml
      ├── encoding_bypass.yaml
      ├── jailbreak_arsenal.yaml
      └── ...

渗透期间使用（零代码改动）:
  仅需编辑 scenarios/templates/*.yaml 中的 prompts 内容：
    python run_redteam.py --penetrating-mode --penetrating-template scenarios/templates/comprehensive.yaml

导入方式:
  from scenarios import PenetratingOrchestrator, PenetratingPromptSet, RAGPayloadGenerator, ...
===============================================================================
"""

# ── Schema 模块零依赖立即加载（供模板验证使用）──
from scenarios.schema import (
    PenetratingPromptSet, PenetratingPrompt, PenetratingModeConfig,
    PromptCategory, DifficultyLevel, OWASPCategory, TemplateMode,
    AttackStrategy, STRATEGY_CONVERTER_MAP, STRATEGY_CATEGORIES,
    PromptVariant, VariantType,
)
from scenarios.variant_generator import PromptVariantGenerator
from scenarios.rag_attacks import RAGPayloadGenerator, RAGPayload
from scenarios.agent_attacks import AgentPayloadGenerator, AgentPayload
from scenarios.infra_attacks import InfraPayloadGenerator, InfraPayload

# ── 🆕 统一 Payload 提供层（PyRIT-aligned, 全 12 模块覆盖）──
from scenarios.payloads import (
    ModulePayloadProvider,
    get_payloads,
    get_provider,
    create_generator,
    GENERATOR_MAP,
    GenericPayload,
    # 🆕 孤立模块 Generator
    PromptInjectionPayloadGenerator,
    JailbreakPayloadGenerator,
    ExfiltrationPayloadGenerator,
    OutputHandlingPayloadGenerator,
    # 🆕 前沿漏洞 Generator
    FrontierPayloadGenerator,
)

# ── Target 场景预设（延迟导入，避免触发 PyRIT 链）──
# SCENARIO_PRESETS, build_custom_target, register_scenario
# 通过 get_target_presets() 延迟导入

# ── 重型模块延迟加载（避免触发 PyRIT 导入链）──
# PenetratingOrchestrator 和 PenetratingSecurityReporter 在需要时延迟导入

__all__ = [
    # Schema
    "PenetratingPromptSet", "PenetratingPrompt", "PenetratingModeConfig",
    "PromptCategory", "DifficultyLevel", "OWASPCategory", "TemplateMode",
    "AttackStrategy", "STRATEGY_CONVERTER_MAP", "STRATEGY_CATEGORIES",
    "PromptVariant", "VariantType",
    # Generators
    "PromptVariantGenerator",
    "RAGPayloadGenerator", "RAGPayload",
    "AgentPayloadGenerator", "AgentPayload",
    "InfraPayloadGenerator", "InfraPayload",
    # 🆕 统一 Payload 层 + 孤立模块 Generator
    "ModulePayloadProvider", "get_payloads", "get_provider", "create_generator",
    "GENERATOR_MAP", "GenericPayload",
    "PromptInjectionPayloadGenerator",
    "JailbreakPayloadGenerator",
    "ExfiltrationPayloadGenerator",
    "OutputHandlingPayloadGenerator",
    "FrontierPayloadGenerator",
    # Frontier 前沿漏洞追踪
    "get_frontier_registry", "get_frontier_vulns", "get_frontier_strategies",
    "FrontierVuln", "FrontierPayload", "FrontierStatus",
    # Target Presets
    "SCENARIO_PRESETS", "build_custom_target", "register_scenario",
    # Orchestrator & Reporter (lazy)
    "PenetratingOrchestrator",
    "PenetratingSecurityReporter",
    # Templates
    "DEFAULT_TEMPLATES",
]


def get_orchestrator():
    """延迟导入 PenetratingOrchestrator（避免 PyRIT 循环导入）"""
    from scenarios.orchestrator import PenetratingOrchestrator
    return PenetratingOrchestrator


def get_reporter():
    """延迟导入 PenetratingSecurityReporter"""
    from scenarios.reporter import PenetratingSecurityReporter
    return PenetratingSecurityReporter


def get_target_presets():
    """延迟导入连接场景预设（依赖 targets.http_target → PyRIT）"""
    from scenarios.target_presets import (
        SCENARIO_PRESETS,
        build_custom_target,
        register_scenario,
    )
    return SCENARIO_PRESETS, build_custom_target, register_scenario


# ═══════════════════════════════════════════════════════════════════
# 🆕 前沿漏洞追踪 — 懒加载
# ═══════════════════════════════════════════════════════════════════

def get_frontier_registry(auto_discover: bool = True):
    """延迟获取 FrontierRegistry 单例"""
    from scenarios.frontier.registry import get_registry as _get
    return _get(auto_discover=auto_discover)


def get_frontier_vulns():
    """懒加载：获取所有活跃的前沿漏洞"""
    from scenarios.frontier.registry import get_frontier_vulns as _get
    return _get()


def get_frontier_strategies():
    """懒加载：获取所有活跃的前沿策略名称"""
    from scenarios.frontier.registry import get_frontier_strategies as _get
    return _get()

TEMPLATE_SEARCH_DIRS = {
    "exploring": ["scenarios/templates"],
    "penetrating": ["scenarios/templates"],
}

DEFAULT_TEMPLATES = {
    "exploring": {
        "prompt_injection": "scenarios/templates/prompt_injection.yaml",
        "encoding_bypass": "scenarios/templates/encoding_bypass.yaml",
        "jailbreak_arsenal": "scenarios/templates/jailbreak_arsenal.yaml",
    },
    "penetrating": {
        "scenarios": "scenarios/templates/comprehensive.yaml",
        "rag_pipeline": "scenarios/templates/rag_pipeline.yaml",
        "agent_multi_agent": "scenarios/templates/agent_multi_agent.yaml",
        "mcp_protocol": "scenarios/templates/mcp_protocol.yaml",
        "supply_chain": "scenarios/templates/supply_chain.yaml",
        "data_exfiltration": "scenarios/templates/data_exfiltration.yaml",
        "output_handling": "scenarios/templates/output_handling.yaml",
        "red_team_scenarios": "scenarios/templates/red_team_scenarios.yaml",
    },
}
