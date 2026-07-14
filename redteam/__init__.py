"""RedTeam_AI — AI-300 红队攻击流水线。

基于 OffSec AI-300: Advanced AI Red Teaming 11 章课程体系构建。
完整攻击链对齐 OSAI+ 认证考试要求：

阶段映射：
  Ch2: AI 攻击面侦察 (recon/)
  Ch3: 提示注入与越狱 (attack/prompt_inject.py)
  Ch4: Agent 与多智能体攻击 (attack/agent_attack.py)
  Ch5: RAG 流水线攻击 (attack/rag_attack.py)
  Ch6: 嵌入模型攻击 (attack/embeddings_attack.py)
  Ch7: MCP 与工具面攻击 (attack/infra_attack.py)
  Ch8: AI 供应链攻击 (attack/supply_chain.py)
  Ch9: AI 基础设施攻击 (attack/infra_attack.py)
  Ch10: 威胁建模 (pipeline/report_phase.py)
  Ch11: 综合红队报告 (pipeline/report_phase.py)

模块结构：
  - core/: 基础设施模块（数据模型、HTTP客户端、终端输出）
  - recon/: 侦察阶段（AI攻击面发现、认证解析）
  - attack/: 攻击模块（提示注入、Agent攻击、RAG攻击等）
  - pipeline/: 流水线编排（8个阶段的独立模块 + 主编排器）
  - scenario/: 场景驱动攻击（模板驱动，考试推荐）

场景驱动模式（考试推荐）：
  1. 修改 config/scenarios/agent.yaml 中的载荷内容
  2. 运行: redteam scenario run --scenario agent --target https://xxx
  3. 自动执行所有策略 + 生成报告
"""
__version__ = "2.2.0"

from .pipeline import AIPipeline
from .scenario import (
    ScenarioLoader,
    ScenarioOrchestrator,
    MultiTurnOrchestrator,
    PyRITMultiTurnOrchestrator,
    AttackTargetType,
    AttackStrategy,
    AttackPhaseType,
)

__all__ = [
    "AIPipeline",
    "ScenarioLoader",
    "ScenarioOrchestrator",
    "MultiTurnOrchestrator",
    "PyRITMultiTurnOrchestrator",
    "AttackTargetType",
    "AttackStrategy",
    "AttackPhaseType",
]
