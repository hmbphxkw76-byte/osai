"""RedTeam_AI — AI-300 红队攻击流水线。

基于 OffSec AI-300: Advanced AI Red Teaming 11 章课程体系构建。
完整攻击链对齐 OSAI+ 认证考试要求：

阶段映射：
  Ch2: AI 攻击面侦察 (recon/)
  Ch3: 提示注入、Agent 攻击 (attack/agent/)
  Ch4: 多智能体/A2A 攻击 (attack/agent/multi_agent.py)
  Ch5: RAG 流水线攻击 (attack/rag/)
  Ch6: 嵌入模型攻击 (attack/embeddings_attack.py)
  Ch7: MCP 与工具面攻击 (attack/infra/)
  Ch8: AI 供应链攻击 (attack/supply_chain/)
  Ch9: AI 基础设施攻击 (attack/infra/)
  Ch10: 威胁建模 (pipeline/report_writer.py)
  Ch11: 综合红队报告 (pipeline/report_writer.py)

模块结构：
  - core/: 基础设施模块（数据模型、HTTP 客户端、终端输出）
  - recon/: 侦察阶段（AI 攻击面发现、认证解析）
  - attack/: 攻击模块（core 核心引擎 + agent/rag/supply_chain/infra 子模块）
  - pipeline/: 流水线编排（9 个阶段独立模块 + 主编排器）
  - scenario/: 场景驱动攻击（模板驱动，考试推荐）

纯原生架构（v2.4）：默认纯 httpx 引擎，零框架依赖。
"""
__version__ = "2.4.0"

from .pipeline import AIPipeline
from .scenario import (
    ScenarioLoader,
    ScenarioOrchestrator,
    MultiTurnOrchestrator,
    AttackTargetType,
    AttackStrategy,
    AttackPhaseType,
)

__all__ = [
    "AIPipeline",
    "ScenarioLoader",
    "ScenarioOrchestrator",
    "MultiTurnOrchestrator",
    "AttackTargetType",
    "AttackStrategy",
    "AttackPhaseType",
]
