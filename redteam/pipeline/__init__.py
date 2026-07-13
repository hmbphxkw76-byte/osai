"""AI-300 红队攻击流水线模块（Pipeline）。

基于 OffSec AI-300 课程 11 章的完整攻击链编排，对齐 OSAI+ 认证考试要求。

目录结构：
  - __init__.py: 统一导出入口
  - recon_phase.py: AI 攻击面侦察 (Ch2)
  - injection_phase.py: 提示注入攻击 (Ch3)
  - agent_phase.py: Agent 深度攻击 (Ch3+Ch4)
  - multi_agent_phase.py: 多 Agent/A2A 协议攻击 (Ch4)
  - rag_phase.py: RAG 流水线攻击 (Ch5)
  - embeddings_phase.py: 嵌入模型攻击 (Ch6)
  - supply_chain_phase.py: AI 供应链攻击 (Ch8)
  - infra_phase.py: MCP+基础设施攻击 (Ch7+Ch9)
  - report_phase.py: 威胁建模与报告 (Ch10+Ch11)
  - runner.py: 主流水线编排器（含 YAML 配置驱动模式）

设计原则：
  - Library-First：所有 HTTP/探测能力委托 httpx + 成熟工具
  - 渐进式：每一步基于上一步的发现推进
  - 失败隔离：单阶段失败不阻断后续阶段
  - 结果持久化：每个阶段产出 JSON checkpoint
  - YAML 驱动：支持 config/pipeline.yaml 配置驱动模式（考试推荐）
"""

from .runner import AIPipeline

__all__ = [
    "AIPipeline",
]
