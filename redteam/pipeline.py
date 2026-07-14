"""AI-300 红队攻击流水线 (Pipeline) — 向后兼容垫片。

注意：此文件已被拆分到 pipeline/ 目录下的多个独立模块中。
为保持向后兼容性，此文件重新导出新模块的内容。

新的文件结构：
  - pipeline/__init__.py: 统一导出入口
  - pipeline/runner.py: 主编排器 AIPipeline
  - pipeline/recon_phase.py: AI 攻击面侦察 (Ch2)
  - pipeline/injection_phase.py: 提示注入攻击 (Ch3)
  - pipeline/agent_phase.py: Agent 深度攻击 (Ch3+Ch4)
  - pipeline/rag_phase.py: RAG 流水线攻击 (Ch5)
  - pipeline/embeddings_phase.py: 嵌入模型攻击 (Ch6)
  - pipeline/supply_chain_phase.py: AI 供应链攻击 (Ch8)
  - pipeline/infra_phase.py: MCP+基础设施攻击 (Ch7+Ch9)
  - pipeline/report_writer.py: 增量报告写入器 (Ch11)

推荐使用新的导入方式：
  from redteam.pipeline import AIPipeline
  from redteam.pipeline.recon_phase import recon_phase
"""
from __future__ import annotations

from .pipeline.runner import AIPipeline
from .pipeline.recon_phase import recon_phase
from .pipeline.injection_phase import injection_phase
from .pipeline.agent_phase import agent_attack_phase
from .pipeline.rag_phase import rag_attack_phase
from .pipeline.embeddings_phase import embeddings_attack_phase
from .pipeline.supply_chain_phase import supply_chain_phase
from .pipeline.infra_phase import infra_attack_phase

__all__ = [
    "AIPipeline",
    "recon_phase",
    "injection_phase",
    "agent_attack_phase",
    "rag_attack_phase",
    "embeddings_attack_phase",
    "supply_chain_phase",
    "infra_attack_phase",
]