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
  Ch10: 威胁建模 (pipeline.py: _mitre_atlas_mapping)
  Ch11: 综合红队报告 (pipeline.py: report_phase)
"""
__version__ = "2.1.0"
