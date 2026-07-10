"""
===============================================================================
L3: 攻击执行矩阵 — 全场景工具化落地 + 专项能力补强
===============================================================================
五个攻击子模块:
  3a: 直接提示注入 + 越狱 (PyRIT 核心)
  3b: 间接提示注入 XPIA (PyRIT 多模态)
  3c: RAG 专项攻击 (Promptfoo 核心)
  3d: Agent 工具滥用攻击 (PyRIT+Promptfoo 双引擎)
  3e: 模型提取/反演攻击 (PyRIT+Garak)

统一对外接口:
  from attack_execution import (
      DirectInjectionAttack, JailbreakAttack,
      XPIAInjectionAttack,
      RAGAttackExecutor,
      AgentAbuseAttack,
      ModelExtractionAttack,
  )
===============================================================================
"""
from attack_execution._3a_direct_injection import DirectInjectionAttack, JailbreakAttack
from attack_execution._3b_xpia import XPIAInjectionAttack
from attack_execution._3c_rag import RAGAttackExecutor
from attack_execution._3d_agent_abuse import AgentAbuseAttack
from attack_execution._3e_model_extraction import ModelExtractionAttack

__all__ = [
    "DirectInjectionAttack", "JailbreakAttack",
    "XPIAInjectionAttack",
    "RAGAttackExecutor",
    "AgentAbuseAttack",
    "ModelExtractionAttack",
]
