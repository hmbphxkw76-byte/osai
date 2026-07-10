"""
===============================================================================
L2: 攻击指挥中枢 — PyRIT 原生编排 + 动态反馈闭环
===============================================================================
核心职责:
  1. 基于安全画像路由攻击策略 — AttackRouter 根据目标架构选择最佳攻击路径
  2. PyRIT Orchestrator 攻击编排 — PyRITNativeOrchestrator 统一调度 9 种攻击策略
  3. 实时成功率动态调优 — DynamicFeedbackLoop 监控 ASR 并自动调整策略
  4. 速率与 Token 预算管控 — BudgetController 管理 API 调用资源

数据流向:
  L1 Recon → TargetProfile → AttackRouter → AttackProfile
  AttackProfile → PyRITNativeOrchestrator → AttackResult[]
  AttackResult[] → DynamicFeedbackLoop → 策略调整 → PyRITNativeOrchestrator

PyRIT 最佳实践:
  - SQLiteMemory + CentralMemory 全局单例模式
  - PromptSendingAttack / CrescendoAttack / PAIRAttack 等 9 种原生策略
  - AttackConfig 支持 5 套预置渗透场景 (probe/standard/deep/large_context/limited_context)
===============================================================================
"""
from orchestration.attack_router import AttackRouter
from orchestration.pyrit_orchestrator import PyRITNativeOrchestrator, AttackConfig
from orchestration.feedback_loop import DynamicFeedbackLoop
from orchestration.budget_controller import BudgetController, TokenBudget, RateLimiter

__all__ = [
    "AttackRouter",
    "PyRITNativeOrchestrator", "AttackConfig",
    "DynamicFeedbackLoop",
    "BudgetController", "TokenBudget", "RateLimiter",
]
