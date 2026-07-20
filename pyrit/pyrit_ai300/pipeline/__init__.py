# -*- coding: utf-8 -*-
"""
AI-300 Framework - Attack Pipeline Module
攻击流水线模块：payload 加载 -> 分类器判断 -> 策略选择器指派

核心职责：
1. 记录每个 payload 的完整处理链路
2. 提供决策审计追踪（为什么选择该策略）
3. 输出结构化的流水线日志
4. 攻击结果反馈分析（v3.1 新增）
5. 统一凭据管理（v3.6 新增：跨阶段凭据发现/验证/注入）
6. 全链路编排（v3.7 新增：认证→侦察→攻击→报告一键执行）

PyRIT 0.14.0 兼容
"""

from .tracker import PipelineTracker, PipelineStep, PipelineLog
from .feedback_analyzer import FeedbackAnalyzer, FeedbackReport
from .credential_manager import CredentialManager, CredentialResolution
from .orchestrator import (
    PipelineOrchestrator,
    PipelineResult,
    PhaseResult,
)

__all__ = [
    "PipelineTracker",
    "PipelineStep",
    "PipelineLog",
    "FeedbackAnalyzer",
    "FeedbackReport",
    "CredentialManager",
    "CredentialResolution",
    "PipelineOrchestrator",
    "PipelineResult",
    "PhaseResult",
]
