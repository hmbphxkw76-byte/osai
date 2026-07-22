# -*- coding: utf-8 -*-
"""
AI-300 Framework - Giskard RAGET Adapter
RAG 应用评估适配器：集成 Giskard RAGET 进行组件级 RAG 评估

组件：
  - GiskardRagAdapter: 主适配器类
  - 检测维度：正确性、忠实度、相关性、上下文精度
  - 攻击面：RAG 检索注入、知识泄露、幻觉
"""
from .adapter import GiskardRagAdapter

__all__ = ["GiskardRagAdapter"]
