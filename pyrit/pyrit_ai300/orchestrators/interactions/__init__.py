# -*- coding: utf-8 -*-
"""
AI-300 Framework - Interactions Module
站点交互适配器：定义如何与不同类型的 Web UI 交互

每个交互函数接收 (page, message) 参数，返回响应文本。
交互函数是站点相关的，但按交互模式分类（而非按站点命名）。

子模块：
- web_chat: Web 聊天界面交互（输入框 + 发送按钮 + 响应区）
- copilot: Copilot 界面交互（预留）
"""

from .web_chat import create_web_chat_interaction

__all__ = [
    "create_web_chat_interaction",
]
