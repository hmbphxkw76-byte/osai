# -*- coding: utf-8 -*-
"""
DeepTeam Adapter 包

DeepTeam OWASP 红队扫描适配器（Confident AI deepteam v1.0.7）

模块结构（后续扩展）：
    adapter.py   - DeepTeamAdapter 主类（当前完整实现）
    attacks.py   - 攻击类型选择策略（OPT-D1/D2/D5，预留）
    callback.py  - model_callback 增强（OPT-D3，预留）
    findings.py  - 发现提取与 OWASP 映射（预留）
"""

from .adapter import DeepTeamAdapter

__all__ = ["DeepTeamAdapter"]
