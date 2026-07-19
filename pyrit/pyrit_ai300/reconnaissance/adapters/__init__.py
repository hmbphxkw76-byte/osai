# -*- coding: utf-8 -*-
"""
AI-300 Framework - Reconnaissance Adapters

适配器列表（均已模块化为包目录）：
  - ProtocolFingerprintAdapter: 协议指纹探测（直接暴露的 AI API）
  - SPAChatReconAdapter: SPA 智能助手侦察（spa_chat/ 包，8 模块）
  - GarakAdapter: Garak 漏洞扫描（garak/ 包，预留模块化扩展）
  - DeepTeamAdapter: DeepTeam OWASP 红队（deepteam/ 包，预留模块化扩展）
"""

from .base_adapter import AdapterResult, BaseAdapter
from .deepteam import DeepTeamAdapter
from .garak import GarakAdapter
from .protocol_fingerprint_adapter import ProtocolFingerprintAdapter
from .spa_chat import SPAChatReconAdapter

__all__ = [
    "BaseAdapter",
    "AdapterResult",
    "GarakAdapter",
    "DeepTeamAdapter",
    "ProtocolFingerprintAdapter",
    "SPAChatReconAdapter",
]
