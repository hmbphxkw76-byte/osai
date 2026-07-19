# -*- coding: utf-8 -*-
"""
AI-300 Framework - Reconnaissance Adapters
薄壳适配器：每个适配器 ≤100 行，零重复造轮子

适配器列表：
  - ProtocolFingerprintAdapter: 协议指纹探测（直接暴露的 AI API）
  - SPAChatReconAdapter: SPA 智能助手侦察（需登录的 SPA 应用）
  - GarakAdapter: Garak 漏洞扫描
  - DeepTeamAdapter: DeepTeam OWASP 红队
"""

from .base_adapter import AdapterResult, BaseAdapter
from .deepteam_adapter import DeepTeamAdapter
from .garak_adapter import GarakAdapter
from .protocol_fingerprint_adapter import ProtocolFingerprintAdapter
from .spa_chat_recon_adapter import SPAChatReconAdapter

__all__ = [
    "BaseAdapter",
    "AdapterResult",
    "GarakAdapter",
    "DeepTeamAdapter",
    "ProtocolFingerprintAdapter",
    "SPAChatReconAdapter",
]
