# -*- coding: utf-8 -*-
"""
AI-300 Framework - Reconnaissance Adapters

适配器列表（均已模块化为包目录）：
  - ProtocolFingerprintAdapter: 协议指纹探测（aimap/ 包，AIMAP 逻辑）
  - SPAChatReconAdapter: SPA 智能助手侦察（spa_chat/ 包，8 模块）
  - DeepTeamAdapter: DeepTeam OWASP 红队（deepteam/ 包）
  - NativeProbeAdapter: 轻量级探针（native_probe/ 包，零外部依赖）
  - ObservabilityAdapter: 可观测性检测（observability/ 包）
  - GiskardRagAdapter: RAG 应用评估（giskard_rag/ 包，Giskard RAGET 集成）
  - InfraScanAdapter: AI 基础设施漏洞扫描（infra_scan/ 包，Nuclei 集成）
"""

from .base import AdapterResult, BaseAdapter
from .deepteam import DeepTeamAdapter
from .native_probe import NativeProbeAdapter
from .aimap import ProtocolFingerprintAdapter
from .spa_chat import SPAChatReconAdapter
from .giskard_rag import GiskardRagAdapter
from .infra_scan import InfraScanAdapter

__all__ = [
    "BaseAdapter",
    "AdapterResult",
    "DeepTeamAdapter",
    "ProtocolFingerprintAdapter",
    "SPAChatReconAdapter",
    "NativeProbeAdapter",
    "GiskardRagAdapter",
    "InfraScanAdapter",
]
