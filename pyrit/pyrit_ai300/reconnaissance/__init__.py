# -*- coding: utf-8 -*-
"""
AI-300 Framework - Reconnaissance Engine
侦察引擎：独立模块，通过 TargetProfile JSON 与攻击引擎通信

组件：
- ReconEngine：统一调度入口
- TargetProfile：侦察结果数据模型（接口契约）
- ProfileMerger：多工具结果合并器
- adapters/：薄壳适配器（Garak/DeepTeam）
"""

from .recon_engine import ReconEngine
from .target_profile import TargetProfile, FingerprintData, VulnerabilityFinding
from .owasp_taxonomy import OwaspTaxonomy

__all__ = [
    "ReconEngine",
    "TargetProfile",
    "FingerprintData",
    "VulnerabilityFinding",
    "OwaspTaxonomy",
]
