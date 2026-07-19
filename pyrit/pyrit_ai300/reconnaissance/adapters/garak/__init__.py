# -*- coding: utf-8 -*-
"""
Garak Adapter 包

Garak LLM 漏洞扫描适配器（NVIDIA garak v0.15.1）

模块结构（后续扩展）：
    adapter.py        - GarakAdapter 主类（当前完整实现）
    probes.py         - Probe 动态选择策略（OPT-G1/G2，预留）
    detectors.py      - Detector 精确配置（OPT-G4，预留）
    output_parser.py  - 结果解析增强（OPT-G3，预留）
    cache.py          - 增量执行缓存（OPT-G5，预留）
    warmup.py         - 通用预热逻辑（OPT-G6，预留）
"""

from .adapter import GarakAdapter

__all__ = ["GarakAdapter"]
