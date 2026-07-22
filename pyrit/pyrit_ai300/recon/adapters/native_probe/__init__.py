# -*- coding: utf-8 -*-
"""
AI-300 Framework - Native Probe Adapter
轻量级探针适配器：从 garak 提取的静态 probe 数据，零外部依赖

组件：
  - NativeProbeAdapter: 主适配器类
  - probe_data/: YAML 格式的 probe 数据（prompt 列表 + 检测规则 + OWASP 映射）
  - detectors/: 轻量级检测器（正则/关键词/LLM-as-Judge）
"""

from .adapter import NativeProbeAdapter

__all__ = ["NativeProbeAdapter"]
