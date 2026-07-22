# -*- coding: utf-8 -*-
"""
AI-300 Framework - Lightweight Detectors
轻量级检测器：替代 garak ML-based detector，使用正则/关键词/拒绝检测

检测器类型：
  - PatternDetector: 正则表达式 + 关键词匹配
  - RefusalDetector: 拒绝检测（判断模型是否拒绝有害请求）
"""

from .base import BaseDetector, DetectionResult
from .pattern_detector import PatternDetector
from .refusal_detector import RefusalDetector

__all__ = [
    "BaseDetector",
    "DetectionResult",
    "PatternDetector",
    "RefusalDetector",
]
