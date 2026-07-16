# -*- coding: utf-8 -*-
"""
AI-300 Framework - Payloads Module
载荷模块：管理攻击载荷、多维分析

子模块：
- models: 数据模型（ThreatModel, PayloadProfile）
- patterns: 检测模式定义 + YAML 加载
- normalizer: 归一化预处理
- payload_classifier: 核心分析函数
- payload_manager: 载荷管理器
"""

from .payload_manager import PayloadManager
from .models import (
    ThreatModel,
    PayloadProfile,
)
from .payload_classifier import (
    classify_payload,
    classify_payloads,
    get_category_description,
    analyze_payload,
    analyze_payloads,
    MODEL_CONTEXT_WINDOWS,
)
from .patterns import get_loaded_pattern_info
from .normalizer import normalize_payload

__all__ = [
    # PayloadManager
    "PayloadManager",
    # Models
    "ThreatModel",
    "PayloadProfile",
    "MODEL_CONTEXT_WINDOWS",
    # Classifier functions
    "classify_payload",
    "classify_payloads",
    "get_category_description",
    "analyze_payload",
    "analyze_payloads",
    "normalize_payload",
    "get_loaded_pattern_info",
]
