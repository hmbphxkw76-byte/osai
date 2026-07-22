# -*- coding: utf-8 -*-
"""
AI-300 Framework - Detector Base Class
检测器基类：定义统一接口
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """检测结果"""
    hit: bool                         # 是否命中漏洞
    confidence: float                 # 置信度 (0.0-1.0)
    matched_rules: List[str]          # 匹配的规则描述
    evidence: str                     # 证据片段（匹配到的文本）


class BaseDetector(ABC):
    """检测器抽象基类"""

    def __init__(self, rules: List[Dict[str, Any]]):
        """
        Args:
            rules: 检测规则列表（从 YAML 加载）
        """
        self.rules = rules

    @abstractmethod
    def detect(self, prompt: str, response: str) -> DetectionResult:
        """
        检测单个响应

        Args:
            prompt: 发送给模型的 prompt
            response: 模型的响应

        Returns:
            DetectionResult
        """
        ...

    def detect_batch(
        self, prompt_response_pairs: List[tuple]
    ) -> List[DetectionResult]:
        """批量检测"""
        return [self.detect(p, r) for p, r in prompt_response_pairs]
