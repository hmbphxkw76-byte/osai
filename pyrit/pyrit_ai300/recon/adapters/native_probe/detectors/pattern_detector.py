# -*- coding: utf-8 -*-
"""
AI-300 Framework - Pattern Detector
正则/关键词检测器：替代 garak 的 ML-based detector

检测策略：
  1. regex: 正则表达式匹配
  2. keyword: 关键词匹配（响应中包含指定关键词）
  3. regex+filter: 正则匹配 + 关键词过滤（减少误报）
  4. regex+exclude: 正则匹配 + 排除关键词（减少误报）
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List

from .base import BaseDetector, DetectionResult

logger = logging.getLogger(__name__)


class PatternDetector(BaseDetector):
    """正则/关键词模式检测器"""

    def detect(self, prompt: str, response: str) -> DetectionResult:
        """
        使用正则和关键词规则检测响应

        Args:
            prompt: 发送给模型的 prompt
            response: 模型的响应

        Returns:
            DetectionResult
        """
        if not response or not response.strip():
            return DetectionResult(
                hit=False, confidence=0.0, matched_rules=[], evidence=""
            )

        matched_rules: List[str] = []
        max_confidence = 0.0
        evidence = ""

        for rule in self.rules:
            rule_type = rule.get("type", "")

            if rule_type == "regex":
                hit, match_text = self._check_regex(response, rule)
                if hit:
                    desc = rule.get("description", "regex match")
                    matched_rules.append(desc)
                    conf = rule.get("confidence", 0.7)
                    if conf > max_confidence:
                        max_confidence = conf
                        evidence = match_text

            elif rule_type == "keyword":
                hit, match_text = self._check_keyword(response, rule)
                if hit:
                    desc = rule.get("description", "keyword match")
                    matched_rules.append(desc)
                    conf = rule.get("confidence", 0.7)
                    if conf > max_confidence:
                        max_confidence = conf
                        evidence = match_text

        return DetectionResult(
            hit=len(matched_rules) > 0,
            confidence=max_confidence,
            matched_rules=matched_rules,
            evidence=evidence[:500],  # 限制证据长度
        )

    @staticmethod
    def _check_regex(response: str, rule: Dict[str, Any]) -> tuple:
        """检查正则规则"""
        pattern = rule.get("pattern", "")
        if not pattern:
            return False, ""

        try:
            flags = re.IGNORECASE | re.MULTILINE
            match = re.search(pattern, response, flags)
            if match:
                # 检查过滤关键词（仅当匹配文本附近包含过滤词时才算命中）
                filter_keywords = rule.get("filter_keywords", [])
                if filter_keywords:
                    # 在匹配位置前后 200 字符范围内检查过滤词
                    start = max(0, match.start() - 200)
                    end = min(len(response), match.end() + 200)
                    context = response[start:end]
                    if not any(kw.lower() in context.lower() for kw in filter_keywords):
                        return False, ""

                # 检查排除关键词
                exclude_keywords = rule.get("exclude_if_contains", [])
                if exclude_keywords:
                    if any(kw.lower() in response.lower() for kw in exclude_keywords):
                        return False, ""

                return True, match.group(0)
        except re.error as e:
            logger.warning("Invalid regex pattern '%s': %s", pattern, e)

        return False, ""

    @staticmethod
    def _check_keyword(response: str, rule: Dict[str, Any]) -> tuple:
        """检查关键词规则"""
        keywords = rule.get("keywords", [])
        if not keywords:
            return False, ""

        response_lower = response.lower()
        for kw in keywords:
            if kw.lower() in response_lower:
                # 找到关键词位置，提取上下文作为证据
                idx = response_lower.index(kw.lower())
                start = max(0, idx - 50)
                end = min(len(response), idx + len(kw) + 50)
                evidence = response[start:end]
                return True, evidence

        return False, ""
