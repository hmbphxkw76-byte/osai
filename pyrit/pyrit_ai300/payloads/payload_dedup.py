# -*- coding: utf-8 -*-
"""
AI-300 Framework - Payload Deduplicator v1.0
载荷去重器：基于语义相似度的载荷去重

职责：
- 检测语义相同/相似的载荷
- 保留每个聚类中最有代表性的载荷
- 支持精确去重（归一化后完全匹配）和模糊去重（Jaccard 相似度）

使用方式：
    from .payload_dedup import deduplicate_payloads
    unique = deduplicate_payloads(payloads, threshold=0.85)

PyRIT 0.14.0 兼容
"""
from __future__ import annotations

import logging
from typing import List, Set, Tuple, Any

logger = logging.getLogger(__name__)


def _normalize(text: str) -> str:
    """简单归一化：转小写、去多余空白"""
    return " ".join(text.lower().split())


def _jaccard_similarity(s1: str, s2: str) -> float:
    """词级 Jaccard 相似度"""
    set1: Set[str] = set(s1.split())
    set2: Set[str] = set(s2.split())
    if not set1 and not set2:
        return 1.0
    intersection = set1 & set2
    union = set1 | set2
    return len(intersection) / len(union) if union else 0.0


def _char_jaccard(s1: str, s2: str) -> float:
    """字符级 Jaccard 相似度"""
    set1: Set[str] = set(s1)
    set2: Set[str] = set(s2)
    if not set1 and not set2:
        return 1.0
    intersection = set1 & set2
    union = set1 | set2
    return len(intersection) / len(union) if union else 0.0


def _combined_similarity(s1: str, s2: str) -> float:
    """组合相似度：max(词级, 字符级)"""
    return max(_jaccard_similarity(s1, s2), _char_jaccard(s1, s2))


def deduplicate_payloads(
    payloads: List[str],
    threshold: float = 0.85,
    preserve_order: bool = True,
) -> List[str]:
    """
    载荷去重

    使用归一化文本 + 组合 Jaccard 相似度检测重复。
    当相似度 >= threshold 时视为重复，保留先出现的。

    Args:
        payloads: 原始载荷列表
        threshold: 相似度阈值 (0.0-1.0)
        preserve_order: 是否保持原始顺序

    Returns:
        去重后的载荷列表
    """
    if not payloads:
        return []

    # 第一遍：精确去重
    seen_normalized: Set[str] = set()
    exact_deduped: List[Tuple[str, str]] = []

    for payload in payloads:
        normalized = _normalize(payload)
        if normalized not in seen_normalized:
            seen_normalized.add(normalized)
            exact_deduped.append((payload, normalized))

    # 第二遍：模糊去重
    result: List[str] = []
    result_normalized: List[str] = []

    for original, normalized in exact_deduped:
        is_dup = False
        for seen_norm in result_normalized:
            similarity = _combined_similarity(normalized, seen_norm)
            if similarity >= threshold:
                is_dup = True
                logger.debug("Fuzzy duplicate (sim=%.2f): %.60s", similarity, normalized[:60])
                break
        if not is_dup:
            result.append(original)
            result_normalized.append(normalized)

    removed = len(payloads) - len(result)
    if removed > 0:
        logger.info("Dedup: %d -> %d (%d removed)", len(payloads), len(result), removed)
    return result


def deduplicate_with_profiles(
    payloads: List[str],
    profiles: List[Any],
    threshold: float = 0.85,
) -> Tuple[List[str], List[Any]]:
    """带 PayloadProfile 的去重"""
    if len(payloads) != len(profiles):
        return payloads, profiles
    if not payloads:
        return [], []

    result_payloads: List[str] = []
    result_profiles: List[Any] = []
    result_normalized: List[str] = []

    for payload, profile in zip(payloads, profiles):
        normalized = _normalize(payload)
        is_dup = False
        for seen_norm in result_normalized:
            if _combined_similarity(normalized, seen_norm) >= threshold:
                is_dup = True
                break
        if not is_dup:
            result_payloads.append(payload)
            result_profiles.append(profile)
            result_normalized.append(normalized)

    return result_payloads, result_profiles
