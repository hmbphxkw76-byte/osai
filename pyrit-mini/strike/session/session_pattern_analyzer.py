# -*- coding: utf-8 -*-
"""session_pattern_analyzer.py — Session ID 模式自动推断器

从实际 session_id 样本中自动识别模式模板。
支持多种常见格式的自动检测。

Academic basis:
    - OWASP ASI09: Session Identifier Enumeration
    - CWE-330: Use of Insufficiently Random Values

Constitution compliance:
    - R-SIZE: < 300 lines
    - R-H3: 单一职责 — 仅分析模式, 不执行攻击
    - C1: 不使用 PyRIT (纯分析逻辑)
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any


class SessionIDAnalyzer:
    """Session ID 模式自动推断器

    从实际 session_id 样本中自动识别模式模板。
    支持多种常见格式的自动检测。

    Example:
        analyzer = SessionIDAnalyzer()

        # 识别日期+计数器模式
        pattern = analyzer.infer_pattern("MC-20260325-0015")
        # result: "MC-{date:%Y%m%d}-{counter:04d}"

        # 识别纯数字模式
        pattern = analyzer.infer_pattern("session_000042")
        # result: "session_{counter:06d}"
    """

    # 日期正则模式 (按优先级排序)
    _DATE_PATTERNS: list[tuple[str, str]] = [
        (r'\d{8}', '%Y%m%d'),
        (r'\d{6}', '%y%m%d'),
        (r'\d{4}-\d{2}-\d{2}', '%Y-%m-%d'),
        (r'\d{2}/\d{2}/\d{4}', '%m/%d/%Y'),
        (r'\d{2}-\d{2}-\d{2}', '%y-%m-%d'),
    ]

    # UUID 正则
    _UUID_PATTERN = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        re.IGNORECASE,
    )

    @classmethod
    def infer_pattern(cls, session_id: str) -> str:
        """从 session_id 样本推断模式模板

        自动识别以下模式:
            - 日期格式: 20260325, 2026-03-25 → {date:FORMAT}
            - 计数器: 0015, 000042 → {counter:WIDTHd}
            - UUID: 550e8400-e29b-... → {uuid}
            - 纯数字: 123456 → {counter:WIDTHd}
            - 随机字符串: abc123xyz → {random}

        Args:
            session_id: 实际 session_id 样本

        Returns:
            推断出的模式模板字符串
        """
        if not session_id:
            return "{counter:04d}"

        # 检测 UUID
        if cls._UUID_PATTERN.match(session_id):
            return "{uuid}"

        # 尝试识别日期 + 计数器混合模式
        date_parts = cls._extract_date_parts(session_id)
        if date_parts:
            return cls._build_pattern_with_date(session_id, date_parts)

        # 尝试纯计数器模式
        counter_pattern = cls._extract_counter(session_id)
        if counter_pattern:
            return counter_pattern

        # 尝试前缀 + 计数器模式
        prefix_counter = cls._extract_prefix_counter(session_id)
        if prefix_counter:
            return prefix_counter

        return "{random}"

    @classmethod
    def _extract_date_parts(
        cls, session_id: str
    ) -> list[tuple[str, str, int, int]] | None:
        """提取 session_id 中的日期部分.

        Returns:
            [(date_str, date_format, start, end), ...] 或 None
        """
        results: list[tuple[str, str, int, int]] = []

        for regex, fmt in cls._DATE_PATTERNS:
            for match in re.finditer(regex, session_id):
                date_str = match.group()
                try:
                    datetime.strptime(date_str, fmt)
                    results.append((date_str, fmt, match.start(), match.end()))
                except ValueError:
                    continue

        return results if results else None

    @classmethod
    def _build_pattern_with_date(
        cls,
        session_id: str,
        date_parts: list[tuple[str, str, int, int]],
    ) -> str:
        """构建包含日期的模式模板."""
        date_str, date_fmt, date_start, date_end = date_parts[0]

        prefix = session_id[:date_start]
        suffix = session_id[date_end:]
        suffix_pattern = cls._analyze_suffix(suffix)

        return f"{prefix}{{date:{date_fmt}}}{suffix_pattern}"

    @classmethod
    def _analyze_suffix(cls, suffix: str) -> str:
        """分析后缀部分 (计数器 or 随机)."""
        if not suffix:
            return ""

        clean = suffix.lstrip('-_')
        if clean.isdigit():
            return f"{{counter:{len(clean)}d}}"

        if clean:
            return "{random}"

        return suffix

    @classmethod
    def _extract_counter(cls, session_id: str) -> str | None:
        """提取纯数字计数器模式."""
        if session_id.isdigit():
            return f"{{counter:{len(session_id)}d}}"
        return None

    @classmethod
    def _extract_prefix_counter(cls, session_id: str) -> str | None:
        """提取前缀 + 计数器模式."""
        match = re.match(r'^(.+?)[-_](\d+)$', session_id)
        if match:
            prefix = match.group(1)
            counter = match.group(2)
            return f"{prefix}_{{counter:{len(counter)}d}}"

        match = re.match(r'^([a-zA-Z_-]+)(\d+)$', session_id)
        if match:
            prefix = match.group(1)
            counter = match.group(2)
            prefix = prefix.rstrip('-_')
            return f"{prefix}_{{counter:{len(counter)}d}}"

        return None

    @classmethod
    def analyze_batch(cls, session_ids: list[str]) -> dict[str, Any]:
        """批量分析 session_id 样本，返回统计信息."""
        if not session_ids:
            return {"count": 0, "patterns": []}

        patterns: dict[str, int] = {}
        for sid in session_ids:
            pattern = cls.infer_pattern(sid)
            patterns[pattern] = patterns.get(pattern, 0) + 1

        most_common = max(patterns, key=patterns.get) if patterns else ""

        return {
            "count": len(session_ids),
            "unique_patterns": len(patterns),
            "most_common_pattern": most_common,
            "pattern_distribution": patterns,
        }
