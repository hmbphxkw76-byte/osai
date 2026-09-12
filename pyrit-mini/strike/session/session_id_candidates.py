# -*- coding: utf-8 -*-
"""session_id_candidates.py — Session ID 候选生成器

根据 SessionIDAnalyzer 分析结果生成待探测的候选 session ID 列表。
支持多种模式: 结构化序列、时间戳、整数递增、用户名派生。

Academic basis:
    - OWASP ASI09: Session Identifier Enumeration
    - CWE-330: Use of Insufficiently Random Values
    - PortSwigger: Session Hijacking via Predictable Tokens

Constitution compliance:
    - R-SIZE: < 300 lines
    - R-H3: 单一职责 — 仅生成候选, 不执行探测
    - C1: 不使用 PyRIT (纯生成逻辑)
    - R-S1: 不硬编码目标标识符
"""

from __future__ import annotations

import re
from datetime import datetime

from strike.session.session_id_analyzer import AnalysisResult, PatternType


class SessionIDCandidateGenerator:
    """Session ID 候选生成器

    根据分析结果智能生成候选 session ID 列表,
    可直接用于 SessionEnumerator 执行枚举。
    """

    # 用户名派生模式的常用用户名
    USER_PREFIXES: list[str] = [
        "admin",
        "user",
        "test",
        "guest",
        "demo",
        "dev",
        "alice",
        "bob",
        "charlie",
        "operator",
        "root",
        "administrator",
        "system",
        "staging",
        "production",
    ]

    def generate(
        self,
        result: AnalysisResult,
        known_session: str,
        max_candidates: int = 10000,
    ) -> list[str]:
        """根据分析结果生成待探测的候选 session ID 列表

        Args:
            result: analyze() 返回的分析结果
            known_session: 一个已知的有效 session (用于提取前缀/日期部分)
            max_candidates: 最大生成数量

        Returns:
            候选 session ID 列表, 可直接用于 SessionEnumerator
        """
        candidates: list[str] = []

        if result.pattern_type == PatternType.STRUCTURED_SEQ:
            candidates = self._generate_structured_candidates(result, known_session, max_candidates)
        elif result.pattern_type in (PatternType.TIMESTAMP_MS, PatternType.TIMESTAMP_S):
            candidates = self._generate_timestamp_candidates(result, known_session, max_candidates)
        elif result.pattern_type == PatternType.INCREMENTAL_INT:
            candidates = self._generate_incremental_candidates(result, known_session, max_candidates)
        elif result.pattern_type == PatternType.USER_DERIVED:
            candidates = self._generate_user_candidates(known_session, max_candidates)
        else:
            candidates = self._generate_generic_candidates(known_session, max_candidates)

        return candidates[:max_candidates]

    def _generate_structured_candidates(
        self,
        result: AnalysisResult,
        known_session: str,
        max_candidates: int,
    ) -> list[str]:
        """生成结构化序列候选 (PREFIX-YYYYMMDD-COUNTER)"""
        pattern = re.compile(
            r"^(?P<prefix>[A-Za-z][A-Za-z0-9]{0,4})-"
            r"(?P<date>\d{8}|\d{10}|\d{13})-"
            r"(?P<counter>\d{2,8})$"
        )
        match = pattern.match(known_session)
        if not match:
            return []

        prefix = match.group("prefix")
        date_part = match.group("date")
        counter_width = result.counter_width or len(match.group("counter"))

        upper = min(max_candidates, 10**counter_width)
        return [
            f"{prefix}-{date_part}-{i:0{counter_width}d}"
            for i in range(1, upper + 1)
            if f"{prefix}-{date_part}-{i:0{counter_width}d}" != known_session
        ]

    def _generate_timestamp_candidates(
        self,
        result: AnalysisResult,
        known_session: str,
        max_candidates: int,
    ) -> list[str]:
        """生成时间戳模式候选"""
        num = self._extract_numeric_suffix(known_session)
        if num is None:
            num = int(datetime.now().timestamp() * 1000)

        is_ms = result.pattern_type == PatternType.TIMESTAMP_MS
        step = 1 if not is_ms else 1000

        candidates = []
        for i in range(1, min(max_candidates, 86400)):
            candidate = str(num - i * step)
            if candidate != known_session:
                candidates.append(candidate)
            if len(candidates) >= max_candidates:
                break
        return candidates

    def _generate_incremental_candidates(
        self,
        result: AnalysisResult,
        known_session: str,
        max_candidates: int,
    ) -> list[str]:
        """生成纯整数递增候选"""
        max_val = self._extract_numeric_suffix(known_session)
        if max_val is None:
            max_val = max_candidates

        upper = min(max_val, max_candidates)
        return [str(i) for i in range(1, upper + 1) if str(i) != known_session]

    def _generate_user_candidates(
        self,
        known_session: str,
        max_candidates: int,
    ) -> list[str]:
        """生成用户名派生模式候选"""
        prefix = known_session.split("_")[0] if "_" in known_session else ""
        suffix = known_session[len(prefix) + 1 :] if "_" in known_session else known_session

        candidates = []
        for user in self.USER_PREFIXES:
            if user != prefix:
                candidate = f"{user}_{suffix}"
                if candidate != known_session:
                    candidates.append(candidate)
            if len(candidates) >= max_candidates:
                break
        return candidates

    def _generate_generic_candidates(
        self,
        known_session: str,
        max_candidates: int,
    ) -> list[str]:
        """通用模式: 基于数字后缀扩展"""
        num_match = re.search(r"(\d+)$", known_session)
        if not num_match:
            return []

        base = num_match.group(1)
        prefix = known_session[: -len(base)]
        num = int(base)
        width = len(base)

        upper = min(num + max_candidates, 10**width - 1)
        return [f"{prefix}{i:0{width}d}" for i in range(1, upper + 1) if f"{prefix}{i:0{width}d}" != known_session]

    @staticmethod
    def _extract_numeric_suffix(text: str) -> int | None:
        """提取字符串末尾的数字"""
        match = re.search(r"(\d+)$", text)
        return int(match.group(1)) if match else None


def generate_candidates(
    result: AnalysisResult,
    known_session: str,
    max_candidates: int = 10000,
) -> list[str]:
    """便捷函数: 快速生成候选 session ID 列表"""
    generator = SessionIDCandidateGenerator()
    return generator.generate(result, known_session, max_candidates)
