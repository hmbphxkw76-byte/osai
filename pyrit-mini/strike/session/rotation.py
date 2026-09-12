# -*- coding: utf-8 -*-
"""SessionRotationPolicy - 会话轮换策略

管理 session 的生命周期和轮换策略。
支持: 粘性会话、会话池、每次新会话。

策略说明:
    - sticky: 单 session，维持到过期或达到 max_turns
    - pool: 预建立多个 session，并发请求时复用
    - fresh_per_request: 每次请求使用全新 session

Academic basis:
    - Crothers et al. (arXiv:2306.05685) — Adaptive session lifecycle
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SessionInfo:
    """Session 元数据"""

    session_id: str
    turn_count: int = 0
    is_active: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


class SessionRotationPolicy:
    """会话轮换策略

    管理 session 的获取、使用、归还和过期。

    使用示例:
        policy = SessionRotationPolicy(config.rotation)
        session = policy.acquire_session()
        # ... use session ...
        policy.release_session(session)
    """

    def __init__(self, config: Any) -> None:
        """
        Args:
            config: RotationPolicy
        """
        self._config = config
        self._active_session: SessionInfo | None = None
        self._session_pool: list[SessionInfo] = []
        self._pool_index: int = 0

    def acquire_session(
        self,
        tokens: dict[str, str] | None = None,
    ) -> SessionInfo | None:
        """获取一个 session

        Args:
            tokens: 当前 session tokens (用于创建 sticky session)

        Returns:
            SessionInfo 或 None
        """
        rotation_type = self._config.type
        if hasattr(rotation_type, "value"):
            rotation_type = rotation_type.value

        if rotation_type == "sticky":
            return self._acquire_sticky(tokens)
        elif rotation_type == "pool":
            return self._acquire_from_pool()
        elif rotation_type == "fresh_per_request":
            return self._acquire_fresh(tokens)
        else:
            logger.debug("Unknown rotation type: %s", rotation_type)
            return self._acquire_sticky(tokens)

    def release_session(self, session: SessionInfo) -> None:
        """释放 session"""
        session.turn_count += 1
        if session.turn_count >= self._config.max_turns:
            session.is_active = False
            logger.debug("Session %s expired after %d turns", session.session_id[:20], session.turn_count)

    def _acquire_sticky(
        self,
        tokens: dict[str, str] | None = None,
    ) -> SessionInfo | None:
        """获取或创建粘性 session"""
        if self._active_session is not None and self._active_session.is_active:
            return self._active_session

        # 创建新 session
        session_id = self._extract_session_id(tokens)
        if session_id is None:
            return None

        self._active_session = SessionInfo(session_id=session_id)
        logger.debug("New sticky session created: %s...", session_id[:20])
        return self._active_session

    def _acquire_from_pool(self) -> SessionInfo | None:
        """从池中获取 session"""
        # 池未初始化
        if not self._session_pool:
            return None

        # 轮询获取
        attempts = 0
        while attempts < len(self._session_pool):
            session = self._session_pool[self._pool_index % len(self._session_pool)]
            self._pool_index += 1
            if session.is_active:
                return session
            attempts += 1

        # 所有 session 都过期，返回最老的
        if self._session_pool:
            session = self._session_pool[0]
            session.is_active = True
            session.turn_count = 0
            return session
        return None

    def _acquire_fresh(self, tokens: dict[str, str] | None = None) -> SessionInfo | None:
        """获取全新 session (每次请求独立)"""
        session_id = self._extract_session_id(tokens)
        if session_id is None:
            return None
        return SessionInfo(session_id=session_id)

    @staticmethod
    def _extract_session_id(tokens: dict[str, str] | None) -> str | None:
        """从 tokens 中提取 session_id"""
        if not tokens:
            return None

        for key in ("session_id", "sessionid", "session_token", "sid"):
            if key in tokens:
                return tokens[key]

        # 返回第一个值
        return next(iter(tokens.values())) if tokens else None

    def initialize_pool(self, session_ids: list[str]) -> None:
        """初始化 session 池

        Args:
            session_ids: 预建立的 session ID 列表
        """
        self._session_pool = [SessionInfo(session_id=sid) for sid in session_ids[: self._config.pool_size]]
        logger.info("Session pool initialized with %d sessions", len(self._session_pool))

    def should_rotate(self) -> bool:
        """判断是否需要轮换 session"""
        if self._active_session is None:
            return True
        if not self._active_session.is_active:
            return True
        if self._active_session.turn_count >= self._config.max_turns:
            return True
        return False

    def get_active_session(self) -> SessionInfo | None:
        """获取当前活跃 session"""
        return self._active_session
