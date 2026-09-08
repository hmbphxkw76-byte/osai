# -*- coding: utf-8 -*-
"""SessionStateManager - 会话状态管理器 SSOT

会话感知攻击框架的核心组件，统一管理:
1. 状态提取 (SessionExtractor)
2. 状态注入 (SessionInjector)
3. 一致性验证 (SessionValidator)
4. 轮换策略 (SessionRotationPolicy)

与 PyRIT 原生 HTTPTarget.callback_function 集成，
实现零侵入的会话状态追踪。

数据流:
    HTTP Response → callback → extract → state update
    HTTP Request → inject → state attach → send

Academic basis:
    - Russinovich et al. (arXiv:2404.01833) — Multi-turn state tracking
    - PyRIT (arXiv:2407.01232) — Native callback integration
"""
from __future__ import annotations

import logging
from typing import Any

from strike.session.extraction import SessionExtractor
from strike.session.injection import SessionInjector
from strike.session.rotation import SessionRotationPolicy
from strike.session.session_config import SessionConfig
from strike.session.validation import SessionValidator, ValidationResult

logger = logging.getLogger(__name__)


class SessionStateManager:
    """会话状态管理器 (SSOT)

    统一管理会话状态的完整生命周期。
    作为 PyRIT HTTPTarget 回调链的一部分运行。

    使用示例:
        config = SessionConfig.default_config()
        manager = SessionStateManager(config)

        # 在 HTTPTarget 回调中使用
        def callback(response):
            state = manager.extract_from_response(response)
            return parse_response(response)

        # 在发送请求前注入
        def prepare_request(request_text):
            return manager.inject_into_request(request_text)
    """

    def __init__(self, config: SessionConfig | None = None) -> None:
        """
        Args:
            config: SessionConfig，None 则使用默认配置
        """
        self._config = config or SessionConfig.default_config()

        # 初始化子组件
        self._extractor = SessionExtractor(self._config.extraction_rules)
        self._injector = SessionInjector(self._config.injection_rules)
        self._validator = SessionValidator(self._config.validation)
        self._rotation = SessionRotationPolicy(self._config.rotation)

        # 状态存储
        self._current_state: dict[str, str] = {}
        self._previous_state: dict[str, str] | None = None
        self._turn_counter: int = 0
        self._is_active: bool = False

    @property
    def current_state(self) -> dict[str, str]:
        """获取当前会话状态快照"""
        return dict(self._current_state)

    @property
    def is_active(self) -> bool:
        """会话管理器是否激活"""
        return self._is_active

    @property
    def turn_count(self) -> int:
        """当前轮数"""
        return self._turn_counter

    def activate(self) -> None:
        """激活会话管理器"""
        self._is_active = True
        logger.debug("SessionStateManager activated")

    def deactivate(self) -> None:
        """停用会话管理器"""
        self._is_active = False
        logger.debug("SessionStateManager deactivated")

    def extract_from_response(self, response: Any) -> dict[str, str]:
        """从 HTTP 响应中提取会话状态

        Args:
            response: HTTP 响应对象 (支持 .text, .content, .headers)

        Returns:
            提取到的 {token_name: token_value} 字典
        """
        if not self._is_active:
            return {}

        # 提取响应文本
        response_text = self._get_response_text(response)
        if not response_text:
            return {}

        # 提取 headers (如果可用)
        response_headers = self._get_response_headers(response)
        response_cookies = self._get_response_cookies(response)

        # 执行提取
        extracted = self._extractor.extract_all(
            response_text, response_headers, response_cookies
        )

        if extracted:
            self._previous_state = dict(self._current_state)
            self._current_state.update(extracted)
            self._turn_counter += 1

            logger.debug(
                "Session state updated: %s (turn %d)",
                list(extracted.keys()),
                self._turn_counter,
            )

        return extracted

    def inject_into_request(self, request_text: str) -> str:
        """向 HTTP 请求注入会话状态

        Args:
            request_text: HTTP 请求文本

        Returns:
            注入后的请求文本
        """
        if not self._is_active or not self._current_state:
            return request_text

        # 检查轮换策略
        if self._rotation.should_rotate():
            logger.debug("Session rotation triggered")

        return self._injector.inject(request_text, self._current_state)

    def validate_consistency(self) -> ValidationResult:
        """验证会话一致性

        Returns:
            ValidationResult 验证结果
        """
        result = self._validator.validate_turn(
            self._previous_state, self._current_state
        )

        if result.alerts:
            for alert in result.alerts:
                logger.warning("[Session] %s", alert)

        return result

    def snapshot(self) -> dict[str, Any]:
        """生成完整状态快照

        Returns:
            包含当前状态、配置、历史的完整快照
        """
        return {
            "current_state": dict(self._current_state),
            "previous_state": dict(self._previous_state) if self._previous_state else None,
            "turn_counter": self._turn_counter,
            "is_active": self._is_active,
            "config": self._config.to_dict(),
            "history": self._validator.get_history(),
        }

    def restore(self, snapshot: dict[str, Any]) -> None:
        """从快照恢复状态

        Args:
            snapshot: snapshot() 生成的快照
        """
        self._current_state = dict(snapshot.get("current_state", {}))
        prev = snapshot.get("previous_state")
        self._previous_state = dict(prev) if prev else None
        self._turn_counter = snapshot.get("turn_counter", 0)
        self._is_active = snapshot.get("is_active", False)

    def reset(self) -> None:
        """重置会话状态"""
        self._current_state.clear()
        self._previous_state = None
        self._turn_counter = 0
        self._validator.reset()
        logger.debug("SessionStateManager reset")

    @staticmethod
    def _get_response_text(response: Any) -> str | None:
        """从响应对象提取文本"""
        if hasattr(response, "text") and response.text is not None:
            if isinstance(response.text, str):
                return response.text
            return str(response.text)
        if hasattr(response, "content"):
            if isinstance(response.content, bytes):
                return response.content.decode("utf-8", errors="replace")
            return str(response.content)
        return None

    @staticmethod
    def _get_response_headers(response: Any) -> dict[str, str]:
        """从响应对象提取 headers"""
        if hasattr(response, "headers"):
            headers = response.headers
            if hasattr(headers, "items"):
                return dict(headers)
            if isinstance(headers, dict):
                return headers
        return {}

    @staticmethod
    def _get_response_cookies(response: Any) -> dict[str, str]:
        """从响应对象提取 cookies"""
        if hasattr(response, "cookies"):
            cookies = response.cookies
            if hasattr(cookies, "get_dict"):
                return cookies.get_dict()
            if isinstance(cookies, dict):
                return cookies
        return {}

    def create_callback_wrapper(self, original_callback: Any) -> Any:
        """创建组合回调 (PyRIT 原生集成)

        将 session 状态提取嵌入 PyRIT HTTPTarget 回调链。

        Args:
            original_callback: 原始回调函数

        Returns:
            组合后的回调函数
        """
        def combined_callback(response: Any) -> str:
            # 1. 提取 session 状态
            try:
                self.extract_from_response(response)
            except Exception as e:
                logger.debug("Session extraction failed: %s", e)

            # 2. 调用原始回调
            if original_callback:
                return original_callback(response)
            return self._get_response_text(response) or ""

        combined_callback.__name__ = f"session_aware({getattr(original_callback, '__name__', 'callback')})"
        return combined_callback
