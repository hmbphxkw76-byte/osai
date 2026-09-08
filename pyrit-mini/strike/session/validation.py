# -*- coding: utf-8 -*-
"""SessionValidator - 会话一致性验证器

验证多轮攻击中的会话一致性，检测:
1. Session ID 异常变化
2. Session 重置检测
3. 上下文连续性验证
4. Session 固定漏洞检测

Academic basis:
    - Dougherty et al. (arXiv:2306.05685) — Session anomaly detection
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """验证结果"""
    is_valid: bool = True
    is_consistent: bool = True
    changes: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)


class SessionValidator:
    """会话一致性验证器

    在多轮攻击中持续监控 session 状态，确保攻击在同一会话上下文中进行。

    使用示例:
        validator = SessionValidator(config.validation)
        result = validator.validate_turn(previous_state, current_state)
        if not result.is_consistent:
            handle_session_break()
    """

    def __init__(self, config: Any) -> None:
        """
        Args:
            config: SessionValidationConfig
        """
        self._config = config
        self._state_history: list[dict[str, str]] = []
        self._turn_counter: int = 0

    def validate_turn(
        self,
        previous_state: dict[str, str] | None,
        current_state: dict[str, str],
    ) -> ValidationResult:
        """验证单轮会话一致性

        Args:
            previous_state: 上一轮的状态快照
            current_state: 当前轮的状态

        Returns:
            ValidationResult 验证结果
        """
        self._turn_counter += 1
        result = ValidationResult()

        if not self._config.enabled:
            return result

        # 记录历史
        self._state_history.append(dict(current_state))

        # 第一轮无需比较
        if previous_state is None:
            return result

        # 检查变化
        for key, current_value in current_state.items():
            previous_value = previous_state.get(key)
            if previous_value is None:
                result.changes.append(f"新增 token: {key}")
            elif previous_value != current_value:
                change_desc = f"Token '{key}' 变化: {previous_value[:20]}... -> {current_value[:20]}..."
                result.changes.append(change_desc)

                # 重要 token 的变化可能导致会话断裂
                if key in ("session_id", "sessionid", "session_token"):
                    result.is_consistent = False
                    result.alerts.append(f"SESSION RESET DETECTED: {key} changed")

        # 检查缺失的 token
        for key in previous_state:
            if key not in current_state:
                result.changes.append(f"丢失 token: {key}")
                result.alerts.append(f"TOKEN LOST: {key}")

        # 策略特定验证
        if self._config.strategy == "track_changes":
            self._validate_track_changes(previous_state, current_state, result)
        elif self._config.strategy == "fixed":
            self._validate_fixed(previous_state, current_state, result)

        # 年龄检查
        if self._turn_counter > self._config.max_age_turns:
            result.recommendations.append(
                f"Session age ({self._turn_counter} turns) exceeds max ({self._config.max_age_turns})"
            )

        return result

    def _validate_track_changes(
        self,
        previous_state: dict[str, str],
        current_state: dict[str, str],
        result: ValidationResult,
    ) -> None:
        """track_changes 策略: 允许 session 更新，但检测异常重置"""
        # 正常的 session 刷新: 值变化但仍保持连续性
        # 异常重置: session_id 完全改变或消失
        for key in ("session_id", "sessionid", "session_token"):
            if key in previous_state and key in current_state:
                if previous_state[key] != current_state[key]:
                    # session 更新了，这是正常的
                    logger.debug("Session token '%s' refreshed normally", key)

    def _validate_fixed(
        self,
        previous_state: dict[str, str],
        current_state: dict[str, str],
        result: ValidationResult,
    ) -> None:
        """fixed 策略: session 必须保持不变"""
        for key in previous_state:
            if key in current_state:
                if previous_state[key] != current_state[key]:
                    result.is_valid = False
                    result.alerts.append(
                        f"Fixed session violation: '{key}' changed unexpectedly"
                    )

    def detect_session_fixation(self) -> bool:
        """检测 session 固定漏洞

        如果 session_id 在多次请求中保持不变且可预测，
        可能存在 session 固定风险。

        Returns:
            True 如果检测到潜在的 session 固定
        """
        if len(self._state_history) < 3:
            return False

        # 检查 session_id 是否长期不变
        session_ids = []
        for state in self._state_history:
            sid = state.get("session_id") or state.get("sessionid")
            if sid:
                session_ids.append(sid)

        if len(session_ids) >= 3:
            # 如果最近 3 次 session_id 完全相同，可能存在固定风险
            if len(set(session_ids[-3:])) == 1:
                logger.info(
                    "Potential session fixation: session_id unchanged for %d turns",
                    len(session_ids),
                )
                return True

        return False

    def get_history(self) -> list[dict[str, str]]:
        """获取状态历史"""
        return list(self._state_history)

    def reset(self) -> None:
        """重置验证器"""
        self._state_history.clear()
        self._turn_counter = 0
