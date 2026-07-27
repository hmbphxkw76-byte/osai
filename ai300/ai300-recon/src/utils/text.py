# -*- coding: utf-8 -*-
"""
Text Utilities
==============

文本处理工具：
  - 从配置读取截断长度，统一日志/错误消息长度，避免硬编码。
"""

from __future__ import annotations

from typing import Any, Dict, Optional


def truncate_error(
    text: str,
    config: Optional[Dict[str, Any]] = None,
    default: int = 120,
) -> str:
    """截断错误/异常日志消息，优先从配置读取长度限制。"""
    limit = (config or {}).get("logging", {}).get("error_message_limit", default)
    return text[:limit]


def truncate_stage_error(
    text: str,
    config: Optional[Dict[str, Any]] = None,
    default: int = 200,
) -> str:
    """截断阶段异常结果消息，优先从配置读取长度限制。"""
    limit = (config or {}).get("logging", {}).get("stage_error_limit", default)
    return text[:limit]
