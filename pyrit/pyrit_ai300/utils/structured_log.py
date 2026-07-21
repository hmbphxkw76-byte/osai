# -*- coding: utf-8 -*-
"""
AI-300 Framework - Structured JSON Logger (L5)
结构化日志系统：JSON 格式输出，支持日志聚合和分析

特性：
1. JSON 格式日志（可被 ELK/Loki/Grafana 等日志系统直接消费）
2. 上下文字段绑定（bind() 方法，类似 structlog）
3. 性能指标自动记录（duration_ms / status）
4. 异常信息结构化（to_dict 序列化）
5. 向后兼容：不破坏现有 logging.getLogger() 调用
6. 双模式：JSON（生产）+ 文本（开发），通过环境变量切换

设计原则（L5 最佳实践）：
- 零外部依赖（不依赖 structlog/loguru）
- 与标准 logging 模块完全兼容
- 支持渐进式迁移（现有 logger.info() 无需改动）
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union

# 日志格式选择：JSON 或 TEXT
_LOG_FORMAT = os.environ.get("AI300_LOG_FORMAT", "text").lower()
# 日志级别（环境变量覆盖）
_LOG_LEVEL = os.environ.get("AI300_LOG_LEVEL", "INFO").upper()


class StructuredLogFormatter(logging.Formatter):
    """
    JSON 结构化日志格式化器

    输出格式：
    {
        "timestamp": "2026-07-21T10:30:00.123Z",
        "level": "INFO",
        "logger": "pyrit_ai300.recon",
        "message": "Recon complete",
        "context": {"target": "http://...", "duration_ms": 1234},
        "module": "recon_engine",
        "function": "run",
        "line": 42,
        "exception": null
    }
    """

    def __init__(self, include_extra: bool = True):
        super().__init__()
        self._include_extra = include_extra

    def format(self, record: logging.LogRecord) -> str:
        # 基础字段
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # 附加上下文（通过 extra 传入的 kwargs）
        if self._include_extra:
            extra_keys = set(record.__dict__.keys()) - {
                "name", "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "exc_info", "exc_text", "stack_info",
                "funcName", "lineno", "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process", "message",
                "taskName",
            }
            context = {}
            for key in extra_keys:
                val = getattr(record, key, None)
                if val is not None:
                    # 尝试 JSON 序列化，失败则转字符串
                    try:
                        json.dumps(val)
                        context[key] = val
                    except (TypeError, ValueError):
                        context[key] = str(val)
            if context:
                log_entry["context"] = context

        # 异常信息
        if record.exc_info:
            exc_type = record.exc_info[0]
            exc_value = record.exc_info[1]
            log_entry["exception"] = {
                "type": exc_type.__name__ if exc_type else "",
                "message": str(exc_value) if exc_value else "",
            }
            # AI300Error 携带额外上下文
            if hasattr(exc_value, "to_dict"):
                log_entry["exception"]["details"] = exc_value.to_dict()  # type: ignore

        return json.dumps(log_entry, ensure_ascii=False, default=str)


class TextLogFormatter(logging.Formatter):
    """人类可读的彩色文本格式（开发模式）"""

    # ANSI 颜色码
    _COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    _RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self._COLORS.get(record.levelname, "")
        timestamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S.%f")[:-3]
        msg = record.getMessage()

        # 提取上下文字段
        extra_keys = set(record.__dict__.keys()) - {
            "name", "msg", "args", "levelname", "levelno", "pathname",
            "filename", "module", "exc_info", "exc_text", "stack_info",
            "funcName", "lineno", "created", "msecs", "relativeCreated",
            "thread", "threadName", "processName", "process", "message",
            "taskName",
        }
        ctx_parts = []
        for key in extra_keys:
            val = getattr(record, key, None)
            if val is not None:
                ctx_parts.append(f"{key}={val}")

        ctx_str = f" [{', '.join(ctx_parts)}]" if ctx_parts else ""
        prefix = f"{color}{timestamp} [{record.levelname:5s}]{self._RESET}"
        return f"{prefix} {record.name}: {msg}{ctx_str}"


class BoundLogger:
    """
    上下文绑定日志器（类似 structlog.bound）

    绑定的上下文字段会自动附加到每条日志。

    Usage:
        log = StructuredLogger("recon").bind(target="http://example.com", phase="recon")
        log.info("Starting recon")      # → {"message": "Starting recon", "target": "...", "phase": "recon"}
        log.info("Recon complete", duration_ms=1234)  # → 附加 duration_ms
    """

    def __init__(self, logger: logging.Logger, context: Optional[Dict[str, Any]] = None):
        self._logger = logger
        self._context = context or {}

    def bind(self, **kwargs: Any) -> "BoundLogger":
        """绑定上下文字段（返回新实例，不修改原实例）"""
        new_context = {**self._context, **kwargs}
        return BoundLogger(self._logger, new_context)

    def _log(self, level: int, msg: str, *args: Any, **kwargs: Any) -> None:
        """带上下文的日志记录"""
        extra = {**self._context, **kwargs.pop("extra", {})}
        self._logger.log(level, msg, *args, extra=extra, **kwargs)

    def debug(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._log(logging.DEBUG, msg, *args, **kwargs)

    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._log(logging.INFO, msg, *args, **kwargs)

    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._log(logging.WARNING, msg, *args, **kwargs)

    def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._log(logging.ERROR, msg, *args, **kwargs)

    def critical(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._log(logging.CRITICAL, msg, *args, **kwargs)

    def exception(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """记录异常（自动附加 traceback）"""
        extra = {**self._context, **kwargs.pop("extra", {})}
        self._logger.error(msg, *args, extra=extra, exc_info=True, **kwargs)

    @property
    def name(self) -> str:
        return self._logger.name

    @property
    def level(self) -> int:
        return self._logger.level


class StructuredLogger:
    """
    结构化日志器工厂

    统一的日志创建入口，自动选择 JSON 或 TEXT 格式。

    Usage:
        from pyrit_ai300.utils.structured_log import StructuredLogger

        log = StructuredLogger.get_logger("pyrit_ai300.recon")
        log.info("Starting recon", extra={"target": "http://example.com"})

        # 绑定上下文
        bound = StructuredLogger.bind(log, target="http://example.com")
        bound.info("Recon complete", duration_ms=1234)
    """

    _initialized: bool = False

    @classmethod
    def get_logger(
        cls,
        name: str = "pyrit_ai300",
        level: Optional[Union[int, str]] = None,
        log_file: Optional[str] = None,
    ) -> logging.Logger:
        """
        获取配置好的 Logger

        根据 AI300_LOG_FORMAT 环境变量自动选择 JSON 或 TEXT 格式。

        Args:
            name: Logger 名称
            level: 日志级别（None 时使用 AI300_LOG_LEVEL 环境变量）
            log_file: 日志文件路径（可选）

        Returns:
            配置好的 logging.Logger
        """
        # 解析日志级别
        if level is None:
            level = getattr(logging, _LOG_LEVEL, logging.INFO)
        elif isinstance(level, str):
            level = getattr(logging, level.upper(), logging.INFO)

        logger = logging.getLogger(name)
        logger.setLevel(level)

        # 避免重复添加 handler
        if not logger.handlers:
            # 选择格式化器
            if _LOG_FORMAT == "json":
                formatter = StructuredLogFormatter()
            else:
                formatter = TextLogFormatter()

            # 控制台 handler
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(level)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

            # 文件 handler（始终 JSON 格式，便于日志聚合）
            if log_file:
                from pathlib import Path
                Path(log_file).parent.mkdir(parents=True, exist_ok=True)
                file_handler = logging.FileHandler(log_file, encoding="utf-8")
                file_handler.setLevel(level)
                file_handler.setFormatter(StructuredLogFormatter())
                logger.addHandler(file_handler)

            # 防止日志向上传播（避免 root logger 重复输出）
            logger.propagate = False

        return logger

    @staticmethod
    def bind(logger: logging.Logger, **context: Any) -> BoundLogger:
        """
        绑定上下文字段到日志器

        返回 BoundLogger 实例，后续所有日志自动携带绑定字段。

        Args:
            logger: 原始 logging.Logger
            **context: 要绑定的上下文字段

        Returns:
            BoundLogger 实例

        Usage:
            log = StructuredLogger.get_logger("recon")
            bound = StructuredLogger.bind(log, target="http://example.com")
            bound.info("Starting")  # → 自动包含 target 字段
        """
        return BoundLogger(logger, context)

    @staticmethod
    def log_performance(
        logger: logging.Logger,
        operation: str,
        duration_ms: float,
        success: bool = True,
        **extra: Any,
    ) -> None:
        """
        记录性能指标日志

        Args:
            logger: Logger 实例
            operation: 操作名称
            duration_ms: 耗时（毫秒）
            success: 是否成功
            **extra: 额外字段
        """
        level = logging.INFO if success else logging.WARNING
        logger.log(
            level,
            f"Performance: {operation} {'succeeded' if success else 'failed'} in {duration_ms:.1f}ms",
            extra={
                "operation": operation,
                "duration_ms": round(duration_ms, 2),
                "success": success,
                **extra,
            },
        )


def setup_structured_logging(
    level: Optional[str] = None,
    log_format: Optional[str] = None,
    log_file: Optional[str] = None,
) -> None:
    """
    全局初始化结构化日志（在 __init__.py 中调用）

    Args:
        level: 日志级别（None 时使用环境变量）
        log_format: 日志格式 "json" 或 "text"（None 时使用环境变量）
        log_file: 日志文件路径（可选）
    """
    global _LOG_FORMAT, _LOG_LEVEL
    if log_format:
        _LOG_FORMAT = log_format.lower()
        os.environ["AI300_LOG_FORMAT"] = _LOG_FORMAT
    if level:
        _LOG_LEVEL = level.upper()
        os.environ["AI300_LOG_LEVEL"] = _LOG_LEVEL

    StructuredLogger.get_logger("pyrit_ai300", level=_LOG_LEVEL, log_file=log_file)
