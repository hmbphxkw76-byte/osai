"""
日志工具模块
============

提供双通道输出（终端 + 日志文件）和日志初始化工具。

对齐 PyRIT 1.0.0：
- 透传原始 terminal 的关键属性（encoding / errors / isatty / fileno 等），
  确保第三方库（如 PyRIT StdoutSink）能正常访问 sys.stdout.encoding。
- 集成 PyRIT 原生 pyrit.common.logger 日志系统，
  使原生 logger 的输出也写入项目日志文件。
- 使用 pyrit.common.path.LOG_PATH 作为 PyRIT 原生日志文件路径。
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

# PyRIT 原生 logger（模块级导入确保原生日志系统已初始化）
from pyrit.common.logger import logger as _pyrit_logger


class TeeOutput:
    """将 stdout/stderr 同时输出到终端和日志文件

    透传原始 terminal 的关键属性（encoding / errors / isatty / fileno 等），
    确保第三方库（如 PyRIT StdoutSink）能正常访问 sys.stdout.encoding。
    """

    def __init__(self, terminal: Any, log_file: Any):
        self.terminal = terminal
        self.log_file = log_file

    def write(self, data: str) -> None:
        self.terminal.write(data)
        self.log_file.write(data)
        self.log_file.flush()

    def flush(self) -> None:
        self.terminal.flush()
        self.log_file.flush()

    def reconfigure(self, **kwargs: Any) -> None:
        if hasattr(self.terminal, "reconfigure"):
            self.terminal.reconfigure(**kwargs)

    # ---- 属性透传 ----

    @property
    def encoding(self) -> str:
        """透传 encoding（PyRIT StdoutSink 需要）"""
        return getattr(self.terminal, "encoding", "utf-8")

    @property
    def errors(self) -> str:
        """透传 errors"""
        return getattr(self.terminal, "errors", "replace")

    def isatty(self) -> bool:
        return getattr(self.terminal, "isatty", lambda: False)()

    def fileno(self) -> int:
        return self.terminal.fileno()

    def __getattr__(self, name: str) -> Any:
        """其他未显式定义的属性回退到原始 terminal"""
        return getattr(self.terminal, name)


def get_pyrit_logger() -> logging.Logger:
    """获取 PyRIT 原生 logger 实例

    返回 pyrit.common.logger 中配置的 "ai-red-team" logger，
    该 logger 已有 FileHandler（写入 PyRIT 原生 LOG_PATH）和
    StreamHandler（写入 stdout）。

    Returns:
        PyRIT 原生 logging.Logger 实例
    """
    return _pyrit_logger


def configure_pyrit_logger(log_path: Optional[Path] = None) -> Path:
    """配置 PyRIT 原生 logger，使其也写入项目日志文件

    在 PyRIT 原生 logger（"ai-red-team"）上添加一个额外的 FileHandler，
    使原生日志输出同时写入 PyRIT 原生 LOG_PATH 和项目日志文件。

    Args:
        log_path: 项目日志文件路径。如果为 None，则仅使用 PyRIT 原生 LOG_PATH。

    Returns:
        实际使用的日志文件路径
    """
    if log_path is None:
        from pyrit.common.path import LOG_PATH
        return LOG_PATH

    # 避免重复添加同一文件的 handler
    for handler in _pyrit_logger.handlers:
        if isinstance(handler, logging.FileHandler):
            try:
                if Path(handler.baseFilename).resolve() == log_path.resolve():
                    return log_path
            except (OSError, ValueError):
                pass

    # 添加项目日志文件的 FileHandler
    fmt = "[%(asctime)s][%(msecs)d][%(name)s][%(levelname)s][%(message)s]"
    formatter = logging.Formatter(fmt=fmt, datefmt="%H:%M:%S")

    file_handler = logging.FileHandler(filename=log_path, mode="a+", encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    _pyrit_logger.addHandler(file_handler)

    return log_path


def setup_logging(config_loader: Any, start_time: datetime) -> Path:
    """
    设置日志文件，将 stdout/stderr 同时输出到终端和文件

    同时配置 PyRIT 原生 logger 写入项目日志文件，实现全链路日志统一。

    Args:
        config_loader: ConfigLoader 实例（需有 get_logs_dir() 方法）
        start_time: 流水线开始时间

    Returns:
        日志文件路径
    """
    logs_dir = Path(config_loader.get_logs_dir())
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_filename = f"pipeline-{start_time.strftime('%Y%m%d_%H%M%S')}.log"
    log_path = logs_dir / log_filename

    log_file = open(log_path, "w", encoding="utf-8", errors="replace")

    sys.stdout = TeeOutput(sys.stdout, log_file)
    sys.stderr = TeeOutput(sys.stderr, log_file)

    # 配置 PyRIT 原生 logger 也写入项目日志文件
    configure_pyrit_logger(log_path)

    return log_path
