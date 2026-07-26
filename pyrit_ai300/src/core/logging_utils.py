"""
日志工具模块
============

提供双通道输出（终端 + 日志文件）和日志初始化工具。

对齐 PyRIT 1.0.0：透传原始 terminal 的关键属性（encoding / errors / isatty /
fileno 等），确保第三方库（如 PyRIT StdoutSink）能正常访问 sys.stdout.encoding。
"""

import sys
from datetime import datetime
from pathlib import Path
from typing import Any


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


def setup_logging(config_loader: Any, start_time: datetime) -> Path:
    """
    设置日志文件，将 stdout/stderr 同时输出到终端和文件

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

    return log_path
