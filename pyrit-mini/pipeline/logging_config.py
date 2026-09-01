"""日志配置 — 双 Handler 分流 (终端 WARNING+, 文件 INFO)。

v57 重构: 从 main.py 提取日志配置逻辑, 实现关注点分离。
"""

from __future__ import annotations

import logging
from pathlib import Path

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_LOG_DATEFMT = "%H:%M:%S"

# 全局引用: 当前 FileHandler (多 endpoint 切换时更新路径)
current_file_handler: logging.FileHandler | None = None
_top_level_file_handler: logging.FileHandler | None = None


def configure_logging(output_dir: Path, verbose: bool = False) -> None:
    """配置双 Handler 分流: 终端只看卡片+WARNING, 文件记录全量 INFO。

    Args:
        output_dir: 输出目录, pipeline.log 写入此处。
        verbose: True 时终端也显示 INFO (调试模式)。
    """
    global current_file_handler, _top_level_file_handler

    root = logging.getLogger()

    # ── 终端 Handler: 默认 WARNING+, --verbose 时 INFO ──
    terminal_level = logging.INFO if verbose else logging.WARNING
    for h in root.handlers:
        if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler):
            h.setLevel(terminal_level)

    # ── 文件 Handler: 全量 INFO ──
    log_path = output_dir / "pipeline.log"
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATEFMT))
    root.addHandler(file_handler)
    current_file_handler = file_handler
    _top_level_file_handler = file_handler  # L5 fix: keep top-level handler for dual-write

    if verbose:
        logging.getLogger(__name__).info("--verbose 模式: 终端显示 INFO 级别日志")
    logging.getLogger(__name__).info("Pipeline log → %s", log_path)


def switch_log_file(output_dir: Path) -> None:
    """切换文件日志到新的 output_dir (多 endpoint 场景)。

    L5 fix: 保持顶层 pipeline.log 继续接收日志 (dual-write),
    同时在新目录添加 per-endpoint pipeline.log。
    终端 Handler 不变。
    """
    global current_file_handler

    root = logging.getLogger()

    # 移除旧 per-endpoint FileHandler (顶层 handler 保留)
    if current_file_handler is not None and current_file_handler is not _top_level_file_handler:
        try:
            current_file_handler.flush()
        except Exception:
            pass
        current_file_handler.close()
        root.removeHandler(current_file_handler)

    # 添加新 per-endpoint FileHandler
    log_path = output_dir / "pipeline.log"
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATEFMT))
    root.addHandler(file_handler)
    current_file_handler = file_handler

    logging.getLogger(__name__).info("Pipeline log switched → %s", log_path)
