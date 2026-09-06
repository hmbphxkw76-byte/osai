"""日志配置与信号处理器 — 从 main.py 提取的共享基础设施。

提供:
    - setup_logging(): 双 Handler 分流 (终端 WARNING+, 文件全量 INFO)
    - switch_log_file(): 多 endpoint 场景切换日志文件
    - install_signal_handlers(): SIGINT/SIGTERM 优雅退出
"""

from __future__ import annotations

import logging
import os
import signal
import sys
from pathlib import Path
from typing import Any

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_LOG_DATEFMT = "%H:%M:%S"

# 全局引用: 当前 FileHandler (多 endpoint 切换时更新路径)
_current_file_handler: logging.FileHandler | None = None
_top_level_file_handler: logging.FileHandler | None = None

# SIGINT/SIGTERM 信号处理状态
_signal_fired: bool = False
_global_ctx: Any = None


def setup_logging(output_dir: Path, verbose: bool = False) -> None:
    """配置双 Handler 分流: 终端只看卡片+WARNING, 文件记录全量 INFO.

    Args:
        output_dir: 输出目录, pipeline.log 写入此处。
        verbose: True 时终端也显示 INFO (调试模式)。
    """
    global _current_file_handler, _top_level_file_handler

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
    _current_file_handler = file_handler
    _top_level_file_handler = file_handler

    logger = logging.getLogger(__name__)
    if verbose:
        logger.info("--verbose 模式: 终端显示 INFO 级别日志")
    logger.info("Pipeline log → %s", log_path)


def switch_log_file(output_dir: Path) -> None:
    """切换文件日志到新的 output_dir (多 endpoint 场景).

    保持顶层 pipeline.log 继续接收日志 (dual-write),
    同时在新目录添加 per-endpoint pipeline.log。
    终端 Handler 不变。
    """
    global _current_file_handler

    root = logging.getLogger()
    logger = logging.getLogger(__name__)

    # 移除旧 per-endpoint FileHandler (顶层 handler 保留)
    if _current_file_handler is not None and _current_file_handler is not _top_level_file_handler:
        try:
            _current_file_handler.flush()
        except Exception:
            pass
        _current_file_handler.close()
        root.removeHandler(_current_file_handler)

    # 添加新 per-endpoint FileHandler
    log_path = output_dir / "pipeline.log"
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATEFMT))
    root.addHandler(file_handler)
    _current_file_handler = file_handler

    logger.info("Pipeline log switched → %s", log_path)


def install_signal_handlers(ctx: Any = None) -> None:
    """安装 SIGINT/SIGTERM 信号处理器 — 优雅退出 + 资源清理。

    生产级行为:
        1. 第一次信号: 标记中断, 由 event loop 自然退出
        2. 第二次信号: 强制退出 (os._exit)
    """
    global _global_ctx
    _global_ctx = ctx

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)


def _signal_handler(signum: int, frame) -> None:
    """SIGINT/SIGTERM 信号处理器 — 优雅退出 + 资源清理。"""
    global _signal_fired
    if _signal_fired:
        # 重复信号: 直接退出, 不等待
        os._exit(130)
    _signal_fired = True
    print("\n[!] 收到中断信号, 正在退出... (再按一次 Ctrl+C 强制退出)", file=sys.stderr)
    # 抛出 KeyboardInterrupt 让 asyncio.run 自然退出
    raise KeyboardInterrupt


def configure_root_logging(verbose: bool = False) -> None:
    """配置 root logger 基础设置 (终端 + 噪音库压制).

    应在 setup_logging() 之前调用, 设置全局日志级别和格式。
    """
    logging.basicConfig(
        level=logging.WARNING,
        format=_LOG_FORMAT,
        datefmt=_LOG_DATEFMT,
    )
    # 自身包: 提升到 INFO (写入文件)
    for _pkg in ("core", "recon", "arm", "strike", "assess", "report"):
        logging.getLogger(_pkg).setLevel(logging.INFO)
    # 压制噪音库
    logging.getLogger("alembic").setLevel(logging.WARNING)
    logging.getLogger("pyrit").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    # 静默已知第三方警告
    import warnings
    warnings.filterwarnings("ignore", category=SyntaxWarning, module="confusables")


def flush_and_close_handlers() -> None:
    """确保所有 FileHandler flush + close, 防止 pipeline.log 丢失.

    根因: logging.FileHandler 使用缓冲写入, 程序退出前未 flush/close
    导致文件内容停留在内存缓冲区中, 文件为空或不存在。
    """
    global _current_file_handler, _top_level_file_handler
    _logger = logging.getLogger(__name__)
    try:
        root_logger = logging.getLogger()
        for h in root_logger.handlers:
            if isinstance(h, logging.FileHandler):
                try:
                    h.flush()
                    h.close()
                except Exception as e:
                    # R-H2 合规: 不静默吞错, 至少 debug 日志记录
                    _logger.debug("Failed to flush/close FileHandler (non-fatal): %s", e)
        # 从 root logger 移除已关闭的 handlers
        root_logger.handlers = [
            h for h in root_logger.handlers
            if not (isinstance(h, logging.FileHandler) and h.closed)
        ]
        _current_file_handler = None
        _top_level_file_handler = None
    except Exception as e:
        # R-H2 合规: 不静默吞错, 至少 debug 日志记录
        _logger.debug("flush_and_close_handlers failed (non-fatal): %s", e)
