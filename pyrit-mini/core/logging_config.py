"""Logging configurationSignal handling - imports main.py

:
    - setup_logging():  Handler  ( WARNING+,  INFO)
    - switch_log_file():  endpoint
    - install_signal_handlers(): SIGINT/SIGTERM graceful exit
"""

from __future__ import annotations

import logging
import signal
import sys
from pathlib import Path
from typing import Any

from core.cancellation import INTERRUPT_EXIT_CODE, get_cancellation_token

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_LOG_DATEFMT = "%H:%M:%S"

# : FileHandler ( endpoint )
_current_file_handler: logging.FileHandler | None = None
_top_level_file_handler: logging.FileHandler | None = None

# SIGINT/SIGTERM Signal handling
_signal_fired: bool = False
_global_ctx: Any = None

logger = logging.getLogger(__name__)


def setup_logging(output_dir: Path, verbose: bool = False) -> None:
    """Handler : +WARNING, INFO.

    Args:
        output_dir: Output directory, pipeline.log
        verbose: True  INFO ()
    """
    global _current_file_handler, _top_level_file_handler

    root = logging.getLogger()

    # == Handler: WARNING+, --verbose INFO ==
    terminal_level = logging.INFO if verbose else logging.WARNING
    for h in root.handlers:
        if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler):
            h.setLevel(terminal_level)

    # == Handler: INFO ==
    log_path = output_dir / "pipeline.log"
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATEFMT))
    root.addHandler(file_handler)
    _current_file_handler = file_handler
    _top_level_file_handler = file_handler

    logger = logging.getLogger(__name__)
    if verbose:
        logger.info("--verbose :  INFO ")
    logger.info("Pipeline log -> %s", log_path)


def switch_log_file(output_dir: Path) -> None:
    """output_dir ( endpoint ).

    Layer pipeline.log  (dual-write),
     per-endpoint pipeline.log
     Handler
    """
    global _current_file_handler

    root = logging.getLogger()
    logger = logging.getLogger(__name__)

    # per-endpoint FileHandler (Layer handler )
    if _current_file_handler is not None and _current_file_handler is not _top_level_file_handler:
        try:
            _current_file_handler.flush()
        except Exception:
            pass
        _current_file_handler.close()
        root.removeHandler(_current_file_handler)

    # per-endpoint FileHandler
    log_path = output_dir / "pipeline.log"
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATEFMT))
    root.addHandler(file_handler)
    _current_file_handler = file_handler

    logger.info("Pipeline log switched -> %s", log_path)


def install_signal_handlers(ctx: Any = None) -> None:
    """SIGINT/SIGTERM Signal handling - graceful exit +

    Production-grade:
        1. : ,  event loop
        2. :  (plan Wave 4.6: os._exit  SystemExit)

    plan Wave 4.6：取消状态统一由 `core.cancellation.CancellationToken` 持有（C3），
    信号处理只负责「置位 + 抛异常」，不再自己维护布尔 flag，也不再强杀进程。
    """
    global _global_ctx
    _global_ctx = ctx

    # 让流水线各阶段能通过 ctx 轮询取消状态（协作式收敛）
    if ctx is not None:
        try:
            ctx.cancellation_token = get_cancellation_token()
        except Exception as e:  # ctx 可能为只读替身，失败不得阻塞信号安装
            logger.warning("无法挂载 cancellation_token 到 ctx：%s", e)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)


def _signal_handler(signum: int, frame) -> None:
    """SIGINT/SIGTERM Signal handling - graceful exit +

    plan Wave 4.6：此前二次信号直接 `os._exit(130)`——进程级立即终止、不展开栈，
    所有 `finally` 清理（资源释放 / checkpoint 落盘 / 报告收尾）被整体跳过。
    现改为：两次都以**异常**方式退出，保证栈正常展开、`finally` 完整执行。
    """
    global _signal_fired

    _signal_fired = True
    attempts = get_cancellation_token().cancel(reason=f"signal {signum}")

    if attempts == 1:
        print("\n[!] Received interrupt signal, ... ( Ctrl+C )", file=sys.stderr)
        # KeyboardInterrupt asyncio.run
        raise KeyboardInterrupt

    print(
        f"\n[!] 第 {attempts} 次中断：强制退出（仍执行 finally 清理，退出码 "
        f"{INTERRUPT_EXIT_CODE}）",
        file=sys.stderr,
    )
    # SystemExit 同为异常 → finally 仍会执行；区别于 os._exit 的进程级强杀。
    raise SystemExit(INTERRUPT_EXIT_CODE)


def configure_root_logging(verbose: bool = False) -> None:
    """root logger ( + ).

    setup_logging() ,
    """
    logging.basicConfig(
        level=logging.WARNING,
        format=_LOG_FORMAT,
        datefmt=_LOG_DATEFMT,
    )
    # : INFO ()
    for _pkg in ("core", "recon", "arm", "strike", "assess", "report"):
        logging.getLogger(_pkg).setLevel(logging.INFO)
    #
    logging.getLogger("alembic").setLevel(logging.WARNING)
    logging.getLogger("pyrit").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    #
    import warnings

    warnings.filterwarnings("ignore", category=SyntaxWarning, module="confusables")


def flush_and_close_handlers() -> None:
    """Ensure all FileHandler flush + close, pipeline.log .

    : logging.FileHandler ,  flush/close
    ,
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
                    # R-H2 compliant: Do not silently swallow errors, debug
                    _logger.debug("Failed to flush/close FileHandler (non-fatal): %s", e)
        # root logger handlers
        root_logger.handlers = [
            h for h in root_logger.handlers if not (isinstance(h, logging.FileHandler) and h.closed)
        ]
        _current_file_handler = None
        _top_level_file_handler = None
    except Exception as e:
        # R-H2 compliant: Do not silently swallow errors, debug
        _logger.debug("flush_and_close_handlers failed (non-fatal): %s", e)
