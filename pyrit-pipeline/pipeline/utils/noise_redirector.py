# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""噪音输出重定向器。.

将 PyRIT 初始化过程中的 "Skipping scorer..." 等噪音信息
重定向到 .noise.log 文件，保持 stdout 只输出 ASR/攻击/证据核心信号。

参照 pyrit_ai300 项目的双日志架构:
  - pipeline-YYYYMMDD_HHMMSS.log      → 信号 (ASR, 攻击, 证据)
  - pipeline-YYYYMMDD_HHMMSS.noise.log → 噪音 (scorer skipping, config loading)

学术依据:
  - IEEE Std 1044-2009 分类准则: 可追踪性 (traceability) 要求信号/噪音分离
  - AI Red Team 评估中 ASR (Attack Success Rate) 是核心指标,
    噪音信息 (scorer skipping 等) 不影响攻击链路和 ASR 数据可信度
"""

from __future__ import annotations

import contextlib
import re
import sys
import warnings
from pathlib import Path
from typing import Any, TextIO

# ── 噪音模式: 匹配 PyRIT 初始化过程中的非核心输出 ──
# 这些行不影响程序正常运行, 统一归类到噪音日志
_NOISE_PATTERNS: list[re.Pattern[str]] = [
    # Scorer 初始化跳过
    re.compile(r"^Skipping scorer\s", re.IGNORECASE),
    re.compile(r"^No scorers in category\s", re.IGNORECASE),
    re.compile(r"^No composite scorers available", re.IGNORECASE),
    re.compile(r"^Skipping best objective tagging", re.IGNORECASE),
    # 配置加载
    re.compile(r"^Loading configuration file:", re.IGNORECASE),
    # Target 回退
    re.compile(r"^TargetRegistry entry\s.*not found\.", re.IGNORECASE),
    re.compile(r"Falling back to default", re.IGNORECASE),
    # Preload 元数据
    re.compile(r"PreloadScenarioMetadata", re.IGNORECASE),
    # Converter 重试噪音
    re.compile(r"^Retry attempt \d+ for converter\.", re.IGNORECASE),
    # PyRIT 内部日志
    re.compile(r"^\[.*\]\s*(INFO|DEBUG|WARNING)\s", re.IGNORECASE),
    # Python 警告 (SyntaxWarning, DeprecationWarning, FutureWarning 等)
    re.compile(r"\.py:\d+:\s+(Syntax|Deprecation|Future|Resource|Runtime)Warning:", re.IGNORECASE),
    # Python 警告的第二行 (源代码行)
    re.compile(r"^\s+.*=.*''\s*$"),
    # PyRIT TextAdaptive 内部排除技术提示 (噪音)
    re.compile(r"^TextAdaptive:\s", re.IGNORECASE),
    re.compile(r"_EXCLUDED_TECHNIQUES\s", re.IGNORECASE),
    # Converter 构建失败 (非致命, 噪音)
    re.compile(r"^Failed to build converter chain", re.IGNORECASE),
    # PyRIT 技术跳过提示
    re.compile(r"^Skipping technique\s", re.IGNORECASE),
    # Transient API error 重试日志 (噪音)
    re.compile(r"^Transient API error", re.IGNORECASE),
    re.compile(r"got (API)?(Timeout)?Error\s.*retrying", re.IGNORECASE),
]


def _is_noise_line(line: str) -> bool:
    """判断一行是否为噪音输出。.

    噪音行的特征:
      - 以 "Skipping scorer" 开头
      - 以 "No scorers in category" 开头
      - 以 "Loading configuration file" 开头
      - 包含 "TargetRegistry entry ... not found"
      - 包含 "PreloadScenarioMetadata"
      - 以 "Retry attempt N for converter" 开头
      - 匹配 PyRIT 内部日志格式 [time] LEVEL message
    """
    stripped = line.strip()
    if not stripped:
        return False
    return any(p.search(stripped) for p in _NOISE_PATTERNS)


class NoiseFilter:
    """过滤 stdout/stderr 中的噪音行，将噪音写入 noise_log_file，信号写入 signal_log_file。.

    工作原理:
      1. 拦截 write() 调用，按行拆分
      2. 每行用 _is_noise_line() 判断
      3. 噪音行 → 写入 noise_log_file
      4. 信号行 → 写入原始 stdout (显示给用户) + signal_log_file (持久化)

    双通道架构 (NIST SP 800-92):
      - 终端通道: 信号行实时显示给用户 (stdout)
      - 文件通道: 信号行持久化到 signal_log_file (审计可追溯)

    注意:
      - 不完整的行 (无换行符) 留在 buffer 中等待下一次 write
      - flush() 时将 buffer 中的内容路由到对应输出
      - signal_log_path=None 时不写入信号文件 (用于嵌套内层)
    """

    def __init__(
        self,
        original_stream: TextIO,
        noise_log_path: Path,
        signal_log_path: Path | None = None,
    ) -> None:
        """Initialize NoiseFilter."""
        self._original = original_stream
        self._noise_log_path = noise_log_path
        self._noise_log_path.parent.mkdir(parents=True, exist_ok=True)
        self._noise_file: TextIO = open(noise_log_path, "a", encoding="utf-8")  # noqa: SIM115
        self._buffer = ""

        # 信号日志文件 (可选, 内层嵌套时不传以避免重复写入)
        self._signal_log_path = signal_log_path
        self._signal_file: TextIO | None = None
        if signal_log_path:
            signal_log_path.parent.mkdir(parents=True, exist_ok=True)
            self._signal_file = open(signal_log_path, "a", encoding="utf-8")  # noqa: SIM115

    def write(self, text: str) -> int:
        """Write text to the filter, routing signal vs noise."""
        if not text:
            return 0
        self._buffer += text
        # 按行拆分并路由
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            self._route_line(line + "\n")
        return len(text)

    def _route_line(self, line: str) -> None:
        """将一行路由到噪音文件或信号输出 (终端 + 信号文件)。."""
        if _is_noise_line(line):
            self._noise_file.write(line)
            self._noise_file.flush()
        else:
            # 信号行: 写入终端 (原始 stdout)
            self._original.write(line)
            self._original.flush()
            # 信号行: 同时写入信号日志文件 (持久化, NIST SP 800-92)
            if self._signal_file:
                self._signal_file.write(line)
                self._signal_file.flush()

    def flush(self) -> None:
        """Flush buffered content to appropriate destinations."""
        if self._buffer:
            self._route_line(self._buffer)
            self._buffer = ""
        self._noise_file.flush()
        if self._signal_file:
            self._signal_file.flush()
        with contextlib.suppress(Exception):
            """Close the filter and associated files."""
            self._original.flush()

    def close(self) -> None:
        """Close the filter and associated files."""
        self.flush()
        self._noise_file.close()
        if self._signal_file:
            self._signal_file.close()

    def __getattr__(self, name: str) -> Any:
        """代理原始 stream 的其他属性 (如 isatty, encoding 等)。."""
        return getattr(self._original, name)


@contextlib.contextmanager
def redirect_noise_to_file(
    noise_log_path: Path,
    signal_log_path: Path | None = None,
) -> Any:
    """上下文管理器: 将噪音 stdout/stderr 重定向到文件，信号双写到终端+文件。.

    在此上下文内，所有 stdout/stderr 输出经过 NoiseFilter:
      - 噪音行 (Skipping scorer... 等) → noise_log_path 文件
      - 信号行 (ASR, 攻击, 证据) → 原始 stdout (显示给用户) + signal_log_path (持久化)

    同时将 Python warnings (SyntaxWarning, DeprecationWarning 等)
    重定向到噪音日志，避免第三方库警告污染 stdout。

    嵌套使用:
      - 外层 (main.py): redirect_noise_to_file(noise_path, signal_path) — 全流水线
      - 内层 (stage_init/scenario): redirect_noise_to_file(noise_path) — 不传 signal_path
        内层的信号行写往外层 NoiseFilter, 由外层统一写入信号日志, 避免重复

    用法::

        # 外层 (全流水线)
        with redirect_noise_to_file(noise_path, signal_path):
            await pipeline.run()

        # 内层 (局部噪音拦截)
        with redirect_noise_to_file(noise_path):
            await config.initialize_pyrit_async()
    """
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    filter_stdout = NoiseFilter(old_stdout, noise_log_path, signal_log_path)
    filter_stderr = NoiseFilter(old_stderr, noise_log_path, signal_log_path)
    sys.stdout = filter_stdout  # type: ignore[assignment]
    sys.stderr = filter_stderr  # type: ignore[assignment]

    # 捕获 Python warnings (SyntaxWarning 等) 到噪音日志
    # 使用自定义 showwarning 写入噪音文件
    noise_file = filter_stderr._noise_file

    def _noise_warning_handler(
        message: Any,
        category: type[Warning],
        filename: str,
        lineno: int,
        file: Any = None,
        line: Any = None,
    ) -> None:
        """将 Python warnings 写入噪音日志而非 stderr。."""
        msg = warnings.formatwarning(message, category, filename, lineno, line)
        noise_file.write(msg)
        noise_file.flush()

    old_showwarning = warnings.showwarning
    warnings.showwarning = _noise_warning_handler

    try:
        yield
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        warnings.showwarning = old_showwarning
        filter_stdout.close()
        filter_stderr.close()


def suppress_import_warnings(noise_log_path: Path | None = None) -> None:
    """全局抑制第三方库导入时的 SyntaxWarning / DeprecationWarning 等。.

    在 ``main.py`` 最顶部 (任何其他 import 之前) 调用，
    将第三方库 (如 confusables) 的 SyntaxWarning 静默处理。

    Args:
        noise_log_path: 如果指定，警告写入该文件；否则直接忽略。
    """
    if noise_log_path:
        noise_log_path.parent.mkdir(parents=True, exist_ok=True)
        noise_file = open(noise_log_path, "a", encoding="utf-8")  # noqa: SIM115

        def _early_warning_handler(
            message: Any,
            category: type[Warning],
            filename: str,
            lineno: int,
            file: Any = None,
            line: Any = None,
        ) -> None:
            msg = warnings.formatwarning(message, category, filename, lineno, line)
            noise_file.write(msg)
            noise_file.flush()

        warnings.showwarning = _early_warning_handler
    else:
        # 直接忽略 SyntaxWarning / DeprecationWarning
        warnings.filterwarnings("ignore", category=SyntaxWarning)
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        warnings.filterwarnings("ignore", category=FutureWarning)
