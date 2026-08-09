# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""噪音输出重定向器。.

将 PyRIT 初始化过程中的 "Skipping scorer..." 等噪音信息
重定向到 .noise.log 文件，保持 stdout 只输出 ASR/攻击/证据核心信号。

三层日志架构:
  - pipeline-YYYYMMDD_HHMMSS.log      → 信号 (ASR, ✅ 成功攻击, 证据) + log-only (❌ 失败行)
  - pipeline-YYYYMMDD_HHMMSS.noise.log → 噪音 (scorer skipping, config loading)

红队最佳实践:
  终端只展示成功攻击 (✅), 失败行写入信号日志 (审计可追溯)。
  失败聚合计数 (FAIL=N) 已在 tqdm postfix 中实时展示, 不需逐行终端输出。

学术依据:
  - IEEE Std 1044-2009 分类准则: 可追踪性 (traceability) 要求信号/噪音分离
  - NIST SP 800-92: 三层路由 (signal / log-only / noise) 严格分离
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

# ── 噪音模式: 匹配 PyRIT 初始化和执行过程中的非核心输出 ──
# 这些行不影响程序正常运行, 统一归类到噪音日志
# L5 对齐 NIST SP 800-92: 信号/噪音严格分离, 噪音行不进入 signal log
_NOISE_PATTERNS: list[re.Pattern[str]] = [
    # ── Scorer 初始化跳过 ──
    re.compile(r"^Skipping scorer\s", re.IGNORECASE),
    re.compile(r"^No scorers in category\s", re.IGNORECASE),
    re.compile(r"^No composite scorers available", re.IGNORECASE),
    re.compile(r"^Skipping best objective tagging", re.IGNORECASE),
    # ── 配置加载 ──
    re.compile(r"^Loading configuration file:", re.IGNORECASE),
    # ── Target 回退 ──
    re.compile(r"^TargetRegistry entry\s.*not found\.", re.IGNORECASE),
    re.compile(r"Falling back to default", re.IGNORECASE),
    # ── Preload 元数据 ──
    re.compile(r"PreloadScenarioMetadata", re.IGNORECASE),
    # ── Converter/Scorer/Adversarial 重试噪音 ──
    re.compile(r"^Retry attempt \d+ for converter\.", re.IGNORECASE),
    re.compile(r"^Retry attempt \d+ for (objective scorer|adversarial chat)\.", re.IGNORECASE),
    # ── PyRIT 内部日志 ──
    re.compile(r"^\[.*\]\s*(INFO|DEBUG|WARNING)\s", re.IGNORECASE),
    # ── Python 警告 (SyntaxWarning, DeprecationWarning, FutureWarning 等) ──
    re.compile(r"\.py:\d+:\s+(Syntax|Deprecation|Future|Resource|Runtime)Warning:", re.IGNORECASE),
    re.compile(r"^\s+.*=.*''\s*$"),
    # ── PyRIT TextAdaptive 内部排除技术提示 ──
    re.compile(r"^TextAdaptive:\s", re.IGNORECASE),
    re.compile(r"_EXCLUDED_TECHNIQUES\s", re.IGNORECASE),
    # ── Converter 构建失败 (非致命) ──
    re.compile(r"^Failed to build converter chain", re.IGNORECASE),
    # ── PyRIT 技术跳过提示 ──
    re.compile(r"^Skipping technique\s", re.IGNORECASE),
    # ── Transient API error 重试日志 ──
    re.compile(r"^Transient API error", re.IGNORECASE),
    re.compile(r"got (API)?(Timeout)?Error\s.*retrying", re.IGNORECASE),
    # ── L5: Python Traceback 块 (255 行/次 → 噪音) ──
    re.compile(r"^Traceback \(most recent call last\):"),
    re.compile(r'^  File "'),
    re.compile(r"^\s+\^+$"),  # ^^^ 指针行
    re.compile(r"^(httpcore|httpx|openai|tenacity|asyncio)\.\w+(Error|Exception)"),
    re.compile(r"^ValueError: Atomic attack.*partially failed"),
    re.compile(r"^RuntimeError: Strategy execution failed"),
    # ── L5: EvidenceExporter 渲染/导出失败 (700 行 → 噪音) ──
    re.compile(r"^Failed to (render|export) conversation", re.IGNORECASE),
    # ── L5: PyRIT tqdm 进度条 (含 \r 的行, 33 行 → 噪音) ──
    re.compile(r"^Executing (TextAdaptive|PromptSending):\s+\d+%"),
    re.compile(r"^Executing (TextAdaptive|PromptSending):\s+\d+\|"),
    # ── L5: RateLimitError / API Error (执行阶段噪音) ──
    re.compile(r"^RateLimitError\s", re.IGNORECASE),
    re.compile(r"^Attack failed with (Exception|_StrategyRuntimeError|Error):"),
    re.compile(r"^Scenario 'TextAdaptive' (failed|partially)"),
    re.compile(r"^Atomic attack.*partially completed:"),
    re.compile(r"^Root cause:"),
    re.compile(r"^Details:"),
    re.compile(r"^Attack:\s"),
    re.compile(r"^Component:\s"),
    re.compile(r"^Objective:\s"),
    re.compile(r"^objective_target identifier:"),
    re.compile(r"^Model:\s"),
    re.compile(r"^Endpoint:\s"),
    re.compile(r"^Version check:"),
    re.compile(r"^Patch verification"),
    re.compile(r"^BadRequestException"),
    # ── L5: ANSI 颜色码行 (PyRIT rich console 输出) ──
    re.compile(r"^\x1b\["),  # ESC[ 开头的 ANSI 序列
    # ── L5: Native SeedDataset 回退噪音 ──
    re.compile(r"^Native SeedDataset\.from_yaml_file\(\) failed"),
    re.compile(r"^references"),
    re.compile(r"^  Extra inputs are not permitted"),
    re.compile(r"^    For further information"),
    # ── L5: PyRIT JSON 调试输出 (CrescendoAttack/DeepSeek 等 API 返回的 JSON 片段) ──
    re.compile(r'^"next_message":'),
    re.compile(r'^"rationale":'),
    re.compile(r'^"last_response_summary":'),
    re.compile(r'^"conversation_id":'),
    re.compile(r'^"achieved":'),
    re.compile(r"^}\s*$"),
    re.compile(r"^Endpoint:\s.*Elapsed time:"),
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


# ── Log-Only 模式: 匹配红队执行阶段的失败/错误回调行 ──
# 这些行是重要的审计数据 (写入信号日志), 但不属于终端实时信号
# (红队操作员只需看到成功攻击; 失败聚合计数已在 tqdm postfix 中)
# L5 对齐 NIST SP 800-92: 三层分离 — signal / log-only / noise
_LOG_ONLY_PATTERNS: list[re.Pattern[str]] = [
    # ── 红队回调失败行 (ProgressPoller._poll_loop 输出) ──
    # 注意: _is_log_only_line 先 strip 再匹配, 不需 ^\s+
    re.compile(r"^❌\s"),
    # ── 红队回调错误行 ──
    re.compile(r"^⚠\s"),
]


def _is_log_only_line(line: str) -> bool:
    """判断一行是否为 log-only 输出 (写入信号日志但不显示到终端).

    Log-only 行的特征:
      - 以 "❌" 或 "⚠" 开头的红队回调行 (失败/错误攻击结果)

    设计依据:
      - NIST SP 800-92: 三层分离 (signal / log-only / noise)
      - 红队最佳实践: 终端只展示成功攻击, 失败聚合计数在 tqdm postfix 中
    """
    stripped = line.strip()
    if not stripped:
        return False
    return any(p.search(stripped) for p in _LOG_ONLY_PATTERNS)


class NoiseFilter:
    """过滤 stdout/stderr 中的噪音行，三层路由信号/log-only/噪音。

    工作原理:
      1. 拦截 write() 调用，按行拆分
      2. 每行依次用 _is_noise_line() / _is_log_only_line() 判断
      3. 噪音行 → 写入 noise_log_file
      4. log-only 行 → 写入 signal_log_file (不显示到终端)
      5. 信号行 → 写入原始 stdout (显示给用户) + signal_log_file (持久化)

    三层路由架构 (NIST SP 800-92 + 红队最佳实践):
      - 终端通道: 信号行实时显示给用户 (stdout) — 只含成功攻击 ✅
      - log-only 通道: 失败/错误行写入信号日志 (审计可追溯, 不显示终端)
      - 噪音通道: 非核心输出写入噪音日志 (不到终端, 不到信号日志)

    注意:
      - 不完整的行 (无换行符) 留在 buffer 中等待下一次 write
      - flush() 时将 buffer 中的内容路由到对应输出
      - signal_log_path=None 时 log-only 和 signal 都不写入文件 (用于嵌套内层)
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
        r"""Write text to the filter, routing signal vs noise.

        特殊处理:
          - ``\r`` (回车): tqdm/progress 等进度条用 ``\r`` 刷新当前行,
            不含 ``\n`` 的 ``\r`` 段直接透传到原始终端, 不进 buffer。
            这防止执行阶段 30+ 分钟无输出的问题。
          - ``\n`` (换行): 正常按行拆分并路由。
        """
        if not text:
            return 0

        # 快速路径: 纯 \r 文本 (进度条更新) 直接透传
        # 避免进度条更新堆积在 buffer 中导致终端无输出
        if "\r" in text and "\n" not in text:
            try:
                self._original.write(text)
                self._original.flush()
            except Exception:
                pass  # 静默失败, 不影响程序运行
            return len(text)

        self._buffer += text
        # 按行拆分并路由
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            self._route_line(line + "\n")
        return len(text)

    def _route_line(self, line: str) -> None:
        """将一行路由到噪音文件、log-only 或信号输出 (终端 + 信号文件)。

        三层路由 (NIST SP 800-92 信号/噪音分离 + 红队最佳实践):
          1. 噪音行 → noise_log_file (不到终端, 不到信号日志)
          2. log-only 行 → signal_log_file (不到终端, 保留审计可追溯性)
          3. 信号行 → 终端 (原始 stdout) + signal_log_file

        所有写入操作均使用 try-except 静默失败, 确保即使终端/文件
        写入异常也不会中断流水线执行。
        """
        if _is_noise_line(line):
            try:
                self._noise_file.write(line)
                self._noise_file.flush()
            except Exception:
                pass
        elif _is_log_only_line(line):
            # log-only 行: 审计数据, 不直接显示终端
            if self._signal_file:
                # 有信号日志: 写入信号日志, 不显示终端
                try:
                    self._signal_file.write(line)
                    self._signal_file.flush()
                except Exception:
                    pass
            else:
                # 无信号日志 (嵌套内层): 透传到外层 NoiseFilter 处理
                # 外层 NoiseFilter 有 signal_file, 会写入信号日志但不显示终端
                try:
                    self._original.write(line)
                    self._original.flush()
                except Exception:
                    pass
        else:
            # 信号行: 写入终端 (原始 stdout)
            try:
                self._original.write(line)
                self._original.flush()
            except Exception:
                pass  # 终端写入失败时静默, 不中断程序
            # 信号行: 同时写入信号日志文件 (持久化, NIST SP 800-92)
            if self._signal_file:
                try:
                    self._signal_file.write(line)
                    self._signal_file.flush()
                except Exception:
                    pass

    def flush(self) -> None:
        """Flush buffered content to appropriate destinations."""
        if self._buffer:
            self._route_line(self._buffer)
            self._buffer = ""
        with contextlib.suppress(Exception):
            self._noise_file.flush()
        if self._signal_file:
            with contextlib.suppress(Exception):
                self._signal_file.flush()
        with contextlib.suppress(Exception):
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
    """上下文管理器: 将噪音 stdout/stderr 重定向到文件，三层路由信号/log-only/噪音。

    在此上下文内，所有 stdout/stderr 输出经过 NoiseFilter:
      - 噪音行 (Skipping scorer... 等) → noise_log_path 文件
      - log-only 行 (❌ 失败回调行) → signal_log_path 文件 (不到终端)
      - 信号行 (ASR, ✅ 成功攻击, 证据) → 原始 stdout (显示给用户) + signal_log_path (持久化)

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
