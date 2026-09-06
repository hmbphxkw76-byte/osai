"""display_primitives.py — 终端卡片基础工具 + Banner/状态输出。

从 utils/display.py 拆分出来的基础工具模块, 包含:
    - ANSI 色彩常量 + Windows 终端兼容
    - 边框字符 + 卡片绘制原语
    - Banner / Phase / Status / Error 输出
    - ASR 可视化辅助函数

依赖: 无外部依赖, 纯 Python 标准库。
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# ── 色彩常量 (Windows Terminal / ANSI 兼容) ──
_C_RESET = "\033[0m"
_C_BOLD = "\033[1m"
_C_DIM = "\033[2m"
_C_RED = "\033[91m"
_C_GREEN = "\033[92m"
_C_YELLOW = "\033[93m"
_C_BLUE = "\033[94m"
_C_CYAN = "\033[96m"
_C_MAGENTA = "\033[95m"

# 尝试启用 Windows ANSI 支持 + UTF-8 stdout
import sys as _sys  # noqa: E402

# 强制 stdout/stderr 使用 UTF-8 (Windows GBK 终端兼容)
for _stream in (_sys.stdout, _sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

if _sys.platform == "win32":
    try:
        import ctypes

        _kernel32 = ctypes.windll.kernel32
        _kernel32.SetConsoleMode(_kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

# ── 边框字符 ──
_TOP_LEFT = "╔"
_TOP_RIGHT = "╗"
_BOTTOM_LEFT = "╚"
_BOTTOM_RIGHT = "╝"
_H = "═"
_V = "║"
_H_LIGHT = "─"

_WIDTH = 72
_INNER = _WIDTH - 4  # 内容区宽度 (减去两边 "║ " 和 " ║")


# ════════════════════════════════════════════════════════════════════
# 基础卡片工具
# ════════════════════════════════════════════════════════════════════

# 匹配 ANSI 转义序列 (\033[...m), 用于计算视觉宽度时跳过
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def _visual_width(text: str) -> int:
    """计算文本视觉宽度 (中文字符算 2, 跳过 ANSI 转义码)."""
    import unicodedata

    # 去掉 ANSI 颜色码后再计算视觉宽度
    clean = _ANSI_RE.sub("", text)
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in clean)


def _truncate_to_width(text: str, width: int = _INNER) -> str:
    """将文本截断到指定视觉宽度 (保留 ANSI 转义码)."""
    import unicodedata

    # 分离 ANSI 转义序列和纯文本
    parts = _ANSI_RE.split(text)
    result = ""
    visual_w = 0
    for part in parts:
        if not part:
            continue
        if part.startswith("\033["):
            result += part  # ANSI 码不计入宽度
            continue
        # 逐字符添加, 中文字符算 2
        for ch in part:
            cw = 2 if unicodedata.east_asian_width(ch) in "WF" else 1
            if visual_w + cw >= width:
                # 只在确有后续内容时加省略号 (留 1 宽度给 …)
                result += f"{_C_DIM}…{_C_RESET}"
                visual_w = width - 1  # … 占 1 宽度
                return result
            result += ch
            visual_w += cw
    return result


def _pad_line(text: str, width: int = _INNER) -> str:
    """将文本填充到指定宽度 (超宽时截断)."""
    vw = _visual_width(text)
    if vw > width:
        text = _truncate_to_width(text, width)
        vw = _visual_width(text)
    padding = max(0, width - vw)
    return text + " " * padding


def _card_line(text: str, color: str = "") -> str:
    """生成一行卡片内容 (带边框)."""
    padded = _pad_line(text)
    if color:
        return f"{_V} {color}{padded}{_C_RESET} {_V}"
    return f"{_V} {padded} {_V}"


def _print_card_top(color: str = "") -> None:
    """打印卡片顶边."""
    tl = _TOP_LEFT + _H * _INNER + _TOP_RIGHT
    print(f"{color}{tl}{_C_RESET}" if color else tl)


def _print_card_bottom(color: str = "") -> None:
    """打印卡片底边."""
    bl = _BOTTOM_LEFT + _H * _INNER + _BOTTOM_RIGHT
    print(f"{color}{bl}{_C_RESET}" if color else bl)


def _print_card_sep() -> None:
    """打印卡片内分隔线."""
    print(f"{_V} {_H_LIGHT * _INNER} {_V}")


def print_card(
    title: str,
    rows: list[tuple[str, str]],
    *,
    color: str = "",
    title_color: str = "",
) -> None:
    """打印卡片式信息块.

    Args:
        title: 卡片标题.
        rows: [(label, value), ...] 键值对列表.
        color: 整体色调 (边框/值).
        title_color: 标题色调.
    """
    border_color = color or title_color
    _print_card_top(border_color)
    tc = title_color or color or _C_BOLD
    print(_card_line(title, tc))
    _print_card_sep()
    for label, value in rows:
        print(_card_line(f"{label}: {value}", color))
    _print_card_bottom(border_color)


def print_section(title: str, items: list[str], *, color: str = "") -> None:
    """打印列表式卡片 (无键值对, 只有标题 + 条目列表)."""
    border_color = color or _C_BOLD
    _print_card_top(border_color)
    print(_card_line(title, border_color))
    if items:
        _print_card_sep()
    for item in items:
        print(_card_line(item, color))
    _print_card_bottom(border_color)


# ════════════════════════════════════════════════════════════════════
# 状态 + 阶段输出
# ════════════════════════════════════════════════════════════════════


def print_banner() -> None:
    """打印启动 Banner."""
    print(f"""
{_C_CYAN}{_C_BOLD}╔══════════════════════════════════════════════════════╗
║           PyRIT-Strike v2.0.0                        ║
║     Burp → Attack → Report — One-Click Pipeline      ║
╚══════════════════════════════════════════════════════╝{_C_RESET}
""")


def print_phase(phase: str, description: str) -> None:
    """打印阶段标题 (v57: 带阶段分隔条的醒目标题)."""
    phase_colors = {
        "RECON": _C_CYAN,
        "ARM": _C_BLUE,
        "STRIKE": _C_YELLOW,
        "ESCALATE": _C_MAGENTA,
        "ASSESS": _C_GREEN,
        "REPORT": _C_CYAN,
        "INIT": _C_DIM,
    }
    color = phase_colors.get(phase, _C_BOLD)
    sep = "═" * 60
    print()
    print(f"  {color}{sep}{_C_RESET}")
    print(f"  {color}► [{phase}] {_C_RESET}{_C_BOLD}{description}{_C_RESET}")
    print(f"  {color}{sep}{_C_RESET}")


def print_status(
    phase: str,
    status: str,
    message: str,
    *,
    ok: bool | None = None,
) -> None:
    """打印状态行 (单行, 带图标).

    Args:
        phase: 阶段名.
        status: 状态标签.
        message: 描述.
        ok: None=中性, True=绿色, False=红色.
    """
    if ok is True:
        tag = f"{_C_GREEN}✓{_C_RESET}"
        sc = _C_GREEN
    elif ok is False:
        tag = f"{_C_RED}✗{_C_RESET}"
        sc = _C_RED
    else:
        tag = "►"
        sc = _C_CYAN
    print(f"  {tag} {_C_BOLD}[{phase}]{_C_RESET} {sc}{status}{_C_RESET}  {_C_DIM}{message}{_C_RESET}")


def print_error(message: str) -> None:
    """打印错误卡片."""
    print()
    _print_card_top(_C_RED)
    print(_card_line(f"{_C_RED}{_C_BOLD}✗ ERROR{_C_RESET}", _C_RED))
    _print_card_sep()
    print(_card_line(message, _C_RED))
    _print_card_bottom(_C_RED)
    print()


def _asr_color(asr: float) -> str:
    """ASR 值对应颜色 — 攻击者视角 (高 ASR = 红色危险).

    红队最佳实践: 攻击者视角中高 ASR 是 "好结果" (攻击成功),
    但从安全角度看是 "危险" (目标被攻破), 统一用红色突出。
    低 ASR = 绿色 (目标防御有效), 中间 = 黄色/青色。
    """
    if asr >= 70:
        return _C_RED
    if asr >= 40:
        return _C_YELLOW
    if asr >= 15:
        return _C_CYAN
    return _C_GREEN


def _format_asr(asr: float) -> str:
    """格式化 ASR 值 (带颜色, 攻击者视角)."""
    c = _asr_color(asr)
    return f"{c}{asr:.1f}%{_C_RESET}"


def _asr_bar(asr: float, width: int = 20) -> str:
    """ASR 可视化进度条 (攻击者视角).

    格式: ████████░░░░░░░░░░░░ 40.0%
    颜色随 ASR 值变化 (高=红, 低=绿)。
    """
    c = _asr_color(asr)
    filled = int(asr / 100 * width)
    bar = "█" * filled + "░" * (width - filled)
    return f"{c}{bar} {asr:>5.1f}%{_C_RESET}"


def _get_converter_chain_names(converters: list[Any], *, max_display: int = 5) -> str:
    """获取 converter 链名称 (独立路径编号).

    L5 v39: 将 converter 列表格式化为可读字符串，带编号路径。
    提升自 display_stages → primitives，消除 display_params 的跨模块私有导入。

    Args:
        converters: Converter 实例列表.
        max_display: 最大显示数量，超出时显示 "+N more".

    Returns:
        格式化的 converter 链描述字符串.
    """
    if not converters:
        return "(raw, no converters)"
    if len(converters) == 1:
        c = converters[0]
        return type(c).__name__ if hasattr(c, "__class__") else str(c)
    display_count = min(len(converters), max_display)
    parts = []
    for i, c in enumerate(converters[:display_count]):
        name = type(c).__name__ if hasattr(c, "__class__") else str(c)
        parts.append(f"[{i + 1}] {name}")
    result = " | ".join(parts)
    remaining = len(converters) - max_display
    if remaining > 0:
        result += f" {_C_DIM}... (+{remaining} more){_C_RESET}"
    return result
