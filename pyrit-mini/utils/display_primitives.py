"""display_primitives.py —  + Banner/

imports utils/display.py , :
    - ANSI  + Windows 
    -  + 
    - Banner / Phase / Status / Error 
    - ASR 

: ,  Python 
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# ==  (Windows Terminal / ANSI ) ==
_C_RESET = "\033[0m"
_C_BOLD = "\033[1m"
_C_DIM = "\033[2m"
_C_RED = "\033[91m"
_C_GREEN = "\033[92m"
_C_YELLOW = "\033[93m"
_C_BLUE = "\033[94m"
_C_CYAN = "\033[96m"
_C_MAGENTA = "\033[95m"

#  Windows ANSI  + UTF-8 stdout
import sys as _sys  # noqa: E402

#  stdout/stderr  UTF-8 (Windows GBK )
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

# ==  ==
_TOP_LEFT = "╔"
_TOP_RIGHT = "╗"
_BOTTOM_LEFT = "╚"
_BOTTOM_RIGHT = "╝"
_H = "="
_V = "║"
_H_LIGHT = "="

_WIDTH = 72
_INNER = _WIDTH - 4  #  ( "║ "  " ║")


# ====================================================================
# 
# ====================================================================

#  ANSI  (\033[...m), Skip
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def _visual_width(text: str) -> int:
    """ ( 2, Skip ANSI )."""
    import unicodedata

    #  ANSI 
    clean = _ANSI_RE.sub("", text)
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in clean)


def _truncate_to_width(text: str, width: int = _INNER) -> str:
    """ ( ANSI )."""
    import unicodedata

    #  ANSI 
    parts = _ANSI_RE.split(text)
    result = ""
    visual_w = 0
    for part in parts:
        if not part:
            continue
        if part.startswith("\033["):
            result += part  # ANSI 
            continue
        # ,  2
        for ch in part:
            cw = 2 if unicodedata.east_asian_width(ch) in "WF" else 1
            if visual_w + cw >= width:
                #  ( 1  …)
                result += f"{_C_DIM}…{_C_RESET}"
                visual_w = width - 1  # …  1 
                return result
            result += ch
            visual_w += cw
    return result


def _pad_line(text: str, width: int = _INNER) -> str:
    """ ()."""
    vw = _visual_width(text)
    if vw > width:
        text = _truncate_to_width(text, width)
        vw = _visual_width(text)
    padding = max(0, width - vw)
    return text + " " * padding


def _card_line(text: str, color: str = "") -> str:
    """ ()."""
    padded = _pad_line(text)
    if color:
        return f"{_V} {color}{padded}{_C_RESET} {_V}"
    return f"{_V} {padded} {_V}"


def _print_card_top(color: str = "") -> None:
    """."""
    tl = _TOP_LEFT + _H * _INNER + _TOP_RIGHT
    print(f"{color}{tl}{_C_RESET}" if color else tl)


def _print_card_bottom(color: str = "") -> None:
    """."""
    bl = _BOTTOM_LEFT + _H * _INNER + _BOTTOM_RIGHT
    print(f"{color}{bl}{_C_RESET}" if color else bl)


def _print_card_sep() -> None:
    """."""
    print(f"{_V} {_H_LIGHT * _INNER} {_V}")


def print_card(
    title: str,
    rows: list[tuple[str, str]],
    *,
    color: str = "",
    title_color: str = "",
) -> None:
    """.

    Args:
        title: .
        rows: [(label, value), ...] .
        color:  (/).
        title_color: .
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
    """ (,  + )."""
    border_color = color or _C_BOLD
    _print_card_top(border_color)
    print(_card_line(title, border_color))
    if items:
        _print_card_sep()
    for item in items:
        print(_card_line(item, color))
    _print_card_bottom(border_color)


# ====================================================================
#  + 
# ====================================================================


def print_banner() -> None:
    """ Banner."""
    print(f"""
{_C_CYAN}{_C_BOLD}╔======================================================╗
║           PyRIT-Strike v2.0.0                        ║
║     Burp → Attack → Report — One-Click Pipeline      ║
╚======================================================╝{_C_RESET}
""")


def print_phase(phase: str, description: str) -> None:
    """ (v57: )."""
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
    sep = "=" * 60
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
    """ (, ).

    Args:
        phase: .
        status: .
        message: .
        ok: None=, True=, False=.
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
    """."""
    print()
    _print_card_top(_C_RED)
    print(_card_line(f"{_C_RED}{_C_BOLD}✗ ERROR{_C_RESET}", _C_RED))
    _print_card_sep()
    print(_card_line(message, _C_RED))
    _print_card_bottom(_C_RED)
    print()


def _asr_color(asr: float) -> str:
    """ASR  —  ( ASR = ).

    :  ASR  "" (),
    imports "" (), 
     ASR =  (),  = /
    """
    if asr >= 70:
        return _C_RED
    if asr >= 40:
        return _C_YELLOW
    if asr >= 15:
        return _C_CYAN
    return _C_GREEN


def _format_asr(asr: float) -> str:
    """ ASR  (, )."""
    c = _asr_color(asr)
    return f"{c}{asr:.1f}%{_C_RESET}"


def _asr_bar(asr: float, width: int = 20) -> str:
    """ASR  ().

    : ████████░░░░░░░░░░░░ 40.0%
     ASR  (=, =)
    """
    c = _asr_color(asr)
    filled = int(asr / 100 * width)
    bar = "█" * filled + "░" * (width - filled)
    return f"{c}{bar} {asr:>5.1f}%{_C_RESET}"


def _get_converter_chain_names(converters: list[Any], *, max_display: int = 5) -> str:
    """ converter  ().

    L5 v39:  converter 
     display_stages → primitives display_params from

    Args:
        converters: Converter .
        max_display:  "+N more".

    Returns:
         converter .
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
