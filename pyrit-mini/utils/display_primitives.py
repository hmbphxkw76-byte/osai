"""display_primitives.py - ANSI colors + Banner/Phase/Status cards.

Imports from utils/display.py, provides:
    - ANSI color codes + Windows terminal setup
    - Card drawing utilities (top/sep/bottom/line)
    - Banner / Phase / Status / Error printing
    - ASR bar and formatting

Note: No Chinese characters, pure Python strings only.
"""
from __future__ import annotations

import logging
import re
import sys as _sys  # noqa: E402
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# == ANSI color codes (Windows Terminal / Linux / macOS) ==
_C_RESET = "\033[0m"
_C_BOLD = "\033[1m"
_C_DIM = "\033[2m"
_C_RED = "\033[91m"
_C_GREEN = "\033[92m"
_C_YELLOW = "\033[93m"
_C_BLUE = "\033[94m"
_C_CYAN = "\033[96m"
_C_MAGENTA = "\033[95m"

# Windows ANSI + UTF-8 stdout
# Fix stdout/stderr encoding (Windows GBK -> UTF-8)
for _stream in (_sys.stdout, _sys.stderr):
    try:
        if hasattr(_stream, "reconfigure"):
            _stream.reconfigure(encoding="utf-8")
    except Exception:
        pass

if _sys.platform == "win32":
    try:
        import ctypes

        _kernel32 = ctypes.windll.kernel32
        _kernel32.SetConsoleMode(_kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

# == Card drawing constants ==
_TOP_LEFT = "+"
_TOP_RIGHT = "+"
_BOTTOM_LEFT = "+"
_BOTTOM_RIGHT = "+"
_H = "="
_V = "||"
_H_LIGHT = "="

_WIDTH = 72
_INNER = _WIDTH - 4  # Account for "|| " and " ||"

# ====================================================================
# Helper functions
# ====================================================================

# ANSI escape regex (\033[...m), skip in width calculation
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")

def _visual_width(text: str) -> int:
    """Calculate visual width of text (handle wide chars + ANSI)."""
    import unicodedata

    # Strip ANSI codes for width calculation
    clean = _ANSI_RE.sub("", text)
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in clean)

def _truncate_to_width(text: str, width: int = _INNER) -> str:
    """Truncate text to visual width (handle ANSI codes)."""
    import unicodedata

    # Split by ANSI codes
    parts = _ANSI_RE.split(text)
    result = ""
    visual_w = 0
    for part in parts:
        if not part:
            continue
        if part.startswith("\033["):
            result += part
            continue
        # Normal text, count width
        for ch in part:
            cw = 2 if unicodedata.east_asian_width(ch) in "WF" else 1
            if visual_w + cw >= width:
                result += f"{_C_DIM}...{_C_RESET}"
                visual_w = width - 1  # Reserve space for ...
                return result
            result += ch
            visual_w += cw
    return result

def _pad_line(text: str, width: int = _INNER) -> str:
    """Pad text to visual width (right-pad with spaces)."""
    vw = _visual_width(text)
    if vw > width:
        return text  # No padding if already too wide
    padding = max(0, width - vw)
    return text + " " * padding

def _card_line(text: str, color: str = "") -> str:
    """Format a card line with padding and borders."""
    padded = _pad_line(text)
    if color:
        return f"{color}{_V} {padded} {_V}{_C_RESET}"
    return f"{_V} {padded} {_V}"

def _print_card_top(color: str = "") -> None:
    """Print card top border."""
    tl = _TOP_LEFT + _H * _INNER + _TOP_RIGHT
    print(f"{color}{tl}{_C_RESET}" if color else tl)

def _print_card_bottom(color: str = "") -> None:
    """Print card bottom border."""
    bl = _BOTTOM_LEFT + _H * _INNER + _BOTTOM_RIGHT
    print(f"{color}{bl}{_C_RESET}" if color else bl)

def _print_card_sep() -> None:
    """Print card separator line."""
    print(f"{_V} {_H_LIGHT * _INNER} {_V}")

def print_card(
    title: str,
    rows: list[tuple[str, str]],
    *,
    color: str = "",
    title_color: str = "",
) -> None:
    """Print a card with title and rows.

    Args:
        title: Card title.
        rows: [(label, value), ...] rows to display.
        color: Border color (optional).
        title_color: Title color (overrides color).
    """
    border_color = color or title_color
    _print_card_top(border_color)
    tc = title_color or color or _C_BOLD
    print(_card_line(title, tc))
    _print_card_sep()
    for label, value in rows:
        line = f"{label}: {value}"
        print(_card_line(line))
    _print_card_bottom(border_color)

def print_section(title: str, items: list[str], *, color: str = "") -> None:
    """Print a section with title and items."""
    border_color = color or _C_BOLD
    _print_card_top(border_color)
    print(_card_line(title, border_color))
    if items:
        _print_card_sep()
        for item in items:
            print(_card_line(item))
    _print_card_bottom(border_color)

# ====================================================================
# Display functions
# ====================================================================

def print_banner() -> None:
    """Print PyRIT-Strike banner."""
    print()
    print(f"{_C_CYAN}{_C_BOLD}{_TOP_LEFT}{'=' * _INNER}{_TOP_RIGHT}")
    print(f"{_V}           PyRIT-Strike v2.0.0                        {_V}")
    print(f"{_V}     Burp -> Attack -> Report - One-Click Pipeline      {_V}")
    print(f"{_BOTTOM_LEFT}{'=' * _INNER}{_BOTTOM_RIGHT}{_C_RESET}")
    print()

def print_phase(phase: str, description: str) -> None:
    """Print phase header."""
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
    print(f"  {color}> [{phase}] {_C_RESET}{_C_BOLD}{description}{_C_RESET}")
    print(f"  {color}{sep}{_C_RESET}")

def print_status(
    phase: str,
    status: str,
    message: str,
    *,
    ok: bool | None = None,
) -> None:
    """Print status line (colored by ok flag).

    Args:
        phase: Phase name.
        status: Status message.
        message: Detail message.
        ok: None=info, True=green check, False=red cross.
    """
    if ok is True:
        tag = f"{_C_GREEN}[OK]{_C_RESET}"
        sc = _C_GREEN
    elif ok is False:
        tag = f"{_C_RED}[FAIL]{_C_RESET}"
        sc = _C_RED
    else:
        tag = f"{_C_CYAN}[*]{_C_RESET}"
        sc = _C_CYAN
    print(f"  {tag} {_C_BOLD}[{phase}]{_C_RESET} {sc}{status}{_C_RESET}  {_C_DIM}{message}{_C_RESET}")

def print_error(message: str) -> None:
    """Print error card."""
    print()
    _print_card_top(_C_RED)
    print(_card_line(f"{_C_RED}{_C_BOLD}[FAIL] ERROR{_C_RESET}", _C_RED))
    _print_card_sep()
    print(_card_line(message, _C_RED))
    _print_card_bottom(_C_RED)
    print()

def _asr_color(asr: float) -> str:
    """Get ASR color based on value.

    Thresholds: red (>=70%), yellow (>=40%), cyan (>=15%), green (<15%).
    """
    if asr >= 70:
        return _C_RED
    if asr >= 40:
        return _C_YELLOW
    if asr >= 15:
        return _C_CYAN
    return _C_GREEN

def _format_asr(asr: float) -> str:
    """Format ASR value as colored string."""
    c = _asr_color(asr)
    return f"{c}{asr:.1f}%{_C_RESET}"

def _asr_bar(asr: float, width: int = 20) -> str:
    """Create ASR bar string.

    Format: #################### 40.0%
    Uses # for filled, : for empty.
    """
    c = _asr_color(asr)
    filled = int(asr / 100 * width)
    bar = "#" * filled + "-" * (width - filled)
    return f"{c}{bar} {asr:>5.1f}%{_C_RESET}"

def _get_converter_chain_names(converters: list[Any], *, max_display: int = 5) -> str:
    """Get display string for converter chain.

    L5 v39: Extract converter names for display.

    Args:
        converters: Converter list.
        max_display: Max to show before truncating with "+N more".

    Returns:
        Formatted converter chain string.
    """
    if not converters:
        return ""
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
        result += f" ... (+{remaining})"
    return result
