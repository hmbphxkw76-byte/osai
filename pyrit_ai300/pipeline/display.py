"""
Pipeline Display — 阶段展示辅助
================================

提供阶段标题和信息盒子的统一格式化输出。
所有阶段模块共享这些展示函数，确保输出风格一致。
"""

_BAR = "═" * 63


def stage_header(num: int, title: str, subtitle: str = "") -> None:
    """打印阶段标题"""
    label = f"  阶段 {num}/7: {title}"
    if subtitle:
        label += f" — {subtitle}"
    print(f"\n{_BAR}")
    print(label)
    print(_BAR)


def info_box(title: str, lines: list[str]) -> None:
    """打印信息盒子"""
    print(f"\n  ┌─ {title} {'─' * max(1, 50 - len(title))}┐")
    for line in lines:
        print(f"  │ {line}")
    print(f"  └{'─' * 60}┘")


def banner(text: str) -> None:
    """打印横幅"""
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)


# ============================================================
# 统一辅助函数 (P3-C: 从各阶段模块提取到此处统一导出)
# ============================================================


def cjk_width(s: str) -> int:
    """近似计算字符串显示宽度（CJK 字符算 2 列）"""
    return sum(2 if ord(c) > 0x7F else 1 for c in s)


def pad_right(s: str, width: int) -> str:
    """将字符串填充到指定显示宽度"""
    w = cjk_width(s)
    return s + " " * max(0, width - w)


def trunc(text: str, limit: int = 60) -> str:
    """截断文本，添加省略号"""
    text = text.replace("\n", " ").strip()
    return text[:limit - 3] + "..." if len(text) > limit else text


def handoff_line(stage_num: int, target_stage: int, msg: str) -> None:
    """P2-A: 阶段间衔接行"""
    print(f"\n  → 传递到 Stage {target_stage}: {msg}")
