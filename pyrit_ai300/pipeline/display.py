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
