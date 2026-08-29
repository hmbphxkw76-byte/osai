"""终端输出格式化 + 分阶段报告输出。

输出设计原则 (攻击者视角):
    1. 卡片式: 关键信息用边框卡片突出, 非关键信息压缩
    2. 高信噪比: PyRIT/Alembic 等第三方 INFO 日志全部压制
    3. 攻击者关心: 目标指纹、ASR、成功 payload、报告路径
    4. 视觉层次: 卡片 > 标题 > 数据 > 分隔线
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.context import PipelineContext

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

# 尝试启用 Windows ANSI 支持
import sys as _sys

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
# 卡片输出
# ════════════════════════════════════════════════════════════════════

def _pad_line(text: str, width: int = _INNER) -> str:
    """将文本填充到指定宽度 (中文字符算 2 宽度)."""
    import unicodedata

    visual_width = sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in text)
    padding = max(0, width - visual_width)
    return text + " " * padding


def _card_line(text: str, color: str = "") -> str:
    """生成一行卡片内容 (带边框)."""
    padded = _pad_line(text)
    if color:
        return f"{_V} {color}{padded}{_C_RESET} {_V}"
    return f"{_V} {padded} {_V}"


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
    tl = _TOP_LEFT + _H * _INNER + _TOP_RIGHT
    bl = _BOTTOM_LEFT + _H * _INNER + _BOTTOM_RIGHT
    if border_color:
        tl = f"{border_color}{tl}{_C_RESET}"
        bl = f"{border_color}{bl}{_C_RESET}"

    print(tl)

    # 标题行
    tc = title_color or color or _C_BOLD
    print(_card_line(title, tc))

    # 分隔线
    sep = f"{_V} {'─' * _INNER} {_V}"
    print(sep)

    # 数据行
    for label, value in rows:
        line = f"{label}: {value}"
        print(_card_line(line, color))

    print(bl)


def print_status_card(
    phase: str,
    status: str,
    message: str,
    *,
    ok: bool | None = None,
) -> None:
    """打印状态卡片 (单行关键信息).

    Args:
        phase: 阶段名 (INIT/RECON/ARM/STRIKE/ASSESS/REPORT).
        status: 状态标签 (DONE/FAIL/INFO).
        message: 描述文字.
        ok: None=中性, True=绿色, False=红色.
    """
    if ok is True:
        tag = f"{_C_GREEN}✓{_C_RESET}"
        status_color = _C_GREEN
    elif ok is False:
        tag = f"{_C_RED}✗{_C_RESET}"
        status_color = _C_RED
    else:
        tag = "►"
        status_color = _C_CYAN

    phase_str = f"{_C_BOLD}[{phase}]{_C_RESET}"
    status_str = f"{status_color}{status}{_C_RESET}"
    print(f"  {tag} {phase_str} {status_str}  {_C_DIM}{message}{_C_RESET}")


# ════════════════════════════════════════════════════════════════════
# Banner + 阶段分隔
# ════════════════════════════════════════════════════════════════════

def print_banner() -> None:
    """打印启动 Banner."""
    banner = f"""
{_C_CYAN}{_C_BOLD}╔══════════════════════════════════════════════════════╗
║           PyRIT-Strike v2.0.0                        ║
║     Burp → Attack → Report — One-Click Pipeline      ║
╚══════════════════════════════════════════════════════╝{_C_RESET}
"""
    print(banner)


def print_phase(phase: str, description: str) -> None:
    """打印当前阶段信息 (简洁单行)."""
    print(f"\n{_C_BOLD}► [{phase}]{_C_RESET} {description}")


def print_error(message: str) -> None:
    """打印错误信息 (红色卡片)."""
    print()
    print(f"{_C_RED}{_TOP_LEFT}{_H * _INNER}{_TOP_RIGHT}{_C_RESET}")
    print(f"{_C_RED}{_V}{_C_RESET} {_C_RED}{_C_BOLD}✗ ERROR{_C_RESET}{' ' * (_INNER - 7)} {_C_RED}{_V}{_C_RESET}")
    print(f"{_C_RED}{_V}{'─' * (_INNER + 2)}{_V}{_C_RESET}")
    print(_card_line(message, _C_RED))
    print(f"{_C_RED}{_BOTTOM_LEFT}{_H * _INNER}{_BOTTOM_RIGHT}{_C_RESET}")
    print()


def print_summary(
    *,
    total_attacks: int,
    successful_attacks: int,
    overall_asr: float,
    report_path: str,
) -> None:
    """打印最终摘要 (卡片式)."""
    # ASR 色调: >=70% 绿, >=30% 黄, <30% 红
    if overall_asr >= 70:
        asr_color = _C_GREEN
    elif overall_asr >= 30:
        asr_color = _C_YELLOW
    else:
        asr_color = _C_RED

    asr_str = f"{asr_color}{overall_asr:.1f}%{_C_RESET}"

    print()
    print_card(
        "Attack Summary",
        [
            ("Total Attacks", str(total_attacks)),
            ("Successful", f"{_C_GREEN}{successful_attacks}{_C_RESET}"),
            ("Overall ASR", asr_str),
            ("Report", report_path),
        ],
        color=_C_CYAN,
    )
    print()


# ════════════════════════════════════════════════════════════════════
# ASR 表格
# ════════════════════════════════════════════════════════════════════

def format_asr_table(asr_per_technique: dict[str, float]) -> str:
    """格式化 ASR 表格."""
    lines = ["", f"{'Technique':<30} {'ASR':>10}", "─" * 42]
    for tech, asr in sorted(asr_per_technique.items(), key=lambda x: -x[1]):
        if asr >= 70:
            val = f"{_C_GREEN}{asr:>9.1f}%{_C_RESET}"
        elif asr >= 30:
            val = f"{_C_YELLOW}{asr:>9.1f}%{_C_RESET}"
        else:
            val = f"{_C_RED}{asr:>9.1f}%{_C_RESET}"
        lines.append(f"{tech:<30} {val}")
    lines.append("─" * 42)
    return "\n".join(lines)


# ════════════════════════════════════════════════════════════════════
# 分阶段报告输出 (--stage 模式)
# ════════════════════════════════════════════════════════════════════


def print_arm_report(ctx: "PipelineContext") -> None:
    """输出武器化阶段 (--stage arm) 的结果摘要 (卡片式)."""
    print()
    print_card(
        "ARM — Attack Preparation",
        [
            ("Seeds", str(len(ctx.seeds))),
            ("Techniques", ", ".join(ctx.techniques) if ctx.techniques else "(none)"),
            ("Converters", str(sum(len(v) for v in ctx.converter_map.values()))),
        ],
        color=_C_BLUE,
    )

    # 目标信息卡片
    if ctx.parsed_request:
        fp = ctx.parsed_request.target_fingerprint
        print()
        print_card(
            "Target Profile",
            [
                ("Host", ctx.parsed_request.host),
                ("Model", fp.get("burp_model_name", "Unknown")),
                ("Capabilities", fp.get("capabilities", "none")),
                ("Auth", fp.get("auth_type", "Unknown")),
            ],
            color=_C_CYAN,
        )

    # 角色分离
    obj_name = type(ctx.objective_target).__name__ if ctx.objective_target else "—"
    adv_name = type(ctx.adversarial_target).__name__ if ctx.adversarial_target else "—"
    sco_name = type(ctx.scoring_target).__name__ if ctx.scoring_target else "—"
    print()
    print_card(
        "Role Separation",
        [
            ("Objective Target", obj_name),
            ("Adversarial Target", adv_name),
            ("Scoring Target", sco_name),
        ],
        color=_C_MAGENTA,
    )

    # Converter 链详情
    if ctx.converter_map:
        print(f"\n{_C_BOLD}Converter Chains:{_C_RESET}")
        for tech, converters in ctx.converter_map.items():
            chain = " → ".join(
                type(c).__name__ if hasattr(c, "__class__") else str(c)
                for c in converters
            )
            if not chain:
                chain = "(raw, no converter)"
            print(f"  {_C_DIM}{tech}:{_C_RESET} {chain}")


def _extract_response_text(result: Any) -> str:
    """从 PyRIT AttackResult 提取响应文本 (多层 fallback).

    兼容路径:
        1. result.last_response.converted_value / .original_value (PromptRequestPiece)
        2. result.response / .response_text / .output (直接属性)
        3. result.conversation_history (对话历史中找 assistant 消息)
        4. dict 的 response/output/text 字段
    """
    # 1. last_response (PyRIT PromptRequestPiece)
    last_response = getattr(result, "last_response", None)
    if last_response:
        for attr in ("converted_value", "original_value"):
            val = getattr(last_response, attr, None)
            if val and isinstance(val, str) and len(val) > 0:
                return val

    # 2. 直接属性
    for attr in ("response", "response_text", "output"):
        val = getattr(result, attr, None)
        if val and isinstance(val, str) and len(val) > 0:
            return val

    # 3. conversation_history (找最后一条 assistant 消息)
    history = getattr(result, "conversation_history", None)
    if history:
        try:
            for msg in reversed(history):
                if hasattr(msg, "role") and msg.role == "assistant":
                    content = getattr(msg, "content", "")
                    if content and isinstance(content, str) and len(content) > 0:
                        return content
        except Exception:
            pass

    # 4. dict-like
    if isinstance(result, dict):
        for key in ("response", "output", "text", "result"):
            val = result.get(key)
            if val and isinstance(val, str) and len(val) > 0:
                return val

    return ""


def print_strike_report(ctx: "PipelineContext") -> None:
    """输出单轮攻击阶段 (--stage strike) 的结果摘要 (卡片式)."""
    total = sum(len(results) for results in ctx.attack_results.values())

    print()
    print_card(
        "STRIKE — Attack Results",
        [
            ("Techniques", str(len(ctx.attack_results))),
            ("Total Attacks", str(total)),
        ],
        color=_C_YELLOW,
    )

    if total == 0:
        print(f"\n  {_C_RED}✗ 无攻击结果 — 检查目标是否可用{_C_RESET}")
        return

    # 按技术统计
    print(f"\n{_C_BOLD}Per-Technique Results:{_C_RESET}")
    print(f"  {'Technique':<30} {'Count':>8}")
    print(f"  {'─' * 40}")
    for tech, results in sorted(ctx.attack_results.items()):
        print(f"  {tech:<30} {len(results):>8}")

    # 响应样本 (前 3 条)
    print(f"\n{_C_BOLD}Response Samples (first 3):{_C_RESET}")
    sample_count = 0
    for tech, results in ctx.attack_results.items():
        for r in results:
            if sample_count >= 3:
                break
            resp = _extract_response_text(r)[:120]
            if resp:
                print(f"  {_C_CYAN}[{tech}]{_C_RESET} {resp}...")
            else:
                print(f"  {_C_DIM}[{tech}] (无法提取响应文本){_C_RESET}")
            sample_count += 1
        if sample_count >= 3:
            break


def print_escalate_report(ctx: "PipelineContext") -> None:
    """输出升级链阶段 (--stage escalate) 的结果摘要 (卡片式)."""
    total = sum(len(results) for results in ctx.attack_results.values())

    escalation_techs = [
        k for k in ctx.attack_results
        if any(
            x in k.lower()
            for x in [
                "crescendo", "tap", "pair", "gcg", "best_of_n",
                "skeleton", "native", "rogue", "mcp", "embedding",
                "many_shot", "cair", "encoded",
            ]
        )
    ]

    print()
    print_card(
        "ESCALATE — Multi-Turn Chain",
        [
            ("Total Results", str(total)),
            ("Escalation Techs", str(len(escalation_techs))),
        ],
        color=_C_MAGENTA,
    )

    if escalation_techs:
        print(f"\n{_C_BOLD}Escalation Techniques:{_C_RESET}")
        for tech in sorted(escalation_techs):
            results = ctx.attack_results[tech]
            print(f"  {_C_MAGENTA}{tech}{_C_RESET}: {len(results)} results")
    else:
        print(f"\n  {_C_DIM}(未检测到升级技术 — 可能 ASR 已达标或升级被禁用){_C_RESET}")

    # 编排日志 (精简)
    if ctx.orchestration_log:
        strike_logs = [
            e for e in ctx.orchestration_log
            if e.get("phase") in ("strike", "escalate")
        ]
        if strike_logs:
            print(f"\n{_C_BOLD}Orchestration Log:{_C_RESET}")
            for entry in strike_logs:
                decision = entry.get("decision", "")
                reasoning = entry.get("reasoning", "")
                print(f"  {_C_DIM}[{entry['phase']}]{_C_RESET} {decision}: {reasoning}")


def print_assess_report(ctx: "PipelineContext") -> None:
    """输出评分阶段 (--stage assess) 的结果摘要 (卡片式)."""
    # ASR 色调
    if ctx.overall_asr >= 70:
        asr_color = _C_GREEN
    elif ctx.overall_asr >= 30:
        asr_color = _C_YELLOW
    else:
        asr_color = _C_RED

    rows = [
        ("Overall ASR", f"{asr_color}{ctx.overall_asr:.1f}%{_C_RESET}"),
    ]

    if ctx.wilson_ci and ctx.wilson_ci != (0.0, 0.0):
        rows.append((
            "Wilson 95% CI",
            f"[{ctx.wilson_ci[0]:.1f}%, {ctx.wilson_ci[1]:.1f}%]",
        ))

    print()
    print_card("ASSESS — Scoring Results", rows, color=_C_GREEN)

    # 按技术 ASR
    if ctx.asr_per_technique:
        print(f"\n{_C_BOLD}Per-Technique ASR:{_C_RESET}")
        print(format_asr_table(ctx.asr_per_technique))

    # 双 Judge 统计 (精简)
    if ctx.dual_judge_stats:
        stats = ctx.dual_judge_stats
        print()
        print_card(
            "Dual Judge Cross-Validation",
            [
                ("Total Scored", str(stats.get("total_scored", 0))),
                ("Dual Invoked", f"{stats.get('dual_judge_invoked', 0)} ({stats.get('dual_judge_rate', 0.0):.1f}%)"),
                ("Agreements", str(stats.get("agreements", 0))),
                ("Disagreements", str(stats.get("disagreements", 0))),
                ("Cohen's Kappa", f"{stats.get('cohens_kappa', 0.0):.3f}"),
            ],
            color=_C_BLUE,
        )
