# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""流水线展示工具 — 头部信息 + 尾部汇总 + 统一卡片体系。.

对齐 PyRIT 官方 output 模块最佳实践 (1.0.1):
  - Format vs Sink 分离: 展示逻辑与执行逻辑完全分离
  - 三层卡片体系 (F4 统一风格):
    Layer 1: stage_header (═══) — 阶段标题
    Layer 2: core_card (╔═╗)  — 核心决策卡片 (每阶段 1-2 个)
    Layer 3: info_box (┌─└)   — 详情信息盒
  - handoff_banner (★) — 阶段间传递 (简化版)
  - 安全调用: 所有展示函数 catch 异常, 不影响 pipeline 执行

设计原则 (R-010 对齐):
  - PyRIT 原生优先: 使用原生 output_attack_async / output_scenario_async
  - 自研展示层: 仅在原生 output 模块之外提供流水线级卡片展示
  - 统一卡片宽度 _W=68, CJK 宽度对齐

> **日期**: 2026-8-2
> **更新记录**:
>   2026-8-4 — F4: 统一三层卡片风格 (core_card + info_box + stage_header)
>   2026-8-2 — O1: 新增统一卡片函数 (info_box / decision_card / handoff_banner / asr_bar)
"""

from __future__ import annotations

import contextlib
import os
from typing import Any

from pipeline.context import PipelineContext

# ── 统一卡片宽度 (与 pyrit_ai300 对齐) ──
_W = 68

# ── 终端编码说明 (R-012) ──
# main.py 在所有 import 之前已调用:
#   sys.stdout.reconfigure(encoding="utf-8", errors="replace",
#                          write_through=True, line_buffering=True)
# 此处不再重复 reconfigure, 避免:
#   1. 覆盖 errors="replace" 为默认 "strict" → UnicodeEncodeError
#   2. 覆盖 write_through/line_buffering → 缓冲模式回退 → 终端无输出


def print_pipeline_header(ctx: PipelineContext) -> None:
    """打印流水线头部信息 (目标模型 + 场景 + 日志路径)。.

    B2 修复: 对齐参考日志格式, 增加 URL/端点/开始时间/Verbose 字段。
    """
    output_mgr = ctx.output_manager
    print()
    print("=" * 70)
    print("  PyRIT 端到端全自动 AI 红队框架")
    print("=" * 70)

    # B2: 目标 URL 和端点
    target_url = os.getenv("TARGET_BASE_URL", os.getenv("OPENAI_CHAT_ENDPOINT", "N/A"))
    target_endpoint = os.getenv("TARGET_ENDPOINT", target_url)
    model_name = getattr(ctx.args, "model", None) or os.getenv("OPENAI_CHAT_MODEL", "N/A")
    scorer_endpoint = os.getenv("OBJECTIVE_SCORER_CHAT_ENDPOINT", os.getenv("AZURE_CONTENT_SAFETY_API_ENDPOINT", "N/A"))
    scorer_model = os.getenv(
        "OBJECTIVE_SCORER_CHAT_MODEL",
        os.getenv("AZURE_CONTENT_SAFETY_API_ENDPOINT", "N/A"),
    )

    # 对抗模型 (三方分离原则: 评分 ≠ 对抗 ≠ 目标)
    adversarial_endpoint = os.getenv("ADVERSARIAL_CHAT_ENDPOINT", "N/A")
    adversarial_model = os.getenv("ADVERSARIAL_CHAT_MODEL", "N/A")

    print(f"  目标 URL: {target_url}")
    print(f"  目标端点: {target_endpoint}")
    print(f"  目标模型: {model_name}")
    if scorer_endpoint != "N/A":
        print(f"  评分器端点: {scorer_endpoint}")
    print(f"  评分器模型: {scorer_model}")
    if adversarial_endpoint != "N/A":
        print(f"  对抗模型端点: {adversarial_endpoint}")
    print(f"  对抗模型: {adversarial_model}")
    print(f"  开始时间: {ctx.start_time.isoformat() if ctx.start_time else 'N/A'}")
    if output_mgr:
        print(f"  日志文件: {output_mgr.log_path}")
        print(f"  噪音日志: {output_mgr.noise_log_path}")
    verbose = getattr(ctx.args, "verbose", False)
    print(f"  Verbose: {'开启 (成功攻击详情输出)' if verbose else '关闭'}")
    print(f"  场景: {getattr(ctx.args, 'scenario', 'text_adaptive')}")
    if getattr(ctx.args, "exhaustive", False):
        print("  模式: EXHAUSTIVE (全技术评估)")
    print()


def print_pipeline_footer(ctx: PipelineContext) -> None:
    """Print pipeline footer summary.

    B2 修复: 对齐参考日志格式, 增加总用时/报告路径/证据路径字段。
    """
    print("\n" + "=" * 70)
    print("  Pipeline 完成")
    print("=" * 70)

    # B2: 总用时
    if ctx.start_time and ctx.end_time:
        duration = ctx.end_time - ctx.start_time
        print(f"  总用时: {duration}")
    elif ctx.start_time:
        from datetime import datetime as _dt
        duration = _dt.now() - ctx.start_time
        print(f"  总用时: {duration}")

    if ctx.result:
        total = sum(len(v) for v in ctx.result.attack_results.values())
        success = sum(
            1
            for v in ctx.result.attack_results.values()
            for ar in v
            if ar.outcome and ar.outcome.name == "SUCCESS"
        )
        print(f"  执行结果: {success}/{total} 成功")

    # F2 修复: 数据源和攻击计划 (对齐参考日志格式)
    if ctx.sorted_datasets:
        print(f"  数据源: {len(ctx.sorted_datasets)} 批次")
    if ctx.scenario and hasattr(ctx.scenario, "atomic_attack_count"):
        print(f"  攻击计划: {ctx.scenario.atomic_attack_count} 个")

    if ctx.overall_asr is not None:
        print(f"  总体 ASR: {ctx.overall_asr}%")

    # B2: 报告和证据路径
    l5_report = ctx.metadata.get("l5_report", {})
    if l5_report:
        if l5_report.get("report_path"):
            print(f"  报告: {l5_report['report_path']}")
        if l5_report.get("evidence_archive"):
            print(f"  证据: {l5_report['evidence_archive']}")
    elif ctx.output_manager:
        report_p = ctx.output_manager.report_path("md")
        evidence_p = ctx.output_manager.evidence_zip_path
        if report_p.exists():
            print(f"  报告: {report_p}")
        if evidence_p.exists():
            print(f"  证据: {evidence_p}")

    if ctx.output_manager:
        print(f"  日志: {ctx.output_manager.log_path}")
        print(f"  噪音日志: {ctx.output_manager.noise_log_path}")


# ============================================================
# 统一卡片体系 — 对齐 PyRIT 官方 output 模块最佳实践
# ============================================================

# ── CJK 宽度辅助 ──


def cjk_width(s: str) -> int:
    """近似计算字符串显示宽度 (CJK 字符算 2 列)."""
    return sum(2 if ord(c) > 0x7F else 1 for c in s)


def pad_right(s: str, width: int) -> str:
    """将字符串填充到指定显示宽度."""
    w = cjk_width(s)
    return s + " " * max(0, width - w)


def trunc(text: str, limit: int = 60) -> str:
    """截断文本，添加省略号."""
    text = text.replace("\n", " ").strip()
    return text[:limit - 3] + "..." if len(text) > limit else text


# ── ① 单线信息盒 (info_box) — 普通信息展示 ──


def info_box(title: str, lines: list[str]) -> None:
    """打印单线信息盒子.

    用途: 阶段内部的统计信息、配置摘要等普通信息。
    对齐 pyrit_ai300 pipeline.display.info_box
    """
    try:
        print(f"\n  ┌─ {title} {'─' * max(1, _W - len(title) - 4)}┐")
        for line in lines:
            print(f"  │ {line}")
        print(f"  └{'─' * _W}┘")
    except Exception:
        pass


# ── ② 核心卡片 (core_card) — Layer 2: 每阶段 1-2 个关键决策 ──


def core_card(
    title: str,
    sections: list[dict[str, Any]] | None = None,
) -> None:
    """Layer 2: 核心卡片 (╔═╗) — 每阶段 1-2 个，展示关键决策.

    统一风格 (F4):
      ╔══════════════════════════════════════════════════════════╗
      ║  Title                                                    ║
      ╟────────────────────────────────────────────────────────────╢
      ║  [Section] content                                        ║
      ║           continuation                                    ║
      ║                                                            ║
      ║  [Section] content                                        ║
      ╚══════════════════════════════════════════════════════════╝

    Args:
        title: 卡片标题
        sections: [{"label": "载荷", "lines": ["12 数据集", ...]}]
    """
    try:
        inner_w = _W - 2
        print()
        print("  ╔" + "═" * inner_w + "╗")
        print(f"  ║  {title}")
        if sections:
            print("  ╟" + "─" * inner_w + "╢")
            for i, section in enumerate(sections):
                label = section.get("label", "")
                lines = section.get("lines", [])
                if label:
                    print(f"  ║  [{label}] {lines[0] if lines else ''}")
                    for line in lines[1:]:
                        print(f"  ║{'':>{len(label) + 5}}{line}")
                else:
                    for line in lines:
                        print(f"  ║  {line}")
                if i < len(sections) - 1:
                    print("  ║")
        print("  ╚" + "═" * inner_w + "╝")
    except Exception:
        pass


# ── ②b 双线决策卡片 (decision_card) — 兼容旧接口 ──
def decision_card(
    title: str,
    subtitle: str = "",
    fields: dict[str, str] | None = None,
    sub_sections: list[dict[str, Any]] | None = None,
) -> None:
    """打印双线决策卡片 (┏━┃ ┗).

    用途: 技术池矩阵中每个技术的卡片，关键决策点的展示。
    对齐 pyrit_ai300 的 ┏━ 双线框风格。

    Args:
        title: 卡片标题 (如技术名)
        subtitle: 副标题 (如 "ASR: 62% (Tier A) | 模式: 多轮迭代")
        fields: 字段字典 (如 {"学术先验": "62%", "经验数据": "无"})
        sub_sections: 子区域列表 [{"header": "...", "lines": [...]}]
    """
    try:
        print()
        print("  ┏" + "━" * _W)
        print(f"  ┃  ◆ {title}")
        if subtitle:
            print(f"  ┃    {subtitle}")
        print("  ┃")

        if fields:
            for key, value in fields.items():
                print(f"  ┃    {key}: {value}")
            print("  ┃")

        if sub_sections:
            for section in sub_sections:
                header = section.get("header", "")
                section_lines = section.get("lines", [])
                hdr_dashes = max(1, _W - 6 - cjk_width(header) - 2)
                print(f"  ┃    ┌─ {header} {'─' * hdr_dashes}┐")
                for line in section_lines:
                    print(f"  ┃    │ {line}")
                print(f"  ┃    └{'─' * max(0, _W - 3)}┘")

        print("  ┗" + "━" * _W)
    except Exception:
        pass


# ── ③ ★ 突出传递 Banner (handoff_banner) — 阶段间关键数据传递 ──


def handoff_banner(stage_from: int, stage_to: int, title: str, lines: list[str]) -> None:
    """打印 ★ 突出传递 Banner.

    用途: 阶段间关键数据传递的突出展示。
    对齐 pyrit_ai300 的 ╔═★═╗ 双线粗框 Banner。

    Args:
        stage_from: 来源阶段编号
        stage_to: 目标阶段编号
        title: Banner 标题 (如 "传递到场景初始化 — 决定后续攻击成功率")
        lines: 传递字段列表 (如 ["★ 策略模式: academic → 影响 Tier 执行顺序", ...])
    """
    try:
        print()
        print("  ╔" + "═" * _W + "╗")
        print()
        print(f"       ★  {title}  ★")
        print()
        print("  ╚" + "═" * _W + "╝")

        handoff_hdr = f"传递到 Stage {stage_to} (★ 关键决策)"
        handoff_dashes = max(1, _W - 2 - cjk_width(handoff_hdr) - 2)
        print(f"\n  ┌─ {handoff_hdr} {'─' * handoff_dashes}┐")
        for line in lines:
            print(f"  │ {line}")
        print(f"  └{'─' * _W}┘")
    except Exception:
        pass


# ── ④ ASR 进度条 ──


def asr_bar(asr: float, width: int = 20) -> str:
    """生成 ASR 进度条字符串.

    Args:
        asr: ASR 百分比 (0-100)
        width: 进度条宽度

    Returns:
        如 "██████████░░░░░░░░░░ 50%"
    """
    try:
        filled = int(asr / 100 * width)
        bar = "█" * filled + "░" * (width - filled)
        return f"{bar} {asr:.0f}%"
    except Exception:
        return f"{'░' * width} {asr:.0f}%"


# ── ⑤ 阶段标题 ──


def stage_header(num: int, total: int, title: str, subtitle: str = "") -> None:
    """打印统一阶段标题.

    对齐 pyrit_ai300 pipeline.display.stage_header
    """
    try:
        label = f"  阶段 {num}/{total}: {title}"
        if subtitle:
            label += f" — {subtitle}"
        print(f"\n{'=' * 70}")
        print(label)
        print("=" * 70)
    except Exception:
        pass


# ── ⑥ 阶段间衔接行 ──


def handoff_line(stage_from: int, stage_to: int, msg: str) -> None:
    """阶段间衔接行 (简洁版).

    用于阶段间快速传递信息的单行摘要。
    与 handoff_banner 的区别: handoff_banner 是突出展示, handoff_line 是简洁摘要。
    """
    with contextlib.suppress(Exception):
        print(f"\n  → 传递到 Stage {stage_to}: {msg}")
