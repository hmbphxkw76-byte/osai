# -*- coding: utf-8 -*-
"""
AI-300 Framework - Execution Display
执行展示器：终端实时展示 payload 分类、执行计划、攻击进度、结果汇总

功能：
1. 终端实时展示（Rich 格式化横幅、表格、面板）
2. 从 PyRIT 资深架构师角度提供清晰简洁的状态信息
3. 无 Rich 时自动降级为纯文本输出

PyRIT 0.14.0 兼容
"""

from __future__ import annotations

import sys
import os
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

logger = logging.getLogger(__name__)

# Rich imports (optional, fallback to plain text)
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    logger.warning("Rich library not available, falling back to plain text output")


# ──────────────────────────────────────────────────────────────────────────────
# Category display metadata
# ──────────────────────────────────────────────────────────────────────────────
CATEGORY_META: Dict[str, Dict[str, str]] = {
    "direct_short": {
        "label": "Direct Short",
        "icon": "[>>]",
        "color": "cyan",
        "desc": "直接注入短文本 (<100字符)",
    },
    "role_play": {
        "label": "Role Play",
        "icon": "[ACT]",
        "color": "magenta",
        "desc": "角色扮演类 (DAN/Jailbreak)",
    },
    "multilingual": {
        "label": "Multilingual",
        "icon": "[INT]",
        "color": "yellow",
        "desc": "多语言载荷 (非ASCII>30%)",
    },
    "encoded": {
        "label": "Encoded",
        "icon": "[ENC]",
        "color": "green",
        "desc": "已编码载荷 (Base64/ROT13)",
    },
    "long_context": {
        "label": "Long Context",
        "icon": "[TXT]",
        "color": "blue",
        "desc": "长文本载荷 (>200字符)",
    },
}

STRATEGY_META: Dict[str, Dict[str, str]] = {
    "single_turn": {
        "label": "Single-Turn",
        "icon": "[1]",
        "desc": "单轮攻击 (PromptSendingAttack)",
    },
    "multi_turn": {
        "label": "Multi-Turn",
        "icon": "[N]",
        "desc": "多轮攻击 (MultiTurnOrchestrator)",
    },
    "tree_attack": {
        "label": "Tree Attack",
        "icon": "[*]",
        "desc": "树状攻击 (TreeAttackOrchestrator)",
    },
}

# Scorer 显示元数据（直接复用 PyRIT 类名，不造轮子）
SCORER_META: Dict[str, Dict[str, str]] = {
    "refusal": {
        "label": "SelfAskRefusalScorer",
        "icon": "[R]",
        "color": "red",
        "desc": "拒绝检测（判断模型是否拒绝回答）",
    },
    "true_false": {
        "label": "SelfAskTrueFalseScorer",
        "icon": "[TF]",
        "color": "yellow",
        "desc": "真假判断（自定义评分标准）",
    },
    "substring": {
        "label": "SubStringScorer",
        "icon": "[SS]",
        "color": "green",
        "desc": "子串匹配（检测特定关键词）",
    },
    "category": {
        "label": "SelfAskCategoryScorer",
        "icon": "[CT]",
        "color": "magenta",
        "desc": "分类评分（多类别判断）",
    },
}


class ExecutionDisplay:
    """
    执行展示器

    提供终端实时展示功能（Rich 格式化）：
    - 启动横幅
    - Payload 分类结果
    - 评分器信息
    - 执行计划
    - 攻击进度
    - 结果汇总
    - 模块完成信息

    使用方式：
        display = ExecutionDisplay()
        display.show_banner(config_path, target_path)
        display.show_classification(categorized_payloads)
        display.show_execution_plan(plan, plan_summary)
        display.show_attack_progress(current, total, result)
        display.show_results_summary(results)
        display.show_module_complete(module_name, results)
    """

    def __init__(self, console: Optional[Any] = None):
        """
        Args:
            console: Rich Console 实例（可选）
        """
        self.console = console or (Console() if HAS_RICH else None)
        self._attack_count = 0
        self._start_time = datetime.now()

    # ──────────────────────────────────────────────────────────────────────────
    # Terminal Output Methods
    # ──────────────────────────────────────────────────────────────────────────

    def show_banner(self, config_path: str, target_path: str) -> None:
        """显示框架启动横幅"""
        if self.console and HAS_RICH:
            self.console.print()
            self.console.print(
                Panel.fit(
                    f"[bold cyan]AI-300 Red Teaming Framework[/bold cyan] [dim]v2.0[/dim]\n"
                    f"[dim]Smart Match Engine — Payload Auto-Classification & Attack Orchestration[/dim]\n\n"
                    f"[yellow]Config:[/yellow] {config_path}\n"
                    f"[yellow]Target:[/yellow] {target_path}\n"
                    f"[yellow]Time:[/yellow]   {self._start_time.strftime('%Y-%m-%d %H:%M:%S')}",
                    title="[bold]PyRIT 0.14.0[/bold]",
                    border_style="cyan",
                    padding=(1, 4),
                )
            )
        else:
            print("=" * 70)
            print("  AI-300 Red Teaming Framework v2.0")
            print("  Smart Match Engine")
            print(f"  Config: {config_path}")
            print(f"  Target: {target_path}")
            print(f"  Time:   {self._start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            print("=" * 70)

    def show_classification(self, categorized: Dict[str, List[str]]) -> None:
        """展示 payload 分类结果"""
        total = sum(len(v) for v in categorized.values())

        if self.console and HAS_RICH:
            self.console.print()
            self.console.print("[bold]═══ Phase 1: Payload Classification ═══[/bold]")
            self.console.print()

            table = Table(
                title=f"Classified {total} Payloads into {len(categorized)} Categories",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold cyan",
            )
            table.add_column("Category", style="bold", min_width=16)
            table.add_column("Count", justify="right", min_width=6)
            table.add_column("Payloads", min_width=40)

            for category, payloads in sorted(categorized.items()):
                meta = CATEGORY_META.get(category, {})
                label = meta.get("label", category)
                icon = meta.get("icon", "[?]")
                color = meta.get("color", "white")

                payload_preview = ""
                for i, p in enumerate(payloads[:3]):
                    truncated = p[:50] + "..." if len(p) > 50 else p
                    payload_preview += f"  {i+1}. {truncated}\n"
                if len(payloads) > 3:
                    payload_preview += f"  ... and {len(payloads) - 3} more"

                table.add_row(
                    f"[{color}]{icon} {label}[/{color}]",
                    str(len(payloads)),
                    payload_preview.rstrip(),
                )

            self.console.print(table)
        else:
            print("\n=== Phase 1: Payload Classification ===")
            print(f"Total: {total} payloads in {len(categorized)} categories\n")
            for category, payloads in sorted(categorized.items()):
                meta = CATEGORY_META.get(category, {})
                label = meta.get("label", category)
                print(f"  [{label}] ({len(payloads)} payloads)")
                for i, p in enumerate(payloads[:3]):
                    truncated = p[:60] + "..." if len(p) > 60 else p
                    print(f"    {i+1}. {truncated}")
                if len(payloads) > 3:
                    print(f"    ... and {len(payloads) - 3} more")
            print()

    def show_execution_plan(self, plan: List[Dict[str, Any]], plan_summary: Dict[str, Any]) -> None:
        """展示执行计划（兼容 v3.0 新格式）"""
        if self.console and HAS_RICH:
            self.console.print()
            self.console.print("[bold]═══ Phase 2: Execution Plan (PyRIT Native) ═══[/bold]")
            self.console.print()

            # Summary panel
            total = plan_summary.get("total", plan_summary.get("total_executions", len(plan)))
            by_attack = plan_summary.get("by_attack_class", {})
            by_category = plan_summary.get("by_category", plan_summary.get("by_category", {}))

            summary_lines = [f"Total: [bold cyan]{total}[/bold cyan]"]
            if by_attack:
                summary_lines.append(f"By Attack: {', '.join(f'{k}: {v}' for k, v in by_attack.items())}")
            if by_category:
                summary_lines.append(f"By Category: {', '.join(f'{k}: {v}' for k, v in by_category.items())}")

            self.console.print(
                Panel(
                    "\n".join(summary_lines),
                    title="[bold]Plan Summary (v3.0)[/bold]",
                    border_style="yellow",
                )
            )

            # Detailed plan table
            self.console.print()
            table = Table(
                title="Attack Plan (PyRIT Native Strategies)",
                box=box.SIMPLE_HEAVY,
                show_header=True,
                header_style="bold yellow",
            )
            table.add_column("#", justify="right", width=4)
            table.add_column("Category", min_width=14)
            table.add_column("PyRIT Attack", min_width=24)
            table.add_column("Reason", min_width=30)
            table.add_column("Payload Preview", min_width=28)

            for i, item in enumerate(plan, 1):
                cat = item.get("payload_category", "?")
                cat_meta = CATEGORY_META.get(cat, {})
                cat_label = cat_meta.get("label", cat)
                cat_color = cat_meta.get("color", "white")

                # v3.0: attack_class 替代 converter_preset + attack_strategy
                attack_class = item.get("attack_class", item.get("attack_strategy", "?"))
                if "." in attack_class:
                    attack_class = attack_class.split(".")[-1]
                reason = item.get("attack_reason", item.get("converter_preset", "—"))

                payload = item.get("payload", "")[:38]
                if len(item.get("payload", "")) > 38:
                    payload += "..."

                table.add_row(
                    str(i),
                    f"[{cat_color}]{cat_label}[/{cat_color}]",
                    attack_class,
                    reason,
                    payload,
                )

            self.console.print(table)
        else:
            print("\n=== Phase 2: Execution Plan (PyRIT Native v3.0) ===")
            print(f"Total: {len(plan)}")
            print(f"By Attack: {plan_summary.get('by_attack_class', {})}")
            print(f"By Category: {plan_summary.get('by_category', {})}")
            print()
            for i, item in enumerate(plan, 1):
                cat = item.get("payload_category", "?")
                attack_class = item.get("attack_class", item.get("attack_strategy", "?"))
                if "." in attack_class:
                    attack_class = attack_class.split(".")[-1]
                reason = item.get("attack_reason", "")
                payload = item.get("payload", "")[:50]
                print(f"  {i:3d}. [{cat}] {attack_class} — {reason}")
                print(f"       Payload: {payload}...")
            print()

    def show_scorer_info(self, scorer_info_list: List[Any]) -> None:
        """
        展示选用的策略评分器（含外部 LLM 后端信息）

        直接复用 PyRIT 评分器，展示：
        - 评分器名称（对应 PyRIT 类名）
        - 评分器类型（LLM / 非 LLM）
        - 外部 LLM 后端信息（base_url, model_name）
        - 评分器功能描述

        Args:
            scorer_info_list: 评分器信息列表，每项为 str（名称）或 dict（含 name, backend, description）
        """
        if not scorer_info_list:
            return

        if self.console and HAS_RICH:
            items = []
            for info in scorer_info_list:
                if isinstance(info, str):
                    name = info
                    backend = ""
                    description = ""
                else:
                    name = info.get("name", "")
                    backend = info.get("backend", "")
                    description = info.get("description", "")

                meta = SCORER_META.get(name, {})
                label = meta.get("label", name)
                icon = meta.get("icon", "[?]")
                color = meta.get("color", "white")
                desc = meta.get("desc", description)

                # 构建显示文本
                line = f"[{color}]{icon} {label}[/{color}]"
                if desc:
                    line += f" — [dim]{desc}[/dim]"
                if backend and backend != "objective_target":
                    line += f"\n      [dim yellow]Backend:[/dim yellow] {backend}"
                    if isinstance(info, dict) and info.get("backend_info"):
                        line += f" [dim]({info['backend_info']})[/dim]"
                items.append(line)

            self.console.print()
            self.console.print(
                Panel(
                    "\n\n".join(items),
                    title="[bold]Scorers (PyRIT Built-in)[/bold]",
                    border_style="red",
                    padding=(1, 4),
                )
            )
        else:
            print("\n=== Scorers (PyRIT Built-in) ===")
            for info in scorer_info_list:
                if isinstance(info, str):
                    name = info
                    backend = ""
                    description = ""
                else:
                    name = info.get("name", "")
                    backend = info.get("backend", "")
                    description = info.get("description", "")

                meta = SCORER_META.get(name, {})
                label = meta.get("label", name)
                desc = meta.get("desc", description)
                print(f"  [{label}] {desc}")
                if backend and backend != "objective_target":
                    print(f"      Backend: {backend}")
                    if isinstance(info, dict) and info.get("backend_info"):
                        print(f"      ({info['backend_info']})")
            print()

    def show_attack_start(self) -> None:
        """展示攻击开始信息"""
        if self.console and HAS_RICH:
            self.console.print()
            self.console.print("[bold]═══ Phase 3: Attack Execution ═══[/bold]")
            self.console.print()

    def show_attack_progress(
        self,
        index: int,
        total: int,
        category: str,
        preset: str,
        strategy: str,
        status: str,
        response_preview: str = "",
    ) -> None:
        """展示单次攻击进度（兼容 v3.0）"""
        self._attack_count += 1
        cat_meta = CATEGORY_META.get(category, {})
        cat_label = cat_meta.get("label", category)
        cat_color = cat_meta.get("color", "white")

        # v3.0: preset 可能是 PyRIT 攻击类名
        if "." in preset:
            preset = preset.split(".")[-1]
        # 截断过长的名称
        if len(preset) > 20:
            preset = preset[:17] + "..."

        status_icon = "[green]OK[/green]" if status == "success" else "[red]FAIL[/red]"

        if self.console and HAS_RICH:
            self.console.print(
                f"  [{self._attack_count:3d}/{total}] "
                f"[{cat_color}]{cat_label}[/{cat_color}] | "
                f"[cyan]{preset}[/cyan] | "
                f"{status_icon} {response_preview[:60]}"
            )
        else:
            print(
                f"  [{self._attack_count:3d}/{total}] "
                f"[{cat_label}] {preset} | "
                f"{status.upper()} {response_preview[:60]}"
            )

    def show_results_summary(self, results: Dict[str, Any]) -> None:
        """展示攻击结果汇总（兼容 v3.0）"""
        total = results.get("total_executions", 0)
        success = results.get("success_count", 0)
        failure = results.get("failure_count", 0)
        rate = (success / (success + failure) * 100) if (success + failure) > 0 else 0
        category_stats = results.get("category_stats", {})
        best_combinations = results.get("best_combinations", [])

        # Collect attack class info from results (v3.0)
        attack_classes = []
        seen_classes = set()
        for r in results.get("results", []):
            cls = r.get("attack_class", r.get("preset", ""))
            if cls and cls not in seen_classes:
                seen_classes.add(cls)
                attack_classes.append(cls)

        if self.console and HAS_RICH:
            self.console.print()
            self.console.print("[bold]═══ Phase 4: Results Summary (v3.0) ═══[/bold]")
            self.console.print()

            # Overall stats
            stats_table = Table(
                title="Overall Statistics",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold green",
            )
            stats_table.add_column("Metric", style="bold")
            stats_table.add_column("Value", justify="right")
            stats_table.add_row("Total Executions", str(total))
            stats_table.add_row("Successful", f"[green]{success}[/green]")
            stats_table.add_row("Failed", f"[red]{failure}[/red]")
            stats_table.add_row("Success Rate", f"[bold cyan]{rate:.1f}%[/bold cyan]")
            self.console.print(stats_table)

            # Attack classes used
            if attack_classes:
                self.console.print()
                self.console.print(
                    Panel(
                        "\n".join(f"  • {c}" for c in attack_classes),
                        title="[bold]PyRIT Attack Classes Used[/bold]",
                        border_style="blue",
                        padding=(1, 4),
                    )
                )

            # Category breakdown
            if category_stats:
                self.console.print()
                cat_table = Table(
                    title="Results by Category",
                    box=box.SIMPLE_HEAVY,
                    show_header=True,
                    header_style="bold cyan",
                )
                cat_table.add_column("Category", min_width=16)
                cat_table.add_column("Success", justify="right", min_width=8)
                cat_table.add_column("Failed", justify="right", min_width=8)
                cat_table.add_column("Rate", justify="right", min_width=8)

                for cat, stats in sorted(category_stats.items()):
                    cat_meta = CATEGORY_META.get(cat, {})
                    cat_label = cat_meta.get("label", cat)
                    cat_color = cat_meta.get("color", "white")
                    s = stats.get("success", 0)
                    f = stats.get("failure", 0)
                    total_cat = s + f
                    rate_cat = (s / total_cat * 100) if total_cat > 0 else 0

                    cat_table.add_row(
                        f"[{cat_color}]{cat_label}[/{cat_color}]",
                        f"[green]{s}[/green]",
                        f"[red]{f}[/red]",
                        f"{rate_cat:.0f}%",
                    )

                self.console.print(cat_table)

            # Best combinations
            if best_combinations:
                self.console.print()
                best_table = Table(
                    title="Top Performing Categories",
                    box=box.SIMPLE_HEAVY,
                    show_header=True,
                    header_style="bold yellow",
                )
                best_table.add_column("Category", min_width=16)
                best_table.add_column("Success Rate", justify="right", min_width=12)
                best_table.add_column("Tests", justify="right", min_width=6)

                for combo in best_combinations:
                    cat = combo.get("category", "?")
                    cat_meta = CATEGORY_META.get(cat, {})
                    cat_label = cat_meta.get("label", cat)
                    cat_color = cat_meta.get("color", "white")
                    best_table.add_row(
                        f"[{cat_color}]{cat_label}[/{cat_color}]",
                        f"[bold green]{combo.get('success_rate', 0) * 100:.0f}%[/bold green]",
                        str(combo.get("total_tests", 0)),
                    )

                self.console.print(best_table)

            self.console.print()
        else:
            print("\n=== Phase 4: Results Summary (v3.0) ===")
            print(f"Total: {total} | Success: {success} | Failed: {failure} | Rate: {rate:.1f}%")
            if attack_classes:
                print(f"\nPyRIT Attacks: {', '.join(attack_classes)}")
            print("\nBy Category:")
            for cat, stats in sorted(category_stats.items()):
                s = stats.get("success", 0)
                f = stats.get("failure", 0)
                total_cat = s + f
                rate_cat = (s / total_cat * 100) if total_cat > 0 else 0
                print(f"  [{cat}] Success: {s} | Failed: {f} | Rate: {rate_cat:.0f}%")
            print()

    def show_module_complete(self, module_name: str, results: Dict[str, Any]) -> None:
        """展示模块完成信息"""
        success = results.get("summary", {}).get("successful_payloads", 0)
        total = results.get("summary", {}).get("total_payloads", 0)
        rate = (success / total * 100) if total > 0 else 0

        if self.console and HAS_RICH:
            self.console.print()
            self.console.print(
                Panel.fit(
                    f"[bold green]Module Complete:[/bold green] {module_name}\n"
                    f"Payloads: {total} | Successful: {success} | Rate: {rate:.1f}%",
                    border_style="green",
                    padding=(1, 4),
                )
            )
        else:
            print(f"\n=== Module Complete: {module_name} ===")
            print(f"Payloads: {total} | Successful: {success} | Rate: {rate:.1f}%")

    # ──────────────────────────────────────────────────────────────────────────
    # File Output Methods
    # ──────────────────────────────────────────────────────────────────────────

    def save_execution_report(
        self,
        results: Dict[str, Any],
        plan: List[Dict[str, Any]],
        module_name: str = "unknown",
        config_path: str = "",
        target_path: str = "",
    ) -> str:
        """
        保存执行报告到文件

        Returns:
            报告文件路径
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"smart_match_{module_name}_{timestamp}.md"
        filepath = self._get_output_dir() / filename

        content = self._generate_report_markdown(results, plan, module_name, config_path, target_path)
        filepath.write_text(content, encoding="utf-8")
        logger.info("Execution report saved: %s", filepath)

        if self.console and HAS_RICH:
            self.console.print(f"  [dim]Report saved: {filepath}[/dim]")

        return str(filepath)

    def _get_output_dir(self) -> Path:
        """获取报告输出目录"""
        output_dir = Path("results/visualizations")
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir

    def _generate_report_markdown(
        self,
        results: Dict[str, Any],
        plan: List[Dict[str, Any]],
        module_name: str,
        config_path: str,
        target_path: str,
    ) -> str:
        """生成 Markdown 格式执行报告（兼容 v3.0）"""
        total = results.get("total_executions", 0)
        success = results.get("success_count", 0)
        failure = results.get("failure_count", 0)
        rate = (success / (success + failure) * 100) if (success + failure) > 0 else 0
        category_stats = results.get("category_stats", {})
        best_combinations = results.get("best_combinations", [])
        plan_summary = results.get("plan_summary", {})

        lines = [
            f"# Smart Match Execution Report — {module_name}",
            "",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Config:** {config_path}",
            f"**Target:** {target_path}",
            f"**Mode:** smart_match v3.0 (PyRIT Native)",
            "",
            "---",
            "",
            "## 1. Execution Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Total Executions | {total} |",
            f"| Successful | {success} |",
            f"| Failed | {failure} |",
            f"| Success Rate | {rate:.1f}% |",
            "",
            "## 2. Plan Summary",
            "",
        ]

        by_attack = plan_summary.get("by_attack_class", {})
        by_category = plan_summary.get("by_category", {})
        if by_attack:
            lines.append(f"- **By Attack:** {', '.join(f'{k}: {v}' for k, v in by_attack.items())}")
        if by_category:
            lines.append(f"- **By Category:** {', '.join(f'{k}: {v}' for k, v in by_category.items())}")

        lines.extend([
            "",
            "## 3. Attack Plan",
            "",
            "| # | Category | PyRIT Attack | Reason | Payload |",
            "|---|----------|-------------|--------|---------|",
        ])

        for i, item in enumerate(plan, 1):
            cat = item.get("payload_category", "?")
            cat_meta = CATEGORY_META.get(cat, {})
            cat_label = cat_meta.get("label", cat)

            attack_class = item.get("attack_class", item.get("attack_strategy", "?"))
            if "." in attack_class:
                attack_class = attack_class.split(".")[-1]
            reason = item.get("attack_reason", "")
            payload = item.get("payload", "")[:45].replace("|", "\\|")
            if len(item.get("payload", "")) > 45:
                payload += "..."

            lines.append(
                f"| {i} | {cat_label} | {attack_class} | {reason} | {payload} |"
            )

        lines.extend([
            "",
            "## 4. Detailed Results",
            "",
            "| # | Category | Attack Class | Status | Response |",
            "|---|----------|-------------|--------|----------|",
        ])

        for i, r in enumerate(results.get("results", []), 1):
            cat = r.get("payload_category", "?")
            cat_meta = CATEGORY_META.get(cat, {})
            cat_label = cat_meta.get("label", cat)
            attack_class = r.get("attack_class", r.get("preset", "?"))
            if "." in str(attack_class):
                attack_class = attack_class.split(".")[-1]
            status = r.get("status", "?")
            response = r.get("response", r.get("error", ""))[:60].replace("|", "\\|")

            lines.append(
                f"| {i} | {cat_label} | {attack_class} | {status} | {response} |"
            )

        lines.extend([
            "",
            "## 5. Category Statistics",
            "",
            "| Category | Success | Failed | Rate |",
            "|----------|---------|--------|------|",
        ])

        for cat, stats in sorted(category_stats.items()):
            cat_meta = CATEGORY_META.get(cat, {})
            cat_label = cat_meta.get("label", cat)
            s = stats.get("success", 0)
            f = stats.get("failure", 0)
            total_cat = s + f
            rate_cat = (s / total_cat * 100) if total_cat > 0 else 0

            lines.append(
                f"| {cat_label} | {s} | {f} | {rate_cat:.0f}% |"
            )

        if best_combinations:
            lines.extend([
                "",
                "## 6. Top Performing Categories",
                "",
                "| Category | Success Rate | Tests |",
                "|----------|-------------|-------|",
            ])
            for combo in best_combinations:
                cat = combo.get("category", "?")
                cat_meta = CATEGORY_META.get(cat, {})
                cat_label = cat_meta.get("label", cat)
                lines.append(
                    f"| {cat_label} | "
                    f"{combo.get('success_rate', 0) * 100:.0f}% | {combo.get('total_tests', 0)} |"
                )

        lines.extend([
            "",
            "---",
            "",
            "*Generated by AI-300 Framework v3.0 — PyRIT Native Attack Orchestration*",
        ])

        return "\n".join(lines)
