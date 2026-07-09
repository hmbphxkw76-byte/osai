"""
===============================================================================
PyRIT Red Team — 实时仪表盘状态管理器
===============================================================================
包含:
- DashboardState: 攻击进度追踪、成功/失败计数、Rich 实时布局
- 🆕 实时专家指导面板集成 (Stage 2 In-Execution Guidance)
- console: Rich Console 实例（供模块内使用）
===============================================================================
"""
from __future__ import annotations

import json
import time

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.progress import Progress, TaskID
from rich.text import Text

console = Console()


class DashboardState:
    def __init__(self, total_tasks: int, target_url: str = "", current_phase: str = ""):
        self.total = total_tasks
        self.completed = 0
        self.success = 0
        self.failure = 0
        self.error = 0
        self.latest_log = Text("等待任务启动...", style="bold cyan")
        # 🆕 实时指导字段
        self.guidance_result: dict | None = None
        self.target_url = target_url
        self.current_phase = current_phase
        # 累计攻击结果（供 guidance 生成器消费）
        self.accumulated_results: list[dict] = []

    def update(self, status: str, log_msg: str, result_data: dict | None = None):
        if status != "RUNNING":
            self.completed += 1
            if status == "SUCCESS":
                self.success += 1
            elif status == "FAILURE":
                self.failure += 1
            else:
                self.error += 1

        color = "green" if status == "SUCCESS" else ("red" if status == "FAILURE" else ("yellow" if status == "ERROR" else "cyan"))
        self.latest_log = Text(log_msg, style=f"bold {color}")

        # 🆕 累计结果用于实时指导
        if result_data:
            self.accumulated_results.append(result_data)

    def refresh_guidance(self):
        """基于累计结果刷新实时指导面板。"""
        from utils.guidance import generate_realtime_guidance
        self.guidance_result = generate_realtime_guidance(
            results=self.accumulated_results,
            current_phase=self.current_phase,
            dashboard_stats={
                "completed": self.completed,
                "success": self.success,
                "failure": self.failure,
                "error": self.error,
                "total": self.total,
            },
            target_url=self.target_url,
        )

    def get_layout(self, progress: Progress, task_id: TaskID) -> Layout:
        layout = Layout()
        # 🆕 动态布局: 有 guidance 时多一个面板
        if self.guidance_result:
            layout.split_column(
                Layout(name="header", size=3),
                Layout(name="progress", size=3),
                Layout(name="stats", size=6),
                Layout(name="guidance", size=10),  # 🆕 实时指导面板
                Layout(name="log", size=3),
            )
        else:
            layout.split_column(
                Layout(name="header", size=3),
                Layout(name="progress", size=3),
                Layout(name="stats", size=5),
                Layout(name="log", size=3),
            )

        stats_table = Table.grid(expand=True)
        stats_table.add_column(justify="center", ratio=1)
        stats_table.add_column(justify="center", ratio=1)
        stats_table.add_column(justify="center", ratio=1)
        stats_table.add_row(
            f"[bold green]🎯 成功: {self.success}[/]",
            f"[bold red]❌ 失败: {self.failure}[/]",
            f"[bold yellow]⚠️ 错误: {self.error}[/]"
        )

        # ── 添加 Top 手法行 ──
        if self.guidance_result and self.guidance_result.get("top_combos"):
            top_combo_lines = []
            for tc in self.guidance_result["top_combos"][:3]:
                bar_len = min(int(tc["rate"] * 20), 20)
                bar = "█" * bar_len + "░" * (20 - bar_len)
                top_combo_lines.append(
                    f"  [cyan]{tc['combo']:30s}[/cyan] [{bar}] [bold]{tc['rate']:.0%}[/bold] ({tc['hits']}次)"
                )
            stats_table.add_row(
                f"[dim]🏆 最有效手法:[/dim]\n" + "\n".join(top_combo_lines),
                f"[dim]📊 成功率: {(self.success/max(self.completed,1)*100):.0f}%[/dim]\n"
                f"[dim]📋 已完成: {self.completed}/{self.total}[/dim]",
                "",
            )

        layout["header"].update(Panel(
            f"[bold]🚀 PyRIT Red Team 实时战术仪表盘[/] | "
            f"阶段: [cyan]{self.current_phase}[/cyan] | 总任务: {self.total}",
            style="bold blue",
        ))
        layout["progress"].update(progress)
        layout["stats"].update(Panel(stats_table, title="实时战况", border_style="green"))

        # 🆕 实时指导面板
        if self.guidance_result:
            gr = self.guidance_result
            guidance_content = []

            # 摘要
            guidance_content.append(f"[bold yellow]{gr.get('summary', '')}[/bold yellow]")
            guidance_content.append("")

            # 阶段建议
            phase_advice = gr.get("phase_advice", "")
            if phase_advice:
                guidance_content.append(f"[bold cyan]💡 战术建议:[/bold cyan]")
                guidance_content.append(f"  {phase_advice}")
                guidance_content.append("")

            # 下一步命令
            next_cmd = gr.get("next_command")
            if next_cmd:
                guidance_content.append(f"[bold green]🚀 立即执行:[/bold green]")
                guidance_content.append(f"  [bold white]$ {next_cmd}[/bold white]")
                desc = gr.get("next_command_desc", "")
                if desc:
                    guidance_content.append(f"  [dim]{desc}[/dim]")
                guidance_content.append("")

            # 警告
            warnings = gr.get("warnings", [])
            for w in warnings:
                guidance_content.append(f"  [yellow]{w}[/yellow]")

            # 进度
            guidance_content.append(f"  [dim]{gr.get('progress_hint', '')}[/dim]")

            layout["guidance"].update(Panel(
                "\n".join(guidance_content),
                title="🧠 PyRIT 实时专家指导",
                border_style="yellow",
            ))

        layout["log"].update(Panel(self.latest_log, title="最新攻击流", border_style="cyan"))
        return layout

    # ═══════════════════════════════════════════════════════════════
    # 🆕 Web SSE 序列化
    # ═══════════════════════════════════════════════════════════════

    def to_sse_event(self, result_data: dict | None = None) -> str:
        """将当前仪表盘状态序列化为 JSON（供 Web SSE 推送）。

        Args:
            result_data: 最近一次攻击结果 dict

        Returns:
            JSON 字符串，包含完整的进度信息
        """
        payload = {
            "type": "progress",
            "completed": self.completed,
            "total": self.total,
            "success": self.success,
            "failure": self.failure,
            "error_count": self.error,
            "percent": round(self.completed / max(self.total, 1) * 100, 1),
            "elapsed_seconds": round(time.time() - self._start_time, 1) if hasattr(self, "_start_time") else 0,
            "log_msg": str(self.latest_log) if self.latest_log else "",
            "guidance": self.guidance_result,
        }
        if result_data:
            payload.update(self._extract_result_fields(result_data))
        return json.dumps(payload, ensure_ascii=False, default=str)

    def get_progress_event(
        self,
        result_data: dict | None = None,
        case_id: str = "",
        combo_name: str = "",
        status: str = "",
        mode: str = "",
    ) -> dict:
        """生成完整进度事件 dict（供 Web callback 消费）。

        Returns:
            包含所有进度字段 + 攻击详情 + 实时指导的 dict
        """
        event = {
            "completed": self.completed,
            "total": self.total,
            "success": self.success,
            "failure": self.failure,
            "error_count": self.error,
            "percent": round(self.completed / max(self.total, 1) * 100, 1),
            "elapsed_seconds": round(time.time() - self._start_time, 1) if hasattr(self, "_start_time") else 0,
            "case_id": case_id,
            "combo_name": combo_name,
            "status": status,
            "mode": mode,
            "log_msg": (str(self.latest_log) if self.latest_log else f"[{case_id}] {combo_name} ({mode}) -> {status}"),
            "guidance": self.guidance_result,
        }
        if result_data:
            event.update(self._extract_result_fields(result_data))
        return event

    @staticmethod
    def _extract_result_fields(result_data: dict) -> dict:
        """从攻击结果中提取需要在 Web UI 显示的字段。"""
        return {
            "response_text": (result_data.get("response_text", "") or "")[:500],
            "objective": (result_data.get("objective", "") or "")[:300],
            "converted_prompt": (result_data.get("converted_prompt", "") or "")[:300],
            "criterion": (result_data.get("criterion", "") or "")[:300],
            "score_reason": (result_data.get("score_reason", "") or "")[:300],
            "turns": result_data.get("turns", 0),
        }

    def mark_start(self):
        """标记开始时间（供 elapsed 计算）。"""
        self._start_time = time.time()
