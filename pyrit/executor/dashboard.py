"""
===============================================================================
PyRIT Red Team — 实时仪表盘状态管理器
===============================================================================
包含:
- DashboardState: 攻击进度追踪、成功/失败计数、Rich 实时布局
- console: Rich Console 实例（供模块内使用）
===============================================================================
"""
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.progress import Progress, TaskID
from rich.text import Text

console = Console()


class DashboardState:
    def __init__(self, total_tasks: int):
        self.total = total_tasks
        self.completed = 0
        self.success = 0
        self.failure = 0
        self.error = 0
        self.latest_log = Text("等待任务启动...", style="bold cyan")

    def update(self, status: str, log_msg: str):
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

    def get_layout(self, progress: Progress, task_id: TaskID) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="progress", size=3),
            Layout(name="stats", size=5),
            Layout(name="log", size=3)
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

        layout["header"].update(Panel(f"[bold]🚀 PyRIT Red Team 实时战术仪表盘[/] | 总任务: {self.total}", style="bold blue"))
        layout["progress"].update(progress)
        layout["stats"].update(Panel(stats_table, title="实时战况", border_style="green"))
        layout["log"].update(Panel(self.latest_log, title="最新攻击流", border_style="cyan"))
        return layout
