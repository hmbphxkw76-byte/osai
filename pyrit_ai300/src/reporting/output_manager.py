"""
Output Manager
==============

统一管理终端输出和文件输出，充分利用 PyRIT 原生 Sink/Printer 体系。

核心能力：
1. 双通道输出：StdoutSink（终端实时显示）+ FileSink（Markdown 文件持久化）
2. 每个攻击结果使用 MarkdownAttackResultMemoryPrinter 生成完整 Markdown
3. 对话历史使用 MarkdownConversationMemoryPrinter 渲染
4. 评分使用 PrettyScorePrinter 展示
5. 批量完成后生成汇总 Markdown 文件

遵循开发规则 1.4.1（原生优先）：使用 PyRIT 原生 output_attack_async / FileSink。
"""

import asyncio
import logging
import time
from pathlib import Path
from typing import Any, List, Optional

from colorama import Back, Fore, Style

from pyrit.output import (
    FileSink,
    IPythonMarkdownSink,
    StdoutSink,
    get_default_sink,
    output_attack_async,
    output_conversation_async,
    output_scenario_async,
    output_score_async,
    output_scorer_async,
)

from src.core.config_loader import get_config_loader

logger = logging.getLogger(__name__)


# ============================================================
# 工具函数
# ============================================================


def _truncate(text: str, max_len: int = 60) -> str:
    """截断文本用于终端显示"""
    text = text.replace("\n", " ").replace("\r", " ").strip()
    return text[:max_len] + "..." if len(text) > max_len else text


def _color(text: str, *colors: str) -> str:
    """ANSI 着色"""
    color_prefix = "".join(colors)
    return f"{color_prefix}{text}{Style.RESET_ALL}"


# ============================================================
# 终端进度仪表盘
# ============================================================


class ProgressDashboard:
    """批量攻击实时进度仪表盘 - 终端 ANSI 着色"""

    def __init__(self, total: int):
        self.total = total
        self.completed = 0
        self.succeeded = 0
        self.failed = 0
        self.errored = 0
        self.upgrade_attempts = 0
        self.upgrade_success = 0
        self._start_time = time.time()

    def update(self, *, succeeded: int = 0, failed: int = 0, errored: int = 0,
               upgrade_attempts: int = 0, upgrade_success: int = 0):
        self.succeeded += succeeded
        self.failed += failed
        self.errored += errored
        self.upgrade_attempts += upgrade_attempts
        self.upgrade_success += upgrade_success

    def increment_completed(self):
        self.completed += 1

    def render(self) -> str:
        elapsed = time.time() - self._start_time
        pct = self.completed / self.total * 100 if self.total > 0 else 0
        rate = self.completed / elapsed * 60 if elapsed > 0 else 0
        remaining = (elapsed / self.completed * (self.total - self.completed)) if self.completed > 0 else 0

        # 进度条
        bar_width = 30
        filled = int(bar_width * pct / 100)
        bar = "█" * filled + "░" * (bar_width - filled)

        lines = [
            "",
            _color(f"  ┌{'─' * 60}┐", Style.BRIGHT, Fore.CYAN),
            _color(f"  │ {'PyRIT AI Red Team - Batch Attack Progress':^56s} │", Style.BRIGHT, Fore.CYAN),
            _color(f"  │ {bar} {self.completed}/{self.total} ({pct:.1f}%){'':>16s}│", Fore.CYAN),
            _color(f"  │ {'✅ OK:':>8s} {self.succeeded:<5d}  {'❌ FAIL:':>8s} {self.failed:<5d}"
                   f"  {'⚠️ ERR:':>7s} {self.errored:<5d}  {'🔄 UPG:':>7s} {self.upgrade_attempts:<3d}│",
                   Fore.GREEN, Fore.RED, Fore.YELLOW, Fore.MAGENTA),
            _color(f"  │ {'Elapsed:':>8s} {elapsed:.0f}s    {'ETA:':>5s} ~{remaining:.0f}s"
                   f"    {'Rate:':>5s} {rate:.1f}/min{'':>8s}│", Fore.CYAN),
            _color(f"  └{'─' * 60}┘", Style.BRIGHT, Fore.CYAN),
        ]
        return "\n".join(lines)

    def print_progress(self):
        print(self.render())


# ============================================================
# 终端汇总表格
# ============================================================


class SummaryTable:
    """批量攻击完成后的汇总表格 - 按攻击模式/技术/OWASP 交叉统计"""

    @staticmethod
    def render_mode_table(mode_stats: dict) -> str:
        """渲染攻击模式汇总表"""
        lines = [
            "",
            _color(f"  ┌{'─' * 70}┐", Style.BRIGHT, Fore.CYAN),
            _color(f"  │ {'Attack Mode Summary':^66s} │", Style.BRIGHT, Fore.CYAN),
            _color(f"  ├{'─' * 70}┤", Fore.CYAN),
            _color(f"  │ {'Mode':<22s} │ {'Total':>6s} │ {'Success':>8s} │ {'Fail':>6s} │ {'Rate':>6s} │",
                   Style.BRIGHT, Fore.CYAN),
            _color(f"  ├{'─' * 22}┼{'─' * 8}┼{'─' * 10}┼{'─' * 8}┼{'─' * 8}┤", Fore.CYAN),
        ]
        total_all = sum(s["total"] for s in mode_stats.values()) if mode_stats else 0
        succ_all = sum(s["success"] for s in mode_stats.values()) if mode_stats else 0
        fail_all = sum(s["fail"] for s in mode_stats.values()) if mode_stats else 0

        for mode, stats in sorted(mode_stats.items()):
            rate = stats["success"] / stats["total"] * 100 if stats["total"] > 0 else 0
            rate_color = Fore.RED if rate >= 75 else (Fore.YELLOW if rate >= 50 else Fore.GREEN)
            lines.append(
                f"  {_color(f'{mode:<22s}', Fore.WHITE)} │ {stats['total']:>6d} │ "
                f"{stats['success']:>8d} │ {stats['fail']:>6d} │ "
                f"{_color(f'{rate:.0f}%', rate_color):>6s} │"
            )

        rate_all = succ_all / total_all * 100 if total_all > 0 else 0
        lines.append(_color(f"  ├{'─' * 22}┼{'─' * 8}┼{'─' * 10}┼{'─' * 8}┼{'─' * 8}┤", Fore.CYAN))
        lines.append(
            f"  {_color(f'{'TOTAL':<22s}', Style.BRIGHT, Fore.WHITE)} │ "
            f"{_color(f'{total_all:>6d}', Style.BRIGHT)} │ "
            f"{_color(f'{succ_all:>8d}', Style.BRIGHT, Fore.GREEN)} │ "
            f"{_color(f'{fail_all:>6d}', Style.BRIGHT, Fore.RED)} │ "
            f"{_color(f'{rate_all:.0f}%', Style.BRIGHT, Fore.YELLOW):>6s} │"
        )
        lines.append(_color(f"  └{'─' * 70}┘", Style.BRIGHT, Fore.CYAN))
        return "\n".join(lines)


# ============================================================
# 输出管理器
# ============================================================


class OutputManager:
    """
    统一输出管理器 - 双通道输出（终端 + 文件）

    终端通道：get_default_sink() 自动检测环境（IPythonMarkdownSink/StdoutSink）
    文件通道：FileSink + MarkdownAttackResultMemoryPrinter（Markdown 持久化）

    L5 对齐 PyRIT 1.0.0 output 模块：
    - 支持 include_reasoning_trace（o1/o3 推理模型推理轨迹）
    - 支持 blur_images（图片模糊，保护审查者）
    - 支持 include_pruned_conversations（树形攻击剪枝分支）
    - 集成 output_scenario_async 输出原生场景级摘要
    - 集成 output_scorer_async 输出评分器评估指标
    - 使用 get_default_sink() 自动检测运行环境（终端 vs Notebook）
    """

    def __init__(
        self,
        exam_id: str,
        verbose: bool = False,
        *,
        include_reasoning_trace: bool = False,
        blur_images: bool = False,
        blur_radius: int = 20,
    ):
        """
        初始化输出管理器

        Args:
            exam_id: 考试 ID
            verbose: 是否在终端输出每个攻击的完整详情
            include_reasoning_trace: 是否包含推理模型的推理轨迹（o1/o3）
            blur_images: 是否模糊图片内容（保护审查者）
            blur_radius: 高斯模糊半径
        """
        self.exam_id = exam_id
        self.verbose = verbose
        self.include_reasoning_trace = include_reasoning_trace
        self.blur_images = blur_images
        self.blur_radius = blur_radius

        config_loader = get_config_loader()
        logs_dir = Path(config_loader.get_logs_dir())
        logs_dir.mkdir(parents=True, exist_ok=True)

        # 文件通道 - 全量 Markdown 日志
        self.terminal_log_path = logs_dir / f"{exam_id}_attacks.md"
        self.file_sink = FileSink(path=self.terminal_log_path, mode="w")

        # 终端通道 - 自动检测环境（IPythonMarkdownSink in notebook, StdoutSink otherwise）
        self.stdout_sink = get_default_sink(StdoutSink)

        # 统计数据
        self._attack_count = 0

    async def output_attack_result(
        self,
        result: Any,
        *,
        to_terminal: bool = True,
        to_file: bool = True,
        include_auxiliary: bool = True,
        include_adversarial: bool = True,
        include_pruned: bool = False,
    ) -> None:
        """
        输出单个攻击结果到双通道

        Args:
            result: AttackResult 实例
            to_terminal: 是否输出到终端（pretty 格式）
            to_file: 是否输出到文件（markdown 格式）
            include_auxiliary: 是否包含辅助评分
            include_adversarial: 是否包含对抗对话
            include_pruned: 是否包含剪枝对话（树形攻击）
        """
        self._attack_count += 1

        # 终端通道 - pretty 格式
        if to_terminal and (self.verbose or self._should_show_terminal(result)):
            try:
                await output_attack_async(
                    result,
                    format="pretty",
                    sink=self.stdout_sink,
                    include_auxiliary_scores=include_auxiliary,
                    include_adversarial_conversation=include_adversarial,
                    include_pruned_conversations=include_pruned,
                    blur_images=self.blur_images,
                    blur_radius=self.blur_radius,
                )
            except Exception as e:
                logger.warning(f"Terminal output failed for attack #{self._attack_count}: {e}")

        # 文件通道 - markdown 格式（全量，包含辅助评分、对抗对话、剪枝对话）
        if to_file:
            try:
                await output_attack_async(
                    result,
                    format="markdown",
                    sink=self.file_sink,
                    include_auxiliary_scores=True,
                    include_adversarial_conversation=True,
                    include_pruned_conversations=include_pruned,
                    blur_images=self.blur_images,
                    blur_radius=self.blur_radius,
                )
            except Exception as e:
                logger.warning(f"File output failed for attack #{self._attack_count}: {e}")

    def _should_show_terminal(self, result: Any) -> bool:
        """判断是否在终端显示（非 verbose 模式下仅显示前 5 个成功结果）"""
        outcome = getattr(result, "outcome", None)
        if outcome is None:
            return False
        outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()
        # 非 verbose 模式下只显示成功的前 5 个
        if outcome_str == "SUCCESS":
            return self._attack_count <= 5
        return False

    async def output_scores(self, scores: List[Any]) -> None:
        """输出评分列表到终端"""
        if scores:
            try:
                await output_score_async(scores, format="pretty", sink=self.stdout_sink)
            except Exception as e:
                logger.warning(f"Score output failed: {e}")

    async def output_conversation(self, messages: List[Any]) -> None:
        """输出对话历史到终端"""
        if messages:
            try:
                await output_conversation_async(
                    messages,
                    format="pretty",
                    sink=self.stdout_sink,
                    include_scores=True,
                    include_reasoning_trace=self.include_reasoning_trace,
                    blur_images=self.blur_images,
                    blur_radius=self.blur_radius,
                )
            except Exception as e:
                logger.warning(f"Conversation output failed: {e}")

    async def output_scenario_result(
        self,
        scenario_result: Any,
        *,
        sort_groups_by_success_rate: bool = False,
    ) -> None:
        """
        输出场景级摘要到终端（原生 output_scenario_async）

        使用 PyRIT 原生 PrettyScenarioResultMemoryPrinter 渲染：
        - 场景信息（名称/版本/PyRIT版本/描述）
        - 目标信息（类型/模型/端点）
        - 评分器信息与评估指标
        - 逐组统计（成功率/结果数）
        - 总体统计（技术数/攻击结果数/总体成功率）

        Args:
            scenario_result: ScenarioResult 实例
            sort_groups_by_success_rate: 是否按成功率排序分组
        """
        try:
            await output_scenario_async(
                scenario_result,
                format="pretty",
                sink=self.stdout_sink,
                sort_groups_by_success_rate=sort_groups_by_success_rate,
            )
        except Exception as e:
            logger.warning(f"Scenario result output failed: {e}")

    async def output_scorer_info(
        self,
        scorer_identifier: Any,
        harm_category: Optional[str] = None,
    ) -> None:
        """
        输出评分器信息与评估指标到终端（原生 output_scorer_async）

        使用 PyRIT 原生 PrettyScorerMemoryPrinter 渲染：
        - 评分器标识（类型/参数/子评分器）
        - 目标信息（模型/温度）
        - 性能指标（Objective: accuracy/F1/precision/recall 或 Harm: MAE/Krippendorff α）

        Args:
            scorer_identifier: ComponentIdentifier 评分器标识
            harm_category: 危害类别（None 表示 Objective 评分器）
        """
        try:
            await output_scorer_async(
                scorer_identifier=scorer_identifier,
                harm_category=harm_category,
                format="pretty",
                sink=self.stdout_sink,
            )
        except Exception as e:
            logger.warning(f"Scorer info output failed: {e}")

    async def close(self) -> None:
        """关闭文件通道"""
        # FileSink 不需要显式关闭，但可以添加结束标记
        try:
            await self.file_sink.write_async(
                f"\n\n---\n*Total attacks logged: {self._attack_count}*\n"
                f"*Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}*\n"
            )
        except Exception:
            pass

    @property
    def log_path(self) -> Path:
        """文件日志路径"""
        return self.terminal_log_path
