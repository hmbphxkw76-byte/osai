# -*- coding: utf-8 -*-
"""
AI-300 Framework - Pipeline Tracker v3.0
攻击流水线追踪器：记录 payload → 分类 → 策略选择的完整决策链路

核心功能：
1. 分阶段记录：加载 → 归一化 → 分类 → 策略选择 → 执行
2. 决策审计：每个步骤的输入/输出/原因/置信度
3. 结构化日志：可导出为 JSON/Markdown 的完整流水线日志
4. 终端输出：Rich 格式化的流水线状态展示

设计原则：
- 追踪器是只读观察者，不干预实际执行
- 所有步骤记录为不可变数据类
- 支持静默模式（仅记录不输出）和详细模式（实时展示）

PyRIT 0.14.0 兼容
"""

from __future__ import annotations

import sys
import os
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

logger = logging.getLogger(__name__)

# Rich imports (optional)
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


# ──────────────────────────────────────────────────────────────────────────────
# 流水线步骤记录（不可变数据类）
# ──────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PipelineStep:
    """
    单个流水线步骤记录

    Attributes:
        stage: 阶段名称 (load / normalize / classify / strategy / execute)
        input_summary: 输入摘要
        output_summary: 输出摘要
        reason: 决策原因
        confidence: 置信度 (0.0-1.0)
        duration_ms: 耗时（毫秒）
        metadata: 附加元数据
    """
    stage: str
    input_summary: str
    output_summary: str
    reason: str = ""
    confidence: float = 1.0
    duration_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PipelineLog:
    """
    单个 payload 的完整流水线日志

    Attributes:
        payload_id: 载荷标识（截断后的文本）
        original_payload: 原始载荷
        steps: 各阶段步骤记录
        final_strategy: 最终选择的攻击策略
        final_category: 最终分类结果
        success: 是否执行成功
        timestamp: 处理时间戳
    """
    payload_id: str
    original_payload: str
    steps: List[PipelineStep] = field(default_factory=list)
    final_strategy: str = ""
    final_category: str = ""
    success: Optional[bool] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def add_step(self, step: PipelineStep) -> None:
        """添加步骤记录"""
        self.steps.append(step)

    @property
    def total_duration_ms(self) -> float:
        """总耗时"""
        return sum(s.duration_ms for s in self.steps)

    @property
    def classification_step(self) -> Optional[PipelineStep]:
        """获取分类步骤"""
        for s in self.steps:
            if s.stage == "classify":
                return s
        return None

    @property
    def strategy_step(self) -> Optional[PipelineStep]:
        """获取策略选择步骤"""
        for s in self.steps:
            if s.stage == "strategy":
                return s
        return None


# ──────────────────────────────────────────────────────────────────────────────
# 流水线追踪器
# ──────────────────────────────────────────────────────────────────────────────

class PipelineTracker:
    """
    攻击流水线追踪器

    记录从 payload 加载到策略选择的完整决策链路。
    提供结构化的日志查询和终端展示。

    使用方式：
        tracker = PipelineTracker(verbose=True)

        # 记录 payload 加载
        tracker.log_load(payload, source="data/owasp/llm.yaml")

        # 记录分类结果
        tracker.log_classify(profile, reason="technique=role_play, encoding=plain")

        # 记录策略选择
        tracker.log_strategy(strategy, reason="ASI01约束: 渐进偏移")

        # 获取完整日志
        logs = tracker.logs
    """

    def __init__(self, verbose: bool = True, console: Optional[Any] = None):
        """
        Args:
            verbose: 是否实时输出到终端
            console: Rich Console 实例（可选）
        """
        self.verbose = verbose
        self.console = console or (Console() if HAS_RICH else None)
        self._logs: List[PipelineLog] = []
        self._current_log: Optional[PipelineLog] = None

    # ──────────────────────────────────────────────────────────────────────────
    # 日志记录方法
    # ──────────────────────────────────────────────────────────────────────────

    def start_payload(self, payload: str, source: str = "") -> PipelineLog:
        """
        开始追踪一个新 payload

        Args:
            payload: 原始载荷文本
            source: 载荷来源（文件路径或标识）

        Returns:
            PipelineLog 实例
        """
        payload_id = payload[:60] + "..." if len(payload) > 60 else payload
        log = PipelineLog(
            payload_id=payload_id,
            original_payload=payload,
        )
        self._logs.append(log)
        self._current_log = log

        if self.verbose:
            logger.debug("Pipeline start: %s (source=%s)", payload_id, source)

        return log

    def log_load(self, payload: str, source: str = "") -> None:
        """记录载荷加载步骤"""
        step = PipelineStep(
            stage="load",
            input_summary=f"source={source}",
            output_summary=f"payload_len={len(payload)}",
            reason=f"从 {source} 加载载荷" if source else "载荷加载",
        )
        self._add_step(step)

    def log_normalize(self, original: str, normalized: str, encodings: List[str]) -> None:
        """记录归一化步骤"""
        if original == normalized:
            step = PipelineStep(
                stage="normalize",
                input_summary=f"len={len(original)}",
                output_summary="无需归一化（纯文本）",
                reason="未检测到编码",
                confidence=0.95,
            )
        else:
            step = PipelineStep(
                stage="normalize",
                input_summary=f"len={len(original)}, encodings={encodings}",
                output_summary=f"len={len(normalized)}, decoded={encodings}",
                reason=f"检测到编码: {', '.join(encodings)}",
                confidence=0.9,
            )
        self._add_step(step)

    def log_classify(self, profile: Any, reason: str = "") -> None:
        """
        记录分类步骤

        Args:
            profile: PayloadProfile 实例
            reason: 分类原因说明
        """
        input_summary = (
            f"technique={profile.technique}, encoding={profile.encoding_state}, "
            f"lang={profile.language}, length={profile.length_class}, "
            f"complexity={profile.complexity}"
        )
        output_summary = f"category={profile.primary_category}"

        step = PipelineStep(
            stage="classify",
            input_summary=input_summary,
            output_summary=output_summary,
            reason=reason or f"主类别判定: {profile.primary_category}",
            confidence=profile.avg_confidence,
            metadata={
                "profile_dict": profile.to_dict() if hasattr(profile, 'to_dict') else {},
                "tags": list(profile.tags) if hasattr(profile, 'tags') else [],
            },
        )
        self._add_step(step)

        if self._current_log:
            self._current_log.final_category = profile.primary_category

    def log_strategy(self, strategy: Dict[str, Any], reason: str = "") -> None:
        """
        记录策略选择步骤

        Args:
            strategy: 策略配置字典（来自 SmartMatcher.select_strategy）
            reason: 策略选择原因
        """
        attack_class = strategy.get("class", "unknown")
        if "." in attack_class:
            attack_class = attack_class.split(".")[-1]

        input_summary = f"family={strategy.get('family', 'unknown')}"
        output_summary = f"attack={attack_class}"

        step = PipelineStep(
            stage="strategy",
            input_summary=input_summary,
            output_summary=output_summary,
            reason=reason or strategy.get("reason", "默认策略"),
            confidence=strategy.get("confidence", 1.0),
            metadata={
                "params": strategy.get("params", {}),
                "fallback_chain": strategy.get("fallback_chain", []),
            },
        )
        self._add_step(step)

        if self._current_log:
            self._current_log.final_strategy = attack_class

    def log_execution(self, result: Dict[str, Any]) -> None:
        """记录执行结果"""
        status = result.get("status", "unknown")
        step = PipelineStep(
            stage="execute",
            input_summary=f"strategy={result.get('attack_class', 'unknown')}",
            output_summary=f"status={status}",
            reason=f"执行结果: {status}",
            metadata={"response": result.get("response", "")[:200]},
        )
        self._add_step(step)

        if self._current_log:
            self._current_log.success = (status == "success")

    def _add_step(self, step: PipelineStep) -> None:
        """添加步骤到当前日志"""
        if self._current_log:
            self._current_log.add_step(step)

    # ──────────────────────────────────────────────────────────────────────────
    # 查询方法
    # ──────────────────────────────────────────────────────────────────────────

    @property
    def logs(self) -> List[PipelineLog]:
        """获取所有日志"""
        return list(self._logs)

    def get_logs_by_category(self, category: str) -> List[PipelineLog]:
        """按分类筛选日志"""
        return [log for log in self._logs if log.final_category == category]

    def get_logs_by_strategy(self, strategy: str) -> List[PipelineLog]:
        """按策略筛选日志"""
        return [log for log in self._logs if log.final_strategy == strategy]

    def get_category_distribution(self) -> Dict[str, int]:
        """获取分类分布统计"""
        dist: Dict[str, int] = {}
        for log in self._logs:
            cat = log.final_category or "unknown"
            dist[cat] = dist.get(cat, 0) + 1
        return dist

    def get_strategy_distribution(self) -> Dict[str, int]:
        """获取策略分布统计"""
        dist: Dict[str, int] = {}
        for log in self._logs:
            strat = log.final_strategy or "unknown"
            dist[strat] = dist.get(strat, 0) + 1
        return dist

    def get_summary(self) -> Dict[str, Any]:
        """获取流水线摘要"""
        total = len(self._logs)
        success_count = sum(1 for log in self._logs if log.success is True)
        failure_count = sum(1 for log in self._logs if log.success is False)
        pending_count = sum(1 for log in self._logs if log.success is None)

        return {
            "total_payloads": total,
            "executed": success_count + failure_count,
            "success": success_count,
            "failure": failure_count,
            "pending": pending_count,
            "category_distribution": self.get_category_distribution(),
            "strategy_distribution": self.get_strategy_distribution(),
        }

    # ──────────────────────────────────────────────────────────────────────────
    # 终端展示方法
    # ──────────────────────────────────────────────────────────────────────────

    def show_classification_summary(self) -> None:
        """展示分类结果摘要"""
        dist = self.get_category_distribution()
        total = sum(dist.values())

        if self.console and HAS_RICH:
            self.console.print()
            self.console.print("[bold]═══ Phase 1: Payload Classification ═══[/bold]")
            self.console.print()

            table = Table(
                title=f"Classified {total} Payloads",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold cyan",
            )
            table.add_column("Category", style="bold", min_width=16)
            table.add_column("Count", justify="right", min_width=6)
            table.add_column("Percentage", justify="right", min_width=10)

            for cat, count in sorted(dist.items(), key=lambda x: -x[1]):
                pct = count / total * 100 if total > 0 else 0
                table.add_row(cat, str(count), f"{pct:.1f}%")

            self.console.print(table)
        else:
            print("\n=== Phase 1: Payload Classification ===")
            for cat, count in sorted(dist.items(), key=lambda x: -x[1]):
                print(f"  [{cat}] {count} payloads")

    def show_strategy_summary(self) -> None:
        """展示策略选择摘要"""
        dist = self.get_strategy_distribution()
        total = sum(dist.values())

        if self.console and HAS_RICH:
            self.console.print()
            self.console.print("[bold]═══ Phase 2: Strategy Selection ═══[/bold]")
            self.console.print()

            table = Table(
                title=f"Selected {total} Attack Strategies",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold yellow",
            )
            table.add_column("Attack Strategy", style="bold", min_width=24)
            table.add_column("Count", justify="right", min_width=6)
            table.add_column("Percentage", justify="right", min_width=10)

            for strat, count in sorted(dist.items(), key=lambda x: -x[1]):
                pct = count / total * 100 if total > 0 else 0
                table.add_row(strat, str(count), f"{pct:.1f}%")

            self.console.print(table)
        else:
            print("\n=== Phase 2: Strategy Selection ===")
            for strat, count in sorted(dist.items(), key=lambda x: -x[1]):
                print(f"  [{strat}] {count} payloads")

    def show_decision_trace(self, index: int = 0) -> None:
        """
        展示单个 payload 的完整决策链路

        Args:
            index: payload 索引
        """
        if index >= len(self._logs):
            return

        log = self._logs[index]

        if self.console and HAS_RICH:
            self.console.print()
            self.console.print(f"[bold]═══ Decision Trace: {log.payload_id} ═══[/bold]")

            for step in log.steps:
                conf_str = f"[dim](conf={step.confidence:.2f})[/dim]" if step.confidence < 1.0 else ""
                self.console.print(
                    f"  [cyan]{step.stage:12s}[/cyan] "
                    f"{step.output_summary} "
                    f"[dim]← {step.reason}[/dim] "
                    f"{conf_str}"
                )
        else:
            print(f"\n=== Decision Trace: {log.payload_id} ===")
            for step in log.steps:
                print(f"  [{step.stage:12s}] {step.output_summary} <- {step.reason}")

    def show_full_report(self) -> None:
        """展示完整流水线报告"""
        self.show_classification_summary()
        self.show_strategy_summary()

        if self.console and HAS_RICH:
            self.console.print()
            self.console.print("[bold]═══ Pipeline Summary ═══[/bold]")
            summary = self.get_summary()
            self.console.print(
                Panel(
                    f"Total: {summary['total_payloads']} | "
                    f"Executed: {summary['executed']} | "
                    f"Success: {summary['success']} | "
                    f"Pending: {summary['pending']}",
                    border_style="cyan",
                )
            )

    # ──────────────────────────────────────────────────────────────────────────
    # 导出方法
    # ──────────────────────────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """导出为字典"""
        return {
            "summary": self.get_summary(),
            "logs": [
                {
                    "payload_id": log.payload_id,
                    "final_category": log.final_category,
                    "final_strategy": log.final_strategy,
                    "success": log.success,
                    "steps": [
                        {
                            "stage": s.stage,
                            "input": s.input_summary,
                            "output": s.output_summary,
                            "reason": s.reason,
                            "confidence": s.confidence,
                        }
                        for s in log.steps
                    ],
                }
                for log in self._logs
            ],
        }

    def export_markdown(self, output_path: str) -> str:
        """
        导出 Markdown 格式流水线报告

        Returns:
            文件路径
        """
        summary = self.get_summary()
        lines = [
            "# Attack Pipeline Report",
            "",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Total Payloads:** {summary['total_payloads']}",
            "",
            "## Classification Distribution",
            "",
            "| Category | Count |",
            "|----------|-------|",
        ]
        for cat, count in sorted(summary["category_distribution"].items(), key=lambda x: -x[1]):
            lines.append(f"| {cat} | {count} |")

        lines.extend([
            "",
            "## Strategy Distribution",
            "",
            "| Strategy | Count |",
            "|----------|-------|",
        ])
        for strat, count in sorted(summary["strategy_distribution"].items(), key=lambda x: -x[1]):
            lines.append(f"| {strat} | {count} |")

        lines.extend([
            "",
            "## Decision Traces",
            "",
        ])
        for log in self._logs:
            lines.append(f"### {log.payload_id}")
            lines.append("")
            lines.append("| Stage | Output | Reason | Confidence |")
            lines.append("|-------|--------|--------|------------|")
            for step in log.steps:
                lines.append(
                    f"| {step.stage} | {step.output_summary} | "
                    f"{step.reason} | {step.confidence:.2f} |"
                )
            lines.append("")

        content = "\n".join(lines)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        return output_path
