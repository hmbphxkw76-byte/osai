# -*- coding: utf-8 -*-
"""
AI-300 Framework - Pipeline Tracker v3.1
全链路追踪器：记录侦察 → 攻击 → 评分的完整决策链路

核心功能：
1. 侦察阶段记录：工具执行 → 合并 → 画像加载
2. 攻击阶段记录：加载 → 归一化 → 分类 → 策略选择 → 执行
3. 决策审计：每个步骤的输入/输出/原因/置信度
4. 结构化日志：可导出为 JSON/Markdown 的完整流水线日志
5. 终端输出：Rich 格式化的流水线状态展示

追踪阶段：
  recon_start → recon_tool(N) → recon_merge → recon_complete → profile_loaded
  → load → normalize → classify → strategy → execute → scoring

设计原则：
- 追踪器是只读观察者，不干预实际执行
- 所有步骤记录为不可变数据类
- 支持静默模式（仅记录不输出）和详细模式（实时展示）
- 支持三种模式：仅侦察 / 仅攻击 / 侦察+攻击

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
        stage: 阶段名称
            (recon_start/recon_tool/recon_merge/recon_complete/
            profile_loaded/load/normalize/classify/strategy/execute/scoring)
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
# 侦察阶段日志（独立于 payload 级别）
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ReconLog:
    """
    侦察阶段完整日志

    记录从侦察开始到 TargetProfile 生成的完整过程。
    与 payload 级别的 PipelineLog 独立存在。
    """
    target: str = ""
    steps: List[PipelineStep] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    vulnerability_count: int = 0
    risk_level: str = "unknown"
    profile_path: str = ""
    success: bool = True
    duration_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def add_step(self, step: PipelineStep) -> None:
        """添加步骤记录"""
        self.steps.append(step)

    @property
    def tool_results(self) -> List[PipelineStep]:
        """获取所有工具执行步骤"""
        return [s for s in self.steps if s.stage == "recon_tool"]


# ──────────────────────────────────────────────────────────────────────────────
# 流水线追踪器
# ──────────────────────────────────────────────────────────────────────────────

class PipelineTracker:
    """
    全链路流水线追踪器（v3.1）

    记录从侦察到攻击的完整决策链路。
    提供结构化的日志查询和终端展示。

    支持三种模式：
    1. 仅侦察：recon 命令独立运行，生成 ReconLog
    2. 仅攻击：run 命令不带 --profile/--auto-recon，仅生成 PipelineLog
    3. 侦察+攻击：--auto-recon 或 --profile，先 ReconLog 后 PipelineLog

    使用方式：
        tracker = PipelineTracker(verbose=True)

        # 侦察阶段
        tracker.log_recon_start(target, tools=["garak", "deepteam"])
        tracker.log_recon_tool("garak", True, findings_count=5)
        tracker.log_recon_merge(tools_used=["garak", "deepteam"], vuln_count=8, risk_level="high")
        tracker.log_recon_complete(profile_path="results/recon/profile.json")

        # 攻击阶段
        tracker.start_payload(payload)
        tracker.log_load(payload, source="data/owasp/llm.yaml")
        tracker.log_classify(profile, reason="technique=role_play")
        tracker.log_strategy(strategy, reason="ASI01约束: 渐进偏移")
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
        self._recon_log: Optional[ReconLog] = None

    # ──────────────────────────────────────────────────────────────────────────
    # 侦察阶段记录方法
    # ──────────────────────────────────────────────────────────────────────────

    def log_recon_start(self, target: str, tools: List[str]) -> ReconLog:
        """
        记录侦察开始

        Args:
            target: 目标 URL/endpoint
            tools: 计划使用的工具列表

        Returns:
            ReconLog 实例
        """
        self._recon_log = ReconLog(target=target)
        self._recon_log.tools_used = tools

        step = PipelineStep(
            stage="recon_start",
            input_summary=f"target={target}",
            output_summary=f"tools={','.join(tools)}",
            reason=f"开始侦察: {target}",
        )
        self._recon_log.add_step(step)

        if self.verbose:
            self._print_header("侦察阶段", "cyan")
            self._print_step("recon_start", f"目标: {target}", f"工具: {', '.join(tools)}")

        return self._recon_log

    def log_recon_tool(
        self,
        tool: str,
        success: bool,
        findings_count: int = 0,
        duration_ms: float = 0.0,
        error: str = "",
    ) -> None:
        """
        记录单个侦察工具执行结果

        Args:
            tool: 工具名称
            success: 是否成功
            findings_count: 发现数量
            duration_ms: 耗时（毫秒）
            error: 错误信息（如果失败）
        """
        if not self._recon_log:
            return

        status = "成功" if success else "失败"
        step = PipelineStep(
            stage="recon_tool",
            input_summary=f"tool={tool}",
            output_summary=f"status={status}, findings={findings_count}",
            reason=error if error else f"{tool} 执行{status}",
            confidence=1.0 if success else 0.0,
            duration_ms=duration_ms,
            metadata={"tool": tool, "success": success, "findings_count": findings_count},
        )
        self._recon_log.add_step(step)

        if self.verbose:
            symbol = "✓" if success else "✗"
            self._print_step(
                f"recon_tool:{tool}",
                f"{symbol} {tool}: {status}",
                f"发现: {findings_count}" + (f", 错误: {error}" if error else ""),
            )

    def log_recon_merge(
        self,
        tools_used: List[str],
        vuln_count: int,
        risk_level: str,
        duration_ms: float = 0.0,
    ) -> None:
        """
        记录 ProfileMerger 合并结果

        Args:
            tools_used: 成功使用的工具列表
            vuln_count: 合并后漏洞总数
            risk_level: 综合风险等级
            duration_ms: 耗时（毫秒）
        """
        if not self._recon_log:
            return

        step = PipelineStep(
            stage="recon_merge",
            input_summary=f"tools={','.join(tools_used)}",
            output_summary=f"vulns={vuln_count}, risk={risk_level}",
            reason=f"合并 {len(tools_used)} 个工具结果",
            duration_ms=duration_ms,
            metadata={
                "tools_used": tools_used,
                "vuln_count": vuln_count,
                "risk_level": risk_level,
            },
        )
        self._recon_log.add_step(step)
        self._recon_log.vulnerability_count = vuln_count
        self._recon_log.risk_level = risk_level

        if self.verbose:
            self._print_step(
                "recon_merge",
                f"合并完成: {len(tools_used)} 个工具",
                f"漏洞: {vuln_count}, 风险: {risk_level}",
            )

    def log_recon_complete(
        self,
        profile_path: str,
        success: bool = True,
        duration_ms: float = 0.0,
    ) -> None:
        """
        记录侦察完成

        Args:
            profile_path: TargetProfile JSON 保存路径
            success: 是否成功
            duration_ms: 总耗时（毫秒）
        """
        if not self._recon_log:
            return

        step = PipelineStep(
            stage="recon_complete",
            input_summary="merge_done",
            output_summary=f"profile={profile_path}",
            reason="侦察完成，画像已保存" if success else "侦察完成（有错误）",
            confidence=1.0 if success else 0.5,
            duration_ms=duration_ms,
            metadata={"profile_path": profile_path, "success": success},
        )
        self._recon_log.add_step(step)
        self._recon_log.profile_path = profile_path
        self._recon_log.success = success
        self._recon_log.duration_ms = duration_ms

        if self.verbose:
            self._print_step(
                "recon_complete",
                f"画像已保存: {profile_path}",
                f"总耗时: {duration_ms:.0f}ms",
            )
            self._print_header("侦察阶段完成", "green")

    def log_profile_loaded(self, profile_path: str, recommendations: List[str]) -> None:
        """
        记录 ProfileLoader 加载画像（侦察→攻击的桥梁）

        Args:
            profile_path: TargetProfile JSON 路径
            recommendations: 攻击建议列表
        """
        step = PipelineStep(
            stage="profile_loaded",
            input_summary=f"profile={profile_path}",
            output_summary=f"recommendations={len(recommendations)}",
            reason="加载侦察画像，驱动攻击策略选择",
            metadata={
                "profile_path": profile_path,
                "recommendations": recommendations,
            },
        )

        # 添加到当前 payload 日志（如果有）
        if self._current_log:
            self._current_log.add_step(step)

        if self.verbose:
            self._print_header("攻击阶段", "yellow")
            self._print_step(
                "profile_loaded",
                f"画像: {profile_path}",
                f"建议: {len(recommendations)} 条",
            )

    # ──────────────────────────────────────────────────────────────────────────
    # 攻击阶段记录方法
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

    def log_scorer_selection(
        self,
        asi_category: str,
        scorer_type: str,
        reason: str,
    ) -> None:
        """
        记录评分器选择步骤

        Args:
            asi_category: ASI 类别 (如 "ASI01")
            scorer_type: 评分器类型 (如 "refusal")
            reason: 选择原因
        """
        step = PipelineStep(
            stage="scorer_select",
            input_summary=f"asi={asi_category}",
            output_summary=scorer_type or "none",
            reason=reason,
            confidence=0.9,
            metadata={
                "asi_category": asi_category,
                "scorer_type": scorer_type,
            },
        )
        self._add_step(step)

    def log_scoring_result(
        self,
        scorer_name: str,
        score_value: str,
        score_label: str,
        reason: str,
        response_snippet: str = "",
    ) -> None:
        """
        记录评分结果

        Args:
            scorer_name: 评分器名称
            score_value: 评分值
            score_label: 评分标签
            reason: 评分理由
            response_snippet: 响应片段
        """
        step = PipelineStep(
            stage="scoring",
            input_summary=f"scorer={scorer_name}",
            output_summary=f"label={score_label}, value={score_value}",
            reason=reason[:100],
            metadata={
                "scorer_name": scorer_name,
                "score_value": score_value,
                "score_label": score_label,
                "response_snippet": response_snippet[:200],
            },
        )
        self._add_step(step)

    def _add_step(self, step: PipelineStep) -> None:
        """添加步骤到当前日志"""
        if self._current_log:
            self._current_log.add_step(step)

    # ──────────────────────────────────────────────────────────────────────────
    # 终端输出方法（####xx### 风格标题）
    # ──────────────────────────────────────────────────────────────────────────

    def _print_header(self, title: str, color: str = "cyan") -> None:
        """打印 ####xx### 风格标题"""
        if self.console and HAS_RICH:
            self.console.print()
            self.console.print(f"[bold {color}]#### {title} ####[/bold {color}]")
        else:
            print(f"\n#### {title} ####")

    def _print_step(self, stage: str, output: str, detail: str = "") -> None:
        """打印步骤信息"""
        if self.console and HAS_RICH:
            self.console.print(
                f"  [cyan]{stage:16s}[/cyan] "
                f"{output} "
                f"[dim]{detail}[/dim]"
            )
        else:
            line = f"  [{stage:16s}] {output}"
            if detail:
                line += f" ({detail})"
            print(line)

    # ──────────────────────────────────────────────────────────────────────────
    # 查询方法
    # ──────────────────────────────────────────────────────────────────────────

    @property
    def logs(self) -> List[PipelineLog]:
        """获取所有 payload 日志"""
        return list(self._logs)

    @property
    def recon_log(self) -> Optional[ReconLog]:
        """获取侦察日志"""
        return self._recon_log

    @property
    def has_recon(self) -> bool:
        """是否包含侦察阶段"""
        return self._recon_log is not None

    @property
    def has_attack(self) -> bool:
        """是否包含攻击阶段"""
        return len(self._logs) > 0

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

        summary = {
            "total_payloads": total,
            "executed": success_count + failure_count,
            "success": success_count,
            "failure": failure_count,
            "pending": pending_count,
            "category_distribution": self.get_category_distribution(),
            "strategy_distribution": self.get_strategy_distribution(),
        }

        # 添加侦察摘要（如果有）
        if self._recon_log:
            summary["recon"] = {
                "target": self._recon_log.target,
                "tools_used": self._recon_log.tools_used,
                "vulnerability_count": self._recon_log.vulnerability_count,
                "risk_level": self._recon_log.risk_level,
                "profile_path": self._recon_log.profile_path,
                "duration_ms": self._recon_log.duration_ms,
            }

        return summary

    # ──────────────────────────────────────────────────────────────────────────
    # 终端展示方法
    # ──────────────────────────────────────────────────────────────────────────

    def show_recon_summary(self) -> None:
        """展示侦察阶段摘要"""
        if not self._recon_log:
            return

        if self.console and HAS_RICH:
            self.console.print()
            self.console.print("[bold cyan]######## 侦察阶段摘要 ########[/bold cyan]")
            self.console.print()

            table = Table(
                title=f"Recon: {self._recon_log.target}",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold cyan",
            )
            table.add_column("Tool", style="bold", min_width=12)
            table.add_column("Status", min_width=8)
            table.add_column("Findings", justify="right", min_width=8)

            for step in self._recon_log.tool_results:
                tool = step.metadata.get("tool", "?")
                success = step.metadata.get("success", False)
                findings = step.metadata.get("findings_count", 0)
                status = "✓ 成功" if success else "✗ 失败"
                table.add_row(tool, status, str(findings))

            self.console.print(table)
            self.console.print(
                f"[dim]风险等级: {self._recon_log.risk_level} | "
                f"漏洞总数: {self._recon_log.vulnerability_count}[/dim]"
            )
        else:
            print("\n######## 侦察阶段摘要 ########")
            for step in self._recon_log.tool_results:
                tool = step.metadata.get("tool", "?")
                success = step.metadata.get("success", False)
                findings = step.metadata.get("findings_count", 0)
                status = "成功" if success else "失败"
                print(f"  {tool}: {status} ({findings} findings)")
            print(
                f"风险: {self._recon_log.risk_level} | "
                f"漏洞: {self._recon_log.vulnerability_count}"
            )

    def show_classification_summary(self) -> None:
        """展示分类结果摘要（用户友好格式）"""
        dist = self.get_category_distribution()
        total = sum(dist.values())

        if self.console and HAS_RICH:
            self.console.print()
            self.console.print("[bold]######## 载荷分类统计 ########[/bold]")
            self.console.print(
                "[dim]说明：Count = 该类型的载荷数量，Percentage = 占总数的比例[/dim]"
            )
            self.console.print()

            table = Table(
                title=f"共 {total} 个载荷",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold cyan",
            )
            table.add_column("载荷类型", style="bold", min_width=20)
            table.add_column("说明", min_width=24)
            table.add_column("数量", justify="right", min_width=6)
            table.add_column("占比", justify="right", min_width=8)

            from pyrit_ai300.reporting.execution_report import CATEGORY_META

            for cat, count in sorted(dist.items(), key=lambda x: -x[1]):
                pct = count / total * 100 if total > 0 else 0
                meta = CATEGORY_META.get(cat, {"label": cat, "desc": ""})
                table.add_row(meta["label"], meta["desc"], str(count), f"{pct:.1f}%")

            self.console.print(table)
        else:
            print("\n######## 载荷分类统计 ########")
            print("说明：Count = 该类型的载荷数量，Percentage = 占总数的比例")
            from pyrit_ai300.reporting.execution_report import CATEGORY_META

            for cat, count in sorted(dist.items(), key=lambda x: -x[1]):
                pct = count / total * 100 if total > 0 else 0
                meta = CATEGORY_META.get(cat, {"label": cat, "desc": ""})
                print(f"  {meta['label']:<18} {meta['desc']:<22} {count:>3} ({pct:.1f}%)")

    def show_strategy_summary(self) -> None:
        """展示策略选择摘要（用户友好格式）"""
        dist = self.get_strategy_distribution()
        total = sum(dist.values())

        if self.console and HAS_RICH:
            self.console.print()
            self.console.print("[bold]######## 攻击策略选择结果 ########[/bold]")
            self.console.print(
                "[dim]说明：Count = 使用该策略的载荷数量，Percentage = 占总数的比例[/dim]"
            )
            self.console.print()

            table = Table(
                title=f"共 {total} 个载荷",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold yellow",
            )
            table.add_column("攻击策略", style="bold", min_width=20)
            table.add_column("说明", min_width=24)
            table.add_column("数量", justify="right", min_width=6)
            table.add_column("占比", justify="right", min_width=8)

            # 策略名称到中文说明的映射
            STRATEGY_DESC = {
                "PromptSendingAttack": "单轮直接发送（最简攻击）",
                "CrescendoAttack": "渐进式多轮升级",
                "TreeAttack": "树状分支探索",
                "TAPAttack": "树状攻击提示",
                "PAIRAttack": "点对点迭代优化",
                "AnecdoctorAttack": " anecdote 注入",
            }

            for strat, count in sorted(dist.items(), key=lambda x: -x[1]):
                pct = count / total * 100 if total > 0 else 0
                desc = STRATEGY_DESC.get(strat, "智能匹配选择的策略")
                table.add_row(strat, desc, str(count), f"{pct:.1f}%")

            self.console.print(table)
        else:
            print("\n######## 攻击策略选择结果 ########")
            print("说明：Count = 使用该策略的载荷数量，Percentage = 占总数的比例")

            STRATEGY_DESC = {
                "PromptSendingAttack": "单轮直接发送（最简攻击）",
                "CrescendoAttack": "渐进式多轮升级",
                "TreeAttack": "树状分支探索",
                "TAPAttack": "树状攻击提示",
                "PAIRAttack": "点对点迭代优化",
                "AnecdoctorAttack": "anecdote 注入",
            }

            for strat, count in sorted(dist.items(), key=lambda x: -x[1]):
                pct = count / total * 100 if total > 0 else 0
                desc = STRATEGY_DESC.get(strat, "智能匹配选择的策略")
                print(f"  {strat:<22} {desc:<22} {count:>3} ({pct:.1f}%)")

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
                conf_str = (
                    f"[dim](conf={step.confidence:.2f})[/dim]"
                    if step.confidence < 1.0
                    else ""
                )
                self.console.print(
                    f"  [cyan]{step.stage:16s}[/cyan] "
                    f"{step.output_summary} "
                    f"[dim]← {step.reason}[/dim] "
                    f"{conf_str}"
                )
        else:
            print(f"\n=== Decision Trace: {log.payload_id} ===")
            for step in log.steps:
                print(f"  [{step.stage:16s}] {step.output_summary} <- {step.reason}")

    def show_scorer_summary(self) -> None:
        """展示评分器选择摘要"""
        scorer_dist: Dict[str, int] = {}
        for log in self._logs:
            for step in log.steps:
                if step.stage == "scorer_select":
                    output = step.output_summary
                    scorer_dist[output] = scorer_dist.get(output, 0) + 1

        if not scorer_dist:
            return

        total = sum(scorer_dist.values())

        if self.console and HAS_RICH:
            self.console.print()
            self.console.print("[bold]######## 评分器选择结果 ########[/bold]")
            self.console.print(
                "[dim]说明：Count = 使用该评分器的载荷数量，Percentage = 占总数的比例[/dim]"
            )
            self.console.print()

            table = Table(
                title=f"共 {total} 个载荷",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold green",
            )
            table.add_column("评分器", style="bold", min_width=24)
            table.add_column("说明", min_width=20)
            table.add_column("数量", justify="right", min_width=6)
            table.add_column("占比", justify="right", min_width=8)

            # 评分器名称到中文说明的映射
            SCORER_DESC = {
                "SubStringScorer": "子串匹配（检测目标字符串）",
                "SelfAskRefusalScorer": "拒绝检测（判断模型是否拒绝）",
                "SelfAskTrueFalseScorer": "真假判断（自定义问题评分）",
                "SelfAskCategoryScorer": "分类评分（多类别判定）",
            }

            for scorer, count in sorted(scorer_dist.items(), key=lambda x: -x[1]):
                pct = count / total * 100 if total > 0 else 0
                desc = SCORER_DESC.get(scorer, scorer)
                table.add_row(scorer, desc, str(count), f"{pct:.1f}%")

            self.console.print(table)
        else:
            print("\n######## 评分器选择结果 ########")
            print("说明：Count = 使用该评分器的载荷数量，Percentage = 占总数的比例")

            SCORER_DESC = {
                "SubStringScorer": "子串匹配（检测目标字符串）",
                "SelfAskRefusalScorer": "拒绝检测（判断模型是否拒绝）",
                "SelfAskTrueFalseScorer": "真假判断（自定义问题评分）",
                "SelfAskCategoryScorer": "分类评分（多类别判定）",
            }

            for scorer, count in sorted(scorer_dist.items(), key=lambda x: -x[1]):
                pct = count / total * 100 if total > 0 else 0
                desc = SCORER_DESC.get(scorer, scorer)
                print(f"  {scorer:<24} {desc:<20} {count:>3} ({pct:.1f}%)")

    def show_full_report(self) -> None:
        """展示完整流水线报告（侦察 + 攻击）"""
        # 侦察摘要
        if self.has_recon:
            self.show_recon_summary()

        # 攻击摘要
        if self.has_attack:
            self.show_classification_summary()
            self.show_strategy_summary()
            self.show_scorer_summary()

        # 总摘要
        if self.console and HAS_RICH:
            self.console.print()
            self.console.print("[bold]═══ Pipeline Summary ═══[/bold]")
            summary = self.get_summary()

            # 侦察信息
            recon_info = ""
            if "recon" in summary:
                r = summary["recon"]
                recon_info = (
                    f"Recon: {r['tools_used']} | "
                    f"Vulns: {r['vulnerability_count']} | "
                    f"Risk: {r['risk_level']} | "
                )

            self.console.print(
                Panel(
                    f"{recon_info}"
                    f"Payloads: {summary['total_payloads']} | "
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
        result = {
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

        # 添加侦察日志（如果有）
        if self._recon_log:
            result["recon"] = {
                "target": self._recon_log.target,
                "tools_used": self._recon_log.tools_used,
                "vulnerability_count": self._recon_log.vulnerability_count,
                "risk_level": self._recon_log.risk_level,
                "profile_path": self._recon_log.profile_path,
                "duration_ms": self._recon_log.duration_ms,
                "steps": [
                    {
                        "stage": s.stage,
                        "input": s.input_summary,
                        "output": s.output_summary,
                        "reason": s.reason,
                        "confidence": s.confidence,
                    }
                    for s in self._recon_log.steps
                ],
            }

        return result

    def export_markdown(self, output_path: str) -> str:
        """
        导出 Markdown 格式流水线报告

        Returns:
            文件路径
        """
        summary = self.get_summary()
        lines = [
            "# Full Pipeline Report (Recon + Attack)",
            "",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
        ]

        # 侦察部分
        if "recon" in summary:
            r = summary["recon"]
            lines.extend([
                "## Reconnaissance Phase",
                "",
                f"- **Target:** {r['target']}",
                f"- **Tools:** {', '.join(r['tools_used'])}",
                f"- **Vulnerabilities:** {r['vulnerability_count']}",
                f"- **Risk Level:** {r['risk_level']}",
                f"- **Profile:** {r['profile_path']}",
                "",
            ])

        # 攻击部分
        lines.extend([
            "## Attack Phase",
            "",
            f"**Total Payloads:** {summary['total_payloads']}",
            "",
            "### Classification Distribution",
            "",
            "| Category | Count |",
            "|----------|-------|",
        ])
        for cat, count in sorted(summary["category_distribution"].items(), key=lambda x: -x[1]):
            lines.append(f"| {cat} | {count} |")

        lines.extend([
            "",
            "### Strategy Distribution",
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

        # 评分结果汇总
        scoring_results = []
        for log in self._logs:
            for step in log.steps:
                if step.stage == "scoring":
                    scoring_results.append({
                        "payload": log.payload_id[:40],
                        "scorer": step.metadata.get("scorer_name", ""),
                        "label": step.metadata.get("score_label", ""),
                        "value": step.metadata.get("score_value", ""),
                    })

        if scoring_results:
            lines.extend([
                "",
                "## Scoring Results",
                "",
                "| Payload | Scorer | Label | Value |",
                "|---------|--------|-------|-------|",
            ])
            for sr in scoring_results:
                lines.append(
                    f"| {sr['payload']} | {sr['scorer']} | {sr['label']} | {sr['value']} |"
                )
            lines.append("")

        content = "\n".join(lines)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        return output_path
