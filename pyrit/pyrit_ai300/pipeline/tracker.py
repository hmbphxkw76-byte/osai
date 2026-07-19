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

    def log_recon_aimap_garak_bridge(
        self,
        aimap_protocols: List[str],
        garak_endpoint: str,
        garak_model_type: str,
        garak_model_name: str,
    ) -> None:
        """
        记录 AIMAP→Garak 端点桥接步骤

        Args:
            aimap_protocols: AIMAP 检测到的协议列表
            garak_endpoint: Garak 使用的端点 URL
            garak_model_type: Garak 模型类型
            garak_model_name: Garak 模型名称
        """
        if not self._recon_log:
            return

        step = PipelineStep(
            stage="recon_aimap_garak_bridge",
            input_summary=f"aimap_protocols={','.join(aimap_protocols)}",
            output_summary=f"garak_endpoint={garak_endpoint}",
            reason=f"AIMAP 检测到 {', '.join(aimap_protocols)} → Garak 使用 {garak_model_type}/{garak_model_name}",
            confidence=0.9,
            metadata={
                "aimap_protocols": aimap_protocols,
                "garak_endpoint": garak_endpoint,
                "garak_model_type": garak_model_type,
                "garak_model_name": garak_model_name,
            },
        )
        self._recon_log.add_step(step)

        if self.verbose:
            self._print_step(
                "aimap→garak",
                f"协议: {', '.join(aimap_protocols)} → Garak: {garak_model_type}/{garak_model_name}",
                f"端点: {garak_endpoint}",
            )

    def log_recon_merge(
        self,
        tools_used: List[str],
        vuln_count: int,
        risk_level: str,
        duration_ms: float = 0.0,
        conflicts: Optional[List[Dict[str, Any]]] = None,
        cross_validated: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        """
        记录 ProfileMerger 合并结果

        Args:
            tools_used: 成功使用的工具列表
            vuln_count: 合并后漏洞总数
            risk_level: 综合风险等级
            duration_ms: 耗时（毫秒）
            conflicts: 冲突列表 [{owasp_id, tools, severities, description}]
            cross_validated: 交叉验证列表 [{owasp_id, tools, confidence}]
        """
        if not self._recon_log:
            return

        # 构建输出摘要（含冲突信息）
        output_parts = [f"vulns={vuln_count}", f"risk={risk_level}"]
        if conflicts:
            output_parts.append(f"conflicts={len(conflicts)}")
        if cross_validated:
            output_parts.append(f"cross_validated={len(cross_validated)}")

        step = PipelineStep(
            stage="recon_merge",
            input_summary=f"tools={','.join(tools_used)}",
            output_summary=", ".join(output_parts),
            reason=f"合并 {len(tools_used)} 个工具结果",
            duration_ms=duration_ms,
            metadata={
                "tools_used": tools_used,
                "vuln_count": vuln_count,
                "risk_level": risk_level,
                "conflicts": conflicts or [],
                "cross_validated": cross_validated or [],
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
            # 展示冲突详情
            if conflicts:
                for c in conflicts:
                    self._print_step(
                        "recon_conflict",
                        f"⚠ {c.get('owasp_id', '?')}: {', '.join(c.get('tools', []))} 结论不一致",
                        f"severity: {', '.join(c.get('severities', []))}",
                    )
            # 展示交叉验证结果
            if cross_validated:
                for cv in cross_validated:
                    self._print_step(
                        "recon_cross_val",
                        f"✓ {cv.get('owasp_id', '?')}: {', '.join(cv.get('tools', []))} 交叉验证",
                        f"confidence: {cv.get('confidence', 0):.2f}",
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

    def log_recon_optimization(
        self,
        stage: str,
        optimization_id: str,
        input_summary: str = "",
        output_summary: str = "",
        reason: str = "",
        confidence: float = 1.0,
        duration_ms: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        记录侦察优化阶段执行结果（OPT-A1~A6, OPT-G1~G6, OPT-D1~D5, OPT-M1~M2, OPT-E1~E3）

        Args:
            stage: 优化阶段名称（如 recon_parallel_dispatch / recon_cache_hit / recon_adaptive_timeout）
            optimization_id: 优化项 ID（如 OPT-A1 / OPT-E1）
            input_summary: 输入摘要
            output_summary: 输出摘要
            reason: 说明原因
            confidence: 置信度
            duration_ms: 耗时（毫秒）
            metadata: 附加元数据
        """
        if not self._recon_log:
            # 如果没有 recon_log，创建一个
            self._recon_log = ReconLog(target="")

        step = PipelineStep(
            stage=stage,
            input_summary=input_summary,
            output_summary=output_summary,
            reason=reason or f"{optimization_id}: {stage}",
            confidence=confidence,
            duration_ms=duration_ms,
            metadata={
                "optimization_id": optimization_id,
                **(metadata or {}),
            },
        )
        self._recon_log.add_step(step)

        if self.verbose:
            self._print_step(
                f"recon_opt:{optimization_id}",
                f"{optimization_id} | {input_summary}",
                f"{output_summary}" + (f" ({duration_ms:.0f}ms)" if duration_ms else ""),
            )

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

    def log_encoding_filter_owasp(
        self,
        owasp_id: str,
        total_converters: int,
        filtered_converters: List[str],
        duration_ms: float = 0.0,
    ) -> None:
        """
        记录编码选择第1阶段：OWASP 类别静态过滤

        Args:
            owasp_id: OWASP ID (如 "LLM01")
            total_converters: 过滤前转换器总数
            filtered_converters: 过滤后的转换器列表
            duration_ms: 耗时（毫秒）
        """
        step = PipelineStep(
            stage="encoding_filter_owasp",
            input_summary=f"owasp={owasp_id}, total={total_converters}",
            output_summary=f"compatible={len(filtered_converters)}",
            reason=f"OWASP 类别静态过滤: {total_converters} → {len(filtered_converters)}",
            confidence=1.0,
            duration_ms=duration_ms,
            metadata={
                "owasp_id": owasp_id,
                "total_converters": total_converters,
                "filtered_converters": filtered_converters,
                "excluded_count": total_converters - len(filtered_converters),
            },
        )
        self._add_step(step)

        if self.verbose:
            self._print_step(
                "encoding:owasp",
                f"[{owasp_id}] 静态过滤: {total_converters} → {len(filtered_converters)} 兼容",
                f"排除 {total_converters - len(filtered_converters)} 个不兼容转换器",
            )

    def log_encoding_filter_language(
        self,
        language: str,
        input_count: int,
        filtered_converters: List[str],
        excluded: List[str],
        duration_ms: float = 0.0,
    ) -> None:
        """
        记录编码选择第1阶段：语言兼容性过滤

        Args:
            language: 语言代码 (如 "en", "zh")
            input_count: 过滤前转换器数量
            filtered_converters: 过滤后的转换器列表
            excluded: 被排除的转换器列表
            duration_ms: 耗时（毫秒）
        """
        step = PipelineStep(
            stage="encoding_filter_language",
            input_summary=f"lang={language}, input={input_count}",
            output_summary=f"compatible={len(filtered_converters)}, excluded={len(excluded)}",
            reason=f"语言兼容性过滤 ({language}): 排除 {len(excluded)} 个不兼容编码",
            confidence=1.0,
            duration_ms=duration_ms,
            metadata={
                "language": language,
                "input_count": input_count,
                "filtered_converters": filtered_converters,
                "excluded_converters": excluded,
            },
        )
        self._add_step(step)

        if self.verbose:
            excluded_str = ", ".join(excluded[:5])
            if len(excluded) > 5:
                excluded_str += f" ...+{len(excluded)-5}个"
            self._print_step(
                "encoding:lang",
                f"[{language}] 语言过滤: {input_count} → {len(filtered_converters)}",
                f"排除: {excluded_str}" if excluded else "无排除",
            )

    def log_encoding_probe(
        self,
        converter_count: int,
        probe_payload_count: int,
        pass_rates: Dict[str, float],
        threshold: float = 0.3,
        duration_ms: float = 0.0,
    ) -> None:
        """
        记录编码选择第2阶段：目标自适应探测

        Args:
            converter_count: 探测的转换器数量
            probe_payload_count: 探针 payload 数量
            pass_rates: {converter_name: pass_rate} 通过率映射
            threshold: 有效阈值
            duration_ms: 耗时（毫秒）
        """
        effective = sum(1 for r in pass_rates.values() if r >= threshold)
        total_probes = converter_count * probe_payload_count

        # 按通过率排序，取前10个
        top_converters = sorted(pass_rates.items(), key=lambda x: x[1], reverse=True)[:10]
        top_str = ", ".join(f"{n}:{r:.0%}" for n, r in top_converters)

        step = PipelineStep(
            stage="encoding_probe",
            input_summary=f"converters={converter_count}, probes={probe_payload_count}, total_requests={total_probes}",
            output_summary=f"effective={effective}/{converter_count}, threshold={threshold:.0%}",
            reason=f"目标探测完成: {effective}/{converter_count} 编码有效 | 顶部: {top_str}",
            confidence=0.85,
            duration_ms=duration_ms,
            metadata={
                "converter_count": converter_count,
                "probe_payload_count": probe_payload_count,
                "total_probes": total_probes,
                "pass_rates": pass_rates,
                "effective_count": effective,
                "threshold": threshold,
            },
        )
        self._add_step(step)

        if self.verbose:
            self._print_step(
                "encoding:probe",
                f"目标探测: {effective}/{converter_count} 编码有效 (阈值 {threshold:.0%})",
                f"顶部: {top_str}",
            )

    def log_encoding_selection(
        self,
        payload_index: int,
        language: str,
        selected_encodings: List[str],
        candidates_count: int,
        target_profile_built: bool = False,
    ) -> None:
        """
        记录编码选择第3阶段：最终编码选择结果

        Args:
            payload_index: payload 索引
            language: payload 语言
            selected_encodings: 选中的编码列表
            candidates_count: 候选编码数量
            target_profile_built: 是否使用了目标画像
        """
        step = PipelineStep(
            stage="encoding_selection",
            input_summary=f"payload_idx={payload_index}, lang={language}, candidates={candidates_count}",
            output_summary=f"selected={len(selected_encodings)} [{', '.join(selected_encodings)}]",
            reason=f"最终选择: {len(selected_encodings)}/{candidates_count} 编码"
                + (" (基于目标画像)" if target_profile_built else " (无画像，使用候选)"),
            confidence=0.9 if target_profile_built else 0.7,
            metadata={
                "payload_index": payload_index,
                "language": language,
                "selected_encodings": selected_encodings,
                "candidates_count": candidates_count,
                "target_profile_built": target_profile_built,
            },
        )
        self._add_step(step)

        if self.verbose:
            self._print_step(
                "encoding:select",
                f"[{payload_index}] {language} → {len(selected_encodings)} 编码",
                f"{', '.join(selected_encodings)}",
            )

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

    # ──────────────────────────────────────────────────────────────────────────
    # P0-P3 优化阶段记录方法
    # ──────────────────────────────────────────────────────────────────────────

    def log_dedup(
        self,
        before_count: int,
        after_count: int,
        threshold: float = 0.85,
        removed_samples: Optional[List[str]] = None,
        duration_ms: float = 0.0,
    ) -> None:
        """
        记录载荷去重步骤 (P3-J)

        Args:
            before_count: 去重前载荷数量
            after_count: 去重后载荷数量
            threshold: Jaccard 相似度阈值
            removed_samples: 被移除的载荷样本（最多 5 个）
            duration_ms: 耗时
        """
        removed_count = before_count - after_count
        step = PipelineStep(
            stage="dedup",
            input_summary=f"before={before_count}",
            output_summary=f"after={after_count}, removed={removed_count}",
            reason=f"Jaccard 相似度 >= {threshold:.2f} 视为重复，移除 {removed_count} 个",
            confidence=1.0,
            duration_ms=duration_ms,
            metadata={
                "before_count": before_count,
                "after_count": after_count,
                "removed_count": removed_count,
                "threshold": threshold,
                "removed_samples": (removed_samples or [])[:5],
            },
        )
        self._add_step(step)

        if self.verbose:
            self._print_step(
                "dedup",
                f"{before_count} → {after_count} (去除 {removed_count} 个)",
                f"阈值={threshold:.2f}",
            )

    def log_converter_selection(
        self,
        payload_idx: int,
        language: str,
        technique: str,
        owasp_id: str,
        candidates_count: int,
        selected_converters: List[str],
        reason: str = "",
    ) -> None:
        """
        记录逐载荷转换器选择步骤 (P0-A)

        Args:
            payload_idx: 载荷索引
            language: 载荷语言
            technique: 载荷技术类别
            owasp_id: OWASP ID
            candidates_count: 候选转换器数量
            selected_converters: 最终选中的转换器列表
            reason: 选择原因
        """
        step = PipelineStep(
            stage="converter_selection",
            input_summary=(
                f"idx={payload_idx}, lang={language}, technique={technique}, "
                f"owasp={owasp_id}, candidates={candidates_count}"
            ),
            output_summary=f"selected={len(selected_converters)} [{', '.join(selected_converters)}]",
            reason=reason or f"基于 {technique}/{language} 选择 {len(selected_converters)} 个转换器",
            confidence=0.9,
            metadata={
                "payload_idx": payload_idx,
                "language": language,
                "technique": technique,
                "owasp_id": owasp_id,
                "candidates_count": candidates_count,
                "selected_converters": selected_converters,
            },
        )
        self._add_step(step)

        if self.verbose:
            self._print_step(
                "converter_select",
                f"[{payload_idx}] {language}/{technique} → {len(selected_converters)} 转换器",
                ", ".join(selected_converters),
            )

    def log_fallback_enrich(
        self,
        payload_idx: int,
        fallback_count: int,
        converter_combos: int,
        enriched_chain: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        """
        记录 Fallback 链增强步骤 (P0-B)

        Args:
            payload_idx: 载荷索引
            fallback_count: 回退项数量
            converter_combos: 转换器组合总数
            enriched_chain: 增强后的回退链（可选）
        """
        total_attempts = fallback_count + converter_combos
        step = PipelineStep(
            stage="fallback_enrich",
            input_summary=f"idx={payload_idx}, fallback_items={fallback_count}",
            output_summary=f"converter_combos={converter_combos}, total_attempts={total_attempts}",
            reason=f"每个回退项附加 converter_override，覆盖编码被过滤场景",
            confidence=0.85,
            metadata={
                "payload_idx": payload_idx,
                "fallback_count": fallback_count,
                "converter_combos": converter_combos,
                "total_attempts": total_attempts,
                "enriched_chain": enriched_chain or [],
            },
        )
        self._add_step(step)

        if self.verbose:
            self._print_step(
                "fallback_enrich",
                f"[{payload_idx}] {fallback_count} 回退项 x {converter_combos} 转换器 = {total_attempts} 种尝试",
            )

    def log_early_stop(
        self,
        consecutive_failures: int,
        skipped_count: int,
        threshold: int = 5,
    ) -> None:
        """
        记录早停触发步骤 (P1-E)

        Args:
            consecutive_failures: 连续失败次数
            skipped_count: 被跳过的载荷数量
            threshold: 触发阈值
        """
        step = PipelineStep(
            stage="early_stop",
            input_summary=f"consecutive_failures={consecutive_failures}",
            output_summary=f"skipped={skipped_count}",
            reason=f"连续 {consecutive_failures} 次失败（>= {threshold}），触发早停",
            confidence=1.0,
            metadata={
                "consecutive_failures": consecutive_failures,
                "skipped_count": skipped_count,
                "threshold": threshold,
            },
        )
        self._add_step(step)

        if self.verbose:
            self._print_step(
                "early_stop",
                f"WARNING: 连续 {consecutive_failures} 次失败，触发早停（跳过 {skipped_count} 个载荷）",
            )

    def log_best_combinations(
        self,
        combinations: List[Dict[str, Any]],
        top_count: int = 10,
    ) -> None:
        """
        记录高成功率攻击组合步骤 (P0-C)

        Args:
            combinations: 组合列表，每项含 category/attack_family/attack_class/success/failure/total/rate
            top_count: 返回的 Top-N 数量
        """
        top = combinations[:top_count]
        # 构建 top 摘要（避免 f-string 中使用反斜杠）
        top_parts = []
        for c in top[:5]:
            cat = c.get("category", "?")
            rate = c.get("rate", 0)
            top_parts.append(f"{cat}:{rate:.0%}")
        top_summary = ", ".join(top_parts)
        step = PipelineStep(
            stage="best_combinations",
            input_summary=f"total_combos={len(combinations)}",
            output_summary=f"top_{top_count}=[{top_summary}]",
            reason=f"从执行结果提取 Top-{top_count} 高成功率组合",
            confidence=1.0,
            metadata={
                "combinations": combinations,
                "top_count": top_count,
            },
        )
        self._add_step(step)

        if self.verbose:
            self._print_step(
                "best_combos",
                f"Top-{top_count} 组合已计算",
                f"最优: {top[0]['category']}/{top[0].get('attack_class','?')} {top[0].get('rate',0):.0%}" if top else "无数据",
            )

    def log_feedback(
        self,
        success_rate: float,
        recommended_families: List[str],
        recommended_aggression: str,
        best_strategies: Optional[List[str]] = None,
        worst_strategies: Optional[List[str]] = None,
        best_combinations: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        """
        记录反馈分析步骤

        Args:
            success_rate: 总体成功率
            recommended_families: 推荐的攻击族列表
            recommended_aggression: 推荐的攻击强度
            best_strategies: 最优策略列表
            worst_strategies: 最差策略列表
            best_combinations: 最优组合列表
        """
        step = PipelineStep(
            stage="feedback",
            input_summary=f"results_analyzed",
            output_summary=f"rate={success_rate:.1%}, families={','.join(recommended_families[:3])}",
            reason=f"成功率 {success_rate:.1%} → 推荐 {recommended_aggression} 强度",
            confidence=0.9,
            metadata={
                "success_rate": success_rate,
                "recommended_families": recommended_families,
                "recommended_aggression": recommended_aggression,
                "best_strategies": best_strategies or [],
                "worst_strategies": worst_strategies or [],
                "best_combinations": best_combinations or [],
            },
        )
        self._add_step(step)

        if self.verbose:
            self._print_step(
                "feedback",
                f"成功率: {success_rate:.1%} | 推荐: {','.join(recommended_families[:3])} | 强度: {recommended_aggression}",
            )

    def log_mutation(
        self,
        mutation_count: int,
        strategies: List[str],
        source_count: int = 0,
    ) -> None:
        """
        记录变异体生成步骤 (P1-F)

        Args:
            mutation_count: 生成的变异体数量
            strategies: 使用的变异策略列表
            source_count: 源载荷数量
        """
        step = PipelineStep(
            stage="mutation",
            input_summary=f"source={source_count}, strategies={','.join(strategies)}",
            output_summary=f"mutations={mutation_count}",
            reason=f"从 {source_count} 个成功载荷生成 {mutation_count} 个变异体",
            confidence=0.9,
            metadata={
                "mutation_count": mutation_count,
                "strategies": strategies,
                "source_count": source_count,
            },
        )
        self._add_step(step)

        if self.verbose:
            self._print_step(
                "mutation",
                f"生成 {mutation_count} 个变异体 ({'+'.join(strategies)})",
            )

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
            recon_summary = {
                "target": self._recon_log.target,
                "tools_used": self._recon_log.tools_used,
                "vulnerability_count": self._recon_log.vulnerability_count,
                "risk_level": self._recon_log.risk_level,
                "profile_path": self._recon_log.profile_path,
                "duration_ms": self._recon_log.duration_ms,
            }
            # 添加冲突和交叉验证信息
            for step in self._recon_log.steps:
                if step.stage == "recon_merge":
                    if step.metadata.get("conflicts"):
                        recon_summary["conflicts"] = step.metadata["conflicts"]
                    if step.metadata.get("cross_validated"):
                        recon_summary["cross_validated"] = step.metadata["cross_validated"]
                    break
            summary["recon"] = recon_summary

        return summary

    # ──────────────────────────────────────────────────────────────────────────
    # 终端展示方法
    # ──────────────────────────────────────────────────────────────────────────

    def show_recon_summary(self) -> None:
        """展示侦察阶段摘要（含冲突检测和交叉验证结果）"""
        if not self._recon_log:
            return

        # 从 merge step 获取冲突和交叉验证信息
        merge_step = None
        for step in self._recon_log.steps:
            if step.stage == "recon_merge":
                merge_step = step
                break

        conflicts = merge_step.metadata.get("conflicts", []) if merge_step else []
        cross_validated = merge_step.metadata.get("cross_validated", []) if merge_step else []

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

            # 展示冲突检测
            if conflicts:
                self.console.print()
                self.console.print("[bold red]  ⚠ 工具间冲突（severity 差异 ≥ 2）:[/bold red]")
                for c in conflicts:
                    owasp_id = c.get("owasp_id", "?")
                    tools = ", ".join(c.get("tools", []))
                    severities = ", ".join(c.get("severities", []))
                    desc = c.get("description", "")[:60]
                    self.console.print(
                        f"    [red]• {owasp_id}[/red]: {tools} → "
                        f"severity=[{severities}] {desc}"
                    )

            # 展示交叉验证
            if cross_validated:
                self.console.print()
                self.console.print("[bold green]  ✓ 多工具交叉验证（置信度提升）:[/bold green]")
                for cv in cross_validated:
                    owasp_id = cv.get("owasp_id", "?")
                    tools = ", ".join(cv.get("tools", []))
                    conf = cv.get("confidence", 0)
                    self.console.print(
                        f"    [green]• {owasp_id}[/green]: {tools} → "
                        f"confidence={conf:.2f}"
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

            # 展示冲突检测
            if conflicts:
                print("\n  ⚠ 工具间冲突（severity 差异 ≥ 2）:")
                for c in conflicts:
                    owasp_id = c.get("owasp_id", "?")
                    tools = ", ".join(c.get("tools", []))
                    severities = ", ".join(c.get("severities", []))
                    desc = c.get("description", "")[:60]
                    print(f"    • {owasp_id}: {tools} → severity=[{severities}] {desc}")

            # 展示交叉验证
            if cross_validated:
                print("\n  ✓ 多工具交叉验证（置信度提升）:")
                for cv in cross_validated:
                    owasp_id = cv.get("owasp_id", "?")
                    tools = ", ".join(cv.get("tools", []))
                    conf = cv.get("confidence", 0)
                    print(f"    • {owasp_id}: {tools} → confidence={conf:.2f}")

    def show_recon_optimizations(self) -> None:
        """
        展示侦察优化阶段摘要（OPT-A1~A6, OPT-G1~G6, OPT-D1~D5, OPT-M1~M2, OPT-E1~E3）

        从 recon_log 中提取所有 stage 以 recon_ 开头且含 optimization_id 的步骤，
        按 optimization_id 分组展示。
        """
        if not self._recon_log:
            return

        # 收集所有优化步骤
        opt_steps = []
        for step in self._recon_log.steps:
            opt_id = step.metadata.get("optimization_id", "")
            if opt_id:
                opt_steps.append(step)

        if not opt_steps:
            return

        if self.console and HAS_RICH:
            self.console.print()
            self.console.print("[bold magenta]######## 侦察阶段优化（OPT-A/G/D/M/E） ########[/bold magenta]")
            self.console.print()

            table = Table(
                title=f"共 {len(opt_steps)} 项优化已执行",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold magenta",
            )
            table.add_column("OPT-ID", style="bold", min_width=8)
            table.add_column("Stage", min_width=20)
            table.add_column("Input", min_width=25)
            table.add_column("Output", min_width=25)
            table.add_column("耗时", justify="right", min_width=8)

            for step in opt_steps:
                opt_id = step.metadata.get("optimization_id", "?")
                stage = step.stage
                inp = step.input_summary[:40] if step.input_summary else ""
                outp = step.output_summary[:40] if step.output_summary else ""
                dur = f"{step.duration_ms:.0f}ms" if step.duration_ms else "-"
                table.add_row(opt_id, stage, inp, outp, dur)

            self.console.print(table)
        else:
            print("\n######## 侦察阶段优化（OPT-A/G/D/M/E） ########")
            for step in opt_steps:
                opt_id = step.metadata.get("optimization_id", "?")
                print(f"  {opt_id} | {step.stage}: {step.output_summary}")

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

    def show_encoding_summary(self) -> None:
        """展示编码选择三阶段汇总"""
        # 收集编码选择各阶段步骤
        owasp_steps = []
        lang_steps = []
        probe_steps = []
        selection_steps = []

        for log in self._logs:
            for step in log.steps:
                if step.stage == "encoding_filter_owasp":
                    owasp_steps.append(step)
                elif step.stage == "encoding_filter_language":
                    lang_steps.append(step)
                elif step.stage == "encoding_probe":
                    probe_steps.append(step)
                elif step.stage == "encoding_selection":
                    selection_steps.append(step)

        if not any([owasp_steps, lang_steps, probe_steps, selection_steps]):
            return

        if self.console and HAS_RICH:
            self.console.print()
            self.console.print("[bold magenta]######## 智能编码选择 ########[/bold magenta]")

            # 阶段1a: OWASP 静态过滤
            if owasp_steps:
                self.console.print()
                self.console.print("[bold cyan]  阶段1a: OWASP 类别静态过滤[/bold cyan]")
                table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
                table.add_column("OWASP ID", min_width=10)
                table.add_column("过滤前", justify="right", min_width=8)
                table.add_column("过滤后", justify="right", min_width=8)
                table.add_column("排除", justify="right", min_width=8)
                for step in owasp_steps:
                    meta = step.metadata
                    table.add_row(
                        meta.get("owasp_id", "?"),
                        str(meta.get("total_converters", "?")),
                        str(len(meta.get("filtered_converters", []))),
                        str(meta.get("excluded_count", "?")),
                    )
                self.console.print(table)

            # 阶段1b: 语言兼容性过滤
            if lang_steps:
                self.console.print()
                self.console.print("[bold cyan]  阶段1b: 语言兼容性过滤[/bold cyan]")
                table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
                table.add_column("语言", min_width=8)
                table.add_column("过滤前", justify="right", min_width=8)
                table.add_column("过滤后", justify="right", min_width=8)
                table.add_column("排除的转换器", min_width=30)
                for step in lang_steps:
                    meta = step.metadata
                    excluded = meta.get("excluded_converters", [])
                    excluded_str = ", ".join(excluded[:6])
                    if len(excluded) > 6:
                        excluded_str += f" ...+{len(excluded)-6}个"
                    table.add_row(
                        meta.get("language", "?"),
                        str(meta.get("input_count", "?")),
                        str(len(meta.get("filtered_converters", []))),
                        excluded_str or "(无)",
                    )
                self.console.print(table)

            # 阶段2: 目标探测
            if probe_steps:
                self.console.print()
                self.console.print("[bold yellow]  阶段2: 目标自适应探测[/bold yellow]")
                for step in probe_steps:
                    meta = step.metadata
                    pass_rates = meta.get("pass_rates", {})
                    threshold = meta.get("threshold", 0.3)

                    table = Table(box=box.SIMPLE, show_header=True, header_style="bold yellow")
                    table.add_column("转换器", min_width=20)
                    table.add_column("通过率", justify="right", min_width=10)
                    table.add_column("状态", min_width=8)

                    for name, rate in sorted(pass_rates.items(), key=lambda x: x[1], reverse=True):
                        status = "✓ 有效" if rate >= threshold else "✗ 无效"
                        table.add_row(name, f"{rate:.0%}", status)

                    self.console.print(table)
                    self.console.print(
                        f"[dim]  探测请求: {meta.get('total_probes', '?')} | "
                        f"有效: {meta.get('effective_count', '?')}/{meta.get('converter_count', '?')} | "
                        f"阈值: {threshold:.0%}[/dim]"
                    )

            # 阶段3: 最终选择统计
            if selection_steps:
                self.console.print()
                self.console.print("[bold green]  阶段3: 编码选择结果[/bold green]")
                # 统计编码使用频率
                encoding_usage: Dict[str, int] = {}
                encoding_by_lang: Dict[str, Dict[str, int]] = {}
                for step in selection_steps:
                    meta = step.metadata
                    lang = meta.get("language", "unknown")
                    for enc in meta.get("selected_encodings", []):
                        encoding_usage[enc] = encoding_usage.get(enc, 0) + 1
                        if lang not in encoding_by_lang:
                            encoding_by_lang[lang] = {}
                        encoding_by_lang[lang][enc] = encoding_by_lang[lang].get(enc, 0) + 1

                table = Table(box=box.SIMPLE, show_header=True, header_style="bold green")
                table.add_column("编码", min_width=20)
                table.add_column("使用次数", justify="right", min_width=10)
                table.add_column("占比", justify="right", min_width=8)
                table.add_column("适用语言", min_width=15)

                for name, count in sorted(encoding_usage.items(), key=lambda x: x[1], reverse=True):
                    pct = count / len(selection_steps) * 100
                    langs = [lang for lang, encs in encoding_by_lang.items() if name in encs]
                    table.add_row(name, str(count), f"{f'{pct:.0f}%'}", ", ".join(langs))

                self.console.print(table)
                self.console.print(
                    f"[dim]  共 {len(selection_steps)} 个 payload 参与编码选择[/dim]"
                )

        else:
            # 非 Rich 模式
            print("\n######## 智能编码选择 ########")
            if owasp_steps:
                print("\n  阶段1a: OWASP 类别静态过滤")
                for step in owasp_steps:
                    meta = step.metadata
                    print(
                        f"    {meta.get('owasp_id', '?')}: "
                        f"{meta.get('total_converters', '?')} → "
                        f"{len(meta.get('filtered_converters', []))} "
                        f"(排除 {meta.get('excluded_count', '?')})"
                    )
            if lang_steps:
                print("\n  阶段1b: 语言兼容性过滤")
                for step in lang_steps:
                    meta = step.metadata
                    excluded = meta.get("excluded_converters", [])
                    print(
                        f"    {meta.get('language', '?')}: "
                        f"{meta.get('input_count', '?')} → "
                        f"{len(meta.get('filtered_converters', []))} "
                        f"(排除: {', '.join(excluded[:5])}{'...' if len(excluded) > 5 else ''})"
                    )
            if probe_steps:
                print("\n  阶段2: 目标自适应探测")
                for step in probe_steps:
                    meta = step.metadata
                    pass_rates = meta.get("pass_rates", {})
                    threshold = meta.get("threshold", 0.3)
                    for name, rate in sorted(pass_rates.items(), key=lambda x: x[1], reverse=True):
                        status = "有效" if rate >= threshold else "无效"
                        print(f"    {name}: {rate:.0%} ({status})")
            if selection_steps:
                print("\n  阶段3: 编码选择结果")
                encoding_usage: Dict[str, int] = {}
                for step in selection_steps:
                    for enc in step.metadata.get("selected_encodings", []):
                        encoding_usage[enc] = encoding_usage.get(enc, 0) + 1
                for name, count in sorted(encoding_usage.items(), key=lambda x: x[1], reverse=True):
                    print(f"    {name}: {count} 次")

    def show_converter_summary(self) -> None:
        """展示逐载荷转换器选择摘要 (P0-A)"""
        selection_steps = []
        for log in self._logs:
            for step in log.steps:
                if step.stage == "converter_selection":
                    selection_steps.append(step)

        if not selection_steps:
            return

        if self.console and HAS_RICH:
            self.console.print()
            self.console.print("[bold magenta]######## 逐载荷转换器选择 ########[/bold magenta]")
            self.console.print(
                "[dim]说明：基于每个载荷的 PayloadProfile（语言/技术/OWASP）独立选择最优转换器[/dim]"
            )
            self.console.print()

            table = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta")
            table.add_column("#", justify="right", min_width=4)
            table.add_column("语言", min_width=6)
            table.add_column("技术", min_width=12)
            table.add_column("OWASP", min_width=8)
            table.add_column("选中转换器", min_width=40)

            for step in selection_steps:
                meta = step.metadata
                table.add_row(
                    str(meta.get("payload_idx", "?")),
                    meta.get("language", "?"),
                    meta.get("technique", "?"),
                    meta.get("owasp_id", "?"),
                    ", ".join(meta.get("selected_converters", [])),
                )
            self.console.print(table)
        else:
            print("\n######## 逐载荷转换器选择 ########")
            for step in selection_steps:
                meta = step.metadata
                print(
                    f"  [{meta.get('payload_idx', '?')}] "
                    f"{meta.get('language', '?')}/{meta.get('technique', '?')} → "
                    f"{', '.join(meta.get('selected_converters', []))}"
                )

    def show_best_combinations(self) -> None:
        """展示高成功率攻击组合 (P0-C)"""
        combo_steps = []
        for log in self._logs:
            for step in log.steps:
                if step.stage == "best_combinations":
                    combo_steps.append(step)

        if not combo_steps:
            return

        # 取最后一个 best_combinations 步骤（最终结果）
        last_step = combo_steps[-1]
        combinations = last_step.metadata.get("combinations", [])

        if not combinations:
            return

        if self.console and HAS_RICH:
            self.console.print()
            self.console.print("[bold green]######## 高成功率攻击组合 (Top-10) ########[/bold green]")
            self.console.print(
                "[dim]说明：从执行结果提取 payload_category x attack_family x attack_class 的成功率[/dim]"
            )
            self.console.print()

            table = Table(box=box.SIMPLE, show_header=True, header_style="bold green")
            table.add_column("#", justify="right", min_width=4)
            table.add_column("载荷类别", min_width=20)
            table.add_column("攻击族", min_width=10)
            table.add_column("攻击类", min_width=22)
            table.add_column("成功", justify="right", min_width=6)
            table.add_column("失败", justify="right", min_width=6)
            table.add_column("成功率", justify="right", min_width=8)

            for i, c in enumerate(combinations[:10], 1):
                rate = c.get("rate", 0)
                rate_str = f"{rate:.0%}"
                table.add_row(
                    str(i),
                    c.get("category", "?"),
                    c.get("attack_family", "?"),
                    c.get("attack_class", "?"),
                    str(c.get("success", 0)),
                    str(c.get("failure", 0)),
                    rate_str,
                )
            self.console.print(table)
        else:
            print("\n######## 高成功率攻击组合 (Top-10) ########")
            for i, c in enumerate(combinations[:10], 1):
                print(
                    f"  {i}. {c.get('category', '?')}/{c.get('attack_class', '?')} "
                    f"{c.get('rate', 0):.0%} ({c.get('success', 0)}/{c.get('total', 0)})"
                )

    def show_feedback_summary(self) -> None:
        """展示反馈分析与变异摘要 (P1-F)"""
        feedback_steps = []
        mutation_steps = []
        for log in self._logs:
            for step in log.steps:
                if step.stage == "feedback":
                    feedback_steps.append(step)
                elif step.stage == "mutation":
                    mutation_steps.append(step)

        if not feedback_steps and not mutation_steps:
            return

        if self.console and HAS_RICH:
            self.console.print()
            self.console.print("[bold yellow]######## 反馈分析与变异 ########[/bold yellow]")

            if feedback_steps:
                last_fb = feedback_steps[-1]
                meta = last_fb.metadata
                self.console.print(
                    f"  成功率: [bold]{meta.get('success_rate', 0):.1%}[/bold] | "
                    f"推荐强度: [bold]{meta.get('recommended_aggression', '?')}[/bold]"
                )
                families = meta.get("recommended_families", [])
                if families:
                    self.console.print(f"  推荐攻击族: {', '.join(families)}")
                best_strats = meta.get("best_strategies", [])
                if best_strats:
                    self.console.print(f"  最优策略: {', '.join(best_strats[:5])}")

            if mutation_steps:
                last_mut = mutation_steps[-1]
                meta = last_mut.metadata
                self.console.print(
                    f"  变异体: [bold]{meta.get('mutation_count', 0)}[/bold] 个 "
                    f"(策略: {', '.join(meta.get('strategies', []))})"
                )
        else:
            print("\n######## 反馈分析与变异 ########")
            if feedback_steps:
                meta = feedback_steps[-1].metadata
                print(f"  成功率: {meta.get('success_rate', 0):.1%} | 强度: {meta.get('recommended_aggression', '?')}")
            if mutation_steps:
                meta = mutation_steps[-1].metadata
                print(f"  变异体: {meta.get('mutation_count', 0)} 个 ({', '.join(meta.get('strategies', []))})")

    def show_dedup_summary(self) -> None:
        """展示载荷去重摘要 (P3-J)"""
        dedup_steps = []
        for log in self._logs:
            for step in log.steps:
                if step.stage == "dedup":
                    dedup_steps.append(step)

        if not dedup_steps:
            return

        last_step = dedup_steps[-1]
        meta = last_step.metadata

        if self.console and HAS_RICH:
            self.console.print()
            self.console.print("[bold cyan]######## 载荷去重 ########[/bold cyan]")
            self.console.print(
                f"  {meta.get('before_count', '?')} → {meta.get('after_count', '?')} "
                f"(去除 {meta.get('removed_count', 0)} 个, 阈值={meta.get('threshold', 0.85):.2f})"
            )
        else:
            print("\n######## 载荷去重 ########")
            print(f"  {meta.get('before_count', '?')} → {meta.get('after_count', '?')} (去除 {meta.get('removed_count', 0)} 个)")

    def show_early_stop_summary(self) -> None:
        """展示早停触发摘要 (P1-E)"""
        es_steps = []
        for log in self._logs:
            for step in log.steps:
                if step.stage == "early_stop":
                    es_steps.append(step)

        if not es_steps:
            return

        if self.console and HAS_RICH:
            self.console.print()
            self.console.print("[bold red]######## 早停触发 ########[/bold red]")
            for step in es_steps:
                meta = step.metadata
                self.console.print(
                    f"  连续 {meta.get('consecutive_failures', 0)} 次失败 "
                    f"(阈值 {meta.get('threshold', 5)}) → 跳过 {meta.get('skipped_count', 0)} 个载荷"
                )
        else:
            print("\n######## 早停触发 ########")
            for step in es_steps:
                meta = step.metadata
                print(f"  连续 {meta.get('consecutive_failures', 0)} 次失败 → 跳过 {meta.get('skipped_count', 0)} 个")

    def show_full_report(self) -> None:
        """展示完整流水线报告（全阶段 ######## 格式标题）"""
        # 侦察摘要
        if self.has_recon:
            self.show_recon_summary()
            self.show_recon_optimizations()

        # 载荷去重
        self.show_dedup_summary()

        # 攻击摘要
        if self.has_attack:
            self.show_classification_summary()
            self.show_converter_summary()
            self.show_strategy_summary()
            self.show_scorer_summary()

        # 编码选择摘要
        self.show_encoding_summary()

        # 早停
        self.show_early_stop_summary()

        # 高成功率组合
        self.show_best_combinations()

        # 反馈与变异
        self.show_feedback_summary()

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

    @property
    def encoding_steps(self) -> List[PipelineStep]:
        """获取所有编码选择相关步骤"""
        steps = []
        for log in self._logs:
            for step in log.steps:
                if step.stage.startswith("encoding_"):
                    steps.append(step)
        return steps

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

            # 添加侦察优化阶段日志（OPT-A/G/D/M/E）
            opt_steps = [
                {
                    "stage": s.stage,
                    "optimization_id": s.metadata.get("optimization_id", ""),
                    "input": s.input_summary,
                    "output": s.output_summary,
                    "reason": s.reason,
                    "confidence": s.confidence,
                    "duration_ms": s.duration_ms,
                    "metadata": s.metadata,
                }
                for s in self._recon_log.steps
                if s.metadata.get("optimization_id")
            ]
            if opt_steps:
                result["recon_optimizations"] = opt_steps

        # 添加编码选择日志（如果有）
        enc_steps = self.encoding_steps
        if enc_steps:
            result["encoding_selection"] = {
                "owasp_filter": [],
                "language_filter": [],
                "probe": [],
                "selection": [],
            }
            for step in enc_steps:
                entry = {
                    "stage": step.stage,
                    "input": step.input_summary,
                    "output": step.output_summary,
                    "reason": step.reason,
                    "metadata": step.metadata,
                }
                if step.stage == "encoding_filter_owasp":
                    result["encoding_selection"]["owasp_filter"].append(entry)
                elif step.stage == "encoding_filter_language":
                    result["encoding_selection"]["language_filter"].append(entry)
                elif step.stage == "encoding_probe":
                    result["encoding_selection"]["probe"].append(entry)
                elif step.stage == "encoding_selection":
                    result["encoding_selection"]["selection"].append(entry)

        # 添加 P0-P3 优化阶段日志
        p0_p3_stages = {
            "converter_selection": [],
            "fallback_enrich": [],
            "best_combinations": [],
            "early_stop": [],
            "feedback": [],
            "mutation": [],
            "dedup": [],
        }
        for log in self._logs:
            for step in log.steps:
                if step.stage in p0_p3_stages:
                    p0_p3_stages[step.stage].append({
                        "stage": step.stage,
                        "input": step.input_summary,
                        "output": step.output_summary,
                        "reason": step.reason,
                        "metadata": step.metadata,
                    })

        # 只添加非空的阶段
        for stage_name, entries in p0_p3_stages.items():
            if entries:
                result[stage_name] = entries

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

            # 冲突检测和交叉验证
            conflicts = r.get("conflicts", [])
            cross_validated = r.get("cross_validated", [])
            if conflicts:
                lines.extend([
                    "### Tool Conflicts (severity diff ≥ 2)",
                    "",
                    "| OWASP ID | Tools | Severities | Description |",
                    "|----------|-------|------------|-------------|",
                ])
                for c in conflicts:
                    owasp_id = c.get("owasp_id", "?")
                    tools = ", ".join(c.get("tools", []))
                    severities = ", ".join(c.get("severities", []))
                    desc = c.get("description", "")[:80]
                    lines.append(f"| {owasp_id} | {tools} | {severities} | {desc} |")
                lines.append("")
            if cross_validated:
                lines.extend([
                    "### Cross-Validation (confidence boost)",
                    "",
                    "| OWASP ID | Tools | Confidence |",
                    "|----------|-------|------------|",
                ])
                for cv in cross_validated:
                    owasp_id = cv.get("owasp_id", "?")
                    tools = ", ".join(cv.get("tools", []))
                    conf = cv.get("confidence", 0)
                    lines.append(f"| {owasp_id} | {tools} | {conf:.2f} |")
                lines.append("")

            # 侦察优化阶段（OPT-A/G/D/M/E）
            if self._recon_log:
                opt_steps = [
                    s for s in self._recon_log.steps
                    if s.metadata.get("optimization_id")
                ]
                if opt_steps:
                    lines.extend([
                        "### Reconnaissance Optimizations (OPT-A/G/D/M/E)",
                        "",
                        f"**Total optimizations applied:** {len(opt_steps)}",
                        "",
                        "| OPT-ID | Stage | Input | Output | Duration |",
                        "|--------|-------|-------|--------|----------|",
                    ])
                    for step in opt_steps:
                        opt_id = step.metadata.get("optimization_id", "?")
                        stage = step.stage
                        inp = step.input_summary[:50] if step.input_summary else "-"
                        outp = step.output_summary[:50] if step.output_summary else "-"
                        dur = f"{step.duration_ms:.0f}ms" if step.duration_ms else "-"
                        lines.append(f"| {opt_id} | {stage} | {inp} | {outp} | {dur} |")
                    lines.append("")

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

        # 编码选择部分
        enc_steps = self.encoding_steps
        if enc_steps:
            lines.extend([
                "",
                "## Intelligent Encoding Selection",
                "",
            ])

            # 阶段1a: OWASP 过滤
            owasp_steps = [s for s in enc_steps if s.stage == "encoding_filter_owasp"]
            if owasp_steps:
                lines.extend([
                    "### Phase 1a: OWASP Category Static Filtering",
                    "",
                    "| OWASP ID | Before | After | Excluded |",
                    "|----------|--------|-------|----------|",
                ])
                for step in owasp_steps:
                    meta = step.metadata
                    lines.append(
                        f"| {meta.get('owasp_id', '?')} | {meta.get('total_converters', '?')} "
                        f"| {len(meta.get('filtered_converters', []))} | {meta.get('excluded_count', '?')} |"
                    )
                lines.append("")

            # 阶段1b: 语言过滤
            lang_steps = [s for s in enc_steps if s.stage == "encoding_filter_language"]
            if lang_steps:
                lines.extend([
                    "### Phase 1b: Language Compatibility Filtering",
                    "",
                    "| Language | Before | After | Excluded Converters |",
                    "|----------|--------|-------|---------------------|",
                ])
                for step in lang_steps:
                    meta = step.metadata
                    excluded = meta.get("excluded_converters", [])
                    excluded_str = ", ".join(excluded[:5])
                    if len(excluded) > 5:
                        excluded_str += f" ...+{len(excluded)-5} more"
                    lines.append(
                        f"| {meta.get('language', '?')} | {meta.get('input_count', '?')} "
                        f"| {len(meta.get('filtered_converters', []))} | {excluded_str or '(none)'} |"
                    )
                lines.append("")

            # 阶段2: 目标探测
            probe_steps = [s for s in enc_steps if s.stage == "encoding_probe"]
            if probe_steps:
                lines.extend([
                    "### Phase 2: Target Adaptive Probing",
                    "",
                ])
                for step in probe_steps:
                    meta = step.metadata
                    pass_rates = meta.get("pass_rates", {})
                    threshold = meta.get("threshold", 0.3)
                    lines.extend([
                        f"**Probes:** {meta.get('total_probes', '?')} requests | "
                        f"**Effective:** {meta.get('effective_count', '?')}/{meta.get('converter_count', '?')} | "
                        f"**Threshold:** {threshold:.0%}",
                        "",
                        "| Converter | Pass Rate | Status |",
                        "|-----------|-----------|--------|",
                    ])
                    for name, rate in sorted(pass_rates.items(), key=lambda x: x[1], reverse=True):
                        status = "✓ Effective" if rate >= threshold else "✗ Ineffective"
                        lines.append(f"| {name} | {rate:.0%} | {status} |")
                    lines.append("")

            # 阶段3: 选择结果统计
            selection_steps = [s for s in enc_steps if s.stage == "encoding_selection"]
            if selection_steps:
                encoding_usage: Dict[str, int] = {}
                for step in selection_steps:
                    for enc in step.metadata.get("selected_encodings", []):
                        encoding_usage[enc] = encoding_usage.get(enc, 0) + 1

                lines.extend([
                    "### Phase 3: Final Encoding Selection",
                    "",
                    f"**Total payloads:** {len(selection_steps)}",
                    "",
                    "| Encoding | Usage Count | Percentage |",
                    "|----------|-------------|------------|",
                ])
                for name, count in sorted(encoding_usage.items(), key=lambda x: x[1], reverse=True):
                    pct = count / len(selection_steps) * 100
                    lines.append(f"| {name} | {count} | {pct:.0f}% |")
                lines.append("")

        content = "\n".join(lines)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        return output_path
