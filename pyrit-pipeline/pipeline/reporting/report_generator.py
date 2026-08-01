# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""报告生成器 — OWASP 映射 + 三级证据链 + Markdown 报告渲染 + 证据导出。

L5 对齐 PyRIT 1.0.0 output 模块:
  1. EvidenceExporter 使用 render_async() 替代 write_async()+read-back, 消除冗余 I/O
  2. ReportGenerator 集成 output_scorer_async 输出评分器评估指标
  3. attack_summary.csv 增加完整列 (turns/execution_time/scorer/score_value/outcome_reason)
  4. 新增 owasp_coverage_matrix.csv 和 attack_timeline.csv
  5. ReportGenerator 实现三级证据链 (Finding → AttackResult → Conversation)
  6. ReportGenerator 新增 OWASP 覆盖矩阵章节 + 攻击时间线章节
  7. ReportGenerator 动态计算 confidence (基于 score_value 和 scorer_type)
  8. ReportGenerator 集成 Converter Transformation Log (后处理重转换中间步骤)
  9. ReportGenerator 集成 DiversityAnalyzer (Shannon 熵 + OWASP 覆盖 + 范式覆盖)
 10. OWASP 数据外部化到 owasp_data.py (LLM01-10 + ASI01-10 完整定义)

三级证据链:
  1. Finding (OWASP 映射漏洞)
  2. AttackResult (具体攻击结果)
  3. Conversation (完整对话历史)

学术依据:
  - OWASP Top 10 for LLM Applications 2025
  - HarmBench (arXiv:2402.04249): 标准化红队证据收集
  - JailbreakBench (arXiv:2402.01135): 漏洞披露最佳实践
  - Shannon entropy (Shannon, 1948): 信息论多样性度量
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pyrit.memory import CentralMemory
from pyrit.output import output_scorer_async

from pipeline.reporting.format_converter import convert_report_formats
from pipeline.reporting.owasp_data import ALL_OWASP_DETAILS, get_owasp_details, get_all_owasp_standards

logger = logging.getLogger(__name__)


# ============================================================
# 数据模型
# ============================================================


@dataclass
class OWASPFinding:
    """OWASP 漏洞发现 — 三级证据链第一级。"""
    owasp_id: str
    owasp_name: str = ""
    owasp_framework: str = "llm"
    severity: str = "MEDIUM"
    cvss_score: float = 5.0
    attack_type: str = ""
    description: str = ""
    indicators: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence_ids: list[str] = field(default_factory=list)


@dataclass
class ReportResult:
    """报告生成结果。"""
    report_path: str
    owasp_findings: list[OWASPFinding] = field(default_factory=list)
    evidence_archive: str = ""
    report_html_path: str | None = None
    report_pdf_path: str | None = None


# ============================================================
# OWASP 映射器
# ============================================================


class OWASPMapper:
    """将攻击结果映射到 OWASP 安全标准 (LLM01-10 + ASI01-10)。"""

    ATTACK_CLASS_TO_CATEGORY = {
        "PromptSendingAttack": "prompt_injection",
        "MultiPromptSendingAttack": "prompt_injection",
        "RedTeamingAttack": "jailbreak",
        "CrescendoAttack": "jailbreak",
        "TAPAttack": "jailbreak",
        "PAIRAttack": "jailbreak",
        "TreeOfAttacksWithPruningAttack": "jailbreak",
        "SequentialAttack": "adaptive_attack",
        "ManyShotJailbreakAttack": "goal_hijack",
        "SkeletonKeyAttack": "goal_hijack",
        "BargeInAttack": "agent_communication_attack",
        "ChunkedRequestAttack": "context_injection",
    }

    CATEGORY_TO_OWASP = {
        "prompt_injection": ["LLM01"],
        "jailbreak": ["LLM01"],
        "adaptive_attack": ["LLM01"],
        "goal_hijack": ["LLM06"],
        "agent_communication_attack": ["LLM06"],
        "context_injection": ["LLM01"],
    }

    def attack_to_owasp(self, attack_type: str) -> list[str]:
        """将攻击类型映射到 OWASP ID。"""
        category = self.ATTACK_CLASS_TO_CATEGORY.get(attack_type, "")
        if category and category in self.CATEGORY_TO_OWASP:
            return self.CATEGORY_TO_OWASP[category]
        return ["LLM01"]

    def map_attacks_to_findings(self, attack_results: list[Any]) -> list[OWASPFinding]:
        """将攻击结果映射到 OWASP 漏洞发现 (三级证据链第一级)。"""
        attacks_by_type: dict[str, list[Any]] = {}
        for ar in attack_results:
            attack_type = _get_attack_type(ar)
            if attack_type not in attacks_by_type:
                attacks_by_type[attack_type] = []
            attacks_by_type[attack_type].append(ar)

        findings: list[OWASPFinding] = []
        for attack_type, related in attacks_by_type.items():
            owasp_ids = self.attack_to_owasp(attack_type)
            for owasp_id in owasp_ids:
                details = get_owasp_details(owasp_id)
                framework = "agentic" if owasp_id.startswith("ASI") else "llm"
                successful = sum(1 for ar in related if _get_outcome_str(ar).upper() == "SUCCESS")
                total = len(related)
                has_score = any(_safe_get(ar, "last_score") is not None for ar in related)
                base_confidence = successful / total if total > 0 else 0
                confidence = min(1.0, base_confidence * 0.8 + (0.2 if has_score else 0.0))
                evidence_ids = list(set(
                    str(_safe_get(ar, "conversation_id", "")) for ar in related
                    if _safe_get(ar, "conversation_id")
                ))
                findings.append(OWASPFinding(
                    owasp_id=owasp_id,
                    owasp_name=details.get("name", ""),
                    owasp_framework=framework,
                    severity=details.get("severity", "MEDIUM"),
                    cvss_score=details.get("cvss_base", 5.0),
                    attack_type=attack_type,
                    description=details.get("description", ""),
                    indicators=details.get("indicators", []),
                    remediation=details.get("remediation", []),
                    confidence=confidence,
                    evidence_ids=evidence_ids,
                ))
        return findings

    def build_coverage_matrix(self, attack_results: list[Any]) -> dict[str, dict[str, Any]]:
        """构建 OWASP 覆盖矩阵。"""
        owasp_stats: dict[str, dict[str, int]] = {}
        for ar in attack_results:
            attack_type = _get_attack_type(ar)
            owasp_ids = self.attack_to_owasp(attack_type)
            outcome = _get_outcome_str(ar).upper()
            for owasp_id in owasp_ids:
                if owasp_id not in owasp_stats:
                    owasp_stats[owasp_id] = {"total": 0, "success": 0}
                owasp_stats[owasp_id]["total"] += 1
                if outcome == "SUCCESS":
                    owasp_stats[owasp_id]["success"] += 1

        matrix: dict[str, dict[str, Any]] = {}
        for owasp_id, details in get_all_owasp_standards().items():
            stats = owasp_stats.get(owasp_id, {"total": 0, "success": 0})
            total = stats["total"]
            success = stats["success"]
            matrix[owasp_id] = {
                "name": details.get("name", ""),
                "severity": details.get("severity", "UNKNOWN"),
                "framework": "agentic" if owasp_id.startswith("ASI") else "llm",
                "attack_count": total,
                "success_count": success,
                "success_rate": success / total * 100 if total > 0 else 0,
                "covered": total > 0,
            }
        return matrix


# ============================================================
# 辅助函数
# ============================================================


def _safe_get(obj: Any, attr: str, default: Any = None) -> Any:
    try:
        return getattr(obj, attr, default)
    except Exception:
        return default


def _get_outcome_str(ar: Any) -> str:
    outcome = _safe_get(ar, "outcome")
    if outcome is None:
        return "unknown"
    if hasattr(outcome, "value"):
        return str(outcome.value)
    return str(outcome)


def _get_attack_type(ar: Any) -> str:
    try:
        strategy_id = ar.get_attack_strategy_identifier()
        if strategy_id:
            return str(strategy_id).split("::")[0]
    except Exception:
        pass
    raw = _safe_get(ar, "atomic_attack_identifier")
    if raw:
        return str(raw).split("::")[0]
    return "unknown"


def _format_time(ms: Any) -> str:
    if ms is None:
        return "N/A"
    try:
        ms_int = int(ms)
    except (ValueError, TypeError):
        return "N/A"
    if ms_int < 1000:
        return f"{ms_int}ms"
    return f"{ms_int / 1000:.2f}s"


# ============================================================
# 报告生成器
# ============================================================


class ReportGenerator:
    """报告生成器 — 生成 AI Red Team 评估报告 (MD/HTML/PDF) + 证据导出。

    L5 对齐:
      - 集成 EvidenceExporter (render_async)
      - 集成 ConverterLogCollector (变换日志)
      - 集成 DiversityAnalyzer (多样性分析)
      - 集成 output_scorer_async (评分器指标)
      - 三级证据链 (Finding → AttackResult → Conversation)
      - OWASP 覆盖矩阵 + 攻击时间线
    """

    def __init__(self):
        self.owasp_mapper = OWASPMapper()

    async def generate_report(
        self,
        scenario_result: Any,
        output_dir: Path,
        evidence_dir: Path | None = None,
        *,
        generate_html: bool = True,
        generate_pdf: bool = True,
        title: str = "AI Red Team Report",
        include_reasoning_trace: bool = True,
        blur_images: bool = False,
    ) -> ReportResult:
        """生成完整报告 + 证据包。

        Args:
            scenario_result: ScenarioResult 实例
            output_dir: 报告输出目录 (outputs/reports/...)
            evidence_dir: 证据输出目录 (outputs/evidence/...), None 时使用 output_dir/evidence
            generate_html: 是否生成 HTML
            generate_pdf: 是否生成 PDF
            title: 报告标题
            include_reasoning_trace: 是否包含推理轨迹
            blur_images: 是否模糊图片
        """
        memory = CentralMemory.get_memory_instance()
        attack_results = memory.get_attack_results()

        # ── 评分器指标 (PyRIT 原生) ──
        try:
            scorer_identifier = _safe_get(scenario_result, "objective_scorer_identifier")
            if scorer_identifier is not None:
                await output_scorer_async(scorer_identifier=scorer_identifier, format="pretty")
        except Exception as e:
            logger.warning(f"Scorer output failed: {e}")

        # ── OWASP 映射 + 覆盖矩阵 ──
        findings = self.owasp_mapper.map_attacks_to_findings(attack_results)
        coverage_matrix = self.owasp_mapper.build_coverage_matrix(attack_results)

        # ── Converter 变换日志 ──
        converter_report = self._collect_converter_log(attack_results)

        # ── 多样性分析 ──
        diversity_metrics = self._analyze_diversity(attack_results, coverage_matrix)

        # ── 攻击详情 (三级证据链第二级 + 第三级) ──
        attack_details = self._collect_attack_details(attack_results)

        # ── 渲染 Markdown 报告 ──
        report_content = self._render_markdown(
            findings, attack_results, coverage_matrix, scenario_result,
            attack_details, converter_report, diversity_metrics,
        )

        # ── 保存 Markdown ──
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        report_path = output_dir / "report.md"
        report_path.write_text(report_content, encoding="utf-8")

        # ── 格式转换 (MD → HTML → PDF) ──
        base_path = output_dir / "report"
        format_result = convert_report_formats(
            report_content, base_path,
            generate_html=generate_html,
            generate_pdf=generate_pdf,
            title=title,
        )

        # ── 证据导出 (EvidenceExporter with render_async) ──
        evidence_archive = ""
        if evidence_dir is None:
            evidence_dir = output_dir.parent / "evidence" / output_dir.name
        try:
            from pipeline.reporting.evidence_exporter import EvidenceExporter
            exporter = EvidenceExporter(
                evidence_dir,
                include_reasoning_trace=include_reasoning_trace,
                blur_images=blur_images,
            )
            evidence_archive = str(await exporter.export_all_evidence(
                attack_results, owasp_coverage=coverage_matrix,
            ))
        except Exception as e:
            logger.warning(f"Evidence export failed: {e}")

        return ReportResult(
            report_path=str(report_path),
            owasp_findings=findings,
            evidence_archive=evidence_archive,
            report_html_path=str(format_result["html"]) if format_result.get("html") else None,
            report_pdf_path=str(format_result["pdf"]) if format_result.get("pdf") else None,
        )

    def _collect_converter_log(self, attack_results: list[Any]) -> dict[str, Any]:
        """收集 Converter 变换日志 (集成 ConverterLogCollector)。"""
        try:
            from pipeline.converters.log import ConverterLogCollector

            collector = ConverterLogCollector()
            # ConverterLogCollector 期望 dict[str, list] 格式
            attack_results_dict: dict[str, list[Any]] = {"default": attack_results}
            report = collector.collect(attack_results=attack_results_dict)
            return report.to_dict()
        except Exception as e:
            logger.warning(f"Converter log collection failed: {e}")
            return {}

    def _analyze_diversity(
        self,
        attack_results: list[Any],
        coverage_matrix: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        """分析攻击多样性 (集成 DiversityAnalyzer)。"""
        try:
            from pipeline.analysis.diversity_analyzer import DiversityAnalyzer

            analyzer = DiversityAnalyzer()
            attack_results_dict: dict[str, list[Any]] = {"default": attack_results}
            metrics = analyzer.analyze(attack_results=attack_results_dict)
            return metrics.to_dict()
        except Exception as e:
            logger.warning(f"Diversity analysis failed: {e}")
            return {}

    def _collect_attack_details(self, attack_results: list[Any]) -> dict[str, list[dict[str, Any]]]:
        """从 Memory 收集攻击详情 (三级证据链第二级 + 第三级)。"""
        try:
            memory = CentralMemory.get_memory_instance()
        except Exception:
            return {}

        details: dict[str, list[dict[str, Any]]] = {}
        for ar in attack_results:
            attack_type = _get_attack_type(ar)
            if not attack_type:
                continue

            conv_id = _safe_get(ar, "conversation_id")
            conversation: list[dict[str, str]] = []
            if conv_id:
                try:
                    pieces = memory.get_message_pieces(conversation_id=str(conv_id))
                    for p in pieces:
                        conversation.append({
                            "role": str(_safe_get(p, "role", "unknown")),
                            "text": str(_safe_get(p, "converted_value", _safe_get(p, "original_value", ""))),
                            "timestamp": str(_safe_get(p, "timestamp", "")),
                        })
                except Exception:
                    pass

            last_score = _safe_get(ar, "last_score")
            score_info = {}
            if last_score:
                score_info = {
                    "value": _safe_get(last_score, "score_value"),
                    "type": _safe_get(last_score, "score_type"),
                    "category": _safe_get(last_score, "score_category"),
                    "rationale": str(_safe_get(last_score, "score_rationale", ""))[:200],
                }

            # Converter 信息
            conv_info = self._extract_converter_info(ar)

            detail = {
                "objective": str(_safe_get(ar, "objective", "N/A")),
                "outcome": _get_outcome_str(ar),
                "outcome_reason": str(_safe_get(ar, "outcome_reason", "")),
                "executed_turns": _safe_get(ar, "executed_turns", 0),
                "execution_time_ms": _safe_get(ar, "execution_time_ms", 0),
                "conversation": conversation,
                "conversation_id": str(conv_id or ""),
                "score": score_info,
                "converter_chain_name": conv_info.get("converter_chain_name"),
                "converter_class_names": conv_info.get("converter_class_names", []),
                "has_converters": conv_info.get("has_converters", False),
            }

            if attack_type not in details:
                details[attack_type] = []
            details[attack_type].append(detail)

        return details

    def _extract_converter_info(self, ar: Any) -> dict[str, Any]:
        """从 AttackResult 提取 Converter 信息。"""
        chain_names: list[str] = []
        try:
            identifier = ar.get_attack_strategy_identifier()
            if identifier is not None:
                children = getattr(identifier, "children", None) or {}
                request_converters = children.get("request_converters")
                if request_converters and isinstance(request_converters, list):
                    for conv in request_converters:
                        if isinstance(conv, str):
                            chain_names.append(conv)
                        else:
                            chain_names.append(type(conv).__name__)
        except Exception:
            pass

        return {
            "converter_chain_name": "→".join(chain_names) if chain_names else None,
            "converter_class_names": chain_names,
            "has_converters": len(chain_names) > 0,
        }

    def _render_markdown(
        self,
        findings: list[OWASPFinding],
        attack_results: list[Any],
        coverage_matrix: dict[str, dict[str, Any]],
        scenario_result: Any,
        attack_details: dict[str, list[dict[str, Any]]],
        converter_report: dict[str, Any],
        diversity_metrics: dict[str, Any],
    ) -> str:
        """渲染 Markdown 报告 (L5 专家级结构)。"""
        lines: list[str] = []

        total_attacks = len(attack_results)
        successful = sum(1 for ar in attack_results if _get_outcome_str(ar).upper() == "SUCCESS")
        asr = successful / total_attacks * 100 if total_attacks > 0 else 0

        # 1. Executive Summary
        lines.extend([
            "# AI Red Team Assessment Report",
            "",
            "## 1. Executive Summary",
            "",
            f"- **Total Attacks**: {total_attacks}",
            f"- **Successful**: {successful}",
            f"- **ASR (Attack Success Rate)**: {asr:.1f}%",
            f"- **Total Findings**: {len(findings)}",
            "",
        ])

        # 2. OWASP Coverage Matrix
        lines.extend([
            "## 2. OWASP Coverage Matrix",
            "",
            "### OWASP Top 10 for LLM Applications 2025",
            "",
            "| OWASP ID | Vulnerability | Severity | Attacks | Success | Rate | Covered |",
            "|----------|--------------|----------|---------|---------|------|---------|",
        ])
        for owasp_id in [f"LLM{i:02d}" for i in range(1, 11)]:
            info = coverage_matrix.get(owasp_id, {})
            covered = "✅" if info.get("covered") else "❌"
            rate = info.get("success_rate", 0)
            lines.append(
                f"| {owasp_id} | {info.get('name', 'N/A')} | {info.get('severity', 'N/A')} | "
                f"{info.get('attack_count', 0)} | {info.get('success_count', 0)} | "
                f"{rate:.0f}% | {covered} |"
            )
        lines.append("")

        lines.extend([
            "### OWASP Top 10 for Agentic AI",
            "",
            "| OWASP ID | Threat | Severity | Attacks | Success | Rate | Covered |",
            "|----------|--------|----------|---------|---------|------|---------|",
        ])
        for owasp_id in [f"ASI{i:02d}" for i in range(1, 11)]:
            info = coverage_matrix.get(owasp_id, {})
            covered = "✅" if info.get("covered") else "❌"
            rate = info.get("success_rate", 0)
            lines.append(
                f"| {owasp_id} | {info.get('name', 'N/A')} | {info.get('severity', 'N/A')} | "
                f"{info.get('attack_count', 0)} | {info.get('success_count', 0)} | "
                f"{rate:.0f}% | {covered} |"
            )
        lines.append("")

        # 3. Detailed Findings (三级证据链)
        lines.extend([
            "## 3. Detailed Findings (Attack Narrative)",
            "",
        ])
        for i, finding in enumerate(findings, 1):
            lines.extend([
                f"### 3.{i} {finding.owasp_name}",
                "",
                f"- **OWASP ID**: {finding.owasp_id}",
                f"- **Framework**: {finding.owasp_framework.upper()}",
                f"- **Severity**: {finding.severity}",
                f"- **CVSS Score**: {finding.cvss_score}",
                f"- **Attack Type**: {finding.attack_type}",
                f"- **Confidence**: {finding.confidence:.0%}",
                f"- **Description**: {finding.description}",
                "",
                "**Indicators**:",
            ])
            for indicator in finding.indicators:
                lines.append(f"- {indicator}")
            lines.extend(["", "**Suggested Remediation**:"])
            for remediation in finding.remediation:
                lines.append(f"- {remediation}")
            lines.append("")

            # 三级证据链 - 第二级 + 第三级
            related_attacks = attack_details.get(finding.attack_type, [])
            if related_attacks:
                lines.extend(["**Steps to Reproduce**:", ""])
                for j, detail in enumerate(related_attacks[:3], 1):
                    lines.extend([
                        f"#### Step {j}",
                        "",
                        f"- **Objective**: {detail['objective']}",
                        f"- **Outcome**: {detail['outcome']}",
                        f"- **Turns**: {detail.get('executed_turns', 'N/A')}",
                        f"- **Execution Time**: {_format_time(detail.get('execution_time_ms'))}",
                        f"- **Conversation ID**: `{detail.get('conversation_id', 'N/A')}`",
                    ])
                    if detail.get("has_converters"):
                        lines.extend([
                            "",
                            f"- **Converter Chain**: `{detail.get('converter_chain_name', 'N/A')}`",
                            f"- **Converter Classes**: {', '.join(detail.get('converter_class_names', []))}",
                        ])
                    lines.append("")

                    # 完整对话历史 (三级证据链第三级)
                    conv = detail.get("conversation", [])
                    if conv:
                        lines.extend(["**Conversation History**:", ""])
                        for msg in conv:
                            role = msg.get("role", "unknown").upper()
                            text = msg.get("text", "")
                            lines.extend([f"**[{role}]**", "```", text, "```", ""])
            lines.extend(["---", ""])

        # 4. Attack Timeline
        lines.extend([
            "## 4. Attack Timeline",
            "",
            "| # | Attack Type | Objective | Outcome | Turns | Time |",
            "|---|-------------|-----------|---------|-------|------|",
        ])
        for idx, ar in enumerate(attack_results, 1):
            obj = str(_safe_get(ar, "objective", "N/A"))[:60].replace("|", "\\|")
            lines.append(
                f"| {idx} | {_get_attack_type(ar)} | {obj} | "
                f"{_get_outcome_str(ar)} | {_safe_get(ar, 'executed_turns', 'N/A')} | "
                f"{_format_time(_safe_get(ar, 'execution_time_ms'))} |"
            )
        lines.append("")

        # 5. Successful Attack Highlights
        success_idx = 0
        lines.extend([
            "## 5. Successful Attack Highlights",
            "",
        ])
        for attack_type, details_list in attack_details.items():
            for detail in details_list:
                if detail.get("outcome", "").upper() != "SUCCESS":
                    continue
                success_idx += 1
                lines.extend([
                    f"### 5.{success_idx} Successful Attack #{success_idx}",
                    "",
                    f"- **Attack Type**: {attack_type}",
                    f"- **Objective**: {detail['objective']}",
                    "- **Outcome**: ✅ SUCCESS",
                    f"- **Turns**: {detail.get('executed_turns', 'N/A')}",
                    f"- **Execution Time**: {_format_time(detail.get('execution_time_ms'))}",
                    "",
                ])
                conv = detail.get("conversation", [])
                if conv:
                    lines.extend(["**Conversation History**:", ""])
                    for msg in conv:
                        role = msg.get("role", "unknown").upper()
                        text = msg.get("text", "")
                        lines.extend([f"**[{role}]**", "```", text, "```", ""])
                lines.extend(["---", ""])
        if success_idx == 0:
            lines.extend(["*No successful attacks to display.*", ""])

        # 6. Converter Analysis (变换日志)
        if converter_report and converter_report.get("total_with_converters", 0) > 0:
            lines.extend([
                "## 6. Converter Analysis",
                "",
                f"- **Total Attacks**: {converter_report.get('total_attacks', 0)}",
                f"- **With Converters**: {converter_report.get('total_with_converters', 0)}",
                f"- **Usage Rate**: {converter_report.get('converter_usage_rate', 0):.1%}",
                "",
                "### Converter Chain Statistics",
                "",
                "| Chain | Total | Success | Fail | Error | ASR |",
                "|-------|-------|---------|------|-------|-----|",
            ])
            chain_stats = converter_report.get("chain_stats", {})
            for chain_name, stats in sorted(chain_stats.items(), key=lambda x: x[1].get("success_rate", 0), reverse=True):
                lines.append(
                    f"| {chain_name} | {stats.get('total_uses', 0)} | "
                    f"{stats.get('successes', 0)} | {stats.get('failures', 0)} | "
                    f"{stats.get('errors', 0)} | {stats.get('success_rate', 0):.1%} |"
                )
            lines.append("")

            # L5 对齐: 后处理重转换中间步骤 (方案B)
            transformation_steps = converter_report.get("transformation_steps", {})
            if transformation_steps:
                lines.extend([
                    "### Converter Transformation Log",
                    "",
                    "| Attack | Step | Converter | LLM? | Input | Output | Error |",
                    "|--------|------|-----------|------|-------|--------|-------|",
                ])
                for attack_id, steps in transformation_steps.items():
                    for step in steps:
                        inp = str(step.get("input_text", ""))[:60].replace("|", "\\|").replace("\n", " ")
                        outp = str(step.get("output_text", ""))[:60].replace("|", "\\|").replace("\n", " ")
                        llm = "Yes" if step.get("is_llm_converter") else "No"
                        err = step.get("error", "") or ""
                        lines.append(
                            f"| {attack_id[:20]} | {step.get('step', '')} | "
                            f"{step.get('converter_class', '')} | {llm} | "
                            f"`{inp}...` | `{outp}...` | {err} |"
                        )
                lines.append("")

        # 7. Diversity & Coverage Analysis (多样性分析)
        if diversity_metrics:
            lines.extend([
                "## 7. Diversity & Coverage Analysis",
                "",
                f"- **Technique Entropy (Shannon)**: {diversity_metrics.get('technique_entropy', 0):.4f}",
                f"- **Unique Techniques**: {diversity_metrics.get('unique_techniques', 0)}",
                f"- **Paradigm Coverage**: {diversity_metrics.get('paradigm_coverage', 0):.1%}",
                f"- **Paradigms Used**: {', '.join(diversity_metrics.get('paradigms_used', []))}",
                f"- **Overall Diversity Score**: {diversity_metrics.get('overall_diversity_score', 0):.2f}",
                f"- **Diversity Grade**: {diversity_metrics.get('diversity_grade', 'F')}",
                "",
                "### Attack Mode Distribution",
                "",
                "| Paradigm | Count |",
                "|----------|-------|",
            ])
            for mode, count in diversity_metrics.get("attack_mode_distribution", {}).items():
                lines.append(f"| {mode} | {count} |")
            lines.append("")

            # L5 对齐: 失败模式集中度
            failure_dist = diversity_metrics.get("failure_type_distribution", {})
            if failure_dist:
                lines.extend([
                    "### Failure Concentration Analysis",
                    "",
                    f"- **Concentration**: {diversity_metrics.get('failure_concentration', 0):.1%} (higher = more concentrated)",
                    "",
                    "| Failure Type | Count | Percentage |",
                    "|--------------|-------|------------|",
                ])
                total_f = sum(failure_dist.values())
                for ftype, count in failure_dist.items():
                    pct = count / total_f * 100 if total_f > 0 else 0
                    lines.append(f"| {ftype} | {count} | {pct:.1f}% |")
                lines.append("")

        # 8. Appendix
        lines.extend([
            "## 8. Appendix",
            "",
            "### Appendix A | Evidence Archive",
            "- `evidence.json` — Structured data (model dumps)",
            "- `attacks/` — Per-attack Markdown reports",
            "- `conversations/` — Per-conversation Markdown files",
            "- `conversation_history.md` — Consolidated conversation log",
            "- `attack_summary.csv` — Complete attack summary",
            "- `owasp_coverage_matrix.csv` — OWASP coverage matrix",
            "- `attack_timeline.csv` — Chronological timeline",
            "",
            "### Appendix B | Risk Definitions",
            "",
            "| Severity | Definition |",
            "|----------|-----------|",
            "| Critical | Immediate threat with potential for system compromise |",
            "| High | Significant vulnerability leading to unauthorized access |",
            "| Medium | Moderate risk requiring specific conditions to exploit |",
            "| Low | Limited impact vulnerability, often informational |",
            "",
        ])

        return "\n".join(lines)


# ============================================================
# 工厂函数
# ============================================================


async def generate_report(
    scenario_result: Any,
    output_dir: Path,
    evidence_dir: Path | None = None,
    *,
    generate_html: bool = True,
    generate_pdf: bool = True,
    title: str = "AI Red Team Report",
    include_reasoning_trace: bool = True,
    blur_images: bool = False,
) -> ReportResult:
    """生成报告 (工厂函数)。"""
    generator = ReportGenerator()
    return await generator.generate_report(
        scenario_result,
        output_dir,
        evidence_dir,
        generate_html=generate_html,
        generate_pdf=generate_pdf,
        title=title,
        include_reasoning_trace=include_reasoning_trace,
        blur_images=blur_images,
    )


def map_attacks_to_owasp(attack_results: list[Any]) -> list[OWASPFinding]:
    """将攻击结果映射到 OWASP (工厂函数)。"""
    mapper = OWASPMapper()
    return mapper.map_attacks_to_findings(attack_results)
