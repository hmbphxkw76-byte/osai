# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""报告生成器 — OWASP 映射 + 三级证据链 + Markdown 报告渲染 + 证据导出。.

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
 11. ReportGenerator 新增 MITRE ATT&CK Mapping 章节 (从 owasp_data.py 获取)
 12. ReportGenerator 新增 Tool Usage 章节 (动态提取)
 13. ReportGenerator 新增 Introduction 章节 (L5 专家级结构对齐)
 14. ReportGenerator 增强 Appendix (Configuration Summary + Reproduction Configuration)
 15. ReportGenerator 使用 extract_converter_info_from_result + format_technique_display
 16. ReportGenerator 使用 render_diversity_section_from_dict 渲染多样性分析
 17. G2: _analyze_diversity 传递 available_techniques + owasp_mapping (覆盖率不再恒为100%)
 18. G3: _collect_converter_log 异步化 + reconvert_async 后处理重转换 (transformation_steps 填充)
 19. G5: findings 按严重度降序排序 (CRITICAL → HIGH → MEDIUM → LOW)
 20. G6: Executive Summary 新增 Overall Risk Assessment (加权 CVSS × confidence)
 21. G7: docstring + HTML lang 属性修正 (lang=en 对齐英文报告)

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
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from pyrit.memory import CentralMemory
from pyrit.output import output_scorer_async
from pyrit.output.conversation.markdown import MarkdownConversationMemoryPrinter
from pyrit.output.score.markdown import MarkdownScorePrinter

from pipeline.converters.log import extract_converter_info_from_result, format_technique_display
from pipeline.reporting.format_converter import convert_report_formats
from pipeline.reporting.owasp_data import get_all_owasp_standards, get_owasp_details

logger = logging.getLogger(__name__)


# ============================================================
# 数据模型
# ============================================================


@dataclass
class OWASPFinding:
    """OWASP 漏洞发现 — 三级证据链第一级。."""
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
    # L5 对齐: MITRE ATT&CK 技术映射
    mitre_techniques: list[str] = field(default_factory=list)
    kill_chain_phases: list[str] = field(default_factory=list)


@dataclass
class ReportResult:
    """报告生成结果。."""
    report_path: str
    owasp_findings: list[OWASPFinding] = field(default_factory=list)
    evidence_archive: str = ""
    report_html_path: str | None = None
    report_pdf_path: str | None = None
    # L5 对齐: 时间追踪
    start_time: datetime | None = None
    end_time: datetime | None = None
    duration_seconds: float = 0.0


# ============================================================
# OWASP 映射器
# ============================================================


class OWASPMapper:
    """将攻击结果映射到 OWASP 安全标准 (LLM01-10 + ASI01-10)。.

    基于 OWASP Top 10 for LLM Applications 2025 + OWASP Top 10 for Agentic Applications。
    映射策略:
      1. 优先从 AttackResult 的 metadata 中提取 owasp_id (来自 prompt 文件 seed 元数据)
      2. 回退到 ATTACK_CLASS_TO_CATEGORY → CATEGORY_TO_OWASP 硬编码映射
      3. 最终回退到 LLM01 (Prompt Injection 是最通用的类别)
    """

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
        "SkeletonKeyAttack": "privilege_escalation",
        "BargeInAttack": "agent_communication_attack",
        "ChunkedRequestAttack": "context_injection",
    }

    # OWASP Top 10 for LLM Applications 2025 + Agentic Applications 映射
    CATEGORY_TO_OWASP = {
        # LLM01: Prompt Injection — 直接/间接注入、越狱、自适应攻击
        "prompt_injection": ["LLM01"],
        "jailbreak": ["LLM01"],
        "adaptive_attack": ["LLM01"],
        "context_injection": ["LLM01"],
        # LLM02: Sensitive Information Disclosure — 信息提取
        "info_extraction": ["LLM02"],
        # LLM03: Supply Chain — 依赖/模型来源
        "supply_chain": ["LLM03"],
        # LLM04: Data and Model Poisoning — 后门/投毒触发
        "data_poisoning": ["LLM04"],
        # LLM05: Improper Output Handling — XSS/SQL/RCE 输出
        "output_handling": ["LLM05"],
        # LLM06: Excessive Agency — 权限提升、Agent 误用
        #   交叉映射: privilege_escalation → ASI05, agent_communication_attack → ASI07
        "goal_hijack": ["LLM06"],
        "agent_communication_attack": ["LLM06", "ASI07"],
        "privilege_escalation": ["LLM06", "ASI05"],
        # LLM07: System Prompt Leakage — 系统提示词提取
        "system_prompt_leakage": ["LLM07"],
        # LLM08: Vector and Embedding Weaknesses — RAG/向量库
        "vector_embedding": ["LLM08"],
        # LLM09: Misinformation — 幻觉/虚假信息
        "misinformation": ["LLM09"],
        # LLM10: Unbounded Consumption — 资源耗尽/模型提取
        "unbounded_consumption": ["LLM10"],
        # ASI01: Agent Identity Spoofing — 身份冒充
        "agent_identity_spoofing": ["ASI01"],
        # ASI02: Tool Misuse — 工具误用
        "tool_misuse": ["ASI02"],
        # ASI03: Unauthorized Actions — 未授权操作
        "unauthorized_actions": ["ASI03"],
        # ASI04: Data Exfiltration — 数据外泄
        "data_exfiltration": ["ASI04"],
        # ASI06: Memory Poisoning — 记忆投毒
        "memory_poisoning": ["ASI06"],
        # ASI08: Cascading Failures — 级联故障
        "cascading_failure": ["ASI08"],
        # ASI09: Trust Boundary Violation — 信任边界违规
        "trust_boundary_violation": ["ASI09"],
        # ASI10: Rogue Agent — 恶意代理
        "rogue_agent": ["ASI10"],
    }

    def attack_to_owasp(self, attack_type: str, attack_result: Any = None) -> list[str]:
        """将攻击类型映射到 OWASP ID。.

        优先从 attack_result 的 metadata 中提取 owasp_id（来自 prompt 文件
        seed 元数据），回退到硬编码映射。

        Args:
            attack_type: 攻击类型字符串 (如 "PromptSendingAttack")
            attack_result: 可选的 AttackResult 对象，用于提取 metadata.owasp_id
        """
        # 1. 优先从 metadata 提取 owasp_id
        if attack_result is not None:
            owasp_id = self._extract_owasp_id_from_metadata(attack_result)
            if owasp_id:
                return [owasp_id]

        # 2. 回退到硬编码映射
        category = self.ATTACK_CLASS_TO_CATEGORY.get(attack_type, "")
        if category and category in self.CATEGORY_TO_OWASP:
            return self.CATEGORY_TO_OWASP[category]
        return ["LLM01"]

    @staticmethod
    def _extract_owasp_id_from_metadata(attack_result: Any) -> str | None:
        """从 AttackResult 的 metadata 中提取 owasp_id。."""
        # 尝试从 memory_labels 获取
        labels = _safe_get(attack_result, "memory_labels", None)
        if labels and isinstance(labels, dict):
            owasp_id = labels.get("owasp_id", "")
            if owasp_id:
                return owasp_id
        # 尝试从 objective 的 metadata 获取
        objective = _safe_get(attack_result, "objective", None)
        if objective:
            metadata = _safe_get(objective, "metadata", None)
            if metadata and isinstance(metadata, dict):
                owasp_id = metadata.get("owasp_id", "")
                if owasp_id:
                    return owasp_id
        return None

    def map_attacks_to_findings(self, attack_results: list[Any]) -> list[OWASPFinding]:
        """将攻击结果映射到 OWASP 漏洞发现 (三级证据链第一级)。."""
        attacks_by_type: dict[str, list[Any]] = {}
        for ar in attack_results:
            attack_type = _get_attack_type(ar)
            if attack_type not in attacks_by_type:
                attacks_by_type[attack_type] = []
            attacks_by_type[attack_type].append(ar)

        findings: list[OWASPFinding] = []
        for attack_type, related in attacks_by_type.items():
            # 优先从第一个 attack_result 的 metadata 提取 owasp_id
            sample_ar = related[0] if related else None
            owasp_ids = self.attack_to_owasp(attack_type, attack_result=sample_ar)
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
                    mitre_techniques=details.get("mitre_techniques", []),
                    kill_chain_phases=details.get("kill_chain_phases", []),
                ))
        return findings

    def build_coverage_matrix(self, attack_results: list[Any]) -> dict[str, dict[str, Any]]:
        """构建 OWASP 覆盖矩阵。."""
        owasp_stats: dict[str, dict[str, int]] = {}
        for ar in attack_results:
            attack_type = _get_attack_type(ar)
            owasp_ids = self.attack_to_owasp(attack_type, attack_result=ar)
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


# R3: 对话文本截断阈值 — 超过此长度的单条消息将被截断
_MAX_CONVERSATION_TEXT_LENGTH = 500


def _truncate_text(text: str, max_length: int = _MAX_CONVERSATION_TEXT_LENGTH) -> str:
    """截断超长文本, 添加截断标注 (R3: 幻觉文本截断机制).

    模型幻觉产生的数千字垃圾文本会严重膨胀报告,
    超过阈值的文本截断并标注省略字符数。
    """
    if len(text) <= max_length:
        return text
    omitted = len(text) - max_length
    return f"{text[:max_length]}\n\n[... truncated: {omitted} chars omitted ...]"


# ============================================================
# 报告生成器
# ============================================================


class ReportGenerator:
    """报告生成器 — 生成 AI Red Team 评估报告 (MD/HTML/PDF) + 证据导出。.

    L5 对齐:
      - 集成 EvidenceExporter (render_async)
      - 集成 ConverterLogCollector (变换日志)
      - 集成 DiversityAnalyzer (多样性分析)
      - 集成 output_scorer_async (评分器指标)
      - 三级证据链 (Finding → AttackResult → Conversation)
      - OWASP 覆盖矩阵 + 攻击时间线
      - MITRE ATT&CK 映射
      - Tool Usage 动态提取
      - Introduction + 增强 Appendix
    """

    def __init__(self) -> None:
        """Initialize ReportGenerator."""
        self.owasp_mapper = OWASPMapper()

    async def generate_report(
        self,
        scenario_result: Any,
        output_dir: Path,
        evidence_dir: Path | None = None,
        *,
        generate_html: bool = True,
        generate_pdf: bool = False,
        title: str = "AI Red Team Report",
        include_reasoning_trace: bool = True,
        blur_images: bool = False,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        report_base_name: str = "report",
    ) -> ReportResult:
        """生成完整报告 + 证据包。.

        Args:
            scenario_result: ScenarioResult 实例
            output_dir: 报告输出目录 (outputs/reports/...)
            evidence_dir: 证据输出目录 (outputs/evidence/...), None 时使用 output_dir/evidence
            generate_html: 是否生成 HTML
            generate_pdf: 是否生成 PDF
            title: 报告标题
            include_reasoning_trace: 是否包含推理轨迹
            blur_images: 是否模糊图片
            start_time: 评估开始时间 (None 时使用当前时间).
            end_time: 评估结束时间 (None 时使用当前时间).
            report_base_name: 报告文件基础名 (不含扩展名).
        """
        if start_time is None:
            start_time = datetime.now()
        if end_time is None:
            end_time = datetime.now()

        logger.info(f"ReportGenerator.generate_report started, output_dir={output_dir}, evidence_dir={evidence_dir}")

        memory = CentralMemory.get_memory_instance()
        attack_results = memory.get_attack_results()

        logger.info(f"ReportGenerator: {len(attack_results)} attack_results from memory")

        # ── 评分器指标 (PyRIT 原生) ──
        try:
            scorer_identifier = _safe_get(scenario_result, "objective_scorer_identifier")
            if scorer_identifier is not None:
                await output_scorer_async(scorer_identifier=scorer_identifier, format="pretty")
        except Exception as e:
            logger.warning(f"Scorer output failed: {e}")

        # ── OWASP 映射 + 覆盖矩阵 ──
        findings = self.owasp_mapper.map_attacks_to_findings(attack_results)
        # G5 修复: 按严重度降序排序 (CRITICAL → HIGH → MEDIUM → LOW)
        _severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda f: _severity_order.get(f.severity, 99))
        coverage_matrix = self.owasp_mapper.build_coverage_matrix(attack_results)

        # ── Converter 变换日志 (G3: 异步 + reconvert_async) ──
        converter_report = await self._collect_converter_log(attack_results)

        # ── 多样性分析 ──
        diversity_metrics = self._analyze_diversity(attack_results, coverage_matrix)

        # ── 攻击详情 (三级证据链第二级 + 第三级) ──
        attack_details = await self._collect_attack_details(attack_results)

        # ── 渲染 Markdown 报告 ──
        report_content = self._render_markdown(
            findings, attack_results, coverage_matrix, scenario_result,
            attack_details, converter_report, diversity_metrics,
            start_time, end_time,
        )

        # ── 保存 Markdown ──
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        report_path = output_dir / f"{report_base_name}.md"
        report_path.write_text(report_content, encoding="utf-8")

        # ── 格式转换 (MD → HTML → PDF) ──
        base_path = output_dir / report_base_name
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
            logger.exception(f"Evidence export failed: {e}")
            print(f"  [警告] 证据导出失败: {e}")

        return ReportResult(
            report_path=str(report_path),
            owasp_findings=findings,
            evidence_archive=evidence_archive,
            report_html_path=str(format_result["html"]) if format_result.get("html") else None,
            report_pdf_path=str(format_result["pdf"]) if format_result.get("pdf") else None,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=(end_time - start_time).total_seconds(),
        )

    async def _collect_converter_log(self, attack_results: list[Any]) -> dict[str, Any]:
        """收集 Converter 变换日志 (集成 ConverterLogCollector + G3 reconvert_async).

        G3 修复: 在 collect() 后执行 reconvert_async() 后处理重转换,
        填充 transformation_steps 字段, 使报告中 Converter Transformation Log 有数据。
        """
        try:
            from pipeline.converters.log import ConverterLogCollector

            collector = ConverterLogCollector()
            attack_results_dict: dict[str, list[Any]] = {"default": attack_results}
            report = collector.collect(attack_results=attack_results_dict)
            # G3 修复: 后处理重转换 — 对非 LLM Converter 重新执行变换链, 记录中间步骤
            report = await collector.reconvert_async(report)
            return report.to_dict()
        except Exception as e:
            logger.warning(f"Converter log collection failed: {e}")
            return {}

    def _analyze_diversity(
        self,
        attack_results: list[Any],
        coverage_matrix: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        """分析攻击多样性 (集成 DiversityAnalyzer + G2 参数补全).

        G2 修复: 传递 available_techniques 和 owasp_mapping 参数, 确保技术覆盖度
        和 OWASP 覆盖度不被错误地计算为 100%/0%。
        """
        try:
            from pipeline.analysis.diversity_analyzer import DiversityAnalyzer

            analyzer = DiversityAnalyzer()
            attack_results_dict: dict[str, list[Any]] = {"default": attack_results}

            # G2 修复: 获取可用技术列表
            available_techniques: list[str] = []
            try:
                from pyrit.registry import AttackTechniqueRegistry
                available_techniques = list(
                    AttackTechniqueRegistry.get_registry_singleton().get_factories().keys()
                )
            except (ImportError, RuntimeError):
                pass

            # G2 修复: 构建 owasp_mapping (attack_type → owasp_id)
            owasp_mapping: dict[str, str] = {}
            for ar in attack_results:
                attack_type = _get_attack_type(ar)
                owasp_ids = self.owasp_mapper.attack_to_owasp(attack_type, attack_result=ar)
                if owasp_ids:
                    owasp_mapping[attack_type] = owasp_ids[0]

            metrics = analyzer.analyze(
                attack_results=attack_results_dict,
                available_techniques=available_techniques or None,
                owasp_mapping=owasp_mapping or None,
            )
            return metrics.to_dict()
        except Exception as e:
            logger.warning(f"Diversity analysis failed: {e}")
            return {}

    async def _collect_attack_details(self, attack_results: list[Any]) -> dict[str, list[dict[str, Any]]]:
        """从 Memory 收集攻击详情 (三级证据链第二级 + 第三级).

        K1 优化: 使用原生 MarkdownConversationMemoryPrinter.render_async() 渲染对话,
        替代手动构建 **[USER]** / **[ASSISTANT]** 格式, 保持与 evidence 文件格式一致。
        """
        try:
            memory = CentralMemory.get_memory_instance()
        except Exception:
            return {}

        # K1: 原生打印机实例
        score_printer = MarkdownScorePrinter()
        conv_printer = MarkdownConversationMemoryPrinter(score_printer=score_printer)

        details: dict[str, list[dict[str, Any]]] = {}
        for ar in attack_results:
            attack_type = _get_attack_type(ar)
            if not attack_type:
                continue

            conv_id = _safe_get(ar, "conversation_id")
            conversation: list[dict[str, str]] = []
            conversation_md: str = ""
            if conv_id:
                try:
                    pieces = memory.get_message_pieces(conversation_id=str(conv_id))
                    for p in pieces:
                        raw_text = str(_safe_get(p, "converted_value", _safe_get(p, "original_value", "")))
                        # R3: 截断超长对话文本 (幻觉文本截断机制)
                        conversation.append({
                            "role": str(_safe_get(p, "role", "unknown")),
                            "text": _truncate_text(raw_text),
                            "timestamp": str(_safe_get(p, "timestamp", "")),
                        })
                    # K1: 使用原生 render_async() 渲染对话 Markdown
                    # R3: 渲染后截断超长对话内容
                    if pieces:
                        try:
                            conversation_md = _truncate_text(
                                await conv_printer.render_async(
                                    pieces,
                                    include_scores=True,
                                ),
                                max_length=2000,
                            )
                        except Exception as e:
                            logger.warning(f"Failed to render conversation for {conv_id}: {e}")
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

            # L5 对齐: 使用 extract_converter_info_from_result (数据流闭环增强)
            conv_info = extract_converter_info_from_result(ar)

            detail = {
                "objective": str(_safe_get(ar, "objective", "N/A")),
                "outcome": _get_outcome_str(ar),
                "outcome_reason": str(_safe_get(ar, "outcome_reason", "")),
                "executed_turns": _safe_get(ar, "executed_turns", 0),
                "execution_time_ms": _safe_get(ar, "execution_time_ms", 0),
                "conversation": conversation,
                "conversation_md": conversation_md,
                "conversation_id": str(conv_id or ""),
                "score": score_info,
                "converter_chain_name": conv_info.get("converter_chain_name"),
                "converter_class_names": conv_info.get("converter_class_names", []),
                "has_converters": conv_info.get("has_converters", False),
                # L5 对齐: 攻击技术名 (同时展示 snake_case 和 PascalCase)
                "attack_technique_display": format_technique_display(attack_type),
            }

            if attack_type not in details:
                details[attack_type] = []
            details[attack_type].append(detail)

        return details

    def _render_markdown(
        self,
        findings: list[OWASPFinding],
        attack_results: list[Any],
        coverage_matrix: dict[str, dict[str, Any]],
        scenario_result: Any,
        attack_details: dict[str, list[dict[str, Any]]],
        converter_report: dict[str, Any],
        diversity_metrics: dict[str, Any],
        start_time: datetime,
        end_time: datetime,
    ) -> str:
        """渲染 Markdown 报告 (L5 专家级结构)。."""
        lines: list[str] = []

        total_attacks = len(attack_results)
        successful = sum(1 for ar in attack_results if _get_outcome_str(ar).upper() == "SUCCESS")
        asr = successful / total_attacks * 100 if total_attacks > 0 else 0

        critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")
        medium_count = sum(1 for f in findings if f.severity == "MEDIUM")
        low_count = sum(1 for f in findings if f.severity == "LOW")

        # ============================================================
        # 1. Introduction
        # ============================================================
        lines.extend([
            "# AI Red Team Assessment Report",
            "",
            "## 1. Introduction",
            "",
            "This report documents all efforts conducted during the AI Red Team assessment.",
            "The assessment aimed to identify and exploit AI-focused attack vectors across",
            "the target environment, demonstrating a complete exploitation path against",
            "AI-enabled systems.",
            "",
            "### Objective",
            "",
            "The objective of this assessment is to perform a hands-on red team engagement",
            "against an AI-enabled environment. The assessment identifies and exploits",
            "AI-focused attack vectors, documenting every step taken, commands issued,",
            "and relevant output to ensure reproducibility.",
            "",
            "### Requirements",
            "",
            "The report documents all attacks, including every step taken, all commands issued,",
            "any code or scripts written, and the relevant console output. Where an existing",
            "script or exploit is used, a link to its source is provided. Each stage of the",
            "attack is supported by evidence showing the various steps and stages of the",
            "exploitation process. AI tooling used during the engagement — including prompts,",
            "model interactions, and AI-assisted payload generation — is documented to the",
            "same standard as any other tool or technique.",
            "",
        ])

        # ============================================================
        # 2. Executive Summary
        # ============================================================
        lines.extend([
            "## 2. Executive Summary",
            "",
            f"- **Assessment ID**: {scenario_result.id if hasattr(scenario_result, 'id') else 'N/A'}",
            f"- **Start Time**: {start_time.isoformat()}",
            f"- **End Time**: {end_time.isoformat()}",
            f"- **Duration**: {end_time - start_time}",
            "",
            "### Overview",
            "",
            "This section provides a high-level, non-technical overview of the engagement",
            "suitable for a management audience. The assessment evaluated the target AI",
            "system against the OWASP Top 10 for LLM Applications 2025 and the OWASP Top 10",
            "for Agentic Applications, identifying vulnerabilities that could be exploited by an adversary.",
            "",
            "### High-Level Attack Path",
            "",
            "1. **Reconnaissance** — The target endpoint was identified and its AI system type",
            "   was determined through automated probing.",
            f"2. **Payload Delivery** — {total_attacks} attacks were executed against the",
            "   target, covering single-turn, multi-turn, converter-enhanced, and sequential",
            "   attack modes.",
            f"3. **Exploitation** — {successful} attacks successfully achieved",
            f"   their objectives, resulting in {len(findings)} confirmed findings.",
            "",
            "### Findings Summary",
            f"- Total Findings: {len(findings)}",
            f"- Critical: {critical_count}",
            f"- High: {high_count}",
            f"- Medium: {medium_count}",
            f"- Low: {low_count}",
            "",
        ])

        # G6 新增: 聚合风险评分 (加权 CVSS × confidence)
        if findings:
            weighted_score = sum(f.cvss_score * f.confidence for f in findings) / len(findings)
            if weighted_score >= 7.0:
                risk_level = "Critical"
            elif weighted_score >= 5.0:
                risk_level = "High"
            elif weighted_score >= 3.0:
                risk_level = "Medium"
            else:
                risk_level = "Low"
            lines.extend([
                "### Overall Risk Assessment",
                f"- **Weighted Risk Score**: {weighted_score:.2f} / 10.0",
                f"- **Risk Level**: {risk_level}",
                "- **Formula**: Σ(CVSS × Confidence) / N(findings)",
                "",
            ])

        lines.extend([
            "### Attack Summary",
            f"- Total Attacks: {total_attacks}",
            f"- Successful: {successful}",
            f"- Success Rate: {asr:.1f}%",
            "",
        ])

        # Attack Technique Distribution
        technique_distribution: dict[str, int] = {}
        for ar in attack_results:
            tech = _get_attack_type(ar)
            technique_distribution[tech] = technique_distribution.get(tech, 0) + 1

        if technique_distribution:
            lines.extend([
                "### Attack Technique Distribution",
                "| Technique | Count |",
                "|-----------|-------|",
            ])
            for technique, count in sorted(technique_distribution.items(), key=lambda x: -x[1]):
                lines.append(f"| {format_technique_display(technique)} | {count} |")
            lines.append("")

        # Converter Chain Usage
        converter_usage: dict[str, int] = {}
        for _attack_type, details_list in attack_details.items():
            for detail in details_list:
                if detail.get("has_converters"):
                    chain = detail.get("converter_chain_name", "unknown")
                    converter_usage[chain] = converter_usage.get(chain, 0) + 1

        if converter_usage:
            lines.extend([
                "### Converter Chain Usage",
                "| Chain | Count |",
                "|-------|-------|",
            ])
            for chain, count in sorted(converter_usage.items(), key=lambda x: -x[1]):
                lines.append(f"| {chain} | {count} |")
            lines.append("")

        # Failure Analysis
        failure_reasons: dict[str, int] = {}
        for ar in attack_results:
            outcome = _get_outcome_str(ar).upper()
            if outcome in ("FAILURE", "ERROR"):
                raw_error = str(_safe_get(ar, "error_message", "") or _safe_get(ar, "outcome_reason", ""))
                if "ValidationError" in raw_error or "score_rationale" in raw_error:
                    reason = "scorer_validation_error"
                elif "Timeout" in raw_error:
                    reason = "timeout"
                elif "Status Code: 500" in raw_error or "finish_reason" in raw_error:
                    reason = "model_response_error"
                elif "Refusal" in raw_error or "refused" in raw_error:
                    reason = "model_refusal"
                elif raw_error:
                    reason = raw_error[:60]
                else:
                    reason = "objective_not_achieved"
                failure_reasons[reason] = failure_reasons.get(reason, 0) + 1

        if failure_reasons:
            lines.extend([
                "### Failure Analysis",
                "| Failure Reason | Count |",
                "|----------------|-------|",
            ])
            for reason, count in sorted(failure_reasons.items(), key=lambda x: -x[1]):
                lines.append(f"| {str(reason)[:50]} | {count} |")
            lines.append("")

        # Diversity & Coverage Analysis (L5 对齐: 使用 render_diversity_section_from_dict)
        if diversity_metrics:
            try:
                from pipeline.analysis.diversity_analyzer import render_diversity_section_from_dict
                lines.append(render_diversity_section_from_dict(diversity_metrics))
            except ImportError:
                pass

        # ============================================================
        # 3. OWASP Coverage Matrix
        # ============================================================
        lines.extend([
            "## 3. OWASP Coverage Matrix",
            "",
            "This section shows the coverage of OWASP security standards across all attacks.",
            "",
            "### OWASP Top 10 for LLM Applications 2025",
            "",
            "| OWASP ID | Vulnerability | Severity | Attacks | Success | Success Rate | Covered |",
            "|----------|--------------|----------|---------|---------|--------------|---------|",
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
            "### OWASP Top 10 for Agentic Applications",
            "",
            "| OWASP ID | Threat | Severity | Attacks | Success | Success Rate | Covered |",
            "|----------|--------|----------|---------|---------|--------------|---------|",
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

        # ============================================================
        # 4. Detailed Findings (三级证据链) — R1+R2+R5 优化
        # ============================================================
        lines.extend([
            "## 4. Detailed Findings (Attack Narrative)",
            "",
            "This section describes confirmed vulnerabilities with full exploitation",
            "evidence. Each finding includes vulnerability details, MITRE technique mapping,",
            "successful attack conversations (Steps to Reproduce), failed attempt summary,",
            "and suggested remediation.",
            "",
        ])

        # R5: Findings 汇总表
        if findings:
            lines.extend([
                "### Findings Summary",
                "",
                "| # | OWASP ID | Vulnerability | Severity | CVSS | Confidence | Attacks | Success |",
                "|---|----------|---------------|----------|------|------------|---------|---------|",
            ])
            for i, f in enumerate(findings, 1):
                # 从 coverage_matrix 获取攻击数和成功数
                cov = coverage_matrix.get(f.owasp_id, {})
                lines.append(
                    f"| {i} | {f.owasp_id} | {f.owasp_name} | {f.severity} | "
                    f"{f.cvss_score} | {f.confidence:.0%} | "
                    f"{cov.get('attack_count', 0)} | {cov.get('success_count', 0)} |"
                )
            lines.append("")

        for i, finding in enumerate(findings, 1):
            lines.extend([
                f"### 4.{i} {finding.owasp_name}",
                "",
                f"- **OWASP ID**: {finding.owasp_id}",
                f"- **Framework**: {finding.owasp_framework.upper()}",
                f"- **Severity**: {finding.severity}",
                f"- **CVSS Score**: {finding.cvss_score}",
                f"- **Attack Type**: {finding.attack_type}",
                f"- **Confidence**: {finding.confidence:.0%}",
                f"- **Description**: {finding.description}",
                "",
                f"**Potential Impact: {finding.severity}**",
                "",
                f"**MITRE Technique ID**: {', '.join(finding.mitre_techniques) if finding.mitre_techniques else 'N/A'}",
                "",
                "**Indicators**:",
            ])
            for indicator in finding.indicators:
                lines.append(f"- {indicator}")
            lines.extend(["", "**Suggested Remediation**:"])
            for remediation in finding.remediation:
                lines.append(f"- {remediation}")
            lines.append("")

            # R1+R2: 三级证据链 — 仅展示成功攻击的完整对话
            related_attacks = attack_details.get(finding.attack_type, [])
            successful_attacks = [d for d in related_attacks if d.get("outcome", "").upper() == "SUCCESS"]
            failed_attacks = [d for d in related_attacks if d.get("outcome", "").upper() != "SUCCESS"]

            # R1: 成功攻击 — 完整对话历史 (唯一出现位置)
            if successful_attacks:
                lines.extend(["**Confirmed Exploitation (Steps to Reproduce)**:", ""])
                for j, detail in enumerate(successful_attacks[:5], 1):
                    lines.extend([
                        f"#### Exploit {j}",
                        "",
                        f"- **Objective**: {detail['objective']}",
                        "- **Outcome**: ✅ SUCCESS",
                        f"- **Outcome Reason**: {detail.get('outcome_reason', 'Objective achieved')}",
                        f"- **Turns Executed**: {detail.get('executed_turns', 'N/A')}",
                        f"- **Execution Time**: {_format_time(detail.get('execution_time_ms'))}",
                        f"- **Conversation ID**: `{detail.get('conversation_id', 'N/A')}`",
                    ])

                    # 评分详情
                    score = detail.get("score", {})
                    if score and score.get("value") is not None:
                        lines.extend([
                            "",
                            f"- **Score Value**: {score.get('value')}",
                            f"- **Score Type**: {score.get('type', 'N/A')}",
                            f"- **Score Category**: {score.get('category', 'N/A')}",
                            f"- **Score Rationale**: {score.get('rationale', 'N/A')}",
                        ])

                    # Converter 信息
                    if detail.get("has_converters"):
                        lines.extend([
                            "",
                            f"- **Converter Chain**: `{detail.get('converter_chain_name', 'N/A')}`",
                            f"- **Converter Classes**: {', '.join(detail.get('converter_class_names', []))}",
                        ])
                    lines.append("")

                    # 完整对话历史 (三级证据链第三级) — K1: 使用原生渲染
                    conv_md = detail.get("conversation_md", "")
                    if conv_md:
                        lines.extend(["**Conversation History**:", "", conv_md, ""])
                    elif detail.get("conversation"):
                        # 回退: 手动渲染 (向后兼容)
                        lines.extend(["**Conversation History**:", ""])
                        for msg in detail["conversation"]:
                            role = msg.get("role", "unknown").upper()
                            text = msg.get("text", "")
                            lines.extend([f"**[{role}]**", "```", text, "```", ""])
                    else:
                        lines.extend(["*No conversation history available*", ""])

                    lines.extend(["---", ""])

            # R2: 失败攻击 — 仅表格摘要 (不含完整对话)
            if failed_attacks:
                lines.extend([
                    "**Failed Attempts Summary**:",
                    "",
                    "| # | Objective | Outcome | Turns | Time |",
                    "|---|-----------|---------|-------|------|",
                ])
                for j, detail in enumerate(failed_attacks[:10], 1):
                    obj = str(detail.get("objective", "N/A"))[:60].replace("|", "\\|")
                    lines.append(
                        f"| {j} | {obj} | {detail.get('outcome', 'N/A')} | "
                        f"{detail.get('executed_turns', 'N/A')} | "
                        f"{_format_time(detail.get('execution_time_ms'))} |"
                    )
                if len(failed_attacks) > 10:
                    lines.append(f"| ... | *{len(failed_attacks) - 10} more failed attempts* | | | |")
                lines.extend(["", "---", ""])

            if not successful_attacks and not failed_attacks:
                lines.extend(["*No attack data available for this finding.*", "", "---", ""])

        # R1+R4: Section 5 (Timeline) + Section 5.5 (Successful Highlights) 已移除
        # Timeline 数据见 attack_timeline.csv (Appendix D 引用)
        # Successful Highlights 对话已合并到 Section 4 (R1 消除重复)

        # ============================================================
        # 5. Converter Analysis
        # ============================================================
        if converter_report and converter_report.get("total_with_converters", 0) > 0:
            lines.extend([
                "## 5. Converter Analysis",
                "",
                "This section provides detailed analysis of converter transformations applied",
                "during the assessment. It includes transformation logs showing intermediate",
                "steps of each converter chain.",
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
            for chain_name, stats in sorted(
                chain_stats.items(), key=lambda x: x[1].get("success_rate", 0), reverse=True
            ):
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

        # ============================================================
        # 6. MITRE ATT&CK Mapping
        # ============================================================
        lines.extend(["## 6. MITRE ATT&CK Mapping", ""])
        mitre_map: dict[str, list[str]] = {}
        for finding in findings:
            for technique in finding.mitre_techniques:
                if technique not in mitre_map:
                    mitre_map[technique] = []
                mitre_map[technique].append(finding.owasp_id)

        for technique, owasp_ids in sorted(mitre_map.items()):
            lines.append(f"- **{technique}**: {', '.join(owasp_ids)}")
        if not mitre_map:
            lines.append("*No MITRE ATT&CK mappings available.*")
        lines.append("")

        # R4+R7: Tool Usage 移至 Appendix E
        tool_usage = self._extract_tool_usage(technique_distribution, converter_usage)

        # ============================================================
        # 7. Appendix — R6+R7 合并 C+D, 添加 Tool Usage + Timeline 引用
        # ============================================================
        lines.extend([
            "## 7. Appendix",
            "",
            "### Appendix A | Evidence Archive",
            "",
            "The complete evidence archive is included as a ZIP file containing:",
            "- `evidence.json` — Structured data (model dumps) for all attack results, scores, and conversations",
            "- `attacks/` — Per-attack Markdown reports with full conversation history and scores",
            "- `conversations/` — Per-conversation Markdown files with scores",
            "- `conversation_history.md` — Consolidated conversation log",
            "- `attack_summary.csv` — Complete attack summary with all metrics",
            "- `owasp_coverage_matrix.csv` — OWASP coverage matrix data",
            "- `attack_timeline.csv` — Chronological attack timeline",
            "",
            "### Appendix B | Risk Definitions",
            "",
            "| Severity | Definition |",
            "|----------|-----------|",
            "| Critical | Immediate threat: system compromise, data breach, or unauthorized code execution |",
            "| High | Significant vulnerability that could lead to unauthorized access or data exposure |",
            "| Medium | Moderate risk that may require specific conditions to exploit |",
            "| Low | Limited impact vulnerability, often informational |",
            "",
        ])

        # R6: 合并 Appendix C+D → Configuration & Reproduction
        memory_db = os.getenv("MEMORY_DB_TYPE", "DuckDB")
        db_path = os.getenv("MEMORY_DB_PATH", "memory.db")
        max_concurrency = os.getenv("MAX_CONCURRENCY", "5")
        per_attack_timeout = os.getenv("PER_ATTACK_TIMEOUT", "300")
        target_endpoint = os.getenv("TARGET_ENDPOINT", "N/A")
        target_model = os.getenv("TARGET_MODEL", "N/A")
        judge_endpoint = os.getenv("JUDGE_ENDPOINT", "N/A")
        judge_model = os.getenv("JUDGE_MODEL", "N/A")
        assessment_id = scenario_result.id if hasattr(scenario_result, "id") else "N/A"

        lines.extend([
            "### Appendix C | Configuration & Reproduction",
            "",
            "| Parameter | Value |",
            "|-----------|-------|",
            f"| Target Endpoint | `{target_endpoint}` |",
            f"| Target Model | `{target_model}` |",
            f"| Judge Endpoint | `{judge_endpoint}` |",
            f"| Judge Model | `{judge_model}` |",
            f"| Memory Backend | {memory_db} |",
            f"| Database Path | {db_path} |",
            f"| Max Concurrency | {max_concurrency} |",
            f"| Per-Attack Timeout | {per_attack_timeout}s |",
            f"| Assessment ID | {assessment_id} |",
            f"| Start Time | {start_time.isoformat()} |",
            "",
            "> **Note**: To reproduce, set the above parameters in `.env` and run:",
            "> ```bash",
            "> python main.py --load-owasp-local",
            "> ```",
            "",
        ])

        # R4: Attack Timeline 引用 CSV
        lines.extend([
            "### Appendix D | Attack Timeline",
            "",
            "The complete chronological attack timeline is available as `attack_timeline.csv`",
            "in the evidence archive. The CSV contains: attack index, type, objective,",
            "outcome, turns executed, and execution time for all attacks.",
            "",
        ])

        # R4: Tool Usage 移至 Appendix E
        lines.extend([
            "### Appendix E | Tool Usage",
            "",
            "| Tool | Description | Count |",
            "|------|-------------|-------|",
        ])
        for tool, (desc, count) in sorted(tool_usage.items(), key=lambda x: -x[1][1]):
            lines.append(f"| {tool} | {desc} | {count} |")
        lines.append("")

        return "\n".join(lines)

    def _extract_tool_usage(
        self,
        technique_distribution: dict[str, int],
        converter_usage: dict[str, int],
    ) -> dict[str, tuple[str, int]]:
        """从统计中动态提取工具使用信息。."""
        tools: dict[str, tuple[str, int]] = {
            "PyRIT": ("Python Risk Identification Toolkit for AI red teaming", 1),
            "OpenAIChatTarget": ("LLM target interface for sending prompts", 1),
        }

        # 从攻击技术分布提取实际使用的 Attack 类
        for technique, count in technique_distribution.items():
            if technique not in ("unknown", ""):
                tools[technique] = (f"Attack technique: {format_technique_display(technique)}", count)

        # 从 Converter 链使用提取
        for chain, count in converter_usage.items():
            tools[f"ConverterChain:{chain}"] = (f"Encoding/obfuscation converter chain: {chain}", count)

        return tools


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
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    report_base_name: str = "report",
) -> ReportResult:
    """生成报告 (工厂函数)。."""
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
        start_time=start_time,
        end_time=end_time,
        report_base_name=report_base_name,
    )


def map_attacks_to_owasp(attack_results: list[Any]) -> list[OWASPFinding]:
    """将攻击结果映射到 OWASP (工厂函数)。."""
    mapper = OWASPMapper()
    return mapper.map_attacks_to_findings(attack_results)
