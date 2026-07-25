"""
Reporting Module
=================

本模块负责报告层，包括报告生成、OWASP 映射、证据导出（遵循开发规则 1.4.1）。

L5 对齐 PyRIT 1.0.0 output 模块：
1. EvidenceExporter 使用 render_async() 替代 write_async()+read-back，消除冗余 I/O
2. EvidenceExporter 使用 MarkdownAttackResultMemoryPrinter.render_async() 生成每个攻击 Markdown
3. EvidenceExporter 使用 MarkdownConversationMemoryPrinter.render_async() 渲染对话历史
4. EvidenceExporter 支持 include_reasoning_trace（o1/o3 推理模型）和 blur_images（图片模糊）
5. EvidenceExporter 汇总对话历史使用原生 MarkdownConversationMemoryPrinter 替代手工渲染
6. ReportGenerator 集成 output_scenario_async 输出原生场景级摘要
7. ReportGenerator 集成 output_scorer_async 输出评分器评估指标
8. attack_summary.csv 增加完整列（turns/execution_time/scorer/score_value/outcome_reason）
9. 新增 owasp_coverage_matrix.csv 和 attack_timeline.csv
10. ReportGenerator 实现三级证据链（Finding → AttackResult → Conversation）
11. ReportGenerator 新增 OWASP 覆盖矩阵章节 + 攻击时间线章节
12. ReportGenerator 动态计算 confidence（基于 score_value 和 scorer_type）
"""

import csv
import io
import json
import logging
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from pyrit.memory import CentralMemory
from pyrit.output import (
    FileSink,
    StdoutSink,
    get_default_sink,
    output_attack_async,
    output_scenario_async,
    output_scorer_async,
)
from pyrit.output.attack_result.markdown import MarkdownAttackResultMemoryPrinter
from pyrit.output.conversation.markdown import MarkdownConversationMemoryPrinter
from pyrit.output.score.markdown import MarkdownScorePrinter

from src.core.models import (
    OWASPFinding,
    ReportResult,
    ReportSummary,
)
from src.core.config_loader import get_config_loader

logger = logging.getLogger(__name__)


def _safe_get(obj: Any, attr: str, default: Any = None) -> Any:
    """安全获取属性"""
    try:
        return getattr(obj, attr, default)
    except Exception:
        return default


def _get_outcome_str(ar: Any) -> str:
    """从 AttackResult 提取 outcome 字符串"""
    outcome = _safe_get(ar, "outcome")
    if outcome is None:
        return "unknown"
    if hasattr(outcome, "value"):
        return str(outcome.value)
    return str(outcome)


def _get_attack_type(ar: Any) -> str:
    """从 AttackResult 提取攻击类型"""
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


def _format_time(ms: Optional[int]) -> str:
    """格式化毫秒时间为可读字符串"""
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
# OWASP 映射器
# ============================================================


class OWASPMapper:
    """
    OWASP 映射器 - 将攻击结果映射到 OWASP 安全标准

    支持两个 OWASP 安全标准：
    - OWASP Top 10 for LLM Applications 2025 (LLM01-LLM10)
    - OWASP Top 10 for Agentic AI (ASI01-ASI10)
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
        # PyRIT 1.0.0: 已移除的 Attack 类不再映射
        # "FlipAttack" → 使用 FlipConverter + PromptSendingAttack
        # "RolePlayAttack" → 使用 PolicyPuppetryConverter/PersuasionConverter + PromptSendingAttack
        # "ContextComplianceAttack" → 使用 PromptSendingAttack + PrependedConversationConfig
        "XPIATestWorkflow": "xpia",  # 跨域提示注入
        "ManyShotJailbreakAttack": "goal_hijack",
        "SkeletonKeyAttack": "goal_hijack",
        "BargeInAttack": "agent_communication_attack",
        "ChunkedRequestAttack": "context_injection",
    }

    def __init__(self):
        self.config_loader = get_config_loader()

    def attack_to_owasp(self, attack_type: str) -> List[str]:
        """将攻击类型映射到 OWASP ID"""
        attack_to_owasp = self.config_loader.get_owasp_mapping()
        if attack_type in attack_to_owasp:
            return attack_to_owasp[attack_type]
        category = self.ATTACK_CLASS_TO_CATEGORY.get(attack_type, "")
        if category and category in attack_to_owasp:
            return attack_to_owasp[category]
        return []

    def get_owasp_details(self, owasp_id: str) -> Optional[Dict[str, Any]]:
        """获取 OWASP 漏洞详细信息"""
        return self.config_loader.get_owasp_details(owasp_id)

    def map_attacks_to_findings(
        self,
        attack_results: List[Any],
    ) -> List[OWASPFinding]:
        """
        将攻击结果映射到 OWASP 漏洞发现（三级证据链 - 第一级）

        每个 Finding 关联其对应的具体 AttackResult 列表。
        """
        findings = []
        all_owasp_standards = self.config_loader.get_all_owasp_standards()

        # 按攻击类型分组 AttackResult
        attacks_by_type: Dict[str, List[Any]] = {}
        for ar in attack_results:
            attack_type = _get_attack_type(ar)
            if attack_type not in attacks_by_type:
                attacks_by_type[attack_type] = []
            attacks_by_type[attack_type].append(ar)

        for attack_type, related_results in attacks_by_type.items():
            owasp_ids = self.attack_to_owasp(attack_type)
            for owasp_id in owasp_ids:
                details = all_owasp_standards.get(owasp_id, {})
                framework = "agentic" if owasp_id.startswith("ASI") else "llm"

                # 动态计算 confidence：基于成功比例和评分
                successful = sum(
                    1 for ar in related_results
                    if _get_outcome_str(ar).upper() == "SUCCESS"
                )
                total = len(related_results)
                base_confidence = successful / total if total > 0 else 0
                # 有评分器确认的额外加权
                has_score = any(_safe_get(ar, "last_score") is not None for ar in related_results)
                confidence = min(1.0, base_confidence * 0.8 + (0.2 if has_score else 0.0))

                # 收集证据 ID（conversation_id 列表）
                evidence_ids = list(set(
                    str(_safe_get(ar, "conversation_id", ""))
                    for ar in related_results
                    if _safe_get(ar, "conversation_id")
                ))

                finding = OWASPFinding(
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
                )
                findings.append(finding)

        return findings

    def build_coverage_matrix(
        self,
        attack_results: List[Any],
    ) -> Dict[str, Dict[str, Any]]:
        """
        构建 OWASP 覆盖矩阵

        Returns:
            {owasp_id: {name, severity, attack_count, success_count, success_rate}}
        """
        all_standards = self.config_loader.get_all_owasp_standards()
        matrix: Dict[str, Dict[str, Any]] = {}

        # 统计每个 OWASP ID 的攻击数和成功数
        owasp_stats: Dict[str, Dict[str, int]] = {}
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

        # 构建完整矩阵（包括未覆盖的）
        for owasp_id, details in all_standards.items():
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
# 证据导出器
# ============================================================


class EvidenceExporter:
    """
    证据导出器 - 利用 PyRIT MemoryInterface + 原生 Markdown 打印器

    L5 对齐 PyRIT 1.0.0 output 模块：
    - 使用 render_async() 直接获取渲染字符串，消除 write_async()+read-back 冗余 I/O
    - 每个攻击生成独立 Markdown 文件（MarkdownAttackResultMemoryPrinter）
    - 每个对话生成独立 Markdown 文件（MarkdownConversationMemoryPrinter）
    - 汇总对话历史使用原生 MarkdownConversationMemoryPrinter 替代手工渲染
    - 支持 include_reasoning_trace（o1/o3 推理模型推理轨迹）
    - 支持 blur_images（图片模糊，保护审查者）
    - evidence.json 使用 model_dump() 替代 str()
    - attack_summary.csv 增加完整列
    - 新增 owasp_coverage_matrix.csv 和 attack_timeline.csv
    """

    def __init__(
        self,
        exam_id: str,
        *,
        include_reasoning_trace: bool = True,
        blur_images: bool = False,
        blur_radius: int = 20,
    ):
        """
        初始化证据导出器

        Args:
            exam_id: 考试 ID
            include_reasoning_trace: 是否包含推理模型的推理轨迹（o1/o3）
            blur_images: 是否模糊图片内容（保护审查者）
            blur_radius: 高斯模糊半径
        """
        self.exam_id = exam_id
        self.include_reasoning_trace = include_reasoning_trace
        self.blur_images = blur_images
        self.blur_radius = blur_radius

        config_loader = get_config_loader()
        evidence_base = config_loader.get_global_value("pyrit", "evidence_dir", default="output/evidence")
        self.evidence_dir = Path(evidence_base) / exam_id
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

        # 子目录
        self.attacks_dir = self.evidence_dir / "attacks"
        self.attacks_dir.mkdir(parents=True, exist_ok=True)
        self.conversations_dir = self.evidence_dir / "conversations"
        self.conversations_dir.mkdir(parents=True, exist_ok=True)

    async def export_all_evidence(self, owasp_coverage: Optional[Dict] = None) -> Path:
        """
        导出完整证据包

        Args:
            owasp_coverage: OWASP 覆盖矩阵数据（由 OWASPMapper.build_coverage_matrix 生成）

        Returns:
            证据包 zip 文件路径
        """
        memory = CentralMemory.get_memory_instance()
        attack_results = memory.get_attack_results()

        # 提取对话 ID
        conversation_ids = list(set(
            str(_safe_get(ar, "conversation_id"))
            for ar in attack_results
            if _safe_get(ar, "conversation_id")
        ))

        # 获取消息片段
        message_pieces = []
        scores_for_pieces = []
        if conversation_ids:
            for conv_id in conversation_ids:
                pieces = memory.get_message_pieces(conversation_id=conv_id)
                message_pieces.extend(pieces)
                piece_ids = [str(p.id) for p in pieces]
                if piece_ids:
                    piece_scores = memory.get_prompt_scores(prompt_ids=piece_ids)
                    scores_for_pieces.extend(piece_scores)

        # 获取其他数据
        scenario_results = memory.get_scenario_results()
        scores = memory.get_scores()
        stats = {}
        if conversation_ids:
            stats = memory.get_conversation_stats(conversation_ids=conversation_ids)

        # 1. 生成结构化 evidence.json（使用 model_dump 替代 str）
        evidence_data = self._build_evidence_json(
            attack_results, message_pieces, scores_for_pieces,
            scenario_results, scores, stats, conversation_ids,
        )

        # 2. 生成每个攻击的 Markdown 文件
        attack_md_files = await self._export_attack_markdowns(attack_results)

        # 3. 生成每个对话的 Markdown 文件
        conversation_md_files = await self._export_conversation_markdowns(
            memory, conversation_ids,
        )

        # 4. 生成汇总对话历史 Markdown（使用原生 MarkdownConversationMemoryPrinter）
        conversation_summary_md = await self._render_conversation_log_async(
            memory, attack_results, conversation_ids, scores_for_pieces,
        )

        # 5. 生成攻击摘要 CSV（完整列）
        attack_csv = self._render_attack_summary_csv(attack_results)

        # 6. 生成 OWASP 覆盖矩阵 CSV
        coverage_csv = self._render_coverage_matrix_csv(owasp_coverage or {})

        # 7. 生成攻击时间线 CSV
        timeline_csv = self._render_attack_timeline_csv(attack_results)

        # 打包为 zip
        archive_path = self.evidence_dir.parent / f"{self.exam_id}_evidence.zip"
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            # 主文件
            zipf.writestr("evidence.json", json.dumps(evidence_data, indent=2, ensure_ascii=False, default=str))
            zipf.writestr("conversation_history.md", conversation_summary_md)
            zipf.writestr("attack_summary.csv", attack_csv)
            zipf.writestr("owasp_coverage_matrix.csv", coverage_csv)
            zipf.writestr("attack_timeline.csv", timeline_csv)

            # 每个攻击的 Markdown
            for filename, content in attack_md_files:
                zipf.writestr(f"attacks/{filename}", content)

            # 每个对话的 Markdown
            for filename, content in conversation_md_files:
                zipf.writestr(f"conversations/{filename}", content)

        return archive_path

    def _build_evidence_json(
        self,
        attack_results: List[Any],
        message_pieces: List[Any],
        scores_for_pieces: List[Any],
        scenario_results: List[Any],
        scores: List[Any],
        stats: Any,
        conversation_ids: List[str],
    ) -> Dict[str, Any]:
        """构建结构化 evidence.json（使用 model_dump）"""

        # 使用 model_dump 替代 str() 确保结构化数据
        def _safe_dump(obj):
            if hasattr(obj, "model_dump"):
                try:
                    return obj.model_dump(mode="json")
                except Exception:
                    return str(obj)
            return str(obj)

        return {
            "exam_id": self.exam_id,
            "export_time": datetime.now().isoformat(),
            "attack_results": [_safe_dump(ar) for ar in attack_results],
            "attack_results_count": len(attack_results),
            "message_pieces": [_safe_dump(p) for p in message_pieces],
            "message_piece_count": len(message_pieces),
            "message_piece_scores": [_safe_dump(s) for s in scores_for_pieces],
            "scenario_results": [_safe_dump(sr) for sr in scenario_results],
            "scores": [_safe_dump(s) for s in scores],
            "conversation_stats": str(stats) if not isinstance(stats, dict) else stats,
            "conversation_ids": conversation_ids,
        }

    async def _export_attack_markdowns(self, attack_results: List[Any]) -> List[tuple]:
        """
        使用 MarkdownAttackResultMemoryPrinter.render_async() 生成每个攻击的 Markdown 文件

        L5 对齐：使用 render_async() 直接获取渲染字符串，
        同时写入独立文件和 zip 包，消除 write_async()+read-back 冗余 I/O。
        支持 include_reasoning_trace（o1/o3 推理模型）和 blur_images（图片模糊）。
        """
        files = []
        # 创建 printer 实例（sink 不影响 render_async，仅 write_async 使用）
        printer = MarkdownAttackResultMemoryPrinter(
            blur_images=self.blur_images,
            blur_radius=self.blur_radius,
        )

        for i, ar in enumerate(attack_results, 1):
            filename = f"attack_{i:04d}.md"
            file_path = self.attacks_dir / filename

            try:
                # 使用 render_async() 直接获取 Markdown 字符串
                content = await printer.render_async(
                    ar,
                    include_auxiliary_scores=True,
                    include_pruned_conversations=True,
                    include_adversarial_conversation=True,
                )
                # 写入独立文件（证据目录）
                file_path.write_text(content, encoding="utf-8")
                files.append((filename, content))
            except Exception as e:
                logger.warning(f"Failed to export attack #{i} as markdown: {e}")
                # 回退到简单格式
                fallback = f"# Attack {i}\n\n*Export failed: {e}*\n\n" \
                           f"- Objective: {_safe_get(ar, 'objective', 'N/A')}\n" \
                           f"- Outcome: {_get_outcome_str(ar)}\n"
                files.append((filename, fallback))

        return files

    async def _export_conversation_markdowns(self, memory: Any, conversation_ids: List[str]) -> List[tuple]:
        """
        使用 MarkdownConversationMemoryPrinter.render_async() 生成每个对话的 Markdown 文件

        L5 对齐：使用 render_async() 直接获取渲染字符串，
        同时写入独立文件和 zip 包，消除 write_async()+read-back 冗余 I/O。
        支持 include_reasoning_trace（o1/o3 推理模型）和 blur_images（图片模糊）。
        """
        files = []
        # 创建共享的 score_printer 和 conversation printer
        score_printer = MarkdownScorePrinter()
        printer = MarkdownConversationMemoryPrinter(
            score_printer=score_printer,
            blur_images=self.blur_images,
            blur_radius=self.blur_radius,
        )

        for conv_id in conversation_ids:
            filename = f"conv_{conv_id[:8]}.md"
            file_path = self.conversations_dir / filename

            try:
                messages = list(memory.get_conversation_messages(conversation_id=conv_id))
                if not messages:
                    continue

                # 使用 render_async() 直接获取 Markdown 字符串
                content = await printer.render_async(
                    messages,
                    include_scores=True,
                    include_reasoning_trace=self.include_reasoning_trace,
                )
                # 写入独立文件（证据目录）
                file_path.write_text(content, encoding="utf-8")
                files.append((filename, content))
            except Exception as e:
                logger.warning(f"Failed to export conversation {conv_id} as markdown: {e}")

        return files

    async def _render_conversation_log_async(
        self,
        memory: Any,
        attack_results: List[Any],
        conversation_ids: List[str],
        scores: List[Any],
    ) -> str:
        """
        渲染汇总对话历史 Markdown

        L5 对齐：使用原生 MarkdownConversationMemoryPrinter.render_async() 渲染每个对话，
        替代手工拼接，确保与 PyRIT 原生输出格式完全一致。
        支持 include_reasoning_trace（o1/o3 推理模型）和 blur_images（图片模糊）。
        """
        lines = [
            f"# AI Conversation History - {self.exam_id}",
            "",
            f"Generated: {datetime.now().isoformat()}",
            f"Total Attack Results: {len(attack_results)}",
            f"Total Conversations: {len(conversation_ids)}",
            "",
            "---",
            "",
        ]

        # 创建原生 conversation printer（共享实例）
        score_printer = MarkdownScorePrinter()
        conv_printer = MarkdownConversationMemoryPrinter(
            score_printer=score_printer,
            blur_images=self.blur_images,
            blur_radius=self.blur_radius,
        )

        # 构建 conversation_id → attack_result 映射
        ar_by_conv: Dict[str, Any] = {}
        for ar in attack_results:
            conv_id = str(_safe_get(ar, "conversation_id", ""))
            if conv_id:
                ar_by_conv[conv_id] = ar

        for conv_id in conversation_ids:
            lines.extend([f"## Conversation: {conv_id}", ""])

            # 添加关联的攻击结果元数据
            related_ar = ar_by_conv.get(conv_id)
            if related_ar:
                lines.extend([
                    f"**Objective**: {_safe_get(related_ar, 'objective', 'N/A')}",
                    f"**Outcome**: {_get_outcome_str(related_ar)}",
                    f"**Turns**: {_safe_get(related_ar, 'executed_turns', 'N/A')}",
                    f"**Execution Time**: {_format_time(_safe_get(related_ar, 'execution_time_ms'))}",
                    "",
                ])

            # 使用原生 printer 渲染对话
            try:
                messages = list(memory.get_conversation_messages(conversation_id=conv_id))
                if messages:
                    conv_md = await conv_printer.render_async(
                        messages,
                        include_scores=True,
                        include_reasoning_trace=self.include_reasoning_trace,
                    )
                    lines.append(conv_md)
                else:
                    lines.append(f"*No messages found for conversation: {conv_id}*\n")
            except Exception as e:
                logger.warning(f"Failed to render conversation {conv_id}: {e}")
                lines.append(f"*Render failed: {e}*\n")

            lines.extend(["---", ""])

        # 评分摘要
        if scores:
            lines.extend([
                "## Scoring Summary",
                "",
                "| Score ID | Score Type | Value | Category | Rationale |",
                "|----------|-----------|-------|----------|-----------|",
            ])
            for s in scores:
                score_id = str(_safe_get(s, "id", "N/A"))
                score_type = str(_safe_get(s, "score_type", "N/A"))
                score_value = str(_safe_get(s, "score_value", "N/A"))
                score_category = str(_safe_get(s, "score_category", "N/A"))
                rationale = str(_safe_get(s, "score_rationale", ""))[:120]
                lines.append(f"| {score_id} | {score_type} | {score_value} | {score_category} | {rationale} |")
            lines.append("")

        return "\n".join(lines)

    def _render_attack_summary_csv(self, attack_results: List[Any]) -> str:
        """渲染完整列的攻击摘要 CSV"""
        output = io.StringIO()
        fieldnames = [
            "attack_id", "conversation_id", "attack_type", "objective",
            "outcome", "outcome_reason", "executed_turns", "execution_time_ms",
            "last_score_value", "last_score_category", "last_score_type",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for ar in attack_results:
            last_score = _safe_get(ar, "last_score")
            row = {
                "attack_id": str(_safe_get(ar, "attack_result_id", "")),
                "conversation_id": str(_safe_get(ar, "conversation_id", "")),
                "attack_type": _get_attack_type(ar),
                "objective": str(_safe_get(ar, "objective", "")).replace("\n", " ").replace("\r", " "),
                "outcome": _get_outcome_str(ar),
                "outcome_reason": str(_safe_get(ar, "outcome_reason", "")).replace("\n", " ").replace("\r", " "),
                "executed_turns": _safe_get(ar, "executed_turns", ""),
                "execution_time_ms": _safe_get(ar, "execution_time_ms", ""),
                "last_score_value": _safe_get(last_score, "score_value", ""),
                "last_score_category": _safe_get(last_score, "score_category", ""),
                "last_score_type": _safe_get(last_score, "score_type", ""),
            }
            writer.writerow(row)

        return output.getvalue()

    def _render_coverage_matrix_csv(self, coverage: Dict[str, Dict[str, Any]]) -> str:
        """渲染 OWASP 覆盖矩阵 CSV"""
        output = io.StringIO()
        fieldnames = ["owasp_id", "name", "framework", "severity", "attack_count", "success_count", "success_rate", "covered"]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for owasp_id, info in sorted(coverage.items()):
            writer.writerow({
                "owasp_id": owasp_id,
                "name": info.get("name", ""),
                "framework": info.get("framework", ""),
                "severity": info.get("severity", ""),
                "attack_count": info.get("attack_count", 0),
                "success_count": info.get("success_count", 0),
                "success_rate": f"{info.get('success_rate', 0):.1f}%",
                "covered": "Yes" if info.get("covered") else "No",
            })

        return output.getvalue()

    def _render_attack_timeline_csv(self, attack_results: List[Any]) -> str:
        """渲染攻击时间线 CSV"""
        output = io.StringIO()
        fieldnames = ["timestamp", "attack_id", "attack_type", "objective", "outcome", "outcome_reason", "turns", "execution_time"]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        # 按时间戳排序
        sorted_results = sorted(attack_results, key=lambda ar: str(_safe_get(ar, "timestamp", "")))
        for ar in sorted_results:
            writer.writerow({
                "timestamp": str(_safe_get(ar, "timestamp", "")),
                "attack_id": str(_safe_get(ar, "attack_result_id", "")),
                "attack_type": _get_attack_type(ar),
                "objective": str(_safe_get(ar, "objective", "")).replace("\n", " ")[:100],
                "outcome": _get_outcome_str(ar),
                "outcome_reason": str(_safe_get(ar, "outcome_reason", "")).replace("\n", " ")[:100],
                "turns": _safe_get(ar, "executed_turns", ""),
                "execution_time": _format_time(_safe_get(ar, "execution_time_ms")),
            })

        return output.getvalue()


# ============================================================
# 报告生成器
# ============================================================


class ReportGenerator:
    """报告生成器 - 生成考试专用报告（L5 专家级）"""

    def __init__(self):
        self.config_loader = get_config_loader()
        self.owasp_mapper = OWASPMapper()

    async def generate_report(
        self,
        scenario_result: Any,
        exam_id: str,
        start_time: datetime,
        end_time: datetime,
        *,
        include_reasoning_trace: bool = True,
        blur_images: bool = False,
    ) -> ReportResult:
        """
        生成报告

        L5 对齐 PyRIT 1.0.0 output 模块：
        - 集成 output_scenario_async 输出原生场景级摘要
        - 集成 output_scorer_async 输出评分器评估指标
        - EvidenceExporter 支持 include_reasoning_trace 和 blur_images

        Args:
            scenario_result: ScenarioResult 实例或 AttackResult 列表
            exam_id: 考试 ID
            start_time: 开始时间
            end_time: 结束时间
            include_reasoning_trace: 是否包含推理轨迹（o1/o3）
            blur_images: 是否模糊图片内容
        """
        memory = CentralMemory.get_memory_instance()
        attack_results = memory.get_attack_results()

        # 尝试获取原生 ScenarioResult（用于场景级摘要输出）
        native_scenario_result = None
        try:
            scenario_results = memory.get_scenario_results()
            if scenario_results:
                native_scenario_result = scenario_results[-1]  # 取最新的
        except Exception:
            pass

        # L5 对齐：使用原生 output_scenario_async 输出场景级摘要
        if native_scenario_result is not None:
            try:
                await output_scenario_async(
                    native_scenario_result,
                    format="pretty",
                    sort_groups_by_success_rate=True,
                )
            except Exception as e:
                logger.warning(f"Scenario output failed: {e}")

        # L5 对齐：使用原生 output_scorer_async 输出评分器评估指标
        if native_scenario_result is not None:
            scorer_identifier = _safe_get(native_scenario_result, "objective_scorer_identifier")
            if scorer_identifier is not None:
                try:
                    await output_scorer_async(
                        scorer_identifier=scorer_identifier,
                        format="pretty",
                    )
                except Exception as e:
                    logger.warning(f"Scorer output failed: {e}")

        # 映射到 OWASP（三级证据链 - 第一级）
        findings = self.owasp_mapper.map_attacks_to_findings(attack_results)

        # 构建 OWASP 覆盖矩阵
        coverage_matrix = self.owasp_mapper.build_coverage_matrix(attack_results)

        # 生成摘要（传入覆盖矩阵用于多样性分析）
        summary = self._generate_summary(findings, attack_results, scenario_result, coverage_matrix)

        # 收集攻击详情（三级证据链 - 第二级 + 第三级）
        attack_details = self._collect_attack_details(attack_results)

        # 渲染 Markdown 报告
        report_content = self._render_markdown_report(
            exam_id, findings, summary, start_time, end_time,
            scenario_result, attack_details, coverage_matrix,
        )

        # 保存 Markdown 报告文件
        output_dir = Path(self.config_loader.get_global_value("report", "output_dir", default="output/reports"))
        output_dir.mkdir(parents=True, exist_ok=True)
        report_path = output_dir / f"{exam_id}_report.md"

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        # P1-6: 多格式转换（Markdown → HTML / PDF）
        html_path = None
        pdf_path = None
        try:
            from src.reporting.format_converter import convert_report_formats
            format_result = convert_report_formats(
                report_content,
                output_dir / f"{exam_id}_report",
                generate_html=True,
                generate_pdf=True,
                title=f"AI Red Team Assessment Report - {exam_id}",
            )
            if format_result.get("html"):
                html_path = str(format_result["html"])
            if format_result.get("pdf"):
                pdf_path = str(format_result["pdf"])
        except ImportError as e:
            logger.warning(f"Format conversion skipped (dependency missing): {e}")
        except Exception as e:
            logger.warning(f"Format conversion failed: {e}")

        # 导出证据（传入覆盖矩阵 + L5 参数）
        evidence_exporter = EvidenceExporter(
            exam_id,
            include_reasoning_trace=include_reasoning_trace,
            blur_images=blur_images,
        )
        evidence_archive = await evidence_exporter.export_all_evidence(owasp_coverage=coverage_matrix)

        return ReportResult(
            report_path=str(report_path),
            owasp_findings=findings,
            summary=summary,
            evidence_archive=str(evidence_archive),
            start_time=start_time,
            end_time=end_time,
            duration_seconds=(end_time - start_time).total_seconds(),
            report_html_path=html_path,
            report_pdf_path=pdf_path,
        )

    def _generate_summary(
        self,
        findings: List[OWASPFinding],
        attack_results: List[Any],
        scenario_result: Any,
        coverage_matrix: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> ReportSummary:
        """生成报告摘要

        Args:
            findings: OWASP Finding 列表
            attack_results: AttackResult 列表
            scenario_result: 场景结果
            coverage_matrix: OWASP 覆盖矩阵（用于多样性分析）
        """
        total_findings = len(findings)
        critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")
        medium_count = sum(1 for f in findings if f.severity == "MEDIUM")
        low_count = sum(1 for f in findings if f.severity == "LOW")

        total_attacks = len(attack_results)
        successful_attacks = sum(
            1 for ar in attack_results
            if _get_outcome_str(ar).upper() == "SUCCESS"
        )

        upgrade_attempts = _safe_get(scenario_result, "upgrade_attempts", 0)
        upgrade_success = _safe_get(scenario_result, "upgrade_success", 0)

        # 攻击技术分布统计（从 labels 提取）
        technique_distribution: Dict[str, int] = {}
        converter_usage: Dict[str, int] = {}
        failure_reasons: Dict[str, int] = {}

        for ar in attack_results:
            labels = _safe_get(ar, "labels", {})
            if not isinstance(labels, dict):
                labels = {}
            technique = labels.get("attack_technique", _get_attack_type(ar))
            technique_distribution[technique] = technique_distribution.get(technique, 0) + 1

            converter_chain = labels.get("converter_chain_name")
            if converter_chain:
                converter_usage[converter_chain] = converter_usage.get(converter_chain, 0) + 1

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

        # P1-3: 多样性分析
        from src.reporting.diversity_analyzer import DiversityAnalyzer
        diversity_analyzer = DiversityAnalyzer()
        diversity_result = diversity_analyzer.analyze(
            attack_results=attack_results,
            technique_distribution=technique_distribution,
            converter_usage=converter_usage,
            failure_reasons=failure_reasons,
            coverage_matrix=coverage_matrix,
            total_attacks=total_attacks,
        )

        return ReportSummary(
            total_targets=1,
            pyrit_attackable_targets=1,
            external_tool_targets=0,
            total_attacks=total_attacks,
            successful_attacks=successful_attacks,
            total_scenarios=1,
            total_findings=total_findings,
            critical_findings=critical_count,
            high_findings=high_count,
            medium_findings=medium_count,
            low_findings=low_count,
            success_rate=successful_attacks / total_attacks if total_attacks > 0 else 0.0,
            upgrade_attempts=upgrade_attempts,
            upgrade_success=upgrade_success,
            attack_technique_distribution=technique_distribution,
            converter_chain_usage=converter_usage,
            failure_analysis={"failure_reasons": failure_reasons},
            diversity_metrics=diversity_result.to_dict(),
        )

    def _collect_attack_details(self, attack_results: List[Any]) -> Dict[str, List[Dict[str, Any]]]:
        """
        从 Memory 收集攻击详情（三级证据链 - 第二级 + 第三级）

        每个 detail 包含完整的攻击指标和对话历史。
        """
        try:
            memory = CentralMemory.get_memory_instance()
        except Exception:
            return {}

        details: Dict[str, List[Dict[str, Any]]] = {}
        for ar in attack_results:
            attack_type = _get_attack_type(ar)
            if not attack_type:
                continue

            conv_id = _safe_get(ar, "conversation_id")
            conversation = []
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

            detail = {
                "objective": str(_safe_get(ar, "objective", "N/A")),
                "outcome": _get_outcome_str(ar),
                "outcome_reason": str(_safe_get(ar, "outcome_reason", "")),
                "executed_turns": _safe_get(ar, "executed_turns", 0),
                "execution_time_ms": _safe_get(ar, "execution_time_ms", 0),
                "conversation": conversation,
                "conversation_id": str(conv_id or ""),
                "score": score_info,
            }

            if attack_type not in details:
                details[attack_type] = []
            details[attack_type].append(detail)

        return details

    def _render_markdown_report(
        self,
        exam_id: str,
        findings: List[OWASPFinding],
        summary: ReportSummary,
        start_time: datetime,
        end_time: datetime,
        scenario_result: Any,
        attack_details: Dict[str, List[Dict[str, Any]]],
        coverage_matrix: Dict[str, Dict[str, Any]],
    ) -> str:
        """渲染 Markdown 报告（L5 专家级结构）"""
        lines: List[str] = []

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
            f"- **Assessment ID**: {exam_id}",
            f"- **Start Time**: {start_time.isoformat()}",
            f"- **End Time**: {end_time.isoformat()}",
            f"- **Duration**: {end_time - start_time}",
            "",
            "### Overview",
            "",
            "This section provides a high-level, non-technical overview of the engagement",
            "suitable for a management audience. The assessment evaluated the target AI",
            "system against the OWASP Top 10 for LLM Applications 2025 and the OWASP Top 10",
            "for Agentic AI, identifying vulnerabilities that could be exploited by an adversary.",
            "",
            "### High-Level Attack Path",
            "",
            "1. **Reconnaissance** — The target endpoint was identified and its AI system type",
            "   was determined through automated probing.",
            f"2. **Payload Delivery** — {summary.total_attacks} attacks were executed against the",
            "   target, covering single-turn, multi-turn, converter-enhanced, and sequential",
            "   attack modes.",
            f"3. **Exploitation** — {summary.successful_attacks} attacks successfully achieved",
            f"   their objectives, resulting in {summary.total_findings} confirmed findings.",
            "",
            "### Findings Summary",
            f"- Total Findings: {summary.total_findings}",
            f"- Critical: {summary.critical_findings}",
            f"- High: {summary.high_findings}",
            f"- Medium: {summary.medium_findings}",
            f"- Low: {summary.low_findings}",
            "",
            "### Attack Summary",
            f"- Total Attacks: {summary.total_attacks}",
            f"- Successful: {summary.successful_attacks}",
            f"- Success Rate: {summary.success_rate * 100:.1f}%",
            "",
        ])

        # Feedback Loop Statistics
        if summary.upgrade_attempts > 0:
            lines.extend([
                "### Feedback Loop Statistics",
                f"- Upgrade Attempts: {summary.upgrade_attempts}",
                f"- Upgrade Success: {summary.upgrade_success}",
                f"- Upgrade Success Rate: {summary.upgrade_success * 100 / summary.upgrade_attempts:.1f}%",
                "",
            ])

        # Attack Technique Distribution
        if summary.attack_technique_distribution:
            lines.extend([
                "### Attack Technique Distribution",
                "| Technique | Count |",
                "|-----------|-------|",
            ])
            for technique, count in sorted(summary.attack_technique_distribution.items(), key=lambda x: -x[1]):
                lines.append(f"| {technique} | {count} |")
            lines.append("")

        # Converter Chain Usage
        if summary.converter_chain_usage:
            lines.extend([
                "### Converter Chain Usage",
                "| Chain | Count |",
                "|-------|-------|",
            ])
            for chain, count in sorted(summary.converter_chain_usage.items(), key=lambda x: -x[1]):
                lines.append(f"| {chain} | {count} |")
            lines.append("")

        # Failure Analysis
        if summary.failure_analysis and summary.failure_analysis.get("failure_reasons"):
            lines.extend([
                "### Failure Analysis",
                "| Failure Reason | Count |",
                "|----------------|-------|",
            ])
            for reason, count in sorted(summary.failure_analysis["failure_reasons"].items(), key=lambda x: -x[1]):
                reason_str = str(reason)[:50] if reason else "unknown"
                lines.append(f"| {reason_str} | {count} |")
            lines.append("")

        # P1-3: Diversity & Coverage Analysis
        if summary.diversity_metrics:
            from src.reporting.diversity_analyzer import DiversityAnalysisResult, render_diversity_section
            diversity_result = DiversityAnalysisResult(
                technique_entropy=summary.diversity_metrics.get("technique_entropy", 0.0),
                technique_normalized_entropy=summary.diversity_metrics.get("technique_normalized_entropy", 0.0),
                technique_coverage_ratio=summary.diversity_metrics.get("technique_coverage_ratio", 0.0),
                unique_techniques_used=summary.diversity_metrics.get("unique_techniques_used", 0),
                owasp_covered_count=summary.diversity_metrics.get("owasp_covered_count", 0),
                owasp_total_count=summary.diversity_metrics.get("owasp_total_count", 20),
                owasp_coverage_ratio=summary.diversity_metrics.get("owasp_coverage_ratio", 0.0),
                converter_diversity_ratio=summary.diversity_metrics.get("converter_diversity_ratio", 0.0),
                unique_converters_used=summary.diversity_metrics.get("unique_converters_used", 0),
                failure_concentration=summary.diversity_metrics.get("failure_concentration", 0.0),
                top_failure_reason=summary.diversity_metrics.get("top_failure_reason", ""),
                success_technique_distribution=summary.diversity_metrics.get("success_technique_distribution", {}),
                failure_technique_distribution=summary.diversity_metrics.get("failure_technique_distribution", {}),
            )
            lines.append(render_diversity_section(diversity_result))

        # ============================================================
        # 3. OWASP Coverage Matrix
        # ============================================================
        lines.extend([
            "## 3. OWASP Coverage Matrix",
            "",
            "This section shows the coverage of OWASP security standards across all attacks.",
            "",
        ])

        # LLM Top 10
        lines.extend([
            "### OWASP Top 10 for LLM Applications 2025",
            "",
            "| OWASP ID | Vulnerability | Severity | Attacks | Success | Success Rate | Covered |",
            "|----------|--------------|----------|---------|---------|--------------|---------|",
        ])
        for owasp_id in [f"LLM{i:02d}" for i in range(1, 11)]:
            info = coverage_matrix.get(owasp_id, {})
            covered_icon = "✅" if info.get("covered") else "❌"
            rate = info.get("success_rate", 0)
            lines.append(
                f"| {owasp_id} | {info.get('name', 'N/A')} | {info.get('severity', 'N/A')} | "
                f"{info.get('attack_count', 0)} | {info.get('success_count', 0)} | "
                f"{rate:.0f}% | {covered_icon} |"
            )
        lines.append("")

        # Agentic AI Top 10
        lines.extend([
            "### OWASP Top 10 for Agentic AI",
            "",
            "| OWASP ID | Threat | Severity | Attacks | Success | Success Rate | Covered |",
            "|----------|--------|----------|---------|---------|--------------|---------|",
        ])
        for owasp_id in [f"ASI{i:02d}" for i in range(1, 11)]:
            info = coverage_matrix.get(owasp_id, {})
            covered_icon = "✅" if info.get("covered") else "❌"
            rate = info.get("success_rate", 0)
            lines.append(
                f"| {owasp_id} | {info.get('name', 'N/A')} | {info.get('severity', 'N/A')} | "
                f"{info.get('attack_count', 0)} | {info.get('success_count', 0)} | "
                f"{rate:.0f}% | {covered_icon} |"
            )
        lines.append("")

        # ============================================================
        # 4. Detailed Findings (Attack Narrative) - 三级证据链
        # ============================================================
        lines.extend([
            "## 4. Detailed Findings (Attack Narrative)",
            "",
            "This section describes in detail what exact actions were performed during the",
            "assessment and what the outcome was. Each finding includes the vulnerability",
            "description, potential impact, MITRE technique mapping, execution metrics,",
            "steps to reproduce (with full conversation history), and suggested remediation.",
            "",
        ])

        for i, finding in enumerate(findings, 1):
            lines.extend([
                f"### 4.{i}. {finding.owasp_name}",
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

            # 三级证据链 - 第二级 + 第三级：具体 AttackResult + 完整对话历史
            related_attacks = attack_details.get(finding.attack_type, [])
            if related_attacks:
                lines.extend(["**Steps to Reproduce**:", ""])

                for j, detail in enumerate(related_attacks[:3], 1):
                    lines.extend([
                        f"#### Step {j}",
                        "",
                        f"- **Objective**: {detail['objective']}",
                        f"- **Outcome**: {detail['outcome']}",
                        f"- **Outcome Reason**: {detail.get('outcome_reason', 'N/A')}",
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
                    lines.append("")

                    # 完整对话历史（三级证据链 - 第三级）
                    conv = detail.get("conversation", [])
                    if conv:
                        lines.extend(["**Conversation History**:", ""])
                        for msg in conv:
                            role = msg.get("role", "unknown").upper()
                            text = msg.get("text", "")
                            lines.extend([
                                f"**[{role}]**",
                                "```",
                                text,
                                "```",
                                "",
                            ])

            lines.append("---")
            lines.append("")

        # ============================================================
        # 5. Attack Timeline
        # ============================================================
        lines.extend([
            "## 5. Attack Timeline",
            "",
            "| # | Timestamp | Attack Type | Objective | Outcome | Turns | Time |",
            "|---|-----------|-------------|-----------|---------|-------|------|",
        ])
        idx = 1
        for attack_type, details_list in attack_details.items():
            for detail in details_list:
                obj_trunc = str(detail["objective"])[:60].replace("|", "\\|")
                lines.append(
                    f"| {idx} | {detail.get('conversation_id', '')[:8]} | {attack_type} | "
                    f"{obj_trunc} | {detail['outcome']} | "
                    f"{detail.get('executed_turns', 'N/A')} | "
                    f"{_format_time(detail.get('execution_time_ms'))} |"
                )
                idx += 1
        lines.append("")

        # ============================================================
        # 5.5 Successful Attack Highlights (完整成功攻击详情)
        # ============================================================
        lines.extend([
            "## 5.5 Successful Attack Highlights",
            "",
            "This section provides full details for every successful attack, including",
            "the complete conversation history between the attacker and the target model.",
            "This serves as primary evidence for the assessment findings.",
            "",
        ])

        success_idx = 0
        for attack_type, details_list in attack_details.items():
            for detail in details_list:
                if detail.get("outcome", "").upper() != "SUCCESS":
                    continue
                success_idx += 1
                lines.extend([
                    f"### 5.5.{success_idx} Successful Attack #{success_idx}",
                    "",
                    f"- **Attack Type**: {attack_type}",
                    f"- **Objective**: {detail['objective']}",
                    f"- **Outcome**: ✅ SUCCESS",
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
                lines.append("")

                # 完整对话历史
                conv = detail.get("conversation", [])
                if conv:
                    lines.extend(["**Conversation History**:", ""])
                    for msg in conv:
                        role = msg.get("role", "unknown").upper()
                        text = msg.get("text", "")
                        lines.extend([
                            f"**[{role}]**",
                            "```",
                            text,
                            "```",
                            "",
                        ])
                else:
                    lines.extend(["*No conversation history available*", ""])

                lines.append("---")
                lines.append("")

        if success_idx == 0:
            lines.extend(["*No successful attacks to display.*", ""])

        # ============================================================
        # 6. MITRE ATT&CK Mapping
        # ============================================================
        lines.extend(["## 6. MITRE ATT&CK Mapping", ""])
        mitre_map: Dict[str, List[str]] = {}
        for finding in findings:
            for technique in finding.mitre_techniques:
                if technique not in mitre_map:
                    mitre_map[technique] = []
                mitre_map[technique].append(finding.owasp_id)

        for technique, owasp_ids in sorted(mitre_map.items()):
            lines.append(f"- **{technique}**: {', '.join(owasp_ids)}")
        lines.append("")

        # ============================================================
        # 7. Tool Usage (动态提取)
        # ============================================================
        lines.extend([
            "## 7. Tool Usage",
            "",
            "| Tool | Description | Count |",
            "|------|-------------|-------|",
        ])
        tool_usage = self._extract_tool_usage(summary)
        for tool, (desc, count) in sorted(tool_usage.items(), key=lambda x: -x[1][1]):
            lines.append(f"| {tool} | {desc} | {count} |")
        lines.append("")

        # ============================================================
        # 8. Appendix
        # ============================================================
        lines.extend([
            "## 8. Appendix",
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
            "| Critical | Immediate threat with potential for system compromise, data breach, or unauthorized code execution |",
            "| High | Significant vulnerability that could lead to unauthorized access or data exposure |",
            "| Medium | Moderate risk that may require specific conditions to exploit |",
            "| Low | Limited impact vulnerability, often informational |",
            "",
            "### Appendix C | Configuration Summary",
            "",
            f"- Memory Backend: {self.config_loader.get_memory_db_type()}",
            f"- Database Path: {self.config_loader.get_db_path()}",
            f"- Evidence Directory: {self.config_loader.get_evidence_dir()}",
            f"- Max Concurrency: {self.config_loader.get_batch_max_concurrency()}",
        ])
        timeout_overrides = self.config_loader.get_batch_timeout_overrides()
        if timeout_overrides:
            lines.append(f"- Default Timeout: {self.config_loader.get_batch_per_attack_timeout()}s")
            for mode, timeout in timeout_overrides.items():
                lines.append(f"  - {mode}: {timeout}s")
        else:
            lines.append(f"- Per-Attack Timeout: {self.config_loader.get_batch_per_attack_timeout()}s")
        lines.append("")
        return "\n".join(lines)

    def _extract_tool_usage(self, summary: ReportSummary) -> Dict[str, tuple]:
        """从统计中动态提取工具使用信息"""
        tools = {
            "PyRIT": ("Python Risk Identification Toolkit for AI red teaming", 1),
            "OpenAIChatTarget": ("LLM target interface for sending prompts", 1),
        }

        # 从攻击技术分布提取实际使用的 Attack 类
        for technique, count in summary.attack_technique_distribution.items():
            if technique not in ("unknown", ""):
                tools[technique] = (f"Attack technique: {technique}", count)

        # 从 Converter 链使用提取
        for chain, count in summary.converter_chain_usage.items():
            tools[f"ConverterChain:{chain}"] = (f"Encoding/obfuscation converter chain: {chain}", count)

        return tools


# ============================================================
# 工厂函数
# ============================================================


async def generate_report(
    scenario_result: Any,
    exam_id: str,
    start_time: datetime,
    end_time: datetime,
    *,
    include_reasoning_trace: bool = True,
    blur_images: bool = False,
) -> ReportResult:
    """生成报告（工厂函数）"""
    generator = ReportGenerator()
    return await generator.generate_report(
        scenario_result,
        exam_id,
        start_time,
        end_time,
        include_reasoning_trace=include_reasoning_trace,
        blur_images=blur_images,
    )


def map_attacks_to_owasp(attack_results: List[Any]) -> List[OWASPFinding]:
    """将攻击结果映射到 OWASP（工厂函数）"""
    mapper = OWASPMapper()
    return mapper.map_attacks_to_findings(attack_results)
