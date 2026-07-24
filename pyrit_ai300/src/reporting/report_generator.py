"""
Reporting Module
=================

本模块负责报告层，包括报告生成、OWASP 映射、证据导出（遵循开发规则 1.4.1）。
"""

import json
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from pyrit.memory import CentralMemory
from pyrit.output import output_scenario_async

from src.core.models import (
    AISystemType,
    OWASPFinding,
    ReportResult,
    ReportSummary,
    AttackEvidence,
)
from src.core.config_loader import get_config_loader


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

    # PyRIT 攻击类名到攻击类别名的映射
    ATTACK_CLASS_TO_CATEGORY = {
        "PromptSendingAttack": "prompt_injection",
        "RedTeamingAttack": "jailbreak",
        "CrescendoAttack": "jailbreak",
        "TAPAttack": "jailbreak",
        "PAIRAttack": "jailbreak",
        "XPIATestWorkflow": "xpia",
        "FlipAttack": "prompt_injection",
        "FuzzerAttack": "prompt_injection",
        # Agentic AI 相关攻击映射
        "ManyShotJailbreakAttack": "goal_hijack",
        "SkeletonKeyAttack": "goal_hijack",
        "RolePlayAttack": "identity_abuse",
        "BargeInAttack": "agent_communication_attack",
        "ChunkedRequestAttack": "context_injection",
        "ContextComplianceAttack": "context_injection",
    }

    def __init__(self):
        """初始化 OWASP 映射器"""
        self.config_loader = get_config_loader()

    def attack_to_owasp(self, attack_type: str) -> List[str]:
        """
        将攻击类型映射到 OWASP ID

        支持两种输入：
        1. 攻击类别名（如 "prompt_injection", "jailbreak"）
        2. PyRIT 攻击类名（如 "RedTeamingAttack", "XPIATestWorkflow"）

        Args:
            attack_type: 攻击类型（类别名或类名）

        Returns:
            OWASP ID 列表，如 ["LLM01"] 或 ["ASI01", "ASI02"]
        """
        attack_to_owasp = self.config_loader.get_owasp_mapping()

        # 如果直接匹配，返回结果
        if attack_type in attack_to_owasp:
            return attack_to_owasp[attack_type]

        # 尝试通过类名到类别名映射查找
        category = self.ATTACK_CLASS_TO_CATEGORY.get(attack_type, "")
        if category and category in attack_to_owasp:
            return attack_to_owasp[category]

        return []

    def get_owasp_details(self, owasp_id: str) -> Optional[Dict[str, Any]]:
        """
        获取 OWASP 漏洞详细信息

        Args:
            owasp_id: OWASP ID，如 "LLM01"

        Returns:
            OWASP 详情字典，如果不存在则返回 None
        """
        return self.config_loader.get_owasp_details(owasp_id)

    def map_attacks_to_findings(
        self,
        attack_results: List[Any],
    ) -> List[OWASPFinding]:
        """
        将攻击结果映射到 OWASP 漏洞发现

        Args:
            attack_results: 攻击结果列表 (AttackResult)

        Returns:
            OWASPFinding 列表
        """
        findings = []
        all_owasp_standards = self.config_loader.get_all_owasp_standards()

        # 从攻击结果中提取攻击类型
        # AttackResult 使用 get_attack_strategy_identifier() 获取攻击类名
        # 返回格式如 "PromptSendingAttack::b8cedcae"，需要提取类名部分
        attack_types = set()
        for attack_result in attack_results:
            # 优先使用 get_attack_strategy_identifier() (非废弃 API)
            try:
                strategy_id = attack_result.get_attack_strategy_identifier()
                if strategy_id:
                    class_name = str(strategy_id).split("::")[0]
                    attack_types.add(class_name)
                    continue
            except Exception:
                pass

            # 回退到 atomic_attack_identifier
            attack_class = getattr(attack_result, "atomic_attack_identifier", None)
            if attack_class:
                attack_types.add(str(attack_class).split("::")[0])

        # 映射到 OWASP
        for attack_type in attack_types:
            owasp_ids = self.attack_to_owasp(attack_type)
            for owasp_id in owasp_ids:
                details = all_owasp_standards.get(owasp_id, {})
                # 判断属于哪个 OWASP 框架
                framework = "agentic" if owasp_id.startswith("ASI") else "llm"
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
                    mitre_techniques=details.get("mitre_techniques", []),
                    confidence=0.8,  # 简化处理
                )
                findings.append(finding)

        return findings


# ============================================================
# 证据导出器
# ============================================================


class EvidenceExporter:
    """证据导出器 - 利用 PyRIT MemoryInterface 原生导出功能收集证据"""

    def __init__(self, exam_id: str):
        """
        初始化证据导出器

        Args:
            exam_id: 考试 ID
        """
        self.exam_id = exam_id
        config_loader = get_config_loader()
        evidence_base = config_loader.get_global_value("pyrit", "evidence_dir", default="output/evidence")
        self.evidence_dir = Path(evidence_base) / exam_id
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    async def export_all_evidence(self) -> Path:
        """
        导出完整证据包（利用 MemoryInterface 原生方法）

        使用 get_message_pieces 替代已废弃的 export_conversations，
        直接序列化对话记录。同时生成结构化对话日志和 Markdown 证据文件。

        Returns:
            证据包 zip 文件路径
        """
        memory = CentralMemory.get_memory_instance()

        # 获取攻击结果
        attack_results = memory.get_attack_results()

        # 从攻击结果中提取对话 ID
        conversation_ids = list(set(
            str(ar.conversation_id) for ar in attack_results
            if hasattr(ar, "conversation_id") and ar.conversation_id
        ))

        # 使用 get_message_pieces 获取对话记录（替代已废弃的 export_conversations）
        message_pieces = []
        scores_for_pieces = []
        if conversation_ids:
            for conv_id in conversation_ids:
                pieces = memory.get_message_pieces(conversation_id=conv_id)
                message_pieces.extend(pieces)
                # 获取每条消息的评分
                piece_ids = [str(p.id) for p in pieces]
                if piece_ids:
                    piece_scores = memory.get_prompt_scores(prompt_ids=piece_ids)
                    scores_for_pieces.extend(piece_scores)

        # 序列化对话数据
        conversations_data = json.dumps(
            [p.model_dump(mode="json") for p in message_pieces],
            indent=2,
            ensure_ascii=False,
            default=str,
        )

        scenario_results = memory.get_scenario_results()
        scores = memory.get_scores()

        # get_conversation_stats 需要 conversation_ids 参数
        stats = {}
        if conversation_ids:
            stats = memory.get_conversation_stats(conversation_ids=conversation_ids)

        # 保存到 JSON 文件
        evidence_data = {
            "exam_id": self.exam_id,
            "export_time": datetime.now().isoformat(),
            "conversations": conversations_data,
            "attack_results": [str(ar) for ar in attack_results],
            "attack_results_count": len(attack_results),
            "scenario_results": [str(sr) for sr in scenario_results],
            "scores": [str(s) for s in scores],
            "message_piece_scores": [str(s) for s in scores_for_pieces],
            "message_piece_count": len(message_pieces),
            "stats": str(stats),
            "conversation_ids": conversation_ids,
        }

        # 生成 Markdown 格式的对话历史证据
        conversation_md = self._render_conversation_log(
            attack_results, message_pieces, scores_for_pieces
        )

        # 生成攻击摘要 CSV（便于快速查阅）
        attack_csv = self._render_attack_summary_csv(attack_results)

        # 打包为 zip
        archive_path = self.evidence_dir.parent / f"{self.exam_id}_evidence.zip"
        with zipfile.ZipFile(archive_path, "w") as zipf:
            zipf.writestr(
                "evidence.json",
                json.dumps(evidence_data, indent=2, ensure_ascii=False, default=str),
            )
            zipf.writestr(
                "conversation_history.md",
                conversation_md,
            )
            zipf.writestr(
                "attack_summary.csv",
                attack_csv,
            )

        return archive_path

    def _render_conversation_log(
        self,
        attack_results: List[Any],
        message_pieces: List[Any],
        scores: List[Any],
    ) -> str:
        """渲染 Markdown 格式的对话历史证据"""
        lines = [
            f"# AI Conversation History - {self.exam_id}",
            "",
            f"Generated: {datetime.now().isoformat()}",
            f"Total Attack Results: {len(attack_results)}",
            f"Total Message Pieces: {len(message_pieces)}",
            "",
            "---",
            "",
        ]

        # 按对话 ID 分组消息
        conv_messages: Dict[str, List[Any]] = {}
        for p in message_pieces:
            conv_id = str(getattr(p, "conversation_id", "unknown"))
            if conv_id not in conv_messages:
                conv_messages[conv_id] = []
            conv_messages[conv_id].append(p)

        # 按对话 ID 渲染
        for conv_id, msgs in conv_messages.items():
            lines.extend([
                f"## Conversation: {conv_id}",
                "",
            ])

            # 找到对应的攻击结果
            related_ar = None
            for ar in attack_results:
                if str(getattr(ar, "conversation_id", "")) == conv_id:
                    related_ar = ar
                    break

            if related_ar:
                objective = str(getattr(related_ar, "objective", "N/A"))
                outcome_obj = getattr(related_ar, "outcome", None)
                outcome = str(outcome_obj.value if outcome_obj and hasattr(outcome_obj, "value") else outcome_obj or "unknown")

                lines.extend([
                    f"**Objective**: {objective}",
                    f"**Outcome**: {outcome}",
                    "",
                ])

            # 渲染每条消息
            for msg in msgs:
                role = str(getattr(msg, "role", "unknown")).upper()
                text = str(getattr(msg, "converted_value", getattr(msg, "original_value", "")))
                timestamp = str(getattr(msg, "timestamp", ""))

                lines.extend([
                    f"### [{role}] - {timestamp}",
                    "",
                    "```",
                    text,
                    "```",
                    "",
                ])

            lines.extend(["---", ""])

        # 添加评分摘要
        if scores:
            lines.extend([
                "## Scoring Summary",
                "",
                "| Score ID | Score Type | Value | Rationale |",
                "|----------|-----------|-------|-----------|",
            ])
            for s in scores:
                score_id = str(getattr(s, "id", "N/A"))
                score_type = str(getattr(s, "score_type", "N/A"))
                score_value = str(getattr(s, "score_value", "N/A"))
                rationale = str(getattr(s, "rationale", ""))[:100]
                lines.append(f"| {score_id} | {score_type} | {score_value} | {rationale} |")
            lines.append("")

        return "\n".join(lines)

    def _render_attack_summary_csv(self, attack_results: List[Any]) -> str:
        """渲染 CSV 格式的攻击摘要"""
        lines = [
            "attack_id,conversation_id,attack_type,objective,outcome",
        ]
        for ar in attack_results:
            conv_id = str(getattr(ar, "conversation_id", ""))
            objective = str(getattr(ar, "objective", "")).replace('"', "'").replace("\n", " ")
            outcome_obj = getattr(ar, "outcome", None)
            outcome = str(outcome_obj.value if outcome_obj and hasattr(outcome_obj, "value") else outcome_obj or "unknown")

            attack_type = ""
            try:
                strategy_id = ar.get_attack_strategy_identifier()
                if strategy_id:
                    attack_type = str(strategy_id).split("::")[0]
            except Exception:
                pass

            lines.append(f'"{conv_id}","{conv_id}","{attack_type}","{objective}","{outcome}"')

        return "\n".join(lines)


# ============================================================
# 报告生成器
# ============================================================


class ReportGenerator:
    """报告生成器 - 生成考试专用报告"""

    def __init__(self):
        """初始化报告生成器"""
        self.config_loader = get_config_loader()
        self.owasp_mapper = OWASPMapper()

    async def generate_report(
        self,
        scenario_result: Any,
        exam_id: str,
        start_time: datetime,
        end_time: datetime,
    ) -> ReportResult:
        """
        生成报告

        Args:
            scenario_result: Scenario 结果
            exam_id: 考试 ID
            start_time: 开始时间
            end_time: 结束时间

        Returns:
            报告结果
        """
        # 1. 从 Memory 获取攻击结果
        memory = CentralMemory.get_memory_instance()
        attack_results = memory.get_attack_results()

        # 2. 映射到 OWASP
        findings = self.owasp_mapper.map_attacks_to_findings(attack_results)

        # 3. 生成摘要
        summary = self._generate_summary(
            findings, attack_results, scenario_result
        )

        # 4. 渲染 Markdown 报告
        report_content = self._render_markdown_report(
            exam_id, findings, summary, start_time, end_time, scenario_result
        )

        # 5. 保存报告文件
        output_dir = Path(self.config_loader.get_global_value("report", "output_dir", default="reports"))
        output_dir.mkdir(parents=True, exist_ok=True)
        report_path = output_dir / f"{exam_id}_report.md"

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        # 6. 导出证据
        evidence_exporter = EvidenceExporter(exam_id)
        evidence_archive = await evidence_exporter.export_all_evidence()

        # 7. 创建 ReportResult
        return ReportResult(
            report_path=str(report_path),
            owasp_findings=findings,
            summary=summary,
            evidence_archive=str(evidence_archive),
            start_time=start_time,
            end_time=end_time,
            duration_seconds=(end_time - start_time).total_seconds(),
        )

    def _generate_summary(
        self,
        findings: List[OWASPFinding],
        attack_results: List[Any],
        scenario_result: Any,
    ) -> ReportSummary:
        """生成报告摘要"""
        total_findings = len(findings)
        critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")
        medium_count = sum(1 for f in findings if f.severity == "MEDIUM")
        low_count = sum(1 for f in findings if f.severity == "LOW")

        total_attacks = len(attack_results)
        # AttackResult 使用 outcome 字段 (AttackOutcome 枚举: SUCCESS/FAILURE/ERROR/UNDETERMINED)
        # outcome.value 为小写字符串 (如 "success")，outcome.name 为大写 (如 "SUCCESS")
        successful_attacks = sum(
            1 for ar in attack_results
            if getattr(ar, "outcome", None) is not None
            and ar.outcome.value.upper() == "SUCCESS"
        )

        # 反馈循环统计
        upgrade_attempts = getattr(scenario_result, "upgrade_attempts", 0)
        upgrade_success = getattr(scenario_result, "upgrade_success", 0)

        # 攻击技术分布统计
        technique_distribution: Dict[str, int] = {}
        converter_usage: Dict[str, int] = {}
        failure_reasons: Dict[str, int] = {}

        for ar in attack_results:
            # 从 memory_labels 获取攻击技术
            labels = getattr(ar, "memory_labels", {})
            technique = labels.get("attack_technique", "unknown")
            technique_distribution[technique] = technique_distribution.get(technique, 0) + 1

            # Converter 链使用统计
            converter_chain = labels.get("converter_chain_name")
            if converter_chain:
                converter_usage[converter_chain] = converter_usage.get(converter_chain, 0) + 1

            # 失败分析
            outcome = getattr(ar, "outcome", None)
            if outcome is not None:
                outcome_str = str(outcome.value).upper()
                if outcome_str in ("FAILURE", "ERROR"):
                    # 按错误类型分类，而非保留完整 traceback
                    raw_error = ""
                    if hasattr(ar, "error_message") and ar.error_message:
                        raw_error = str(ar.error_message)
                    # 分类错误
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

        return ReportSummary(
            total_targets=1,  # 简化
            pyrit_attackable_targets=1,  # 简化
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
        )

    def _render_markdown_report(
        self,
        exam_id: str,
        findings: List[OWASPFinding],
        summary: ReportSummary,
        start_time: datetime,
        end_time: datetime,
        scenario_result: Any,
    ) -> str:
        """渲染 Markdown 报告"""
        lines = [
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
            "## 2. Executive Summary",
            "",
            f"- Assessment ID: {exam_id}",
            f"- Start Time: {start_time.isoformat()}",
            f"- End Time: {end_time.isoformat()}",
            f"- Duration: {end_time - start_time}",
            "",
            "### Overview",
            "",
            "This section provides a high-level, non-technical overview of the engagement",
            "suitable for a management audience. The assessment evaluated the target AI",
            "system against the OWASP Top 10 for LLM Applications and the OWASP Top 10 for",
            "Agentic AI, identifying vulnerabilities that could be exploited by an adversary.",
            "",
            "### High-Level Attack Path",
            "",
            f"1. **Reconnaissance** — The target endpoint was identified and its AI system type",
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
            "### Feedback Loop Statistics",
            f"- Upgrade Attempts: {summary.upgrade_attempts}",
            f"- Upgrade Success: {summary.upgrade_success}",
            f"- Upgrade Success Rate: {summary.upgrade_success * 100 / summary.upgrade_attempts:.1f}%" if summary.upgrade_attempts > 0 else "- Upgrade Success Rate: N/A",
            "",
            "### Attack Technique Distribution",
            "| Technique | Count |",
            "|-----------|-------|",
        ]
        for technique, count in sorted(summary.attack_technique_distribution.items(), key=lambda x: -x[1]):
            lines.append(f"| {technique} | {count} |")
        lines.append("")

        if summary.converter_chain_usage:
            lines.extend([
                "### Converter Chain Usage",
                "| Chain | Count |",
                "|-------|-------|",
            ])
            for chain, count in sorted(summary.converter_chain_usage.items(), key=lambda x: -x[1]):
                lines.append(f"| {chain} | {count} |")
            lines.append("")

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

        lines.extend([
            "## 3. Detailed Findings (Attack Narrative)",
            "",
            "This section describes in detail what exact actions were performed during the",
            "assessment and what the outcome was. Each finding includes the vulnerability",
            "description, potential impact, MITRE technique mapping, steps to reproduce,",
            "and suggested remediation.",
            "",
        ])

        # 从 Memory 获取攻击对话详情
        attack_details = self._collect_attack_details()

        for i, finding in enumerate(findings, 1):
            lines.extend([
                f"### 3.{i}. {finding.owasp_name}",
                "",
                f"- **OWASP ID**: {finding.owasp_id}",
                f"- **Framework**: {finding.owasp_framework.upper()}",
                f"- **Severity**: {finding.severity}",
                f"- **CVSS Score**: {finding.cvss_score}",
                f"- **Attack Type**: {finding.attack_type}",
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
            lines.extend([
                "",
                "**Suggested Remediation**:",
            ])
            for remediation in finding.remediation:
                lines.append(f"- {remediation}")
            lines.append("")

            # 添加该 finding 对应的攻击证据
            related_attacks = attack_details.get(finding.attack_type, [])
            if related_attacks:
                lines.extend([
                    "**Steps to Reproduce**:",
                    "",
                ])
                for j, detail in enumerate(related_attacks[:3], 1):
                    lines.append(f"Step {j}:")
                    lines.append(f"```")
                    lines.append(f"Objective: {detail['objective']}")
                    lines.append(f"Outcome: {detail['outcome']}")
                    if detail.get('conversation'):
                        lines.append("")
                        lines.append("--- Conversation ---")
                        for msg in detail['conversation']:
                            role = msg.get('role', 'unknown').upper()
                            text = msg.get('text', '')
                            lines.append(f"[{role}]: {text[:500]}")
                    lines.append(f"```")
                    lines.append("")

        # 添加 MITRE ATT&CK 映射附录
        lines.extend([
            "## 4. MITRE ATT&CK Mapping",
            "",
        ])

        mitre_map: Dict[str, List[str]] = {}
        for finding in findings:
            for technique in finding.mitre_techniques:
                if technique not in mitre_map:
                    mitre_map[technique] = []
                mitre_map[technique].append(finding.owasp_id)

        for technique, owasp_ids in sorted(mitre_map.items()):
            lines.append(f"- **{technique}**: {', '.join(owasp_ids)}")

        lines.extend([
            "",
            "## 5. Tool Usage",
            "",
            "| Tool | Description |",
            "|------|-------------|",
            "| PyRIT | Python Risk Identification Toolkit for AI red teaming |",
            "| OpenAIChatTarget | LLM target interface for sending prompts |",
            "| SelfAskTrueFalseScorer | LLM-based scoring for attack success evaluation |",
            "| Converter Chains | Encoding/obfuscation converters for bypass testing |",
            "",
            "## 6. Appendix",
            "",
            "### Appendix A | AI Conversation History",
            "",
            "The complete AI conversation history, prompts used during the engagement,",
            "and model interaction logs are included in the evidence archive (evidence.zip).",
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
        ])

        lines.append("")
        return "\n".join(lines)

    def _collect_attack_details(self) -> Dict[str, List[Dict[str, Any]]]:
        """从 Memory 收集攻击详情，按攻击类型分组"""
        try:
            memory = CentralMemory.get_memory_instance()
            attack_results = memory.get_attack_results()

            details: Dict[str, List[Dict[str, Any]]] = {}
            for ar in attack_results:
                # 提取攻击类型
                attack_type = ""
                try:
                    strategy_id = ar.get_attack_strategy_identifier()
                    if strategy_id:
                        attack_type = str(strategy_id).split("::")[0]
                except Exception:
                    attack_type = getattr(ar, "atomic_attack_identifier", "")
                    if attack_type:
                        attack_type = str(attack_type).split("::")[0]

                if not attack_type:
                    continue

                # 提取对话内容
                conversation = []
                conv_id = getattr(ar, "conversation_id", None)
                if conv_id:
                    pieces = memory.get_message_pieces(conversation_id=str(conv_id))
                    for p in pieces:
                        conversation.append({
                            "role": str(getattr(p, "role", "unknown")),
                            "text": str(getattr(p, "converted_value", getattr(p, "original_value", ""))),
                        })

                # 提取 outcome
                outcome = "unknown"
                outcome_obj = getattr(ar, "outcome", None)
                if outcome_obj is not None:
                    outcome = str(outcome_obj.value if hasattr(outcome_obj, "value") else outcome_obj)

                detail = {
                    "objective": str(getattr(ar, "objective", "N/A")),
                    "outcome": outcome,
                    "conversation": conversation,
                }

                if attack_type not in details:
                    details[attack_type] = []
                details[attack_type].append(detail)

            return details
        except Exception:
            return {}


# ============================================================
# 工厂函数
# ============================================================


async def generate_report(
    scenario_result: Any,
    exam_id: str,
    start_time: datetime,
    end_time: datetime,
) -> ReportResult:
    """
    生成报告（工厂函数）

    Args:
        scenario_result: Scenario 结果
        exam_id: 考试 ID
        start_time: 开始时间
        end_time: 结束时间

    Returns:
        报告结果
    """
    generator = ReportGenerator()
    return await generator.generate_report(
        scenario_result, exam_id, start_time, end_time
    )


def map_attacks_to_owasp(attack_results: List[Any]) -> List[OWASPFinding]:
    """
    将攻击结果映射到 OWASP（工厂函数）

    Args:
        attack_results: 攻击结果列表

    Returns:
        OWASPFinding 列表
    """
    mapper = OWASPMapper()
    return mapper.map_attacks_to_findings(attack_results)