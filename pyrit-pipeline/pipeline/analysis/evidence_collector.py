# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""证据收集器 — 从攻击结果中提取和结构化安全漏洞证据。.

PyRIT 原生输出 AttackResult 和 Markdown 报告，但不提供结构化的
"漏洞证据" 视图。本模块从攻击结果中提取:

  1. 成功的攻击载荷 (jailbreak prompt)
  2. 目标模型的漏洞响应 (harmful output)
  3. 使用的攻击技术 + Converter 链
  4. OWASP 分类映射
  5. ASR 和置信度
  6. 完整的对话历史

这些证据用于:
  - 生成结构化漏洞报告 (JSON + Markdown)
  - 供安全团队验证和修复
  - 供合规审计追溯

学术依据:
  - HarmBench (arXiv:2402.04249): 标准化红队证据收集
  - JailbreakBench (arXiv:2402.01135): 漏洞披露最佳实践

> **日期**: 2026-8-1
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from pipeline.analysis.technique_name_mapper import (
    get_arxiv_reference,
    get_display_name,
    normalize_technique_name,
)

logger = logging.getLogger(__name__)


# ============================================================
# 数据结构
# ============================================================


@dataclass
class VulnerabilityEvidence:
    """单个漏洞证据。."""

    evidence_id: str = ""
    attack_id: str = ""
    technique_name: str = ""
    technique_display_name: str = ""
    converter_chain: str = ""
    owasp_id: str = ""
    owasp_category: str = ""
    objective: str = ""
    jailbreak_prompt: str = ""
    harmful_output: str = ""
    conversation_history: list[dict[str, str]] = field(default_factory=list)
    asr: float = 0.0
    confidence: str = "medium"
    arxiv_reference: str = ""
    timestamp: str = ""
    target_model: str = ""
    model_tier: str = ""
    # P1: 攻击链路 (SequentialAttack 中尝试的技术序列)
    attack_chain: list[dict[str, str]] = field(default_factory=list)
    # P1: Converter 转换日志 (原始→变换后的 prompt 记录)
    converter_log: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class EvidenceCollection:
    """证据集合。."""

    collection_id: str = ""
    timestamp: str = ""
    target_model: str = ""
    model_tier: str = ""
    total_attacks: int = 0
    successful_attacks: int = 0
    failed_attacks: int = 0
    overall_asr: float = 0.0
    evidence: list[VulnerabilityEvidence] = field(default_factory=list)
    owasp_coverage: dict[str, int] = field(default_factory=dict)
    technique_distribution: dict[str, int] = field(default_factory=dict)
    # P1: ASR 趋势 (跨运行历史)
    asr_trend: list[dict[str, Any]] = field(default_factory=list)
    # P1: 失败分析摘要
    failure_analysis: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary with detailed fields."""
        return {
            "collection_id": self.collection_id,
            "timestamp": self.timestamp,
            "target_model": self.target_model,
            "model_tier": self.model_tier,
            "total_attacks": self.total_attacks,
            "successful_attacks": self.successful_attacks,
            "failed_attacks": self.failed_attacks,
            "overall_asr": round(self.overall_asr, 2),
            "evidence_count": len(self.evidence),
            "owasp_coverage": self.owasp_coverage,
            "technique_distribution": self.technique_distribution,
            "asr_trend": self.asr_trend,
            "failure_analysis": self.failure_analysis,
            "evidence": [e.to_dict() for e in self.evidence],
        }


# ============================================================
# OWASP 分类映射
# ============================================================

_OWASP_LLM_CATEGORIES: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

_OWASP_ASI_CATEGORIES: dict[str, str] = {
    "ASI01": "Agent Identity Spoofing",
    "ASI02": "Tool Misuse",
    "ASI03": "Unauthorized Actions",
    "ASI04": "Data Exfiltration",
    "ASI05": "Privilege Escalation",
    "ASI06": "Memory Poisoning",
    "ASI07": "Cross-Agent Injection",
    "ASI08": "Cascading Failures",
    "ASI09": "Trust Boundary Violation",
    "ASI10": "Rogue Agent",
}


def get_owasp_category(owasp_id: str) -> str:
    """获取 OWASP 分类的完整名称。."""
    if owasp_id in _OWASP_LLM_CATEGORIES:
        return _OWASP_LLM_CATEGORIES[owasp_id]
    if owasp_id in _OWASP_ASI_CATEGORIES:
        return _OWASP_ASI_CATEGORIES[owasp_id]
    return owasp_id


# ============================================================
# EvidenceCollector
# ============================================================


class EvidenceCollector:
    """证据收集器 — 从攻击结果中提取结构化漏洞证据。.

    使用方式:
        collector = EvidenceCollector(
            target_model="gpt-4o",
            model_tier="strong",
        )
        collection = collector.collect(
            attack_results=result.attack_results,
            scenario_result_id=result.id,
            asr_per_technique=ctx.asr_per_technique,
            overall_asr=ctx.overall_asr,
        )
        collector.save_json(collection, output_dir=ctx.output_dir)
        collector.save_markdown(collection, output_dir=ctx.output_dir)
    """

    def __init__(
        self,
        target_model: str = "unknown",
        model_tier: str = "unknown",
    ) -> None:
        """Initialize EvidenceCollector.

        Args:
            target_model: Target model name.
            model_tier: Model filter strength tier.
            overall_asr: Overall ASR percentage.
        """
        self._target_model = target_model
        self._model_tier = model_tier

    @staticmethod
    def _extract_owasp_id_from_display_group(display_group_name: str) -> str:
        """从显示组名提取 OWASP ID (Round 8 修复).

        显示组名格式示例:
            - llm02_sensitive_info_disclosure_many_shot_jailbreak
            - asi01_agent_identity_spoofing_prompt_sending
            - harmbench_many_shot_jailbreak
            - curated_seeds_many_shot_jailbreak

        Args:
            display_group_name: 显示组名称

        Returns:
            OWASP ID (如 "LLM02", "ASI01"), 空字符串表示未找到
        """
        # 匹配 llm01-llm10 或 asi01-asi10 格式
        import re
        match = re.search(r"(llm\d{2}|asi\d{2})", display_group_name.lower())
        if match:
            return match.group(1).upper()
        return ""

    def collect(
        self,
        attack_results: dict[str, list[Any]],
        scenario_result_id: str = "",
        asr_per_technique: dict[str, float] | None = None,
        overall_asr: float = 0.0,
        owasp_id: str = "",
        display_groups: dict[str, list[Any]] | None = None,
    ) -> EvidenceCollection:
        """从攻击结果中收集证据。.

        Args:
            attack_results: ScenarioResult.attack_results 字典
            scenario_result_id: ScenarioResult ID
            asr_per_technique: 按技术的 ASR 统计
            overall_asr: 总体 ASR
            owasp_id: OWASP 分类 ID (全局, 回退用)
            display_groups: ScenarioResult.get_display_groups() 的结果
                             用于从显示组名提取数据集特定的 OWASP ID

        Returns:
            EvidenceCollection: 结构化证据集合
        """
        collection = EvidenceCollection(
            collection_id=scenario_result_id or datetime.now().strftime("%Y%m%d_%H%M%S"),
            timestamp=datetime.now().isoformat(),
            target_model=self._target_model,
            model_tier=self._model_tier,
            overall_asr=overall_asr,
        )

        evidence_idx = 0
        owasp_counter: dict[str, int] = {}
        tech_counter: dict[str, int] = {}

        # Round 8 P0: 构建技术名到 OWASP ID 的映射 (从 display_groups 提取)
        tech_to_owasp: dict[str, str] = {}
        if display_groups:
            for display_name, results in display_groups.items():
                owasp_id = self._extract_owasp_id_from_display_group(display_name)
                if owasp_id and results:
                    # 从第一个结果提取技术名
                    tech_name = self._extract_technique_name(results[0])
                    tech_to_owasp[tech_name] = owasp_id
                    logger.debug(f"OWASP mapping: {tech_name} → {owasp_id} (from {display_name})")
        # 回退到全局 owasp_id
        if not tech_to_owasp and owasp_id:
            logger.debug(f"OWASP: using global owasp_id={owasp_id}")

        for attack_id, results in attack_results.items():
            for ar in results:
                collection.total_attacks += 1

                # 提取技术名
                tech_name = self._extract_technique_name(ar)
                tech_counter[tech_name] = tech_counter.get(tech_name, 0) + 1

                # 判断成功
                is_success = self._is_success(ar)
                if is_success:
                    collection.successful_attacks += 1
                else:
                    collection.failed_attacks += 1

                # 只收集成功攻击的证据
                if not is_success:
                    continue

                # Round 8 P0: 从 tech_to_owasp 映射提取 OWASP ID, 回退到全局 owasp_id
                current_owasp_id = tech_to_owasp.get(tech_name, owasp_id)

                evidence_idx += 1
                evidence = VulnerabilityEvidence(
                    evidence_id=f"EVD-{evidence_idx:04d}",
                    attack_id=attack_id,
                    technique_name=tech_name,
                    technique_display_name=get_display_name(normalize_technique_name(tech_name)),
                    converter_chain=self._extract_converter_chain(ar),
                    owasp_id=current_owasp_id,
                    owasp_category=get_owasp_category(current_owasp_id) if current_owasp_id else "",
                    objective=self._extract_objective(ar),
                    jailbreak_prompt=self._extract_jailbreak_prompt(ar),
                    harmful_output=self._extract_harmful_output(ar),
                    conversation_history=self._extract_conversation(ar),
                    asr=asr_per_technique.get(tech_name, 0.0) if asr_per_technique else 0.0,
                    confidence=self._compute_confidence(ar, asr_per_technique or {}),
                    arxiv_reference=get_arxiv_reference(normalize_technique_name(tech_name)) or "",
                    timestamp=datetime.now().isoformat(),
                    target_model=self._target_model,
                    model_tier=self._model_tier,
                    # P1: 攻击链路
                    attack_chain=self._extract_attack_chain(ar),
                    # P1: Converter 转换日志
                    converter_log=self._extract_converter_log(ar),
                )

                collection.evidence.append(evidence)

        # OWASP 覆盖统计 (Round 8 P0: 使用 current_owasp_id)
        if current_owasp_id:
            owasp_counter[current_owasp_id] = owasp_counter.get(current_owasp_id, 0) + 1

        # 子结果 (SequentialAttack 的子攻击)
        child_results = getattr(ar, "child_attack_results", None) or []
        for child in child_results:
            if child is None:
                continue
            if self._is_success(child):
                evidence_idx += 1
                child_evidence = VulnerabilityEvidence(
                    evidence_id=f"EVD-{evidence_idx:04d}",
                    attack_id=f"{attack_id}_child",
                    technique_name=self._extract_technique_name(child),
                    technique_display_name=get_display_name(
                        normalize_technique_name(self._extract_technique_name(child))
                    ),
                    converter_chain=self._extract_converter_chain(child),
                    owasp_id=current_owasp_id,  # Round 8 P0: 子攻击继承父攻击的 OWASP ID
                    owasp_category=get_owasp_category(current_owasp_id) if current_owasp_id else "",
                    objective=self._extract_objective(child),
                    jailbreak_prompt=self._extract_jailbreak_prompt(child),
                    harmful_output=self._extract_harmful_output(child),
                    conversation_history=self._extract_conversation(child),
                    asr=asr_per_technique.get(tech_name, 0.0) if asr_per_technique else 0.0,
                    confidence="medium",
                    arxiv_reference=get_arxiv_reference(normalize_technique_name(tech_name)) or "",
                    timestamp=datetime.now().isoformat(),
                    target_model=self._target_model,
                    model_tier=self._model_tier,
                )
                collection.evidence.append(child_evidence)

        collection.owasp_coverage = owasp_counter
        collection.technique_distribution = tech_counter

        # P1: 加载 ASR 趋势 (跨运行历史)
        collection.asr_trend = self._load_asr_trend()

        # P1: 失败分析摘要
        collection.failure_analysis = self._build_failure_analysis(
            attack_results,
            collection.total_attacks,
        )

        logger.info(
            f"EvidenceCollector: {collection.total_attacks} attacks, "
            f"{collection.successful_attacks} successful, "
            f"{len(collection.evidence)} evidence items collected"
        )

        return collection

    def save_json(
        self,
        collection: EvidenceCollection,
        output_dir: Path,
    ) -> Path:
        """将证据集合保存为 JSON 文件。."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        json_path = output_dir / "evidence.json"

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(collection.to_dict(), f, indent=2, ensure_ascii=False, default=str)

        logger.info(f"Evidence saved to {json_path}")
        return json_path

    def save_markdown(
        self,
        collection: EvidenceCollection,
        output_dir: Path,
    ) -> Path:
        """将证据集合保存为 Markdown 报告。."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        md_path = output_dir / "evidence_report.md"

        lines: list[str] = []
        lines.append("# AI 红队漏洞证据报告")
        lines.append("")
        lines.append(f"**报告 ID**: {collection.collection_id}")
        lines.append(f"**生成时间**: {collection.timestamp}")
        lines.append(f"**目标模型**: {collection.target_model} (tier={collection.model_tier})")
        lines.append(f"**总体 ASR**: {collection.overall_asr:.1f}%")
        lines.append(f"**总攻击数**: {collection.total_attacks}")
        lines.append(f"**成功攻击**: {collection.successful_attacks}")
        lines.append(f"**失败攻击**: {collection.failed_attacks}")
        lines.append("")

        # OWASP 覆盖
        if collection.owasp_coverage:
            lines.append("## OWASP 分类覆盖")
            lines.append("")
            lines.append("| OWASP ID | 分类 | 证据数 |")
            lines.append("|----------|------|--------|")
            for owasp_id, count in sorted(collection.owasp_coverage.items()):
                lines.append(f"| {owasp_id} | {get_owasp_category(owasp_id)} | {count} |")
            lines.append("")

        # 技术分布
        if collection.technique_distribution:
            lines.append("## 攻击技术分布")
            lines.append("")
            lines.append("| 技术 | 攻击数 |")
            lines.append("|------|--------|")
            for tech, count in sorted(
                collection.technique_distribution.items(),
                key=lambda x: x[1],
                reverse=True,
            ):
                lines.append(f"| {tech} | {count} |")
            lines.append("")

        # P1: ASR 趋势
        if collection.asr_trend:
            lines.append("## ASR 趋势 (跨运行历史)")
            lines.append("")
            lines.append("| 技术 | 历史 ASR | 数据来源 |")
            lines.append("|------|----------|----------|")
            for item in collection.asr_trend:
                lines.append(
                    f"| {item.get('technique', 'N/A')} "
                    f"| {item.get('historical_asr', 0):.1f}% "
                    f"| {item.get('source', 'N/A')} |"
                )
            lines.append("")

        # P1: 失败分析
        if collection.failure_analysis:
            fa = collection.failure_analysis
            lines.append("## 失败分析")
            lines.append("")
            lines.append(f"- 总攻击: {fa.get('total_attacks', 0)}")
            lines.append(f"- 成功: {fa.get('total_successes', 0)}")
            lines.append(f"- 失败: {fa.get('total_failures', 0)}")
            lines.append("")

            ftype_dist = fa.get("failure_type_distribution", {})
            if ftype_dist:
                lines.append("### 失败类型分布")
                lines.append("")
                lines.append("| 失败类型 | 次数 |")
                lines.append("|----------|------|")
                for ftype, count in sorted(ftype_dist.items(), key=lambda x: x[1], reverse=True):
                    lines.append(f"| {ftype} | {count} |")
                lines.append("")

            tech_rates = fa.get("technique_success_rates", [])
            if tech_rates:
                lines.append("### 技术成功率排名")
                lines.append("")
                lines.append("| 技术 | 成功 | 失败 | 总计 | 成功率 |")
                lines.append("|------|------|------|------|--------|")
                for tr in tech_rates:
                    lines.append(
                        f"| {tr.get('technique', 'N/A')} "
                        f"| {tr.get('successes', 0)} "
                        f"| {tr.get('failures', 0)} "
                        f"| {tr.get('total', 0)} "
                        f"| {tr.get('success_rate', 0):.1f}% |"
                    )
                lines.append("")

        # 漏洞证据详情
        lines.append("## 漏洞证据详情")
        lines.append("")

        for i, ev in enumerate(collection.evidence, 1):
            lines.append(f"### 证据 #{i}: {ev.evidence_id}")
            lines.append("")
            lines.append(f"**攻击技术**: {ev.technique_display_name}")
            lines.append(f"**Converter 链**: {ev.converter_chain or '无'}")
            if ev.owasp_id:
                lines.append(f"**OWASP 分类**: {ev.owasp_id} — {ev.owasp_category}")
            lines.append(f"**攻击目标**: {ev.objective[:200]}")
            lines.append(f"**ASR**: {ev.asr:.1f}%")
            lines.append(f"**置信度**: {ev.confidence}")
            if ev.arxiv_reference:
                lines.append(f"**学术引用**: {ev.arxiv_reference}")
            lines.append("")
            lines.append("#### 越狱载荷 (Jailbreak Prompt)")
            lines.append("```")
            lines.append(ev.jailbreak_prompt[:1000] if ev.jailbreak_prompt else "(未提取)")
            lines.append("```")
            lines.append("")
            lines.append("#### 目标模型响应 (Harmful Output)")
            lines.append("```")
            lines.append(ev.harmful_output[:1000] if ev.harmful_output else "(未提取)")
            lines.append("```")
            lines.append("")

            if ev.conversation_history:
                lines.append("#### 完整对话历史")
                lines.append("")
                for msg in ev.conversation_history:
                    role = msg.get("role", "unknown")
                    content = msg.get("content", "")
                    lines.append(f"**{role}**: {content[:300]}")
                    lines.append("")
                lines.append("---")
                lines.append("")

            # P1: 攻击链路
            if ev.attack_chain:
                lines.append("#### 攻击链路 (Attack Chain)")
                lines.append("")
                lines.append("| 步骤 | 技术 | 结果 | 角色 | 失败原因 |")
                lines.append("|------|------|------|------|----------|")
                for step in ev.attack_chain:
                    reason = step.get("failure_reason", "")
                    lines.append(
                        f"| {step.get('step', '')} "
                        f"| {step.get('technique', '')} "
                        f"| {step.get('outcome', '')} "
                        f"| {step.get('role', '')} "
                        f"| {reason} |"
                    )
                lines.append("")

            # P1: Converter 转换日志
            if ev.converter_log:
                lines.append("#### Converter 转换日志")
                lines.append("")
                for cl in ev.converter_log:
                    transformed = cl.get("transformed", "false") == "true"
                    marker = "🔄" if transformed else "⚫"
                    lines.append(f"{marker} **步骤 {cl.get('step', '')}** ({cl.get('role', '')})")
                    if transformed:
                        lines.append(f"  - 原始: `{cl.get('original', '')[:200]}...`")
                        lines.append(f"  - 变换: `{cl.get('converted', '')[:200]}...`")
                    else:
                        lines.append(f"  - 内容: `{cl.get('original', '')[:200]}...`")
                    lines.append("")
                lines.append("---")
                lines.append("")

        with open(md_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        logger.info(f"Evidence Markdown report saved to {md_path}")
        return md_path

    # ------------------------------------------------------------------
    # 提取辅助方法
    # ------------------------------------------------------------------

    def _is_success(self, attack_result: Any) -> bool:
        """判断攻击是否成功。."""
        outcome = getattr(attack_result, "outcome", None)
        if outcome is None:
            return False
        outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()
        return outcome_str == "SUCCESS"

    def _extract_technique_name(self, attack_result: Any) -> str:
        """从 AttackResult 提取技术名 (委托给 AttackResultAnalyzer)。."""
        from pipeline.analysis.attack_result_analyzer import AttackResultAnalyzer

        return AttackResultAnalyzer.extract_technique_name(attack_result)

    def _extract_converter_chain(self, attack_result: Any) -> str:
        """从 AttackResult 提取 Converter 链名。."""
        identifier = None
        if hasattr(attack_result, "get_attack_strategy_identifier"):
            identifier = attack_result.get_attack_strategy_identifier()
        if identifier is not None:
            children = getattr(identifier, "children", None) or {}
            request_converters = children.get("request_converters")
            if request_converters and isinstance(request_converters, list):
                names = []
                for conv in request_converters:
                    if isinstance(conv, str):
                        names.append(conv)
                    else:
                        names.append(type(conv).__name__)
                return "→".join(names)
        return ""

    def _extract_objective(self, attack_result: Any) -> str:
        """提取攻击目标。."""
        objective = getattr(attack_result, "objective", None)
        if objective:
            return str(objective)
        # 从 last_request 提取
        last_request = getattr(attack_result, "last_request", None)
        if last_request:
            pieces = getattr(last_request, "request_pieces", None) or []
            if pieces:
                return str(getattr(pieces[0], "original_value", "") or getattr(pieces[0], "converted_value", ""))
        return ""

    def _extract_jailbreak_prompt(self, attack_result: Any) -> str:
        """提取越狱载荷 (变换后的 prompt)。."""
        last_request = getattr(attack_result, "last_request", None)
        if last_request:
            pieces = getattr(last_request, "request_pieces", None) or []
            if pieces:
                # 最后一条 user piece 是变换后的
                for piece in reversed(pieces):
                    role = getattr(piece, "role", "")
                    if role == "user":
                        return str(getattr(piece, "converted_value", "") or getattr(piece, "original_value", ""))
        return ""

    def _extract_harmful_output(self, attack_result: Any) -> str:
        """提取目标模型的有害输出。."""
        last_response = getattr(attack_result, "last_response", None)
        if last_response:
            pieces = getattr(last_response, "request_pieces", None) or []
            if pieces:
                for piece in reversed(pieces):
                    role = getattr(piece, "role", "")
                    if role == "assistant":
                        return str(getattr(piece, "converted_value", "") or getattr(piece, "original_value", ""))
        return ""

    def _extract_conversation(self, attack_result: Any) -> list[dict[str, str]]:
        """提取完整对话历史。."""
        history: list[dict[str, str]] = []
        conversation = getattr(attack_result, "conversation", None)
        if conversation is None:
            return history

        try:
            messages = getattr(conversation, "messages", None) or []
            for msg in messages:
                role = getattr(msg, "role", "unknown")
                content = getattr(msg, "content", "") or ""
                history.append({"role": str(role), "content": str(content)})
        except Exception as e:
            logger.debug(f"Failed to extract conversation: {e}")

        return history

    def _compute_confidence(
        self,
        attack_result: Any,
        asr_per_technique: dict[str, float],
    ) -> str:
        """计算证据置信度。."""
        tech_name = self._extract_technique_name(attack_result)
        asr = asr_per_technique.get(tech_name, 0.0)

        if asr >= 70:
            return "high"
        if asr >= 30:
            return "medium"
        if asr > 0:
            return "low"
        return "medium"  # 无 ASR 数据时默认中等

    # ------------------------------------------------------------------
    # P1: 攻击链路 + Converter 日志 + ASR 趋势 + 失败分析
    # ------------------------------------------------------------------

    def _extract_attack_chain(self, attack_result: Any) -> list[dict[str, str]]:
        """P1: 提取攻击链路 — SequentialAttack 中尝试的技术序列。.

        对于 SequentialAttack(FIRST_SUCCESS), 显示在成功之前尝试了哪些技术
        以及它们的失败原因, 提供完整的攻击路径可追溯性。
        """
        chain: list[dict[str, str]] = []

        # 主结果
        main_tech = self._extract_technique_name(attack_result)
        main_outcome = getattr(attack_result, "outcome", None)
        main_outcome_str = (
            (str(main_outcome.value).upper() if hasattr(main_outcome, "value") else str(main_outcome).upper())
            if main_outcome
            else "UNKNOWN"
        )

        chain.append(
            {
                "step": "1",
                "technique": main_tech,
                "outcome": main_outcome_str,
                "role": "primary",
            }
        )

        # 子结果 (SequentialAttack 的子攻击)
        child_results = getattr(attack_result, "child_attack_results", None) or []
        for i, child in enumerate(child_results, 2):
            if child is None:
                continue
            child_tech = self._extract_technique_name(child)
            child_outcome = getattr(child, "outcome", None)
            child_outcome_str = (
                (str(child_outcome.value).upper() if hasattr(child_outcome, "value") else str(child_outcome).upper())
                if child_outcome
                else "UNKNOWN"
            )

            # 提取失败原因
            failure_reason = ""
            error_msg = getattr(child, "error_message", None) or getattr(child, "outcome_reason", "")
            if error_msg:
                failure_reason = str(error_msg)[:200]

            chain.append(
                {
                    "step": str(i),
                    "technique": child_tech,
                    "outcome": child_outcome_str,
                    "role": "fallback",
                    "failure_reason": failure_reason,
                }
            )

        return chain

    def _extract_converter_log(self, attack_result: Any) -> list[dict[str, str]]:
        """P1: 提取 Converter 转换日志 — 原始 prompt → 变换后 prompt 的记录。.

        从 AttackResult 的 last_request 中提取每个 request_piece 的
        original_value 和 converted_value, 展示 Converter 的变换过程。
        """
        log: list[dict[str, str]] = []

        last_request = getattr(attack_result, "last_request", None)
        if not last_request:
            return log

        pieces = getattr(last_request, "request_pieces", None) or []
        for i, piece in enumerate(pieces, 1):
            original = getattr(piece, "original_value", "") or ""
            converted = getattr(piece, "converted_value", "") or ""
            role = getattr(piece, "role", "unknown")

            # 只记录有变换的 piece
            if original and converted and original != converted:
                log.append(
                    {
                        "step": str(i),
                        "role": str(role),
                        "original": original[:500],
                        "converted": converted[:500],
                        "transformed": "true",
                    }
                )
            elif original:
                log.append(
                    {
                        "step": str(i),
                        "role": str(role),
                        "original": original[:500],
                        "converted": converted[:500] if converted else original[:500],
                        "transformed": "false",
                    }
                )

        return log

    def _load_asr_trend(self) -> list[dict[str, Any]]:
        """P1: 加载 ASR 趋势数据 — 跨运行的历史 ASR 变化。.

        从经验 ASR 文件加载上一次运行的 ASR 数据,
        与当前运行的数据合并, 形成 ASR 趋势。
        """
        trend: list[dict[str, Any]] = []

        try:
            from pipeline.asr.optimizer import load_empirical_asr

            historical = load_empirical_asr()
            if historical:
                for tech, asr in sorted(historical.items(), key=lambda x: x[1], reverse=True):
                    trend.append(
                        {
                            "technique": tech,
                            "historical_asr": round(asr * 100, 1),
                            "source": "empirical",
                        }
                    )
        except Exception as e:
            logger.debug(f"Failed to load ASR trend: {e}")

        return trend

    def _build_failure_analysis(
        self,
        attack_results: dict[str, list[Any]],
        total_attacks: int,
    ) -> dict[str, Any]:
        """P1: 构建失败分析摘要 — 统计失败类型和分布。.

        从攻击结果中提取失败模式, 按失败类型和技术分类统计,
        提供可操作的失败分析报告。
        """
        from collections import Counter

        failure_types: Counter = Counter()
        failure_by_tech: dict[str, int] = {}
        success_by_tech: dict[str, int] = {}

        for _attack_id, results in attack_results.items():
            for ar in results:
                tech_name = self._extract_technique_name(ar)
                is_success = self._is_success(ar)

                if is_success:
                    success_by_tech[tech_name] = success_by_tech.get(tech_name, 0) + 1
                else:
                    failure_by_tech[tech_name] = failure_by_tech.get(tech_name, 0) + 1

                    # 提取失败类型
                    try:
                        from pipeline.asr.failure_type_selector import extract_failure_type_from_result

                        ftype = extract_failure_type_from_result(ar)
                    except ImportError:
                        ftype = "unknown"
                    failure_types[ftype] += 1

        total_failures = sum(failure_by_tech.values())
        total_successes = sum(success_by_tech.values())

        # 技术成功率排名
        tech_success_rate: list[dict[str, Any]] = []
        all_techs = set(list(failure_by_tech.keys()) + list(success_by_tech.keys()))
        for tech in all_techs:
            s = success_by_tech.get(tech, 0)
            f = failure_by_tech.get(tech, 0)
            total = s + f
            rate = (s / total * 100) if total > 0 else 0
            tech_success_rate.append(
                {
                    "technique": tech,
                    "successes": s,
                    "failures": f,
                    "total": total,
                    "success_rate": round(rate, 1),
                }
            )
        tech_success_rate.sort(key=lambda x: x["success_rate"], reverse=True)

        return {
            "total_attacks": total_attacks,
            "total_successes": total_successes,
            "total_failures": total_failures,
            "failure_type_distribution": dict(failure_types),
            "technique_success_rates": tech_success_rate,
        }
