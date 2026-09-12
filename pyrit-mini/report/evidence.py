"""Evidence collection and OWASP compliance tracking.

Academic basis:
    - arXiv:2402.12109 - Russinovich et al., Crescendo
    - arXiv:2407.01232 - PyRIT, evidence extraction from CentralMemory
    - arXiv:2308.07920 - Zhang et al., Dual Judge scoring evidence

OWASP standards supported:
    - OWASP Top 10 (2025) - Web Application Security
      Reference: https://owasp.org/www-project-top-10/
    - OWASP LLM Top 10 for LLM Applications (2025 Edition)
      Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/
    - OWASP Agentic AI Top 10
      Reference: https://owasp.org/www-project-agent-security/

Data sources:
    - attack_results: PyRIT AttackResult objects (imports attack metadata)
    - scan_results: MCPSec vulnerability scan findings (API, severity, description)
    - burp_findings: Burp Suite imported findings (when available)
    - OWASP compliance stats (Web Top 10 + LLM Top 10 + Agentic AI Top 10)
    - ASR tracking + dual judge agreement (_success)

Core data classes:
    - VulnerabilityEvidence: Single evidence item with OWASP mapping + converter(s)
    - EvidenceCollection: Aggregated collection with OWASP compliance tracking

Extraction fallback (3-layer):
    - jailbreak_prompt: AttackResult -> CentralMemory -> objective
    - harmful_output: AttackResult -> CentralMemory -> response
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from report.evidence_extract import (
    _classify_failure,
    _determine_confidence,
    _extract_conversation,
    _extract_converter_log,
    _extract_harmful_output,
    _extract_jailbreak_prompt,
    _extract_score_details,
    _get_arxiv_reference,
    _get_technique_display_name,
    _is_success,
)
from report.owasp_constants import (  # noqa: F401
    _MITRE_ATLAS_TECHNIQUES,
    _OWASP_ASI_CATEGORIES,
    _OWASP_ASI_MITIGATIONS,
    _OWASP_LLM_CATEGORIES,
    _OWASP_LLM_MITIGATIONS,
    _OWASP_SEVERITY_LEVELS,
    _OWASP_WEB_CATEGORIES,
    _OWASP_WEB_MITIGATIONS,
    OWASP_ASI_TOP10_REFERENCE,
    OWASP_LLM_TOP10_REFERENCE,
    OWASP_WEB_TOP10_REFERENCE,
)
from report.owasp_mapping import (  # noqa: F401
    _build_findings,
    _compute_owasp_risk_score,
    _compute_owasp_severity,
    _get_cvss_vector,
    _get_owasp_id,
    _get_owasp_mitigations,
    _get_owasp_reference_url,
    _get_owasp_standard,
    _infer_owasp_id_from_objective,
    generate_poc_script,
)

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityEvidence:
    """
    OWASP :
        - owasp_standard: OWASP  (Web Top 10 2025 / LLM Top 10 2025 / Agentic AI Top 10)
        - owasp_severity: OWASP  (critical/high/medium/low/info)
        - owasp_risk_score: OWASP  (0-10, CVSS-like)
        - owasp_mitigations: OWASP
        - owasp_reference: OWASP  URL

    :
        - is_success:
        - file_suffix:  ("_success"  "")
    """

    evidence_id: str
    attack_id: str
    # - results key
    # : "prompt_sending" / "encoded_injection" / "crescendo" / "tap" / "pair"
    # : , PyRIT Converter , MITRE ATLAS
    technique_name: str
    # - ( "Prompt Sending (Baseline)")
    technique_display_name: str
    # PyRIT Converter - Converter ( "Base64Converter, ROT13Converter")
    # PyRIT Converter ( encoded_injection),
    # ( "base64 (encoded_injection)")
    # "" Converter
    converter_chain: str
    owasp_id: str
    owasp_category: str
    owasp_standard: str  # "OWASP Top 10 (2025)" / "OWASP LLM Top 10 (2025 Edition)" / "OWASP ASI Top 10 (Agentic AI)"
    owasp_severity: str  # critical/high/medium/low/info
    owasp_risk_score: float  # 0.0-10.0
    owasp_mitigations: list[str]  # OWASP
    owasp_reference: str  # OWASP URL
    objective: str
    jailbreak_prompt: str
    harmful_output: str
    is_success: bool  # ( _success )
    file_suffix: str  # "_success" ""
    cvss_vector: str = ""  # CVSS 3.1
    conversation_history: list[dict[str, str]] = field(default_factory=list)
    asr: float = 0.0
    confidence: str = "medium"
    arxiv_reference: str = ""
    timestamp: str = ""
    target_model: str = ""
    converter_log: list[dict[str, str]] = field(default_factory=list)
    score_details: list[dict[str, str]] = field(default_factory=list)
    # P0-2: MITRE ATLAS
    # MITRE ATLAS - ( "Execution", "Persistence")
    mitre_tactic: str = ""
    # MITRE ATLAS - "AML.T0051" (LLM Prompt Injection)
    mitre_technique_id: str = ""
    # MITRE ATLAS - "LLM Prompt Injection" / "Data Poisoning"
    # : MITRE ATLAS , technique_name ()
    mitre_technique_name: str = ""
    # MITRE ATLAS URL
    mitre_url: str = ""
    # :
    attack_result_ref: Any = None
    # == plan Wave 6 / CB-2：组件元数据（修组件专属报告永不生成的断裂）==
    # `report/component_reports.py` 通过 `getattr(ev, "metadata", {}).get("component_type")`
    # 判定组件归属；此前本数据类无该字段 → 恒 {} → `_determine_dominant_component()`
    # 恒 None → 组件专属章节永远不生成。
    # 由 `core/phases/_component_bridge.stamp_component_metadata` 统一写入（规则 CB-1：
    # 禁止其他模块直接写 `component_type`）。
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class OWASPFinding:
    """
    : converter(s) Finding  OWASP converter(s) (Results)
    converter(s) Result  (Conversation)

    :
        1. Finding - OWASP  +  +  ASR
        2. Result -  (technique + prompt + response + score)
        3. Conversation -  (role + content)
    """

    finding_id: str
    owasp_id: str
    owasp_category: str
    owasp_standard: str
    owasp_severity: str
    owasp_risk_score: float
    asr: float
    total_tested: int
    total_success: int
    mitigations: list[str] = field(default_factory=list)
    mitre_tactic: str = ""
    mitre_technique_id: str = ""
    mitre_technique_name: str = ""
    results: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class EvidenceCollection:
    """
    OWASP :
        - owasp_web_compliance: Web Top 10  {owasp_id: {tested, success, failed, asr, category, mitigations}}
        - owasp_llm_compliance: LLM Top 10  {owasp_id: {tested, success, failed, asr, category, mitigations}}
        - owasp_asi_compliance: Agentic AI Top 10
        - owasp_standard_references: OWASP
        - successful_evidence:  ( _success )
    """

    collection_id: str
    timestamp: str
    target_model: str
    total_attacks: int = 0
    successful_attacks: int = 0
    failed_attacks: int = 0
    overall_asr: float = 0.0
    evidence: list[VulnerabilityEvidence] = field(default_factory=list)
    successful_evidence: list[VulnerabilityEvidence] = field(default_factory=list)
    owasp_coverage: dict[str, int] = field(default_factory=dict)
    owasp_web_compliance: dict[str, dict[str, Any]] = field(default_factory=dict)
    owasp_llm_compliance: dict[str, dict[str, Any]] = field(default_factory=dict)
    owasp_asi_compliance: dict[str, dict[str, Any]] = field(default_factory=dict)
    owasp_standard_references: list[str] = field(default_factory=list)
    technique_distribution: dict[str, int] = field(default_factory=dict)
    failure_analysis: dict[str, Any] = field(default_factory=dict)
    # :
    target_fingerprint: dict[str, str] = field(default_factory=dict)
    #
    attack_surface: dict[str, Any] = field(default_factory=dict)
    # L5 v8: Judge (single definition)
    dual_judge_stats: dict[str, Any] = field(default_factory=dict)
    # L5 v29: Wilson Score + Cohen's Kappa
    wilson_ci: tuple[float, float] = (0.0, 0.0)
    cohens_kappa: float = 0.0
    # P0-4: Findings
    findings: list[OWASPFinding] = field(default_factory=list)
    # "Orchestration Decision Log" (P2-07: audit trail of all pipeline decisions)
    orchestration_log: list[dict[str, Any]] = field(default_factory=list)
    # == plan Wave 6：组合体 / 攻击链 / 影响链 / 预算的可交付投影 ==
    # 报告是交付物，识别与链执行的结果必须落到报告里，而不是只留在日志。
    component_graph: dict[str, Any] = field(default_factory=dict)  # ComponentGraph.to_dict()
    attack_chain: dict[str, Any] = field(default_factory=dict)  # StatefulAttackChain.to_dict()
    impact_chains: list[dict[str, Any]] = field(default_factory=list)  # list[ImpactChain.to_dict()]
    impact_gaps: list[dict[str, Any]] = field(default_factory=list)  # 因果链缺口（举证不完整项）
    budget_report: dict[str, Any] = field(default_factory=dict)  # 预算快照 + 裁剪原因
    score_manifest: dict[str, Any] = field(default_factory=dict)  # 评分运行清单（可复现指纹）
    # == : (pyrit_scan --memory-labels) ==
    # PipelineContext.memory_labels ,
    # : {"run_id": "r001", "target": "deepseek"}
    memory_labels: dict[str, str] = field(default_factory=dict)


def _extract_result_metadata(result: Any, *, technique_name: str = "") -> dict[str, Any]:
    """从 AttackResult 读取组件元数据，供 `VulnerabilityEvidence.metadata` 落盘（CB-2）。

    规则 CB-1：`component_type` 的写入权归 `core/phases/_component_bridge`。
    本函数**只读不写**——若上游未盖章，返回空 dict，由组件报告走既有推断逻辑，
    绝不在此伪造 component_type（C9 诚实汇报）。

    Args:
        result: PyRIT AttackResult
        technique_name: 技术名（用于附加可观测上下文）

    Returns:
        元数据 dict（可能为空）。
    """
    meta = getattr(result, "metadata", None)
    if not isinstance(meta, dict):
        return {}
    # 浅拷贝：避免证据对象与攻击结果共享可变状态（防状态污染）
    out = {k: v for k, v in meta.items() if isinstance(k, str)}
    if technique_name:
        out.setdefault("technique_name", technique_name)
    return out


class EvidenceCollector:
    """
    imports AttackResult :
        -  (jailbreak_prompt)
        -  (harmful_output)
        -
        - Converter
        -
        -  ()
    """

    def __init__(
        self,
        *,
        target_model: str = "",
        target_fingerprint: dict[str, str] | None = None,
    ) -> None:
        self._target_model = target_model
        self._target_fingerprint = target_fingerprint or {}
        # W6: 采集器级单调序号 + 已发号集合，保证 EVD-* 全局唯一（证据文件不被覆盖）
        self._evidence_seq = 0
        self._issued_evidence_ids: set[str] = set()

    def _next_evidence_id(self, attack_index: int, attack_id: Any) -> str:
        """生成唯一 evidence_id。

        基础编号保持可读（EVD-0001…）；一旦冲突，附加 attack_id 的稳定短哈希，
        再冲突则递增后缀。任何情况下不重复发号。
        """
        base = f"EVD-{attack_index + 1:04d}"
        if base not in self._issued_evidence_ids:
            self._issued_evidence_ids.add(base)
            return base

        digest = hashlib.sha1(str(attack_id).encode("utf-8")).hexdigest()[:6].upper()
        candidate = f"{base}-{digest}"
        n = 2
        while candidate in self._issued_evidence_ids:
            candidate = f"{base}-{digest}-{n}"
            n += 1
        self._issued_evidence_ids.add(candidate)
        logger.warning("[Evidence] evidence_id 冲突已消解: %s -> %s", base, candidate)
        return candidate

    def collect(
        self,
        *,
        attack_results: dict[str, list[Any]],
        scenario_result_id: str | None = None,
        asr_per_technique: dict[str, float] | None = None,
        overall_asr: float = 0.0,
        memory_labels: dict[str, str] | None = None,
        orchestration_log: list[dict[str, Any]] | None = None,
    ) -> EvidenceCollection:
        """

         OWASP :
            - LLM Top 10: converter(s) tested/success/failed/asr
            - ASI Top 10: converter(s) tested/success/failed/asr
            - all successful_evidence

        Args:
            attack_results:
            scenario_result_id:  ID
            asr_per_technique:  ASR
            overall_asr:  ASR
            memory_labels:  ( --memory-labels),
            orchestration_log: ,

        Returns:
            EvidenceCollection: Collection of evidence for all attacks.
        """
        asr_per_technique = asr_per_technique or {}
        collection = EvidenceCollection(
            collection_id=str(uuid.uuid4()),
            timestamp=datetime.now().isoformat(),
            target_model=self._target_model,
            overall_asr=overall_asr,
            target_fingerprint=self._target_fingerprint,
            owasp_standard_references=[OWASP_WEB_TOP10_REFERENCE, OWASP_LLM_TOP10_REFERENCE, OWASP_ASI_TOP10_REFERENCE],
            memory_labels=memory_labels or {},
            orchestration_log=orchestration_log or [],
        )

        # ( target_fingerprint )
        # Data flow: recon (target_router) -> target_fingerprint -> evidence.attack_surface -> report
        # : + MCP + OpenAPI + + +
        fp = self._target_fingerprint
        collection.attack_surface = {
            #
            "api_path": fp.get("api_path", ""),
            "auth_type": fp.get("auth_type", ""),
            "framework": fp.get("framework", ""),
            "app_type": fp.get("app_type", ""),
            "content_type": fp.get("content_type", ""),
            #
            "capabilities": fp.get("capabilities", ""),
            "model_family": fp.get("model_family", ""),
            "language": fp.get("language", ""),
            "session_type": fp.get("session_type", ""),
            "secret_format": fp.get("secret_format", ""),
            "tenant_id": fp.get("tenant_id", ""),
            # MCP
            "mcp_tool_count": len(fp.get("mcp_tools", [])),
            "mcp_resource_count": len(fp.get("mcp_resources", [])),
            "mcp_tool_names": fp.get("mcp_tool_names", []),
            # OpenAPI
            "openapi_spec_path": fp.get("openapi_spec_path", ""),
            "openapi_endpoint_count": len(fp.get("openapi_endpoints", [])),
            "openapi_security_schemes": fp.get("openapi_security_schemes", []),
            #
            "port_endpoint_count": len(fp.get("port_endpoints", [])),
            #
            "probe_count": fp.get("probe_count", 0),
            "probe_duration_seconds": fp.get("probe_duration_seconds", 0),
            # L5 v39: ( converter )
            # Data flow: recon -> target_fingerprint -> _classify_target_type -> build_converter_map
            "target_type": fp.get("target_type", ""),
            # (P0-P2 )
            # Data flow: recon () -> target_fingerprint -> evidence.attack_surface -> report
            "ai_framework": fp.get("ai_framework", ""),
            "ai_framework_category": fp.get("ai_framework_category", ""),
            "system_prompt_leaked": fp.get("system_prompt_leaked", False),
            "system_prompt_extraction_method": fp.get("system_prompt_extraction_method", ""),
            "system_prompt_length": fp.get("system_prompt_length", 0),
            "model_ids": fp.get("model_ids", []),
            "api_behavior": fp.get("api_behavior", {}),
            "vector_dbs": fp.get("vector_dbs", []),
            "mcp_tool_safety": fp.get("mcp_tool_safety", []),
            "mcp_tool_safety_risky_count": sum(1 for t in fp.get("mcp_tool_safety", []) if t.get("risks")),
        }

        # OWASP
        owasp_web_stats: dict[str, dict[str, Any]] = {
            k: {
                "tested": 0,
                "success": 0,
                "failed": 0,
                "asr": 0.0,
                "category": v,
                "mitigations": _OWASP_WEB_MITIGATIONS.get(k, []),
            }
            for k, v in _OWASP_WEB_CATEGORIES.items()
        }
        owasp_llm_stats: dict[str, dict[str, Any]] = {
            k: {
                "tested": 0,
                "success": 0,
                "failed": 0,
                "asr": 0.0,
                "category": v,
                "mitigations": _OWASP_LLM_MITIGATIONS.get(k, []),
            }
            for k, v in _OWASP_LLM_CATEGORIES.items()
        }
        owasp_asi_stats: dict[str, dict[str, Any]] = {
            k: {
                "tested": 0,
                "success": 0,
                "failed": 0,
                "asr": 0.0,
                "category": v,
                "mitigations": _OWASP_ASI_MITIGATIONS.get(k, []),
            }
            for k, v in _OWASP_ASI_CATEGORIES.items()
        }

        total = 0
        success_count = 0
        fail_count = 0

        for technique_name, results in attack_results.items():
            technique_display_name = _get_technique_display_name(technique_name)
            # Calculate per-technique ASR for confidence scoring
            tech_total = len(results)
            tech_success = sum(1 for r in results if _is_success(r))
            technique_asr = (tech_success / tech_total * 100) if tech_total > 0 else 0.0

            for i, result in enumerate(results):
                is_success = _is_success(result)
                total += 1
                if is_success:
                    success_count += 1
                else:
                    fail_count += 1

                # W6 fix: 原先用 `enumerate(results)` 的局部索引 i，导致**每个技术都从
                # EVD-0001 重新编号** → EVD-0001 在多技术间重复 N 次，证据文件互相覆盖。
                # 改为采集器级单调序号，并由 _next_evidence_id 做唯一性兜底。
                evidence = self._build_evidence(
                    result=result,
                    technique_name=technique_name,
                    technique_display_name=technique_display_name,
                    technique_asr=technique_asr,
                    attack_index=self._evidence_seq,
                    is_success=is_success,
                )
                self._evidence_seq += 1

                collection.evidence.append(evidence)
                # Track successful evidence (P0-1 fix: was `pass`, now appends)
                if is_success:
                    collection.successful_evidence.append(evidence)

                # OWASP web stats
                owasp_id = evidence.owasp_id
                if owasp_id:
                    if owasp_id in owasp_web_stats:
                        stats = owasp_web_stats[owasp_id]
                        stats["tested"] += 1
                        if is_success:
                            stats["success"] += 1
                        else:
                            stats["failed"] += 1
                    elif owasp_id in owasp_llm_stats:
                        stats = owasp_llm_stats[owasp_id]
                        stats["tested"] += 1
                        if is_success:
                            stats["success"] += 1
                        else:
                            stats["failed"] += 1
                    elif owasp_id in owasp_asi_stats:
                        stats = owasp_asi_stats[owasp_id]
                        stats["tested"] += 1
                        if is_success:
                            stats["success"] += 1
                        else:
                            stats["failed"] += 1

                #
                collection.technique_distribution[technique_name] = (
                    collection.technique_distribution.get(technique_name, 0) + 1
                )

        collection.total_attacks = total
        collection.successful_attacks = success_count
        collection.failed_attacks = fail_count

        # OWASP compliance stats (P0-2 fix: removed buggy loop, direct assignment)
        collection.owasp_web_compliance = owasp_web_stats
        collection.owasp_llm_compliance = owasp_llm_stats
        collection.owasp_asi_compliance = owasp_asi_stats

        #
        collection.failure_analysis = self._analyze_failures(attack_results)

        # P0-4: Findings
        collection.findings = _build_findings(collection.evidence, owasp_web_stats, owasp_llm_stats, owasp_asi_stats)

        logger.info(
            "Evidence collected: %d total, %d success, %d failed, ASR=%.1f%% | "
            "OWASP Web coverage: %d/10, LLM coverage: %d/10, ASI coverage: %d/10 | Findings: %d",
            total,
            success_count,
            fail_count,
            overall_asr,
            sum(1 for v in owasp_web_stats.values() if v["tested"] > 0),
            sum(1 for v in owasp_llm_stats.values() if v["tested"] > 0),
            sum(1 for v in owasp_asi_stats.values() if v["tested"] > 0),
            len(collection.findings),
        )
        return collection

    def _build_evidence(
        self,
        *,
        result: Any,
        technique_name: str,
        technique_display_name: str,
        technique_asr: float,
        attack_index: int,
        is_success: bool,
    ) -> VulnerabilityEvidence:
        """Build VulnerabilityEvidence from attack result.

        R10 : all, Ensure JSON :
            - arxiv_reference: _get_arxiv_reference -> fallback "PyRIT (arXiv:2407.01232)"
            - conversation_history: _extract_conversation 3Layer fallback ->  objective+harmful_output
            - converter_log: _extract_converter_log -> metadata encoder -> "none (baseline)"
            - validation_runs: _extract_validation_runs ->  1
            - testing_conditions: _extract_testing_conditions -> timestamp/outcome/attack_id
            - converter_chain: imports converter_log  ->  "none (baseline)"
        """
        owasp_id = _get_owasp_id(result)
        objective = _extract_jailbreak_prompt(result)
        harmful_output = _extract_harmful_output(result)
        conversation = _extract_conversation(result)
        converter_log = _extract_converter_log(result)
        score_details = _extract_score_details(result)
        arxiv_ref = _get_arxiv_reference(technique_name)
        confidence = _determine_confidence(technique_asr, is_success)

        # P0-3: Ensure arxiv_reference - use fallback if _get_arxiv_reference returns None
        if not arxiv_ref:
            arxiv_ref = "PyRIT (arXiv:2407.01232)"

        # P0-1: Ensure conversation_history - 3Layer fallback
        # Build conversation from objective + harmful_output if not already present
        if not conversation:
            conv_obj = objective or ""
            conv_resp = harmful_output or ""
            if conv_obj and conv_resp:
                conversation = [
                    {"role": "user", "content": str(conv_obj)},
                    {"role": "assistant", "content": str(conv_resp)},
                ]
            elif conv_obj:
                conversation = [{"role": "user", "content": str(conv_obj)}]
            elif conv_resp:
                conversation = [{"role": "assistant", "content": str(conv_resp)}]
            else:
                # Fallback: system message indicating no data
                conversation = [{"role": "system", "content": "No conversation data available"}]

        # L5 v35: PyRIT Converter populates converter_log via result.metadata["encoder"]
        # For encoded_injection techniques, result.metadata["encoder"] records the encoding
        # type (e.g., base64, rot13, unicode_homoglyph)
        result_metadata = getattr(result, "metadata", {}) or {}
        if not converter_log:
            encoder = result_metadata.get("encoder", "")
            if encoder:
                converter_log = [
                    {
                        "converter": f"{encoder} (encoded_injection)",
                        "original": "",
                        "transformed": objective[:200] if objective else "",
                    }
                ]

        # P0-2: Even if baseline (no converter), ensure converter_log is populated
        # R10: converter_log for ALL evidence
        # baseline attacks record "none (baseline)"
        if not converter_log:
            converter_log = [
                {
                    "converter": "none (baseline)",
                    "original": objective[:200] if objective else "",
                    "transformed": objective[:200] if objective else "",
                }
            ]

        # P1-1: converter_chain - derived from converter_log, ensured by above
        converter_chain_str = ", ".join(c.get("converter", "") for c in converter_log)
        if not converter_chain_str:
            converter_chain_str = "none"

        # P0-4: score_details - single fallback (no pseudo validation_runs)
        if not score_details:
            score_details = [
                {
                    "scorer": "AttackOutcome",
                    "score_value": "success" if is_success else "failure",
                    "rationale": "Determined by post-hoc scoring (no explicit scorer object attached)",
                }
            ]

        # OWASP
        owasp_standard = _get_owasp_standard(owasp_id)
        owasp_severity = _compute_owasp_severity(owasp_id, is_success, technique_asr)
        owasp_risk_score = _compute_owasp_risk_score(owasp_id, is_success, technique_asr)
        owasp_mitigations = _get_owasp_mitigations(owasp_id)
        owasp_reference = _get_owasp_reference_url(owasp_id)
        cvss_vector = _get_cvss_vector(owasp_id)

        # P0-2: MITRE ATLAS
        mitre_info = _MITRE_ATLAS_TECHNIQUES.get(owasp_id, {})
        mitre_tactic = mitre_info.get("tactic", "")
        mitre_technique_id = mitre_info.get("technique_id", "")
        mitre_technique_name = mitre_info.get("technique_name", "")
        mitre_url = mitre_info.get("url", "")

        # : _success
        file_suffix = "_success" if is_success else ""

        # evidence_id _success
        attack_id = getattr(result, "attack_result_id", getattr(result, "id", str(uuid.uuid4())))
        evidence_id = self._next_evidence_id(attack_index, attack_id)

        return VulnerabilityEvidence(
            evidence_id=evidence_id,
            attack_id=attack_id,
            technique_name=technique_name,
            technique_display_name=technique_display_name,
            converter_chain=converter_chain_str,
            owasp_id=owasp_id,
            owasp_category=_OWASP_LLM_CATEGORIES.get(owasp_id, _OWASP_ASI_CATEGORIES.get(owasp_id, "Unknown")),
            owasp_standard=owasp_standard,
            owasp_severity=owasp_severity,
            owasp_risk_score=owasp_risk_score,
            owasp_mitigations=owasp_mitigations,
            owasp_reference=owasp_reference,
            cvss_vector=cvss_vector,
            objective=objective,
            jailbreak_prompt=objective,
            harmful_output=harmful_output,
            is_success=is_success,
            file_suffix=file_suffix,
            conversation_history=conversation,
            asr=technique_asr,
            confidence=confidence,
            arxiv_reference=arxiv_ref,
            timestamp=datetime.now().isoformat(),
            target_model=self._target_model,
            converter_log=converter_log,
            score_details=score_details,
            mitre_tactic=mitre_tactic,
            mitre_technique_id=mitre_technique_id,
            mitre_technique_name=mitre_technique_name,
            mitre_url=mitre_url,
            attack_result_ref=result,
            metadata=_extract_result_metadata(result, technique_name=technique_name),
        )

    def _analyze_failures(self, attack_results: dict[str, list[Any]]) -> dict[str, Any]:
        """Analyze attack failure patterns and compute per-technique ranking.

        Returns:
            Dict with keys: failure_types, technique_ranking
        """
        technique_success: dict[str, int] = {}
        technique_total: dict[str, int] = {}
        failure_types: dict[str, int] = {}

        for technique_name, results in attack_results.items():
            for result in results:
                technique_total[technique_name] = technique_total.get(technique_name, 0) + 1
                if _is_success(result):
                    technique_success[technique_name] = technique_success.get(technique_name, 0) + 1
                else:
                    failure_type = _classify_failure(result)
                    failure_types[failure_type] = failure_types.get(failure_type, 0) + 1

        # Compute technique ranking (by success rate)
        ranking = []
        total = sum(technique_total.values())
        for tech in technique_total:
            success = technique_success.get(tech, 0)
            rate = (success / total * 100) if total > 0 else 0
            ranking.append({"technique": tech, "success_rate": round(rate, 1), "total": total})

        ranking.sort(key=lambda x: x["success_rate"], reverse=True)

        return {
            "failure_types": failure_types,
            "technique_ranking": ranking,
        }
