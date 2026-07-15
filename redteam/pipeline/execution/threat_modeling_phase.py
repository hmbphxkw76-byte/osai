"""AI 目标威胁建模阶段（AI-300 Ch10: Threat Modeling Phase）。

Phase 10: 基于前面所有阶段的攻击数据，进行系统化威胁建模分析。
输出威胁建模报告，包含：
  - 假设登记册 (Hypothesis Register)
  - 信任区域界定 (Trust Boundary Mapping)
  - 攻击路径图 (Attack Path Graph)
  - 风险矩阵 (Risk Matrix)

AI-300 章节映射：Ch10: AI Target Threat Modeling
OSAI 评分维度：攻击链构建（20% 权重）
技术点：STRIDE 威胁建模、信任边界分析、攻击面映射
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from redteam.core.models import AIService, Finding, OWASPLlm, OWASP_AGENTIC, MITREATLASTactic, Severity
from redteam.core.kill_chain_tracker import get_tracker
from redteam.core.store import load_json, save_json
from redteam.core.terminal_output import print_section_header


@dataclass
class Hypothesis:
    """威胁建模假设条目。"""
    id: str  # H-001, H-002, ...
    observation: str
    hypothesis: str
    confidence: str  # low / medium / high / confirmed
    status: str  # unverified / investigating / confirmed / refuted
    related_findings: list[str] = field(default_factory=list)  # Finding 类别引用
    kill_chain_phase: str = ""


@dataclass
class TrustBoundary:
    """信任区域边界。"""
    id: str
    name: str
    description: str
    entry_points: list[str] = field(default_factory=list)
    exit_points: list[str] = field(default_factory=list)
    data_flows: list[str] = field(default_factory=list)
    risk_level: str = "medium"


@dataclass
class AttackPath:
    """攻击路径节点。"""
    id: str
    phase: str
    description: str
    technique: str
    prerequisites: list[str] = field(default_factory=list)
    impact: str = ""
    difficulty: str = "medium"  # trivial / easy / medium / hard / extreme


@dataclass
class ThreatModel:
    """威胁建模分析结果。"""
    target: str = ""
    hypotheses: list[Hypothesis] = field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    risk_summary: dict[str, int] = field(default_factory=dict)


def threat_modeling_phase(
    run_id: str,
    services: list[AIService],
    findings: list[Finding],
    target: str = "",
) -> ThreatModel:
    """AI 目标威胁建模分析（Phase 10）。

    构建系统化威胁模型：
      1. 假设登记册生成
      2. 信任区域边界映射
      3. 攻击路径构建
      4. 风险矩阵生成
      5. Kill Chain 覆盖率集成

    Args:
        run_id: 运行 ID
        services: AI 服务列表
        findings: 全部阶段的 Findings
        target: 目标 URL

    Returns:
        ThreatModel
    """
    print_section_header("[Phase 10] AI 目标威胁建模", "Ch10: Hypothesis Register + Trust Boundaries + Attack Paths")

    model = ThreatModel(target=target)
    model.hypotheses = _build_hypothesis_register(findings)
    model.trust_boundaries = _map_trust_boundaries(services, findings)
    model.attack_paths = _build_attack_paths(findings)
    model.risk_summary = _generate_risk_summary(findings)

    # ── Kill Chain 覆盖率数据集成 ──
    tracker = get_tracker()
    kc_coverage = tracker.get_coverage()
    atlas_map = tracker.get_atlas_map()

    # 保存威胁建模结果（含 Kill Chain 数据）
    model_data = {
        "target": model.target,
        "hypotheses": [_h_to_dict(h) for h in model.hypotheses],
        "trust_boundaries": [_tb_to_dict(tb) for tb in model.trust_boundaries],
        "attack_paths": [_ap_to_dict(ap) for ap in model.attack_paths],
        "risk_summary": model.risk_summary,
        "kill_chain_coverage": kc_coverage,
        "kill_chain_atlas_mapping": atlas_map,
    }
    save_json(run_id, "threat_model", model_data, subdir="recon")

    # 打印摘要
    print(f"  Hypotheses: {len(model.hypotheses)}")
    print(f"  Trust Boundaries: {len(model.trust_boundaries)}")
    print(f"  Attack Paths: {len(model.attack_paths)}")
    if model.risk_summary:
        print(f"  Risk Summary: {model.risk_summary}")
    print(f"  Kill Chain Coverage: {kc_coverage['covered']}/{kc_coverage['total_phases']} phases ({int(kc_coverage['ratio'] * 100)}%)")

    return model


def _build_hypothesis_register(findings: list[Finding]) -> list[Hypothesis]:
    """从 Findings 构建假设登记册。

    每个 Finding 的类别产生一个假设：
    - 观察：Finding 描述
    - 假设：该漏洞可能导致的攻击路径
    - 置信度：基于严重度推断
    - 状态：基于 verified 标记
    """
    hypotheses: list[Hypothesis] = []
    seen_categories: set[str] = set()

    for idx, f in enumerate(findings):
        cat = f.category or "unknown"
        if cat in seen_categories:
            continue
        seen_categories.add(cat)

        # 置信度推断
        sev = (f.severity or "").lower()
        if sev in ("critical",):
            confidence = "high"
        elif sev in ("high",):
            confidence = "medium"
        elif sev in ("medium",):
            confidence = "low"
        else:
            confidence = "low"

        # 状态推断
        status = "confirmed" if f.verified else "investigating"

        hypotheses.append(Hypothesis(
            id=f"H-{idx + 1:03d}",
            observation=f.description[:200] if f.description else cat,
            hypothesis=_generate_hypothesis_text(cat, f),
            confidence=confidence,
            status=status,
            related_findings=[cat],
            kill_chain_phase=f.mitre_atlas_tactic.value if hasattr(f.mitre_atlas_tactic, 'value') else str(f.mitre_atlas_tactic),
        ))

    return hypotheses


def _generate_hypothesis_text(category: str, finding: Finding) -> str:
    """根据 Finding 类别生成假设描述。"""
    templates: dict[str, str] = {
        "direct_prompt_injection": "攻击者可注入恶意指令绕过系统护栏，获取敏感信息或操控 Agent 行为",
        "memory_poisoning": "攻击者可污染 Agent 记忆，导致持久化行为偏差和信息泄露",
        "tool_hijacking": "攻击者可劫持 Agent 工具调用，实现未授权的系统操作",
        "goal_hijack": "攻击者可篡改 Agent 任务目标，使其执行恶意操作",
        "cross_agent_injection": "攻击者可利用 Agent 间信任关系进行横向移动",
        "rogue_agent": "攻击者可注入恶意 Agent 实现持久化 C2 通道",
        "cascading_failure": "单 Agent 故障可传播至整个多 Agent 系统",
        "knowledge_poisoning": "攻击者可投毒 RAG 知识库，影响检索结果的准确性",
        "retrieval_leakage": "RAG 系统可能泄露未授权的知识库内容",
    }
    return templates.get(category, f"漏洞类别 {category} 可能导致安全影响")


def _map_trust_boundaries(
    services: list[AIService],
    findings: list[Finding],
) -> list[TrustBoundary]:
    """映射信任区域边界。

    识别系统中的信任边界：
    - Agent ↔ LLM Core 边界
    - Agent ↔ 外部工具 边界
    - Agent ↔ Agent 边界（多 Agent 系统）
    - RAG ↔ 外部数据源 边界
    """
    boundaries: list[TrustBoundary] = []

    for svc in services:
        # Agent ↔ LLM Core 边界
        if svc.protocol in ("openai", "ollama", "llm"):
            boundaries.append(TrustBoundary(
                id=f"TB-{len(boundaries) + 1:03d}",
                name=f"Agent↔LLM Core ({svc.protocol})",
                description="Agent 系统与 LLM 推理核心之间的信任边界",
                entry_points=[f"{svc.url}/v1/chat/completions"],
                exit_points=[f"{svc.url}/responses"],
                data_flows=["prompt → LLM → completion → Agent"],
                risk_level="medium",
            ))

        # Agent ↔ 工具 边界
        if svc.tools:
            boundaries.append(TrustBoundary(
                id=f"TB-{len(boundaries) + 1:03d}",
                name=f"Agent↔Tools ({svc.protocol})",
                description="Agent 与其可用工具之间的信任边界",
                entry_points=svc.tools[:3],
                exit_points=["tool execution results → Agent → LLM context"],
                data_flows=["Agent → tool_call → execution → output → Agent"],
                risk_level="high",
            ))

        # Agent ↔ Agent 边界（多 Agent）
        if svc.protocol == "agent_to_agent":
            boundaries.append(TrustBoundary(
                id=f"TB-{len(boundaries) + 1:03d}",
                name="Inter-Agent Communication",
                description="多 Agent 系统中 Agent 之间的通信边界",
                entry_points=[svc.url],
                exit_points=["A2A broadcast / peer-to-peer messages"],
                data_flows=["Agent A → A2A message → Agent B"],
                risk_level="high",
            ))

    # RAG ↔ 知识库边界
    has_rag = any("rag" in (f.category or "").lower() or "knowledge" in (f.category or "").lower() for f in findings)
    if has_rag:
        boundaries.append(TrustBoundary(
            id=f"TB-{len(boundaries) + 1:03d}",
            name="RAG↔Knowledge Base",
            description="RAG 系统与向量数据库/知识库之间的信任边界",
            entry_points=["retrieval endpoint", "embedding API"],
            exit_points=["search results → LLM context"],
            data_flows=["query → embedding → vector search → chunks → LLM"],
            risk_level="high",
        ))

    return boundaries


def _build_attack_paths(findings: list[Finding]) -> list[AttackPath]:
    """构建攻击路径图。

    从 Findings 中提取攻击链节点，构建端到端攻击路径：
    Recon → Initial Access → Execution → Privilege Escalation → Impact
    """
    paths: list[AttackPath] = []

    # 按 Kill Chain 阶段分组 Findings
    phase_findings: dict[str, list[Finding]] = {}
    for f in findings:
        phase = "unknown"
        if f.category:
            cat = f.category.lower()
            if any(k in cat for k in ("recon", "discover")):
                phase = "reconnaissance"
            elif any(k in cat for k in ("inject", "bypass", "extract", "jailbreak")):
                phase = "initial_access"
            elif any(k in cat for k in ("tool", "execute", "code", "rce")):
                phase = "execution"
            elif any(k in cat for k in ("memory", "poison", "persist", "backdoor")):
                phase = "persistence"
            elif any(k in cat for k in ("priv", "escal", "abuse", "cross_agent")):
                phase = "privilege_escalation"
            elif any(k in cat for k in ("leak", "collect", "retriev")):
                phase = "collection"
            elif any(k in cat for k in ("cascade", "failure", "impact", "denial")):
                phase = "actions_on_objective"

        if phase not in phase_findings:
            phase_findings[phase] = []
        phase_findings[phase].append(f)

    # 构建攻击路径
    path_id = 1
    kill_chain_phases = [
        ("reconnaissance", "AI 资产发现与侦察"),
        ("initial_access", "提示注入获取初始访问"),
        ("execution", "工具误用/代码执行"),
        ("persistence", "记忆投毒建立持久化"),
        ("privilege_escalation", "权限提升/横向移动"),
        ("collection", "数据收集与泄露"),
        ("actions_on_objective", "最终影响/目标达成"),
    ]

    for phase_key, phase_desc in kill_chain_phases:
        phase_fs = phase_findings.get(phase_key, [])
        if phase_fs:
            for pf in phase_fs[:1]:  # 每阶段取一个代表性 Finding
                paths.append(AttackPath(
                    id=f"AP-{path_id:03d}",
                    phase=phase_key,
                    description=f"{phase_desc}: {pf.title or pf.description[:100]}",
                    technique=pf.category or "",
                    impact=_estimate_impact(pf),
                    difficulty=_estimate_difficulty(pf),
                ))
                path_id += 1
        else:
            # 即使没有 Finding 也保留节点（表示攻击路径中可达但未探测的阶段）
            paths.append(AttackPath(
                id=f"AP-{path_id:03d}",
                phase=phase_key,
                description=f"[未探测] {phase_desc}",
                technique="",
                impact="unknown",
                difficulty="unknown",
            ))
            path_id += 1

    return paths


def _estimate_impact(finding: Finding) -> str:
    """根据 Finding 严重度估算影响。"""
    sev = (finding.severity or "").lower()
    if sev == "critical":
        return "全系统妥协/数据完全泄露"
    elif sev == "high":
        return "部分系统控制/敏感数据泄露"
    elif sev == "medium":
        return "有限数据访问/服务降级"
    return "低影响/信息泄露"


def _estimate_difficulty(finding: Finding) -> str:
    """根据 Finding 类别估算攻击难度。"""
    cat = (finding.category or "").lower()
    if "pickle" in cat or "rce" in cat:
        return "easy"  # 已知漏洞利用
    elif "inject" in cat or "bypass" in cat:
        return "medium"
    elif "memory" in cat or "poison" in cat:
        return "medium"
    elif "cross" in cat or "multi" in cat:
        return "hard"
    return "medium"


def _generate_risk_summary(findings: list[Finding]) -> dict[str, int]:
    """生成风险摘要矩阵。"""
    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.severity or "info").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
        else:
            sev_counts["info"] += 1
    return sev_counts


# ── 序列化辅助 ────────────────────────────────────────────────

def _h_to_dict(h: Hypothesis) -> dict:
    return {
        "id": h.id, "observation": h.observation, "hypothesis": h.hypothesis,
        "confidence": h.confidence, "status": h.status,
        "related_findings": h.related_findings, "kill_chain_phase": h.kill_chain_phase,
    }


def _tb_to_dict(tb: TrustBoundary) -> dict:
    return {
        "id": tb.id, "name": tb.name, "description": tb.description,
        "entry_points": tb.entry_points, "exit_points": tb.exit_points,
        "data_flows": tb.data_flows, "risk_level": tb.risk_level,
    }


def _ap_to_dict(ap: AttackPath) -> dict:
    return {
        "id": ap.id, "phase": ap.phase, "description": ap.description,
        "technique": ap.technique, "prerequisites": ap.prerequisites,
        "impact": ap.impact, "difficulty": ap.difficulty,
    }


__all__ = [
    "Hypothesis",
    "TrustBoundary",
    "AttackPath",
    "ThreatModel",
    "threat_modeling_phase",
]
