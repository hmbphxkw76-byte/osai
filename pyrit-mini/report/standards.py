"""report/standards.py — 报告标准映射（REQ-166）。

把每条 finding 映射到 offsec 行业标准的分层/阶段/评分，作为既有
OWASP LLM/Web/ASI + MITRE ATLAS + CVSS 映射（REQ-113）的**增量 section**：

    - **OWASP AI Testing Guide (AITG)** 四层：Model / Implementation / System / Runtime
    - **PTES** 七阶段：Pre-engagement / Intelligence Gathering / Threat Modeling /
      Vulnerability Analysis / Exploitation / Post-Exploitation / Reporting
    - **AI-SSCV**（AI 专用严重度评分）：可解释的 0–10 评分 + 严重度分档

设计约束：
    - 纯数据 + 纯函数（无 IO、无 LLM），可离线生成（NFR-7）；
    - 不另立报告管线（C3），只提供 section 渲染与映射查询。

学术/标准依据：
    - OWASP AI Testing Guide（分层测试）
    - PTES (Penetration Testing Execution Standard)
    - AI-SSCV（AI-specific severity scoring，类比 CVSS）
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# OWASP AI Testing Guide 四层
# ---------------------------------------------------------------------------
AITG_LAYERS: dict[str, str] = {
    "Model": "模型层：对齐/越狱/有害生成/系统提示泄露",
    "Implementation": "实现层：Prompt 拼接/工具调用/检索管道/RAG 投毒",
    "System": "系统层：认证/会话/多租户/网关/审计",
    "Runtime": "运行时层：限流/熔断/成本放大/时序侧信道",
}

# ---------------------------------------------------------------------------
# PTES 七阶段
# ---------------------------------------------------------------------------
PTES_PHASES: tuple[str, ...] = (
    "Pre-engagement",
    "Intelligence Gathering",
    "Threat Modeling",
    "Vulnerability Analysis",
    "Exploitation",
    "Post-Exploitation",
    "Reporting",
)

# ---------------------------------------------------------------------------
# AI-SSCV：评分维度与权重（合计 1.0）
# ---------------------------------------------------------------------------
AI_SSCV_WEIGHTS: dict[str, float] = {
    "exploitability": 0.30,  # 利用难度（ASR 越高越易利用）
    "impact": 0.30,  # 影响面（数据泄露/权限/业务）
    "autonomy": 0.20,  # 自主性（是否无需人工介入即可复现）
    "data_sensitivity": 0.20,  # 触及数据的敏感度
}

SEVERITY_BANDS: tuple[tuple[float, str], ...] = (
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
    (0.0, "Info"),
)

# component_key → (AITG 层, PTES 阶段)
_COMPONENT_STANDARDS: dict[str, tuple[str, str]] = {
    "model_behavior_shift": ("Model", "Exploitation"),
    "mcp_tool_poisoning": ("Implementation", "Exploitation"),
    "rag_pipeline": ("Implementation", "Exploitation"),
    "embedding": ("Implementation", "Vulnerability Analysis"),
    "a2a_agent_integrity": ("Implementation", "Exploitation"),
    "llm_gateway": ("System", "Exploitation"),
    "session_memory": ("System", "Post-Exploitation"),
    "web_api": ("System", "Exploitation"),
    "audit_evasion": ("System", "Post-Exploitation"),
    "supply_chain": ("Implementation", "Intelligence Gathering"),
}


def severity_band(score: float) -> str:
    """Map an AI-SSCV score (0–10) to a severity band."""
    for threshold, label in SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "Info"


def compute_ai_sscv(
    *,
    exploitability: float,
    impact: float,
    autonomy: float,
    data_sensitivity: float,
) -> dict[str, Any]:
    """Compute an AI-SSCV score (0–10) from four normalized (0–1) metrics."""
    metrics = {
        "exploitability": max(0.0, min(1.0, exploitability)),
        "impact": max(0.0, min(1.0, impact)),
        "autonomy": max(0.0, min(1.0, autonomy)),
        "data_sensitivity": max(0.0, min(1.0, data_sensitivity)),
    }
    score = round(sum(metrics[k] * AI_SSCV_WEIGHTS[k] for k in AI_SSCV_WEIGHTS) * 10, 1)
    return {"score": score, "severity": severity_band(score), "metrics": metrics}


def ai_sscv_from_asr(
    *,
    asr_percent: float,
    component_key: str = "",
    exfil_confirmed: bool = False,
) -> dict[str, Any]:
    """Derive an AI-SSCV score from the observed ASR + component (report helper).

    Calibration (documented, not magic): exploitability tracks ASR; impact is
    raised by a confirmed exfiltration; autonomy/data sensitivity are component
    priors. Kept deterministic for reproducibility (NFR-5).
    """
    exploitability = max(0.0, min(1.0, (asr_percent or 0.0) / 100.0))
    impact = 0.9 if exfil_confirmed else 0.5
    autonomy = 0.7 if component_key in ("mcp_tool_poisoning", "a2a_agent_integrity") else 0.5
    data_sensitivity = 0.8 if component_key in ("session_memory", "rag_pipeline") else 0.4
    return compute_ai_sscv(
        exploitability=exploitability,
        impact=impact,
        autonomy=autonomy,
        data_sensitivity=data_sensitivity,
    )


def map_finding_to_standards(
    *,
    owasp_id: str = "",
    component_key: str = "",
) -> dict[str, str]:
    """Map a finding to AITG layer + PTES phase (falls back by OWASP id family)."""
    layer, phase = _COMPONENT_STANDARDS.get(component_key, ("", ""))
    if not layer:
        owasp = (owasp_id or "").upper()
        if owasp.startswith("LLM01") or owasp.startswith("LLM06"):
            layer, phase = "Model", "Exploitation"
        elif owasp.startswith("LLM") or owasp.startswith("ASI"):
            layer, phase = "Implementation", "Exploitation"
        elif owasp.startswith("A0"):
            layer, phase = "System", "Exploitation"
        else:
            layer, phase = "Implementation", "Vulnerability Analysis"
    return {
        "aitg_layer": layer,
        "aitg_layer_desc": AITG_LAYERS.get(layer, ""),
        "ptes_phase": phase,
        "component_key": component_key,
        "owasp_id": owasp_id,
    }


def build_standards_section(findings: list[dict[str, Any]] | None = None) -> str:
    """Render the standards-alignment markdown section (REQ-166).

    `findings` items may carry `owasp_id` / `component_key` / `asr_percent` /
    `exfil_confirmed`; missing keys degrade gracefully.
    """
    lines: list[str] = ["## Standards Alignment (OWASP AITG / PTES / AI-SSCV)", ""]

    lines.append("### OWASP AI Testing Guide — Layer Coverage")
    lines.append("")
    lines.append("| Layer | Scope |")
    lines.append("|---|---|")
    for layer, desc in AITG_LAYERS.items():
        lines.append(f"| {layer} | {desc} |")
    lines.append("")

    lines.append("### PTES — Phase Coverage")
    lines.append("")
    lines.append("| # | Phase |")
    lines.append("|---|---|")
    for idx, phase in enumerate(PTES_PHASES, start=1):
        lines.append(f"| {idx} | {phase} |")
    lines.append("")

    if findings:
        lines.append("### Per-Finding Standard Mapping & AI-SSCV")
        lines.append("")
        lines.append("| Finding | OWASP | AITG Layer | PTES Phase | AI-SSCV | Severity |")
        lines.append("|---|---|---|---|---|---|")
        for idx, finding in enumerate(findings, start=1):
            mapping = map_finding_to_standards(
                owasp_id=str(finding.get("owasp_id", "")),
                component_key=str(finding.get("component_key", "")),
            )
            sscv = ai_sscv_from_asr(
                asr_percent=float(finding.get("asr_percent", 0.0) or 0.0),
                component_key=str(finding.get("component_key", "")),
                exfil_confirmed=bool(finding.get("exfil_confirmed", False)),
            )
            title = str(finding.get("title") or f"F-{idx}")
            lines.append(
                f"| {title} | {mapping['owasp_id'] or '—'} | {mapping['aitg_layer']} | "
                f"{mapping['ptes_phase']} | {sscv['score']} | {sscv['severity']} |"
            )
        lines.append("")

    lines.append(
        "> AI-SSCV 为 AI 专用严重度评分（exploitability/impact/autonomy/data_sensitivity）；"
        "评分锚点与 ASR 口径见 NFR-13，禁止与历史数值直接对比得出退化结论。"
    )
    return "\n".join(lines)
