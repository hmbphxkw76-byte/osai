"""report/web/sections — Web/API report section builder (object-local)."""
from __future__ import annotations

from report.common.replay import _assess_replay_complexity
from report.evidence import EvidenceCollection


def _build_web_api_sections(evidence: EvidenceCollection) -> dict[str, str]:
    """Build Web/API specific report sections.

    Sections:
        - auth_bypass: Authentication bypass evidence
        - rate_evasion: Rate limit evasion evidence
        - smuggling: HTTP request smuggling evidence
        - gateway_bypass: API Gateway/WAF bypass evidence
    """
    sections: dict[str, str] = {}

    # Auth bypass evidence
    auth_evidence: list[str] = []
    for ev in evidence.evidence:
        meta = getattr(ev, "metadata", {}) or {}
        cat = meta.get("category", "")
        if "auth" in cat.lower() or "jwt" in cat.lower() or "token" in cat.lower():
            technique = getattr(ev, "technique_name", "unknown")
            auth_evidence.append(f"{technique}: {cat}")

    if auth_evidence:
        auth_list = "\n".join(f"    - {ae}" for ae in auth_evidence)
        sections["auth_bypass"] = f"## Authentication Bypass Evidence\n\nAuth mechanism compromise:\n\n{auth_list}\n"

    # Rate limit evasion
    rate_evidence: list[str] = []
    for ev in evidence.successful_evidence:
        response = getattr(ev, "response", "") or ""
        meta = getattr(ev, "metadata", {}) or {}
        if "rate" in response.lower() or "throttle" in response.lower():
            technique = getattr(ev, "technique_name", "unknown")
            rate_evidence.append(f"{technique}: rate limit evasion")

    if rate_evidence:
        rate_list = "\n".join(f"    - {re}" for re in set(rate_evidence))
        sections["rate_evasion"] = f"## Rate Limit Evasion\n\nThrottling bypass:\n\n{rate_list}\n"

    # Request smuggling
    smuggling_evidence: list[str] = []
    for ev in evidence.evidence:
        meta = getattr(ev, "metadata", {}) or {}
        cat = meta.get("category", "")
        if "smuggl" in cat.lower():
            technique = getattr(ev, "technique_name", "unknown")
            smuggling_evidence.append(f"{technique}: {cat}")

    if smuggling_evidence:
        smg_list = "\n".join(f"    - {se}" for se in smuggling_evidence)
        sections["smuggling"] = f"## Request Smuggling Evidence\n\nHTTP smuggling vectors:\n\n{smg_list}\n"

    # Gateway bypass
    gateway_evidence: list[str] = []
    for ev in evidence.evidence:
        meta = getattr(ev, "metadata", {}) or {}
        cat = meta.get("category", "")
        if "gateway" in cat.lower() or "waf" in cat.lower():
            technique = getattr(ev, "technique_name", "unknown")
            gateway_evidence.append(f"{technique}: {cat}")

    if gateway_evidence:
        gw_list = "\n".join(f"    - {ge}" for ge in gateway_evidence)
        sections["gateway_bypass"] = f"## API Gateway/WAF Bypass\n\nSecurity control evasion:\n\n{gw_list}\n"

    # Replay complexity
    sections["replay_complexity"] = _assess_replay_complexity(evidence, "web")

    return sections
