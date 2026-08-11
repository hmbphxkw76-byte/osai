"""跨目标关联分析 — 多页面/多目标间共享漏洞关联

场景：同一 Web 应用的多个子页面（/, /explore, /labs/PI_01）各自扫描后，
需对比各页面的安全态势，识别：
  1. 共享后端 API（多页面调用同一 endpoint → 一次漏洞多处有效）
  2. 隔离边界（不同页面 → 不同 API → 独立风险域）
  3. 漏洞重叠（同一 OWASP 类在多个页面均被利用 → 系统性问题）
  4. 独有风险（某页面独有的漏洞 → 页面特定问题）

产物: outputs/04_analysis/cross_target_{timestamp}.json
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def analyze_cross_target(
    batch_summary: dict[str, Any],
    artifacts_dir: str = "outputs",
) -> dict[str, Any]:
    """跨目标关联分析

    :param batch_summary: batch_runner.run_batch() 的汇总结果
    :param artifacts_dir: 产物根目录
    :returns: 关联分析结果 dict
    """
    targets = batch_summary.get("targets", [])
    if len(targets) < 2:
        return {"analyzed": False, "reason": "少于 2 个目标，无需关联分析"}

    # 收集各目标的详细分析结果
    target_analyses = _collect_target_analyses(targets)

    # 1. 共享 endpoint 检测
    shared_endpoints = _detect_shared_endpoints(target_analyses)

    # 2. 漏洞重叠分析
    vulnerability_overlap = _analyze_vulnerability_overlap(target_analyses)

    # 3. 独有风险识别
    unique_risks = _identify_unique_risks(target_analyses)

    # 4. 风险域隔离分析
    risk_domains = _analyze_risk_domains(target_analyses, shared_endpoints)

    # 5. 系统性问题识别
    systemic_issues = _identify_systemic_issues(vulnerability_overlap)

    result = {
        "analyzed": True,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_targets": len(target_analyses),
        "shared_endpoints": shared_endpoints,
        "vulnerability_overlap": vulnerability_overlap,
        "unique_risks": unique_risks,
        "risk_domains": risk_domains,
        "systemic_issues": systemic_issues,
        "recommendations": _generate_recommendations(
            shared_endpoints, vulnerability_overlap, systemic_issues,
        ),
    }

    # 保存产物
    out_dir = Path(artifacts_dir) / "04_analysis"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"cross_target_{time.strftime('%Y%m%d_%H%M')}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    result["output_path"] = str(out_path)

    return result


def _collect_target_analyses(targets: list[dict]) -> list[dict]:
    """收集各目标的详细分析结果"""
    analyses = []
    for t in targets:
        if t.get("status") != "success":
            continue
        analysis_path = t.get("analysis_path")
        if not analysis_path or not Path(analysis_path).exists():
            analyses.append({
                "name": t.get("name", "?"),
                "model": t.get("model", "?"),
                "endpoint": t.get("endpoint", ""),
                "defcon": t.get("defcon"),
                "worst_asr": t.get("worst_asr", 0),
                "owasp": {},
            })
            continue
        try:
            with open(analysis_path, encoding="utf-8") as f:
                analysis = json.load(f)
            analyses.append({
                "name": t.get("name", "?"),
                "model": t.get("model", "?"),
                "endpoint": t.get("endpoint", ""),
                "defcon": t.get("defcon"),
                "worst_asr": t.get("worst_asr", 0),
                "owasp": analysis.get("owasp_llm", {}),
                "overall": analysis.get("overall", {}),
            })
        except Exception as exc:
            logger.debug("读取 %s 分析结果失败: %s", t.get("name"), exc)
            analyses.append({
                "name": t.get("name", "?"),
                "model": t.get("model", "?"),
                "endpoint": t.get("endpoint", ""),
                "defcon": t.get("defcon"),
                "worst_asr": t.get("worst_asr", 0),
                "owasp": {},
            })
    return analyses


def _detect_shared_endpoints(target_analyses: list[dict]) -> dict[str, list[str]]:
    """检测多个页面是否共享同一后端 API endpoint

    :returns: {endpoint: [target_name, ...], ...}
    """
    endpoint_map: dict[str, list[str]] = {}
    for ta in target_analyses:
        ep = ta.get("endpoint", "")
        if ep:
            endpoint_map.setdefault(ep, []).append(ta["name"])
    # 仅返回被多个目标共享的 endpoint
    return {ep: names for ep, names in endpoint_map.items() if len(names) > 1}


def _analyze_vulnerability_overlap(target_analyses: list[dict]) -> dict[str, Any]:
    """分析各目标间的漏洞重叠情况"""
    # 收集每个目标的 OWASP 漏洞类集合
    target_vulns: dict[str, set[str]] = {}
    for ta in target_analyses:
        owasp = ta.get("owasp", {})
        vulns = set()
        for category, data in owasp.items():
            if isinstance(data, dict):
                asr = data.get("worst_asr", 0)
                defcon = data.get("defcon", 5)
                if asr > 0 or defcon <= 3:
                    vulns.add(category)
        target_vulns[ta["name"]] = vulns

    # 计算重叠
    overlap: dict[str, list[str]] = {}
    all_vulns = set()
    for vulns in target_vulns.values():
        all_vulns |= vulns

    for vuln in all_vulns:
        affected = [name for name, vulns in target_vulns.items() if vuln in vulns]
        if len(affected) > 1:
            overlap[vuln] = affected

    return {
        "overlapping_vulnerabilities": overlap,
        "all_vulnerabilities": sorted(all_vulns),
        "target_vulnerability_sets": {
            name: sorted(vulns) for name, vulns in target_vulns.items()
        },
    }


def _identify_unique_risks(target_analyses: list[dict]) -> dict[str, list[str]]:
    """识别各目标独有的风险（其他目标未出现的漏洞类）"""
    target_vulns: dict[str, set[str]] = {}
    for ta in target_analyses:
        owasp = ta.get("owasp", {})
        vulns = set()
        for category, data in owasp.items():
            if isinstance(data, dict):
                asr = data.get("worst_asr", 0)
                defcon = data.get("defcon", 5)
                if asr > 0 or defcon <= 3:
                    vulns.add(category)
        target_vulns[ta["name"]] = vulns

    unique: dict[str, list[str]] = {}
    for name, vulns in target_vulns.items():
        others = set()
        for other_name, other_vulns in target_vulns.items():
            if other_name != name:
                others |= other_vulns
        only_this = vulns - others
        if only_this:
            unique[name] = sorted(only_this)
    return unique


def _analyze_risk_domains(
    target_analyses: list[dict],
    shared_endpoints: dict[str, list[str]],
) -> dict[str, Any]:
    """分析风险域隔离情况"""
    if not shared_endpoints:
        # 所有目标使用不同 endpoint → 完全隔离
        return {
            "isolation": "fully_isolated",
            "description": "各页面使用独立后端 API，风险域完全隔离",
            "domains": [
                {"name": ta["name"], "endpoint": ta.get("endpoint", "")}
                for ta in target_analyses
            ],
        }

    # 有共享 endpoint → 部分共享
    shared_names = set()
    for names in shared_endpoints.values():
        shared_names.update(names)

    isolated_names = [ta["name"] for ta in target_analyses if ta["name"] not in shared_names]

    return {
        "isolation": "partially_shared",
        "description": f"{len(shared_names)} 个页面共享后端 API，{len(isolated_names)} 个页面独立",
        "shared_targets": sorted(shared_names),
        "isolated_targets": isolated_names,
        "shared_endpoints": list(shared_endpoints.keys()),
    }


def _identify_systemic_issues(overlap: dict[str, Any]) -> list[dict[str, Any]]:
    """识别系统性问题（在多个目标中均出现的漏洞 → 系统性而非页面特定）"""
    systemic = []
    for vuln, affected_targets in overlap.get("overlapping_vulnerabilities", {}).items():
        systemic.append({
            "vulnerability": vuln,
            "affected_targets": affected_targets,
            "severity": "systemic" if len(affected_targets) >= 3 else "shared",
            "description": (
                f"{vuln} 在 {len(affected_targets)} 个页面均被利用，"
                f"属于系统性问题而非单页面缺陷"
            ),
        })
    return systemic


def _generate_recommendations(
    shared_endpoints: dict[str, list[str]],
    overlap: dict[str, Any],
    systemic_issues: list[dict[str, Any]],
) -> list[str]:
    """生成跨目标关联分析的建议"""
    recs = []

    if shared_endpoints:
        for ep, names in shared_endpoints.items():
            recs.append(
                f"共享 API {ep} 被 {len(names)} 个页面调用（{', '.join(names)}），"
                "修复该 API 的漏洞可同时改善多个页面的安全态势"
            )

    if systemic_issues:
        recs.append(
            f"发现 {len(systemic_issues)} 个系统性问题（多页面共享漏洞），"
            "建议优先修复系统性问题以获得最大投入产出比"
        )

    if not shared_endpoints and not systemic_issues:
        recs.append(
            "各页面风险域独立，无共享漏洞。可按页面优先级独立修复"
        )

    return recs
