"""Stage 4 — 攻击分析

解析 Stage3 产出的 garak 原生 JSONL 报告：
- 提取每 probe × detector 的 ASR（攻击成功率）与置信区间
- 计算 DEFCON 评分（规则三，基于 garak analyze.score_to_defcon）
- 双框架聚合（OWASP LLM Top10 + Agentic Top10 2026）
- 产出 analysis_{run_id}.json 供 Stage5 卡片展示与 PyRIT 消费

严格消费 garak 原生报告格式（规则一：不另起炉灶）。
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from .recon_garak import (
    classify_probes_dual,
)


def parse_garak_report(report_path: str) -> dict:
    """解析 garak 报告 JSONL

    :param report_path: garak <uuid>.report.jsonl 路径
    :returns: {
        "probe_summaries": [probe_summary 记录...],
        "evals": [eval 记录...],   # 含 ASR/置信区间
        "run_id": str,
    }
    """
    probe_summaries: list[dict] = []
    evals: list[dict] = []
    run_id = None

    p = Path(report_path)
    if not p.exists():
        raise FileNotFoundError(f"未找到 garak 报告: {report_path}")

    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            et = rec.get("entry_type")
            if et == "probe_summary":
                probe_summaries.append(rec)
            elif et == "eval":
                evals.append(rec)
            elif et == "run":
                run_id = rec.get("run_id")

    return {"probe_summaries": probe_summaries, "evals": evals, "run_id": run_id}


def _compute_asr(eval_rec: dict) -> float:
    """由 eval 记录计算攻击成功率（失败数 / 评估总数）"""
    fails = eval_rec.get("fails", 0)
    total = eval_rec.get("total_evaluated", 0)
    if not total:
        return 0.0
    return 100.0 * fails / total


def _aggregate_by_probe(evals: list[dict]) -> dict[str, dict]:
    """按 probe 聚合其所有 detector 的最差 ASR（最保守估计）

    :returns: {probe: {"asr": float, "detectors": {det: asr}, "ci": (lo,hi)|None}}
    """
    by_probe: dict[str, dict] = defaultdict(lambda: {"detectors": {}, "worst": 0.0, "ci": None})
    for e in evals:
        probe = e.get("probe")
        det = e.get("detector")
        if not probe or not det:
            continue
        asr = _compute_asr(e)
        entry = by_probe[probe]
        entry["detectors"][det] = asr
        entry["worst"] = max(entry["worst"], asr)
        # 取最宽置信区间
        if e.get("confidence_lower") is not None and e.get("confidence_upper") is not None:
            lo = e["confidence_lower"] * 100
            hi = e["confidence_upper"] * 100
            if entry["ci"] is None:
                entry["ci"] = [lo, hi]
            else:
                entry["ci"][0] = min(entry["ci"][0], lo)
                entry["ci"][1] = max(entry["ci"][1], hi)
    return dict(by_probe)


def analyze(
    report_path: str,
    filtered_probes: list[dict],
    run_id: str,
    artifacts_dir: str,
    garak_run_id: str | None = None,
) -> dict:
    """分析 garak 报告，双框架聚合 + DEFCON 评分

    :param report_path: Stage3 的 garak 报告路径
    :param filtered_probes: Stage1 模态裁剪后的探针元数据（用于双框架分类）
    :param run_id: 运行标识
    :param artifacts_dir: 产物根目录
    :param garak_run_id: garak 原生报告 uuid（优先于报告内解析）
    :returns: 分析结果 dict（并写出 analysis_{run_id}.json）
    """
    parsed = parse_garak_report(report_path)
    agg = _aggregate_by_probe(parsed["evals"])

    # DEFCON: 复用 garak analyze 评分（最差 ASR → DEFCON 1-5）
    from garak.analyze import ABSOLUTE_DEFCON_BOUNDS, score_to_defcon

    probe_results: dict[str, dict] = {}
    for probe, info in agg.items():
        asr = info["worst"]
        # garak score_to_defcon 接收 0-1 的 sucess rate
        defcon = score_to_defcon(asr / 100.0, ABSOLUTE_DEFCON_BOUNDS)
        probe_results[probe] = {
            "asr": round(asr, 2),
            "defcon": defcon,
            "detectors": {d: round(v, 2) for d, v in info["detectors"].items()},
            "ci": [round(x, 2) for x in info["ci"]] if info["ci"] else None,
        }

    # 双框架分类（复用 Stage1 分类逻辑，保证一致）
    dual = classify_probes_dual(filtered_probes)

    # 按框架桶聚合 ASR（桶内取最差 probe 的 ASR 作为桶评级）
    def _bucket_asr(label_map: dict[str, list[str]]) -> dict[str, dict]:
        out: dict[str, dict] = {}
        for label, probes in label_map.items():
            asrs = [probe_results[p]["asr"] for p in probes if p in probe_results]
            if not asrs:
                continue
            worst = max(asrs)
            defcon = score_to_defcon(
                worst / 100.0, ABSOLUTE_DEFCON_BOUNDS
            )
            out[label] = {
                "probe_count": len(probes),
                "evaluated": len(asrs),
                "worst_asr": round(worst, 2),
                "defcon": defcon,
            }
        return out

    llm_summary = _bucket_asr(dual["owasp_llm"])
    agentic_summary = _bucket_asr(dual["owasp_agentic"])

    result = {
        "run_id": run_id,
        "garak_run_id": garak_run_id or parsed["run_id"],
        "report_path": report_path,
        "probes_evaluated": len(probe_results),
        "probe_results": probe_results,
        "owasp_llm": llm_summary,
        "owasp_agentic": agentic_summary,
    }

    out_dir = Path(artifacts_dir) / "04_analysis"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"analysis_{run_id}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    result["analysis_path"] = str(out_path)
    return result
