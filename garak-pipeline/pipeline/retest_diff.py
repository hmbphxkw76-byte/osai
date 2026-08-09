"""P2-3: re-test diff 模式 — 对比历史扫描结果与当前扫描结果

加载历史 analysis JSON（baseline），与当前扫描的 analysis JSON 对比，
生成 per-probe ASR/DEFCON 差异报告，标注回归/改善。

产物：outputs/04_analysis/retest_diff_{old_run_id}_to_{new_run_id}.json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_analysis(run_id: str, artifacts_dir: str = "outputs") -> dict[str, Any] | None:
    """加载指定 run_id 的 analysis JSON"""
    path = Path(artifacts_dir) / "04_analysis" / f"analysis_{run_id}.json"
    if not path.exists():
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def compute_retest_diff(
    baseline: dict[str, Any],
    current: dict[str, Any],
) -> dict[str, Any]:
    """计算两次扫描的 per-probe ASR/DEFCON 差异

    :param baseline: 历史扫描 analysis JSON
    :param current: 当前扫描 analysis JSON
    :returns: diff 报告 dict
    """
    baseline_probes = baseline.get("probe_results", {})
    current_probes = current.get("probe_results", {})

    all_probe_names = sorted(set(baseline_probes.keys()) | set(current_probes.keys()))

    probe_diffs: list[dict] = []
    asr_regressions = 0
    asr_improvements = 0
    defcon_regressions = 0
    defcon_improvements = 0

    for probe_name in all_probe_names:
        old = baseline_probes.get(probe_name, {})
        new = current_probes.get(probe_name, {})

        old_asr = old.get("asr", 0.0)
        new_asr = new.get("asr", 0.0)
        old_defcon = old.get("defcon", 5)
        new_defcon = new.get("defcon", 5)

        asr_delta = round(new_asr - old_asr, 2)
        defcon_delta = new_defcon - old_defcon

        # ASR 上升 = 回归（更不安全），DEFCON 下降 = 回归（风险等级升高）
        if asr_delta > 0:
            asr_regressions += 1
        elif asr_delta < 0:
            asr_improvements += 1

        if defcon_delta < 0:
            defcon_regressions += 1
        elif defcon_delta > 0:
            defcon_improvements += 1

        probe_diffs.append({
            "probe": probe_name,
            "baseline_asr": old_asr,
            "current_asr": new_asr,
            "asr_delta": asr_delta,
            "baseline_defcon": old_defcon,
            "current_defcon": new_defcon,
            "defcon_delta": defcon_delta,
            "status": _classify_change(asr_delta, defcon_delta),
        })

    # overall 对比
    old_overall = baseline.get("overall", {})
    new_overall = current.get("overall", {})

    return {
        "baseline_run_id": baseline.get("run_id", "unknown"),
        "current_run_id": current.get("run_id", "unknown"),
        "summary": {
            "total_probes_compared": len(all_probe_names),
            "asr_regressions": asr_regressions,
            "asr_improvements": asr_improvements,
            "defcon_regressions": defcon_regressions,
            "defcon_improvements": defcon_improvements,
            "baseline_overall_defcon": old_overall.get("defcon", 5),
            "current_overall_defcon": new_overall.get("defcon", 5),
            "baseline_worst_asr": old_overall.get("worst_asr", 0),
            "current_worst_asr": new_overall.get("worst_asr", 0),
        },
        "probe_diffs": probe_diffs,
    }


def _classify_change(asr_delta: float, defcon_delta: int) -> str:
    """分类单个探针的变化状态"""
    if asr_delta == 0 and defcon_delta == 0:
        return "unchanged"
    if asr_delta > 0 and defcon_delta < 0:
        return "regression"
    if asr_delta < 0 and defcon_delta > 0:
        return "improvement"
    if asr_delta > 0:
        return "asr_regression"
    if asr_delta < 0:
        return "asr_improvement"
    if defcon_delta < 0:
        return "defcon_regression"
    if defcon_delta > 0:
        return "defcon_improvement"
    return "unchanged"


def save_retest_diff(
    diff: dict[str, Any],
    baseline_run_id: str,
    current_run_id: str,
    artifacts_dir: str = "outputs",
) -> str:
    """保存 re-test diff 报告"""
    out_dir = Path(artifacts_dir) / "04_analysis"
    out_dir.mkdir(parents=True, exist_ok=True)
    filename = f"retest_diff_{baseline_run_id}_to_{current_run_id}.json"
    path = out_dir / filename
    with open(path, "w", encoding="utf-8") as f:
        json.dump(diff, f, ensure_ascii=False, indent=2)
    return str(path)
