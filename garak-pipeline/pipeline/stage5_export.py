"""Stage 5 — PyRIT 消费导出

将 Stage4 的双框架分析报告 (analysis_{run_id}.json) 转换为 PyRIT 可消费的结构。
PyRIT 通常以 `Score` / `Dataset` / `Endpoint` 或自定义 JSON 消费安全评估结果。

本阶段输出一个**扁平化的评估结果列表**，每条含：
    - owasp_id          : OWASP 分类键 (owasp:llm01 / owasp:agentic06 ...)
    - framework         : "owasp_llm_top10_2025" | "owasp_agentic_top10_2026"
    - category          : 可读分类名
    - risk_score        : 0~1 风险评分
    - probe_count       : 覆盖探针数
    - vulnerable_rate   : 脆弱率
    - notes             : 人类可读风险描述

PyRIT 侧可加载后映射为 pyrit `Score`(score_value=risk_score,
score_type=ScoreType.TrueScore) 或 `Dataset`(用于红队评测复现)。

输出：
    outputs/05_export/pyrit_consumable_{run_id}.json
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

FRAMEWORK_LABELS = {
    "owasp_llm_top10_2025": "OWASP LLM Top 10 (2025)",
    "owasp_agentic_top10_2026": "OWASP Agentic Top 10 (2026, ASI01-10)",
}


class Stage5Exporter:
    def __init__(self, artifacts_dir: str = "outputs"):
        self.artifacts_dir = artifacts_dir

    def _resolve_analysis(self, run_id: str) -> Path | None:
        cands = [
            Path(self.artifacts_dir) / "04_analysis" / f"analysis_{run_id}.json",
            Path(self.artifacts_dir) / "04_analysis" / "analysis_20260801_1719.json",
        ]
        for c in cands:
            if c.exists():
                return c
        return None

    def _notes(self, fw: str, cid: str, v: dict) -> str:
        if fw.startswith("owasp_agentic"):
            if v.get("probe_count", 0) == 0:
                return "未映射探针（当前仅分类骨架，无执行数据）"
            return f"覆盖 {v['probe_count']} 个探针，需执行攻击以评估实际风险"
        status = v.get("status")
        if status == "no_coverage":
            return "无探针覆盖"
        if status == "fail":
            return f"高风险: 脆弱率 {v.get('vulnerable_rate')}，nones {v.get('nones_rate')}"
        if status == "warn":
            return f"中风险: 脆弱率 {v.get('vulnerable_rate')}"
        return f"低风险: 脆弱率 {v.get('vulnerable_rate')}，nones {v.get('nones_rate')}"

    def run(self, run_id: str) -> dict:
        analysis_path = self._resolve_analysis(run_id)
        if analysis_path is None:
            raise FileNotFoundError(
                f"未找到分析产物 analysis_{run_id}.json，请先运行 Stage4"
            )
        with analysis_path.open(encoding="utf-8") as fh:
            analysis = json.load(fh)

        records: list[dict] = []
        for fw, view in analysis["frameworks"].items():
            for cid, v in view.items():
                records.append(
                    {
                        "owasp_id": cid,
                        "framework": fw,
                        "framework_label": FRAMEWORK_LABELS.get(fw, fw),
                        "category": v.get("label", cid),
                        "risk_score": v.get("risk_score", 0.0),
                        "probe_count": v.get("probe_count", 0),
                        "vulnerable_rate": v.get("vulnerable_rate", 0.0),
                        "nones_rate": v.get("nones_rate", 0.0),
                        "status": v.get("status", "unknown"),
                        "notes": self._notes(fw, cid, v),
                    }
                )

        payload = {
            "schema": "pyrit-consumable/v1",
            "run_id": run_id,
            "source_analysis": str(analysis_path),
            "frameworks": list(FRAMEWORK_LABELS.values()),
            "results": records,
        }

        out_dir = Path(self.artifacts_dir) / "05_export"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"pyrit_consumable_{run_id}.json"
        with out_path.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        logger.info("PyRIT 消费产物: %s (%d 条记录)", out_path, len(records))
        return payload


def export(run_id: str, artifacts_dir: str = "outputs") -> dict:
    return Stage5Exporter(artifacts_dir=artifacts_dir).run(run_id)
