"""Stage 5 — 报告与导出

- 终端卡片化展示最终评估结果（各 OWASP / Agentic 桶 DEFCON + ASR）
- 导出 PyRIT 可消费格式（AIR 风格攻击-影响-记录），供下游红队流水线

严格消费 Stage4 analysis_{run_id}.json（产物链契约）。
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

# PyRIT 1.0 Score 字段约束（经 pyrit.score.scorer.Score 实测）：
#   - score_value : str          (非 float)
#   - score_category: list[str]  (非 str)
#   - message_piece_id: UUID str (必填，不可 null)
#   - timestamp   : 必须带时区 (timezone-aware)
#   - score_metadata: 不接受 None 值（None 应省略该键）
#   - 模型禁止额外字段 (extra_forbidden) → 每条 Score 不含 "schema" 键
# 故导出严格对齐该 schema，使下游 `Score.model_validate(item)` 可直接加载。
_PYRIT_SCHEMA = "pyrit-score/v1"


def _stable_uuid(*parts: str) -> str:
    """由内容派生的确定性 UUID5（基于 DNS namespace），保证可复现且非空"""
    seed = "|".join(parts)
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, seed))


def _now_iso() -> str:
    """带时区的当前时间戳（满足 PyRIT timestamp 约束）"""
    return datetime.now(timezone.utc).isoformat()


def render_final_cards(analysis: dict, all_owasp_ids: list[str] | None = None) -> None:
    """渲染终态卡片：LLM / Agentic 双框架 DEFCON + ASR 表格

    :param analysis: Stage4 分析结果 dict
    :param all_owasp_ids: OWASP LLM Top10 完整类标签列表（来自 recon_garak
                          .OWASP_CATEGORIES.values()）。若提供，则对未被任何
                          garak 探针覆盖的类标注 N/A（透明宣称覆盖局限，而非
                          静默遗漏），如 LLM03/05/07/08 在 garak 0.15.1 下无探针。
    """
    from .utils import print_table_card

    llm = analysis.get("owasp_llm", {})
    agentic = analysis.get("owasp_agentic", {})

    if llm or all_owasp_ids:
        # 完整类集合（评估到的 ∪ 期望全量），保序
        labels = list(llm.keys())
        if all_owasp_ids:
            for lbl in all_owasp_ids:
                if lbl not in labels:
                    labels.append(lbl)
        labels = sorted(labels)
        rows = []
        na_count = 0
        for label in labels:
            v = llm.get(label)
            if v:
                # 有效率 = effective_coverage（0-100%），评估有效样本占比
                eff = v.get("effective_coverage", 0.0)
                eff_str = f"{eff:.0f}%" if eff > 0 else "—"
                rows.append([
                    label, str(v["probe_count"]), str(v["evaluated"]),
                    f'{v["worst_asr"]}%', eff_str, f'DEFCON {v["defcon"]}',
                ])
            else:
                na_count += 1
                rows.append([
                    label, "0", "0", "N/A", "—",
                    "未覆盖(garak 无对应探针)",
                ])
        print_table_card(
            "OWASP LLM Top 10 (2025) — 攻击面评估",
            ["分类", "探针数", "已评估", "最差ASR", "有效率", "评级"],
            rows,
        )
        if na_count:
            print(f"   ⚠️  {na_count} 个 OWASP 类未被 garak 探针覆盖（标注 N/A，非评估通过）")

    if agentic:
        rows = [
            [label, str(v["probe_count"]), str(v["evaluated"]),
             f'{v["worst_asr"]}%',
             f'{v.get("effective_coverage", 0.0):.0f}%' if v.get("effective_coverage") else "—",
             f'DEFCON {v["defcon"]}']
            for label, v in sorted(agentic.items())
        ]
        print_table_card(
            "OWASP Agentic Top 10 (2026) — 攻击面评估",
            ["分类", "探针数", "已评估", "最差ASR", "有效率", "评级"],
            rows,
        )

    # 数据可靠性告警（对齐 garak 0.15.1 官方对 nones 的态度）
    dq = analysis.get("data_quality", {})
    rel = dq.get("reliability", "normal")
    null_rate = dq.get("overall_null_rate", 0.0)
    eff_cov = dq.get("overall_effective_coverage", 0.0)
    if rel == "unreliable":
        print(
            f"\n  ⚠️  数据可靠性告警: 评估不可靠（nones={null_rate:.1f}%，"
            f"有效样本率仅 {eff_cov:.1f}%）"
        )
        print(f"  → 目标可能不可达或模型响应异常，ASR/DEFCON 评分不代表目标安全性。")
        print(f"  → 请检查目标连通性与模型可用性后重新评估。")
    elif rel == "degraded":
        print(
            f"\n  ⚠️  数据可靠性告警: 评估质量下降（nones={null_rate:.1f}%，"
            f"有效样本率 {eff_cov:.1f}%），结果置信度降低。"
        )

    print(
        f"\n🛡️  共评估 {analysis.get('probes_evaluated', 0)} 个探针"
        f"（garak run_id: {analysis.get('garak_run_id')}）"
    )


def _asr_to_score_type(asr: float) -> str:
    """ASR 百分比 → PyRIT score_type 语义映射

    PyRIT 常用 'float_scale' 表示 0~1 连续风险值。此处以百分比字符串
    表达，score_type 标为 'float_scale' 以兼容下游聚合。
    """
    return "float_scale"


def _asr_to_score_value(asr: float) -> str:
    """ASR 百分比 → PyRIT float_scale 归一化值 (0~1 字符串)

    PyRIT 约束: float_scale 类型的 score_value 必须在 [0, 1]。
    故 75.5% → "0.755"。
    """
    return str(round(asr / 100.0, 4))


def export_pyrit_air(
    analysis: dict,
    artifacts_dir: str,
    run_id: str,
    all_owasp_ids: list[str] | None = None,
) -> str:
    """导出 PyRIT 1.0 原生可消费格式（Score 数组）

    每个 OWASP 桶 / 每个被评估探针 → 一条 PyRIT `Score` dict，字段严格对齐
    `pyrit.score.scorer.Score` 的 pydantic schema：
        - score_value       : str(ASR 百分比)
        - score_type        : 'float_scale'
        - score_category    : [owasp_id, framework]
        - score_rationale   : 人类可读风险描述
        - score_metadata    : 携带 DEFCON / 置信区间 / 检测器明细
        - scorer_class_identifier: 固定标识本管线
        - message_piece_id  : 由 run_id+probe+detector 派生的确定性 UUID5
                              （非空、可复现、符合 PyRIT UUID 约束）

    下游消费示例：
        from pyrit.score.scorer import Score
        data = json.load(open(path))
        scores = [Score.model_validate(s) for s in data["scores"]]

    :param analysis: Stage4 分析结果
    :param artifacts_dir: 产物根目录
    :param run_id: 运行标识
    :param all_owasp_ids: OWASP LLM Top10 完整类标签。若提供，对未被覆盖类
                          在 attack_surface.coverage_gaps 中声明（透明标注局限）
    :returns: 导出文件路径
    """
    scores: list[dict] = []
    ts = _now_iso()

    # 计算覆盖缺口（N/A 类）：期望全量 − 实际评估到的
    coverage_gaps: list[str] = []
    evaluated_llm = set(analysis.get("owasp_llm", {}).keys())
    if all_owasp_ids:
        coverage_gaps = [lbl for lbl in all_owasp_ids if lbl not in evaluated_llm]

    # 1) 桶级（OWASP 分类）聚合 Score —— 供框架级风险聚合
    for framework_key, framework_label in (
        ("owasp_llm", "OWASP LLM Top 10 (2025)"),
        ("owasp_agentic", "OWASP Agentic Top 10 (2026)"),
    ):
        buckets = analysis.get(framework_key, {})
        for label, v in buckets.items():
            owasp_id = label.split("_")[0].lower()  # LLM01 / ASI06
            asr = v.get("worst_asr", 0.0)
            # score_metadata 仅允许标量值（PyRIT 约束），复杂结构不入此
            meta = {
                "framework_label": framework_label,
                "owasp_label": label,
                "defcon": v.get("defcon"),
                "probe_count": v.get("probe_count", 0),
                "evaluated": v.get("evaluated", 0),
                "null_rate": v.get("null_rate", 0.0),
                "effective_coverage": v.get("effective_coverage", 0.0),
            }
            scores.append({
                "score_value": _asr_to_score_value(asr),
                "score_value_description": f"{framework_label} {label} 最差攻击成功率 {asr}%",
                "score_type": _asr_to_score_type(asr),
                "score_category": [owasp_id, framework_key],
                "score_rationale": (
                    f"覆盖 {v.get('probe_count', 0)} 探针，评估 {v.get('evaluated', 0)} 条，"
                    f"最差 ASR {asr}%，DEFCON {v.get('defcon', '-')}"
                ),
                "score_metadata": meta,
                "scorer_class_identifier": {
                    "__type__": "garak_pipeline.owasp_scorer",
                    "run_id": run_id,
                },
                "message_piece_id": _stable_uuid(run_id, framework_key, label),
                "timestamp": ts,
                "objective": None,
            })

    # 2) 探针级 Score —— 供个体攻击复现/关联
    for probe, v in analysis.get("probe_results", {}).items():
        asr = v.get("asr", 0.0)
        # 复杂结构序列化为字符串存入 metadata（PyRIT 仅接受标量值）
        meta = {
            "defcon": v.get("defcon"),
            "detectors": json.dumps(v.get("detectors", {}), ensure_ascii=False),
            "null_rate": v.get("null_rate", 0.0),
            "effective_coverage": v.get("effective_coverage", 0.0),
        }
        ci = v.get("ci")
        if ci is not None:
            meta["confidence_interval"] = json.dumps(ci)
        scores.append({
            "score_value": _asr_to_score_value(asr),
            "score_value_description": f"probe {probe} ASR {asr}%",
            "score_type": _asr_to_score_type(asr),
            "score_category": ["probe", probe],
            "score_rationale": f"探针 {probe} 最差检测器 ASR {asr}%，DEFCON {v.get('defcon')}",
            "score_metadata": meta,
            "scorer_class_identifier": {
                "__type__": "garak_pipeline.probe_scorer",
                "run_id": run_id,
            },
            "message_piece_id": _stable_uuid(run_id, "probe", probe),
            "timestamp": ts,
            "objective": None,
        })

    # 人类可读 + 透明信息视图（不与 Score 数组混用，结构清晰）
    air = {
        "schema": "garak-pipeline/owasp-assessment/v1",
        "pyrit_score_schema": _PYRIT_SCHEMA,
        "run_id": run_id,
        "garak_run_id": analysis.get("garak_run_id"),
        "generated_by": "garak-pipeline",
        "consumption_note": (
            "下游 PyRIT 消费: scores[] 中每条均为合法 pyrit.score.scorer.Score dict，"
            "可用 Score.model_validate(item) 逐条加载做聚合/可视化。"
        ),
        "attack_surface": {
            "owasp_llm": analysis.get("owasp_llm", {}),
            "owasp_agentic": analysis.get("owasp_agentic", {}),
        },
        # 覆盖缺口：声明未被 garak 探针覆盖的 OWASP 类（N/A，非评估通过）
        "coverage_gaps": coverage_gaps,
        # 数据可靠性：nones 占比过高时标注评估不可靠（对齐 garak 0.15.1 官方行为）
        "data_reliability": analysis.get("data_quality", {}),
        "modality_filter": analysis.get("modality_filter"),
        "scores": scores,
    }

    out_dir = Path(artifacts_dir) / "05_export"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"pyrit_air_{run_id}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(air, f, ensure_ascii=False, indent=2)
    return str(out_path)
