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
        print("  → 目标可能不可达或模型响应异常，ASR/DEFCON 评分不代表目标安全性。")
        print("  → 请检查目标连通性与模型可用性后重新评估。")
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
        # ATLAS TTP 映射（对齐 L5：多框架标注）
        atlas_ttps = v.get("atlas_ttps", [])
        if atlas_ttps:
            meta["atlas_ttps"] = json.dumps(
                [t["id"] for t in atlas_ttps], ensure_ascii=False
            )
        # 探针元数据（对齐 L5：tier + tags 供下游分类聚合）
        if v.get("probe_tier") is not None:
            meta["probe_tier"] = v["probe_tier"]
        if v.get("probe_tags"):
            meta["probe_tags"] = json.dumps(v["probe_tags"], ensure_ascii=False)
        # garak 官方校准评分（对齐 L5：行业基准标定视角）
        cal = v.get("detectors_calibrated", {})
        if cal:
            rel_defcons = [d.get("relative_defcon") for d in cal.values() if d.get("relative_defcon") is not None]
            if rel_defcons:
                meta["relative_defcon"] = min(rel_defcons)
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
        "target_model": analysis.get("target_model"),
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


def export_html(analysis: dict, artifacts_dir: str, run_id: str) -> str:
    """生成 HTML 可视化报告（DEFCON 雷达图 + ASR 条形图 + 探针明细表）

    对齐 L5 专家水平：输出人类可读的可视化格式供非技术决策者快速理解风险态势。

    :param analysis: Stage4 分析结果
    :param artifacts_dir: 产物根目录
    :param run_id: 运行标识
    :returns: HTML 报告路径
    """
    from pipeline.report_html import export_html_report

    return export_html_report(analysis, run_id, artifacts_dir)


def export_avid(analysis: dict, artifacts_dir: str, run_id: str, report_path: str | None = None) -> str | None:
    """S2.4: 导出 garak 原生 AVID 格式

    对齐 L5：复用 garak.report.Report 类的原生 AVID 导出能力，
    将 garak 原生 JSONL 报告转换为 AVID (AI Vulnerability Database) 格式。
    AVID 是 AI 安全领域的标准化漏洞报告格式，供下游 AVID 数据库消费。

    :param analysis: Stage4 分析结果（用于定位 garak 报告路径）
    :param artifacts_dir: 产物根目录
    :param run_id: 运行标识
    :param report_path: garak 报告路径（若提供则直接使用，否则从 analysis 推导）
    :returns: AVID 导出文件路径；失败则 None
    """
    # 定位 garak 原生报告
    garak_report = report_path or analysis.get("report_path", "")
    if not garak_report:
        return None

    # shutil 和 Path 已在模块级导入，不再在 try 块内重复导入
    # （避免 try 失败时 except 块中的 Path 成为 UnboundLocalError）
    import shutil

    try:
        from garak.report import Report

        report = Report(report_location=garak_report)
        report.load()
        report.get_evaluations()
        report.export()

        avid_path = garak_report.replace(".report.", ".avid.")
        if not avid_path.endswith(".jsonl"):
            avid_path = avid_path.replace(".jsonl", ".jsonl")

        # 移动 AVID 文件到 05_export 目录
        avid_p = Path(avid_path)
        if avid_p.exists():
            out_dir = Path(artifacts_dir) / "05_export"
            out_dir.mkdir(parents=True, exist_ok=True)
            dest = out_dir / f"avid_{run_id}.jsonl"
            shutil.move(str(avid_p), str(dest))
            return str(dest)
        return avid_path if avid_p.exists() else None
    except Exception as exc:
        import logging
        from garak.exception import ReportIncompatibleError
        logger = logging.getLogger(__name__)
        if isinstance(exc, ReportIncompatibleError):
            logger.warning(
                "AVID 导出失败: garak 报告格式不兼容 (%s)。"
                "可能原因: 报告由不同 garak 版本生成、缺少 probe_tags 字段。"
                "建议: 确保 garak 版本一致后重新生成报告。", exc
            )
        else:
            logger.warning("AVID 导出失败: %s", exc)

        # P3-3: AVID 导出 fallback — 生成简化版 AVID JSON
        try:
            out_dir = Path(artifacts_dir) / "05_export"
            out_dir.mkdir(parents=True, exist_ok=True)
            fallback_path = out_dir / f"avid_{run_id}.json"
            avid_fallback = {
                "avid_id": f"garak-pipeline/{run_id}",
                "summary": {
                    "target_model": analysis.get("target_model", "unknown"),
                    "overall_defcon": analysis.get("overall", {}).get("defcon", 5),
                    "worst_asr": analysis.get("overall", {}).get("worst_asr", 0),
                    "total_probes": analysis.get("overall", {}).get("total_probes", 0),
                },
                "findings": [
                    {
                        "probe": probe,
                        "asr": info.get("asr", 0),
                        "defcon": info.get("defcon", 5),
                        "defcon_confidence": info.get("defcon_confidence", "unknown"),
                        "owasp_llm": info.get("owasp_llm"),
                        "owasp_agentic": info.get("owasp_agentic"),
                    }
                    for probe, info in analysis.get("probe_results", {}).items()
                    if info.get("asr", 0) > 0
                ],
                "note": "Simplified AVID fallback (garak native export failed)",
            }
            with open(fallback_path, "w", encoding="utf-8") as f:
                json.dump(avid_fallback, f, ensure_ascii=False, indent=2)
            logger.info("AVID fallback 导出完成: %s", fallback_path)
            return str(fallback_path)
        except Exception as fallback_exc:
            logger.warning("AVID fallback 导出也失败: %s", fallback_exc)
            return None


def export_sarif(analysis: dict, artifacts_dir: str, run_id: str) -> str:
    """P1-2: 导出 SARIF 2.1.0 格式报告

    对齐 L5：SARIF (Static Analysis Results Interchange Format) 是安全扫描工具的
    行业标准输出格式，GitHub Code Scanning / Azure DevOps 均原生消费。
    本函数将 OWASP 双框架评估结果转为 SARIF 2.1.0 JSON。

    :param analysis: Stage4 分析结果
    :param artifacts_dir: 产物根目录
    :param run_id: 运行标识
    :returns: SARIF JSON 文件路径
    """
    target_model = analysis.get("target_model", "unknown")
    results: list[dict] = []

    # 合并 LLM + Agentic 桶
    for framework_key, framework_label in (
        ("owasp_llm", "OWASP_LLM"),
        ("owasp_agentic", "OWASP_Agentic"),
    ):
        buckets = analysis.get(framework_key, {})
        for label, v in buckets.items():
            defcon = v.get("defcon", 5)
            asr = v.get("worst_asr", 0.0)
            level = "error" if defcon <= 2 else "warning" if defcon <= 3 else "note"
            results.append({
                "ruleId": f"{framework_label}/{label}",
                "level": level,
                "message": {
                    "text": (
                        f"{label}: ASR {asr}%, DEFCON {defcon}, "
                        f"覆盖 {v.get('probe_count', 0)} 探针，"
                        f"评估 {v.get('evaluated', 0)} 条"
                    )
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f"model:{target_model}"}
                    }
                }],
                "properties": {
                    "owasp_category": label,
                    "framework": framework_label,
                    "asr": asr,
                    "defcon": defcon,
                    "reliability": v.get("reliability", "normal"),
                    "null_rate": v.get("null_rate", 0.0),
                    "effective_coverage": v.get("effective_coverage", 0.0),
                },
            })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "garak-pipeline",
                    "version": "2.0.0",
                    "informationUri": "https://github.com/NVIDIA/garak",
                    "rules": [
                        {
                            "id": f"{framework}/{label}",
                            "name": label,
                            "shortDescription": {"text": f"{label} vulnerability assessment"},
                        }
                        for framework, buckets in (
                            ("OWASP_LLM", analysis.get("owasp_llm", {})),
                            ("OWASP_Agentic", analysis.get("owasp_agentic", {})),
                        )
                        for label in buckets
                    ],
                }
            },
            "results": results,
        }],
    }

    out_dir = Path(artifacts_dir) / "05_export"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"sarif_{run_id}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, ensure_ascii=False, indent=2)
    return str(out_path)


def export_pyrit_with_conversations(
    analysis: dict, artifacts_dir: str, run_id: str,
) -> str | None:
    """P3-1: 导出 PyRIT 对话上下文（prompt → response → judge verdict）

    对齐 L5：PyRIT 的 Conversation 模型支持完整攻击对话链，
    下游红队可能需要复现攻击过程而非仅看 Score。
    本函数从 hitlog JSONL 提取命中明细，构建对话记录。

    :returns: 对话上下文 JSON 路径；无 hitlog 则 None
    """
    hitlog = analysis.get("hitlog", {})
    jsonl_path = hitlog.get("jsonl_path")
    if not jsonl_path or not Path(jsonl_path).exists():
        return None

    # C-6: 加载 judge 二次判定结果（如存在），附加到每条对话
    judge_verdicts_by_probe: dict[str, list[dict]] = {}
    judge_path = None
    # 从 analysis 或标准路径推导 judge_results 路径
    exec_dir = Path(artifacts_dir) / "03_execution"
    judge_candidate = exec_dir / f"judge_results_{run_id}.jsonl"
    if judge_candidate.exists():
        judge_path = str(judge_candidate)
    if judge_path:
        try:
            with open(judge_path, encoding="utf-8") as jf:
                for jline in jf:
                    jline = jline.strip()
                    if not jline:
                        continue
                    try:
                        jrec = json.loads(jline)
                    except json.JSONDecodeError:
                        continue
                    probe = jrec.get("probe", "unknown")
                    judge_verdicts_by_probe.setdefault(probe, []).append({
                        "jailbroken": jrec.get("jailbroken", False),
                        "confidence": jrec.get("confidence", 0.0),
                        "reason": jrec.get("reason", ""),
                    })
        except Exception:
            pass

    conversations: list[dict] = []
    with open(jsonl_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                hit = json.loads(line)
            except json.JSONDecodeError:
                continue
            probe_name = hit.get("probe", "unknown")
            conv = {
                "conversation_id": _stable_uuid(run_id, probe_name, str(len(conversations))),
                "run_id": run_id,
                "probe": probe_name,
                "goal": hit.get("goal", ""),
                "messages": [
                    {"role": "user", "content": hit.get("prompt", ""), "sequence": 0},
                    {"role": "assistant", "content": hit.get("output", ""), "sequence": 1},
                ],
                "detectors": hit.get("triggered_detectors", []),
                "tags": hit.get("tags", []),
            }
            # C-6: 附加 judge verdicts（按 probe 匹配，按序号对应）
            probe_verdicts = judge_verdicts_by_probe.get(probe_name, [])
            if probe_verdicts:
                idx = len([c for c in conversations if c["probe"] == probe_name])
                if idx < len(probe_verdicts):
                    conv["judge_verdict"] = probe_verdicts[idx]
            conversations.append(conv)

    if not conversations:
        return None

    out_dir = Path(artifacts_dir) / "05_export"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"pyrit_conversations_{run_id}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({
            "schema": "garak-pipeline/conversations/v1",
            "run_id": run_id,
            "target_model": analysis.get("target_model"),
            "conversations": conversations,
        }, f, ensure_ascii=False, indent=2)
    return str(out_path)


def export_pdf(analysis: dict, artifacts_dir: str, run_id: str) -> str | None:
    """S3.5: PDF 导出 — 将 HTML 报告转为 PDF

    对齐 L5：顶级红队报告需提供 PDF 格式供正式交付与归档。
    使用 weasyprint 或 playwright 将 HTML 报告转为 PDF。

    :param analysis: Stage4 分析结果
    :param artifacts_dir: 产物根目录
    :param run_id: 运行标识
    :returns: PDF 文件路径；依赖不可用则 None
    """
    import logging
    from pathlib import Path

    logger = logging.getLogger(__name__)

    # 先生成 HTML
    html_path = export_html(analysis, artifacts_dir, run_id)
    if not html_path or not Path(html_path).exists():
        logger.warning("PDF 导出：HTML 报告未生成，跳过")
        return None

    out_dir = Path(artifacts_dir) / "05_export"
    out_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = out_dir / f"report_{run_id}.pdf"

    # 优先尝试 weasyprint（纯 Python，无浏览器依赖）
    try:
        from weasyprint import HTML

        HTML(filename=html_path).write_pdf(str(pdf_path))
        logger.info("PDF 导出完成（weasyprint）: %s", pdf_path)
        return str(pdf_path)
    except ImportError:
        logger.debug("weasyprint 不可用，尝试 playwright")
    except Exception as exc:
        logger.debug("weasyprint PDF 导出失败: %s", exc)

    # 备选：playwright（需安装浏览器）
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(f"file://{Path(html_path).resolve()}")
            page.pdf(path=str(pdf_path), format="A4")
            browser.close()
        logger.info("PDF 导出完成（playwright）: %s", pdf_path)
        return str(pdf_path)
    except ImportError:
        logger.warning("PDF 导出：weasyprint 和 playwright 均不可用，跳过 PDF 生成")
        return None
    except Exception as exc:
        logger.warning("PDF 导出失败: %s", exc)
        return None


def generate_full_report(
    analysis: dict,
    artifacts_dir: str,
    run_id: str,
    all_owasp_ids: list[str] | None = None,
) -> dict:
    """生成完整报告套件（终端卡片 + PyRIT JSON + HTML 可视化 + AVID + PDF）

    L5 一站式入口：调用方只需此函数即可产出全部报告格式。

    :returns: {"cards": None, "pyrit_air": path, "html": path, "avid": path|None, "pdf": path|None}
    """
    render_final_cards(analysis, all_owasp_ids)
    pyrit_path = export_pyrit_air(analysis, artifacts_dir, run_id, all_owasp_ids)
    html_path = export_html(analysis, artifacts_dir, run_id)
    # S2.4: 导出 garak 原生 AVID 格式
    avid_path = export_avid(analysis, artifacts_dir, run_id)
    # S3.5: PDF 导出
    pdf_path = export_pdf(analysis, artifacts_dir, run_id)
    # P1-2: SARIF 导出（供 GitHub Code Scanning / Azure DevOps 消费）
    sarif_path = export_sarif(analysis, artifacts_dir, run_id)
    # P3-1: PyRIT 对话上下文导出
    conv_path = export_pyrit_with_conversations(analysis, artifacts_dir, run_id)
    return {
        "cards": None,
        "pyrit_air": pyrit_path,
        "html": html_path,
        "avid": avid_path,
        "pdf": pdf_path,
        "sarif": sarif_path,
        "conversations": conv_path,
    }
