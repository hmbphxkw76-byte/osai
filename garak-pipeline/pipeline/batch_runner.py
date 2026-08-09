"""多目标批量扫描 — 一次扫描多个 LLM 目标并汇总

对齐 L5 专家水平：企业红队常需对比多个模型的安全态势，单目标扫描效率低。
本模块读取 config/target_list.yaml，对每个目标独立运行完整流水线，
最终产出汇总报告（对比各目标的 DEFCON/ASR/覆盖率）。

用法:
    python main.py --batch config/target_list.yaml
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


def run_batch(
    config_path: str,
    project_root: str = ".",
) -> dict:
    """对 target_list.yaml 中所有目标运行完整流水线并汇总

    :param config_path: config/target_list.yaml 路径
    :param project_root: 项目根目录
    :returns: 汇总结果 dict（含每个目标的 DEFCON/ASR/覆盖率对比）
    """
    with open(config_path, encoding="utf-8") as f:
        batch_cfg = yaml.safe_load(f)

    targets = batch_cfg.get("targets", [])
    shared = batch_cfg.get("shared_config", {})

    if not targets:
        raise ValueError("target_list.yaml 中未配置任何目标")

    from pipeline.env import get_env
    from pipeline.runner import PipelineRunner

    project = Path(project_root)
    results: list[dict] = []

    for i, tgt in enumerate(targets, 1):
        name = tgt.get("name", f"target_{i}")
        print(f"\n{'='*60}")
        print(f"📦 批量扫描 [{i}/{len(targets)}]: {name}")
        print(f"{'='*60}")

        # 从 .env 回填留空字段
        target = {
            "kind": tgt.get("kind", "openai"),
            "endpoint": tgt.get("endpoint") or get_env("OPENAI_TARGET_ENDPOINT", ""),
            "model": tgt.get("model") or get_env("OPENAI_TARGET_MODEL", ""),
            "api_key": tgt.get("api_key") or get_env("OPENAICompatible_API_KEY", ""),
        }

        # 每个目标独立 artifacts 子目录
        artifacts_dir = str(project / shared.get("artifacts_dir", "outputs") / name)
        run_id = f"{name}_{time.strftime('%Y%m%d_%H%M')}"

        config = dict(shared)
        config["target"] = target

        try:
            runner = PipelineRunner(
                target=target,
                mode=shared.get("mode", "standard"),
                artifacts_dir=artifacts_dir,
                config=config,
                run_id=run_id,
            )
            runner.run(stages="all")

            # 读取该目标的分析结果
            analysis_path = Path(artifacts_dir) / "04_analysis" / f"analysis_{run_id}.json"
            if analysis_path.exists():
                with open(analysis_path, encoding="utf-8") as f:
                    analysis = json.load(f)
                overall = analysis.get("overall", {})
                results.append({
                    "name": name,
                    "model": target["model"],
                    "endpoint": target["endpoint"],
                    "run_id": run_id,
                    "defcon": overall.get("defcon"),
                    "worst_asr": overall.get("worst_asr", 0),
                    "probes_evaluated": overall.get("probes_evaluated", 0),
                    "probes_total": overall.get("probes_total", 0),
                    "judge_asr": overall.get("judge_asr"),
                    "reliability": analysis.get("data_quality", {}).get("reliability"),
                    "repro_hash": analysis.get("repro_hash"),
                    "analysis_path": str(analysis_path),
                    "status": "success",
                })
            else:
                results.append({
                    "name": name, "model": target["model"], "run_id": run_id,
                    "status": "no_analysis", "error": "分析产物未生成",
                })
        except Exception as exc:
            logger.exception("目标 %s 扫描失败", name)
            results.append({
                "name": name, "model": target.get("model", ""),
                "status": "failed", "error": str(exc),
            })

    # 汇总报告
    summary = {
        "batch_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_targets": len(targets),
        "succeeded": sum(1 for r in results if r["status"] == "success"),
        "failed": sum(1 for r in results if r["status"] == "failed"),
        "targets": results,
        # 按最差 ASR 排序的风险排行
        "risk_ranking": sorted(
            [r for r in results if r["status"] == "success"],
            key=lambda x: x.get("worst_asr", 0),
            reverse=True,
        ),
    }

    # S2.5: 利用 garak 原生 aggregate_reports 聚合多目标报告
    # 对齐 L5：garak 原生 aggregate_reports 可将多个 .report.jsonl 合并为一个，
    # 并自动重建 digest。对同模型多轮扫描的批量聚合尤其有用。
    try:
        garak_reports = []
        for r in results:
            if r["status"] == "success":
                analysis_path = r.get("analysis_path")
                if analysis_path:
                    with open(analysis_path, encoding="utf-8") as f:
                        analysis = json.load(f)
                    report_path = analysis.get("report_path")
                    if report_path and Path(report_path).exists():
                        garak_reports.append(report_path)

        if len(garak_reports) > 1:
            from garak.analyze.aggregate_reports import main as aggregate_main

            aggregated_path = str(
                project / shared.get("artifacts_dir", "outputs")
                / f"aggregated_report_{time.strftime('%Y%m%d_%H%M')}.jsonl"
            )
            # garak aggregate_reports.main 接受 argv: [-o output, file1, file2, ...]
            aggregate_main(["-o", aggregated_path, *garak_reports])
            summary["aggregated_report"] = aggregated_path
            logger.info("garak 原生 aggregate_reports 完成: %s", aggregated_path)
    except Exception as exc:
        logger.debug("garak aggregate_reports 跳过: %s", exc)

    out_dir = project / shared.get("artifacts_dir", "outputs")
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / f"batch_summary_{time.strftime('%Y%m%d_%H%M')}.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"\n{'='*60}")
    print(f"📊 批量扫描汇总: {summary['succeeded']}/{summary['total_targets']} 成功")
    print(f"   汇总报告: {summary_path}")
    print(f"{'='*60}")

    # 打印风险排行
    if summary["risk_ranking"]:
        print("\n风险排行（按最差 ASR 降序）:")
        for i, r in enumerate(summary["risk_ranking"], 1):
            defcon = r.get("defcon", "N/A")
            print(f"   {i}. {r['name']} ({r['model']}): "
                  f"DEFCON {defcon}, ASR {r.get('worst_asr', 0)}%")

    # R4: 多目标对比可视化 — 生成 batch HTML 雷达图
    try:
        html_path = _generate_batch_comparison_html(summary, str(out_dir))
        if html_path:
            summary["comparison_html_path"] = html_path
            print(f"   对比报告: {html_path}")
    except Exception as exc:
        logger.debug("R4 batch 对比可视化跳过: %s", exc)

    return summary


def _generate_batch_comparison_html(summary: dict, out_dir: str) -> str | None:
    """R4: 生成多目标对比 HTML 报告（Chart.js 雷达图 + 风险排行表）

    :param summary: batch 汇总 dict
    :param out_dir: 输出目录
    :returns: HTML 文件路径
    """
    targets = summary.get("risk_ranking", [])
    if len(targets) < 2:
        return None

    import html as html_mod

    # 收集所有目标名称和 OWASP 维度
    all_dimensions = set()
    target_data = []
    for t in targets:
        name = f"{t['name']} ({t.get('model', '?')})"
        owasp = t.get("owasp_coverage", {})
        dims = {}
        for cat, probes in owasp.items():
            if isinstance(probes, list) and probes:
                # ASR per category — 使用 worst_asr 作为代理
                dims[cat] = t.get("worst_asr", 0)
                all_dimensions.add(cat)
        if not dims:
            # 如果没有 OWASP 数据，至少填入 worst_asr 作为总维度
            dims["Overall"] = t.get("worst_asr", 0)
            all_dimensions.add("Overall")
        target_data.append({"name": name, "dims": dims, "defcon": t.get("defcon", "N/A"), "worst_asr": t.get("worst_asr", 0)})

    dimensions = sorted(all_dimensions)

    # 构建 Chart.js datasets
    datasets_js = []
    colors = [
        "rgba(255, 99, 132, 0.4)",   # 红
        "rgba(54, 162, 235, 0.4)",   # 蓝
        "rgba(255, 206, 86, 0.4)",   # 黄
        "rgba(75, 192, 192, 0.4)",   # 绿
        "rgba(153, 102, 255, 0.4)",  # 紫
        "rgba(255, 159, 64, 0.4)",   # 橙
    ]
    border_colors = [
        "rgba(255, 99, 132, 1)",
        "rgba(54, 162, 235, 1)",
        "rgba(255, 206, 86, 1)",
        "rgba(75, 192, 192, 1)",
        "rgba(153, 102, 255, 1)",
        "rgba(255, 159, 64, 1)",
    ]
    for i, td in enumerate(target_data):
        data = [td["dims"].get(dim, 0) for dim in dimensions]
        datasets_js.append(
            f'{{label:{json.dumps(td["name"])},data:{json.dumps(data)},'
            f'borderColor:"{border_colors[i % len(border_colors)]}",'
            f'backgroundColor:"{colors[i % len(colors)]}",'
            f'borderWidth:2,pointRadius:4}}'
        )

    # 风险排行表
    table_rows = ""
    for i, td in enumerate(target_data, 1):
        defcon_class = f"defcon-{td['defcon']}" if isinstance(td["defcon"], int) else ""
        table_rows += (
            f'<tr class="{defcon_class}">'
            f"<td>{i}</td>"
            f"<td>{html_mod.escape(td['name'])}</td>"
            f'<td class="defcon-badge">{td["defcon"]}</td>'
            f'<td>{td["worst_asr"]}%</td>'
            f"</tr>"
        )

    html_content = f"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>多目标安全对比报告</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f0f2f5; color: #333; padding: 20px; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{ text-align: center; color: #1a1a2e; margin-bottom: 8px; }}
.subtitle {{ text-align: center; color: #666; margin-bottom: 24px; font-size: 14px; }}
.card {{ background: #fff; border-radius: 12px; padding: 24px; margin-bottom: 24px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
.card h2 {{ font-size: 18px; margin-bottom: 16px; color: #1a1a2e; border-bottom: 2px solid #e8e8e8; padding-bottom: 8px; }}
.chart-container {{ position: relative; height: 500px; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #e8e8e8; }}
th {{ background: #f5f5f5; font-weight: 600; font-size: 13px; }}
.defcon-1 {{ background: #ffcdd2; }}
.defcon-2 {{ background: #fff9c4; }}
.defcon-3 {{ background: #c8e6c9; }}
.defcon-4 {{ background: #bbdefb; }}
.defcon-5 {{ background: #e1f5fe; }}
.defcon-badge {{ font-weight: 700; text-align: center; }}
.summary-stats {{ display: flex; gap: 16px; margin-bottom: 24px; }}
.stat {{ flex: 1; background: #fff; border-radius: 12px; padding: 16px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
.stat-value {{ font-size: 28px; font-weight: 700; color: #1a1a2e; }}
.stat-label {{ font-size: 12px; color: #666; margin-top: 4px; }}
</style>
</head>
<body>
<div class="container">
<h1>📊 多目标安全对比报告</h1>
<p class="subtitle">生成时间: {summary.get("batch_timestamp", "N/A")} | 目标数: {summary.get("total_targets", 0)}</p>
<div class="summary-stats">
<div class="stat"><div class="stat-value">{summary.get("succeeded", 0)}</div><div class="stat-label">成功</div></div>
<div class="stat"><div class="stat-value">{summary.get("failed", 0)}</div><div class="stat-label">失败</div></div>
<div class="stat"><div class="stat-value">{len(target_data)}</div><div class="stat-label">已对比</div></div>
</div>
<div class="card">
<h2>DEFCON 雷达图对比</h2>
<div class="chart-container"><canvas id="radarChart"></canvas></div>
</div>
<div class="card">
<h2>风险排行</h2>
<table><thead><tr><th>#</th><th>目标</th><th>DEFCON</th><th>最差 ASR</th></tr></thead><tbody>{table_rows}</tbody></table>
</div>
</div>
<script>
const ctx = document.getElementById('radarChart');
if (ctx) {{
  new Chart(ctx, {{
    type: 'radar',
    data: {{ labels: {json.dumps(dimensions)}, datasets: [{', '.join(datasets_js)}] }},
    options: {{
      responsive: true, maintainAspectRatio: false,
      scales: {{ r: {{ beginAtZero: true, max: 100, ticks: {{ stepSize: 20 }},
        grid: {{ color: '#e0e0e0' }}, pointLabels: {{ font: {{ size: 11 }} }} }} }},
      plugins: {{ legend: {{ position: 'bottom' }} }}
    }}
  }});
}}
</script>
</body>
</html>"""

    html_path = Path(out_dir) / f"batch_comparison_{time.strftime('%Y%m%d_%H%M')}.html"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    logger.info("R4 batch 对比 HTML 已生成: %s", html_path)
    return str(html_path)
