"""HTML 可视化报告 — DEFCON 雷达图 + ASR 趋势 + 框架覆盖矩阵

对齐 L5 专家水平：顶级红队报告需输出人类可读的可视化格式（HTML/PDF），
供非技术决策者快速理解风险态势。JSON 仍作为机器消费格式保留。

输出:
    outputs/05_export/report_{run_id}.html — 含 Chart.js DEFCON 雷达图 +
    按探针 ASR 排序条形图 + OWASP/Agentic 框架覆盖矩阵 + ATLAS 战术视图 +
    命中明细表 + 校准评分（relative_score）+ 覆盖缺口透明声明

依赖: 无外部依赖（Chart.js 通过 CDN 引入，离线时降级为表格）
"""

from __future__ import annotations

import html
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


def _load_hitlog_details(jsonl_path: str | None) -> list[dict]:
    """加载 hitlog JSONL 命中明细（供 HTML 表格展示）

    :param jsonl_path: hitlog JSONL 路径
    :returns: 命中记录列表，每项含 probe/goal/prompt/output/triggered_detectors
    """
    if not jsonl_path:
        return []
    p = Path(jsonl_path)
    if not p.exists():
        return []
    hits: list[dict] = []
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                hits.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return hits


def _aggregate_atlas_ttps(probe_results: dict) -> dict[str, list[dict]]:
    """聚合所有探针的 ATLAS TTP 映射（按 TTP ID 分组）

    :returns: {ttp_id: [{"probe": str, "name": str}, ...]}
    """
    atlas_map: dict[str, list[dict]] = {}
    for probe, info in probe_results.items():
        for ttp in info.get("atlas_ttps", []):
            ttp_id = ttp.get("id", "")
            if ttp_id not in atlas_map:
                atlas_map[ttp_id] = []
            atlas_map[ttp_id].append({
                "probe": probe,
                "name": ttp.get("name", "Unknown"),
            })
    return dict(sorted(atlas_map.items()))


def export_html_report(
    analysis: dict,
    run_id: str,
    artifacts_dir: str,
) -> str:
    """生成 HTML 可视化报告（L5 专家水平）

    :param analysis: stage4 analyze() 返回的完整结果 dict
    :param run_id: 运行标识
    :param artifacts_dir: 产物根目录
    :returns: HTML 报告路径
    """
    out_dir = Path(artifacts_dir) / "05_export"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"report_{run_id}.html"

    probe_results = analysis.get("probe_results", {})
    overall = analysis.get("overall", {})
    owasp_llm = analysis.get("owasp_llm", {})
    owasp_agentic = analysis.get("owasp_agentic", {})
    data_quality = analysis.get("data_quality", {})
    hitlog = analysis.get("hitlog", {})

    # 探针 ASR 排序（降序，取前 30）
    sorted_probes = sorted(
        probe_results.items(),
        key=lambda x: x[1].get("asr", 0),
        reverse=True,
    )[:30]

    # DEFCON 颜色映射
    defcon_colors = {
        1: "#d32f2f",  # 红 — 严重
        2: "#f57c00",  # 橙 — 高危
        3: "#fbc02d",  # 黄 — 中危
        4: "#7cb342",  # 浅绿 — 低危
        5: "#388e3c",  # 绿 — 安全
    }

    # 雷达图数据（OWASP LLM 各桶 DEFCON → 风险分）
    radar_labels = list(owasp_llm.keys()) or ["LLM01", "LLM02", "LLM04", "LLM05",
                                                "LLM06", "LLM09", "LLM10"]
    radar_data = [6 - owasp_llm.get(k, {}).get("defcon", 5) for k in radar_labels]

    # ASR 条形图数据
    bar_labels = [p[0].split(".")[-1] for p in sorted_probes]
    bar_data = [p[1].get("asr", 0) for p in sorted_probes]

    # 命中明细
    hit_count = hitlog.get("hit_count", 0)
    hit_details = _load_hitlog_details(hitlog.get("jsonl_path"))

    # ATLAS TTP 聚合
    atlas_aggregated = _aggregate_atlas_ttps(probe_results)

    # OWASP 完整覆盖列表（从 recon_garak 获取期望全量）
    try:
        from .recon_garak import OWASP_CATEGORIES
        all_owasp_ids = list(OWASP_CATEGORIES.values())
    except Exception:
        all_owasp_ids = []
    evaluated_llm = set(owasp_llm.keys())
    coverage_gaps = [lbl for lbl in all_owasp_ids if lbl not in evaluated_llm] if all_owasp_ids else []

    # 目标模型（从 analysis 中提取）
    target_model = analysis.get("target_model", "—")

    html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>garak 红队报告 — {html.escape(run_id)}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          margin: 0; padding: 20px; background: #f5f5f5; color: #333; }}
  .container {{ max-width: 1200px; margin: 0 auto; background: white;
                padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
  h1 {{ color: #1a237e; border-bottom: 3px solid #1a237e; padding-bottom: 10px; }}
  h2 {{ color: #283593; margin-top: 30px; border-bottom: 1px solid #e0e0e0; padding-bottom: 5px; }}
  h3 {{ color: #3949ab; margin-top: 20px; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                   gap: 15px; margin: 20px 0; }}
  .summary-card {{ background: #f8f9fa; padding: 15px; border-radius: 6px;
                   border-left: 4px solid #1a237e; }}
  .summary-card .label {{ font-size: 12px; color: #666; text-transform: uppercase; }}
  .summary-card .value {{ font-size: 24px; font-weight: bold; color: #1a237e; }}
  .defcon-badge {{ display: inline-block; padding: 4px 12px; border-radius: 12px;
                   color: white; font-weight: bold; font-size: 14px; }}
  .chart-container {{ position: relative; height: 400px; margin: 20px 0; }}
  table {{ width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 13px; }}
  th, td {{ padding: 8px 10px; text-align: left; border-bottom: 1px solid #e0e0e0; }}
  th {{ background: #e8eaf6; color: #1a237e; position: sticky; top: 0; }}
  tr:hover {{ background: #f5f5f5; }}
  .warning {{ background: #fff3e0; border-left: 4px solid #ff9800; padding: 12px;
              margin: 15px 0; border-radius: 4px; }}
  .danger {{ background: #ffebee; border-left: 4px solid #f44336; padding: 12px;
             margin: 15px 0; border-radius: 4px; }}
  .info {{ background: #e3f2fd; border-left: 4px solid #2196f3; padding: 12px;
           margin: 15px 0; border-radius: 4px; }}
  .tag {{ display: inline-block; background: #e0e0e0; padding: 2px 8px; border-radius: 10px;
          font-size: 11px; margin: 1px; }}
  .tag-owasp {{ background: #ffcdd2; color: #b71c1c; }}
  .tag-avid {{ background: #c8e6c9; color: #1b5e20; }}
  .tag-payload {{ background: #fff9c4; color: #f57f17; }}
  .code-cell {{ font-family: monospace; font-size: 12px; max-width: 300px;
                overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .prompt-cell {{ font-family: monospace; font-size: 11px; max-width: 250px;
                  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
                  color: #666; }}
  footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #e0e0e0;
            font-size: 12px; color: #999; text-align: center; }}
  .collapsible {{ cursor: pointer; padding: 10px; background: #e8eaf6; border: none;
                  text-align: left; font-size: 14px; color: #1a237e; width: 100%;
                  border-radius: 4px; margin: 5px 0; }}
  .collapsible-content {{ display: none; padding: 10px; border: 1px solid #e0e0e0;
                          border-top: none; max-height: 400px; overflow-y: auto; }}
  .collapsible-content.active {{ display: block; }}
  /* R8: i18n 语言切换 */
  .lang-toggle {{ position: absolute; top: 20px; right: 30px; background: #1a237e; color: white;
                  border: none; padding: 6px 14px; border-radius: 4px; cursor: pointer; font-size: 13px; }}
  .lang-toggle:hover {{ background: #3949ab; }}
</style>
<script>
// R8: i18n — 中英文翻译字典
const I18N = {{
  "zh": {{
    "title": "garak LLM 红队扫描报告",
    "run_batch": "运行批次",
    "gen_time": "生成时间",
    "garak_ver": "garak 版本",
    "target_model": "目标模型",
    "overall_defcon": "整体 DEFCON",
    "worst_asr": "最差 ASR",
    "probes_eval": "评估探针数",
    "hit_count": "命中数",
    "reliability": "数据可靠性",
    "repro_hash": "可复现哈希",
    "exec_summary": "执行摘要",
    "overall_assessment": "总体评估",
    "top_findings": "最高风险发现",
    "remediation": "立即行动建议",
    "radar_chart": "DEFCON 雷达图（OWASP LLM Top 10）",
    "bar_chart": "探针 ASR 排行",
    "owasp_matrix": "OWASP LLM Top 10 覆盖矩阵",
    "agentic_matrix": "OWASP Agentic Top 10 覆盖矩阵",
    "atlas_view": "MITRE ATLAS 战术视图",
    "hit_details": "命中明细",
    "coverage_gaps": "覆盖缺口声明",
    "probe": "探针",
    "asr": "ASR",
    "defcon": "DEFCON",
    "goal": "攻击目标",
    "prompt": "Prompt",
    "output": "输出",
    "detectors": "触发检测器",
    "category": "类别",
    "probes": "探针",
    "ttp_id": "TTP ID",
    "ttp_name": "TTP 名称",
    "confidence": "置信度",
    "back_to_top": "返回顶部",
  }},
  "en": {{
    "title": "garak LLM Red Team Report",
    "run_batch": "Run ID",
    "gen_time": "Generated",
    "garak_ver": "garak Version",
    "target_model": "Target Model",
    "overall_defcon": "Overall DEFCON",
    "worst_asr": "Worst ASR",
    "probes_eval": "Probes Evaluated",
    "hit_count": "Hits",
    "reliability": "Data Reliability",
    "repro_hash": "Reproducibility Hash",
    "exec_summary": "Executive Summary",
    "overall_assessment": "Overall Assessment",
    "top_findings": "Top Risk Findings",
    "remediation": "Immediate Actions",
    "radar_chart": "DEFCON Radar (OWASP LLM Top 10)",
    "bar_chart": "Probe ASR Ranking",
    "owasp_matrix": "OWASP LLM Top 10 Coverage Matrix",
    "agentic_matrix": "OWASP Agentic Top 10 Coverage Matrix",
    "atlas_view": "MITRE ATLAS Tactics View",
    "hit_details": "Hit Details",
    "coverage_gaps": "Coverage Gaps",
    "probe": "Probe",
    "asr": "ASR",
    "defcon": "DEFCON",
    "goal": "Attack Goal",
    "prompt": "Prompt",
    "output": "Output",
    "detectors": "Triggered Detectors",
    "category": "Category",
    "probes": "Probes",
    "ttp_id": "TTP ID",
    "ttp_name": "TTP Name",
    "confidence": "Confidence",
    "back_to_top": "Back to Top",
  }}
}};
function applyLang(lang) {{
  document.querySelectorAll('[data-i18n]').forEach(el => {{
    const key = el.getAttribute('data-i18n');
    if (I18N[lang] && I18N[lang][key]) el.textContent = I18N[lang][key];
  }});
  document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';
  localStorage.setItem('garak-report-lang', lang);
}}
function toggleLang() {{
  const cur = localStorage.getItem('garak-report-lang') || 'zh';
  applyLang(cur === 'zh' ? 'en' : 'zh');
  const btn = document.getElementById('langBtn');
  if (btn) btn.textContent = cur === 'zh' ? '中文' : 'English';
}}
</script>
</head>
<body onload="applyLang(localStorage.getItem('garak-report-lang') || 'zh')">
<div class="container">
  <button id="langBtn" class="lang-toggle" onclick="toggleLang()">English</button>
  <h1 data-i18n="title">garak LLM 红队扫描报告</h1>
  <p style="color:#666;">
     <span data-i18n="run_batch">运行批次</span>: <strong>{html.escape(run_id)}</strong> ·
     <span data-i18n="gen_time">生成时间</span>: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")} ·
     <span data-i18n="garak_ver">garak 版本</span>: {html.escape(str(analysis.get("garak_version", "unknown")))} ·
     <span data-i18n="target_model">目标模型</span>: <strong>{html.escape(str(target_model))}</strong>
  </p>

  <div class="summary-grid">
    <div class="summary-card">
      <div class="label" data-i18n="overall_defcon">整体 DEFCON</div>
      <div class="value">
        <span class="defcon-badge" style="background:{defcon_colors.get(overall.get("defcon", 5), "#999")}">
          DEFCON {overall.get("defcon", "N/A")}
        </span>
      </div>
    </div>
    <div class="summary-card">
      <div class="label" data-i18n="worst_asr">最差 ASR</div>
      <div class="value">{overall.get("worst_asr", 0)}%</div>
    </div>
    <div class="summary-card">
      <div class="label" data-i18n="probes_eval">评估探针数</div>
      <div class="value">{overall.get("probes_evaluated", 0)}/{overall.get("probes_total", 0)}</div>
    </div>
    <div class="summary-card">
      <div class="label" data-i18n="hit_count">命中数</div>
      <div class="value">{hit_count}</div>
    </div>
    <div class="summary-card">
      <div class="label" data-i18n="reliability">数据可靠性</div>
      <div class="value" style="font-size:16px;">{html.escape(data_quality.get("reliability", "unknown"))}</div>
    </div>
    <div class="summary-card">
      <div class="label" data-i18n="repro_hash">可复现哈希</div>
      <div class="value" style="font-size:14px; font-family:monospace;">{html.escape(str(analysis.get("repro_hash", "N/A")))}</div>
    </div>
  </div>
"""

    # 数据质量告警
    reliability = data_quality.get("reliability", "normal")
    if reliability in ("unreliable", "degraded"):
        css_class = "danger" if reliability == "unreliable" else "warning"
        note = data_quality.get("reliability_note", "")
        html_content += f'  <div class="{css_class}">{html.escape(note)}</div>\n'

    if data_quality.get("session_likely_expired"):
        html_content += f'  <div class="warning">{html.escape(data_quality.get("session_expired_note", ""))}</div>\n'

    # ---- P0-3: 执行摘要（Executive Summary）----
    from pipeline.recon_garak import OWASP_REMEDIATION, AGENTIC_REMEDIATION

    top_findings = sorted_probes[:3] if sorted_probes else []
    top_findings_html = "".join(
        f"<li><code>{html.escape(p[0])}</code> — ASR {p[1].get('asr',0)}%, "
        f"DEFCON {p[1].get('defcon','N/A')}</li>"
        for p in top_findings
    )
    overall_defcon_val = overall.get("defcon", 5)
    defcon_comments_map = {
        1: "即时风险（完全失败）— 目标模型存在严重安全漏洞",
        2: "关键风险 — 存在高危攻击面需立即修复",
        3: "中危风险 — 存在可利用的攻击面",
        4: "低危风险 — 攻击面有限",
        5: "极低风险 — 目标模型表现良好",
    }
    defcon_comment_text = defcon_comments_map.get(overall_defcon_val, "")

    # 最差 OWASP 类别 + 修复建议
    remediation_html = ""
    if owasp_llm:
        worst_owasp = min(owasp_llm.items(), key=lambda x: x[1].get("defcon", 5))
        w_label, w_data = worst_owasp
        actions = OWASP_REMEDIATION.get(w_label, ["参考 OWASP LLM Top 10 官方修复指南"])
        remediation_html = f"""  <h3>立即行动建议（针对 {html.escape(w_label)}）</h3>
  <ul>{''.join(f'<li>{html.escape(a)}</li>' for a in actions)}</ul>
"""
    # C-4: Agentic 修复建议（如果 Agentic 桶有更差的 DEFCON）
    agentic_remediation_html = ""
    if owasp_agentic:
        worst_agentic = min(owasp_agentic.items(), key=lambda x: x[1].get("defcon", 5))
        a_label, a_data = worst_agentic
        a_defcon = a_data.get("defcon", 5)
        llm_defcon = w_data.get("defcon", 5) if owasp_llm else 5
        # 仅当 Agentic 比 LLM 更差时附加 Agentic 修复建议
        if a_defcon <= llm_defcon:
            a_actions = AGENTIC_REMEDIATION.get(a_label, ["参考 OWASP Agentic Top 10 官方修复指南"])
            agentic_remediation_html = f"""  <h3>Agentic 行动建议（针对 {html.escape(a_label)}）</h3>
  <ul>{''.join(f'<li>{html.escape(a)}</li>' for a in a_actions)}</ul>
"""
    remediation_html += agentic_remediation_html
    covered_cats = len([v for v in owasp_llm.values() if v.get("evaluated", 0) > 0])
    html_content += f"""  <h2 data-i18n=\"exec_summary\">📋 执行摘要</h2>
  <div class="executive-summary" style="background:#f8f9fa;padding:20px;border-radius:8px;margin:15px 0;">
    <p>本次扫描对目标模型 <strong>{html.escape(str(target_model))}</strong> 执行了
       {overall.get('probes_evaluated', 0)}/{overall.get('probes_total', 0)} 个探针，
       覆盖 OWASP LLM Top 10 中 {covered_cats}/10 个类别。</p>
    <p>整体风险评级:
       <span class="defcon-badge" style="background:{defcon_colors.get(overall_defcon_val, '#999')}">
         DEFCON {overall_defcon_val}
       </span>
       — 最差 ASR {overall.get('worst_asr', 0)}%</p>
    <p style="color:#666;">{html.escape(defcon_comment_text)}</p>
    <h3 data-i18n=\"top_findings\">关键发现 Top 3</h3>
    <ol>{top_findings_html}</ol>
    {remediation_html}
  </div>
"""

    # ---- C-1: 安全态势趋势图表（P3-1: 替换为 Chart.js line chart）----
    trend = analysis.get("trend_analysis", {})
    trend_points = trend.get("trend_points", [])
    if len(trend_points) >= 2:
        trend_dir = trend.get("trend_direction", "stable")
        dir_labels = {
            "improving": "✅ 安全态势改善",
            "degrading": "⚠️ 安全态势恶化",
            "stable": "➡️ 安全态势稳定",
            "insufficient": "数据不足",
        }
        dir_label = dir_labels.get(trend_dir, trend_dir)
        # 构建 Chart.js 数据
        trend_labels = [pt.get("run_id", "")[-8:] for pt in trend_points]
        defcon_data = [pt.get("defcon") or 5 for pt in trend_points]
        asr_data = [pt.get("worst_asr", 0) for pt in trend_points]
        trend_labels_json = json.dumps(trend_labels)
        defcon_data_json = json.dumps(defcon_data)
        asr_data_json = json.dumps(asr_data)
        html_content += f"""  <h3>📈 安全态势趋势 — {dir_label}</h3>
  <div style="margin:15px 0; max-width:600px;">
    <canvas id="trendChart" width="500" height="180"></canvas>
  </div>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
  <script>
  (function() {{
    var ctx = document.getElementById('trendChart');
    if (!ctx) return;
    new Chart(ctx, {{
      type: 'line',
      data: {{
        labels: {trend_labels_json},
        datasets: [
          {{
            label: 'DEFCON',
            data: {defcon_data_json},
            borderColor: '#e74c3c',
            backgroundColor: 'rgba(231,76,60,0.1)',
            yAxisID: 'y_defcon',
            tension: 0.3,
            fill: false,
            pointRadius: 4,
          }},
          {{
            label: 'ASR%',
            data: {asr_data_json},
            borderColor: '#3498db',
            backgroundColor: 'rgba(52,152,219,0.1)',
            yAxisID: 'y_asr',
            tension: 0.3,
            fill: false,
            pointRadius: 4,
            borderDash: [5, 5],
          }}
        ]
      }},
      options: {{
        responsive: true,
        plugins: {{
          legend: {{ position: 'top' }},
          tooltip: {{ mode: 'index', intersect: false }}
        }},
        scales: {{
          y_defcon: {{
            type: 'linear',
            position: 'left',
            min: 1,
            max: 5,
            title: {{ display: true, text: 'DEFCON', color: '#e74c3c' }},
            ticks: {{ color: '#e74c3c', stepSize: 1 }},
            grid: {{ drawOnChartArea: true }}
          }},
          y_asr: {{
            type: 'linear',
            position: 'right',
            min: 0,
            max: 100,
            title: {{ display: true, text: 'ASR%', color: '#3498db' }},
            ticks: {{ color: '#3498db' }},
            grid: {{ drawOnChartArea: false }}
          }}
        }}
      }}
    }});
  }})();
  </script>
"""

    # ---- C-5: System Prompt 探测结果 ----
    sp_probe = analysis.get("system_prompt_probe") or {}
    # 也从 target_profile 间接获取（analysis 可能不直接携带）
    if not sp_probe:
        sp_probe = analysis.get("target_profile", {}).get("system_prompt_probe", {})
    if sp_probe and sp_probe.get("has_system_prompt") is not None:
        has_sp = sp_probe["has_system_prompt"]
        extractable = sp_probe.get("extractable", False)
        sp_icon = "🔒" if has_sp and not extractable else "🔓" if extractable else "ℹ️"
        sp_text = (
            f"目标{'存在' if has_sp else '无明显'}系统提示词"
            + ("（⚠️ 可被提取！）" if extractable else "（不可提取）" if has_sp else "")
        )
        html_content += f"""  <div class="info" style="margin:10px 0;">
    {sp_icon} System Prompt 探测: {html.escape(sp_text)}
  </div>
"""

    # Judge ASR（如果启用）
    judge_asr = overall.get("judge_asr")
    if judge_asr is not None:
        html_content += f"""  <div class="summary-card" style="margin:15px 0;">
    <div class="label">LLM-as-Judge 二次判定 ASR</div>
    <div class="value">{judge_asr}% <span style="font-size:14px;color:#666;">({overall.get("judge_jailbreaks",0)}/{overall.get("judge_total",0)} 样本判定越狱)</span></div>
  </div>
"""

    # ---- OWASP LLM Top 10 覆盖矩阵 ----
    html_content += """  <h2 data-i18n=\"owasp_matrix\">OWASP LLM Top 10 (2025) — 攻击面覆盖</h2>
  <table>
    <thead><tr><th>分类</th><th>探针数</th><th>已评估</th><th>最差ASR</th><th>有效率</th><th>评级</th></tr></thead>
    <tbody>
"""
    if all_owasp_ids:
        labels = sorted(set(list(owasp_llm.keys()) + all_owasp_ids))
    else:
        labels = sorted(owasp_llm.keys())
    na_count = 0
    for label in labels:
        v = owasp_llm.get(label)
        if v:
            eff = v.get("effective_coverage", 0.0)
            eff_str = f"{eff:.0f}%" if eff > 0 else "—"
            defcon = v.get("defcon", "N/A")
            color = defcon_colors.get(defcon, "#999")
            html_content += f"""    <tr>
      <td><strong>{html.escape(label)}</strong></td>
      <td>{v.get("probe_count", 0)}</td>
      <td>{v.get("evaluated", 0)}</td>
      <td>{v.get("worst_asr", 0)}%</td>
      <td>{eff_str}</td>
      <td><span class="defcon-badge" style="background:{color}">{defcon}</span></td>
    </tr>
"""
        else:
            na_count += 1
            html_content += f"""    <tr style="color:#999;">
      <td>{html.escape(label)}</td>
      <td>0</td><td>0</td><td>N/A</td><td>—</td>
      <td><small>未覆盖</small></td>
    </tr>
"""
    html_content += "  </tbody></table>\n"
    if na_count:
        html_content += f'  <div class="info">ℹ️ {na_count} 个 OWASP 类未被 garak 探针覆盖（标注 N/A，非评估通过）— 这反映了 garak 0.15.1 探针库的覆盖局限，非评估遗漏。</div>\n'

    # ---- DEFCON 雷达图 ----
    html_content += f"""  <h2 data-i18n=\"radar_chart\">OWASP LLM Top 10 — DEFCON 雷达图</h2>
  <div class="chart-container"><canvas id="radarChart"></canvas></div>
  <script>
  new Chart(document.getElementById("radarChart"), {{
    type: "radar",
    data: {{
      labels: {json.dumps(radar_labels, ensure_ascii=False)},
      datasets: [{{ label: "风险等级(1-5, 5=最高)", data: {json.dumps(radar_data)},
                    backgroundColor: "rgba(26,35,126,0.2)", borderColor: "#1a237e",
                    pointBackgroundColor: "#1a237e" }}]
    }},
    options: {{ scales: {{ r: {{ min: 0, max: 5, ticks: {{ stepSize: 1 }} }} }} }}
  }});
  </script>
"""

    # ---- ASR 条形图 ----
    html_content += f"""  <h2 data-i18n=\"bar_chart\">探针 ASR 排序（Top {len(sorted_probes)}）</h2>
  <div class="chart-container"><canvas id="barChart"></canvas></div>
  <script>
  new Chart(document.getElementById("barChart"), {{
    type: "bar",
    data: {{
      labels: {json.dumps(bar_labels, ensure_ascii=False)},
      datasets: [{{ label: "ASR (%)", data: {json.dumps(bar_data)},
                    backgroundColor: "#f57c00" }}]
    }},
    options: {{ indexAxis: "y", scales: {{ x: {{ beginAtZero: true, max: 100 }} }} }}
  }});
  </script>
"""

    # ---- 探针明细表（增强：含 tier/tags/group/校准评分 + P1-3 交互过滤） ----
    html_content += """  <h2>探针评估明细</h2>
  <div class="filter-controls" style="margin:15px 0;">
    <select id="defconFilter" onchange="filterTable()" style="padding:6px;border-radius:4px;border:1px solid #ddd;">
      <option value="">全部 DEFCON</option>
      <option value="1">DEFCON 1 (严重)</option>
      <option value="2">DEFCON 2 (高危)</option>
      <option value="3">DEFCON 3 (中危)</option>
      <option value="4">DEFCON 4 (低危)</option>
      <option value="5">DEFCON 5 (安全)</option>
    </select>
    <input type="text" id="probeSearch" oninput="filterTable()" placeholder="搜索探针名..." style="padding:6px;border-radius:4px;border:1px solid #ddd;width:300px;">
    <span id="filterCount" style="color:#666;margin-left:10px;"></span>
  </div>
  <table id="probeTable">
    <thead><tr>
      <th>Probe</th><th>Tier</th><th>ASR</th><th>DEFCON</th>
      <th>校准评分</th><th>Null Rate</th><th>Inf/Det</th>
      <th>ATLAS TTPs</th><th>Tags</th><th>Judge ASR</th>
    </tr></thead>
    <tbody>
"""
    for probe, info in sorted_probes:
        defcon = info.get("defcon", "N/A")
        color = defcon_colors.get(defcon, "#999")
        atlas = ", ".join(t["id"] for t in info.get("atlas_ttps", [])) or "—"
        judge = info.get("judge_asr", "—")
        tier = info.get("probe_tier") or "—"
        tags = info.get("probe_tags", [])
        tags_html = " ".join(
            f'<span class="tag {"tag-owasp" if "owasp" in t else "tag-avid" if "avid" in t else "tag-payload" if "payload" in t else ""}">{html.escape(t)}</span>'
            for t in tags[:5]
        )
        # 校准评分（relative_score from digest）
        cal_data = info.get("detectors_calibrated", {})
        rel_scores = [
            d.get("relative_score") for d in cal_data.values()
            if isinstance(d.get("relative_score"), (int, float))
        ]
        rel_html = "—"
        if rel_scores:
            min_rel = min(rel_scores)
            rel_defcon = min(d.get("relative_defcon", 5) for d in cal_data.values() if d.get("relative_defcon"))
            rel_comment = next((d.get("relative_comment", "") for d in cal_data.values() if d.get("relative_comment")), "")
            rel_html = f'{min_rel:.2f} (DEFCON {rel_defcon})'
            if rel_comment:
                rel_html += f'<br><small>{html.escape(rel_comment)}</small>'
        inf_det = f'{info.get("inference_count", 0)}/{info.get("detection_count", 0)}'
        html_content += f"""    <tr data-defcon="{defcon}">
      <td><code>{html.escape(probe)}</code></td>
      <td>{tier}</td>
      <td>{info.get('asr', 0)}%</td>
      <td><span class="defcon-badge" style="background:{color}">{defcon}</span></td>
      <td><small>{rel_html}</small></td>
      <td>{info.get('null_rate', 0)}%</td>
      <td>{inf_det}</td>
      <td><small>{html.escape(atlas)}</small></td>
      <td>{tags_html}</td>
      <td>{judge if judge != '—' else '—'}</td>
    </tr>
"""
    html_content += """  </tbody></table>
  <script>
  function filterTable() {
    const defcon = document.getElementById("defconFilter").value;
    const search = document.getElementById("probeSearch").value.toLowerCase();
    let visible = 0, total = 0;
    document.querySelectorAll("#probeTable tbody tr").forEach(row => {
      total++;
      const matchDefcon = !defcon || row.dataset.defcon === defcon;
      const matchSearch = !search || row.textContent.toLowerCase().includes(search);
      if (matchDefcon && matchSearch) { row.style.display = ""; visible++; }
      else { row.style.display = "none"; }
    });
    document.getElementById("filterCount").textContent = `显示 ${visible}/${total} 条`;
  }
  </script>
"""

    # ---- ATLAS 战术视图 ----
    if atlas_aggregated:
        html_content += """  <h2 data-i18n=\"atlas_view\">MITRE ATLAS 战术视图</h2>
  <p class="info">将 garak 探针映射到 MITRE ATLAS (Adversarial Threat Landscape for AI Systems) 战术/技术，提供攻击战术视角的跨团队协作参考。</p>
  <table>
    <thead><tr><th>ATLAS TTP ID</th><th>技术名称</th><th>关联探针</th></tr></thead>
    <tbody>
"""
        # TTP 名称查表
        ttp_names = {}
        for _probe, info in probe_results.items():
            for ttp in info.get("atlas_ttps", []):
                ttp_names[ttp["id"]] = ttp.get("name", "Unknown")

        for ttp_id, probes in atlas_aggregated.items():
            probe_list = ", ".join(p["probe"] for p in probes)
            name = ttp_names.get(ttp_id, "Unknown")
            html_content += f"""    <tr>
      <td><code>{html.escape(ttp_id)}</code></td>
      <td>{html.escape(name)}</td>
      <td><small>{html.escape(probe_list)}</small></td>
    </tr>
"""
        html_content += "  </tbody></table>\n"

    # ---- 命中明细表 ----
    if hit_details:
        html_content += f"""  <h2>攻击命中明细（{len(hit_details)} 条）</h2>
  <p class="info">garak 检测器判定为「攻击成功」的 attempt 记录，供安全分析师复核真假阳性。完整明细见 hitlog_{html.escape(run_id)}.md / .jsonl</p>
  <table>
    <thead><tr><th>#</th><th>Probe</th><th>Detector</th><th>Goal</th><th>Prompt (截断)</th><th>Output (截断)</th></tr></thead>
    <tbody>
"""
        for i, h in enumerate(hit_details[:50], 1):
            dets = ", ".join(h.get("triggered_detectors", [])) or "N/A"
            prompt_escaped = html.escape(h.get("prompt", "")[:120].replace("\n", " "))
            output_escaped = html.escape(h.get("output", "")[:120].replace("\n", " "))
            goal_escaped = html.escape(h.get("goal", "")[:80].replace("\n", " "))
            html_content += f"""    <tr>
      <td>{i}</td>
      <td><code>{html.escape(h.get("probe", "unknown"))}</code></td>
      <td><small>{html.escape(dets)}</small></td>
      <td class="prompt-cell">{goal_escaped}</td>
      <td class="prompt-cell">{prompt_escaped}</td>
      <td class="prompt-cell">{output_escaped}</td>
    </tr>
"""
        html_content += "  </tbody></table>\n"
        if len(hit_details) > 50:
            html_content += f'  <p style="color:#999;">仅显示前 50 条，共 {len(hit_details)} 条命中。完整明细见 JSONL 文件。</p>\n'

    # ---- OWASP Agentic 矩阵 ----
    if owasp_agentic:
        html_content += """  <h2 data-i18n=\"agentic_matrix\">OWASP Agentic AI Top 10 (2026) 覆盖</h2>
  <table>
    <thead><tr><th>风险项</th><th>探针数</th><th>已评估</th><th>最差 ASR</th><th>有效率</th><th>DEFCON</th></tr></thead>
    <tbody>
"""
        for label, info in sorted(owasp_agentic.items()):
            defcon = info.get("defcon", "N/A")
            color = defcon_colors.get(defcon, "#999")
            eff = info.get("effective_coverage", 0.0)
            eff_str = f"{eff:.0f}%" if eff > 0 else "—"
            html_content += f"""    <tr>
      <td><strong>{html.escape(label)}</strong></td>
      <td>{info.get('probe_count', 0)}</td>
      <td>{info.get('evaluated', 0)}</td>
      <td>{info.get('worst_asr', 0)}%</td>
      <td>{eff_str}</td>
      <td><span class="defcon-badge" style="background:{color}">{defcon}</span></td>
    </tr>
"""
        html_content += "  </tbody></table>\n"

    # ---- 覆盖缺口透明声明 ----
    if coverage_gaps:
        html_content += """  <h2 data-i18n=\"coverage_gaps\">覆盖缺口声明</h2>
  <div class="info">
    <p>以下 OWASP LLM Top 10 类别在 garak 0.15.1 探针库中无对应探针覆盖，
    标注为 <strong>N/A</strong> 而非评估通过。这是 garak 探针库的已知局限，
    非本流水线评估遗漏：</p>
    <ul>
"""
        for gap in coverage_gaps:
            html_content += f"      <li>{html.escape(gap)}</li>\n"
        html_content += """    </ul>
  </div>
"""

    # ---- C-2: 嵌入 garak 原生 digest Markdown ----
    native_md = analysis.get("native_digest_markdown")
    if native_md:
        try:
            import markdown as _md
            native_html_rendered = _md.markdown(native_md)
        except ImportError:
            # markdown 库不可用时做简单 HTML 转义
            native_html_rendered = f"<pre>{html.escape(native_md[:5000])}</pre>"
        html_content += f"""  <details style="margin:15px 0;">
  <summary style="cursor:pointer;font-weight:bold;">📄 garak 原生 digest 报告（点击展开）</summary>
  <div class="native-digest" style="margin:10px 0;padding:15px;background:#fafafa;border-radius:8px;overflow-x:auto;">
    {native_html_rendered}
  </div>
</details>
"""

    html_content += f"""
  <footer>
    <p>本报告由 garak-pipeline 自动生成 · run_id: {html.escape(run_id)} ·
       repro_hash: {html.escape(str(analysis.get('repro_hash', 'N/A')))}</p>
    <p>命中明细 Markdown: {html.escape(str(hitlog.get('markdown_path', 'N/A')))}</p>
    <p>PyRIT AIR 导出: {html.escape(str(analysis.get('analysis_path', 'N/A')).replace('04_analysis', '05_export'))}</p>
  </footer>
</div>
</body>
</html>
"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    logger.info("HTML 报告已生成: %s", out_path)
    return str(out_path)
