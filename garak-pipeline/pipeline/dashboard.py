"""Web UI 趋势看板 — FastAPI + WebSocket 实时推送

功能：
  1. 实时扫描进度推送（WebSocket）
  2. 历史趋势可视化（REST API）
  3. 多目标对比数据
  4. DEFCON 热力图数据
  5. 合规评分看板

路由:
  GET  /              → 看板 HTML 页面
  GET  /api/trends    → 历史趋势数据
  GET  /api/targets   → 多目标对比数据
  GET  /api/compliance → 合规评分数据
  WS   /ws/progress   → 实时进度推送
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def create_dashboard_app(artifacts_dir: str = "outputs"):
    """创建看板 FastAPI 应用

    :param artifacts_dir: 产物根目录
    :returns: FastAPI app 实例
    """
    try:
        from fastapi import FastAPI, WebSocket
        from fastapi.responses import HTMLResponse
    except ImportError:
        logger.warning("FastAPI 不可用，看板功能需要 fastapi + uvicorn")
        return None

    app = FastAPI(title="garak-pipeline 看板", docs_url="/docs")
    artifacts = Path(artifacts_dir)

    # --- HTML 看板页面 ---
    @app.get("/", response_class=HTMLResponse)
    async def dashboard_page():
        return _render_dashboard_html()

    # --- 历史趋势 API ---
    @app.get("/api/trends")
    async def get_trends():
        return _collect_trend_data(artifacts)

    # --- 多目标对比 API ---
    @app.get("/api/targets")
    async def get_targets():
        return _collect_target_data(artifacts)

    # --- 合规评分 API ---
    @app.get("/api/compliance")
    async def get_compliance():
        return _collect_compliance_data(artifacts)

    # --- 实时进度 WebSocket ---
    @app.websocket("/ws/progress")
    async def progress_websocket(websocket: WebSocket):
        await websocket.accept()
        try:
            # 发送当前最新状态
            latest = _collect_latest_status(artifacts)
            await websocket.send_json(latest)

            # 保持连接，周期性推送更新
            import asyncio
            while True:
                await asyncio.sleep(5)
                latest = _collect_latest_status(artifacts)
                await websocket.send_json(latest)
        except Exception:
            pass

    return app


def _render_dashboard_html() -> str:
    """渲染看板 HTML 页面"""
    return """<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>garak-pipeline 安全态势看板</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }
.container { max-width: 1400px; margin: 0 auto; }
h1 { text-align: center; margin-bottom: 24px; color: #38bdf8; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 24px; }
.card { background: #1e293b; border-radius: 12px; padding: 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
.card h2 { font-size: 16px; margin-bottom: 12px; color: #94a3b8; }
.chart-container { position: relative; height: 300px; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid #334155; }
th { color: #64748b; font-size: 13px; }
.defcon-1 { color: #ef4444; font-weight: 700; }
.defcon-2 { color: #f59e0b; font-weight: 700; }
.defcon-3 { color: #eab308; }
.defcon-4 { color: #22c55e; }
.defcon-5 { color: #06b6d4; }
#progress { position: fixed; bottom: 20px; right: 20px; background: #1e293b; padding: 10px 15px; border-radius: 8px; font-size: 13px; display: none; }
</style>
</head>
<body>
<div class="container">
<h1>🛡️ garak-pipeline 安全态势看板</h1>
<div class="grid">
<div class="card"><h2>ASR 趋势</h2><div class="chart-container"><canvas id="asrChart"></canvas></div></div>
<div class="card"><h2>DEFCON 分布</h2><div class="chart-container"><canvas id="defconChart"></canvas></div></div>
</div>
<div class="card" style="margin-bottom:24px"><h2>多目标对比</h2><div class="chart-container"><canvas id="targetChart"></canvas></div></div>
<div class="card"><h2>合规评分</h2><table id="complianceTable"><thead><tr><th>框架</th><th>评分</th><th>失败项</th><th>警告项</th></tr></thead><tbody></tbody></table></div>
</div>
<div id="progress">📡 连接中...</div>
<script>
async function loadData() {
  const [trends, targets, compliance] = await Promise.all([
    fetch('/api/trends').then(r=>r.json()),
    fetch('/api/targets').then(r=>r.json()),
    fetch('/api/compliance').then(r=>r.json()),
  ]);
  // 渲染趋势图
  if (trends.runs) {
    new Chart(document.getElementById('asrChart'), {
      type: 'line',
      data: { labels: trends.runs.map(r=>r.run_id), datasets: [{label:'Worst ASR %', data: trends.runs.map(r=>r.worst_asr), borderColor:'#38bdf8', tension:0.3}] },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: '#94a3b8' } } }, scales: { x: { ticks: { color: '#64748b' } }, y: { ticks: { color: '#64748b' } } } }
    });
  }
  // 渲染合规表
  if (compliance.frameworks) {
    const tbody = document.querySelector('#complianceTable tbody');
    compliance.frameworks.forEach(f => {
      tbody.innerHTML += `<tr><td>${f.name}</td><td>${f.score}%</td><td class="defcon-1">${f.failed}</td><td class="defcon-2">${f.warned}</td></tr>`;
    });
  }
}
loadData();
// WebSocket 实时进度
const ws = new WebSocket(`ws://${location.host}/ws/progress`);
const progressDiv = document.getElementById('progress');
ws.onopen = () => { progressDiv.style.display = 'block'; progressDiv.textContent = '✅ 已连接'; };
ws.onmessage = (e) => { const d = JSON.parse(e.data); progressDiv.textContent = `📡 ${d.status || 'idle'} ${d.progress || ''}`; };
ws.onclose = () => { progressDiv.textContent = '⚠️ 已断开'; };
</script>
</body>
</html>"""


def _collect_trend_data(artifacts: Path) -> dict[str, Any]:
    """收集历史趋势数据"""
    analysis_dir = artifacts / "04_analysis"
    runs = []
    if analysis_dir.exists():
        for f in sorted(analysis_dir.glob("analysis_*.json")):
            try:
                with open(f, encoding="utf-8") as af:
                    data = json.load(af)
                overall = data.get("overall", {})
                runs.append({
                    "run_id": f.stem.replace("analysis_", ""),
                    "worst_asr": overall.get("worst_asr", 0),
                    "defcon": overall.get("defcon", "N/A"),
                    "timestamp": data.get("timestamp", ""),
                })
            except Exception:
                continue
    return {"runs": runs[-20:]}  # 最近 20 次


def _collect_target_data(artifacts: Path) -> dict[str, Any]:
    """收集多目标对比数据"""
    targets = []
    for subdir in sorted(artifacts.iterdir()):
        if not subdir.is_dir():
            continue
        analysis_dir = subdir / "04_analysis"
        if analysis_dir.exists():
            for f in sorted(analysis_dir.glob("analysis_*.json")):
                try:
                    with open(f, encoding="utf-8") as af:
                        data = json.load(af)
                    overall = data.get("overall", {})
                    targets.append({
                        "name": subdir.name,
                        "worst_asr": overall.get("worst_asr", 0),
                        "defcon": overall.get("defcon", "N/A"),
                    })
                except Exception:
                    continue
    return {"targets": targets}


def _collect_compliance_data(artifacts: Path) -> dict[str, Any]:
    """收集合规评分数据"""
    export_dir = artifacts / "05_export"
    frameworks = []
    if export_dir.exists():
        for f in sorted(export_dir.glob("compliance_*.json")):
            try:
                with open(f, encoding="utf-8") as af:
                    data = json.load(af)
                for fw_name, fw_data in data.get("compliance_checklist", {}).items():
                    frameworks.append({
                        "name": fw_data.get("framework_name", fw_name),
                        "score": fw_data.get("compliance_score", 0),
                        "failed": fw_data.get("failed", 0),
                        "warned": fw_data.get("warned", 0),
                    })
                break  # 取最新一份
            except Exception:
                continue
    return {"frameworks": frameworks}


def _collect_latest_status(artifacts: Path) -> dict[str, Any]:
    """收集最新扫描状态（供 WebSocket 推送）"""
    exec_dir = artifacts / "03_execution"
    checkpoint_files = sorted(exec_dir.glob(".checkpoint_*.json")) if exec_dir.exists() else []
    if checkpoint_files:
        try:
            with open(checkpoint_files[-1], encoding="utf-8") as f:
                ckpt = json.load(f)
            completed = len(ckpt.get("completed", []))
            return {"status": "scanning", "progress": f"{completed} probes completed"}
        except Exception:
            pass
    return {"status": "idle", "progress": ""}
