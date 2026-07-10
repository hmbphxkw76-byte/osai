#!/usr/bin/env python3
"""
RedTeam_AI Web Dashboard — Flask REST API 后端
================================================
为 AI 红队六阶段管道 (L0-L5) 提供统一 Web 操作界面，支持：
- L0 侦察: 创建/管理扫描任务、实时进度、结果浏览与下载
- L1-L5: 管道编排、攻击监控、报告生成（逐步扩展）

当前已实现: L0 Recon 完整功能 + L1-L5 框架占位
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

# 项目根目录（本文件在 web/ 下）
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

# recon 模块目录
_RECON_ROOT = _PROJECT_ROOT / "recon"

from flask import Flask, jsonify, render_template, request, send_file, send_from_directory

_WEB_ROOT = Path(__file__).resolve().parent
app = Flask(__name__, template_folder=str(_WEB_ROOT / "templates"), static_folder=str(_WEB_ROOT / "static"))
app.config["JSON_AS_ASCII"] = False

# ── 全局状态 ──
_scan_jobs: dict[str, dict] = {}
_scans_lock = threading.Lock()

OUTPUT_DIR = _RECON_ROOT / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)


def _run_scan_in_thread(scan_id: str, params: dict):
    """在独立线程中运行异步扫描，捕获输出并更新状态。"""
    job = _scan_jobs.get(scan_id)
    if not job:
        return

    log_buffer = io.StringIO()

    class LogCapture:
        """捕获 stdout 到 buffer 中。"""
        def __init__(self, original, buffer):
            self.original = original
            self.buffer = buffer

        def write(self, data):
            self.original.write(data)
            self.buffer.write(data)

        def flush(self):
            self.original.flush()

    log_capture = LogCapture(sys.stdout, log_buffer)
    orig_stdout = sys.stdout
    sys.stdout = log_capture

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        from recon.engine import ReconEngine

        job["status"] = "running"
        job["started_at"] = datetime.now().isoformat()

        engine = ReconEngine(
            target_url=params["target_url"],
            login_url=params.get("login_url", ""),
            login_cred=params.get("login_cred"),
            auth_cookie=params.get("auth_cookie", ""),
            auth_bearer=params.get("auth_bearer", ""),
            auth_headers=params.get("auth_headers"),
            enable_spa_render=params.get("enable_spa_render", True),
            enable_js_extraction=params.get("enable_js_extraction", True),
            enable_traffic_capture=params.get("enable_traffic_capture", True),
            enable_dict_scan=params.get("enable_dict_scan", False),
            headless=params.get("headless", True),
            output_dir=str(OUTPUT_DIR),
            concurrency=params.get("concurrency", 2),
            timeout=params.get("timeout", 30),
            verify_ssl=params.get("verify_ssl", False),
            rate_profile=params.get("rate_profile", "stealth"),
        )

        # 阶段性同步 findings 到 job
        _stop_sync = {"v": False}

        def _sync_findings():
            last_idx = 0
            while not _stop_sync["v"]:
                try:
                    cur_findings = list(engine.findings)
                    if len(cur_findings) > last_idx:
                        job["findings"] = cur_findings
                        job["finding_count"] = len(cur_findings)
                        last_idx = len(cur_findings)
                except Exception:
                    pass
                time.sleep(0.5)

        sync_thread = threading.Thread(target=_sync_findings, daemon=True)
        sync_thread.start()

        profile = loop.run_until_complete(engine.run())
        _stop_sync["v"] = True
        loop.run_until_complete(engine.cleanup())
        loop.close()

        # 最终同步 findings
        job["findings"] = list(engine.findings)
        job["finding_count"] = len(engine.findings)

        # 查找生成的文件
        safe_host = params["target_url"].replace("://", "_").replace("/", "_").replace(":", "_")
        profile_files = sorted(OUTPUT_DIR.glob(f"target_profile_*{safe_host}*.json"),
                               key=lambda f: f.stat().st_mtime, reverse=True)
        screenshot_files = sorted(OUTPUT_DIR.glob("screenshot_*.png"),
                                  key=lambda f: f.stat().st_mtime, reverse=True)

        job["status"] = "completed"
        job["completed_at"] = datetime.now().isoformat()
        job["profile_data"] = profile.to_dict()
        job["profile_file"] = str(profile_files[0].name) if profile_files else None
        job["screenshots"] = [f.name for f in screenshot_files if "landing" in f.name.lower()]

    except Exception as e:
        import traceback
        job["status"] = "failed"
        job["error"] = str(e)
        job["traceback"] = traceback.format_exc()
    finally:
        sys.stdout = orig_stdout
        job["log"] = log_buffer.getvalue()
        log_buffer.close()
        duration_ms = int((time.time() - job["created"]) * 1000) if job.get("created") else 0
        job["duration_ms"] = duration_ms


# ── 页面路由 ──

@app.route("/")
def index():
    """主页面 — 单页应用入口。"""
    return render_template("index.html")


# ── API: 扫描管理 ──

@app.route("/api/scans", methods=["GET"])
def list_scans():
    """列出所有扫描任务。"""
    with _scans_lock:
        scans = []
        for sid, job in _scan_jobs.items():
            scans.append({
                "id": sid,
                "target_url": job.get("target_url", ""),
                "status": job.get("status"),
                "created_at": job.get("created_at"),
                "started_at": job.get("started_at"),
                "completed_at": job.get("completed_at"),
                "duration_ms": job.get("duration_ms"),
                "error": job.get("error"),
                "screenshots": job.get("screenshots", []),
                "has_profile": bool(job.get("profile_data")),
            })
        scans.sort(key=lambda s: s.get("created_at", ""), reverse=True)
        return jsonify({"scans": scans, "total": len(scans)})


@app.route("/api/scans/start", methods=["POST"])
def start_scan():
    """启动新的 L0 侦测扫描。"""
    data = request.get_json(silent=True) or {}

    target_url = (data.get("target_url") or "").strip()
    if not target_url:
        return jsonify({"error": "target_url 不能为空"}), 400
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    # 解析 login_cred
    login_cred = data.get("login_cred")
    if isinstance(login_cred, str) and login_cred.strip():
        try:
            login_cred = json.loads(login_cred)
        except json.JSONDecodeError:
            return jsonify({"error": "login_cred JSON 格式无效"}), 400
    elif isinstance(login_cred, dict):
        pass
    else:
        login_cred = None

    # 解析 auth_headers
    auth_headers = data.get("auth_headers")
    if isinstance(auth_headers, list) and auth_headers:
        headers = {}
        for h in auth_headers:
            val = h.get("value", "")
            key = h.get("key", "")
            if key:
                headers[key] = val
        auth_headers = headers if headers else None
    elif isinstance(auth_headers, dict):
        auth_headers = auth_headers if auth_headers else None
    else:
        auth_headers = None

    scan_id = str(uuid.uuid4())[:8]
    job = {
        "id": scan_id,
        "target_url": target_url,
        "status": "pending",
        "created": time.time(),
        "created_at": datetime.now().isoformat(),
        "params": data,
        "log": "",
        "profile_data": None,
        "profile_file": None,
        "screenshots": [],
        "error": None,
    }

    params = {
        "target_url": target_url,
        "login_url": (data.get("login_url") or "").strip(),
        "login_cred": login_cred,
        "auth_cookie": (data.get("auth_cookie") or "").strip(),
        "auth_bearer": (data.get("auth_bearer") or "").strip(),
        "auth_headers": auth_headers,
        "enable_spa_render": not data.get("no_spa", False),
        "enable_js_extraction": not data.get("no_js_extract", False),
        "enable_traffic_capture": not data.get("no_traffic", False),
        "enable_dict_scan": data.get("dict_scan", False),
        "headless": not data.get("headed", False),
        "output_dir": str(OUTPUT_DIR),
        "concurrency": data.get("concurrency", 5),
        "timeout": data.get("timeout", 30),
        "verify_ssl": data.get("verify_ssl", False),
    }

    with _scans_lock:
        _scan_jobs[scan_id] = job

    thread = threading.Thread(target=_run_scan_in_thread, args=(scan_id, params), daemon=True)
    thread.start()

    return jsonify({"scan_id": scan_id, "status": "pending"}), 201


@app.route("/api/scans/<scan_id>", methods=["GET"])
def get_scan(scan_id):
    """获取单个扫描任务的完整状态与结果。"""
    with _scans_lock:
        job = _scan_jobs.get(scan_id)
    if not job:
        return jsonify({"error": "扫描任务不存在"}), 404

    return jsonify({
        "id": scan_id,
        "target_url": job.get("target_url"),
        "status": job.get("status"),
        "created_at": job.get("created_at"),
        "started_at": job.get("started_at"),
        "completed_at": job.get("completed_at"),
        "duration_ms": job.get("duration_ms"),
        "error": job.get("error"),
        "screenshots": job.get("screenshots", []),
        "profile_file": job.get("profile_file"),
        "profile": job.get("profile_data"),
        "log": job.get("log", ""),
        "findings": job.get("findings", []),
        "finding_count": job.get("finding_count", 0),
    })


@app.route("/api/scans/<scan_id>/log", methods=["GET"])
def get_scan_log(scan_id):
    """获取扫描日志。"""
    with _scans_lock:
        job = _scan_jobs.get(scan_id)
    if not job:
        return jsonify({"error": "扫描任务不存在"}), 404
    return jsonify({"log": job.get("log", "")})


@app.route("/api/scans/<scan_id>/profile", methods=["GET"])
def download_profile(scan_id):
    """下载 target_profile JSON 文件。"""
    with _scans_lock:
        job = _scan_jobs.get(scan_id)
    if not job:
        return jsonify({"error": "扫描任务不存在"}), 404

    profile_file = job.get("profile_file")
    if not profile_file:
        return jsonify({"error": "未找到 profile 文件"}), 404

    file_path = OUTPUT_DIR / profile_file
    if not file_path.exists():
        return jsonify({"error": "profile 文件已不存在"}), 404

    return send_file(
        file_path,
        as_attachment=True,
        download_name=profile_file,
        mimetype="application/json",
    )


@app.route("/api/scans/<scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    """删除扫描任务记录。"""
    with _scans_lock:
        if scan_id in _scan_jobs:
            del _scan_jobs[scan_id]
            return jsonify({"deleted": True})
    return jsonify({"error": "扫描任务不存在"}), 404


# ── API: 输出文件 ──

@app.route("/api/outputs", methods=["GET"])
def list_outputs():
    """列出 outputs 目录下的所有文件。"""
    files = []
    for f in sorted(OUTPUT_DIR.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if f.is_file():
            files.append({
                "name": f.name,
                "size": f.stat().st_size,
                "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
            })
    return jsonify({"files": files})


@app.route("/api/outputs/<path:filename>", methods=["GET"])
def serve_output(filename):
    """提供 outputs 目录下的文件。"""
    return send_from_directory(str(OUTPUT_DIR), filename)


# ── API: 管道状态 ──

@app.route("/api/pipeline", methods=["GET"])
def pipeline_status():
    """获取六阶段管道整体状态。"""
    with _scans_lock:
        completed = sum(1 for j in _scan_jobs.values() if j.get("status") == "completed")
        running = sum(1 for j in _scan_jobs.values() if j.get("status") == "running")
        failed = sum(1 for j in _scan_jobs.values() if j.get("status") == "failed")

    return jsonify({
        "stages": {
            "L0_recon": {"status": "active", "scans_completed": completed, "scans_running": running},
            "L1_garak": {"status": "coming_soon"},
            "L2_bridge": {"status": "coming_soon"},
            "L3_promptfoo": {"status": "coming_soon"},
            "L4_pyrit": {"status": "coming_soon"},
            "L5_report": {"status": "coming_soon"},
        },
        "total_completed": completed,
        "total_running": running,
        "total_failed": failed,
    })


# ── API: 统计 ──

@app.route("/api/stats", methods=["GET"])
def get_stats():
    """获取全局统计信息。"""
    with _scans_lock:
        total = len(_scan_jobs)
        completed = sum(1 for j in _scan_jobs.values() if j.get("status") == "completed")
        running = sum(1 for j in _scan_jobs.values() if j.get("status") == "running")
        pending = sum(1 for j in _scan_jobs.values() if j.get("status") == "pending")
        failed = sum(1 for j in _scan_jobs.values() if j.get("status") == "failed")

    return jsonify({
        "total_scans": total,
        "completed": completed,
        "running": running,
        "pending": pending,
        "failed": failed,
    })


if __name__ == "__main__":
    sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf-8', buffering=1)
    print(f"[RedTeam_AI] Web Dashboard starting...")
    print(f"   URL:    http://127.0.0.1:8086")
    print(f"   Output: {OUTPUT_DIR}")
    print(f"   Pipeline: L0 Recon ✓ | L1 Garak (soon) | L2 Bridge (soon) | L3 Promptfoo (soon) | L4 PyRIT (soon) | L5 Report (soon)")
    app.run(host="0.0.0.0", port=8086, debug=True)
