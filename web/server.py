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
import base64
import io
import http.cookies
import json
import os
import random
import re
import shutil
import sys
import threading
import time
import platform
import uuid
from datetime import datetime
from pathlib import Path

# 项目根目录（本文件在 web/ 下）
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

# recon 模块目录
_RECON_ROOT = _PROJECT_ROOT / "recon"

from flask import Flask, jsonify, render_template, request, send_file, send_from_directory
from werkzeug.utils import secure_filename

_WEB_ROOT = Path(__file__).resolve().parent
app = Flask(__name__, template_folder=str(_WEB_ROOT / "templates"), static_folder=str(_WEB_ROOT / "static"))
app.config["JSON_AS_ASCII"] = False

# ── 全局状态 ──
_scan_jobs: dict[str, dict] = {}
_scans_lock = threading.Lock()
_batches: dict[str, dict] = {}
_batches_lock = threading.Lock()
_basic_jobs: dict[str, dict] = {}
_basic_lock = threading.Lock()

OUTPUT_DIR = _RECON_ROOT / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)
CERTS_DIR = _WEB_ROOT / "certs"
CERTS_DIR.mkdir(exist_ok=True)

_ALLOWED_CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".key"}


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
            ca_cert=params.get("ca_cert"),
            rate_profile=params.get("rate_profile", "stealth"),
            stealth_mode=params.get("stealth_mode", "auto"),
            chrome_path=params.get("chrome_path"),
            humanize=params.get("humanize", True),
            storage_state_path=params.get("storage_state_path"),
            har_output_path=params.get("har_output_path"),
            rate_limit_rpm=params.get("rate_limit_rpm"),
            request_delay_ms=params.get("request_delay_ms"),
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
    # 支持 multipart/form-data（证书上传）或纯 JSON
    is_multipart = request.content_type and request.content_type.startswith("multipart/form-data")
    if is_multipart:
        data = request.form.to_dict()
        # 布尔字段从字符串还原
        for key in ["dict_scan", "headed", "no_spa", "no_js_extract", "no_traffic", "verify_ssl"]:
            data[key] = data.get(key) in ("true", "on", "1")
        for key in ["concurrency", "timeout"]:
            if data.get(key):
                try:
                    data[key] = int(data[key])
                except ValueError:
                    pass
    else:
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
    if is_multipart:
        auth_headers = {}
        extra_headers_json = (data.get("extra_headers_json") or "").strip()
        if extra_headers_json:
            try:
                parsed = json.loads(extra_headers_json)
                if isinstance(parsed, dict):
                    auth_headers.update({k: str(v) for k, v in parsed.items()})
                else:
                    return jsonify({"error": "额外请求头 JSON 必须是对象"}), 400
            except json.JSONDecodeError:
                return jsonify({"error": "额外请求头 JSON 格式无效"}), 400
        api_key = (data.get("api_key") or "").strip()
        api_key_header = data.get("api_key_header", "Authorization")
        if api_key:
            header_name = api_key_header or "Authorization"
            header_value = (
                f"Bearer {api_key}"
                if header_name == "Authorization" and not api_key.lower().startswith("bearer ")
                else api_key
            )
            auth_headers[header_name] = header_value
        auth_headers = auth_headers if auth_headers else None
    else:
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

    # 处理上传的证书文件
    ca_cert_path: str | None = None
    cert_file = request.files.get("ca_cert_file") if is_multipart else None
    if cert_file and cert_file.filename:
        filename = secure_filename(cert_file.filename)
        ext = Path(filename).suffix.lower()
        if ext not in _ALLOWED_CERT_EXTENSIONS:
            return jsonify({"error": f"不支持的证书格式: {ext}。请上传 .pem/.crt/.cer/.key 文件"}), 400
        # 使用唯一文件名避免冲突
        saved_name = f"{uuid.uuid4().hex[:8]}_{filename}"
        cert_save_path = CERTS_DIR / saved_name
        try:
            cert_file.save(str(cert_save_path))
            ca_cert_path = str(cert_save_path)
        except Exception as e:
            return jsonify({"error": f"证书保存失败: {e}"}), 500

    # 处理上传的 storageState 会话文件
    storage_state_path: str | None = None
    storage_state_file = request.files.get("storage_state_file") if is_multipart else None
    if storage_state_file and storage_state_file.filename:
        filename = secure_filename(storage_state_file.filename)
        saved_name = f"storage_state_{uuid.uuid4().hex[:8]}_{filename}"
        save_path = OUTPUT_DIR / saved_name
        try:
            os.makedirs(OUTPUT_DIR, exist_ok=True)
            storage_state_file.save(str(save_path))
            storage_state_path = str(save_path)
        except Exception as e:
            return jsonify({"error": f"storageState 文件保存失败: {e}"}), 500

    # HAR 录制路径
    har_output_path: str | None = None
    if data.get("har_output", False):
        har_filename = f"traffic_{uuid.uuid4().hex[:8]}.har"
        har_output_path = str(OUTPUT_DIR / har_filename)

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
        "ca_cert": ca_cert_path,
        "rate_profile": data.get("rate_profile", "stealth"),
        "stealth_mode": "auto",  # Web UI 目前固定 auto，CLI 可指定其他模式
        "chrome_path": None,
        "humanize": True,
        "storage_state_path": storage_state_path,
        "har_output_path": har_output_path,
        # 速率限制参数（由前端快速探测结果传递）
        "rate_limit_rpm": data.get("rate_limit_rpm"),
        "request_delay_ms": data.get("request_delay_ms"),
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


# ── API: 批次扫描（多 URL） ──

@app.route("/api/batches", methods=["POST"])
def create_batch():
    """创建批次扫描 — 一次提交多个目标 URL，共享同一套认证配置。"""
    is_multipart = request.content_type and request.content_type.startswith("multipart/form-data")

    if is_multipart:
        data = request.form.to_dict()
        for key in ["dict_scan", "headed", "no_spa", "no_js_extract", "no_traffic", "verify_ssl"]:
            data[key] = data.get(key) in ("true", "on", "1")
        for key in ["concurrency", "timeout"]:
            if data.get(key):
                try:
                    data[key] = int(data[key])
                except ValueError:
                    pass
    else:
        data = request.get_json(silent=True) or {}

    # 解析目标 URL 列表
    if is_multipart:
        target_urls_raw = request.form.getlist("target_urls")
    elif isinstance(data, dict):
        target_urls_raw = data.get("target_urls", "")
    else:
        target_urls_raw = ""

    if isinstance(target_urls_raw, list):
        urls = [u.strip() for u in target_urls_raw if u and u.strip()]
    elif isinstance(target_urls_raw, str):
        urls = _parse_url_list(target_urls_raw)
    else:
        return jsonify({"error": "target_urls 不能为空"}), 400

    valid_urls = []
    for url in urls:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        valid_urls.append(url)

    if not valid_urls:
        return jsonify({"error": "至少需要一个有效的目标 URL"}), 400

    if len(valid_urls) == 1:
        return jsonify({"error": "单个 URL 请使用 /api/scans/start；批次接口需要 2+ 个 URL"}), 400

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
    if is_multipart:
        auth_headers = {}
        extra_headers_json = (data.get("extra_headers_json") or "").strip()
        if extra_headers_json:
            try:
                parsed = json.loads(extra_headers_json)
                if isinstance(parsed, dict):
                    auth_headers.update({k: str(v) for k, v in parsed.items()})
                else:
                    return jsonify({"error": "额外请求头 JSON 必须是对象"}), 400
            except json.JSONDecodeError:
                return jsonify({"error": "额外请求头 JSON 格式无效"}), 400
        api_key = (data.get("api_key") or "").strip()
        api_key_header = data.get("api_key_header", "Authorization")
        if api_key:
            header_name = api_key_header or "Authorization"
            header_value = (
                f"Bearer {api_key}"
                if header_name == "Authorization" and not api_key.lower().startswith("bearer ")
                else api_key
            )
            auth_headers[header_name] = header_value
        auth_headers = auth_headers if auth_headers else None
    else:
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

    # 处理上传的证书文件（批次共享）
    ca_cert_path: str | None = None
    cert_file = request.files.get("ca_cert_file") if is_multipart else None
    if cert_file and cert_file.filename:
        filename = secure_filename(cert_file.filename)
        ext = Path(filename).suffix.lower()
        if ext not in _ALLOWED_CERT_EXTENSIONS:
            return jsonify({"error": f"不支持的证书格式: {ext}"}), 400
        saved_name = f"{uuid.uuid4().hex[:8]}_{filename}"
        cert_save_path = CERTS_DIR / saved_name
        try:
            cert_file.save(str(cert_save_path))
            ca_cert_path = str(cert_save_path)
        except Exception as e:
            return jsonify({"error": f"证书保存失败: {e}"}), 500

    # 处理上传的 storageState 文件（批次共享）
    storage_state_path: str | None = None
    storage_state_file = request.files.get("storage_state_file") if is_multipart else None
    if storage_state_file and storage_state_file.filename:
        filename = secure_filename(storage_state_file.filename)
        saved_name = f"storage_state_{uuid.uuid4().hex[:8]}_{filename}"
        save_path = OUTPUT_DIR / saved_name
        try:
            os.makedirs(OUTPUT_DIR, exist_ok=True)
            storage_state_file.save(str(save_path))
            storage_state_path = str(save_path)
        except Exception as e:
            return jsonify({"error": f"storageState 文件保存失败: {e}"}), 500

    # 构建共享参数模板
    shared_params = {
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
        "ca_cert": ca_cert_path,
        "rate_profile": data.get("rate_profile", "stealth"),
        "stealth_mode": "auto",
        "chrome_path": None,
        "humanize": True,
        "storage_state_path": storage_state_path,
    }

    batch_id = str(uuid.uuid4())[:8]
    scan_ids = []

    with _scans_lock, _batches_lock:
        for url in valid_urls:
            scan_id = str(uuid.uuid4())[:8]
            scan_ids.append(scan_id)

            # HAR 录制 — 每个扫描独立文件
            har_output_path = None
            if data.get("har_output", False):
                har_filename = f"traffic_{scan_id}.har"
                har_output_path = str(OUTPUT_DIR / har_filename)

            job = {
                "id": scan_id,
                "target_url": url,
                "status": "pending",
                "created": time.time(),
                "created_at": datetime.now().isoformat(),
                "params": data,
                "log": "",
                "profile_data": None,
                "profile_file": None,
                "screenshots": [],
                "error": None,
                "batch_id": batch_id,
            }
            _scan_jobs[scan_id] = job

            params = dict(shared_params)
            params["target_url"] = url
            params["har_output_path"] = har_output_path

            thread = threading.Thread(target=_run_scan_in_thread, args=(scan_id, params), daemon=True)
            thread.start()

        _batches[batch_id] = {
            "id": batch_id,
            "scan_ids": scan_ids,
            "target_urls": valid_urls,
            "created": time.time(),
            "created_at": datetime.now().isoformat(),
            "status": "running",
        }

    return jsonify({
        "batch_id": batch_id,
        "scan_ids": scan_ids,
        "total": len(scan_ids),
    }), 201


@app.route("/api/batches/<batch_id>", methods=["GET"])
def get_batch(batch_id):
    """获取批次状态 — 返回所有子扫描任务的摘要。"""
    with _batches_lock:
        batch = _batches.get(batch_id)
    if not batch:
        return jsonify({"error": "批次不存在"}), 404

    scans = []
    completed = 0
    running = 0
    pending = 0
    failed = 0

    with _scans_lock:
        for sid in batch["scan_ids"]:
            job = _scan_jobs.get(sid)
            if not job:
                continue
            s = {
                "id": sid,
                "target_url": job.get("target_url", ""),
                "status": job.get("status"),
                "created_at": job.get("created_at"),
                "started_at": job.get("started_at"),
                "completed_at": job.get("completed_at"),
                "duration_ms": job.get("duration_ms"),
                "error": job.get("error"),
                "profile": job.get("profile_data"),
                "finding_count": job.get("finding_count", 0),
                "has_profile": bool(job.get("profile_data")),
            }
            scans.append(s)
            st = s.get("status")
            if st == "completed":
                completed += 1
            elif st == "running":
                running += 1
            elif st == "pending":
                pending += 1
            elif st == "failed":
                failed += 1

    # 判定批次整体状态
    if completed + failed == len(scans) and len(scans) > 0:
        batch_status = "completed"
    elif running > 0 or pending > 0:
        batch_status = "running"
    else:
        batch_status = "unknown"

    return jsonify({
        "batch_id": batch_id,
        "status": batch_status,
        "total": len(scans),
        "completed": completed,
        "running": running,
        "pending": pending,
        "failed": failed,
        "scans": scans,
        "created_at": batch.get("created_at"),
    })


def _parse_url_list(raw: str) -> list[str]:
    """从文本中解析 URL 列表，支持换行、逗号、分号分隔。"""
    # 先按换行拆
    lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    urls = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # 再按分号拆
        parts = line.replace("；", ";").split(";")
        for part in parts:
            part = part.strip()
            if not part:
                continue
            # 再按逗号拆（但要避免拆 URL 内的逗号，简单处理：非 http 开头的逗号才拆）
            if "," in part and (part.startswith("http://") or part.startswith("https://")):
                # URL 中不太可能出现逗号分隔多个 URL，安全起见拆分
                sub_parts = part.split(",")
                for sp in sub_parts:
                    sp = sp.strip()
                    if sp:
                        urls.append(sp)
            else:
                urls.append(part)
    return urls


# ── 快速基本扫描（轻量端点探测） ──

_BASIC_SCAN_PATHS = [
    "/", "/login", "/auth", "/token", "/api/auth",
    "/v1/chat/completions", "/api/chat/completions", "/chat/completions",
    "/v1/models", "/api/models", "/models", "/api/tags", "/api/ps",
    "/api/version", "/api/generate", "/api/chat", "/health", "/docs",
    "/openapi.json", "/api/status", "/api/info", "/generate",
    "/embeddings", "/v1/embeddings", "/api/agent", "/rag", "/api/rag",
    "/debug", "/admin", "/dashboard", "/api/keys", "/metrics",
    "/mcp/sse", "/api/messages", "/api/conversations", "/v1/messages",
    "/api/v1/chat/completions", "/api/v1/models", "/api/openai",
    "/api/show", "/api/copy", "/api/delete", "/api/blobs",
    "/v1/completions", "/api/completions", "/api/v1/completions",
    "/ai/chat", "/llm/chat", "/ask", "/query",
]

_WAF_KEYWORDS = [
    "cloudflare", "incapsula", "sucuri", "akamai", "imperva",
    "fortinet", "barracuda", "aws waf", "challenge", "captcha",
    "bot", "waf", "firewall", "blocked", "access denied",
]

# 常见速率限制响应头（按优先级排列）
_RATE_LIMIT_HEADERS = [
    ("x-ratelimit-limit", "limit"), ("x-rate-limit-limit", "limit"),
    ("x-ratelimit-remaining", "remaining"), ("x-rate-limit-remaining", "remaining"),
    ("x-ratelimit-reset", "reset"), ("x-rate-limit-reset", "reset"),
    ("x-ratelimit-policy", "policy"), ("x-rate-limit-policy", "policy"),
    ("retry-after", "retry_after"),
    ("ratelimit-limit", "limit"), ("ratelimit-remaining", "remaining"), ("ratelimit-reset", "reset"),
]


def _detect_waf_basic(headers: dict, body: str) -> str:
    """从响应头和响应体中快速识别 WAF / 反爬标记。"""
    text = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    text += " " + body[:2000].lower()
    for kw in _WAF_KEYWORDS:
        if kw in text:
            return kw
    return ""


def _extract_rate_limit_info(headers: dict, status: int, endpoints_hit_429: int = 0) -> dict:
    """从 HTTP 响应头中提取 API 速率限制参数。

    返回:
        {
            "detected": True/False,
            "limit": "每分钟 60 次" / None,      # 格式化后的配额
            "remaining": 47 / None,               # 剩余次数
            "reset_seconds": 53 / None,            # 重置倒计时 (秒)
            "retry_after_seconds": 5 / None,       # Retry-After 秒数
            "raw_headers": {"x-ratelimit-limit": "60", ...},  # 原始响应头
            "advice": "P0" / "P1" / "P2" / "",     # 攻速建议等级
        }
    """
    result: dict = {
        "detected": False,
        "limit": None,
        "remaining": None,
        "reset_seconds": None,
        "retry_after_seconds": None,
        "raw_headers": {},
        "advice": "",
        "endpoints_hit_429": endpoints_hit_429,
    }

    headers_lower = {k.lower(): v for k, v in headers.items()}

    # 1) Retry-After（最直接的限流信号）
    retry_after = headers_lower.get("retry-after", "")
    if retry_after:
        try:
            result["retry_after_seconds"] = int(retry_after)
        except ValueError:
            pass

    # 2) 标准速率限制头
    for header_name, field in _RATE_LIMIT_HEADERS:
        val = headers_lower.get(header_name)
        if val is not None:
            result["raw_headers"][header_name] = val
            if field == "limit":
                try:
                    result["limit"] = int(val)
                except ValueError:
                    result["limit"] = val
            elif field == "remaining":
                try:
                    result["remaining"] = int(val)
                except ValueError:
                    result["remaining"] = val
            elif field == "reset":
                try:
                    # 判断是时间戳还是秒数
                    ts = int(val)
                    if ts > 1_000_000_000:  # Unix 时间戳
                        import time as _time
                        result["reset_seconds"] = max(0, ts - int(_time.time()))
                    else:
                        result["reset_seconds"] = ts
                except ValueError:
                    pass
            elif field == "retry_after":
                try:
                    result["retry_after_seconds"] = result.get("retry_after_seconds") or int(val)
                except ValueError:
                    pass

    # 3) 429 状态码或端点命中 429
    has_429 = status == 429 or endpoints_hit_429 > 0
    if has_429 and not result["raw_headers"]:
        result["detected"] = True

    if result["raw_headers"]:
        result["detected"] = True

    # 4) 生成人类可读的格式和攻速建议
    if result["limit"] is not None and isinstance(result["limit"], int):
        result["limit_formatted"] = f"每窗口 {result['limit']} 次"
    elif result["limit"] is not None:
        result["limit_formatted"] = str(result["limit"])
    else:
        result["limit_formatted"] = None

    # 攻速建议等级
    if result["detected"]:
        if result["limit"] is not None and isinstance(result["limit"], int):
            if result["limit"] <= 10:
                result["advice"] = "P0"  # 极严格 - 单线程串行/stealth
            elif result["limit"] <= 60:
                result["advice"] = "P1"  # 中等 - balanced
            else:
                result["advice"] = "P2"  # 宽松 - balanced/fast
        elif has_429:
            result["advice"] = "P0"
        else:
            result["advice"] = "P1"
        # 补充 Retry-After 信息
        if result["retry_after_seconds"]:
            result["advice"] += f" (重试等待 {result['retry_after_seconds']}s)"

    return result


def _detect_anti_defense(root_status: int, headers: dict, body: str, endpoints: list) -> dict:
    """判断目标是否存在反爬 / 高级防御，或扫描结果为空。"""
    reasons = []
    waf = _detect_waf_basic(headers, body)
    if waf:
        reasons.append(f"检测到防御标记: {waf}")
    if root_status in (403, 502, 503, 504, 520, 521, 522, 523):
        reasons.append(f"根路径返回 HTTP {root_status}")
    # 若探测结果为空或全部不可达
    if not endpoints:
        reasons.append("未发现任何存活端点")
    else:
        non_error = [ep for ep in endpoints if ep["status"] > 0 and ep["status"] < 400]
        if not non_error:
            reasons.append("所有端点均返回 4xx/5xx 或不可达")
    if reasons:
        return {"detected": True, "reason": "; ".join(reasons)}
    return {"detected": False, "reason": ""}


def _build_auth_headers(auth: dict | None) -> dict[str, str]:
    """根据前端认证配置构造请求头字典。

    支持 Basic Auth、Bearer/JWT、API Key（Header）、Cookie、Custom Headers 以及
    这些方式的组合。注意：同一请求中 Authorization 头只能生效一个，因此
    Bearer 会覆盖 Basic，API Key 若使用 Authorization 也会覆盖前者。
    """
    headers: dict[str, str] = {}
    if not auth:
        return headers

    # Basic Auth
    basic = auth.get("basic") or {}
    username = (basic.get("username") or "").strip()
    password = basic.get("password") or ""
    if username:
        creds = f"{username}:{password}".encode("utf-8")
        headers["Authorization"] = f"Basic {base64.b64encode(creds).decode('ascii')}"

    # Bearer / JWT
    bearer = auth.get("bearer") or {}
    token = (bearer.get("token") or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    # API Key（仅支持 Header 形式）
    api_key = auth.get("api_key") or {}
    key_name = (api_key.get("name") or "").strip()
    key_value = (api_key.get("value") or "").strip()
    if key_name and key_value:
        headers[key_name] = key_value

    # Cookie
    cookie = (auth.get("cookie") or "").strip()
    if cookie:
        headers["Cookie"] = cookie

    # Custom Headers
    custom_headers = auth.get("headers") or {}
    if isinstance(custom_headers, dict):
        for k, v in custom_headers.items():
            if k:
                headers[k] = v

    return headers


def _run_basic_scan_in_thread(basic_id: str, urls: list[str], options: dict):
    """在独立线程中执行轻量 HTTP 端点探测。"""
    job = _basic_jobs.get(basic_id)
    if not job:
        return

    try:
        job["status"] = "running"
        job["started_at"] = datetime.now().isoformat()

        import asyncio
        import httpx
        from recon.scanners.dict_scan import DictScanner
        from recon.analysis.endpoint_infer import EndpointInferrer

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        extra_headers = _build_auth_headers(options.get("auth"))
        base_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/json,*/*",
        }

        scanner = DictScanner(
            concurrency=options.get("concurrency", 3),
            timeout=options.get("timeout", 10),
            verify_ssl=options.get("verify_ssl", False),
            rate_profile=options.get("rate_profile", "balanced"),
            llm_paths=options.get("paths", _BASIC_SCAN_PATHS),
            web_paths=[],
        )
        inferrer = EndpointInferrer()

        results = []
        for url in urls:
            url = url.rstrip("/")
            root_status = 0
            title = ""
            server = ""
            waf = ""
            headers = {}
            body = ""
            try:
                with httpx.Client(
                    verify=options.get("verify_ssl", False),
                    timeout=httpx.Timeout(options.get("timeout", 10)),
                    follow_redirects=True,
                    headers={**base_headers, **extra_headers},
                ) as client:
                    r = client.get(url)
                    root_status = r.status_code
                    headers = dict(r.headers)
                    server = r.headers.get("server", "")
                    title_match = re.search(r"<title>(.*?)</title>", r.text, re.IGNORECASE)
                    title = title_match.group(1) if title_match else ""
                    body = r.text[:2000]
                    waf = _detect_waf_basic(headers, body)
            except Exception as e:
                root_status = -3
                job.setdefault("errors", []).append(f"{url} root probe: {e}")

            # 字典探测
            try:
                scan_results = loop.run_until_complete(scanner.scan(url, extra_headers=extra_headers))
            except Exception as e:
                scan_results = []
                job.setdefault("errors", []).append(f"{url} dict scan: {e}")

            endpoints = []
            for r in scan_results:
                if r.get("status", 0) == 0:
                    continue
                ep = inferrer.classify_endpoint({
                    "url": r.get("url", ""),
                    "method": r.get("method", "GET"),
                    "status": r.get("status", 0),
                    "content_type": r.get("content_type", ""),
                    "body": r.get("body_snippet", ""),
                    "response_time_ms": r.get("response_time_ms", 0.0),
                })
                endpoints.append({
                    "path": ep.path,
                    "full_url": ep.full_url,
                    "method": ep.method,
                    "status": ep.status,
                    "content_type": ep.content_type,
                    "category": ep.category,
                    "is_chat_endpoint": ep.is_chat_endpoint,
                    "requires_auth": ep.requires_auth,
                    "response_time_ms": ep.response_time_ms,
                    "body_snippet": (ep.body_snippet or "")[:300],
                })

            # 排序：200 优先，401/403 次之，其它最后
            endpoints.sort(key=lambda ep: (0 if ep["status"] in (200, 201) else 1 if ep["status"] in (401, 403) else 2))

            # 认证需求判定：401/403 或路径含登录/认证关键词
            auth_required = any(
                ep["status"] in (401, 403)
                or ep["category"] == "auth"
                or any(k in ep["path"].lower() for k in ["/login", "/auth", "/token", "/signin", "/oauth"])
                for ep in endpoints
            )

            anti = _detect_anti_defense(root_status, headers, body, endpoints)

            # 速率限制检测
            endpoints_hit_429 = sum(1 for ep in endpoints if ep["status"] == 429)
            rate_limit = _extract_rate_limit_info(headers, root_status, endpoints_hit_429)

            results.append({
                "url": url,
                "root_status": root_status,
                "title": title,
                "server": server,
                "waf": waf,
                "auth_required": auth_required,
                "auth_used": bool(extra_headers),
                "anti_defense": anti["detected"],
                "anti_defense_reason": anti["reason"],
                "rate_limit": rate_limit,
                "endpoints": endpoints,
            })

        job["results"] = results
        job["status"] = "completed"
        job["completed_at"] = datetime.now().isoformat()
    except Exception as e:
        import traceback
        job["status"] = "failed"
        job["error"] = str(e)
        job["traceback"] = traceback.format_exc()


@app.route("/api/basic_scan", methods=["POST"])
def create_basic_scan():
    """创建轻量基本扫描任务（多 URL 并发端点探测）。"""
    data = request.get_json(silent=True) or {}

    target_urls_raw = data.get("target_urls", "")
    if isinstance(target_urls_raw, list):
        urls = [u.strip() for u in target_urls_raw if u and u.strip()]
    elif isinstance(target_urls_raw, str):
        urls = _parse_url_list(target_urls_raw)
    else:
        return jsonify({"error": "target_urls 不能为空"}), 400

    valid_urls = []
    for url in urls:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        valid_urls.append(url)

    if not valid_urls:
        return jsonify({"error": "至少需要一个有效的目标 URL"}), 400

    options = {
        "verify_ssl": bool(data.get("verify_ssl", False)),
        "timeout": int(data.get("timeout", 20)),
        "concurrency": int(data.get("concurrency", 3)),
        "rate_profile": data.get("rate_profile", "balanced"),
    }
    paths = data.get("paths")
    if isinstance(paths, list) and paths:
        options["paths"] = paths

    auth = data.get("auth")
    if isinstance(auth, dict) and auth:
        options["auth"] = auth

    basic_id = str(uuid.uuid4())[:8]
    with _basic_lock:
        _basic_jobs[basic_id] = {
            "id": basic_id,
            "target_urls": valid_urls,
            "status": "pending",
            "created": time.time(),
            "created_at": datetime.now().isoformat(),
            "results": [],
            "errors": [],
            "error": None,
            "auth": options.get("auth"),
        }

    thread = threading.Thread(
        target=_run_basic_scan_in_thread,
        args=(basic_id, valid_urls, options),
        daemon=True,
    )
    thread.start()

    return jsonify({
        "basic_id": basic_id,
        "status": "pending",
        "total": len(valid_urls),
    }), 201


@app.route("/api/basic_scan/<basic_id>", methods=["GET"])
def get_basic_scan(basic_id):
    """获取基本扫描任务状态与结果。"""
    with _basic_lock:
        job = _basic_jobs.get(basic_id)
    if not job:
        return jsonify({"error": "基本扫描任务不存在"}), 404

    return jsonify({
        "basic_id": basic_id,
        "status": job.get("status"),
        "target_urls": job.get("target_urls"),
        "auth": job.get("auth"),
        "results": job.get("results", []),
        "errors": job.get("errors", []),
        "error": job.get("error"),
        "created_at": job.get("created_at"),
        "completed_at": job.get("completed_at"),
    })

# ── 手动登录 Token 提取（启动 headed 浏览器，用户手动完成滑块等验证码）──

_manual_login_jobs: dict[str, dict] = {}
_manual_login_lock = threading.Lock()


def _detect_system_default_browser() -> Optional[str]:
    """检测可用浏览器路径，优先 Chrome，其次系统默认浏览器。

    搜索顺序：
    1. Chrome（稳定版/Beta/Dev/Canary）
    2. 系统默认浏览器（仅限 Chromium 内核：Edge/360/Brave/Opera）
    3. 如果都没有，返回 None（Playwright 回退到内置 Chromium）
    """
    system = platform.system().lower()
    is_windows = system in ("windows", "win32")

    if is_windows:
        # ── 步骤 1：优先搜索 Chrome ──
        chrome_candidates = [
            os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%ProgramFiles%\Google\Chrome Beta\Application\chrome.exe"),
            os.path.expandvars(r"%ProgramFiles%\Google\Chrome Dev\Application\chrome.exe"),
            os.path.expandvars(r"%ProgramFiles%\Google\Chrome SxS\Application\chrome.exe"),
        ]
        # 也尝试从环境变量 PATH 中找
        for path_dir in os.environ.get("PATH", "").split(os.pathsep):
            candidate = os.path.join(path_dir, "chrome.exe")
            if candidate not in chrome_candidates:
                chrome_candidates.append(candidate)

        for candidate in chrome_candidates:
            if os.path.isfile(candidate):
                return candidate

        # ── 步骤 2：读取注册表中的系统默认浏览器 ──
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice",
            ) as key:
                progid, _ = winreg.QueryValueEx(key, "Progid")
            if progid:
                with winreg.OpenKey(
                    winreg.HKEY_CLASSES_ROOT,
                    rf"{progid}\shell\open\command",
                ) as key:
                    command, _ = winreg.QueryValueEx(key, "")
                if command:
                    try:
                        import shlex
                        parts = shlex.split(command)
                        exe = parts[0]
                    except Exception:
                        exe = command.strip().strip('"').split('"')[0]
                    if exe and os.path.isfile(exe):
                        lower = exe.lower()
                        if any(b in lower for b in ["chrome", "edge", "360", "brave", "opera"]):
                            return exe
        except Exception:
            pass

        # ── 步骤 3：搜索 Edge（常见回退） ──
        edge_candidates = [
            os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
            os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
            os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\Application\msedge.exe"),
        ]
        for candidate in edge_candidates:
            if os.path.isfile(candidate):
                return candidate
    # Fallback: 常见路径
    common_paths = []
    if system == "windows" or system == "win32":
        common_paths = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\Application\msedge.exe"),
            r"C:\Program Files (x86)\360\360chrome\Chrome\Application\360chrome.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\360Chrome\Chrome\Application\360chrome.exe"),
            r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\Application\brave.exe"),
            r"C:\Program Files\Opera\launcher.exe",
            r"C:\Program Files (x86)\Opera\launcher.exe",
        ]
    elif system == "darwin":
        common_paths = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
            "/Applications/Opera.app/Contents/MacOS/Opera",
        ]
    else:
        common_paths = [
            "/usr/bin/google-chrome",
            "/usr/bin/chromium-browser",
            "/usr/bin/chromium",
            "/usr/bin/microsoft-edge",
            "/usr/bin/brave-browser",
            "/usr/bin/opera",
        ]
    for p in common_paths:
        try:
            if os.path.isfile(p):
                return p
        except Exception:
            continue
    return None


def _extract_tokens_from_text(text: str) -> dict[str, str]:
    """从文本片段中提取 token/jwt/apikey 等敏感值。"""
    findings: dict[str, str] = {}
    if not text or len(text) > 5 * 1024 * 1024:
        return findings

    # JWT (HS256/RS256/ES256)
    jwt_match = re.search(
        r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}", text
    )
    if jwt_match:
        findings["jwt"] = jwt_match.group(0)

    # access_token / id_token / refresh_token
    for token_name in ["access_token", "id_token", "refresh_token"]:
        m = re.search(
            rf'(?i)["\']?{token_name}["\']?\s*[:=]\s*["\']([^"\']+)["\']', text
        )
        if m and not findings.get(token_name):
            findings[token_name] = m.group(1)

    # api_key / apikey / api-key / x-api-key
    api_match = re.search(
        r'(?i)["\']?(?:api_key|apikey|api-key|x-api-key)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        text,
    )
    if api_match:
        findings["api_key"] = api_match.group(1)

    # Bearer token
    bearer_match = re.search(
        r"(?i)bearer\s+([A-Za-z0-9_\-\.]{20,})", text
    )
    if bearer_match:
        findings["bearer"] = bearer_match.group(1)

    # 常见平台 API key 格式
    for pattern, name in [
        (r"sk-proj-[a-zA-Z0-9\-]{20,}", "openai_api_key"),
        (r"sk-[a-zA-Z0-9]{20,}", "openai_api_key"),
        (r"xai-[a-zA-Z0-9]{20,}", "xai_api_key"),
        (r"AIza[0-9A-Za-z_-]{30,}", "google_api_key"),
    ]:
        m = re.search(pattern, text)
        if m:
            findings[name] = m.group(0)
            break

    return findings


def _parse_manual_credentials(text: str, source_url: str = "") -> dict:
    """解析用户从浏览器 DevTools 复制来的请求头或 cURL，提取认证凭据。

    支持两种常见粘贴格式：
    1. cURL 命令（多行 -H 'Name: Value' 或 --header "Name: Value"）
    2. Chrome/Firefox DevTools 「Copy request headers」生成的纯文本（Name: Value 每行）

    返回结构兼容现有 save_credentials / 前端回填逻辑。
    """
    result: dict[str, any] = {
        "headers": {},
        "cookies": {},
        "cookie_string": "",
        "authorization": "",
        "bearer": "",
        "jwt": "",
        "access_token": "",
        "id_token": "",
        "api_key": "",
        "custom_headers": {},
        "request_url": "",
        "source_url": source_url.strip(),
    }
    if not text or not text.strip():
        return result

    raw = text.strip()
    is_curl = raw.lower().startswith("curl ")

    # 1) 从 cURL 中提取目标 URL
    if is_curl:
        url_match = re.search(r"\s['\"]?((https?://)[^\s'\"]+)['\"]?", raw)
        if url_match:
            result["request_url"] = url_match.group(1).strip().strip("'\";")

    # 2) 提取 headers：同时支持 cURL -H/--header 和 DevTools 纯文本
    headers: dict[str, str] = {}
    if is_curl:
        # 先去掉 cURL 行继续符（\ 或 ^），把多行拼接成一行再解析
        normalized = re.sub(r"\s*[\\^]\s*\n\s*", " ", raw)
        # -H 'Name: Value' 或 --header "Name: Value"，允许跨多行
        for m in re.finditer(r"(?:-\^?H|--header)\s+['\"](.+?)['\"](?=\s+(?:-[A-Za-z-]|\s*$))", normalized, re.DOTALL):
            line = m.group(1).replace("\\n", "\n").strip()
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.strip()] = value.strip()
    else:
        # DevTools 纯文本：Authorization: Bearer xxx\nCookie: a=1; b=2
        for line in raw.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            # 跳过 HTTP 方法行，如 GET /path HTTP/1.1
            if re.match(r"^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+", line, re.I):
                continue
            name, value = line.split(":", 1)
            headers[name.strip()] = value.strip()

    result["headers"] = headers

    # 3) 解析关键认证头
    for key, val in headers.items():
        lk = key.lower()
        if lk == "authorization":
            result["authorization"] = val
            if val.lower().startswith("bearer "):
                result["bearer"] = val[7:].strip()
        elif lk == "cookie":
            result["cookie_string"] = val
            try:
                sc = http.cookies.SimpleCookie()
                sc.load(val)
                result["cookies"] = {k: v.value for k, v in sc.items()}
            except Exception:
                # 简单兜底解析
                result["cookies"] = {}
                for part in val.split(";"):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        result["cookies"][k.strip()] = v.strip()
        elif lk in ("x-api-key", "api-key", "x-auth-token"):
            result["api_key"] = val
            result["custom_headers"][key] = val
        elif lk in ("referer", "origin", "user-agent", "x-requested-with"):
            result["custom_headers"][key] = val

    # 4) 用通用 token 提取器再扫一遍
    tokens = _extract_tokens_from_text(raw)
    if tokens.get("jwt"):
        result["jwt"] = tokens["jwt"]
    if tokens.get("bearer"):
        result["bearer"] = tokens["bearer"]
    if tokens.get("access_token"):
        result["access_token"] = tokens["access_token"]
    if tokens.get("id_token"):
        result["id_token"] = tokens["id_token"]
    if tokens.get("api_key"):
        result["api_key"] = result["api_key"] or tokens["api_key"]

    # 5) 若 source_url 提供但 request_url 未解析出，回退使用 source_url
    if not result["request_url"] and result["source_url"]:
        result["request_url"] = result["source_url"]

    # 6) 最终 access_token 优先级：access_token > bearer > jwt
    result["access_token"] = (
        result["access_token"] or result["bearer"] or result["jwt"] or ""
    )

    return result


def _run_manual_login_in_thread(
    job_id: str,
    login_url: str,
    username: str,
    password: str,
    chrome_path: Optional[str] = None,
    keep_open_seconds: int = 0,
    auto_devtools: bool = False,
    auto_submit: bool = True,
):
    """在独立线程中启动 headed 浏览器，等用户手动完成登录后提取 token。

    支持：
    - 自动检测系统默认浏览器并启动；
    - 增强反检测参数，降低被目标站风控拦截的概率；
    - 监听网络请求/响应，自动提取 Cookie、Authorization、JWT、api_key 等；
    - 登录成功后保持窗口打开以便按 F12 抓取数据。
    """
    job = _manual_login_jobs.get(job_id)
    if not job:
        return

    async def _run():
        # 优先使用 Patchright（CDP 层反检测），回退标准 Playwright
        try:
            from patchright.async_api import async_playwright
            _using_patchright = True
        except ImportError:
            from playwright.async_api import async_playwright
            _using_patchright = False

        async with async_playwright() as p:
            # 优先使用用户指定的浏览器路径，否则自动检测系统默认浏览器
            exe_path = chrome_path or _detect_system_default_browser()

            # 创建独立的临时用户数据目录，避免旧缓存/cookie 污染页面显示
            user_data_dir = os.path.join(str(OUTPUT_DIR), f"chrome_profile_{job_id}")
            os.makedirs(user_data_dir, exist_ok=True)

            launch_args = [
                # 核心反检测
                "--disable-blink-features=AutomationControlled",
                "--disable-features=IsolateOrigins,site-per-process,AutomationControlled",
                # 禁用自动化标记
                "--disable-infobars",
                "--no-first-run",
                "--no-default-browser-check",
                "--no-service-autorun",
                "--disable-default-apps",
                "--disable-extensions",
                "--disable-dev-shm-usage",
                # 网络/证书
                "--ignore-certificate-errors",
                "--ignore-urlfetcher-cert-requests",
                "--disable-web-security",
                # 性能/稳定性
                "--disable-background-networking",
                "--disable-background-timer-throttling",
                "--disable-backgrounding-occluded-windows",
                "--disable-breakpad",
                "--disable-component-update",
                "--disable-domain-reliability",
                "--disable-hang-monitor",
                "--disable-ipc-flooding-protection",
                "--disable-renderer-backgrounding",
                "--disable-sync",
                "--disable-translate",
                "--metrics-recording-only",
                "--mute-audio",
                "--no-pings",
                # 窗口外观
                "--window-size=1440,900",
                "--window-position=120,60",
            ]
            if auto_devtools:
                launch_args.append("--auto-open-devtools-for-tabs")

            launch_options = {
                "headless": False,
                "args": launch_args,
                "viewport": {"width": 1440, "height": 900},
                "locale": "zh-CN",
                "timezone_id": "Asia/Shanghai",
                "ignore_https_errors": True,
                "user_agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/131.0.0.0 Safari/537.36"
                ),
                "bypass_csp": True,
            }
            if exe_path:
                launch_options["executable_path"] = exe_path
                job["message"] = f"正在启动系统浏览器: {exe_path}"
            else:
                engine = "Patchright" if _using_patchright else "Playwright 内置 Chromium"
                job["message"] = f"正在启动 {engine}..."

            # 手动登录任务启用 HAR 录制，便于事后从网络归档中提取 Authorization 等凭据
            har_path = str(OUTPUT_DIR / f"manual_login_{job_id}.har")
            launch_options["record_har_path"] = har_path

            # 使用持久化上下文，模拟真实浏览器用户配置
            context = await p.chromium.launch_persistent_context(
                user_data_dir, **launch_options
            )
            page = await context.new_page()


            # 反检测：patchright 已在 CDP/二进制层处理，playwright-stealth 作为 JS 层叠加
            if not _using_patchright:
                try:
                    from playwright_stealth import Stealth
                    stealth = Stealth()
                    await stealth.apply_stealth_async(page)
                except Exception:
                    pass

            # 网络请求监听器，收集认证凭据（注册在 context 级别，捕获所有页面/弹窗/跨域请求）
            captured: dict = {
                "headers": {},  # 敏感请求/响应头
                "tokens": {},   # 从 URL/响应体/请求头提取的 token
                "network_log": [],
            }

            async def _handle_request(request):
                try:
                    headers = request.headers
                    url = request.url
                    method = request.method
                    sensitive_keys = [
                        "authorization", "cookie", "x-api-key", "api-key",
                        "x-auth-token", "x-requested-with", "referer", "origin",
                    ]
                    for key in sensitive_keys:
                        val = headers.get(key)
                        if val:
                            captured["headers"][key] = val
                    # 从 Authorization 头中提取 bearer
                    auth = headers.get("authorization", "")
                    if auth:
                        captured["headers"]["authorization"] = auth
                        tokens = _extract_tokens_from_text(auth)
                        captured["tokens"].update(tokens)
                    # 记录关键请求日志
                    captured["network_log"].append({
                        "url": url,
                        "method": method,
                        "headers": {k: headers[k] for k in sensitive_keys if k in headers},
                    })
                except Exception:
                    pass

            async def _handle_response(response):
                try:
                    headers = response.headers
                    url = response.url
                    sensitive_keys = [
                        "set-cookie", "authorization", "x-api-key", "x-auth-token",
                        "www-authenticate",
                    ]
                    for key in sensitive_keys:
                        val = headers.get(key)
                        if val:
                            captured["headers"][key] = val
                    # 读取响应体并提取 token（限制大小避免阻塞）
                    try:
                        body = await response.body()
                        if 0 < len(body) < 2 * 1024 * 1024:
                            text = body.decode("utf-8", errors="ignore")
                            tokens = _extract_tokens_from_text(text)
                            if tokens:
                                captured["tokens"].update(tokens)
                    except Exception:
                        pass
                except Exception:
                    pass

            context.on("request", lambda req: asyncio.create_task(_handle_request(req)))
            context.on("response", lambda resp: asyncio.create_task(_handle_response(resp)))

            try:
                # 1) 导航到登录页
                job["status"] = "navigating"
                job["message"] = "正在加载登录页面..."
                await page.goto(login_url, wait_until="networkidle", timeout=30000)

                # 记录初始 cookie 数量，用于后续变化检测
                initial_cookies = await context.cookies()
                initial_cookie_count = len(initial_cookies)
                initial_cookie_names = {c["name"] for c in initial_cookies}

                # 2) 如果提供了凭据，自动填写用户名和密码（拟人输入触发前端校验）
                if username:
                    job["status"] = "filling"
                    job["message"] = "正在填写账号密码..."

                    async def _fill_field(page, selectors, value):
                        for sel in selectors:
                            try:
                                el = await page.wait_for_selector(sel, timeout=2000)
                                if not el:
                                    continue
                                await el.click()
                                await asyncio.sleep(random.uniform(0.2, 0.6))
                                await el.fill("")
                                await page.keyboard.type(value, delay=random.randint(30, 120))
                                await asyncio.sleep(random.uniform(0.2, 0.5))
                                await el.evaluate(
                                    """el => {
                                        el.dispatchEvent(new InputEvent('input', { bubbles: true, composed: true }));
                                        el.dispatchEvent(new Event('change', { bubbles: true }));
                                        el.dispatchEvent(new FocusEvent('blur', { bubbles: true }));
                                        if (el.form) {
                                            Array.from(el.form.elements).forEach(e => {
                                                e.dispatchEvent(new Event('input', { bubbles: true }));
                                                e.dispatchEvent(new Event('change', { bubbles: true }));
                                            });
                                        }
                                    }"""
                                )
                                return True
                            except Exception:
                                continue
                        return False

                    username_selectors = [
                        'input[name="username"]', 'input[name="UserName"]',
                        'input[name="account"]', 'input[name="user"]',
                        'input[name="email"]', 'input[type="text"]',
                        '#username', '#UserName', '#account',
                    ]
                    await _fill_field(page, username_selectors, username)

                    password_selectors = [
                        'input[name="password"]', 'input[name="Password"]',
                        'input[name="passwd"]', 'input[type="password"]',
                        '#password', '#Password',
                    ]
                    await _fill_field(page, password_selectors, password)

                    # 勾选用户协议/隐私政策/服务条款复选框
                    job["message"] = "正在勾选用户协议..."
                    agreement_selectors = [
                        'input[type="checkbox"]',
                        'input[name="agreement"]', 'input[name="protocol"]',
                        'input[name="terms"]', 'input[name="consent"]',
                        'input[name="policy"]',
                        '.ant-checkbox-input', '.ant-checkbox-wrapper input',
                        '.el-checkbox__original', '.el-checkbox__input',
                        '.ivu-checkbox-input', '.ivu-checkbox-wrapper input',
                        ':text("同意") input[type="checkbox"]',
                        ':text("协议") input[type="checkbox"]',
                        ':text("我已阅读") input[type="checkbox"]',
                    ]
                    for sel in agreement_selectors:
                        try:
                            cb = await page.wait_for_selector(sel, timeout=1500)
                            if not cb:
                                continue
                            is_checked = await cb.evaluate("el => el.checked")
                            if is_checked:
                                continue
                            await cb.click()
                            await asyncio.sleep(random.uniform(0.1, 0.3))
                            await cb.evaluate(
                                """el => {
                                    el.checked = true;
                                    el.setAttribute('checked', 'checked');
                                    el.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
                                    el.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
                                    el.dispatchEvent(new MouseEvent('click', { bubbles: true, composed: true }));
                                    if (el.form) {
                                        Array.from(el.form.elements).forEach(e => {
                                            e.dispatchEvent(new Event('change', { bubbles: true }));
                                        });
                                    }
                                }"""
                            )
                            job["message"] = "已勾选用户协议"
                            break
                        except Exception:
                            continue

                    # 若前端因校验状态未更新导致登录按钮仍禁用，尝试强制启用常见提交按钮

                    try:
                        await page.evaluate(
                            """() => {
                                document.querySelectorAll('button, input[type="submit"]').forEach(btn => {
                                    if (btn.disabled || btn.getAttribute('disabled')) {
                                        btn.removeAttribute('disabled');
                                        btn.disabled = false;
                                    }
                                });
                            }"""
                        )
                    except Exception:
                        pass


                # 辅助：检测滑块/验证码是否已验证通过（支持普通滑块、极验 geetest 等）


                async def _is_slider_passed(page):
                    # 1) 普通文字提示
                    try:
                        if await page.locator("text=验证通过").count() > 0:
                            return True
                    except Exception:
                        pass
                    try:
                        text_ok = await page.evaluate(
                            """() => {
                                const t = document.body.innerText;
                                return t.includes('验证通过') || t.includes('验证成功') || t.includes('滑动验证成功');
                            }"""
                        )
                        if text_ok:
                            return True
                    except Exception:
                        pass

                    # 2) 极验 geetest 验证结果：隐藏字段或 JS 对象
                    try:
                        geetest_filled = await page.evaluate(
                            """() => {
                                const selectors = [
                                    'input[name="geetest_challenge"]',
                                    'input[name="geetest_validate"]',
                                    'input[name="geetest_seccode"]',
                                    'input[name="geetest_captcha_id"]',
                                    '[name="geetest_challenge"]',
                                    '[name="geetest_validate"]',
                                ];
                                for (const s of selectors) {
                                    const el = document.querySelector(s);
                                    if (el && el.value && el.value.length > 10) return true;
                                }
                                // 常见极验变量名
                                for (const name of ['captchaObj', 'geetest', 'gtcaptcha', 'initGeetest']) {
                                    const obj = window[name];
                                    if (obj && typeof obj.getValidate === 'function') {
                                        const v = obj.getValidate();
                                        if (v && (v.geetest_validate || v.validate || v.challenge)) return true;
                                    }
                                }
                                return false;
                            }"""
                        )
                        if geetest_filled:
                            return True
                    except Exception:
                        pass

                    return False

                # 辅助：自动点击登录按钮

                async def _click_login_button(page):
                    login_btn_selectors = [
                        'button[type="submit"]',
                        'input[type="submit"]',
                        '.login-btn',
                        '.submit-btn',
                        '.login-button',
                        '#login-btn',
                        'button:has-text("登录")',
                        'button:has-text("登 录")',
                        '.btn-primary:has-text("登录")',
                        '.ant-btn:has-text("登录")',
                        '.el-button:has-text("登录")',
                        'button:has-text("Login")',
                        'button:has-text("Sign in")',
                    ]
                    for sel in login_btn_selectors:
                        try:
                            btn = await page.wait_for_selector(sel, timeout=800)
                            if not btn:
                                continue
                            await btn.click()
                            return True
                        except Exception:
                            continue
                    return False

                # OTP/验证码 前置场景：仅在 auto_submit 开启时，填完账号密码后自动点击一次登录按钮，
                # 以触发 OTP 发送、极验/滑块验证码等二次验证流程。纯手动模式下完全由用户控制，
                # 避免程序反复触发验证码导致页面异常或验证重复弹出。
                _form_submitted = False
                if username and auto_submit:
                    try:
                        has_otp_input = await page.locator(
                            'input[placeholder*="验证码"], input[placeholder*="code"], input[placeholder*="OTP"], input[name*="code"], input[name*="otp"], input[name*="sms"], input[type="text"][maxlength="6"]'
                        ).count() > 0
                        has_send_code_btn = await page.locator(
                            'button:has-text("发送验证码"), button:has-text("获取验证码"), button:has-text("发送短信"), button:has-text("获取短信"), .send-code-btn, .get-code-btn, .sms-btn'
                        ).count() > 0
                        if has_otp_input or has_send_code_btn:
                            job["message"] = "检测到 OTP 页面，自动点击登录按钮触发验证码..."
                            await _click_login_button(page)
                            _form_submitted = True
                            await asyncio.sleep(1.5)
                    except Exception:
                        pass

                    # 若未触发 OTP，尝试点击登录按钮以弹出极验/滑块等二次验证
                    if not _form_submitted:
                        try:
                            already_passed = await _is_slider_passed(page)
                            if not already_passed:
                                job["message"] = "正在点击登录按钮以触发验证码..."
                                await _click_login_button(page)
                                _form_submitted = True
                                await asyncio.sleep(1.5)
                        except Exception:
                            pass

                # 3) 等待用户手动完成滑块验证码并登录


                job["status"] = "waiting"
                if auto_submit:
                    job["message"] = "请在弹出的浏览器中手动拖动滑块验证码并完成登录... (剩余 300 秒)"
                else:
                    job["message"] = "已启用纯手动模式：请在浏览器中自行输入/点击并完成登录，系统只负责监听和提取... (剩余 300 秒)"
                    # 纯手动模式下多给用户一些初始时间看清页面
                    await asyncio.sleep(2)

                import urllib.parse as _up

                detected = False
                detected_reason = ""
                detected_access_token = ""
                detected_id_token = ""
                login_after_url = page.url

                slider_clicked_after_pass = False
                _otp_sent = False
                _otp_submitted = False
                for i in range(300):
                    await asyncio.sleep(1)

                    # 每 2 秒检测一次滑块/OTP 验证状态（纯手动模式下不自动代点）
                    if i % 2 == 0 and auto_submit:
                        # --- 滑块验证：验证通过后自动点击登录 ---
                        try:
                            is_passed = await _is_slider_passed(page)
                            if is_passed and not slider_clicked_after_pass:
                                job["message"] = "检测到滑块验证通过，正在自动点击登录..."
                                if await _click_login_button(page):
                                    slider_clicked_after_pass = True
                            elif not is_passed:
                                slider_clicked_after_pass = False
                        except Exception:
                            pass

                        # --- OTP：自动点击“发送验证码”按钮 ---
                        if not _otp_sent:
                            try:
                                send_btn_selectors = [
                                    'button:has-text("发送验证码")',
                                    'button:has-text("获取验证码")',
                                    'button:has-text("发送短信")',
                                    'button:has-text("获取短信")',
                                    'button:has-text("发送")',
                                    'span:has-text("发送验证码")',
                                    'span:has-text("获取验证码")',
                                    '.send-code-btn', '.get-code-btn', '.sms-btn',
                                    '.code-btn', '.verify-code-btn',
                                    'a:has-text("发送验证码")', 'a:has-text("获取验证码")',
                                ]
                                for sel in send_btn_selectors:
                                    try:
                                        btn = await page.wait_for_selector(sel, timeout=600)
                                        if not btn:
                                            continue
                                        await btn.click()
                                        _otp_sent = True
                                        slider_clicked_after_pass = False
                                        job["message"] = "已自动点击发送验证码，请查收短信..."
                                        break
                                    except Exception:
                                        continue
                            except Exception:
                                pass

                        # --- OTP：检测验证码输入完成并自动提交 ---
                        if not _otp_submitted:
                            try:
                                otp_input_selectors = [
                                    'input[placeholder*="验证码"]',
                                    'input[placeholder*="验证码"]:not([type="hidden"])',
                                    'input[placeholder*="code"]:not([type="hidden"])',
                                    'input[placeholder*="Code"]:not([type="hidden"])',
                                    'input[placeholder*="otp"]:not([type="hidden"])',
                                    'input[placeholder*="OTP"]:not([type="hidden"])',
                                    'input[name*="code"]:not([type="hidden"])',
                                    'input[name*="verify"]:not([type="hidden"])',
                                    'input[name*="otp"]:not([type="hidden"])',
                                    'input[name*="sms"]:not([type="hidden"])',
                                    'input[type="text"][maxlength="6"]',
                                    'input[type="text"][maxlength="4"]',
                                    'input[type="number"][maxlength="6"]',
                                ]
                                for sel in otp_input_selectors:
                                    try:
                                        inp = await page.wait_for_selector(sel, timeout=400)
                                        if not inp:
                                            continue
                                        val = await inp.input_value()
                                        if val and 4 <= len(val.strip()) <= 8:
                                            _otp_submitted = True
                                            job["message"] = f"检测到验证码已输入 ({len(val.strip())}位)，正在自动提交..."
                                            await _click_login_button(page)
                                            break
                                    except Exception:
                                        continue
                            except Exception:
                                pass

                    # 当前 URL 发生跳转后，如果仍在等待，重置 OTP 状态（可能进入新的 OTP 页面）
                    current_url = page.url
                    if current_url != login_after_url and not detected:
                        _otp_sent = False
                        _otp_submitted = False
                    login_after_url = current_url

                    # 每 10 秒输出一次当前 URL，便于排查
                    if i % 10 == 0:
                        job["detail_url"] = current_url

                    # 条件 A：URL 中是否包含 access_token（OIDC 回调）
                    token_match = re.search(r'access_token=([^&\s#]+)', current_url)
                    if token_match:
                        detected_access_token = _up.unquote(token_match.group(1))
                        detected = True
                        detected_reason = "URL 中检测到 access_token"
                        job["message"] = "URL 中检测到 access_token，正在提取凭据..."
                        break

                    # 条件 B：URL 中是否包含 id_token
                    id_match = re.search(r'id_token=([^&\s#]+)', current_url)
                    if id_match:
                        detected_id_token = _up.unquote(id_match.group(1))
                        detected = True
                        detected_reason = "URL 中检测到 id_token"
                        job["message"] = "URL 中检测到 id_token，正在提取凭据..."
                        break

                    # 条件 C：URL 跳转离开登录页（同域跳转、hash 路由也支持）
                    parsed_login = _up.urlparse(login_url)
                    parsed_current = _up.urlparse(current_url)
                    login_path_stripped = parsed_login.path.strip("/")
                    current_path_stripped = parsed_current.path.strip("/")
                    current_fragment = parsed_current.fragment or ""
                    is_auth_related = any(
                        kw in parsed_current.netloc.lower() for kw in ("passport", "cas", "sso", "oauth")
                    ) or any(
                        kw in (parsed_current.path.lower() + current_fragment.lower())
                        for kw in ("login", "signin", "auth", "passport")
                    )
                    logged_in_fragments = ("/home", "/dashboard", "/main", "/index", "/workspace", "/portal")
                    is_logged_in_fragment = any(
                        frag in current_fragment.lower() for frag in logged_in_fragments
                    )
                    if (
                        (login_path_stripped != current_path_stripped or is_logged_in_fragment)
                        and not is_auth_related
                    ):
                        detected = True
                        detected_reason = "页面已跳转离开登录页"
                        job["message"] = "检测到登录成功页面跳转..."
                        break


                    # 条件 D：网络请求中已捕获认证凭据
                    if captured["tokens"].get("access_token") or captured["tokens"].get("jwt"):
                        detected_access_token = (
                            captured["tokens"].get("access_token")
                            or captured["tokens"].get("jwt")
                            or ""
                        )
                        detected = True
                        detected_reason = "网络请求中检测到 access_token/jwt"
                        job["message"] = "网络请求中检测到认证凭据，正在提取..."
                        break

                    if captured["headers"].get("authorization"):
                        detected = True
                        detected_reason = "网络请求中检测到 Authorization 头"
                        job["message"] = "网络请求中检测到 Authorization 头..."
                        break

                    # 条件 E：Cookie 数量/内容发生登录态变化
                    if i % 3 == 0:
                        try:
                            browser_cookies = await context.cookies()
                            current_cookie_names = {c["name"] for c in browser_cookies}
                            new_names = current_cookie_names - initial_cookie_names
                            if new_names and (
                                any(
                                    k.lower() in ["session", "token", "auth", "userid", "login"]
                                    for k in new_names
                                )
                                or len(current_cookie_names) - initial_cookie_count >= 2
                            ):
                                detected = True
                                detected_reason = "检测到登录态 Cookie 新增"
                                job["message"] = "检测到登录态 Cookie 变化..."
                                break
                        except Exception:
                            pass

                    # 条件 F：页面出现登录成功 UI 元素（如"欢迎""退出登录""个人中心"等）
                    if i % 3 == 0:
                        try:
                            success_texts = [
                                "欢迎", "退出登录", "退出", "个人中心", "我的",
                                "账号管理", "安全中心", "修改密码", "个人资料",
                            ]
                            for text in success_texts:
                                if await page.locator(f"text={text}").count() > 0:
                                    detected = True
                                    detected_reason = f"页面中出现登录成功元素: {text}"
                                    job["message"] = f"检测到登录成功（{text}）..."
                                    break
                            if detected:
                                break
                        except Exception:
                            pass

                    # 更新进度
                    remain = 300 - i
                    if i % 5 == 0:
                        job["remain_seconds"] = remain
                        job["message"] = f"请在弹出的浏览器中手动拖动滑块验证码并完成登录... (剩余 {remain} 秒)"

                if not detected:
                    job["status"] = "timeout"
                    job["message"] = "登录超时 (300秒)，请重试"
                    return

                # 4) 登录成功后继续监听 8 秒，让 SPA 页面加载并发起带 Authorization 的请求
                job["message"] = "登录成功，继续监听网络请求提取 Authorization..."
                for _j in range(8):
                    await asyncio.sleep(1)
                    if captured["headers"].get("authorization") or captured["tokens"].get("bearer"):
                        job["message"] = "已捕获到 Authorization 头，准备提取..."
                        break


                # 5) 提取所有 cookies
                browser_cookies = await context.cookies()
                cookie_dict = {c["name"]: c["value"] for c in browser_cookies}
                cookie_string = "; ".join(f"{k}={v}" for k, v in cookie_dict.items())

                # 6) 检查 localStorage/sessionStorage 中的 token（支持多种常见字段名）
                try:
                    storage_keys = [
                        "access_token", "token", "id_token", "refresh_token",
                        "jwt", "auth", "authorization", "user_token", "userToken",
                    ]
                    storage_script = """
                        () => {
                            const keys = %s;
                            for (const store of [localStorage, sessionStorage]) {
                                for (const k of keys) {
                                    const v = store.getItem(k);
                                    if (v && v.length >= 8) return { store: store === localStorage ? "localStorage" : "sessionStorage", key: k, value: v };
                                }
                            }
                            return null;
                        }
                    """ % str(storage_keys).replace("'", '"')
                    storage_token = await page.evaluate(storage_script)
                    if storage_token and not detected_access_token:
                        detected_access_token = storage_token["value"]
                        detected_reason = detected_reason or f"从 {storage_token['store']}.{storage_token['key']} 中提取到 token"
                except Exception:
                    pass


                # 7) 从网络捕获中整理最终凭据
                auth_header = captured["headers"].get("authorization", "")
                bearer_value = captured["tokens"].get("bearer", "")
                jwt_value = captured["tokens"].get("jwt", "")
                api_key_value = captured["tokens"].get("api_key", "")
                if not detected_access_token:
                    detected_access_token = jwt_value or bearer_value or ""

                # 收集自定义 headers（推荐附加到认证探测）
                custom_headers: dict[str, str] = {}
                for key in ["x-requested-with", "referer", "origin"]:
                    val = captured["headers"].get(key)
                    if val:
                        custom_headers[key] = val

                # 8) 截图保存
                screenshot_path = str(OUTPUT_DIR / f"manual_login_{job_id}.png")
                await page.screenshot(path=screenshot_path, full_page=True)

                # 9) 返回结果
                job["status"] = "success"
                job["message"] = "登录成功！已提取 Token 和 Cookie"
                job["result"] = {
                    "access_token": detected_access_token,
                    "id_token": detected_id_token or captured["tokens"].get("id_token", ""),
                    "cookies": cookie_dict,
                    "cookie_string": cookie_string,
                    "authorization": auth_header,
                    "bearer": bearer_value,
                    "jwt": jwt_value,
                    "api_key": api_key_value,
                    "custom_headers": custom_headers,
                    "captured_tokens": captured["tokens"],
                    "captured_headers": captured["headers"],
                    "detected_reason": detected_reason,
                    "login_url_after": login_after_url,
                    "screenshot": screenshot_path,
                    "har_file": har_path,
                    "network_log_count": len(captured["network_log"]),
                }

                # 如果配置保持窗口打开，等待用户按 F12 抓取网络数据
                if keep_open_seconds > 0:
                    job["message"] = (
                        f"登录成功！已提取 Token 和 Cookie。浏览器将保持打开 {keep_open_seconds}s，"
                        f"可按 F12 打开 DevTools 抓取网络数据..."
                    )
                    try:
                        await asyncio.sleep(keep_open_seconds)
                    except Exception:
                        pass

            except Exception as e:
                import traceback as _tb
                job["status"] = "failed"
                job["error"] = str(e)
                job["traceback"] = _tb.format_exc()
            finally:
                try:
                    await context.close()
                except Exception:
                    pass
                # 清理本次任务独立的临时 profile，避免目录堆积
                try:
                    shutil.rmtree(user_data_dir, ignore_errors=True)
                except Exception:
                    pass

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_run())
    finally:
        loop.close()




@app.route("/api/auth/manual_login", methods=["POST"])
def create_manual_login():
    """启动手动登录浏览器，提取 OIDC access_token 和 Cookie。"""
    data = request.get_json(silent=True) or {}
    login_url = (data.get("login_url") or "").strip()
    if not login_url:
        return jsonify({"error": "login_url 不能为空"}), 400

    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    chrome_path = (data.get("chrome_path") or "").strip() or None
    keep_open_seconds = data.get("keep_open_seconds", 0)
    try:
        keep_open_seconds = int(keep_open_seconds)
    except (ValueError, TypeError):
        keep_open_seconds = 0
    keep_open_seconds = max(0, keep_open_seconds)
    auto_devtools = bool(data.get("auto_devtools", False))
    auto_submit = bool(data.get("auto_submit", True))

    job_id = str(uuid.uuid4())[:8]

    with _manual_login_lock:
        _manual_login_jobs[job_id] = {
            "id": job_id,
            "login_url": login_url,
            "status": "starting",
            "message": "正在启动浏览器...",
            "result": None,
            "error": None,
            "created_at": datetime.now().isoformat(),
        }

    t = threading.Thread(
        target=_run_manual_login_in_thread,
        args=(job_id, login_url, username, password, chrome_path, keep_open_seconds, auto_devtools, auto_submit),
        daemon=True,
    )
    t.start()

    return jsonify({
        "job_id": job_id,
        "status": "starting",
        "message": "浏览器即将打开，请手动完成登录",
    }), 201


@app.route("/api/auth/manual_login/<job_id>", methods=["GET"])
def get_manual_login_status(job_id):
    """查询手动登录任务状态。"""
    with _manual_login_lock:
        job = _manual_login_jobs.get(job_id)
    if not job:
        return jsonify({"error": "任务不存在"}), 404

    return jsonify({
        "job_id": job["id"],
        "status": job.get("status"),
        "message": job.get("message"),
        "result": job.get("result"),
        "error": job.get("error"),
    })


@app.route("/api/auth/manual_login/<job_id>/cancel", methods=["POST"])
def cancel_manual_login(job_id):
    """取消手动登录任务。"""
    with _manual_login_lock:
        job = _manual_login_jobs.get(job_id)
        if job and job.get("status") in ("starting", "navigating", "filling", "waiting"):
            job["status"] = "cancelled"
            job["message"] = "任务已取消"
    return jsonify({"ok": True})


@app.route("/api/auth/parse_manual_creds", methods=["POST"])
def parse_manual_credentials():
    """接收用户从浏览器 DevTools 复制来的请求头或 cURL，解析并返回结构化凭据。"""
    data = request.get_json(silent=True) or {}
    text = data.get("text") or ""
    source_url = (data.get("source_url") or "").strip()
    if not text.strip():
        return jsonify({"error": "粘贴内容不能为空"}), 400

    parsed = _parse_manual_credentials(text, source_url)

    # 校验是否解析到有效凭据
    has_value = any(
        parsed.get(k)
        for k in [
            "authorization", "bearer", "jwt", "access_token", "id_token",
            "api_key", "cookie_string", "cookies",
        ]
    )
    if not has_value:
        return jsonify({
            "warning": "未解析到明显凭据，请确认粘贴的是完整请求头或 cURL",
            "parsed": parsed,
        }), 200

    return jsonify({
        "ok": True,
        "parsed": parsed,
        "summary": {
            "has_authorization": bool(parsed.get("authorization")),
            "has_cookie": bool(parsed.get("cookie_string")),
            "has_api_key": bool(parsed.get("api_key")),
            "has_jwt": bool(parsed.get("jwt")),
            "cookie_count": len(parsed.get("cookies") or {}),
        },
    })


# ── 凭据持久化：保存/加载捕获的 Token/Cookie，跨会话复用 ──

_CREDENTIALS_FILE = OUTPUT_DIR / "saved_credentials.json"
_credentials_lock = threading.Lock()


def _load_credentials() -> list[dict]:
    """从文件加载已保存凭据。"""
    try:
        if _CREDENTIALS_FILE.exists():
            return json.loads(_CREDENTIALS_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return []


def _save_credentials(creds: list[dict]):
    """保存凭据到文件。"""
    try:
        _CREDENTIALS_FILE.parent.mkdir(parents=True, exist_ok=True)
        _CREDENTIALS_FILE.write_text(
            json.dumps(creds, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
    except Exception:
        pass


@app.route("/api/auth/saved_credentials", methods=["GET"])
def list_saved_credentials():
    """列出所有已保存凭据。"""
    creds = _load_credentials()
    return jsonify({"credentials": creds})


@app.route("/api/auth/save_credentials", methods=["POST"])
def save_credentials():
    """保存一组 Token/Cookie 凭据。"""
    data = request.get_json(silent=True) or {}
    label = (data.get("label") or f"保存于 {datetime.now().strftime('%Y-%m-%d %H:%M')}").strip()
    target_url = (data.get("target_url") or "").strip()
    credentials = data.get("credentials") or {}

    if not credentials:
        return jsonify({"error": "凭证数据为空"}), 400

    has_value = any(
        credentials.get(k)
        for k in [
            "access_token", "id_token", "cookie", "cookies",
            "authorization", "bearer", "jwt", "api_key", "custom_headers",
        ]
    )
    if not has_value:
        return jsonify({"error": "凭证数据为空（需至少包含一种凭据）"}), 400

    entry = {
        "id": uuid.uuid4().hex[:8],
        "label": label,
        "target_url": target_url,
        "credentials": credentials,
        "created_at": datetime.now().isoformat(),
    }

    with _credentials_lock:
        all_creds = _load_credentials()
        all_creds.append(entry)
        _save_credentials(all_creds)

    return jsonify({"ok": True, "id": entry["id"], "label": entry["label"]}), 201


@app.route("/api/auth/saved_credentials/<cred_id>", methods=["DELETE"])
def delete_saved_credential(cred_id):
    """删除一组已保存凭据。"""
    with _credentials_lock:
        all_creds = _load_credentials()
        before = len(all_creds)
        all_creds = [c for c in all_creds if c["id"] != cred_id]
        if len(all_creds) == before:
            return jsonify({"error": "凭据不存在"}), 404
        _save_credentials(all_creds)

    return jsonify({"ok": True})


if __name__ == "__main__":
    try:
        sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf-8', buffering=1)
    except Exception:
        pass  # Windows / redirected stdout may not support fileno() reopen
    print(f"[RedTeam_AI] Web Dashboard starting...")
    print(f"   URL:    http://127.0.0.1:8086")
    print(f"   Output: {OUTPUT_DIR}")
    print(f"   Pipeline: L0 Recon ✓ | L1 Garak (soon) | L2 Bridge (soon) | L3 Promptfoo (soon) | L4 PyRIT (soon) | L5 Report (soon)")
    app.run(host="0.0.0.0", port=8086, debug=True)
