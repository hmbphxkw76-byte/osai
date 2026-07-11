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
import re
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


def _detect_waf_basic(headers: dict, body: str) -> str:
    """从响应头和响应体中快速识别 WAF / 反爬标记。"""
    text = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    text += " " + body[:2000].lower()
    for kw in _WAF_KEYWORDS:
        if kw in text:
            return kw
    return ""


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

        scanner = DictScanner(
            concurrency=options.get("concurrency", 3),
            timeout=options.get("timeout", 10),
            verify_ssl=options.get("verify_ssl", False),
            rate_profile="balanced",
            llm_paths=_BASIC_SCAN_PATHS,
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
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        "Accept": "text/html,application/json,*/*",
                    },
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
                scan_results = loop.run_until_complete(scanner.scan(url))
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

            results.append({
                "url": url,
                "root_status": root_status,
                "title": title,
                "server": server,
                "waf": waf,
                "auth_required": auth_required,
                "anti_defense": anti["detected"],
                "anti_defense_reason": anti["reason"],
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
        "timeout": int(data.get("timeout", 10)),
        "concurrency": int(data.get("concurrency", 3)),
    }

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
        "results": job.get("results", []),
        "errors": job.get("errors", []),
        "error": job.get("error"),
        "created_at": job.get("created_at"),
        "completed_at": job.get("completed_at"),
    })

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
