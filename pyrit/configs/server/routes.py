"""
===============================================================================
Config Center — 路由 (Blueprint) + 目标探测 + 一键自动配置
===============================================================================
"""
from __future__ import annotations

import asyncio
import logging
import time

import httpx
from flask import Blueprint, render_template, request, jsonify

from . import run_async as _run_async

from .utils import (
    list_env_files,
    list_token_files,
    read_env_file,
    read_token_file,
    validate_and_save_env_file,
    validate_and_save_token_file,
    delete_token_file,
    detect_sensitive_lines,
    check_readiness,
    update_shared_env_variables,
    get_target_config_from_shared,
    get_configs_dir,
)
from .target_config import (
    enumerate_ai_app_endpoints,
    test_target_connection,
)

# 延迟导入 targets 层探测函数（避免触发 SDK 依赖链）
_MP = None  # targets.model_probe


def _get_mp():
    global _MP
    if _MP is None:
        from targets import model_probe as mp
        _MP = mp
    return _MP

logger = logging.getLogger(__name__)

bp = Blueprint("config_center", __name__)
_DEFAULT_TIMEOUT = 10


# ============================================================================
# 页面路由
# ============================================================================

@bp.route("/")
def index():
    return render_template("index.html")


# ============================================================================
# 配置文件 API
# ============================================================================

@bp.route("/api/files")
def api_list_files():
    files = list_env_files()
    tokens = list_token_files()
    return jsonify({"files": files, "tokens": tokens})


@bp.route("/api/files/<name>")
def api_get_file(name: str):
    data = read_env_file(name)
    if data is None:
        return jsonify({"error": f"文件不存在或不允许访问: {name}"}), 404
    sensitive = detect_sensitive_lines(data["raw"])
    return jsonify({**data, "sensitive_lines": sensitive})


@bp.route("/api/files/<name>", methods=["PUT"])
def api_save_file(name: str):
    body = request.get_json(silent=True)
    if not body or "content" not in body:
        return jsonify({"error": "缺少 content 字段"}), 400

    content = body["content"]
    sensitive = detect_sensitive_lines(content)
    force_save = body.get("force", False)
    if sensitive and not force_save:
        return jsonify({
            "requires_confirmation": True,
            "sensitive_lines": sensitive,
            "message": f"检测到 {len(sensitive)} 处可能的凭据信息，请二次确认后保存",
        }), 409

    ok, message = validate_and_save_env_file(name, content)
    if not ok:
        return jsonify({"error": message}), 422
    return jsonify({"ok": True, "message": message, "sensitive_lines": sensitive})


@bp.route("/api/files/<name>/sections", methods=["POST"])
def api_create_section(name: str):
    data = read_env_file(name)
    if data is None:
        return jsonify({"error": f"文件不存在: {name}"}), 404
    if data.get("is_shared"):
        return jsonify({"error": "shared.env 不支持创建 section"}), 400

    body = request.get_json(silent=True)
    if not body or "section" not in body:
        return jsonify({"error": "缺少 section 字段"}), 400

    section_name = body["section"].strip()
    if not section_name or "=" in section_name:
        return jsonify({"error": "无效的 section 名称"}), 400
    if section_name in data["sections"]:
        return jsonify({"error": f"Section [{section_name}] 已存在"}), 409

    raw = data["raw"]
    if not raw.endswith("\n"):
        raw += "\n"
    new_section = f"\n[{section_name}]\n"
    if "variables" in body and isinstance(body["variables"], dict):
        for k, v in body["variables"].items():
            new_section += f"{k}={v}\n"
    new_content = raw.rstrip("\n") + "\n" + new_section

    ok, message = validate_and_save_env_file(name, new_content)
    if not ok:
        return jsonify({"error": message}), 422
    return jsonify({"ok": True, "message": f"已创建 [{section_name}]", "section": section_name})


@bp.route("/api/files/<name>/<section>", methods=["DELETE"])
def api_delete_section(name: str, section: str):
    data = read_env_file(name)
    if data is None:
        return jsonify({"error": f"文件不存在: {name}"}), 404
    if data.get("is_shared"):
        return jsonify({"error": "shared.env 不支持删除 section"}), 400
    if section not in data["sections"]:
        return jsonify({"error": f"Section [{section}] 不存在"}), 404

    raw = data["raw"]
    lines = raw.split("\n")
    new_lines = []
    in_section = False

    for line in lines:
        stripped = line.strip()
        if stripped == f"[{section}]":
            in_section = True
            continue
        if in_section:
            if stripped.startswith("[") and stripped.endswith("]"):
                in_section = False
                new_lines.append(line)
                continue
            if stripped.startswith("#") or stripped == "":
                continue
            continue
        new_lines.append(line)

    new_content = "\n".join(new_lines)
    ok, message = validate_and_save_env_file(name, new_content)
    if not ok:
        return jsonify({"error": message}), 422
    return jsonify({"ok": True, "message": f"已删除 [{section}]", "section": section})


# ============================================================================
# Token 凭证管理 API
# ============================================================================

@bp.route("/api/tokens")
def api_list_tokens():
    return jsonify({"tokens": list_token_files()})


@bp.route("/api/tokens/<name>")
def api_get_token(name: str):
    data = read_token_file(name)
    if data is None:
        return jsonify({"error": f"Token 文件不存在: {name}"}), 404
    return jsonify(data)


@bp.route("/api/tokens/<name>", methods=["PUT"])
def api_save_token(name: str):
    body = request.get_json(silent=True)
    if not body or "content" not in body:
        return jsonify({"error": "缺少 content 字段"}), 400
    ok, message = validate_and_save_token_file(name, body["content"])
    if not ok:
        return jsonify({"error": message}), 422
    return jsonify({"ok": True, "message": message})


@bp.route("/api/tokens/<name>", methods=["DELETE"])
def api_delete_token(name: str):
    ok, message = delete_token_file(name)
    if not ok:
        return jsonify({"error": message}), 404
    return jsonify({"ok": True, "message": message})


# ============================================================================
# 就绪检查 API
# ============================================================================

@bp.route("/api/probe/check")
def api_readiness_check():
    result = check_readiness()
    return jsonify(result)


# ============================================================================
# 目标探测 API（内联 — 委托 targets/ 层）
# ============================================================================

@bp.route("/api/probe/connectivity", methods=["POST"])
def api_probe_connectivity():
    body = request.get_json(silent=True) or {}
    target_url = body.get("target_url", "").strip()
    if not target_url:
        return jsonify({"error": "缺少 target_url 参数"}), 400
    timeout = body.get("timeout", _DEFAULT_TIMEOUT)
    verify_ssl = body.get("verify_ssl", False)
    result = _run_async(_probe_connectivity(target_url, timeout, verify_ssl=verify_ssl))
    return jsonify(result)


@bp.route("/api/probe/api_type", methods=["POST"])
def api_probe_api_type():
    body = request.get_json(silent=True) or {}
    target_url = body.get("target_url", "").strip()
    if not target_url:
        return jsonify({"error": "缺少 target_url 参数"}), 400
    api_key = body.get("api_key", "")
    timeout = body.get("timeout", 15)
    verify_ssl = body.get("verify_ssl", False)
    result = _run_async(_probe_api_type(target_url, api_key, timeout, verify_ssl=verify_ssl))
    return jsonify(result)


@bp.route("/api/probe/models", methods=["POST"])
def api_probe_models():
    body = request.get_json(silent=True) or {}
    target_url = body.get("target_url", "").strip()
    if not target_url:
        return jsonify({"error": "缺少 target_url 参数"}), 400
    api_key = body.get("api_key", "")
    timeout = body.get("timeout", _DEFAULT_TIMEOUT)
    verify_ssl = body.get("verify_ssl", False)
    result = _run_async(_probe_model_list(target_url, api_key, timeout, verify_ssl=verify_ssl))
    return jsonify(result)


# ============================================================================
# 目标配置向导 API
# ============================================================================

@bp.route("/api/target-config")
def api_target_config():
    return jsonify(get_target_config_from_shared())


@bp.route("/api/target-config", methods=["POST"])
def api_save_target_config():
    body = request.get_json(silent=True) or {}
    updates = {
        "BASE_URL": body.get("attack_url", "").strip() or None,
        "BASE_API": body.get("attack_api", "").strip() or None,
        "BASE_MODEL": body.get("attack_model", "").strip() or None,
        "SCORE_BASE_URL": body.get("score_url", "").strip() or None,
        "SCORE_BASE_API": body.get("score_api", "").strip() or None,
        "SCORE_BASE_MODEL": body.get("score_model", "").strip() or None,
    }
    updates = {k: v for k, v in updates.items() if v}
    if not updates:
        return jsonify({"error": "没有可保存的配置项"}), 400

    ok, msg = update_shared_env_variables(updates)
    if not ok:
        return jsonify({"error": msg}), 422
    return jsonify({"ok": True, "message": msg, "config": get_target_config_from_shared()})


@bp.route("/api/target-config/test", methods=["POST"])
def api_test_target_config():
    body = request.get_json(silent=True) or {}
    target = body.get("target", "attack")
    api_format = body.get("api_format", "openai")
    url = body.get("url", "").strip()
    api_key = body.get("api_key", "")
    model = body.get("model", "")
    timeout = body.get("timeout", 30)
    verify_ssl = body.get("verify_ssl", False)

    if not url and api_format not in ("gemini",):
        return jsonify({"ok": False, "error": "缺少 URL 参数"}), 400
    if not url and api_format == "claude":
        url = "https://api.anthropic.com"

    result = _run_async(test_target_connection(api_format, url, api_key, model, timeout, verify_ssl=verify_ssl))
    result["target"] = target
    result["api_format"] = api_format
    return jsonify(result)


@bp.route("/api/target-config/enumerate", methods=["POST"])
def api_enumerate_app():
    body = request.get_json(silent=True) or {}
    url = body.get("url", "").strip()
    if not url:
        return jsonify({"error": "缺少 url 参数"}), 400
    verify_ssl = bool(body.get("verify_ssl", False))
    timeout = body.get("timeout", 5)
    api_key = body.get("api_key", "").strip()
    result = _run_async(enumerate_ai_app_endpoints(url, verify_ssl=verify_ssl, timeout=timeout, api_key=api_key))
    return jsonify(result)


# ============================================================================
# 🔥 一键自动配置（端到端）
# ============================================================================
# 流程: 连通性测试 → API 类型识别 → 模型枚举 → 自动填充 shared.env → 就绪检查
# 只需提供目标 URL，后续全自动

@bp.route("/api/auto-configure", methods=["POST"])
def api_auto_configure():
    """一键自动配置: URL → 探测 → 自动填充 → 就绪检查。

    Body:
      - target_url: 攻击目标 URL（必填）
      - api_key: API Key（可选）
      - score_url: 评分模型 URL（可选）
      - score_api_key: 评分模型 API Key（可选）
      - score_model: 评分模型名（可选，空则自动探测）
    """
    body = request.get_json(silent=True) or {}
    target_url = body.get("target_url", "").strip()
    if not target_url:
        return jsonify({"error": "缺少 target_url 参数"}), 400

    api_key = body.get("api_key", "").strip()
    score_url = body.get("score_url", "").strip()
    score_api_key = body.get("score_api_key", "").strip()
    score_model = body.get("score_model", "").strip()
    timeout = body.get("timeout", _DEFAULT_TIMEOUT)
    verify_ssl = body.get("verify_ssl", False)

    steps = []

    # Step 1: 连通性测试
    conn = _run_async(_probe_connectivity(target_url, timeout, verify_ssl=verify_ssl))
    steps.append({"step": "connectivity", "status": "pass" if conn.get("reachable") else "fail", "data": conn})
    if not conn.get("reachable"):
        return jsonify({"ok": False, "steps": steps, "error": f"目标不可达: {conn.get('error', '未知错误')}"}), 422

    # Step 2: API 类型识别
    api_type_result = _run_async(_probe_api_type(target_url, api_key, timeout, verify_ssl=verify_ssl))
    steps.append({
        "step": "api_type",
        "status": "pass" if api_type_result.get("api_type") != "unknown" else "warn",
        "data": api_type_result,
    })

    # Step 3: 模型枚举
    model_result = _run_async(_probe_model_list(target_url, api_key, timeout, verify_ssl=verify_ssl))
    steps.append({
        "step": "models",
        "status": "pass" if model_result.get("models") else "warn",
        "data": model_result,
    })

    # Step 4: 自动填充 shared.env
    auto_model = api_type_result.get("model_name") or ""
    if model_result.get("models"):
        # 优先使用第一个非 embedding/非 small 模型
        models = model_result.get("models", [])
        for m in models:
            if not any(kw in m.lower() for kw in ("embed", "small", "tokenizer", "sentence")):
                auto_model = m
                break
        if auto_model == api_type_result.get("model_name") and len(models) > 1:
            auto_model = models[0]

    shared_updates = {
        "BASE_URL": target_url,
        "BASE_API": api_key or "None",
        "BASE_MODEL": auto_model,
    }

    if score_url:
        shared_updates["SCORE_BASE_URL"] = score_url
        shared_updates["SCORE_BASE_API"] = score_api_key or "None"
        shared_updates["SCORE_BASE_MODEL"] = score_model or auto_model

    ok, msg = update_shared_env_variables(shared_updates)
    steps.append({"step": "save_config", "status": "pass" if ok else "fail", "data": {"message": msg, "variables": list(shared_updates.keys())}})

    if not ok:
        return jsonify({"ok": False, "steps": steps, "error": msg}), 422

    # Step 5: 就绪检查
    readiness = check_readiness()
    steps.append({
        "step": "readiness",
        "status": "pass" if readiness.get("overall_ready") else "warn",
        "data": readiness,
    })

    config = get_target_config_from_shared()

    return jsonify({
        "ok": True,
        "steps": steps,
        "config": config,
        "summary": {
            "attack_url": target_url,
            "attack_api": api_key or "None",
            "attack_model": auto_model,
            "score_url": score_url or shared_updates.get("SCORE_BASE_URL", ""),
            "api_type": api_type_result.get("api_type", "unknown"),
            "models_found": len(model_result.get("models", [])),
            "ready": readiness.get("overall_ready", False),
        },
    })


# ============================================================================
# 探测函数（内联，委托 targets/ 层）
# ============================================================================

from utils.target_url import normalize_target_url
from utils.http_transport import create_http_client, API_HEADERS


async def _probe_connectivity(target_url: str, timeout: int = _DEFAULT_TIMEOUT, verify_ssl: bool = False) -> dict:
    """连通性测试 — HEAD/GET 快速检查。

    Args:
        verify_ssl: 是否验证 SSL 证书（默认 False，因为内网目标常使用自签名证书）
    """
    nurl = normalize_target_url(target_url)
    t0 = time.monotonic()

    try:
        async with create_http_client(
            verify_ssl=verify_ssl, timeout=timeout,
            headers=API_HEADERS,
        ) as client:
            try:
                resp = await client.head(nurl.full_url)
            except Exception:
                resp = await client.get(nurl.full_url)

            latency_ms = round((time.monotonic() - t0) * 1000, 1)
            return {
                "reachable": resp.status_code < 500,
                "status_code": resp.status_code,
                "latency_ms": latency_ms,
                "headers": {
                    "server": resp.headers.get("server", ""),
                    "content_type": resp.headers.get("content-type", ""),
                },
                "ssl_verified": verify_ssl,
                "error": None,
            }
    except httpx.ConnectError as e:
        latency_ms = round((time.monotonic() - t0) * 1000, 1)
        err_msg = str(e)
        # 识别 SSL 证书错误并给出明确提示
        if _is_ssl_error(e):
            return {
                "reachable": False, "status_code": 0, "latency_ms": latency_ms,
                "headers": {}, "ssl_verified": verify_ssl,
                "error": f"SSL 证书验证失败（自签名证书），请勾选「跳过 SSL 验证」重试",
                "error_type": "ssl_certificate",
                "hint": "勾选页面上的「跳过 SSL 验证」选项后重新测试",
            }
        return {"reachable": False, "status_code": 0, "latency_ms": latency_ms, "headers": {}, "error": f"连接被拒绝: {err_msg}", "ssl_verified": verify_ssl}
    except httpx.TimeoutException:
        latency_ms = round((time.monotonic() - t0) * 1000, 1)
        return {"reachable": False, "status_code": 0, "latency_ms": latency_ms, "headers": {}, "error": f"连接超时 ({timeout}s)", "ssl_verified": verify_ssl}
    except Exception as e:
        latency_ms = round((time.monotonic() - t0) * 1000, 1)
        if _is_ssl_error(e):
            return {
                "reachable": False, "status_code": 0, "latency_ms": latency_ms,
                "headers": {}, "ssl_verified": verify_ssl,
                "error": f"SSL 证书验证失败（自签名证书），请勾选「跳过 SSL 验证」重试",
                "error_type": "ssl_certificate",
                "hint": "勾选页面上的「跳过 SSL 验证」选项后重新测试",
            }
        return {"reachable": False, "status_code": 0, "latency_ms": latency_ms, "headers": {}, "error": str(e)[:200], "ssl_verified": verify_ssl}


def _is_ssl_error(exc: Exception) -> bool:
    """判断异常是否为 SSL 证书相关错误。"""
    msg = str(exc).lower()
    # httpx 包装的 ssl 错误
    if isinstance(exc, httpx.ConnectError) and "ssl" in msg:
        return True
    # 检查关键词
    ssl_keywords = [
        "certificate verify failed",
        "self-signed certificate",
        "ssl", "tls",
        "certificate",
        "unable to get local issuer certificate",
        "certificate has expired",
        "certificate is not yet valid",
        "ssl3_get_server_certificate",
        "tlsv1",
        "sslv3",
    ]
    return any(kw in msg for kw in ssl_keywords)


async def _probe_api_type(target_url: str, api_key: str = "", timeout: int = _DEFAULT_TIMEOUT, verify_ssl: bool = False) -> dict:
    """API 类型识别 — 委托 targets.model_probe 探测。

    Args:
        verify_ssl: 是否验证 SSL 证书（默认 False，因为内网目标常使用自签名证书）
    """
    mp = _get_mp()
    nurl = normalize_target_url(target_url)
    base_url = nurl.full_url

    results = {"api_type": "unknown", "model_name": None, "confidence": 0.0, "models": [], "details": [], "reachable": False}

    # 策略 1: OpenAI /v1/models
    try:
        async with asyncio.timeout(timeout):
            openai_result = await mp._probe_openai_models(base_url, verify_ssl)
        if openai_result:
            results["api_type"] = openai_result.get("endpoint_type", "openai")
            results["model_name"] = openai_result.get("model_name")
            results["confidence"] = openai_result.get("confidence", 0.9)
            results["models"] = openai_result.get("all_models", [])
            results["reachable"] = True
            results["details"].append({"strategy": "OpenAI /v1/models", "status": "success", "data": openai_result})
            return results
    except asyncio.TimeoutError:
        results["details"].append({"strategy": "OpenAI /v1/models", "status": "timeout"})
    except Exception as e:
        results["details"].append({"strategy": "OpenAI /v1/models", "status": "error", "error": str(e)[:200]})

    # 策略 2: OpenAI POST 探测
    try:
        async with asyncio.timeout(timeout):
            post_result = await mp._probe_openai_post(base_url, verify_ssl)
        if post_result and post_result.get("endpoint_type"):
            results["api_type"] = post_result.get("endpoint_type", "openai")
            results["model_name"] = post_result.get("model_name")
            results["confidence"] = post_result.get("confidence", 0.6)
            results["reachable"] = True
            results["details"].append({"strategy": "OpenAI POST", "status": "success", "data": post_result})
            return results
    except asyncio.TimeoutError:
        results["details"].append({"strategy": "OpenAI POST", "status": "timeout"})
    except Exception as e:
        results["details"].append({"strategy": "OpenAI POST", "status": "error", "error": str(e)[:200]})

    # 策略 3: Ollama /api/tags
    try:
        async with asyncio.timeout(timeout):
            ollama_result = await mp._probe_ollama_tags(base_url, verify_ssl)
        if ollama_result:
            results["api_type"] = ollama_result.get("endpoint_type", "ollama")
            results["model_name"] = ollama_result.get("model_name")
            results["confidence"] = ollama_result.get("confidence", 0.9)
            results["models"] = ollama_result.get("all_models", [])
            results["reachable"] = True
            results["details"].append({"strategy": "Ollama /api/tags", "status": "success", "data": ollama_result})
            return results
    except asyncio.TimeoutError:
        results["details"].append({"strategy": "Ollama /api/tags", "status": "timeout"})
    except Exception as e:
        results["details"].append({"strategy": "Ollama /api/tags", "status": "error", "error": str(e)[:200]})

    # 策略 4: 简单 GET 连通性（兜底）
    try:
        async with asyncio.timeout(timeout // 2):
            status, _ = await mp._http_get(base_url, timeout=timeout // 2, verify_ssl=verify_ssl)
        if status == 200:
            results["reachable"] = True
            results["api_type"] = "custom"
            results["details"].append({"strategy": "GET root", "status": "success", "status_code": status})
        elif status in (401, 403):
            results["reachable"] = True
            results["api_type"] = "custom"
            results["details"].append({"strategy": "GET root", "status": "auth_required", "status_code": status})
        else:
            results["details"].append({"strategy": "GET root", "status": "failed", "status_code": status})
    except Exception:
        results["details"].append({"strategy": "GET root", "status": "error"})

    return results


async def _probe_model_list(target_url: str, api_key: str = "", timeout: int = _DEFAULT_TIMEOUT, verify_ssl: bool = False) -> dict:
    """模型列表枚举 — 委托 targets.model_probe。

    Args:
        verify_ssl: 是否验证 SSL 证书（默认 False，因为内网目标常使用自签名证书）
    """
    mp = _get_mp()
    nurl = normalize_target_url(target_url)
    base_url = nurl.full_url

    # 策略 1: OpenAI /v1/models
    try:
        async with asyncio.timeout(timeout):
            result = await mp._probe_openai_models(base_url, verify_ssl)
        if result and result.get("all_models"):
            return {"models": result["all_models"], "source": "OpenAI /v1/models", "count": len(result["all_models"]), "error": None}
    except Exception:
        pass

    # 策略 2: Ollama /api/tags
    try:
        async with asyncio.timeout(timeout):
            result = await mp._probe_ollama_tags(base_url, verify_ssl)
        if result and result.get("all_models"):
            return {"models": result["all_models"], "source": "Ollama /api/tags", "count": len(result["all_models"]), "error": None}
    except Exception:
        pass

    return {"models": [], "source": None, "count": 0, "error": "无法枚举模型列表（目标可能不支持 /v1/models 或 /api/tags）"}
