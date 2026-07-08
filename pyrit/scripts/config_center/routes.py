"""
===============================================================================
Config Center — 路由 (Blueprint)
===============================================================================
"""
from __future__ import annotations

import logging
from pathlib import Path

from flask import Blueprint, render_template, request, jsonify

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
)
from .readiness_probe import probe_connectivity, probe_api_type, probe_model_list, run_async

logger = logging.getLogger(__name__)

bp = Blueprint("config_center", __name__)


# ============================================================================
# 页面路由
# ============================================================================

@bp.route("/")
def index():
    """主页面 — 单页应用"""
    return render_template("index.html")


# ============================================================================
# 配置文件 API
# ============================================================================

@bp.route("/api/files")
def api_list_files():
    """列出所有 .env 配置文件及其统计信息"""
    files = list_env_files()
    tokens = list_token_files()
    return jsonify({
        "files": files,
        "tokens": tokens,
    })


@bp.route("/api/files/<name>")
def api_get_file(name: str):
    """获取单个 .env 文件的完整内容（原始文本 + 解析后的 section 树）"""
    data = read_env_file(name)
    if data is None:
        return jsonify({"error": f"文件不存在或不允许访问: {name}"}), 404

    # 检测敏感信息
    sensitive = detect_sensitive_lines(data["raw"])

    return jsonify({**data, "sensitive_lines": sensitive})


@bp.route("/api/files/<name>", methods=["PUT"])
def api_save_file(name: str):
    """保存 .env 文件（带语法校验）"""
    body = request.get_json(silent=True)
    if not body or "content" not in body:
        return jsonify({"error": "缺少 content 字段"}), 400

    content = body["content"]

    # 敏感信息确认提示（仅当内容包含凭据时）
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
    """在 .env 文件中创建新 section（追加到文件末尾）"""
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

    # 检查是否已存在
    if section_name in data["sections"]:
        return jsonify({"error": f"Section [{section_name}] 已存在"}), 409

    # 追加新 section 到文件末尾
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
    """删除 .env 文件中的某个 section（通过原始文本操作）"""
    data = read_env_file(name)
    if data is None:
        return jsonify({"error": f"文件不存在: {name}"}), 404
    if data.get("is_shared"):
        return jsonify({"error": "shared.env 不支持删除 section"}), 400

    if section not in data["sections"]:
        return jsonify({"error": f"Section [{section}] 不存在"}), 404

    raw = data["raw"]
    # 查找并删除 [section] 块（包括其后的 key=value 行）
    lines = raw.split("\n")
    new_lines = []
    in_section = False
    skip_count = 0

    for line in lines:
        stripped = line.strip()
        if stripped == f"[{section}]":
            in_section = True
            skip_count += 1
            continue
        if in_section:
            # 遇到空行或下一个 section 头 — 结束当前 section
            if stripped.startswith("[") and stripped.endswith("]"):
                in_section = False
                new_lines.append(line)
                continue
            if stripped.startswith("#") or stripped == "":
                # 注释或空行 — 继续检查是否还在 section 内
                # 简单判断：连续空行则结束
                continue  # 跳过注释和空行
            # 跳过 key=value 行
            skip_count += 1
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
    """列出所有 token 文件"""
    return jsonify({"tokens": list_token_files()})


@bp.route("/api/tokens/<name>")
def api_get_token(name: str):
    """获取 token 文件内容"""
    data = read_token_file(name)
    if data is None:
        return jsonify({"error": f"Token 文件不存在: {name}"}), 404
    return jsonify(data)


@bp.route("/api/tokens/<name>", methods=["PUT"])
def api_save_token(name: str):
    """保存/更新 token 文件"""
    body = request.get_json(silent=True)
    if not body or "content" not in body:
        return jsonify({"error": "缺少 content 字段"}), 400

    ok, message = validate_and_save_token_file(name, body["content"])
    if not ok:
        return jsonify({"error": message}), 422

    return jsonify({"ok": True, "message": message})


@bp.route("/api/tokens/<name>", methods=["DELETE"])
def api_delete_token(name: str):
    """删除 token 文件"""
    ok, message = delete_token_file(name)
    if not ok:
        return jsonify({"error": message}), 404
    return jsonify({"ok": True, "message": message})


# ============================================================================
# 就绪检查 API
# ============================================================================

@bp.route("/api/probe/check")
def api_readiness_check():
    """全局就绪检查"""
    result = check_readiness()
    return jsonify(result)


@bp.route("/api/probe/connectivity", methods=["POST"])
def api_probe_connectivity():
    """连通性测试"""
    body = request.get_json(silent=True) or {}
    target_url = body.get("target_url", "").strip()
    if not target_url:
        return jsonify({"error": "缺少 target_url 参数"}), 400

    timeout = body.get("timeout", 10)
    result = run_async(probe_connectivity(target_url, timeout))
    return jsonify(result)


@bp.route("/api/probe/api_type", methods=["POST"])
def api_probe_api_type():
    """API 类型识别探测"""
    body = request.get_json(silent=True) or {}
    target_url = body.get("target_url", "").strip()
    if not target_url:
        return jsonify({"error": "缺少 target_url 参数"}), 400

    api_key = body.get("api_key", "")
    timeout = body.get("timeout", 15)
    result = run_async(probe_api_type(target_url, api_key, timeout))
    return jsonify(result)


@bp.route("/api/probe/models", methods=["POST"])
def api_probe_models():
    """模型列表枚举"""
    body = request.get_json(silent=True) or {}
    target_url = body.get("target_url", "").strip()
    if not target_url:
        return jsonify({"error": "缺少 target_url 参数"}), 400

    api_key = body.get("api_key", "")
    timeout = body.get("timeout", 10)
    result = run_async(probe_model_list(target_url, api_key, timeout))
    return jsonify(result)
