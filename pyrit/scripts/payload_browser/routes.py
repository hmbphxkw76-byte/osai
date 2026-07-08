"""
===============================================================================
Payload Browser — 路由 (Blueprint)
===============================================================================
"""
from __future__ import annotations

import logging
from pathlib import Path

import yaml
from flask import Blueprint, render_template, request, jsonify, abort

from .utils import PAYLOADS_DIR, get_file_stats, parse_payload_sections

logger = logging.getLogger(__name__)

bp = Blueprint("payload_browser", __name__)


# ============================================================================
# 页面路由
# ============================================================================

@bp.route("/")
def index():
    """主页面 — 单页应用"""
    return render_template("index.html")


# ============================================================================
# API 路由
# ============================================================================

@bp.route("/api/manifest")
def api_manifest():
    """返回 payload 模块索引 (manifest 数据 + 统计)"""
    manifest_path = PAYLOADS_DIR / "manifest.yaml"
    if not manifest_path.exists():
        return jsonify({"error": "manifest.yaml not found"}), 404

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = yaml.safe_load(f)

    # 构建模块列表 (modules 在 YAML 根级)
    modules = []
    for m in manifest.get("modules", []):
        filepath = PAYLOADS_DIR / m["file"]
        stats = get_file_stats(filepath)
        modules.append({
            "module_id": m.get("module_id", ""),
            "title": m.get("title", ""),
            "key": m.get("key", ""),
            "file": m.get("file", ""),
            "description": m.get("description", ""),
            "loader": m.get("loader", ""),
            "exists": filepath.exists(),
            **stats,
        })

    # 经典载荷 (classic 在 YAML 根级)
    classics = []
    for c in manifest.get("classic", []):
        filepath = PAYLOADS_DIR / c["file"]
        stats = get_file_stats(filepath)
        classics.append({
            "file": c.get("file", ""),
            "lang": c.get("lang", ""),
            "preset_count": c.get("preset_count", 0),
            "description": c.get("description", ""),
            "exists": filepath.exists(),
            **stats,
        })

    total_payloads = sum(m["total_payloads"] for m in modules)
    return jsonify({
        "version": manifest.get("manifest", {}).get("version", "unknown"),
        "modules": modules,
        "classics": classics,
        "stats": {
            "total_modules": len(modules),
            "total_files": len({m["file"] for m in modules}),
            "total_payloads": total_payloads,
        },
    })


@bp.route("/api/payloads/<path:filename>")
def api_get_payloads(filename: str):
    """获取单个 YAML 文件内容 (用于 Monaco 编辑)"""
    filepath = (PAYLOADS_DIR / filename).resolve()
    # 安全检查：确保文件在 payloads 目录内
    if not str(filepath).startswith(str(PAYLOADS_DIR.resolve())):
        abort(403)

    if not filepath.exists():
        return jsonify({"error": f"File not found: {filename}"}), 404

    with open(filepath, "r", encoding="utf-8") as f:
        raw = f.read()

    sections = parse_payload_sections(raw)
    return jsonify({
        "filename": filename,
        "raw": raw,
        "sections": sections,
        "stats": {
            "total_payloads": sum(len(v) for v in sections.values()),
            "section_count": len(sections),
            "size_bytes": len(raw.encode("utf-8")),
        },
    })


@bp.route("/api/payloads/<path:filename>", methods=["PUT"])
def api_save_payloads(filename: str):
    """保存编辑后的 YAML 内容"""
    filepath = (PAYLOADS_DIR / filename).resolve()
    if not str(filepath).startswith(str(PAYLOADS_DIR.resolve())):
        abort(403)

    data = request.get_json(silent=True)
    if not data or "content" not in data:
        return jsonify({"error": "Missing 'content' field"}), 400

    raw_content = data["content"]

    # YAML 语法校验
    try:
        yaml.safe_load(raw_content)
    except yaml.YAMLError as e:
        line_info = "unknown"
        if hasattr(e, "problem_mark") and e.problem_mark is not None:
            line_info = str(e.problem_mark.line + 1)
        return jsonify({
            "error": f"YAML 语法错误: {str(e)}",
            "line": line_info,
        }), 422

    # 写入文件
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(raw_content)
    except IOError as e:
        return jsonify({"error": f"文件写入失败: {str(e)}"}), 500

    logger.info(f"Payload 文件已保存: {filename}")
    return jsonify({
        "ok": True,
        "filename": filename,
        "message": f"已保存 {filename}",
    })


@bp.route("/api/search")
def api_search():
    """跨模块搜索 payload"""
    q = request.args.get("q", "").strip().lower()
    if not q or len(q) < 2:
        return jsonify([])

    results = []
    for yaml_file in sorted(PAYLOADS_DIR.glob("*.yaml")):
        if yaml_file.name == "manifest.yaml":
            continue
        rel_name = yaml_file.name
        with open(yaml_file, "r", encoding="utf-8") as f:
            raw = f.read()
        sections = parse_payload_sections(raw)
        match_in_file = q in rel_name.lower()
        for section_name, payloads in sections.items():
            match_in_section = q in section_name.lower()
            for payload in payloads:
                if match_in_file or match_in_section or q in payload.lower():
                    results.append({
                        "file": rel_name,
                        "section": section_name,
                        "payload": payload[:500],
                        "full_length": len(payload),
                    })

    return jsonify(results[:100])
