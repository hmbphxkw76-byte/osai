"""
===============================================================================
Payload Browser — 工具函数
===============================================================================
"""
from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# ── 路径常量 ──
_PACKAGE_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _PACKAGE_DIR.parent.parent
PAYLOADS_DIR = _PROJECT_ROOT / "datasets" / "payloads"


def get_file_stats(filepath: Path) -> dict:
    """获取 YAML 文件的统计信息"""
    if not filepath.exists():
        return {"total_payloads": 0, "section_count": 0, "size_kb": 0}

    with open(filepath, "r", encoding="utf-8") as f:
        raw = f.read()

    sections = parse_payload_sections(raw)
    return {
        "total_payloads": sum(len(v) for v in sections.values()),
        "section_count": len(sections),
        "size_kb": round(len(raw.encode("utf-8")) / 1024, 1),
    }


def parse_payload_sections(raw_yaml: str) -> dict[str, list[str]]:
    """从 YAML 原始文本中解析 payloads: 节 → [载荷列表]"""
    import yaml
    try:
        data = yaml.safe_load(raw_yaml)
    except yaml.YAMLError:
        return {}

    if not isinstance(data, dict):
        return {}

    payloads = data.get("payloads", {})
    if not isinstance(payloads, dict):
        return {}

    result = {}
    for section_key, items in payloads.items():
        if isinstance(items, list):
            result[section_key] = [str(item) for item in items if item is not None]
        elif isinstance(items, dict):
            result[section_key] = list(items.keys())
    return result
