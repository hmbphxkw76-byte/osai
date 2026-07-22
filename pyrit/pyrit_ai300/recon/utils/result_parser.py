# -*- coding: utf-8 -*-
"""
AI-300 Framework - Result Parser
结果解析器：解析各工具的 JSONL/JSON 输出

设计原则：
- 容错：解析失败返回空结果而非异常
- 统一：所有解析器返回统一格式
"""

from __future__ import annotations

import sys
import os
import json
from typing import Any, Dict, List

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"


def parse_jsonl(text: str) -> List[Dict[str, Any]]:
    """
    解析 JSONL（每行一个 JSON）

    Args:
        text: JSONL 文本

    Returns:
        解析后的字典列表
    """
    results = []
    for line in text.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


def parse_json_safely(text: str) -> Dict[str, Any]:
    """
    安全解析 JSON（容错）

    Args:
        text: JSON 文本

    Returns:
        解析后的字典，失败返回空字典
    """
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return {}


def extract_findings_from_deepteam(output: str) -> List[Dict[str, Any]]:
    """
    从 DeepTeam 输出中提取标准化发现

    Args:
        output: DeepTeam 原始输出

    Returns:
        标准化发现列表
    """
    findings = []
    data = parse_json_safely(output)

    if isinstance(data, list):
        for item in data:
            finding = {
                "category": item.get("attack_type", "unknown"),
                "severity": item.get("severity", "medium"),
                "description": item.get("description", ""),
                "evidence": item.get("evidence", ""),
                "owasp_mapping": item.get("owasp_mapping", ""),
                "confidence": float(item.get("score", 0.5)),
            }
            findings.append(finding)
    elif isinstance(data, dict):
        for attack_type, results in data.items():
            if isinstance(results, list):
                for r in results:
                    finding = {
                        "category": attack_type,
                        "severity": r.get("severity", "medium"),
                        "description": r.get("description", ""),
                        "evidence": r.get("evidence", ""),
                        "owasp_mapping": r.get("owasp_mapping", ""),
                        "confidence": float(r.get("score", 0.5)),
                    }
                    findings.append(finding)

    return findings
