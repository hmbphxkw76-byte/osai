# -*- coding: utf-8 -*-
"""
AI-300 Framework - HTTP Client
HTTP 客户端工具：统一的 HTTP 请求封装

设计原则：
- 统一超时和错误处理
- 支持 JSON 和纯文本响应
- 轻量级，仅依赖标准库
"""

from __future__ import annotations

import sys
import os
import json
import urllib.request
import urllib.error
from typing import Any, Dict, Optional

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"


def http_get(url: str, timeout: int = 30, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    发送 GET 请求

    Args:
        url: 请求 URL
        timeout: 超时秒数
        headers: 请求头

    Returns:
        包含 status, data, error 的字典
    """
    try:
        req = urllib.request.Request(url, method="GET")
        if headers:
            for key, value in headers.items():
                req.add_header(key, value)

        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
            return {
                "status": response.status,
                "data": _try_parse_json(raw),
                "error": None,
            }
    except urllib.error.HTTPError as e:
        return {"status": e.code, "data": None, "error": f"HTTP {e.code}: {e.reason}"}
    except urllib.error.URLError as e:
        return {"status": 0, "data": None, "error": f"URL Error: {e.reason}"}
    except Exception as e:
        return {"status": 0, "data": None, "error": str(e)}


def http_post(
    url: str,
    data: Optional[Dict[str, Any]] = None,
    json_data: Optional[Dict[str, Any]] = None,
    timeout: int = 30,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    发送 POST 请求

    Args:
        url: 请求 URL
        data: 表单数据
        json_data: JSON 数据（优先）
        timeout: 超时秒数
        headers: 请求头

    Returns:
        包含 status, data, error 的字典
    """
    try:
        req = urllib.request.Request(url, method="POST")

        if json_data is not None:
            req.data = json.dumps(json_data).encode("utf-8")
            req.add_header("Content-Type", "application/json")
        elif data is not None:
            req.data = urllib.parse.urlencode(data).encode("utf-8")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")

        if headers:
            for key, value in headers.items():
                req.add_header(key, value)

        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
            return {
                "status": response.status,
                "data": _try_parse_json(raw),
                "error": None,
            }
    except urllib.error.HTTPError as e:
        return {"status": e.code, "data": None, "error": f"HTTP {e.code}: {e.reason}"}
    except urllib.error.URLError as e:
        return {"status": 0, "data": None, "error": f"URL Error: {e.reason}"}
    except Exception as e:
        return {"status": 0, "data": None, "error": str(e)}


def _try_parse_json(text: str) -> Any:
    """尝试解析 JSON，失败则返回原文"""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return text
