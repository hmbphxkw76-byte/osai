"""
Playwright storageState 会话持久化工具
======================================

使用 Playwright 原生 storageState 格式替代手写 Cookie 解析:
  - 一行代码导入/导出完整浏览器会话 (cookies + localStorage + sessionStorage)
  - 兼容 cookie_to_authfile.py 输出的纯 Cookie 字符串自动转换
  - 支持 Netscape cookies.txt → storageState 自动转换
  - 用 haralyzer 分析 HAR 文件提取 API 端点

依赖 (可选):
  - haralyzer: pip install haralyzer  (HAR 文件分析)
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


def cookie_string_to_storage_state(
    cookie_str: str,
    base_url: str,
    output_path: Optional[str] = None,
) -> dict:
    """将纯 Cookie 字符串或 --auth-file 格式转换为 Playwright storageState JSON。

    Playwright storageState 是标准的浏览器会话持久化格式，包含:
      - cookies: Cookie 数组 (name, value, domain, path, httpOnly, secure, sameSite)
      - origins: 各 origin 的 localStorage 数据

    Args:
        cookie_str: 格式如 "key1=val1; key2=val2; ..."
                    支持 # Extra header: Authorization: Bearer xxx 注释行
        base_url: 目标 URL，用于推断 domain 和 secure 属性
        output_path: 可选，保存为 .json 文件

    Returns:
        Playwright storageState dict
    """
    parsed_url = urlparse(base_url)
    domain = parsed_url.hostname or "localhost"
    is_secure = parsed_url.scheme == "https"

    # 分离 Cookie 行和 Extra header 注释
    extra_headers = {}
    cookie_part = cookie_str
    for line in cookie_str.splitlines():
        line = line.strip()
        if line.startswith("# Extra header:"):
            match = re.match(r"# Extra header:\s*(\S+):\s*(.*)", line)
            if match:
                extra_headers[match.group(1)] = match.group(2).strip()
            cookie_part = cookie_part.replace(line, "")

    cookie_part = cookie_part.strip().rstrip(";").strip()

    # 解析 k=v 对
    cookies = []
    pairs = re.split(r"\s*;\s*", cookie_part)
    for pair in pairs:
        if "=" in pair:
            name, _, value = pair.partition("=")
            name = name.strip()
            if name:
                cookies.append({
                    "name": name,
                    "value": value.strip(),
                    "domain": domain,
                    "path": "/",
                    "httpOnly": False,
                    "secure": is_secure,
                    "sameSite": "Lax" if not is_secure else "None",
                })

    storage_state = {
        "cookies": cookies,
        "origins": [
            {
                "origin": f"{parsed_url.scheme}://{domain}",
                "localStorage": [
                    {"name": name, "value": value}
                    for name, value in extra_headers.items()
                ],
            }
        ] if extra_headers else [],
    }

    if output_path:
        Path(output_path).write_text(
            json.dumps(storage_state, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    return storage_state


def netscape_to_storage_state(
    netscape_text: str,
    base_url: str = "",
    output_path: Optional[str] = None,
) -> dict:
    """将 Netscape cookies.txt 格式转换为 Playwright storageState JSON。

    兼容浏览器扩展导出的标准 cookies.txt 格式:
        # Netscape HTTP Cookie File
        .example.com  TRUE  /  FALSE  1234567890  name  value

    Args:
        netscape_text: Netscape cookies.txt 内容
        base_url: 可选目标 URL，补充 domain 推断
        output_path: 可选，保存为 .json 文件
    """
    parsed_url = urlparse(base_url) if base_url else None
    default_domain = parsed_url.hostname if parsed_url else ""
    default_secure = (parsed_url.scheme == "https") if parsed_url else True

    cookies = []
    for line in netscape_text.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        try:
            domain = parts[0].strip().lstrip(".")
            secure_flag = (parts[3].strip().upper() == "TRUE")
            name = parts[5].strip()
            value = parts[6].strip()
            path = parts[2].strip() if len(parts) > 2 else "/"

            if not domain:
                domain = default_domain
            if not domain:
                continue

            cookies.append({
                "name": name,
                "value": value,
                "domain": domain,
                "path": path or "/",
                "httpOnly": False,
                "secure": secure_flag or default_secure,
                "sameSite": "Lax" if not secure_flag else "None",
            })
        except (IndexError, ValueError):
            continue

    storage_state = {
        "cookies": cookies,
        "origins": [],
    }

    if output_path:
        Path(output_path).write_text(
            json.dumps(storage_state, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    return storage_state


def load_storage_state(
    path: str,
    base_url: str = "",
) -> dict:
    """加载 storage state，自动检测格式。

    支持格式:
      1. Playwright storageState JSON  — 直接加载
      2. 纯 Cookie 字符串文件          — 自动转换
      3. Netscape cookies.txt          — 自动转换

    Args:
        path: 文件路径
        base_url: 目标 URL（Cookie 字符串格式需要，用于推断 domain）

    Returns:
        Playwright storageState dict
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"storage state 文件不存在: {path}")

    text = file_path.read_text(encoding="utf-8").strip()

    # ── 检测 1: JSON 格式 (Playwright storageState) ──
    if text.startswith("{"):
        try:
            data = json.loads(text)
            if "cookies" in data or "origins" in data:
                return data
        except json.JSONDecodeError:
            pass

    # ── 检测 2: Netscape cookies.txt ──
    if "\t" in text and len(text.split("\n")[0].split("\t")) >= 6:
        return netscape_to_storage_state(text, base_url)

    # ── 检测 3: 纯 Cookie 字符串 (k=v; k=v) ──
    return cookie_string_to_storage_state(text, base_url)


def save_storage_state_from_context(context, output_path: str) -> str:
    """从 Playwright browser context 保存 storageState 到文件（需在 async context 内调用）。

    现代用法替代手写 cookie 提取 —— 一行代码捕获完整会话。

    使用示例::

        storage_state = await context.storage_state()
        output = output_path or "storage_state.json"
        import json
        Path(output).write_text(json.dumps(storage_state, indent=2))
        return output
    """
    output = output_path or "storage_state.json"
    # 注意: 实际保存由 BrowserManager.save_storage_state() 异步完成
    # 这个函数仅作为文档参考
    return output


# ── HAR (HTTP Archive) 端点提取 ──

def extract_api_endpoints_from_har(har_data: dict) -> list[dict]:
    """从 HAR JSON 数据中提取 API 端点信息。

    使用标准 HAR 1.2 格式，提取:
      - URL、HTTP 方法、状态码
      - Content-Type、响应体前 2000 字符
      - 请求体 (POST data)
      - 是否为流式响应 (SSE/text/event-stream)

    不依赖 haralyzer，纯 Python 解析保证零额外依赖也能运行。
    如果已安装 haralyzer，可用 HarParser 获得更详细的分析。

    Args:
        har_data: HAR 1.2 JSON dict (Playwright record_har 输出)

    Returns:
        去重后的 API 端点列表，每个元素包含:
          - url, method, status
          - content_type, resource_type
          - post_data, body_snippet, body_size
          - is_streaming
    """
    entries = har_data.get("log", {}).get("entries", [])
    if not entries:
        return []

    static_extensions = {
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
    }
    skip_resource_types = {"image", "font", "media", "stylesheet"}

    endpoints = []
    for entry in entries:
        request = entry.get("request", {})
        response = entry.get("response", {})
        url = request.get("url", "")

        # 跳过静态资源
        resource_type = entry.get("_resourceType", "")
        if resource_type in skip_resource_types:
            continue
        if any(url.lower().endswith(ext) for ext in static_extensions):
            continue

        content = response.get("content", {})
        content_type = (response.get("content", {}).get("mimeType", "")
                        or next(
                            (h.get("value", "")
                             for h in response.get("headers", [])
                             if h.get("name", "").lower() == "content-type"),
                            ""))

        body_text = content.get("text", "")[:2000] if content.get("text") else ""
        body_size = content.get("size", 0) or response.get("bodySize", 0)

        # SSE/流式检测
        is_streaming = any(tag in content_type.lower()
                           for tag in ("event-stream", "text/event-stream"))

        # 如果 body 未解码但可能有意义
        if not body_text and content.get("encoding") == "base64":
            body_text = "(binary/base64 encoded)"

        post_data = None
        if request.get("postData"):
            post_data = request["postData"].get("text", "")[:5000]

        endpoints.append({
            "url": url,
            "method": request.get("method", "GET"),
            "status": response.get("status", 0),
            "content_type": content_type,
            "resource_type": resource_type,
            "post_data": post_data,
            "body_snippet": body_text,
            "body_size": body_size,
            "is_streaming": is_streaming,
        })

    # 去重
    seen = set()
    unique = []
    for ep in endpoints:
        key = (ep["url"], ep["method"])
        if key not in seen:
            seen.add(key)
            unique.append(ep)

    return unique


def extract_api_base_from_har(har_data: dict) -> Optional[str]:
    """从 HAR 中提取 API 基础 URL。

    例如从 https://target.com/api/v1/chat 提取 https://target.com/api/v1
    """
    entries = har_data.get("log", {}).get("entries", [])
    api_patterns = [
        r"^(.*?/api/v\d+)",
        r"^(.*?/api)",
        r"^(.*?/v\d+)",
    ]

    for entry in entries:
        url = entry.get("request", {}).get("url", "")
        for pattern in api_patterns:
            match = re.match(pattern, url)
            if match:
                return match.group(1)
    return None
