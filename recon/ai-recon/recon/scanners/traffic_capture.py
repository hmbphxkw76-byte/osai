"""
网络流量捕获模块 — 拦截浏览器 Network 请求并提取 API 端点。
"""

from __future__ import annotations

import json
import re
from typing import Optional

from rich.console import Console

console = Console()


class TrafficCapture:
    """Playwright Network 请求拦截器。

    捕获浏览器发出的所有 HTTP/HTTPS 请求，提取 API 端点信息。
    支持按域名过滤、请求/响应内容分类。
    """

    def __init__(self, browser_manager):
        self._browser = browser_manager
        self._captured_requests: list[dict] = []
        self._har_entries: list[dict] = []
        self._capturing = False
        self._filter_domains: list[str] = []
        self._cookies: dict = {}

    def set_cookies(self, cookies: dict):
        """设置 cookies（用于后续请求的认证）。"""
        self._cookies.update(cookies)

    def start_capture(self, page, filter_domains: Optional[list[str]] = None):
        """开始捕获页面和 iframe 的网络请求。

        Args:
            page: Playwright Page 对象
            filter_domains: 可选，只捕获这些域名的请求
        """
        self._captured_requests.clear()
        self._har_entries.clear()
        self._capturing = True
        self._filter_domains = filter_domains or []

        async def _on_request(request):
            if not self._capturing:
                return
            entry = {
                "url": request.url,
                "method": request.method,
                "headers": dict(request.headers),
                "post_data": request.post_data,
                "resource_type": request.resource_type,
                "timestamp": request.headers.get("date", ""),
            }
            self._captured_requests.append(entry)

        async def _on_response(response):
            if not self._capturing:
                return
            # 找到对应的 request entry
            for entry in reversed(self._captured_requests):
                if entry["url"] == response.url:
                    try:
                        body = await response.body()
                        entry["response_status"] = response.status
                        entry["response_headers"] = dict(response.headers)
                        entry["response_body"] = body[:5000].decode("utf-8", errors="replace")
                        entry["response_body_size"] = len(body)
                    except Exception:
                        entry["response_status"] = response.status
                        entry["response_headers"] = dict(response.headers)
                        entry["response_body"] = "(binary/cannot decode)"
                    break

        page.on("request", _on_request)
        page.on("response", _on_response)

        console.print("  [dim]📡 流量捕获已启动[/dim]")

    async def stop_capture(self) -> list[dict]:
        """停止捕获并返回提取的 API 端点信息。"""
        self._capturing = False

        # 过滤 API 请求（排除静态资源）
        api_requests = []
        static_extensions = {
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
        }
        api_content_types = {
            "application/json", "application/xml", "text/xml",
            "application/x-www-form-urlencoded", "multipart/form-data",
            "text/plain", "application/octet-stream",
        }

        for req in self._captured_requests:
            url = req.get("url", "")
            resource_type = req.get("resource_type", "")

            # 跳过静态资源
            if resource_type in ("stylesheet", "image", "font", "media"):
                continue
            if any(url.lower().endswith(ext) for ext in static_extensions):
                continue

            # 收集
            api_requests.append({
                "url": url,
                "method": req.get("method", "GET"),
                "status": req.get("response_status", 0),
                "content_type": (req.get("response_headers", {}) or {}).get("content-type", ""),
                "resource_type": resource_type,
                "post_data": req.get("post_data"),
                "body_snippet": (req.get("response_body", "") or "")[:2000],
                "body_size": req.get("response_body_size", 0),
            })

        # 去重（同一 URL + method）
        seen = set()
        unique = []
        for req in api_requests:
            key = (req["url"], req["method"])
            if key not in seen:
                seen.add(key)
                unique.append(req)

        console.print(f"  [dim]📡 流量捕获完成: {len(unique)} 个唯一 API 请求[/dim]")
        return unique

    @staticmethod
    def extract_api_base_from_requests(requests: list[dict]) -> Optional[str]:
        """从捕获的请求中提取 API 基础 URL。

        例如从 https://target.com/api/v1/chat 提取 https://target.com/api/v1
        """
        api_patterns = [
            r"^(.*?/api/v\d+)",
            r"^(.*?/api)",
            r"^(.*?/v\d+)",
        ]

        for req in requests:
            url = req.get("url", "")
            for pattern in api_patterns:
                match = re.match(pattern, url)
                if match:
                    return match.group(1)
        return None
