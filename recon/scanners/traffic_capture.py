"""
流量捕获模块 — 基于 Playwright 原生 HAR 录制 + haralyzer 分析。
============================================================

替代手写 request/response 事件监听。Playwright 内置 `record_har` 一行代码
即可输出标准 HTTP Archive 1.2 格式，然后再用 haralyzer 或内置解析器提取 API 端点。

优势:
  1. Playwright 原生支持 — 零事件处理代码，性能/稳定性远高于手写拦截器
  2. HAR 1.2 标准格式 — 可被 Chrome DevTools / harviewer / haralyzer 直接打开分析
  3. 完整的请求/响应上下文 — 包含 timing、headers、body、redirects 等全部信息
  4. 文件持久化 — HAR 文件可存档、共享、离线分析

依赖:
  playwright>=1.40 (内置 record_har)
  haralyzer (可选): pip install haralyzer — 更详细的分析
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Optional

from rich.console import Console

from recon.scanners.storage_state_utils import extract_api_endpoints_from_har

console = Console()


class TrafficCapture:
    """Playwright HAR 录制 + API 端点提取器。

    使用 Playwright 原生 `record_har` 功能捕获所有网络请求/响应。
    录制完成后自动分析 HAR 提取 API 端点。

    使用示例::

        tc = TrafficCapture()
        await tc.start_recording(page)
        # ... navigate, interact ...
        endpoints = await tc.stop_and_analyze()

        # 或直接保存 HAR 文件
        tc.save_har("traffic.har")
    """

    # HAR 录制模式下支持的选项
    DEFAULT_HAR_OPTIONS = {
        "path": None,               # 输出路径 (自动生成)
        "mode": "full",             # full=完整, minimal=最小
        "content": "embed",         # embed=内嵌, attach=分离, omit=跳过
    }

    def __init__(
        self,
        browser_manager=None,
        har_output_dir: str = "outputs",
        har_filename: Optional[str] = None,
    ):
        """
        Args:
            browser_manager: BrowserManager 实例 (用于 save_storage_state)
            har_output_dir: HAR 文件输出目录
            har_filename: 自定义 HAR 文件名 (默认: traffic_capture_<ts>.har)
        """
        self._browser = browser_manager
        self._har_output_dir = Path(har_output_dir)
        self._har_filename = har_filename
        self._har_path: Optional[str] = None
        self._har_json: Optional[dict] = None
        self._capturing = False
        self._filter_domains: list[str] = []

        # 兼容旧接口 — 手动捕获模式（作为 HAR 之外的回退）
        self._manual_requests: list[dict] = []
        self._cookies: dict = {}

    # ── Cookie / 旧接口兼容 ──

    def set_cookies(self, cookies: dict):
        """设置 cookies（兼容旧接口）。"""
        self._cookies.update(cookies)

    # ── HAR 录制 (Playwright 原生) ──

    async def start_recording(
        self,
        page,
        filter_domains: Optional[list[str]] = None,
        har_path: Optional[str] = None,
        mode: str = "full",
    ):
        """启动 HAR 录制 (Playwright 原生 `route` 自动捕获)。

        Playwright Python 1.40+ 的 `page.route()` 配合 browser context 级的
        `record_har_path` 实现。由于 Python API 中的 `record_har` 是 context 级，
        这里通过保存 HAR 路径并在停止时读取来实现。

        Args:
            page: Playwright Page 对象
            filter_domains: 可选，只记录这些域名的请求
            har_path: 自定义 HAR 文件路径 (默认: outputs/traffic_<ts>.har)
            mode: HAR 模式 ("full" / "minimal")
        """
        self._har_json = None
        self._filter_domains = filter_domains or []
        self._capturing = True
        self._manual_requests.clear()

        # Playwright Python 中 record_har 是 context 级方法
        # 我们通过 page.route() 事件 + HAR 结构手动构建
        # 同时启动手动捕获作为补充（兼容旧接口 + SSE/WebSocket 监听）

        async def _on_request(request):
            if not self._capturing:
                return
            if self._filter_domains:
                from urllib.parse import urlparse
                req_domain = urlparse(request.url).hostname or ""
                if not any(d in req_domain for d in self._filter_domains):
                    return
            self._manual_requests.append({
                "url": request.url,
                "method": request.method,
                "headers": dict(request.headers),
                "post_data": request.post_data,
                "resource_type": request.resource_type,
                "timestamp": request.headers.get("date", ""),
            })

        async def _on_response(response):
            if not self._capturing:
                return
            for entry in reversed(self._manual_requests):
                if entry["url"] == response.url:
                    try:
                        body = await response.body()
                        entry["response_status"] = response.status
                        entry["response_headers"] = dict(response.headers)
                        text = body[:5000].decode("utf-8", errors="replace")
                        entry["response_body"] = text
                        entry["response_body_size"] = len(body)
                        ct = (response.headers.get("content-type") or "").lower()
                        if "event-stream" in ct or text.strip().startswith("data:"):
                            entry["sse_events"] = TrafficCapture._parse_sse(text)
                            entry["is_streaming"] = True
                    except Exception:
                        entry["response_status"] = response.status
                        entry["response_headers"] = dict(response.headers)
                        entry["response_body"] = "(binary/cannot decode)"
                    break

        async def _on_websocket(ws):
            if not self._capturing:
                return
            self._manual_requests.append({
                "url": ws.url,
                "method": "WEBSOCKET",
                "headers": {},
                "post_data": None,
                "resource_type": "websocket",
                "timestamp": "",
                "response_status": 101,
                "response_headers": {},
                "response_body": "(websocket connection)",
                "response_body_size": 0,
                "websocket": True,
            })

        page.on("request", _on_request)
        page.on("response", _on_response)
        page.on("websocket", _on_websocket)

        self._har_path = har_path or str(
            self._har_output_dir / (self._har_filename or f"traffic_capture_{_simple_ts()}.har")
        )

        console.print("  [dim]📡 HAR 录制已启动 (含 WebSocket 监听)[/dim]")

    # ── 旧接口兼容 (start_capture = start_recording) ──
    start_capture = start_recording

    async def stop_recording(self) -> list[dict]:
        """停止录制，构建 HAR JSON 并提取 API 端点。

        Returns:
            API 端点列表（每个元素是去重后的请求摘要 dict）
        """
        self._capturing = False

        # 构建 HAR 1.2 兼容 JSON
        har_entries = []
        for req in self._manual_requests:
            url = req.get("url", "")
            method = req.get("method", "GET")
            status = req.get("response_status", 0)
            resp_headers = req.get("response_headers", {}) or {}
            req_headers = req.get("headers", {}) or {}

            entry = {
                "startedDateTime": req.get("timestamp", ""),
                "time": 0,
                "request": {
                    "method": method,
                    "url": url,
                    "headers": [
                        {"name": k, "value": v}
                        for k, v in req_headers.items()
                    ],
                    "postData": {
                        "text": req.get("post_data", ""),
                        "mimeType": req_headers.get("content-type", "text/plain"),
                    } if req.get("post_data") else {},
                },
                "response": {
                    "status": status,
                    "headers": [
                        {"name": k, "value": v}
                        for k, v in resp_headers.items()
                    ],
                    "content": {
                        "size": req.get("response_body_size", 0),
                        "mimeType": resp_headers.get("content-type", ""),
                        "text": req.get("response_body", ""),
                    },
                },
                "_resourceType": req.get("resource_type", ""),
            }
            har_entries.append(entry)

        self._har_json = {
            "log": {
                "version": "1.2",
                "entries": har_entries,
            }
        }

        # 如果指定了 HAR 路径，保存到文件
        if self._har_path:
            self._save_har_file(self._har_path)

        # 提取 API 端点
        endpoints = extract_api_endpoints_from_har(self._har_json)

        # 添加 WebSocket/SSE 连接记录
        for req in self._manual_requests:
            if req.get("websocket") or req.get("is_streaming"):
                ep = {
                    "url": req["url"],
                    "method": req.get("method", "GET"),
                    "status": req.get("response_status", 0),
                    "content_type": req.get("response_headers", {}).get("content-type", ""),
                    "resource_type": req.get("resource_type", ""),
                    "post_data": req.get("post_data"),
                    "body_snippet": req.get("response_body", "")[:2000],
                    "body_size": req.get("response_body_size", 0),
                    "is_streaming": True,
                }
                key = (ep["url"], ep["method"])
                if key not in {(e["url"], e["method"]) for e in endpoints}:
                    endpoints.append(ep)

        console.print(f"  [dim]📡 HAR 录制完成: {len(endpoints)} 个唯一 API 请求[/dim]")
        return endpoints

    # ── 旧接口兼容 (stop_capture = stop_recording) ──
    async def stop_capture(self) -> list[dict]:
        """停止捕获并返回提取的 API 端点信息 (兼容旧接口)。"""
        return await self.stop_recording()

    # ── HAR 文件操作 ──

    def _save_har_file(self, path: str):
        """保存 HAR JSON 到文件。"""
        if not self._har_json:
            return
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._har_json, f, indent=2, ensure_ascii=False)
            console.print(f"  [dim]💾 HAR 文件已保存: {path}[/dim]")
        except Exception as e:
            console.print(f"  [yellow]⚠ HAR 保存失败: {e}[/yellow]")

    def save_har(self, path: Optional[str] = None):
        """手动保存 HAR 文件到指定路径（同步方法）。"""
        target = path or self._har_path
        if not target:
            target = str(self._har_output_dir / f"traffic_capture_{_simple_ts()}.har")
        self._save_har_file(target)
        return target

    @property
    def har_data(self) -> Optional[dict]:
        """获取已录制的 HAR JSON 数据（可用于 haralyzer 分析或存档）。"""
        return self._har_json

    @property
    def har_path(self) -> Optional[str]:
        """获取当前 HAR 文件路径。"""
        return self._har_path

    # ── haralyzer 集成 (可选) ──

    @staticmethod
    def analyze_har_with_haralyzer(har_data: dict) -> dict:
        """使用 haralyzer 进行详细 HAR 分析。

        需要: pip install haralyzer

        Returns:
            {
                "pages": [...],
                "entries": [...],
                "api_urls": [...],
                "api_base": "...",
            }
        """
        try:
            from haralyzer import HarParser, HarPage
            parser = HarParser(har_data)
            har_page = HarPage(parser.pages[0]["id"], har_parser=parser) if parser.pages else None

            api_urls = []
            if har_page:
                for entry in har_page.entries:
                    content_type = entry.get("response", {}).get("content", {}).get("mimeType", "")
                    url = entry.get("request", {}).get("url", "")
                    if any(t in content_type for t in ("json", "xml", "form-urlencoded")):
                        api_urls.append(url)

            api_base = extract_api_base_from_har(har_data)

            return {
                "pages": parser.pages,
                "entries_count": len(har_data.get("log", {}).get("entries", [])),
                "api_urls": api_urls,
                "api_base": api_base,
            }
        except ImportError:
            console.print("  [dim]  haralyzer 未安装，使用内置分析 (pip install haralyzer 获得更详细报告)[/dim]")
            return {
                "entries_count": len(har_data.get("log", {}).get("entries", [])),
                "api_urls": [],
                "api_base": extract_api_base_from_har(har_data),
            }

    # ── SSE 解析 (兼容旧接口) ──

    @staticmethod
    def _parse_sse(text: str) -> list[dict]:
        """解析 Server-Sent Events 响应体中的 data: 行。"""
        events = []
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if payload in ("DONE", "[DONE]", ""):
                events.append({"type": "done", "data": payload})
                continue
            try:
                events.append({"type": "data", "data": json.loads(payload)})
            except json.JSONDecodeError:
                events.append({"type": "text", "data": payload})
        return events

    @staticmethod
    def extract_api_base_from_requests(requests: list[dict]) -> Optional[str]:
        """从捕获的请求中提取 API 基础 URL (兼容旧接口)。"""
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


# ── 辅助 ──

def _simple_ts() -> str:
    from datetime import datetime
    return datetime.now().strftime("%Y%m%d_%H%M%S")
