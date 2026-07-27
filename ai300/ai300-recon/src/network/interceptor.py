# -*- coding: utf-8 -*-
"""
HTTP Interceptor
================

基于 Playwright response/request 事件拦截网络流量，识别 LLM API 端点，
捕获请求头、请求体、响应体。对 event-stream / SSE / 跨域请求更友好。
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

from src.utils import truncate_error

from .traffic_analyzer import TrafficAnalyzer

logger = logging.getLogger(__name__)


class HTTPInterceptor:
    """HTTP 流量拦截器：捕获 LLM API 请求与响应"""

    def __init__(
        self,
        page: Any,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.page = page
        self.config = config or {}
        self.captured = []
        self.websocket_frames: List[Dict[str, Any]] = []
        self._route_active = False
        self._ws_handlers = []
        # 缓存 request 事件中的请求体，供 response 事件匹配使用
        self._request_bodies: Dict[str, str] = {}
        # 跟踪未完成的异步响应处理任务，stop() 时等待它们完成
        self._pending_tasks: set = set()

        # 从配置读取截断长度，未配置时使用最优默认值
        network_cfg = self.config.get("network", {})
        self.request_body_limit = network_cfg.get("request_body_limit", 5000)
        self.response_body_limit = network_cfg.get("response_body_limit", 5000)
        self.websocket_payload_limit = network_cfg.get("websocket_payload_limit", 2000)

    async def start(self):
        """启用 response/request 事件监听、WebSocket 监听与页面 fetch 拦截"""
        if self._route_active:
            return

        # 使用 response/request 事件监听，对 event-stream / SSE / 跨域请求更友好
        self.page.on("response", self._handle_response)
        self.page.on("request", self._handle_request)

        # 监听 WebSocket
        def on_ws(ws):
            logger.info("WebSocket opened: %s", ws.url)

            def on_frame_sent(payload):
                self._record_ws_frame(ws.url, "sent", payload)

            def on_frame_received(payload):
                self._record_ws_frame(ws.url, "received", payload)

            ws.on("framesent", on_frame_sent)
            ws.on("framereceived", on_frame_received)
            self._ws_handlers.append((ws, on_frame_sent, on_frame_received))

        self.page.on("websocket", on_ws)

        # 安装页面级 fetch 拦截，专门解决 SSE 响应体被页面消费后 Playwright 读不到的问题
        await self._install_fetch_interceptor()

        self._route_active = True
        logger.info("HTTP interception and WebSocket monitoring started")

    async def await_traffic(
        self,
        wait_for_llm: bool = True,
        timeout_ms: int = 15000,
        poll_interval_ms: int = 500,
    ):
        """等待异步响应处理完成，并可选等待至少一个 LLM API 被捕获。

        在 probe_interaction 后调用，确保 analysis 阶段能读到已捕获的 LLM API。
        """
        deadline = time.time() + (timeout_ms / 1000.0)
        poll_seconds = max(0.1, poll_interval_ms / 1000.0)

        while time.time() < deadline:
            # 1. 等待当前未完成的响应处理任务
            if self._pending_tasks:
                pending = list(self._pending_tasks)
                logger.debug("Awaiting %d pending response tasks", len(pending))
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*pending, return_exceptions=True),
                        timeout=2.0,
                    )
                except asyncio.TimeoutError:
                    pass

            # 2. 合并页面级 fetch/XHR 拦截数据（SSE 体通常在这里）
            await self._merge_fetch_intercepted()

            if not wait_for_llm:
                return

            # 3. 若已捕获 LLM API，可提前结束
            if any(e.get("is_llm_api") for e in self.captured):
                logger.info("LLM API traffic settled")
                return

            await asyncio.sleep(poll_seconds)

        logger.debug("Traffic await timed out after %d ms", timeout_ms)

    async def stop(self):
        """停止监听并等待未完成的响应处理任务（保证 SSE 体被完整记录）"""
        self._route_active = False

        # 等待未完成的异步任务，超时 15 秒避免无限阻塞
        if self._pending_tasks:
            pending = list(self._pending_tasks)
            logger.debug("Waiting for %d pending response tasks", len(pending))
            try:
                await asyncio.wait_for(
                    asyncio.gather(*pending, return_exceptions=True),
                    timeout=15.0,
                )
            except asyncio.TimeoutError:
                logger.warning("Some pending response tasks timed out")

        # 合并页面级 fetch 拦截到的数据（尤其是 SSE 响应体）
        await self._merge_fetch_intercepted()

        logger.info("HTTP interception stopped")

    def _handle_request(self, request: Any):
        """缓存请求体，便于 response 事件匹配"""
        task = asyncio.create_task(self._cache_request_body(request))
        self._pending_tasks.add(task)
        task.add_done_callback(self._pending_tasks.discard)

    async def _cache_request_body(self, request: Any):
        """异步缓存请求体"""
        try:
            key = f"{request.method} {request.url}"
            post_data = request.post_data
            if post_data:
                self._request_bodies[key] = post_data[: self.request_body_limit]
        except Exception:
            pass

    def _handle_response(self, response: Any):
        """Playwright response 事件回调"""
        task = asyncio.create_task(self._record_response_async(response))
        self._pending_tasks.add(task)
        task.add_done_callback(self._pending_tasks.discard)

    async def _record_response_async(self, response: Any):
        """异步记录 response 事件中的请求/响应信息"""
        try:
            url = response.url
            request = response.request
            method = request.method
            resource_type = request.resource_type

            if resource_type not in ("xhr", "fetch", "other", "document"):
                return

            # 静态资源过滤
            if self._is_static_url(url):
                return

            status = response.status
            content_type = response.headers.get("content-type", "")
            req_headers = dict(request.headers)

            body_text = ""
            try:
                if "json" in content_type or "text" in content_type or "event-stream" in content_type:
                    body_text = (await response.text())[: self.response_body_limit]
            except Exception:
                pass

            # 从缓存读取请求体；若缓存未命中，尝试直接读取 request.post_data
            request_key = f"{method} {url}"
            request_body = self._request_bodies.pop(request_key, "")
            if not request_body:
                try:
                    post_data = request.post_data
                    if post_data:
                        request_body = post_data[: self.request_body_limit]
                except Exception:
                    pass

            entry = {
                "timestamp": time.time(),
                "url": url,
                "method": method,
                "resource_type": resource_type,
                "request_headers": req_headers,
                "request_body": request_body,
                "response_status": status,
                "response_headers": dict(response.headers),
                "response_body": body_text,
                "is_llm_api": False,
                "api_type": "",
                "model_name": "",
                "intercept_source": "response_event",
            }

            analyzer = TrafficAnalyzer(config=self.config.get("network", {}))
            llm_info = analyzer.analyze_request(entry)
            entry.update(llm_info)

            if not self._has_similar_entry(entry):
                self.captured.append(entry)
                if entry["is_llm_api"]:
                    logger.info("LLM API captured: %s %s model=%s", method, url, entry.get("model_name") or "unknown")
        except Exception as e:
            logger.debug("Failed to record response event: %s", truncate_error(str(e), self.config))

    async def _install_fetch_interceptor(self):
        """在页面注入 fetch/XHR 拦截脚本，捕获 SSE 等流式响应体"""
        script = """
        () => {
            if (window.__pyrit_fetch_hook_installed) return;
            window.__pyrit_fetch_hook_installed = true;
            window.__pyrit_intercepted_calls = window.__pyrit_intercepted_calls || [];

            const push = (obj) => {
                try {
                    window.__pyrit_intercepted_calls.push(obj);
                    if (window.__pyrit_intercepted_calls.length > 200) {
                        window.__pyrit_intercepted_calls.shift();
                    }
                } catch (e) {}
            };

            const isStatic = (url) => {
                const exts = ['.js','.css','.png','.jpg','.jpeg','.svg','.woff','.woff2','.ico','.gif','.ttf','.map','.mp4','.webp','.eot','.otf','.pdf','.zip'];
                const clean = (url.split('?')[0].split('#')[0] || '').toLowerCase();
                return exts.some(ext => clean.endsWith(ext));
            };

            const cloneHeaders = (h) => {
                const out = {};
                try { h.forEach((v, k) => out[k] = v); } catch (e) {}
                return out;
            };

            const readBody = async (response) => {
                const ct = (response.headers.get('content-type') || '').toLowerCase();
                let text = '';
                try {
                    if (ct.includes('event-stream')) {
                        const reader = response.body.getReader();
                        const decoder = new TextDecoder();
                        const chunks = [];
                        let done = false;
                        while (!done && chunks.length < 50) {
                            const { value, done: d } = await reader.read();
                            done = d;
                            if (value) chunks.push(decoder.decode(value, { stream: !done }));
                        }
                        text = chunks.join('');
                    } else {
                        const cloned = response.clone();
                        text = await cloned.text();
                    }
                } catch (e) {}
                return text.slice(0, 5000);
            };

            // fetch 拦截
            const origFetch = window.fetch;
            window.fetch = async function(...args) {
                let url = args[0];
                if (typeof url === 'object' && url.url) url = url.url;
                const init = args[1] || {};
                const method = (init.method || 'GET').toUpperCase();
                let body = init.body || '';
                if (typeof body !== 'string') body = '';
                if (isStatic(url)) return origFetch.apply(this, args);

                const start = Date.now();
                try {
                    const resp = await origFetch.apply(this, args);
                    const text = await readBody(resp);
                    push({
                        timestamp: start / 1000,
                        url: url,
                        method: method,
                        requestBody: body.slice(0, 5000),
                        responseStatus: resp.status,
                        responseHeaders: cloneHeaders(resp.headers),
                        responseBody: text,
                        source: 'fetch_hook'
                    });
                    return resp;
                } catch (err) {
                    push({
                        timestamp: start / 1000,
                        url: url,
                        method: method,
                        requestBody: body.slice(0, 5000),
                        error: String(err.message || err),
                        source: 'fetch_hook'
                    });
                    throw err;
                }
            };

            // XHR 拦截
            const origOpen = XMLHttpRequest.prototype.open;
            const origSend = XMLHttpRequest.prototype.send;
            const xhrMap = new WeakMap();
            XMLHttpRequest.prototype.open = function(method, url, ...rest) {
                try { xhrMap.set(this, { method, url }); } catch (e) {}
                return origOpen.call(this, method, url, ...rest);
            };
            XMLHttpRequest.prototype.send = function(body) {
                const meta = xhrMap.get(this) || { method: 'GET', url: '' };
                if (isStatic(meta.url)) return origSend.call(this, body);
                const start = Date.now();
                const reqBody = (typeof body === 'string' ? body : '').slice(0, 5000);
                const onLoad = () => {
                    try {
                        const ct = (this.getResponseHeader('content-type') || '').toLowerCase();
                        let text = '';
                        if (ct.includes('json') || ct.includes('text') || ct.includes('event-stream')) {
                            text = String(this.responseText || '').slice(0, 5000);
                        }
                        push({
                            timestamp: start / 1000,
                            url: meta.url,
                            method: meta.method,
                            requestBody: reqBody,
                            responseStatus: this.status,
                            responseHeaders: {},
                            responseBody: text,
                            source: 'xhr_hook'
                        });
                    } catch (e) {}
                };
                this.addEventListener('load', onLoad);
                this.addEventListener('error', () => {
                    push({ timestamp: start / 1000, url: meta.url, method: meta.method, requestBody: reqBody, error: 'xhr error', source: 'xhr_hook' });
                });
                return origSend.call(this, body);
            };
        }
        """
        try:
            # 对当前已加载的页面立即执行
            await self.page.evaluate(script)
            # 对未来新页面/iframe 也生效
            await self.page.add_init_script(script)
            logger.debug("Page-level fetch/XHR interceptor installed")
        except Exception as exc:
            logger.warning("Failed to install fetch interceptor: %s", exc)

    async def _merge_fetch_intercepted(self):
        """读取页面级拦截数据并合并到 captured 列表"""
        try:
            calls = await self.page.evaluate("() => window.__pyrit_intercepted_calls || []")
        except Exception as exc:
            logger.debug("Failed to read fetch intercepted calls: %s", exc)
            return

        logger.debug("Fetch hook captured %d calls", len(calls))
        if not calls:
            return

        analyzer = TrafficAnalyzer(config=self.config.get("network", {}))
        for call in calls:
            try:
                url = call.get("url", "")
                method = call.get("method", "GET")
                if not url or self._is_static_url(url):
                    continue

                # 避免与已有 response_event 重复；若已有则用 hook 的响应体补充
                existing = None
                for e in self.captured:
                    if e.get("url") == url and e.get("method") == method:
                        existing = e
                        break

                hook_body = call.get("responseBody", "")
                hook_req_body = call.get("requestBody", "")

                if existing:
                    # 用 hook 的 body 补充空 body
                    if hook_body and not existing.get("response_body"):
                        existing["response_body"] = hook_body[: self.response_body_limit]
                    if hook_req_body and not existing.get("request_body"):
                        existing["request_body"] = hook_req_body[: self.request_body_limit]
                    continue

                entry = {
                    "timestamp": call.get("timestamp", time.time()),
                    "url": url,
                    "method": method,
                    "resource_type": "fetch",
                    "request_headers": {},
                    "request_body": hook_req_body[: self.request_body_limit],
                    "response_status": call.get("responseStatus", 0),
                    "response_headers": call.get("responseHeaders", {}),
                    "response_body": hook_body[: self.response_body_limit],
                    "is_llm_api": False,
                    "api_type": "",
                    "model_name": "",
                    "intercept_source": call.get("source", "fetch_hook"),
                }
                llm_info = analyzer.analyze_request(entry)
                entry.update(llm_info)
                self.captured.append(entry)
                if entry["is_llm_api"]:
                    logger.info("LLM API captured via hook: %s %s model=%s", method, url, entry.get("model_name") or "unknown")
            except Exception as exc:
                logger.debug("Failed to merge fetch call: %s", exc)

    def _is_static_url(self, url: str) -> bool:
        """过滤静态资源 URL"""
        static_exts = (
            ".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".woff", ".woff2",
            ".ico", ".gif", ".ttf", ".map", ".mp4", ".webp", ".eot", ".otf",
            ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz",
        )
        clean = url.split("?")[0].split("#")[0].lower()
        return any(clean.endswith(ext) for ext in static_exts)

    def _has_similar_entry(self, entry: Dict[str, Any]) -> bool:
        """检查是否已有相似记录"""
        url = entry.get("url", "")
        method = entry.get("method", "")
        for existing in self.captured:
            if existing.get("url") == url and existing.get("method") == method:
                # 如果新记录更完整（有模型名），允许覆盖
                if entry.get("model_name") and not existing.get("model_name"):
                    existing.update(entry)
                return True
        return False

    def get_llm_endpoints(self) -> List[Dict[str, Any]]:
        """获取识别到的 LLM API 端点列表"""
        return [e for e in self.captured if e.get("is_llm_api")]

    def get_model_name(self) -> str:
        """获取首个识别到的模型名"""
        for e in self.captured:
            if e.get("model_name"):
                return e["model_name"]
        return ""

    def get_api_endpoints(self) -> List[Dict[str, Any]]:
        """获取所有端点（去重 URL）"""
        seen = set()
        results = []
        for e in self.captured:
            url = e.get("url", "")
            if url not in seen:
                seen.add(url)
                results.append(e)
        return results

    def _record_ws_frame(self, url: str, direction: str, payload: str):
        """记录 WebSocket 帧"""
        self.websocket_frames.append({
            "timestamp": time.time(),
            "url": url,
            "direction": direction,
            "payload": payload[: self.websocket_payload_limit],
        })
        logger.debug("WebSocket %s: %s", direction, url)

    def get_websocket_frames(self) -> List[Dict[str, Any]]:
        """获取 WebSocket 帧记录"""
        return self.websocket_frames

    def get_extracted_credentials(self) -> List[Dict[str, Any]]:
        """汇总所有拦截流量中提取到的 API Key 线索"""
        findings = []
        for e in self.captured:
            keys = e.get("api_keys", [])
            if keys:
                findings.append({
                    "url": e.get("url"),
                    "keys": keys,
                })
        return findings

    def get_rag_features(self) -> List[Dict[str, Any]]:
        """汇总 RAG 特征"""
        results = []
        for e in self.captured:
            features = e.get("rag_features", [])
            if features:
                results.append({"url": e.get("url"), "features": features})
        return results

    def get_agent_features(self) -> List[Dict[str, Any]]:
        """汇总 Agent 特征"""
        results = []
        for e in self.captured:
            features = e.get("agent_features", [])
            if features:
                results.append({"url": e.get("url"), "features": features})
        return results

    def get_protocols(self) -> List[str]:
        """获取检测到的通信协议列表"""
        protocols = set()
        for e in self.captured:
            protocol = e.get("protocol")
            if protocol:
                protocols.add(protocol)
        if self.websocket_frames:
            protocols.add("websocket")
        return sorted(list(protocols))
