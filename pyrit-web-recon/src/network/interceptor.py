# -*- coding: utf-8 -*-
"""
HTTP Interceptor
================

基于 Playwright page.route 拦截网络流量，识别 LLM API 端点，
捕获请求头、请求体、响应体。
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

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

    async def start(self):
        """启用页面路由拦截与 WebSocket 监听"""
        if self._route_active:
            return
        await self.page.route("**/*", self._handle_route)
        self._route_active = True

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
        logger.info("HTTP interception and WebSocket monitoring started")

    async def stop(self):
        """停止页面路由拦截"""
        if not self._route_active:
            return
        await self.page.unroute("**/*", self._handle_route)
        self._route_active = False
        logger.info("HTTP interception stopped")

    async def _handle_route(self, route: Any, request: Any):
        """处理每个请求"""
        try:
            response = await route.fetch()
            await self._record(request, response)
            await route.fulfill(
                status=response.status,
                headers=response.headers,
                body=await response.body(),
            )
        except Exception as e:
            logger.warning("Route fetch failed, falling back to continue: %s", str(e)[:120])
            await route.continue_()

    async def _record(self, request: Any, response: Any):
        """记录请求响应"""
        url = request.url
        method = request.method
        resource_type = request.resource_type

        # 只关注 XHR / fetch / document / other
        if resource_type not in ("xhr", "fetch", "other", "document"):
            return

        try:
            body_text = ""
            try:
                post_data = request.post_data
                if post_data:
                    body_text = post_data[:5000]
            except Exception:
                pass

            resp_body = ""
            try:
                if response.status < 400:
                    body = await response.body()
                    if body:
                        resp_body = body.decode("utf-8", errors="replace")[:5000]
            except Exception:
                pass

            entry = {
                "timestamp": time.time(),
                "url": url,
                "method": method,
                "resource_type": resource_type,
                "request_headers": dict(request.headers),
                "request_body": body_text,
                "response_status": response.status,
                "response_headers": dict(response.headers),
                "response_body": resp_body,
                "is_llm_api": False,
                "api_type": "",
                "model_name": "",
            }

            # LLM API 识别
            analyzer = TrafficAnalyzer()
            llm_info = analyzer.analyze_request(entry)
            entry.update(llm_info)

            self.captured.append(entry)
            if entry["is_llm_api"]:
                logger.info("LLM API captured: %s %s model=%s", method, url, entry.get("model_name") or "unknown")
        except Exception as e:
            logger.warning("Failed to record request: %s", str(e)[:120])

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
            "payload": payload[:2000],
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
