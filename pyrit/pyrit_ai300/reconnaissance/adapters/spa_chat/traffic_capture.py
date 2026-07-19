# -*- coding: utf-8 -*-
"""
SPA Chat Recon - 网络流量捕获模块

NetworkTrafficCapture: 捕获并分析浏览器网络请求/响应
- 识别 LLM API 端点（路径关键词 + body 字段 + 响应特征）
- 提取模型信息 / 认证方式 / 流式响应检测
- RAG 端点探测

从 spa_chat_recon_adapter.py 提取（模块化拆分）
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .constants import (
    LLM_PATH_KEYWORDS,
    LLM_BODY_FIELDS,
    LLM_RESPONSE_FIELDS,
    RAG_PATH_KEYWORDS,
)

logger = logging.getLogger(__name__)

class NetworkTrafficCapture:
    """
    网络流量捕获器

    在浏览器自动化过程中监听所有请求和响应，
    识别 LLM 相关的 API 调用并提取有价值信息。
    """

    def __init__(self):
        self.captured_requests: List[Dict[str, Any]] = []
        self.captured_responses: List[Dict[str, Any]] = []
        self.llm_api_calls: List[Dict[str, Any]] = []
        self.rag_api_calls: List[Dict[str, Any]] = []
        self._request_map: Dict[str, Dict[str, Any]] = {}  # 请求 ID → 请求数据

    def on_request(self, request: Any) -> None:
        """请求事件回调"""
        try:
            url = request.url
            method = request.method
            headers = dict(request.headers)
            post_data = None

            # 尝试获取 POST body
            try:
                post_data = request.post_data
            except Exception:
                pass

            req_info: Dict[str, Any] = {
                "url": url,
                "method": method,
                "headers": headers,
                "post_data": post_data,
                "timestamp": time.time(),
                "path": urlparse(url).path,
            }

            self._request_map[url] = req_info
            self.captured_requests.append(req_info)

        except Exception as e:
            logger.debug("Failed to capture request: %s", str(e))

    async def on_response(self, response: Any) -> None:
        """响应事件回调（异步，捕获 LLM API 响应体）"""
        try:
            url = response.url
            status = response.status
            headers = dict(response.headers)
            content_type = headers.get("content-type", "")

            resp_info: Dict[str, Any] = {
                "url": url,
                "status": status,
                "headers": headers,
                "content_type": content_type,
                "timestamp": time.time(),
                "path": urlparse(url).path,
            }

            # 关联请求
            req_info = self._request_map.get(url)
            if req_info:
                resp_info["request"] = req_info
                # 分析是否是 LLM API 调用（同步分析，不获取 body）
                self._analyze_llm_call(req_info, resp_info)

            # 异步获取响应体（仅对 LLM API 调用和 RAG 调用）
            if req_info:
                path_lower = req_info.get("path", "").lower()
                method = req_info.get("method", "")
                is_potential_llm = (
                    any(kw in path_lower for kw in LLM_PATH_KEYWORDS) or
                    method == "POST"
                )
                if is_potential_llm:
                    try:
                        body_text = await response.text()
                        resp_info["body"] = body_text[:10000]  # 限制大小
                        # 如果已识别为 LLM API 调用，将响应体附加到 call_info
                        if self.llm_api_calls and self.llm_api_calls[-1].get("url") == url:
                            self.llm_api_calls[-1]["response_body"] = body_text[:10000]
                            # 尝试从响应体提取模型生成的文本
                            extracted = self._extract_response_text(body_text, content_type)
                            if extracted:
                                self.llm_api_calls[-1]["response_text_extracted"] = extracted
                    except Exception:
                        pass

            self.captured_responses.append(resp_info)

        except Exception as e:
            logger.debug("Failed to capture response: %s", str(e))

    @staticmethod
    def _extract_response_text(body: str, content_type: str) -> str:
        """从 LLM API 响应体中提取模型生成的文本"""
        if not body:
            return ""

        # SSE 流式响应
        if "text/event-stream" in content_type:
            lines = body.split("\n")
            texts = []
            for line in lines:
                if line.startswith("data:"):
                    data = line[5:].strip()
                    if data and data != "[DONE]":
                        try:
                            chunk = json.loads(data)
                            # OpenAI 格式
                            choices = chunk.get("choices", [])
                            if choices:
                                delta = choices[0].get("delta", {})
                                content = delta.get("content", "")
                                if content:
                                    texts.append(content)
                                # 或 message.content
                                message = choices[0].get("message", {})
                                if message.get("content"):
                                    texts.append(message["content"])
                        except (json.JSONDecodeError, ValueError):
                            continue
            return "".join(texts)

        # JSON 响应
        if "application/json" in content_type:
            try:
                data = json.loads(body)
                choices = data.get("choices", [])
                if choices:
                    message = choices[0].get("message", {})
                    return message.get("content", "")
                # 通义千问格式
                output = data.get("output", {})
                if isinstance(output, dict):
                    return output.get("text", "")
                # 其他格式
                return data.get("response", data.get("answer", data.get("reply", "")))
            except (json.JSONDecodeError, ValueError):
                pass

        return body[:2000]  # 返回原始文本的前 2000 字符

    async def capture_response_body(self, response: Any) -> str:
        """异步获取响应 body 文本"""
        try:
            return await response.text()
        except Exception:
            return ""

    def _analyze_llm_call(self, req_info: Dict[str, Any], resp_info: Dict[str, Any]) -> None:
        """分析请求/响应是否是 LLM API 调用"""
        url = req_info.get("url", "")
        path = req_info.get("path", "").lower()
        method = req_info.get("method", "")
        post_data = req_info.get("post_data", "")
        content_type = resp_info.get("content_type", "").lower()

        # 1. 路径关键词匹配
        path_match = any(kw in path for kw in LLM_PATH_KEYWORDS)

        # 2. POST 请求 + JSON body 包含 LLM 字段
        body_match = False
        parsed_body: Optional[Dict[str, Any]] = None
        if post_data and method == "POST":
            try:
                parsed_body = json.loads(post_data)
                if isinstance(parsed_body, dict):
                    body_fields = set(parsed_body.keys())
                    overlap = body_fields & set(LLM_BODY_FIELDS)
                    body_match = len(overlap) >= 1
            except (json.JSONDecodeError, ValueError):
                pass

        # 3. 响应 content-type 为 SSE 或 JSON
        is_sse = "text/event-stream" in content_type
        is_json = "application/json" in content_type

        # 4. 综合判断
        is_llm = (path_match and method == "POST") or body_match or is_sse

        if is_llm:
            call_info: Dict[str, Any] = {
                "url": url,
                "path": req_info.get("path", ""),
                "method": method,
                "status": resp_info.get("status"),
                "content_type": content_type,
                "is_streaming": is_sse,
                "request_body": parsed_body,
                "request_headers": req_info.get("headers", {}),
                "model_extracted": None,
                "system_prompt_extracted": None,
                "messages_count": 0,
            }

            # 从请求 body 提取模型名称
            if parsed_body:
                call_info["model_extracted"] = parsed_body.get("model")
                messages = parsed_body.get("messages", [])
                call_info["messages_count"] = len(messages) if isinstance(messages, list) else 0

                # 提取系统提示
                if isinstance(messages, list):
                    for msg in messages:
                        if isinstance(msg, dict) and msg.get("role") == "system":
                            content = msg.get("content", "")
                            if content:
                                call_info["system_prompt_extracted"] = str(content)[:2000]
                            break

                # 检测 function_calling
                if parsed_body.get("tools") or parsed_body.get("functions"):
                    call_info["has_tools"] = True

                # 检测 vision（多模态）
                if isinstance(messages, list):
                    for msg in messages:
                        content = msg.get("content")
                        if isinstance(content, list):
                            for part in content:
                                if isinstance(part, dict) and part.get("type") == "image_url":
                                    call_info["has_vision"] = True
                                    break

            # 从请求头提取认证方式
            auth_header = call_info["request_headers"].get("authorization", "")
            if auth_header:
                if auth_header.lower().startswith("bearer "):
                    call_info["auth_type"] = "bearer"
                elif auth_header.lower().startswith("basic "):
                    call_info["auth_type"] = "basic"
                else:
                    call_info["auth_type"] = "custom"
            elif call_info["request_headers"].get("cookie"):
                call_info["auth_type"] = "cookie"
            elif call_info["request_headers"].get("x-api-key"):
                call_info["auth_type"] = "api_key"
            else:
                call_info["auth_type"] = "none"

            self.llm_api_calls.append(call_info)

        # RAG 端点检测
        is_rag = any(kw in path for kw in RAG_PATH_KEYWORDS)
        if is_rag and method in ("GET", "POST"):
            self.rag_api_calls.append({
                "url": url,
                "path": req_info.get("path", ""),
                "method": method,
                "status": resp_info.get("status"),
                "content_type": content_type,
            })

    def get_primary_llm_endpoint(self) -> Optional[Dict[str, Any]]:
        """获取主要的 LLM API 端点（调用次数最多的）"""
        if not self.llm_api_calls:
            return None

        # 按路径分组统计
        path_counts: Dict[str, int] = {}
        path_calls: Dict[str, Dict[str, Any]] = {}
        for call in self.llm_api_calls:
            p = call["path"]
            path_counts[p] = path_counts.get(p, 0) + 1
            path_calls[p] = call  # 保留最后一个

        # 选择调用次数最多的路径
        primary_path = max(path_counts, key=path_counts.get)
        return path_calls[primary_path]

    def get_summary(self) -> Dict[str, Any]:
        """获取流量捕获摘要"""
        primary = self.get_primary_llm_endpoint()
        return {
            "total_requests": len(self.captured_requests),
            "total_responses": len(self.captured_responses),
            "llm_api_calls": len(self.llm_api_calls),
            "rag_api_calls": len(self.rag_api_calls),
            "primary_llm_endpoint": primary["url"] if primary else None,
            "llm_endpoints": list({c["url"] for c in self.llm_api_calls}),
            "rag_endpoints": list({c["url"] for c in self.rag_api_calls}),
        }


