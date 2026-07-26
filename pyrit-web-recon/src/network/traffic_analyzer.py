# -*- coding: utf-8 -*-
"""
Traffic Analyzer
================

网络流量分析器：
  - 识别 LLM API 端点（OpenAI / Claude / Gemini / 国内厂商）
  - 从 JSON / SSE 流中提取模型名
  - 提取 LLM 响应文本
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class TrafficAnalyzer:
    """网络流量分析器：识别 LLM API、解析响应、提取模型名、API Key、RAG/Agent 特征"""

    def __init__(self):
        self.llm_api_patterns = [
            # OpenAI 兼容
            r"/v\d+/chat/completions",
            r"/chat/completions",
            r"/completions",
            r"/v1/embeddings",
            r"/v1/models",
            # 国内厂商
            r"/api/v1/services/aigc/text-generation",
            r"/api/paas/v4/chat/completions",
            r"/compatible-mode/v1/chat/completions",
            r"/api/llm/chat",
            r"/api/chat",
            r"/v1/conversation",
            r"/api/v3/chat",
            r"/prod/api/conversation",
            # Copilot / Claude / Gemini
            r"/conversation",
            r"/api/conversation",
            r"/v1/streams/chat",
            r"/v1beta/models/",
            r"/v1/generateContent",
            # 通用 LLM 关键词
            r"/llm/",
            r"/ai/",
            r"/aigc/",
            r"/generate",
            r"/stream",
        ]
        self.model_name_keys = [
            "model",
            "model_name",
            "modelName",
            "model_id",
            "modelId",
            "model_code",
            "modelCode",
            "modelVersion",
        ]

        # RAG 相关 URL/Body 关键词
        self.rag_keywords = [
            "rag", "retrieval", "knowledge", "knowledge_base", "knowledgebase",
            "document", "doc", "embedding", "vector", "index", "search",
            "知识库", "检索", "向量", "文档",
        ]

        # Agent / Copilot / MCP 相关关键词
        self.agent_keywords = [
            "agent", "copilot", "assistant", "tool", "function_call", "plugin",
            "mcp", "model_context_protocol", "action", "workflow",
            "智能体", "助手", "插件", "工具", "工作流",
        ]

        # API Key 正则（仅识别前缀，避免完整泄露敏感 token）
        self.api_key_patterns = [
            re.compile(r'(sk-[a-zA-Z0-9]{20,})', re.IGNORECASE),
            re.compile(r'(Bearer\s+)([a-zA-Z0-9_\-]{20,})', re.IGNORECASE),
            re.compile(r'(api[_-]?key["\']?\s*[:=]\s*["\']?)([a-zA-Z0-9_\-]{8,})', re.IGNORECASE),
        ]

    def analyze_request(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """分析单个请求条目，返回 LLM 识别结果"""
        url = entry.get("url", "")
        body = entry.get("request_body", "")
        response = entry.get("response_body", "")
        req_headers = entry.get("request_headers", {})
        resp_headers = entry.get("response_headers", {})

        result = {
            "is_llm_api": False,
            "api_type": "",
            "model_name": "",
            "api_keys": [],
            "protocol": self._detect_protocol(resp_headers, url),
            "rag_features": [],
            "agent_features": [],
        }

        # 1. URL 模式匹配
        api_type = self._detect_api_type(url)
        if api_type:
            result["is_llm_api"] = True
            result["api_type"] = api_type

        # 2. Body 中的 model 字段
        model_from_body = self._extract_model_from_text(body)
        if model_from_body:
            result["model_name"] = model_from_body
            result["is_llm_api"] = True

        # 3. 响应体中的模型名
        model_from_response = self._extract_model_from_text(response)
        if model_from_response and not result["model_name"]:
            result["model_name"] = model_from_response

        # 4. SSE 流内容提取
        sse_model = self._extract_model_from_sse(response)
        if sse_model:
            result["model_name"] = sse_model
            result["is_llm_api"] = True

        # 5. 响应头线索
        content_type = resp_headers.get("content-type", "")
        if "text/event-stream" in content_type.lower() and api_type:
            result["is_llm_api"] = True

        # 6. API Key 提取
        result["api_keys"] = self._extract_api_keys(req_headers, body)

        # 7. RAG / Agent 特征识别
        result["rag_features"] = self._detect_rag_features(url, body, response)
        result["agent_features"] = self._detect_agent_features(url, body, response)

        return result

    def _detect_api_type(self, url: str) -> str:
        """根据 URL 判断 API 类型"""
        lower_url = url.lower()
        if "/v1/chat/completions" in lower_url or "/chat/completions" in lower_url:
            return "openai_compatible"
        if "/v1/completions" in lower_url:
            return "openai_completions"
        if "/v1/embeddings" in lower_url:
            return "openai_embeddings"
        if "/v1/models" in lower_url:
            return "openai_models"
        if "/conversation" in lower_url:
            return "claude_compatible"
        if "/v1beta/models/" in lower_url or "/generateContent" in lower_url:
            return "gemini_compatible"
        if "/api/paas/v4" in lower_url or "/compatible-mode/v1" in lower_url:
            return "moonshot_compatible"
        if "/api/v1/services/aigc" in lower_url or "/qianfan" in lower_url:
            return "baidu_qianfan"
        if "/api/v3/chat" in lower_url or "/prod/api/conversation" in lower_url:
            return "zhipu_compatible"
        if "/api/llm/chat" in lower_url or "/api/chat" in lower_url:
            return "generic_llm"
        for pattern in self.llm_api_patterns:
            if re.search(pattern, lower_url):
                return "generic_llm"
        return ""

    def _extract_model_from_text(self, text: str) -> str:
        """从 JSON 文本中提取 model 字段"""
        if not text or len(text) > 5000:
            return ""
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                for key in self.model_name_keys:
                    if key in data and data[key]:
                        return str(data[key])
                # 兼容 {"data": {"model": "xxx"}}
                for nested_key in ["data", "payload", "body", "params"]:
                    nested = data.get(nested_key)
                    if isinstance(nested, dict):
                        for key in self.model_name_keys:
                            if key in nested and nested[key]:
                                return str(nested[key])
        except json.JSONDecodeError:
            # 非 JSON 尝试正则
            for key in self.model_name_keys:
                pattern = rf'"{key}"\s*:\s*"([^"]+)"'
                match = re.search(pattern, text)
                if match:
                    return match.group(1)
        return ""

    def _extract_model_from_sse(self, text: str) -> str:
        """从 SSE 流中提取模型名"""
        if not text:
            return ""
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                payload = line[5:].strip()
                if payload == "[DONE]":
                    continue
                model = self._extract_model_from_text(payload)
                if model:
                    return model
        return ""

    def _detect_protocol(self, response_headers: Dict[str, str], url: str) -> str:
        """识别通信协议"""
        ct = response_headers.get("content-type", "").lower()
        if "text/event-stream" in ct:
            return "sse"
        if "grpc-web" in ct or "/grpc/" in url.lower():
            return "grpc-web"
        if url.lower().startswith("wss://") or url.lower().startswith("ws://"):
            return "websocket"
        return "http"

    def _extract_api_keys(self, headers: Dict[str, str], body: str) -> List[Dict[str, Any]]:
        """从请求头和请求体中提取 API Key 线索"""
        findings: List[Dict[str, Any]] = []
        text_pool = " ".join([f"{k}: {v}" for k, v in headers.items()])
        text_pool += " " + body

        for pattern in self.api_key_patterns:
            for match in pattern.finditer(text_pool):
                full = match.group(0)
                key_value = match.group(2) if len(match.groups()) > 1 else full
                prefix = key_value[:8]
                findings.append({
                    "type": "api_key",
                    "prefix": prefix,
                    "length": len(key_value),
                    "source": "header" if full in str(headers) else "body",
                })

        # 显式 API Key 头
        for name in ["x-api-key", "api-key", "x-auth-token", "x-access-token"]:
            value = headers.get(name) or headers.get(name.title()) or headers.get(name.upper())
            if value:
                findings.append({
                    "type": "api_key_header",
                    "header": name,
                    "prefix": str(value)[:8],
                    "length": len(str(value)),
                    "source": "header",
                })

        return findings

    def _detect_rag_features(self, url: str, body: str, response: str) -> List[Dict[str, Any]]:
        """识别 RAG 相关特征"""
        findings: List[Dict[str, Any]] = []
        combined = f"{url} {body} {response}".lower()
        for keyword in self.rag_keywords:
            if keyword.lower() in combined:
                findings.append({"keyword": keyword, "context": "url/body/response"})
        return findings

    def _detect_agent_features(self, url: str, body: str, response: str) -> List[Dict[str, Any]]:
        """识别 Agent / Copilot / MCP 相关特征"""
        findings: List[Dict[str, Any]] = []
        combined = f"{url} {body} {response}".lower()
        for keyword in self.agent_keywords:
            if keyword.lower() in combined:
                findings.append({"keyword": keyword, "context": "url/body/response"})
        return findings

    def extract_response_text(self, response_body: str) -> str:
        """从 LLM 响应体中提取最终文本"""
        if not response_body:
            return ""

        # 1. OpenAI 兼容格式
        try:
            data = json.loads(response_body)
            if isinstance(data, dict):
                choices = data.get("choices", [])
                if choices and isinstance(choices, list):
                    msg = choices[0].get("message", {})
                    content = msg.get("content") or choices[0].get("text", "")
                    if content:
                        return str(content)
        except Exception:
            pass

        # 2. SSE 流
        texts = []
        for line in response_body.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                payload = line[5:].strip()
                if payload == "[DONE]":
                    continue
                try:
                    data = json.loads(payload)
                    choices = data.get("choices", [])
                    if choices:
                        delta = choices[0].get("delta", {})
                        content = delta.get("content", "")
                        if content:
                            texts.append(content)
                except Exception:
                    continue
        return "".join(texts)

    def is_streaming_response(self, response_headers: Dict[str, str]) -> bool:
        """判断响应是否为流式"""
        ct = response_headers.get("content-type", "").lower()
        return "text/event-stream" in ct or "chunked" in ct
